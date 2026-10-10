"""The AirDrop receiver: HTTPS endpoints /Discover, /Ask, /Upload.

Portable re-implementation of omdrop's airdrop-serve.py behaviour:

  * POST /Discover -> binary plist with ReceiverComputerName / ModelName /
    MediaCapabilities (and ReceiverRecordData when we hold an Apple identity)
  * POST /Ask      -> consent gate (auto-accept in everyone mode, or the
    on_ask callback), stores `links` items as inert .url files
  * POST /Upload   -> application/x-dvzip body -> DVZip decode -> cpio
    extract, with byte/member/rate limits and filename sanitisation

Threaded because sharingd opens several connections at once; a single-thread
server would hold /Discover behind a stalled one.
"""
import contextlib
import io
import json
import logging
import os
import plistlib
import shutil
import socket
import ssl
import struct
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import contacts, cpio, dvzip
from .const import UPLOAD_CONTENT_TYPE
from .util import open_new, safe_name

log = logging.getLogger("airdrop.server")

KIB, MIB, GIB = 1024, 1024 * 1024, 1024 * 1024 * 1024

READ_IDLE_TIMEOUT_SECONDS = 30
INITIAL_READ_SECONDS = 60
MIN_READ_BYTES_PER_SECOND = 64 * KIB
MAX_METADATA_BYTES = 1 * MIB
MAX_ARCHIVE_MEMBERS = 512
MIN_FREE_BYTES = 1 * GIB
DISK_CHECK_INTERVAL = 16 * MIB
IO_CHUNK_BYTES = 64 * KIB
MAX_CHUNK_LINE_BYTES = 128
MAX_TRAILER_BYTES = 8 * KIB
MAX_CONCURRENT_UPLOADS = 2

# ReceiverMediaCapabilities, sent in the Discover and Ask answers: version 1
# and no codecs/containers, so the sender converts to legacy formats (JPEG
# rather than HEIF). The key's presence is the point.
MEDIA_CAPABILITIES = json.dumps({"Version": 1}).encode()


class HandshakeFailed(Exception):
    pass


class RequestBodyError(ValueError):
    status = 400


class BodyTooLarge(RequestBodyError):
    status = 413


class UploadLimitError(ValueError):
    pass


class ReceiveBudget:
    """Byte budget for one upload, from currently free output-disk space."""

    def __init__(self, dest, percent):
        usage = shutil.disk_usage(dest)
        self.free_bytes = usage.free
        percent_bytes = self.free_bytes * percent // 100
        reservable = max(0, self.free_bytes - MIN_FREE_BYTES)
        self.byte_limit = min(percent_bytes, reservable)
        self.percent = percent
        if self.byte_limit <= 0:
            raise UploadLimitError(
                f"not enough free space while preserving {MIN_FREE_BYTES} bytes")


class ReadRateTimeout(socket.timeout):
    pass


class ReadDeadline:
    """Require sustained progress as well as an idle-socket timeout."""

    def __init__(self):
        self.started = time.monotonic()
        self.transferred = 0

    def note(self, size):
        self.transferred += size
        allowed = INITIAL_READ_SECONDS + self.transferred / MIN_READ_BYTES_PER_SECOND
        if time.monotonic() > self.started + allowed:
            raise ReadRateTimeout("request body did not meet minimum read rate")

    def stall_report(self, error, expected):
        why = (f"slower than {MIN_READ_BYTES_PER_SECOND} bytes/s"
               if isinstance(error, ReadRateTimeout)
               else f"nothing arrived for {READ_IDLE_TIMEOUT_SECONDS} s")
        of = f" of {expected}" if expected is not None else ""
        return (f"request body read timed out, {why}: {self.transferred}{of} "
                f"bytes in {time.monotonic() - self.started:.1f} s")


class LimitedWriter:
    """Count writes, enforce a byte ceiling, preserve free disk space."""

    def __init__(self, target, limit, label, limit_error=UploadLimitError,
                 check_disk=False, disk_path=None):
        self.target = target
        self.limit = limit
        self.label = label
        self.limit_error = limit_error
        self.check_disk = check_disk
        self.disk_path = disk_path
        self.total = 0
        self._until_disk_check = 0

    @property
    def remaining(self):
        return self.limit - self.total

    def write(self, data):
        if not data:
            return 0
        size = len(data)
        if size > self.remaining:
            raise self.limit_error(f"{self.label} exceeds {self.limit}-byte limit")
        if self.check_disk and self.disk_path and size >= self._until_disk_check:
            if shutil.disk_usage(self.disk_path).free < MIN_FREE_BYTES + DISK_CHECK_INTERVAL:
                raise UploadLimitError(
                    f"{self.label} stopped to preserve {MIN_FREE_BYTES} bytes free")
            self._until_disk_check = DISK_CHECK_INTERVAL
        written = self.target.write(data)
        if written != size:
            raise OSError(f"short write for {self.label}: {written} of {size} bytes")
        self.total += written
        self._until_disk_check -= written
        return written


def body_plan(headers, limit):
    """Validate framing before 100 Continue or any body read."""
    transfer = headers.get("Transfer-Encoding", "")
    if transfer:
        encodings = [p.strip().lower() for p in transfer.split(",")]
        if encodings != ["chunked"]:
            raise RequestBodyError(f"unsupported Transfer-Encoding: {transfer!r}")
        return "chunked", None
    value = headers.get("Content-Length")
    if value is None:
        raise RequestBodyError("request body needs Content-Length or chunked encoding")
    try:
        length = int(value)
    except (TypeError, ValueError):
        raise RequestBodyError(f"invalid Content-Length: {value!r}") from None
    if length < 0:
        raise RequestBodyError(f"invalid Content-Length: {value!r}")
    if length > limit:
        raise BodyTooLarge(f"request body exceeds {limit}-byte limit")
    return "length", length


def _copy_exact(source, writer, size, truncated, deadline):
    read = getattr(source, "read1", source.read)
    left = size
    while left:
        data = read(min(left, IO_CHUNK_BYTES))
        if not data:
            raise RequestBodyError(truncated)
        deadline.note(len(data))
        writer.write(data)
        left -= len(data)


def _read_chunked(rfile, writer, deadline):
    while True:
        line = rfile.readline(MAX_CHUNK_LINE_BYTES + 1)
        deadline.note(len(line))
        if not line or len(line) > MAX_CHUNK_LINE_BYTES or not line.endswith(b"\n"):
            raise RequestBodyError("invalid or overlong chunk-size line")
        token = line.split(b";", 1)[0].strip()
        try:
            size = int(token, 16)
        except ValueError:
            raise RequestBodyError(f"invalid chunk size: {token[:40]!r}") from None
        if size < 0:
            raise RequestBodyError("negative chunk size")
        if size == 0:
            trailers = 0
            while True:
                line = rfile.readline(MAX_CHUNK_LINE_BYTES + 1)
                deadline.note(len(line))
                trailers += len(line)
                if (not line or len(line) > MAX_CHUNK_LINE_BYTES
                        or trailers > MAX_TRAILER_BYTES):
                    raise RequestBodyError("invalid or overlong chunk trailers")
                if line in (b"\r\n", b"\n"):
                    return
        if size > writer.remaining:
            raise BodyTooLarge(
                f"request body exceeds {writer.limit}-byte limit")
        _copy_exact(rfile, writer, size, "truncated chunk data", deadline)
        ending = rfile.read(2)
        deadline.note(len(ending))
        if ending != b"\r\n":
            raise RequestBodyError("chunk data missing CRLF")


def read_request_body(rfile, headers, target, limit, *, check_disk=False,
                      disk_path=None, plan=None, deadline=None):
    """Stream one framed request body into target under byte/time limits."""
    mode, length = plan or body_plan(headers, limit)
    deadline = deadline or ReadDeadline()
    writer = LimitedWriter(target, limit, "request body", BodyTooLarge,
                           check_disk, disk_path)
    if mode == "chunked":
        _read_chunked(rfile, writer, deadline)
    else:
        _copy_exact(rfile, writer, length, "truncated request body", deadline)
    return writer.total


def read_small_body(rfile, headers, limit=MAX_METADATA_BYTES):
    body = io.BytesIO()
    read_request_body(rfile, headers, body, limit)
    return body.getvalue()


class ExtractionBudget:
    def __init__(self, byte_limit):
        self.byte_limit = byte_limit
        self.members = 0
        self.output_bytes = 0

    def count_member(self):
        self.members += 1
        if self.members > MAX_ARCHIVE_MEMBERS:
            raise UploadLimitError(
                f"archive exceeds {MAX_ARCHIVE_MEMBERS}-member limit")


class ExtractedFileWriter(LimitedWriter):
    def __init__(self, target, budget, name, disk_path):
        super().__init__(target, budget.byte_limit, f"file {name!r}",
                         check_disk=True, disk_path=disk_path)
        self.budget = budget

    def write(self, data):
        if self.budget.output_bytes + len(data) > self.budget.byte_limit:
            raise UploadLimitError(
                f"archive output exceeds {self.budget.byte_limit}-byte limit")
        written = super().write(data)
        self.budget.output_bytes += written
        return written


def store_upload(raw, dest, tid, receive_budget):
    """Decode a DVZip body and extract regular files; remove output on error."""
    created, written = [], []
    try:
        with tempfile.TemporaryFile(dir=dest) as cpio_stream:
            # Decode the framed wire body into a plain cpio stream.
            decoded = _decode_into(raw, cpio_stream, receive_budget.byte_limit, dest)
            raw.seek(0)
            raw.truncate(0)          # release the wire copy's blocks early
            cpio_stream.seek(0)
            magic = cpio_stream.read(6)
            cpio_stream.seek(0)
            log.info("upload %s: decoded to %d bytes, magic %r", tid, decoded, magic)
            budget = ExtractionBudget(receive_budget.byte_limit)
            for entry, stream in cpio.read(cpio_stream):
                budget.count_member()
                # ._members are AppleDouble sidecars; directories are skipped
                # (only regular files are extracted).
                if not entry.isfile or os.path.basename(entry.name).startswith("._"):
                    continue
                declared = entry.size
                if declared > budget.byte_limit:
                    raise UploadLimitError(f"file {entry.name!r} declares {declared} bytes")
                if budget.output_bytes + max(declared, 0) > budget.byte_limit:
                    raise UploadLimitError(
                        f"archive declares more than {budget.byte_limit} output bytes")
                base = safe_name(entry.name, "file")
                name, output = open_new(dest, base)
                created.append(name)
                with output:
                    sink = ExtractedFileWriter(output, budget, name, dest)
                    while True:
                        block = stream.read(IO_CHUNK_BYTES)
                        if not block:
                            break
                        sink.write(block)
                written.append(name)
    except Exception:
        for name in reversed(created):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(os.path.join(dest, name))
        raise
    return written


def _decode_into(raw, cpio_stream, byte_limit, dest):
    writer = LimitedWriter(cpio_stream, byte_limit, "decompressed archive",
                           check_disk=True, disk_path=dest)
    raw.seek(0)
    magic = raw.read(2)
    raw.seek(0)
    if magic == dvzip.GZIP_MAGIC:
        return _decode_gzip(raw, writer)
    return _decode_framed(raw, writer)


def _decode_gzip(raw, writer):
    import zlib
    d = zlib.decompressobj(31)
    while True:
        data = raw.read(IO_CHUNK_BYTES)
        if not data:
            break
        writer.write(d.decompress(data, IO_CHUNK_BYTES))
        if d.unused_data:
            raise ValueError("gzip body has trailing data")
    writer.write(d.flush())
    if not d.eof:
        raise ValueError("truncated gzip body")
    return writer.total


def _decode_framed(raw, writer):
    """DVZip blocks -> cpio bytes into writer (bounded)."""
    import zlib
    while True:
        header = raw.read(4)
        if not header:
            return writer.total
        if len(header) != 4:
            raise ValueError(f"truncated DVZip block header: {len(header)} bytes")
        value = int.from_bytes(header, "big")
        size = value & 0x7FFFFFFF
        if value & dvzip.STORED:
            left = size
            while left:
                data = raw.read(min(left, IO_CHUNK_BYTES))
                if not data:
                    raise ValueError(f"truncated stored block: {left} bytes missing")
                writer.write(data)
                left -= len(data)
        else:
            d = zlib.decompressobj()
            left = size
            while left:
                data = raw.read(min(left, IO_CHUNK_BYTES))
                if not data:
                    raise ValueError(f"truncated compressed block: {left} bytes missing")
                left -= len(data)
                writer.write(d.decompress(data, IO_CHUNK_BYTES))
                if d.unused_data:
                    raise ValueError("compressed block has trailing data")
            writer.write(d.flush())
            if not d.eof:
                raise ValueError("truncated compressed block")


def store_link(url, dest):
    """A received URL becomes an inert .url shortcut (never opened)."""
    parts = urlsplit(url)
    stem = "-".join(p for p in (parts.netloc, parts.path.rstrip("/").rsplit("/", 1)[-1]) if p)
    name, f = open_new(dest, safe_name(stem, "link") + ".url")
    with f:
        f.write(f"[InternetShortcut]\nURL={url}\n".encode())
    return name


def make_handler(cfg):
    """Bind the AirDrop endpoints to one configuration (server-friendly form)."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            self.request.settimeout(READ_IDLE_TIMEOUT_SECONDS)
            try:
                self.request.do_handshake()
            except (OSError, ssl.SSLError) as e:
                log.info("TLS handshake with %s failed: %s", self.client_address, e)
                raise HandshakeFailed from e
            super().setup()

        def handle_expect_100(self):
            if self.path == "/Upload":
                return True
            return super().handle_expect_100()

        def reject(self, status, reason):
            log.warning("%s rejected: %s", self.path, reason)
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

        def answer(self, body):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

        def do_GET(self):
            self.answer(b"\n")

        def do_POST(self):
            log.debug("POST %s, headers:\n%s", self.path, self.headers)
            if self.path == "/Upload":
                self.handle_upload()
                return
            if self.path not in ("/Discover", "/Ask"):
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            try:
                body = read_small_body(self.rfile, self.headers)
            except socket.timeout:
                self.reject(408, "request body read timed out")
                return
            except RequestBodyError as e:
                self.reject(e.status, str(e))
                return
            if self.path == "/Discover":
                self.handle_discover(body)
            else:
                self.handle_ask(body)

        # ---------------------------------------------------------- endpoints

        def handle_discover(self, body):
            if cfg["visibility"] == "contacts":
                try:
                    record = (plistlib.loads(body) or {}).get("SenderRecordData")
                except Exception:
                    record = None
                outcome, detail = contacts.decide_discovery(record)
                if outcome != contacts.ACCEPT:
                    log.info("discovery withheld (contacts only): %s%s",
                             contacts.WHY[outcome], f" [{detail}]" if detail else "")
                    self.send_response(401)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
            answer = {
                "ReceiverMediaCapabilities": MEDIA_CAPABILITIES,
                "ReceiverComputerName": cfg["name"],
                "ReceiverModelName": cfg["model"],
            }
            if cfg.get("record_data"):
                answer["ReceiverRecordData"] = cfg["record_data"]
            self.answer(plistlib.dumps(answer, fmt=plistlib.FMT_BINARY))

        def handle_ask(self, body):
            try:
                ask = plistlib.loads(body)
            except Exception as e:
                log.error("ask: undecodable %d-byte body: %r", len(body), e)
                ask = {}
            files = ask.get("Files") or []
            log.info("ask from %s (%s): type %s, %d item(s): %s",
                     ask.get("SenderComputerName"), ask.get("SenderModelName"),
                     ",".join(ask.get("TransferType") or {}) or "?",
                     len(files),
                     "; ".join(f"{f.get('FileName')} {f.get('FileType')} {f.get('FileSize')}B"
                               for f in files) or (ask.get("Items") or "-"))
            items = ask.get("Items") or []
            if len(items) > MAX_ARCHIVE_MEMBERS:
                self.reject(413, f"Ask exceeds {MAX_ARCHIVE_MEMBERS}-item limit")
                return
            if cfg["visibility"] == "contacts":
                peer_cert = None
                with contextlib.suppress(AttributeError, ValueError):
                    peer_cert = self.connection.getpeercert(binary_form=True)
                outcome, detail = contacts.decide(ask.get("SenderRecordData"), peer_cert)
                if outcome != contacts.ACCEPT:
                    log.warning("ask REFUSED (contacts only): %s%s",
                                contacts.WHY[outcome], f" [{detail}]" if detail else "")
                    self.send_response(403)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                log.info("ask accepted: %s", contacts.WHY[outcome])
                self._contacts_ok = True
            # Interactive consent hook: the CLI/UX layer may veto.
            if cfg.get("on_ask") is not None:
                accepted = cfg["on_ask"](ask)
                if not accepted:
                    self.send_response(403)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
            # A `links` transfer is Ask-only: the URL is in Items; no /Upload.
            if "links" in (ask.get("TransferType") or {}):
                for item in items:
                    if not isinstance(item, str) or not item.startswith(("http://", "https://")):
                        log.warning("ask: ignoring non-http item %.80r", item)
                        continue
                    stored = store_link(item, cfg["dest"])
                    log.info("link stored as %s -> %s", stored, item)
            resp = plistlib.dumps({
                "ReceiverMediaCapabilities": MEDIA_CAPABILITIES,
                "ReceiverComputerName": cfg["name"],
                "ReceiverModelName": cfg["model"],
            }, fmt=plistlib.FMT_BINARY)
            self.answer(resp)
            if cfg.get("on_ask_done"):
                cfg["on_ask_done"](ask)

        def handle_upload(self):
            if cfg["visibility"] == "contacts" and not getattr(self, "_contacts_ok", False):
                self.reject(403, "contacts-only upload has no accepted Ask")
                return
            ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if ctype != UPLOAD_CONTENT_TYPE:
                self.reject(415, f"unsupported Content-Type {ctype!r}")
                return
            if not cfg["upload_slots"].acquire(blocking=False):
                self.reject(503, "too many uploads in progress")
                return
            tid = safe_name(self.headers.get("TransferID", ""), "upload")
            deadline = ReadDeadline()
            plan = None
            try:
                receive_budget = ReceiveBudget(cfg["dest"], cfg["max_receive_percent"])
                plan = body_plan(self.headers, receive_budget.byte_limit)
                log.info("upload %s: %d%% of %d free bytes allows %d bytes",
                         tid, receive_budget.percent, receive_budget.free_bytes,
                         receive_budget.byte_limit)
                if self.headers.get("Expect", "").lower() == "100-continue":
                    self.send_response_only(100)
                    self.end_headers()
                with tempfile.TemporaryFile(dir=cfg["dest"]) as raw:
                    wire_bytes = read_request_body(
                        self.rfile, self.headers, raw, receive_budget.byte_limit,
                        check_disk=True, disk_path=cfg["dest"],
                        plan=plan, deadline=deadline)
                    raw.seek(0)
                    log.info("upload %s: %d bytes dvzip (TotalBytes %s)",
                             tid, wire_bytes, self.headers.get("TotalBytes"))
                    written = store_upload(raw, cfg["dest"], tid, receive_budget)
                log.info("upload %s: stored %s", tid, ", ".join(written))
            except socket.timeout as e:
                expected = plan[1] if plan else None
                self.reject(408, f"upload {tid}: {deadline.stall_report(e, expected)}")
                return
            except (BodyTooLarge, UploadLimitError) as e:
                self.reject(413, str(e))
                return
            except RequestBodyError as e:
                self.reject(e.status, str(e))
                return
            except OSError as e:
                self.reject(507, f"storage failed: {e}")
                return
            except Exception as e:
                self.reject(422, f"upload is not a valid bounded DVZip archive: {e}")
                return
            finally:
                cfg["upload_slots"].release()
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            if cfg.get("on_upload"):
                cfg["on_upload"](tid, written)

        def log_message(self, fmt, *a):
            log.debug("%s %s", self.client_address[0], fmt % a)

    return Handler


class AirDropHTTPServer(ThreadingHTTPServer):
    """Threaded; resets idle sessions on shutdown so the port frees at once."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, *a, **k):
        self.live = set()
        super().__init__(*a, **k)

    def process_request(self, request, client_address):
        log.debug("connection from %s", client_address)
        self.live.add(request)
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        self.live.discard(request)
        super().shutdown_request(request)

    def reset_sessions(self):
        for sock in list(self.live):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack("ii", 1, 0))
                sock.close()
            except OSError:
                pass
            self.live.discard(sock)

    def handle_error(self, request, client_address):
        if isinstance(sys_exc()[1], (ConnectionResetError, HandshakeFailed)):
            return
        super().handle_error(request, client_address)


def sys_exc():
    import sys
    return sys.exc_info()


class ServerV6(AirDropHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        # Dual-stack where the platform lets us: Windows/macOS default
        # IPV6_V6ONLY=1 which would refuse every IPv4 peer on a "::" bind.
        if self.server_address[0] in ("::", None):
            with contextlib.suppress(OSError):
                self.socket.setsockopt(socket.IPPROTO_IPV6,
                                       socket.IPV6_V6ONLY, 0)
        super().server_bind()


class ServerV4(AirDropHTTPServer):
    address_family = socket.AF_INET


def tls_context(identity, visibility, want_peer_cert=False):
    """Server TLS context: our cert; CERT_NONE in everyone mode.

    In contacts mode (or when cert capture is requested) ask for a client
    certificate with CERT_OPTIONAL and trust Apple's chain: the certificate
    binds the sender's validation record to the live connection. Note that
    CERT_OPTIONAL verifies a presented cert -- a peer presenting an
    unverifiable one fails the handshake; intermediates are loaded for that.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = max(ctx.minimum_version, ssl.TLSVersion.TLSv1_1)
    identity.load_cert_chain(ctx)
    ctx.verify_mode = ssl.CERT_NONE
    if visibility != "contacts" and not want_peer_cert:
        return ctx
    root = contacts.apple_root_ca()
    if root:
        ctx.load_verify_locations(cafile=root)
    for intermediate in contacts.apple_intermediates():
        try:
            ctx.load_verify_locations(cafile=intermediate)
        except (OSError, ssl.SSLError):
            log.warning("could not load Apple intermediate %s", intermediate)
    ctx.verify_mode = ssl.CERT_OPTIONAL
    return ctx


def serve(cfg, identity, host="::", port=8771):
    """Create the listening server (does not serve yet). Returns server."""
    cfg.setdefault("upload_slots", threading.BoundedSemaphore(MAX_CONCURRENT_UPLOADS))
    cfg.setdefault("max_receive_percent", 30)
    handler = make_handler(cfg)
    cls = ServerV6 if ":" in (host or "::") else ServerV4
    server = cls((host, port), handler)
    ctx = tls_context(identity, cfg.get("visibility", "everyone"),
                      want_peer_cert=cfg.get("capture_peer_certs", False))
    server.socket = ctx.wrap_socket(server.socket, server_side=True,
                                    do_handshake_on_connect=False)
    return server
