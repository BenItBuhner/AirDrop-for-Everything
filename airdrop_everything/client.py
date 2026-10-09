"""The AirDrop sender: /Discover, /Ask, /Upload over TLS.

Portable re-implementation of omdrop-awdl's airdrop-send.py:

  * browse `_airdrop._tcp` (or take a --direct endpoint / AF-log endpoint)
  * /Discover on one TLS connection, then a FRESH connection for
    /Ask -> /Upload -- sharingd tears its Discover handler down ~1 ms after
    answering, and a reused connection's /Ask is ACKed but never dispatched
  * one /Ask lists every file (the receiver prompts once), then one /Upload
    carries a DVZip-framed cpio archive of them all, chunked like sharingd

Exit semantics mirror the original: 0 sent | 2 no receiver | 3 declined |
4 upload failed -- surfaced as Python exceptions/results here.
"""
import io
import ipaddress
import logging
import os
import plistlib
import socket
import ssl
import threading
import time
import uuid
from http.client import HTTPSConnection

from . import const, dvzip, cpio
from .util import eui64_linklocal, short_hostname

log = logging.getLogger("airdrop.client")
wire = logging.getLogger("airdrop.wire")

OP_TIMEOUT = 20.0


class HTTPSConnectionScoped(HTTPSConnection):
    """HTTPS to a peer that may live at an IPv6 link-local address.

    A link-local address is ambiguous without a zone: append the interface
    (fe80::1 -> fe80::1%awdl0 / %eth0 / %<ifindex>) so the connection leaves
    through the right link.
    """

    def __init__(self, host, port, *, context, interface_name=None, timeout=None):
        if interface_name and "%" not in host:
            try:
                ip = ipaddress.ip_address(host)
                if isinstance(ip, ipaddress.IPv6Address) and ip.is_link_local:
                    host = host + "%" + interface_name
            except ValueError:
                pass
        if timeout is None:
            timeout = OP_TIMEOUT
        super().__init__(host, port, timeout=timeout, context=context)


def client_ssl_context(identity):
    """Present our certificate; verify nothing about the peer's.

    An Everyone-mode peer's certificate is self-signed, and nothing here acts
    on who signed it. (Same posture as omdrop's sender.)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = max(ctx.minimum_version, ssl.TLSVersion.TLSv1_1)
    identity.load_cert_chain(ctx)
    return ctx


class SendError(Exception):
    code = 2


class Declined(SendError):
    code = 3


class AirDropClient:
    """One receiver: /Discover, /Ask and /Upload, POSTed on a kept-alive conn."""

    def __init__(self, identity, receiver, *, interface_name=None,
                 computer_name=None, computer_model="MacBookPro18,3",
                 service_id=None, timeout=None, addresses=None):
        self.identity = identity
        if addresses:
            self._hosts = [a.split("%")[0] for a in addresses]
            self.receiver_host, self.receiver_port = self._hosts[0], receiver[1]
        else:
            self.receiver_host, self.receiver_port = receiver
            self._hosts = [self.receiver_host]
        self.interface_name = interface_name
        self.computer_name = computer_name
        self.computer_model = computer_model
        self.service_id = service_id
        self.timeout = timeout
        self.http_conn = None
        self.transfer_id = None

    # ------------------------------------------------------------------ plumbing

    def _ctx(self):
        return client_ssl_context(self.identity)

    def _connect(self):
        # An advert can carry several addresses (v4/v6/vpn); take the first
        # that actually connects instead of trusting the first listed.
        last = None
        for host in self._hosts:
            conn = HTTPSConnectionScoped(
                host, self.receiver_port,
                interface_name=self.interface_name, context=self._ctx(),
                timeout=self.timeout)
            try:
                conn.connect()
            except OSError as e:
                log.debug("connect %s:%s failed: %r", host,
                          self.receiver_port, e)
                last = e
                continue
            self.receiver_host = host
            self.http_conn = conn
            return
        raise last if last is not None else OSError("no receiver addresses")

    def post(self, path, body, headers=None):
        """POST and read the whole answer -> (status is 200, response bytes)."""
        wire.debug("POST %s", path)
        if self.http_conn is None:
            self._connect()
        self.http_conn.request("POST", path, body=body,
                               headers={**const.HTTP_HEADERS, **(headers or {})})
        resp = self.http_conn.getresponse()
        data = resp.read()
        wire.debug("%s answered %d %s", path, resp.status, resp.reason)
        return resp.status == 200, data

    def reconnect(self, timeout=None):
        """Throw the current connection away and open a fresh one.

        Required between /Discover and /Ask: sharingd dismantles the Discover
        handler while leaving the socket open, so a reused connection's Ask is
        ACKed in full and never dispatched.
        """
        if self.http_conn is not None:
            try:
                self.http_conn.close()
            except OSError:
                pass
        self._connect()      # connects eagerly, with address fallback
        if timeout:
            self.http_conn.sock.settimeout(timeout)

    def close(self):
        if self.http_conn is not None:
            try:
                self.http_conn.close()
            except OSError:
                pass
            self.http_conn = None

    # ------------------------------------------------------------------ protocol

    def send_discover(self):
        """Ask the receiver for its display name; None if it won't say."""
        body = {"DeviceSupportFlags": const.DEVICE_SUPPORT_FLAGS}
        if self.identity.record_data:
            body["SenderRecordData"] = self.identity.record_data
        ok, resp = self.post("/Discover", plistlib.dumps(body, fmt=plistlib.FMT_BINARY))
        if not ok:
            return None
        try:
            pl = plistlib.loads(resp)
        except Exception:
            return None
        return pl.get("ReceiverComputerName")

    def send_ask(self, files, *, auth_tag=None, icon=True, ask_timeout=90):
        """Propose the transfer; True if the receiver accepted."""
        entries = []
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            entries.append({
                "FileName": os.path.basename(f),
                "FileType": const.UTI_BY_EXT.get(ext, const.DEFAULT_UTI),
                "FileSize": os.path.getsize(f),
                "FileBomPath": os.path.join(".", os.path.basename(f)),
                "FileIsDirectory": False,
                "ConvertMediaFormats": False,
            })
        self.transfer_id = str(uuid.uuid4()).upper()
        body = {
            "TransferID": {"id": self.transfer_id},
            "TransferType": {"files": {}},
            "SenderID": self.service_id or "",
            "BundleID": const.BUNDLE_ID,
            "SenderComputerName": self.computer_name or short_hostname(),
            "SenderModelName": self.computer_model,
            "Items": [],
            "Files": entries,
            "ConvertMediaFormats": False,
        }
        if self.identity.record_data:
            body["SenderRecordData"] = self.identity.record_data
        if auth_tag:
            body["SenderIdentityAuthTag"] = bytes.fromhex(auth_tag)
        if icon:
            thumb = self._thumbnail(files[0])
            if thumb:
                body["FileIcon"] = thumb
        ok, _ = self.post("/Ask", plistlib.dumps(body, fmt=plistlib.FMT_BINARY))
        return ok

    def send_upload(self, files):
        """DVZip-framed cpio archive of the files, chunked like sharingd."""
        stream = io.BytesIO()
        entries = []
        for f in files:
            entries.append((f"./{os.path.basename(f)}", open(f, "rb"),
                            os.path.getsize(f)))
        try:
            cpio.write_newc(entries, stream)
        finally:
            for _, fh, _ in entries:
                if hasattr(fh, "close"):
                    fh.close()
        body = dvzip.encode(stream.getvalue())
        headers = {
            "Content-Type": const.UPLOAD_CONTENT_TYPE,
            "TotalBytes": str(sum(os.path.getsize(f) for f in files)),
            "TransferID": self.transfer_id or str(uuid.uuid4()).upper(),
        }
        ok, _ = self.post("/Upload", io.BytesIO(body), headers=headers)
        return ok

    @staticmethod
    def _thumbnail(path):
        try:
            from PIL import Image
            im = Image.open(path)
            im.thumbnail((240, 240))
            buf = io.BytesIO()
            im.convert("RGB").save(buf, "JPEG", quality=80)
            return buf.getvalue()
        except Exception:
            return None


def send_files(files, receiver, identity, *, interface_name=None,
               computer_name=None, computer_model="MacBookPro18,3",
               service_id=None, auth_tag=None, ask_timeout=90,
               progress=None):
    """Full send to (host, port): Discover, fresh conn, Ask, Upload.

    Returns the receiver's display name (or None). Raises Declined on a 403
    at /Ask, SendError for transport failures.
    """
    client = AirDropClient(identity, receiver, interface_name=interface_name,
                           computer_name=computer_name,
                           computer_model=computer_model, service_id=service_id)
    try:
        name = client.send_discover()
        if progress:
            progress("discover", name)
        client.reconnect(timeout=ask_timeout)
        if not client.send_ask(files, auth_tag=auth_tag, ask_timeout=ask_timeout):
            raise Declined("the receiver declined the transfer")
        if progress:
            progress("accepted", name)
        if not client.send_upload(files):
            raise SendError("upload failed")
        if progress:
            progress("sent", name)
        return name
    finally:
        client.close()


class AirDropBrowser:
    """Browse `_airdrop._tcp` over zeroconf on the given interfaces.

    interfaces: list of addresses or interface names zeroconf understands
    (e.g. ['10.0.0.5'] or InterfaceChoice.Default), plus ip_version.
    """

    def __init__(self, interfaces=None, ip_version=None):
        from zeroconf import IPVersion, Zeroconf
        if ip_version is None:
            ip_version = IPVersion.V6Only if _v6_only(interfaces) else IPVersion.All
        kwargs = {}
        if interfaces:
            kwargs["interfaces"] = interfaces
        self.zeroconf = Zeroconf(ip_version=ip_version, **kwargs)
        self.browser = None

    def start(self, callback_add):
        from zeroconf import ServiceBrowser, ServiceStateChange

        def changed(zeroconf, service_type, name, state_change):
            if state_change is ServiceStateChange.Added:
                wire.debug("mDNS: %s appeared", name)
                try:
                    callback_add(zeroconf.get_service_info(service_type, name))
                except Exception as e:
                    wire.debug("service info failed for %s: %r", name, e)

        self.browser = ServiceBrowser(self.zeroconf, const.SERVICE_TYPE,
                                      handlers=[changed])

    def stop(self):
        try:
            if self.browser:
                self.browser.cancel()
        finally:
            self.zeroconf.close()


def _v6_only(interfaces):
    if not interfaces:
        return False
    for i in interfaces:
        try:
            if not isinstance(ipaddress.ip_address(str(i).split("%")[0]),
                              ipaddress.IPv6Address):
                return False
        except ValueError:
            return False
    return True


class Finder:
    """Browse mDNS until a suitable receiver answers /Discover.

    want: optional matcher -- 12-hex service id, 'aa:bb:..' MAC (matched via
    EUI-64 link-local), or substring of the receiver's announced name.
    `first` wins: Apple's own sender picks the first discoverable receiver.
    """

    def __init__(self, identity, *, interfaces=None, interface_name=None,
                 ip_version=None, want=None, computer_name=None,
                 computer_model="MacBookPro18,3", service_id=None,
                 on_peer=None):
        self.identity = identity
        self.interfaces = interfaces
        self.interface_name = interface_name
        self.ip_version = ip_version
        self.want = want
        self.computer_name = computer_name
        self.computer_model = computer_model
        self.service_id = service_id
        self.on_peer = on_peer            # called for every discovered peer
        self.found = threading.Event()
        self.chosen = {}
        self.lock = threading.Lock()
        self.seen = {}                    # ident -> {"name":..,"addr":..}

    def _match(self, info):
        ident = info.name.split(".")[0]
        addrs = info.parsed_addresses()
        props = {k.decode(): (v.decode(errors="replace") if isinstance(v, bytes) else v)
                 for k, v in (info.properties or {}).items() if v is not None}
        log.info("advert %s host=%s port=%s addr=%s flags=%s",
                 ident, info.server, info.port, addrs, props.get("flags"))
        if not addrs:
            return
        want = self.want
        if want and len(want) == 12 and want.lower() != ident.lower():
            return
        if want and ":" in want:
            try:
                want_ll = ipaddress.IPv6Address(eui64_linklocal(want))
                ll = [ipaddress.IPv6Address(a.split("%")[0]) for a in addrs]
                if want_ll not in ll:
                    return
            except ValueError:
                pass
        flags = int(props.get("flags", const.SUPPORTS_DISCOVER_MAYBE))
        if not flags & const.SUPPORTS_DISCOVER_MAYBE:
            log.info("%s: no /Discover support (flags %#x); skipping", ident, flags)
            return
        client = AirDropClient(
            self.identity, (addrs[0], int(info.port)), addresses=addrs,
            interface_name=self.interface_name,
            computer_name=self.computer_name,
            computer_model=self.computer_model, service_id=self.service_id)
        try:
            name = client.send_discover()
        except Exception as e:
            log.info("DISCOVER %s failed: %r", ident, e)
            client.close()
            return
        self.seen[ident] = {"name": name, "addr": addrs[0],
                            "port": int(info.port)}
        if self.on_peer:
            try:
                self.on_peer(ident, name, addrs[0], int(info.port))
            except Exception:
                pass
        if want and len(want) != 12 and ":" not in want and \
                (name is None or want.lower() not in name.lower()):
            client.close()
            return
        if name is None:
            client.close()
            return
        with self.lock:
            if self.found.is_set():
                client.close()
                return
            self.chosen.update(ident=ident, name=name, client=client,
                               addr=addrs[0], port=int(info.port))
            self.found.set()

    def run(self, timeout):
        """Browse for `timeout` seconds; returns chosen peer dict or None."""
        browser = AirDropBrowser(interfaces=self.interfaces,
                                 ip_version=self.ip_version)
        try:
            browser.start(self._match)
            self.found.wait(timeout)
        finally:
            browser.stop()
        return self.chosen or None
