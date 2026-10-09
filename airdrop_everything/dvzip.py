"""DVZip codec -- the framing AirDrop's /Upload uses inside HTTPS.

The body is a sequence of 64 KiB blocks; each is preceded by a 4-byte
big-endian header whose low 31 bits give the block's payload length and whose
high bit marks a *stored* (uncompressed) block. A block is stored when zlib
fails to shrink it -- real senders do this for incompressible media.

sharingd also tolerates a plain gzip stream (magic 1f 8b) in place of the
framed form, which is what OpenDrop sends; we decode both.
"""
import zlib

BLOCK = 1 << 16
STORED = 0x80000000
GZIP_MAGIC = b"\x1f\x8b"


def encode(data, block=BLOCK):
    """bytes -> dvzip-framed bytes."""
    out = bytearray()
    for i in range(0, len(data), block):
        raw = data[i:i + block]
        z = zlib.compress(raw, 6)
        if len(z) < len(raw):
            out += len(z).to_bytes(4, "big") + z
        else:
            out += (STORED | len(raw)).to_bytes(4, "big") + raw
    return bytes(out)


def encode_stream(source, out, block=BLOCK):
    """Read source fully, writing dvzip to out; returns (wire, raw) lengths."""
    wire = raw = 0
    while True:
        chunk = source.read(block)
        if not chunk:
            return wire, raw
        raw += len(chunk)
        z = zlib.compress(chunk, 6)
        if len(z) < len(chunk):
            out.write(len(z).to_bytes(4, "big") + z)
            wire += 4 + len(z)
        else:
            out.write((STORED | len(chunk)).to_bytes(4, "big") + chunk)
            wire += 4 + len(chunk)


def decode(source, target, byte_limit=None):
    """Stream a dvzip (or gzip) body from source into target.

    source/target are binary file objects. Returns the decompressed byte
    count. Raises ValueError on malformed framing.
    """
    total = 0
    pos = source.tell() if hasattr(source, "tell") else None
    magic = source.read(2)
    if pos is not None:
        source.seek(pos)
    if magic == GZIP_MAGIC:
        d = zlib.decompressobj(31)
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            total = _emit(d, chunk, target, total, byte_limit)
            if d.unused_data:
                raise ValueError("gzip body has trailing data")
        tail = d.flush()
        if not d.eof:
            raise ValueError("truncated gzip body")
        total = _write(target, tail, total, byte_limit)
        return total

    while True:
        header = source.read(4)
        if not header:
            return total
        if len(header) != 4:
            raise ValueError(f"truncated DVZip block header: {len(header)} bytes")
        value = int.from_bytes(header, "big")
        size = value & 0x7FFFFFFF
        if value & STORED:
            left = size
            while left:
                data = source.read(min(left, 65536))
                if not data:
                    raise ValueError(f"truncated stored block: {left} bytes missing")
                total = _write(target, data, total, byte_limit)
                left -= len(data)
        else:
            d = zlib.decompressobj()
            left = size
            while left:
                data = source.read(min(left, 65536))
                if not data:
                    raise ValueError(
                        f"truncated compressed block: {left} bytes missing")
                left -= len(data)
                total = _emit(d, data, target, total, byte_limit)
                if d.unused_data:
                    raise ValueError("compressed block has trailing data")
            tail = d.flush()
            if not d.eof:
                raise ValueError("truncated compressed block")
            total = _write(target, tail, total, byte_limit)


def decode_bytes(data):
    """bytes -> decompressed bytes (small inputs, tests)."""
    import io
    out = io.BytesIO()
    decode(io.BytesIO(data), out)
    return out.getvalue()


def _write(target, data, total, limit):
    if data:
        if limit is not None and total + len(data) > limit:
            raise ValueError("decompressed body exceeds byte limit")
        target.write(data)
        total += len(data)
    return total


def _emit(decoder, data, target, total, limit):
    while data:
        room = None if limit is None else max(0, limit - total + 1)
        want = 65536 if room is None else min(65536, room)
        out = decoder.decompress(data, want)
        total = _write(target, out, total, limit)
        if decoder.unconsumed_tail:
            data = decoder.unconsumed_tail
        else:
            return total
    return total
