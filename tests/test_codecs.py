"""DVZip and cpio round-trips + edge cases."""
import io
import zlib

import pytest

from airdrop_everything import cpio, dvzip


def test_dvzip_roundtrip_small():
    data = b"hello airdrop " * 100
    framed = dvzip.encode(data)
    assert framed[:4] != b"\x1f\x8b"
    assert dvzip.decode_bytes(framed) == data


def test_dvzip_roundtrip_multiblock():
    import os
    data = os.urandom(3 * dvzip.BLOCK + 17)
    framed = dvzip.encode(data)
    assert dvzip.decode_bytes(framed) == data


def test_dvzip_stored_block_for_incompressible():
    import os
    raw = os.urandom(dvzip.BLOCK)          # incompressible -> stored
    framed = dvzip.encode(raw)
    assert int.from_bytes(framed[:4], "big") & dvzip.STORED
    assert framed[4:4 + len(raw)] == raw


def test_dvzip_gzip_passthrough():
    data = b"compressed " * 500
    gz = zlib.compress(data)
    import gzip
    gz = gzip.compress(data)
    assert dvzip.decode_bytes(gz) == data


def test_dvzip_empty():
    assert dvzip.encode(b"") == b""
    assert dvzip.decode_bytes(b"") == b""


def test_dvzip_limit():
    data = b"x" * 10000
    framed = dvzip.encode(data)
    with pytest.raises(ValueError):
        dvzip.decode(io.BytesIO(framed), io.BytesIO(), byte_limit=100)


def test_dvzip_truncated():
    data = b"y" * 100
    framed = dvzip.encode(data)
    with pytest.raises(ValueError):
        dvzip.decode(io.BytesIO(framed[:-5]), io.BytesIO())


def test_cpio_roundtrip():
    buf = io.BytesIO()
    payload = b"file content " * 40
    cpio.write_newc([("./hello.txt", payload, len(payload))], buf)
    buf.seek(0)
    names, got = [], {}
    # Slices are lazy: consume during iteration, as the receiver does.
    for e, s in cpio.read(buf):
        names.append(e.name)
        got[e.name] = (e.isfile, s.read())
    assert "./hello.txt" in names
    ok, data = got["./hello.txt"]
    assert ok and data == payload


def test_cpio_roundtrip_multiple():
    buf = io.BytesIO()
    files = [("./a.txt", b"aaa", 3), ("./b.bin", bytes(range(256)) * 10, 2560),
             ("./dir", None, 0)]
    cpio.write_newc(files, buf)
    buf.seek(0)
    got = {}
    for e, s in cpio.read(buf):
        got[e.name] = s.read()
    assert got["./a.txt"] == b"aaa"
    assert got["./b.bin"] == bytes(range(256)) * 10
    assert got["./dir"] == b""


def test_cpio_rejects_garbage():
    with pytest.raises(ValueError):
        list(cpio.read(io.BytesIO(b"NOTCPIO" + b"\0" * 200)))


def test_full_wire_roundtrip():
    """cpio -> dvzip -> dvzip decode -> cpio read == original files."""
    buf = io.BytesIO()
    data = b"payload" * 1000
    cpio.write_newc([("./f.bin", data, len(data))], buf)
    wire = dvzip.encode(buf.getvalue())
    plain = io.BytesIO()
    dvzip.decode(io.BytesIO(wire), plain)
    plain.seek(0)
    got = {}
    for e, s in cpio.read(plain):
        got[e.name] = s.read()
    assert got["./f.bin"] == data
