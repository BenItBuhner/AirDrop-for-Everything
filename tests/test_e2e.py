"""End-to-end loopback: real TLS server + real client on 127.0.0.1.

These run on any platform -- no AWDL, mDNS or hardware needed. The mDNS
discovery path is exercised separately on machines with a multicast-capable
loopback.
"""
import io
import plistlib
import threading

import pytest

from airdrop_everything import identity, server
from airdrop_everything.client import AirDropClient, Declined, send_files


@pytest.fixture
def receiver(tmp_path):
    dest = tmp_path / "dl"
    dest.mkdir()
    ident = identity.resolve(keys=str(tmp_path / "keys"),
                             computer_name="TestBox")
    cfg = {
        "name": "TestBox", "model": "MacBookPro18,3",
        "dest": str(dest), "visibility": "everyone",
        "record_data": b"", "on_ask": None, "on_upload": None,
    }
    srv = server.serve(cfg, ident, host="127.0.0.1", port=0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield ident, port, dest, cfg
    srv.reset_sessions()
    srv.server_close()


def _client(ident, port, **kw):
    return AirDropClient(ident, ("127.0.0.1", port),
                         computer_name="Sender", service_id="aabbccddeeff",
                         **kw)


def test_discover(receiver):
    ident, port, _, _ = receiver
    c = _client(ident, port)
    try:
        assert c.send_discover() == "TestBox"
    finally:
        c.close()


def test_send_files_roundtrip(receiver, tmp_path):
    ident, port, dest, _ = receiver
    src = tmp_path / "photo.bin"
    payload = b"\x89PNG" + bytes(range(256)) * 20
    src.write_bytes(payload)
    name = send_files([str(src)], ("127.0.0.1", port), ident,
                      computer_name="Sender")
    assert name == "TestBox"
    assert (dest / "photo.bin").read_bytes() == payload


def test_no_clobber(receiver, tmp_path):
    ident, port, dest, _ = receiver
    src = tmp_path / "dup.txt"
    src.write_bytes(b"first")
    send_files([str(src)], ("127.0.0.1", port), ident)
    src.write_bytes(b"second")
    send_files([str(src)], ("127.0.0.1", port), ident)
    assert (dest / "dup.txt").read_bytes() == b"first"
    assert (dest / "dup-1.txt").read_bytes() == b"second"


def test_declined(receiver, tmp_path):
    ident, port, dest, cfg = receiver
    cfg["on_ask"] = lambda ask: False
    src = tmp_path / "nope.txt"
    src.write_bytes(b"x")
    with pytest.raises(Declined):
        send_files([str(src)], ("127.0.0.1", port), ident)
    assert not (dest / "nope.txt").exists()


def test_ask_payload_shape(receiver, tmp_path, monkeypatch):
    ident, port, _dest, cfg = receiver
    seen = {}
    cfg["on_ask"] = lambda ask: seen.update(ask) or True
    src = tmp_path / "doc.txt"
    src.write_bytes(b"body")
    send_files([str(src)], ("127.0.0.1", port), ident,
               computer_name="Sender")
    f = seen["Files"][0]
    assert f["FileName"] == "doc.txt" and f["FileSize"] == 4
    assert seen["SenderComputerName"] == "Sender"


def test_bad_body_rejected(receiver):
    ident, port, dest, _ = receiver
    c = _client(ident, port)
    try:
        ok, _ = c.post("/Upload", io.BytesIO(b"not a dvzip at all"),
                       headers={"Content-Type": "application/x-dvzip"})
        assert not ok
    finally:
        c.close()
    assert not list(dest.iterdir())


def test_discover_via_plist(receiver):
    """/Discover returns a binary plist with our name and model."""
    ident, port, _, _ = receiver
    c = _client(ident, port)
    try:
        ok, resp = c.post("/Discover", plistlib.dumps(
            {"DeviceSupportFlags": 0}, fmt=plistlib.FMT_BINARY))
        assert ok
        pl = plistlib.loads(resp)
        assert pl["ReceiverComputerName"] == "TestBox"
        assert "ReceiverMediaCapabilities" in pl
    finally:
        c.close()
