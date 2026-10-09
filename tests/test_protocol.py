"""Protocol-level tests: plists, BLE payload, AF parser, safe_name, contacts."""
import io
import plistlib
import struct

import pytest

from airdrop_everything import aframes, ble, const, contacts, discovery, util
from airdrop_everything.util import safe_name


def test_safe_name():
    assert safe_name("photo.jpg") == "photo.jpg"
    assert safe_name("a/b/c.txt") == "c.txt"
    assert safe_name("..\\evil") == "evil"
    assert safe_name("\x00bad") == "bad"
    assert safe_name("") == "file"
    assert safe_name(".hidden") == "hidden"


def test_eui64():
    assert util.eui64_linklocal("aa:bb:cc:dd:ee:ff") == \
        "fe80::a8bb:ccff:fedd:eeff"


def test_ble_payload_arm_a():
    value, tag = ble.build_payload(arm="A", tag=b"\xaa\xbb\xcc")
    assert value[:2] == bytes([0x05, 0x12])
    assert len(value) == 20
    body = value[2:]
    assert body[0] == 0x40
    assert body[1:4] == b"\xaa\xbb\xcc"
    assert body[8] == 0x03
    assert body[-1] == 0x00
    assert len(body) == 18


def test_ble_payload_arms():
    for arm, marker in (("V2", 0x02), ("B", 0x01)):
        value, _ = ble.build_payload(arm=arm)
        assert value[2 + 8] == marker


def test_mdns_announcement_records():
    from airdrop_everything.discovery import build_announcement, _dname
    ll = bytes.fromhex("fe800000000000000000000000000001")
    pkt = build_announcement("aabbccddeeff", "test.local", 8771, 0x89, ll)
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", pkt[:12])
    assert flags == 0x8400 and qd == 0 and an == 4
    assert b"_airdrop" in pkt
    assert b"flags=137" in pkt


def test_af_parse_fixture():
    """A minimal AWDL MIF with PTR+SRV for _airdrop._tcp parses to an endpoint."""
    def tlv(t, v):
        return bytes([t]) + len(v).to_bytes(2, "little") + v

    def svc_resp(rr_name, rtype, rdata):
        # rr_name is the raw encoded owner name (dict-compressed tail allowed)
        nlen = len(rr_name) + 1
        return nlen.to_bytes(2, "little") + rr_name + bytes([rtype]) + \
            len(rdata).to_bytes(2, "little") + b"\x00\x00" + rdata

    # owner "_airdrop._tcp.local" == dict tail c0 07 alone
    ptr_rd = bytes([4]) + b"peer" + b"\xc0\x07"                    # peer._airdrop._tcp.local
    srv_rd = struct.pack(">HHH", 0, 0, 8771) + bytes([8]) + b"peerhost" + b"\xc0\x0c"

    body = const.AF_VENDOR_MAGIC + bytes([0x08, 0x10, 0x03]) + bytes(9)
    body += tlv(2, svc_resp(b"\xc0\x07", 12, ptr_rd))
    body += tlv(2, svc_resp(bytes([4]) + b"peer" + b"\xc0\x07", 33, srv_rd))

    rec = aframes.parse_body(body)
    assert rec is not None and rec["type"] == 0x03
    ep = aframes.airdrop_endpoint(rec)
    assert ep and ep["port"] == 8771 and ep["id"] == "peer"


def test_extract_body_from_frame():
    hdr = b"\x00" * 24  # fake radiotap+802.11 hdr
    body = const.AF_VENDOR_MAGIC + bytes([0x08, 0x10, 0x00]) + bytes(9)
    found, sa = aframes.extract_body(hdr + b"\xde\xad\xbe\xef\x00\x01" + b"\0\0" + body)
    assert found == body
    # sa is extracted from the fixed 802.11 header offset when present


def test_contacts_normalize():
    assert contacts.normalize("  +1 (234) 567-8901 ") == "12345678901"
    assert contacts.normalize("Me@Example.COM") == "me@example.com"
    assert contacts.normalize("# comment") is None
    assert contacts.normalize("") is None


def test_contacts_decide_no_record():
    outcome, _ = contacts.decide(None, None, known=set())
    assert outcome == contacts.REJECT_NO_RECORD


def test_ask_plist_shape():
    """The /Ask body keys a real receiver parses (from airdrop-send.py)."""
    import uuid
    tid = str(uuid.uuid4()).upper()
    body = {
        "TransferID": {"id": tid},
        "TransferType": {"files": {}},
        "SenderID": "aabbccddeeff",
        "BundleID": const.BUNDLE_ID,
        "SenderComputerName": "test",
        "SenderModelName": "MacBookPro18,3",
        "Items": [],
        "Files": [{
            "FileName": "f.txt", "FileType": "public.plain-text",
            "FileSize": 5, "FileBomPath": "./f.txt",
            "FileIsDirectory": False, "ConvertMediaFormats": False}],
        "ConvertMediaFormats": False,
    }
    blob = plistlib.dumps(body, fmt=plistlib.FMT_BINARY)
    back = plistlib.loads(blob)
    assert back["TransferID"]["id"] == tid
    assert back["Files"][0]["FileName"] == "f.txt"
