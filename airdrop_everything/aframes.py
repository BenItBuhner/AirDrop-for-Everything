"""AWDL action-frame parsing and capture.

Port of omdrop-awdl's awdl-af-parse.py. AWDL devices periodically multicast
action frames (PSF type 0 / MIF type 3) carrying a Service Response TLV that
advertises `_airdrop._tcp` -- reading them is how a sender learns a receiver's
endpoint without waiting for mDNS (a Mac publishes nothing over mDNS until
woken, but always beacons its AWDL service records).

parse_body() input is the frame body starting at the action-frame category
byte: 7f 00 17 f2 | awdl fixed header | TLVs. listen() pulls those bodies off
a monitor interface with AF_PACKET (Linux only, root).
"""
import json
import logging
import struct
import sys
import time

from .const import AF_VENDOR_MAGIC

log = logging.getLogger("airdrop.af")

# AWDL's fixed name dictionary for the c0xx tail of a compressed name.
DICT = {0x00: "", 0x07: "_airdrop._tcp.local", 0x0A: "_tcp.local",
        0x0B: "_udp.local", 0x0C: "local"}


def name(b, off):
    """DNS-style labels with AWDL's c0xx dictionary tail -> (name, next_off)."""
    labels = []
    while off < len(b):
        l = b[off]
        if l == 0xC0:
            code = b[off + 1]
            tail = DICT.get(code, f"<c0{code:02x}>")
            if tail:
                labels.append(tail)
            return ".".join(labels), off + 2
        if l == 0:
            return ".".join(labels), off + 1
        labels.append(b[off + 1:off + 1 + l].decode("utf-8", "replace"))
        off += 1 + l
    return ".".join(labels), off


def tlvs(body):
    i = 0
    while i + 3 <= len(body):
        t = body[i]
        l = struct.unpack("<H", body[i + 1:i + 3])[0]
        yield t, body[i + 3:i + 3 + l]
        i += 3 + l


def service_response(v):
    """One Service Response TLV -> (record_name, {rtype: parsed})."""
    nlen = struct.unpack("<H", v[:2])[0]
    n, _ = name(v, 2)
    off = 2 + nlen - 1                  # name_len counts the type byte
    rtype = v[off]
    dlen = struct.unpack("<H", v[off + 1:off + 3])[0]
    rd = v[off + 5:off + 5 + dlen]      # 2 unknown bytes precede rdata
    if rtype == 12:
        val = {"ptr": name(rd, 0)[0]}
    elif rtype == 33:
        prio, weight, port = struct.unpack(">HHH", rd[:6])
        val = {"srv": {"port": port, "target": name(rd, 6)[0]}}
    elif rtype == 16:
        txt, j = [], 0
        while j < len(rd):
            l = rd[j]
            txt.append(rd[j + 1:j + 1 + l].decode("utf-8", "replace"))
            j += 1 + l
        val = {"txt": txt}
    else:
        val = {f"type{rtype}": rd.hex()}
    return n, val


def parse_body(body):
    """Frame body from the category byte -> {type, host, services{}} or None."""
    if body[:4] != AF_VENDOR_MAGIC:
        return None
    hdr = body[4:4 + 12]                # awdl_hdr_t: magic 08, ver, subtype...
    if len(hdr) < 12 or hdr[0] != 0x08:
        return None
    rec = {"type": hdr[2], "host": None, "services": {}}
    for t, v in tlvs(body[16:]):
        if t == 16 and len(v) > 1:
            rec["host"] = name(v, 1)[0]
        elif t == 2 and len(v) > 5:
            try:
                n, val = service_response(v)
            except (struct.error, IndexError):
                continue
            rec["services"].setdefault(n, {}).update(val)
    return rec


def airdrop_endpoint(rec):
    """The AirDrop receiver identity in a parsed frame, or None."""
    ptr = rec["services"].get("_airdrop._tcp.local", {}).get("ptr")
    if not ptr:
        return None
    inst = rec["services"].get(ptr) or rec["services"].get(
        f"{ptr}._airdrop._tcp.local", {})
    srv = inst.get("srv", {})
    return {"id": ptr.split(".")[0], "port": srv.get("port"),
            "target": srv.get("target"), "txt": inst.get("txt"),
            "host": rec["host"]}


def extract_body(frame):
    """Locate the action-frame body inside a raw 802.11/monitor capture.

    Scans for the vendor-specific action category + Apple OUI magic, which
    skips whatever radiotap/802.11 headers precede it. Returns (body, sa)
    where sa is the transmitter MAC when locatable, else None.
    """
    p = frame.find(AF_VENDOR_MAGIC)
    if p < 0:
        return None, None
    sa = None
    # 802.11 mgmt header is 24 bytes before the action category byte:
    # fc2 dur2 da6 sa6 bssid6 seq2 -- so the source sits at p-14 .. p-8.
    if p - 24 >= 0:
        sa = frame[p - 14:p - 8].hex(":")
    return frame[p:], sa


def listen(iface, callback=None, print_lines=False):
    """Capture AWDL action frames on an interface; parse + report records.

    Linux only (AF_PACKET). For each frame carrying Service Response or Arpa
    TLVs, calls callback(record_dict) and/or prints one JSON line in the
    awdl-af-listen format: `<epoch> <freq=0> <sa> <hexbody>` fields followed
    by the parsed record -- keeping the on-disk format compatible with the
    upstream tools that consume it.
    """
    import socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((iface, 0))
    log.info("listening for AWDL action frames on %s", iface)
    while True:
        frame = s.recv(65535)
        body, sa = extract_body(frame)
        if body is None:
            continue
        try:
            rec = parse_body(body)
        except ValueError:
            continue
        if not rec or (not rec["services"] and not rec["host"]):
            continue
        rec["sa"] = sa
        rec["ts"] = time.time()
        if print_lines:
            print(json.dumps(rec, ensure_ascii=False), flush=True)
        if callback:
            callback(rec)


def endpoints_from_log(path, want=None):
    """Newest AirDrop endpoint per source MAC from a capture log."""
    eps = {}
    import os
    if not os.path.exists(path):
        return []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            ep = airdrop_endpoint(rec)
            if ep and ep.get("port"):
                sa = rec.get("sa") or ""
                if want and ":" in want and sa.lower() != want.lower():
                    continue
                if want and len(want) == 12 and \
                        ep["id"].lower() != want.lower():
                    continue
                eps[sa] = dict(ep, ts=rec.get("ts", 0), sa=sa)
    return sorted(eps.values(), key=lambda e: -e["ts"])
