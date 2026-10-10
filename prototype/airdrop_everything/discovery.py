"""mDNS advertisement and browsing for _airdrop._tcp.

Two paths:

  * zeroconf -- the portable path, works on every OS and on OWL's awdl0 tap
  * raw      -- Linux AF_PACKET unsolicited announcements + a query responder,
    mirroring omdrop-awdl's awdl-airdrop-adv.py / awdl-mdns-respond.py. Raw
    matters on the AWDL interface because multicast-to-air is unreliable and
    periodic bursts are what actually reach an iPhone.
"""
import logging
import socket
import struct
import time

from . import const

log = logging.getLogger("airdrop.mdns")


# ------------------------------------------------------------ zeroconf path

def make_service_info(host_label, service_id, port, flags, addresses):
    """The four-record set an AirDrop receiver advertises:
    PTR _airdrop._tcp.local -> <sid>._airdrop._tcp.local
    SRV <sid>._airdrop._tcp.local -> 0 0 <port> <host>.local
    TXT <sid>._airdrop._tcp.local -> flags=<n>
    + address records for <host>.local (AAAA and/or A).
    """
    from zeroconf import ServiceInfo
    props = {b"flags": str(flags).encode()}
    return ServiceInfo(
        const.SERVICE_TYPE,
        f"{service_id}.{const.SERVICE_TYPE}",
        server=f"{host_label}.local.",
        port=port,
        properties=props,
        parsed_addresses=[str(a).split("%")[0] for a in addresses],
    )


class ZeroconfAnnouncer:
    """Advertise on a set of interfaces; re-announce periodically.

    interfaces=None -> all interfaces zeroconf can use (the LAN default).
    """

    def __init__(self, host_label, service_id, port, flags, interfaces=None,
                 ip_version=None, reannounce=0):
        from zeroconf import IPVersion, Zeroconf
        self.info_kwargs = dict(host_label=host_label, service_id=service_id,
                                port=port, flags=flags)
        self._addresses = interfaces
        kwargs = {}
        if interfaces:
            kwargs["interfaces"] = interfaces
        self.zeroconf = Zeroconf(
            ip_version=ip_version or IPVersion.All, **kwargs)
        self.reannounce = reannounce
        self.info = None
        self._stop = False
        self._thread = None

    def start(self, addresses):
        self.info = make_service_info(addresses=addresses, **self.info_kwargs)
        self.zeroconf.register_service(self.info)
        if self.reannounce:
            self._thread = threading_reannounce(self)
        return self

    def stop(self):
        self._stop = True
        try:
            if self.info:
                self.zeroconf.unregister_service(self.info)
        except Exception:
            pass
        self.zeroconf.close()


def threading_reannounce(ann):
    import threading
    def loop():
        while not ann._stop:
            time.sleep(ann.reannounce)
            if ann._stop or not ann.info:
                return
            try:
                ann.zeroconf.unregister_service(ann.info)
                ann.zeroconf.register_service(ann.info)
            except Exception as e:
                log.debug("reannounce: %r", e)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


# ------------------------------------------------------ raw AWDL (Linux) path
#
# Direct ports of omdrop-awdl's announcer and responder: unsolicited
# authoritative mDNS responses in plain Ethernet-II frames (OWL adds the AWDL
# SNAP encapsulation itself), with a burst cadence because frames outside our
# active slots are dropped.

CACHE_FLUSH = 0x8001


def _dname(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def _rr(name, rtype, rclass, ttl, rdata):
    return _dname(name) + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def _csum16(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_announcement(service_id, host, port, flags, ll_addr16):
    """The unsolicited mDNS response packet (PTR+SRV+TXT+AAAA), DNS-form."""
    svc = const.SERVICE_TYPE
    inst = f"{service_id}.{svc}"
    txt = f"flags={flags}".encode()
    ans = (
        _rr(svc, 12, 0x0001, 4500, _dname(inst)) +
        _rr(inst, 33, CACHE_FLUSH, 120,
            struct.pack("!HHH", 0, 0, port) + _dname(host)) +
        _rr(inst, 16, CACHE_FLUSH, 4500, bytes([len(txt)]) + txt) +
        _rr(host, 28, CACHE_FLUSH, 120, ll_addr16)
    )
    return struct.pack("!HHHHHH", 0, 0x8400, 0, 4, 0, 0) + ans


def build_udp6(src16, dst16, payload):
    udp_len = 8 + len(payload)
    pseudo = src16 + dst16 + struct.pack("!IHBB", udp_len, 0, 0, 17)
    ck = _csum16(pseudo + struct.pack("!HHH", const.MDNS_PORT, const.MDNS_PORT,
                                      udp_len) + b"\0\0" + payload)
    udp = struct.pack("!HHHH", const.MDNS_PORT, const.MDNS_PORT, udp_len,
                      ck or 0xFFFF)
    ip6 = struct.pack("!IHBB", 0x60000000, udp_len, 17, 255) + src16 + dst16
    return ip6 + udp + payload


def wrap_eth(mac6, payload, snap=False, seq=0):
    """Ethernet frame to the mDNS multicast group (33:33:00:00:00:fb).

    snap=False -> plain Ethernet II + IPv6 (what OWL's awdl0 wants: it adds
    the AWDL SNAP encapsulation itself). snap=True -> Apple's AWDL SNAP
    wrapping, for interfaces that need it already applied.
    """
    dst = b"\x33\x33\x00\x00\x00\xfb"
    if not snap:
        return dst + mac6 + b"\x86\xdd" + payload
    body = (b"\xaa\xaa\x03" + const.AWDL_SNAP_OUI + const.AWDL_SNAP_PROTO +
            const.AWDL_SNAP_MAGIC + struct.pack("<H", seq) + b"\x00\x00" +
            b"\x86\xdd" + payload)
    return dst + mac6 + struct.pack("!H", len(body)) + body


class RawAnnouncer:
    """Periodic unsolicited _airdrop._tcp announcements over AF_PACKET.

    Linux only. Plain Ethernet-II on the AWDL interface (OWL encapsulates);
    the burst cadence is what makes multicast actually reach the air.
    """

    def __init__(self, iface, mac, service_id, host, port, flags,
                 interval=3.0, burst=3, burst_gap=0.05):
        self.iface = iface
        self.mac = mac
        self.service_id = service_id
        self.host = host
        self.port = port
        self.flags = flags
        self.interval = interval
        self.burst = burst
        self.burst_gap = burst_gap
        self._stop = False
        self._thread = None

    def _payload(self):
        from .util import eui64_linklocal
        ll = socket.inet_pton(socket.AF_INET6, eui64_linklocal(self.mac))
        dst6 = socket.inet_pton(socket.AF_INET6, const.MDNS_GROUP6)
        msg = build_announcement(self.service_id, self.host, self.port,
                                 self.flags, ll)
        return build_udp6(ll, dst6, msg)

    def _loop(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((self.iface, 0))
        except (OSError, AttributeError) as e:
            log.warning("raw announcer on %s unavailable: %s", self.iface, e)
            return
        payload = self._payload()
        seq = 0
        log.info("%s: announcing %s._airdrop._tcp.local -> %s:%d flags=0x%x",
                 self.iface, self.service_id, self.host, self.port, self.flags)
        while not self._stop:
            for i in range(self.burst):
                try:
                    s.send(wrap_eth(self.mac, payload, seq=(seq + i) & 0xFFFF))
                except OSError as e:
                    log.debug("announce send: %s", e)
                if i + 1 < self.burst:
                    time.sleep(self.burst_gap)
            seq += self.burst
            for _ in range(int(self.interval / 0.1) or 1):
                if self._stop:
                    break
                time.sleep(0.1)
        s.close()

    def start(self):
        import threading
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop = True
        if self._thread:
            self._thread.join(timeout=2)


class RawResponder:
    """Answer mDNS queries for our AirDrop identity on the AWDL interface.

    A peer's sharingd resolves our SRV target over mDNS; on AWDL the
    unsolicited announcements alone don't cover the gap, so answer queries
    naming our host/service/instance with the same record set. One reply per
    query burst. Linux only.
    """

    ETH_P_ALL = 0x0003
    ETH_P_IPV6 = 0x86DD

    def __init__(self, iface, mac, service_id, host, port, flags,
                 min_gap=0.1, burst=5):
        self.iface = iface
        self.mac = mac
        self.service_id = service_id
        self.host = host
        self.port = port
        self.flags = flags
        self.min_gap = min_gap
        self.burst = burst
        self._stop = False
        self._thread = None

    def _payload(self):
        from .util import eui64_linklocal
        ll = socket.inet_pton(socket.AF_INET6, eui64_linklocal(self.mac))
        dst6 = socket.inet_pton(socket.AF_INET6, const.MDNS_GROUP6)
        msg = build_announcement(self.service_id, self.host, self.port,
                                 self.flags, ll)
        # NSEC: we own the name but have no A record (RFC 6762 6.1), so a
        # querier asking for A stops waiting for one.
        nsec = _rr(self.host, 47, CACHE_FLUSH, 120,
                   _dname(self.host) + b"\x00\x06" +
                   bytes([0, 0, 0, 0x08, 0, 0x01]))
        ancount = struct.unpack("!H", msg[6:8])[0] + 1
        msg = msg[:6] + struct.pack("!H", ancount) + msg[8:] + nsec
        return build_udp6(ll, dst6, msg)

    def _loop(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(self.ETH_P_ALL))
            s.bind((self.iface, 0))
        except (OSError, AttributeError) as e:
            log.warning("raw responder on %s unavailable: %s", self.iface, e)
            return
        payload = self._payload()
        ours = {self.host.lower().rstrip("."), const.SERVICE_TYPE,
                f"{self.service_id}.{const.SERVICE_TYPE}".lower()}
        last = 0.0
        seq = 0x4000
        while not self._stop:
            try:
                frame = s.recv(4096)
            except OSError:
                return
            got = _mdns_payload(frame)
            if not got:
                continue
            src, dns = got
            if src == self.mac:
                continue
            hit = [q for q in _questions(dns) if q in ours]
            if not hit:
                continue
            now = time.time()
            if now - last < self.min_gap:
                continue
            try:
                for i in range(self.burst):
                    s.send(wrap_eth(self.mac, payload, seq=(seq + i) & 0xFFFF))
                    if i + 1 < self.burst:
                        time.sleep(0.02)
            except OSError as e:
                log.debug("respond send: %s", e)
                continue
            seq += self.burst
            last = now
            log.info("query from %s for %s -> answered", src.hex(":"), hit[0])

    def start(self):
        import threading
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop = True
        if self._thread:
            self._thread.join(timeout=2)


def _dns_name(pkt, off):
    labels = []
    nxt = None
    hops = 0
    while True:
        if off >= len(pkt):
            raise ValueError("truncated name")
        n = pkt[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if nxt is None:
                nxt = off + 2
            off = ((n & 0x3F) << 8) | pkt[off + 1]
            hops += 1
            if hops > 16:
                raise ValueError("compression loop")
            continue
        labels.append(pkt[off + 1:off + 1 + n].decode("ascii", "replace").lower())
        off += 1 + n
    return ".".join(labels), (nxt if nxt is not None else off)


def _questions(dns):
    if len(dns) < 12:
        return []
    flags, qd = struct.unpack("!HH", dns[2:6])
    if flags & 0x8000 or qd == 0:
        return []
    out, off = [], 12
    try:
        for _ in range(qd):
            name, off = _dns_name(dns, off)
            off += 4
            out.append(name)
    except ValueError:
        return []
    return out


def _mdns_payload(frame):
    """(src_mac, dns bytes) for an IPv6/UDP/5353 frame, plain or SNAP; else None."""
    if len(frame) < 14:
        return None
    src = frame[6:12]
    etype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if etype == RawResponder.ETH_P_IPV6:
        pass
    elif etype <= 1500 and frame[14:17] == b"\xaa\xaa\x03":
        if frame[17:22] != const.AWDL_SNAP_OUI + const.AWDL_SNAP_PROTO \
                or frame[28:30] != b"\x86\xdd":
            return None
        off = 30
    else:
        return None
    ip6 = frame[off:off + 40]
    if len(ip6) < 40 or ip6[6] != 17:
        return None
    udp = frame[off + 40:off + 48]
    if len(udp) < 8 or struct.unpack("!H", udp[2:4])[0] != const.MDNS_PORT:
        return None
    return src, frame[off + 48:]
