"""Pick which link the AirDrop stack runs on.

Three real link layers exist:

  awdl    Apple's Wireless Direct Link. On macOS the awdl0 interface exists
          natively while Wi-Fi is up; on Linux it's created by OWL
          (radio_owl.py) or the brcmfmac-awdl driver. AirDrop between Apple
          devices only ever happens here.
  lan     Any ordinary IP network -- Ethernet, Wi-Fi infrastructure, VPN,
          loopback. Our own devices find and talk to each other here, and a
          Mac with `BrowseAllInterfaces` enabled (or running our stack) can
          too. This is the fallback when AWDL can't run.
  auto    awdl0 when it exists with an IPv6 link-local, else lan.

Windows and Android can't do AWDL without exotic hardware (no monitor-mode +
frame injection drivers), so `auto` resolves to lan there.
"""
import ipaddress
import logging
import socket
import sys

from .util import first_ipv6, iface_mac, platform_name, short_hostname

log = logging.getLogger("airdrop.transport")

AWDL_IFACE = "awdl0"


class Transport:
    """Where the server binds and what mDNS advertises on."""

    def __init__(self, mode, iface=None, bind_addr=None, addrs=None,
                 mac=None, raw_ok=False):
        self.mode = mode                    # 'awdl' or 'lan'
        self.iface = iface                  # interface name or None (all)
        self.bind_addr = bind_addr          # address the HTTP server binds
        self.addrs = addrs or []            # advertised addresses
        self.mac = mac                      # -> default service id
        self.raw_ok = raw_ok                # AF_PACKET announcer available
        self.scope = None

    @property
    def service_id(self):
        return self.mac.hex() if self.mac else f"{id(self) & 0xffffff:012x}"

    def describe(self):
        if self.mode == "awdl":
            return f"AWDL on {self.iface} ({self.bind_addr})"
        if self.iface:
            return f"LAN on {self.iface} ({self.bind_addr})"
        return "LAN on all interfaces"


def iface_has_ipv6(iface):
    return first_ipv6(iface) is not None


def awdl_available():
    """True when an awdl0 interface exists and carries a link-local."""
    try:
        socket.if_nametoindex(AWDL_IFACE)
    except OSError:
        return False
    return iface_has_ipv6(AWDL_IFACE)


def default_addrs():
    """Best addresses to advertise on LAN: all non-loopback IPv6+v4."""
    out = []
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            st = psutil.net_if_stats().get(name)
            if st and not st.isup:
                continue
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith("127."):
                    out.append(a.address)
                elif a.family == socket.AF_INET6:
                    ip = a.address.split("%")[0]
                    if not ip.startswith("::1") and ip != "::":
                        out.append(ip)
    except ImportError:
        pass
    if not out:
        # Fallback: primary source address toward a public IP (no traffic sent)
        for target, fam in (("192.0.2.1", socket.AF_INET), ("2001:db8::1", socket.AF_INET6)):
            try:
                s = socket.socket(fam, socket.SOCK_DGRAM)
                s.connect((target, 80))
                out.append(s.getsockname()[0])
                s.close()
            except OSError:
                pass
    return out


def pick(iface_arg="auto"):
    """Resolve the transport for a user-supplied --iface value.

    iface_arg: 'auto' (default), 'lan', 'awdl'/'awdl0', or an interface name.
    """
    plat = platform_name()
    if iface_arg == "auto":
        if awdl_available():
            return _awdl_transport(AWDL_IFACE)
        return _lan_transport(None)
    if iface_arg in ("awdl", AWDL_IFACE):
        return _awdl_transport(AWDL_IFACE)
    if iface_arg == "lan":
        return _lan_transport(None)
    # Explicit interface name: bind to it specifically.
    ip6 = first_ipv6(iface_arg)
    mac = iface_mac(iface_arg)
    if ip6 is None:
        return _lan_transport(iface_arg)
    return Transport("awdl" if iface_arg == AWDL_IFACE else "lan",
                     iface=iface_arg,
                     bind_addr=f"{ip6}%{iface_arg}",
                     addrs=[str(ip6)], mac=mac,
                     raw_ok=(iface_arg == AWDL_IFACE and plat == "linux"))


def _awdl_transport(iface):
    ip6 = first_ipv6(iface)
    if ip6 is None:
        raise RuntimeError(f"{iface} has no IPv6 address; is AWDL up?")
    return Transport("awdl", iface=iface,
                     bind_addr=f"{ip6}%{iface}",
                     addrs=[str(ip6)], mac=iface_mac(iface),
                     raw_ok=(platform_name() == "linux"))


def _lan_transport(iface):
    addrs = default_addrs()
    bind = "::" if _has_v6() else "0.0.0.0"
    mac = iface_mac(iface) if iface else _primary_mac()
    return Transport("lan", iface=iface, bind_addr=bind,
                     addrs=addrs, mac=mac)


def _has_v6():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.close()
        return True
    except OSError:
        return False


def _primary_mac():
    """MAC of the interface owning the default route (best effort)."""
    try:
        import psutil
        gw = None
        stats = psutil.net_if_stats()
        # Heuristic: first up, non-loopback interface with an IPv4 address.
        for name, addrs in psutil.net_if_addrs().items():
            st = stats.get(name)
            if not st or not st.isup:
                continue
            if any(a.family == socket.AF_INET and not a.address.startswith("127.")
                   for a in addrs):
                for a in addrs:
                    if getattr(a.family, "name", "") == "AF_LINK" or \
                            a.family == getattr(psutil, "AF_LINK", -1):
                        try:
                            return bytes.fromhex(a.address.replace(":", "").replace("-", ""))
                        except ValueError:
                            pass
    except ImportError:
        pass
    import uuid
    node = uuid.getnode()
    if (node >> 40) & 0xFF != 0:        # getnode can return a random fallback
        return node.to_bytes(6, "big")
    return node.to_bytes(6, "big")
