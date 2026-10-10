"""Cross-platform helpers: names, addresses, interface lookup.

Everything here works on Linux, macOS and Windows without platform-specific
syscalls; where a platform detail is needed it is isolated in one function.
"""
import ipaddress
import os
import re
import socket
import sys
import unicodedata

# Path separators, NUL, control characters (Cc) and format characters (Cf:
# bidi overrides, zero-width joiners). A name like "gpj.<U+202E>exe" renders
# as "exe.jpg" in a file manager. Used for received file names and for the
# receiver name we advertise. (Same rule as omdrop's airdrop-serve.py.)
UNSAFE_CHAR = re.compile(
    r'[/\\\x00]|[\u202a-\u202e\u2066-\u2069\u200b-\u200f\ufeff]|[\x01-\x1f\x7f-\x9f]')


def safe_name(name, fallback="file"):
    """Return one non-hidden filesystem component from sender-controlled text."""
    name = unicodedata.normalize("NFC", name.replace("\\", "/").rsplit("/", 1)[-1])
    name = UNSAFE_CHAR.sub("", name).strip().lstrip(".")
    stem, ext = os.path.splitext(name)
    while len((stem + ext).encode("utf-8")) > 255 and stem:
        stem = stem[:-1]
    return (stem + ext) or fallback


def open_new(dest, name):
    """Create dest/name atomically without clobbering an existing file."""
    stem, ext = os.path.splitext(name)
    for i in range(10000):
        cand = name if i == 0 else f"{stem}-{i}{ext}"
        try:
            fd = os.open(os.path.join(dest, cand),
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            continue
        return cand, os.fdopen(fd, "wb")
    raise FileExistsError(name)


def eui64_linklocal(mac):
    """fe80:: EUI-64 address for a MAC (bytes or 'aa:bb:...' string).

    A Mac's AWDL link-local is always the EUI-64 of its AWDL MAC; iPhones
    randomise, so this is a hint there, not a guarantee.
    """
    b = bytes(int(x, 16) for x in mac.split(":")) if isinstance(mac, str) else bytes(mac)
    b = bytes([b[0] ^ 0x02]) + b[1:3] + b"\xff\xfe" + b[3:]
    return "fe80::" + ":".join(f"{b[i] << 8 | b[i + 1]:x}" for i in range(0, 8, 2))


def mac_bytes(mac):
    """Normalise a MAC to 6 bytes (accepts bytes, 'aa:bb:..' or 'aabbcc..')."""
    if isinstance(mac, (bytes, bytearray)):
        return bytes(mac)
    return bytes.fromhex(mac.replace(":", ""))


def iface_mac(iface):
    """MAC of a network interface, portable across Linux/macOS/Windows."""
    if sys.platform.startswith("linux"):
        try:
            with open(f"/sys/class/net/{iface}/address") as f:
                return bytes.fromhex(f.read().strip().replace(":", ""))
        except OSError:
            pass
    try:
        import ifaddr
        for ad in ifaddr.get_adapters():
            if ad.name == iface and ad.ips:
                pass  # ifaddr has no MAC; fall through to other methods
    except ImportError:
        pass
    # Portable fallback: psutil if present, else uuid.getnode guess.
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            if name == iface:
                for a in addrs:
                    if a.family == psutil.AF_LINK or getattr(a.family, "name", "") == "AF_LINK":
                        return mac_bytes(a.address)
    except ImportError:
        pass
    return None


def iface_addrs(iface, want_ipv6=None):
    """All addresses on an interface as (family, ip-string, ifindex-ish).

    Uses psutil when available; on Linux falls back to /proc/net/if_inet6 +
    ioctl-free /sys reads; on Windows/macOS uses `ip`/`ipconfig` via socket
    tricks only when psutil is missing.
    """
    try:
        import psutil
        psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            if name != iface:
                continue
            out = []
            for a in addrs:
                fam = a.family
                if fam == socket.AF_INET and want_ipv6 in (None, False):
                    out.append((fam, a.address))
                elif fam == socket.AF_INET6 and want_ipv6 in (None, True):
                    out.append((fam, a.address.split("%")[0]))
            return out
    except ImportError:
        pass
    out = []
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/if_inet6") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) == 6 and parts[5] == iface and want_ipv6 in (None, True):
                        out.append((socket.AF_INET6,
                                    str(ipaddress.IPv6Address(bytes.fromhex(parts[0])))))
        except OSError:
            pass
    return out


def first_ipv6(iface):
    for _fam, addr in iface_addrs(iface, want_ipv6=True):
        return ipaddress.IPv6Address(addr)
    return None


def interface_for_addr(addr):
    """Return (interface_name_or_index) that owns an address, or None."""
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.address.split("%")[0] == str(addr).split("%")[0]:
                    return name
    except ImportError:
        pass
    return None


def scope_id_for(addr, iface_hint=None):
    """Scope id for a link-local IPv6 address (zone index)."""
    if "%" in str(addr):
        zone = str(addr).split("%", 1)[1]
        try:
            return int(zone)
        except ValueError:
            try:
                return socket.if_nametoindex(zone)
            except OSError:
                return 0
    if iface_hint:
        try:
            return socket.if_nametoindex(iface_hint)
        except OSError:
            return 0
    found = interface_for_addr(addr)
    if found:
        try:
            return socket.if_nametoindex(found)
        except OSError:
            pass
    return 0


def platform_name():
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform.startswith(("win32", "cygwin", "msys")):
        return "windows"
    return sys.platform


def short_hostname():
    return socket.gethostname().split(".")[0] or "airdrop"
