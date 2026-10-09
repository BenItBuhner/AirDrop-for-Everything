"""Protocol constants for AirDrop, recovered from sharingd behaviour.

Sources: omdrop-awdl's userspace tools, omdrop's airdrop-serve.py, and
OpenDrop's config.py / server.py -- all reverse engineered from real
transfers between Apple devices.
"""

# The TCP port AirDrop receivers listen on.  OpenDrop used 8770; Apple
# devices use 8771.  Both are heard on the same interface family.
AIRDROP_PORT = 8771

# mDNS service type and the TXT-record capability flags.
SERVICE_TYPE = "_airdrop._tcp.local."

# Receiver capability flags (sharingd`[SDRapportBrowser defaultSFNodeFlags] and
# `receiverSupportsX` methods, via opendrop/config.py):
SUPPORTS_URL = 0x01
SUPPORTS_DVZIP = 0x02
SUPPORTS_PIPELINING = 0x04
SUPPORTS_MIXED_TYPES = 0x08
SUPPORTS_UNKNOWN1 = 0x10
SUPPORTS_UNKNOWN2 = 0x20
SUPPORTS_IRIS = 0x40
SUPPORTS_DISCOVER_MAYBE = 0x80    # peer answers /Discover
SUPPORTS_UNKNOWN3 = 0x100
SUPPORTS_ASSET_BUNDLE = 0x200

# macOS's own default advertisement.
FLAGS_MACOS_DEFAULT = 0x3FB
# What OpenDrop advertises: pipelining is not implemented, so this omits it.
FLAGS_OPENDROP = SUPPORTS_MIXED_TYPES | SUPPORTS_DISCOVER_MAYBE          # 0x88
# Our default: OpenDrop's set plus URL receiving (the omdrop-awdl value 137).
FLAGS_DEFAULT = FLAGS_OPENDROP | SUPPORTS_URL                          # 0x89

# A sender only talks to nodes that either pipeline or take mixed types;
# sharingd drops every other node in [SDBonjourBrowser removeInvalidNodes:].
FLAGS_MINIMUM_VIABLE = SUPPORTS_PIPELINING | SUPPORTS_MIXED_TYPES

# Value a Mac's /Discover carries; also lets a peer tell "supports /Discover".
DEVICE_SUPPORT_FLAGS = 111611

# The HTTP headers every request carries, in this order (from airdrop-send.py).
HTTP_HEADERS = {
    "Content-Type": "application/octet-stream",
    "Connection": "keep-alive",
    "Accept": "*/*",
    "User-Agent": "AirDrop/1.0",
    "Accept-Language": "en-us",
    "Accept-Encoding": "br, gzip, deflate",
}

# /Upload must use this content type; application/x-cpio is refused (406).
UPLOAD_CONTENT_TYPE = "application/x-dvzip"

# /Ask's BundleID on a real Mac sender.
BUNDLE_ID = "com.apple.finder"

# File extension -> Apple UTI, for the Files[] entries of /Ask.
UTI_BY_EXT = {
    ".jpg": "public.jpeg", ".jpeg": "public.jpeg", ".png": "public.png",
    ".heic": "public.heic", ".heif": "public.heic", ".gif": "com.compuserve.gif",
    ".mov": "com.apple.quicktime-movie", ".mp4": "public.mpeg-4",
    ".m4v": "public.mpeg-4", ".mp3": "public.mp3", ".m4a": "public.mpeg-4-audio",
    ".pdf": "com.adobe.pdf", ".txt": "public.plain-text",
    ".md": "net.daringfireball.markdown", ".csv": "public.comma-separated-values-text",
    ".zip": "public.zip-archive", ".pages": "com.apple.iwork.pages.pages",
    ".numbers": "com.apple.iwork.numbers.numbers", ".key": "com.apple.iwork.keynote.key",
}
DEFAULT_UTI = "public.data"

# --- Apple Continuity BLE advertisement (AirDrop = TLV type 0x05) ----------
APPLE_COMPANY_ID = 0x004C
BLE_TYPE_AIRDROP = 0x05
BLE_TYPE_LEN = 18          # body length byte that follows the type

# --- AWDL action-frame constants --------------------------------------------
AF_VENDOR_MAGIC = bytes.fromhex("7f0017f2")    # category 0x7f + Apple OUI
AWDL_SNAP_OUI = b"\x00\x17\xf2"                # Apple OUI inside SNAP header
AWDL_SNAP_PROTO = b"\x08\x00"                  # AWDL ethertype-in-SNAP
AWDL_SNAP_MAGIC = b"\x03\x04"
MDNS_GROUP6 = "ff02::fb"
MDNS_PORT = 5353
