# AirDrop-for-Everything

**AirDrop on everything.** A clean-room, cross-platform reimplementation of
Apple's AirDrop protocol — send and receive files the way `sharingd` does —
as a **native Rust core** plus thin native shells per OS:
Windows, Linux, macOS, and Android.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](Cargo.toml)
[![Platform: any](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows%20%7C%20android-lightgrey.svg)](#platform-matrix)

Inspired by — and reverse-engineered alongside — **[t4t5/omdrop-owl](https://github.com/t4t5/omdrop-owl)**
(Brent Kearney's Omdrop on OWL). See [NOTICE](NOTICE) for provenance and
credits. Licensed [MIT](LICENSE).

## Why

AirDrop only speaks over AWDL (Apple Wireless Direct Link). On Apple hardware
that's `awdl0`; on Linux it's OWL or the brcmfmac-awdl driver; on Windows and
Android there is no AWDL driver at all. This project splits the protocol
stack from the link layer so the same native binary works everywhere — and if
Apple changes AirDrop's behaviour, the protocol here is ours to fix.

## Architecture

```
                ┌─────────── native shells ───────────┐
                │  a4e (CLI, Rust)   ·  a4e-gui (egui)│
                │  Android (Kotlin)  ·  macOS (SwiftUI)│
                └──────────────┬──────────────────────┘
                     C ABI — crates/ffi
                ┌──────────────┴──────────────────────┐
   airdrop-core │  mDNS _airdrop._tcp  (mdns-sd)      │
     (Rust lib) │  TLS                 (rustls+rcgen) │
                │  HTTP/1.1 endpoints  (hand-rolled)  │
                │  binary plists       (plist crate)  │
                │  DVZip + newc cpio   (flate2+own)   │
                │  AWDL action frames  (aframes)      │
                │  BLE wake advert     (WinRT/BlueZ)  │
                └──────────────┬──────────────────────┘
                     link layer
                awdl0 (macOS · Linux+OWL) · LAN · BLE
```

Everything is synchronous, blocking Rust — no async runtime — so the same
core links cleanly into shells and stays easy to audit.

## Build

```sh
# toolchain: rustup (stable, windows-gnu/msvc/linux/macOS all work)
cargo build --release           # builds a4e (CLI) + a4e-gui + airdrop-ffi
cargo test -p airdrop-core      # codecs + protocol + 127.0.0.1 loopback e2e
```

Artifacts land in `target/release/`:

| Binary | What it is |
|---|---|
| `a4e` | The CLI: `receive` `send` `peers` `wake` `identity` `doctor` `af-parse` `af-listen` |
| `a4e-gui` | Desktop app: Receive/Send/Peers tabs, drag-drop, native file dialogs |
| `airdrop_ffi.{a,so,dll,dylib}` | C ABI for shells (see `shells/ffi.md`) |

### Native shells

- **`shells/android/`** — Kotlin/Compose app over JNI (`cargo-ndk` → `.so`).
  No AWDL on Android; LAN transport + BLE advert via `BluetoothLeAdvertiser`.
- **`shells/macos/`** — SwiftUI app over the static lib + bridging header.
  macOS has real `awdl0` while Wi-Fi is up — `--iface awdl0` puts us on it.
- **Windows GUI** — `a4e-gui` ships in the workspace today (egui/eframe).
- **Linux** — `a4e` CLI + OWL integration (`a4e` drives `awdl0` when OWL or
  the brcmfmac-awdl driver has created it); GTK shell can reuse a4e-gui.

## Quick start

```sh
a4e receive                      # become discoverable, save to ~/Downloads
a4e send photo.jpg               # discover a receiver, ask, upload
a4e peers                        # list receivers in range
a4e doctor                       # what can this machine actually do?
```

```sh
a4e receive --outdir D:\drops --name "My PC" --ask   # prompt per transfer
a4e send file.pdf --to "iPad"            # receiver by name substring
a4e send file --direct 192.168.1.20:8771 # skip discovery
a4e wake                                 # BLE advert to wake Apple receivers
a4e af-parse <hex>                       # decode an AWDL action frame
a4e af-listen awdl0                      # sniff AWDL action frames (Linux, root)
```

## The protocol, as implemented

| Step | Wire format |
|---|---|
| Discovery | mDNS PTR/SRV/TXT/A+AAAA for `_airdrop._tcp.local`; TXT `flags=` bitmask |
| `/Discover` | POST binary plist `{DeviceSupportFlags, SenderRecordData?}` → name/model/caps |
| `/Ask` | POST binary plist `{Files[], Items[], SenderComputerName, TransferID, FileIcon?, …}` → 200 / 403 |
| `/Upload` | POST `application/x-dvzip`, `TransferID` + `TotalBytes`, chunked: DVZip-framed `newc` cpio |

Quirks preserved from the reference implementation: a **fresh TLS
connection** for `/Ask` (sharingd tears the Discover handler down but leaves
the socket open — a reused conn's Ask is ACKed and silently dropped);
`FileBomPath` is `./name`; link-local IPv6 peers get `%zone` scope; the
client falls back through *all* advertised addresses.

Flag bits (default `137` = `0x88|0x09`): URL `0x01` · DVZIP `0x02` ·
PIPELINING `0x04` · MIXED_TYPES `0x08` · IRIS `0x40` · DISCOVER `0x80` ·
ASSET_BUNDLE `0x200`. macOS shares `0x3fb`; senders skip receivers without
`0x80`.

## Platform matrix

| Platform | LAN transport | AWDL | BLE wake | Shell |
|---|---|---|---|---|
| Linux | ✓ | OWL / brcmfmac-awdl (root, ch 6/44/149) | BlueZ/hcitool | `a4e`, `a4e-gui` |
| macOS | ✓ | native `awdl0` | stub | `a4e`, SwiftUI shell |
| Windows | ✓ | no driver exists | WinRT (verified transmitting) | `a4e`, `a4e-gui` |
| Android | ✓ (Termux/app) | — | `BluetoothLeAdvertiser` (stub) | Kotlin shell |

On Windows/Android Apple devices can't be *discovered* (no AWDL); LAN mode
interoperates with other AirDrop-for-Everything instances and Macs running
`BrowseAllInterfaces`.

## Receiver hardening

- filename sanitisation: no separators/controls/bidi overrides, no dotfiles,
  ≤255 UTF-8 bytes
- `create_new(true)` atomic writes → `name-1.ext`, never clobbers
- upload byte/member limits + free-disk budget
- AppleDouble `._` sidecars and non-regular cpio members skipped
- `/Ask` consent gate; `links` items stored as inert `.url` files
- Contacts-Only hook points at the Apple cert chain (vendored public CAs in
  `prototype/airdrop_everything/certs/`)

## Testing

`cargo test -p airdrop-core` — cpio/DVZip round-trips, malformed-input
rejection, BLE payload shapes, and a **real TLS loopback send** on
`127.0.0.1` (no radio needed). The Python prototype under `prototype/` ran
the same suite live on Windows LAN.

## Prototype

`prototype/` holds the original Python implementation this Rust core ports —
kept as executable documentation of the protocol behaviour and as a fallback
for platforms where a Rust toolchain isn't handy (`pip install .` inside
`prototype/` still gives you the Python `a4e`).

## Credits

This project exists because others did the hard reverse-engineering:

- **[t4t5/omdrop-owl](https://github.com/t4t5/omdrop-owl)** — the repo that
  motivated this one. Credit to **t4t5** for the packaging and
  **Brent Kearney** for the underlying implementation.
- **[brentkearney/omdrop-awdl](https://github.com/brentkearney/omdrop-awdl)** —
  the userspace sender, BLE advert, raw-mDNS and AF-parsing tools our
  `client`, `ble`, and `discovery` mirror.
- **[brentkearney/omdrop-plugin](https://github.com/brentkearney/omdrop-plugin)** —
  the receiver whose behaviour `server` mirrors. MIT.
- **[jedbillyb/owl](https://github.com/jedbillyb/owl)** — the AWDL userspace
  daemon our Linux path drives. GPLv3, not vendored.
- **[seemoo-lab/opendrop](https://github.com/seemoo-lab/opendrop)** — the
  original public AirDrop implementation. GPLv3, not vendored.

See [NOTICE](NOTICE) for each upstream's licence notes. Our code is
[MIT](LICENSE).
