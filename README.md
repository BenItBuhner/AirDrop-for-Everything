# AirDrop-for-Everything

**AirDrop on everything.** A clean-room, cross-platform reimplementation of
Apple's AirDrop protocol in portable Python — send and receive files the way
`sharingd` does, on **Linux, macOS, Windows, Android**, and anywhere else
Python runs.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python ≥ 3.9](https://img.shields.io/badge/python-%E2%89%A53.9-blue.svg)](pyproject.toml)
[![Platform: any](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows%20%7C%20android-lightgrey.svg)](README.md#platform-matrix)

Inspired by — and reverse-engineered alongside — **[t4t5/omdrop-owl](https://github.com/t4t5/omdrop-owl)**
(Brent Kearney's Omdrop on OWL). See [NOTICE](NOTICE) for full provenance and
credits. Licensed [MIT](LICENSE).

## Install

```sh
pip install "git+https://github.com/BenItBuhner/AirDrop-for-Everything.git"
# or clone, then: pip install .[all]
```

Extras: `.[all]` adds Pillow thumbnails, `cryptography` cert generation and
`psutil` interface lookup; `.[ble-linux]` adds BlueZ BLE wake adverts;
`.[ble-windows]` adds the WinRT backend.

## Demo

```console
$ a4e receive --outdir .\drops --name TestBox
AirDrop receiver 'TestBox' (MacBookPro18,3)
  service:  4c82a9b89c1f._airdrop._tcp.local :8771
  via:      LAN on all interfaces
  saving:   C:\drops
  policy:   everyone

$ a4e send report.pdf                       # elsewhere on the network
receiver: 'TestBox' (4c82a9b89c1f) at [192.168.4.254]:8771 - asking
sent: report.pdf
```

## Why

AirDrop only speaks over AWDL (Apple Wireless Direct Link). On Apple hardware
that's `awdl0`; on Linux it's OWL or the brcmfmac-awdl driver; on Windows and
Android there is no AWDL driver at all. This package splits the protocol stack
from the link layer so the whole thing still works — between our own devices,
and with Macs that browse all interfaces — over plain LAN. And if Apple
changes AirDrop behaviour, the protocol here is ours to fix.

## Quick start

```sh
a4e receive                     # become discoverable, save to ~/Downloads
a4e send photo.jpg              # discover a receiver, ask, upload
a4e peers                       # list receivers in range
a4e doctor                      # what can this machine actually do?
```

Receive options:

```sh
a4e receive --outdir D:\drops --name "My PC" --ask   # prompt per transfer
a4e receive --contacts            # Contacts Only (needs Apple identity)
a4e receive --iface awdl0         # force the AWDL interface (macOS/Linux)
a4e receive --duration 120        # stay up 2 minutes
```

Send options:

```sh
a4e send a.png b.pdf --to "iPad"           # pick a receiver by name
a4e send file --to 4c82a9b89c1f            # ...or by 12-hex service id
a4e send file --direct 192.168.1.20:8771   # skip discovery entirely
a4e send file --wait --timeout 60          # keep browsing up to 60s
```

## The protocol, as implemented

| Step | Wire format |
|---|---|
| Discovery | mDNS PTR/SRV/TXT/AAAA for `_airdrop._tcp.local`; TXT `flags=` bitmask |
| `/Discover` | POST binary plist `{DeviceSupportFlags, SenderRecordData?}` → receiver name/model/`ReceiverMediaCapabilities` |
| `/Ask` | POST binary plist `{Files[], Items[], SenderComputerName, SenderModelName, TransferID, FileIcon?, SenderRecordData?, SenderIdentityAuthTag?}` → 200 accept / 403 decline |
| `/Upload` | POST `application/x-dvzip`, `TransferID` + `TotalBytes` headers, chunked body: DVZip-framed `newc` cpio archive |

Quirks preserved from the reference implementation (`omdrop-awdl`'s
`airdrop-send.py`): a **fresh TLS connection** is opened for `/Ask`
(sharingd tears the Discover handler down but leaves the socket open, so a
reused connection's Ask is ACKed and silently dropped); `FileBomPath` is
`./name`; the icon is a ≤240px JPEG thumbnail; link-local IPv6 peers get a
`%zone` scope.

Flag bits advertised in TXT (default `137` = `0x88 | 0x09`): `SUPPORTS_URL
0x01`, `DVZIP 0x02`, `PIPELINING 0x04`, `MIXED_TYPES 0x08`, `IRIS 0x40`,
`DISCOVER 0x80`, `ASSET_BUNDLE 0x200`. macOS shares `0x3fb`; senders skip
receivers without bit `0x80`.

## Link layers

```
              ┌────────────── a4e send ──────────────┐
   discover   │  mDNS browse  |  AWDL action frames  │
              └──────────────┬───────────────────────┘
                  TLS + HTTP │  /Discover /Ask /Upload
              ┌──────────────┴───────────────────────┐
   link       │  awdl0 (macOS) · awdl0 via OWL (Linux)│
              │  lan: any IP network (every OS)       │
              │  BLE: AirDrop wake advert (opt.)      │
              └──────────────────────────────────────┘
```

`--iface auto` (default): `awdl0` when it exists with a link-local, else LAN.
Explicit: `--iface lan`, `--iface awdl0`, `--iface <name>`.

### Platform matrix

| Platform | LAN transport | AWDL | BLE wake |
|---|---|---|---|
| Linux | yes | OWL (Broadcom, ch 6/44/149) or brcmfmac-awdl | BlueZ (`pip install .[ble-linux]`) |
| macOS | yes | native `awdl0` | CoreBluetooth backend (stub) |
| Windows | yes | — | WinRT backend (`pip install .[ble-windows]`) |
| Android (Termux etc.) | yes | — | stub — needs BLE peripheral API glue |

On Windows/Android there is no AWDL driver, so Apple devices cannot be
*discovered*; LAN mode interoperates with other AirDrop-for-Everything
instances and with Macs running `com.apple.sharingd BrowseAllInterfaces`.
On Linux, `a4e radio start` brings up OWL's `awdl0` (root, compatible
Broadcom chip, and your AP on channel 6/44/149); `a4e af-listen` sniffs AWDL
action frames on the monitor interface.

### BLE wake

Apple receivers sleep until a Continuity AirDrop advert arrives. `a4e send`
emits one while discovering (when a BLE backend exists); `a4e wake` emits it
standalone. Zero-hashes wake Everyone-mode receivers; Contacts Only needs the
truncated SHA-256 contact hashes from your Apple validation record
(`a4e identity --import cert.pem key.pem record.plist`).

## Receiver hardening

Re-implemented from `omdrop-plugin`'s `airdrop-serve.py`:

- filename sanitisation: no path separators, no control/format characters
  (blocks bidi-override tricks), no dotfiles, ≤255 UTF-8 bytes
- `O_EXCL` atomic create → `name-1.ext`, never clobbers
- upload byte/member/rate limits; free-disk budget (`--max-receive-percent`)
- DVZip decode → cpio extract in memory-isolated stream; AppleDouble `._`
  sidecars and non-regular members skipped
- `/Ask` consent gate (`--ask`), `links` items stored as inert `.url` files

## Contacts Only

Everyone mode works with a self-signed identity (generated on first use).
Contacts Only requires your Apple-issued certificate + validation record —
import them with `a4e identity --import CERT KEY [RECORD]`. The receiver then
verifies the Apple signature chain (vendored public CA certs under
`airdrop_everything/certs/`) and matches the sender's hashed identifiers
against `~/.config/airdrop-everything/known_senders` (phone/email hashes).
Without an Apple identity, `--contacts` fails closed.

## Development

```sh
python -m venv .venv && .venv\Scripts\activate   # or source .venv/bin/activate
pip install -e .[all,test]
pytest                                          # 28 tests: codecs, protocol, e2e loopback
python -m airdrop_everything doctor
```

The test suite covers cpio/DVZip round-trips, mDNS packet build/parse, AWDL
action-frame parsing, BLE advert construction, safe-name rules, and a full
TLS loopback send on `127.0.0.1` — so CI needs no radio at all.

### Layout

```
airdrop_everything/
  const.py       service type, flags, ports, HTTP headers, UTI map
  util.py        safe_name, open_new, EUI-64, iface enumeration
  codec/dvzip    DVZip framing (deflate stream + trailer)
  cpio.py        pure-Python newc/odc cpio writer + streaming reader
  identity.py    cert/key/record resolution, self-signed generation
  contacts.py    Contacts-Only gate (Apple chain + known-sender hashes)
  server.py      threaded HTTPS receiver: /Discover /Ask /Upload
  client.py      sender + mDNS Finder with address fallback
  discovery.py   zeroconf announcer + raw AF_PACKET mDNS for AWDL
  aframes.py     AWDL action-frame TLV parser + AF_PACKET listener
  ble.py         AirDrop wake advert builder, BlueZ/WinRT backends
  radio_owl.py   Linux OWL orchestration (port of omdrop-discoverable)
  transport.py   auto/awdl/lan link selection
  cli.py         a4e receive|send|peers|wake|identity|doctor|radio|af-listen
  certs/         Apple public CA certificates (Contacts Only verification)
  owl-profiles   OWL capability profile list (Linux)
```

## Limitations

- **No AWDL on Windows/Android** — Apple devices can't be discovered there;
  LAN transport interoperates with our own instances and suitably configured
  Macs.
- **OWL needs specific hardware** — Broadcom fullmac (e.g. bcm4355/4364-class),
  monitor mode + frame injection, root, AP on channel 6/44/149.
- **BLE backends** — BlueZ works on Linux; WinRT is written but requires
  `winsdk`; macOS/Android BLE is a documented stub.
- **Contacts Only** — protocol-verified but needs your real Apple identity
  material; Everyone mode is fully self-contained.

## Credits

This project exists because others did the hard reverse-engineering:

- **[t4t5/omdrop-owl](https://github.com/t4t5/omdrop-owl)** — the repository
  that motivated this one: Omdrop packaged for OWL so a Linux laptop can sit
  in the AirDrop picker. Explicit credit to **t4t5** for the packaging and to
  **Brent Kearney** for the underlying implementation.
- **[brentkearney/omdrop-awdl](https://github.com/brentkearney/omdrop-awdl)** —
  the userspace sender, BLE advert, raw-mDNS and AF-parsing tools whose
  behaviour `client.py`, `ble.py`, `discovery.py` and `aframes.py` mirror.
- **[brentkearney/omdrop-plugin](https://github.com/brentkearney/omdrop-plugin)** —
  the receiver (`airdrop-serve.py`) whose behaviour `server.py` mirrors. MIT.
- **[jedbillyb/owl](https://github.com/jedbillyb/owl)** — the AWDL userspace
  daemon our Linux backend drives. GPLv3, not vendored.
- **[seemoo-lab/opendrop](https://github.com/seemoo-lab/opendrop)** — the
  original public AirDrop implementation; protocol constants cross-checked
  against it. GPLv3, not vendored.

See [NOTICE](NOTICE) for the licence notes on each upstream. This project's
own code is [MIT](LICENSE).
