# AirDrop for Everything — macOS shell

SwiftUI app over `libairdrop_ffi` (the Rust `airdrop-core` behind the C ABI
in [`../ffi.md`](../ffi.md)).

## Layout

```
CA4e/                            SwiftPM C target — module map for a4e.h
  include/a4e.h                  canonical FFI header (mirrors ffi.md §1)
  shim.c                         anchor TU so the C target is never empty
AirDropEverything/
  AirDropEverythingApp.swift     @main app entry
  ContentView.swift              UI + AppViewModel + AskGate (callback parking)
  A4eCore.swift                  Swift wrapper: errors, Unmanaged ctx bridging
  A4ePeer.swift                  A4ePeer / A4eAsk / A4eFileMeta / A4eSendOpts
  AirDropEverything-Bridging-Header.h   for the Xcode route (not SwiftPM)
Package.swift
```

## Build

### 1. Build the Rust core

```sh
# from the repo root — produces a static archive
cargo build --release -p airdrop-ffi      # → target/release/libairdrop_ffi.a
```

`airdrop-ffi`'s Cargo.toml needs `crate-type = ["staticlib"]` (or both
`cdylib`/`staticlib`) so the output is `libairdrop_ffi.a`.

### 2a. SwiftPM (dev run)

```sh
cd shells/macos
mkdir -p lib && cp ../../target/release/libairdrop_ffi.a lib/
swift run
```

`Package.swift` links the archive via `-L lib -lairdrop_ffi` on the `CA4e`
target. If your toolchain doesn't resolve the relative `-L`, pass an
absolute path instead:

```sh
swift run -Xlinker -L$PWD/lib -Xlinker -lairdrop_ffi
```

Note: `swift run` produces a bare executable, not an `.app` — fine for
development; the app still gets a Dock-less window from the SwiftUI scene.

### 2b. Xcode (real .app — required for entitlements)

1. New project → macOS App ("AirDropEverything"), SwiftUI lifecycle.
2. Drag the four `.swift` files in `AirDropEverything/` into the target.
3. *Build Settings → Objective-C Bridging Header* →
   `AirDropEverything/AirDropEverything-Bridging-Header.h`
   (it `#import`s `CA4e/include/a4e.h`; add that dir to *Header Search
   Paths* or keep the relative import).
4. *Link Binary With Libraries* → add `libairdrop_ffi.a`; set *Library
   Search Paths* to `../../target/release` (or `lib/`).
5. Signing & Capabilities for sandboxed builds (below).

## Platform notes

- **AWDL exists natively.** With Wi-Fi on, `awdl0` is present and the core
  can pick it — link-local peers arrive as `fe80::…%awdl0` and interop with
  real Apple devices works (subject to the usual Everyone/Contacts rules).
- **mDNS entitlements for sandboxed/App Store builds:** enable
  `com.apple.developer.networking.multicast` plus
  `com.apple.security.network.client` and `.server`; add
  `NSBonjourServices` = `_airdrop._tcp` to Info.plist. Unsandboxed dev
  builds (`swift run`) need none of this.
- **Sandbox file access:** receiving to `~/Downloads` needs
  `com.apple.security.files.downloads.read-write` (or use a
  security-scoped/NSOpenPanel-chosen folder); sending dropped files needs
  `com.apple.security.files.user-selected.read-only`.
- **Threading:** `browse`/`sendFiles` run on `DispatchQueue.global()`; the
  ask callback runs on a core worker thread and blocks (≤60 s) on
  `AskGate`, a semaphore parked until the alert is answered — ffi.md §6.
- **ctx lifetime:** the ask-closure box is `Unmanaged.passRetained` until
  `a4e_receiver_stop` returns, matching the contract in ffi.md §5.
