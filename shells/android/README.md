# AirDrop for Everything — Android shell

Kotlin / Jetpack Compose app over `libairdrop_ffi` (the Rust `airdrop-core`
via the C ABI in [`../ffi.md`](../ffi.md)).

## Layout

```
app/src/main/java/tech/airdrop4e/
  A4eCore.kt              JNI bindings + data classes (a4e_* contract)
  MainViewModel.kt        StateFlow state, FFI calls on Dispatchers.IO,
                          ask-queue, SAF→cache staging for sends
  MainActivity.kt         Compose UI: receiver toggle, peers, picker, log
  MulticastLockHolder.kt  WifiManager.MulticastLock wrapper (mDNS needs it)
app/src/main/AndroidManifest.xml
```

## Build

Prereqs: Android SDK (compileSdk 34), JDK 17, Rust, cargo-ndk.

```sh
# one-time
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64
cargo install cargo-ndk

# build the Rust FFI lib into the app's jniLibs dir (run from repo root)
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
    -o shells/android/app/src/main/jniLibs \
    build --release -p airdrop-ffi

# then build the app
cd shells/android
./gradlew assembleDebug        # or gradlew.bat on Windows
```

`cargo ndk -t <abi>` accepts `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`.
`airdrop-ffi`'s Cargo.toml needs `crate-type = ["cdylib"]` so the output is
`libairdrop_ffi.so`.

### JNI glue

Kotlin calls `System.loadLibrary("airdrop_ffi")` and invokes `external fun`s
on `tech.airdrop4e.A4eCore`. The `airdrop-ffi` crate carries a
`#[cfg(target_os = "android")]` module (on the `jni` crate) that exports the
matching `Java_tech_airdrop4e_A4eCore_*` symbols, marshals the callback
structs into `A4eAsk`/`A4ePeer` objects, attaches core worker threads to the
JVM, and turns `-1`/error strings into thrown `A4eException`s. The exact
marshalling contract is specified in `../ffi.md` §7.

## Platform notes

- **No AWDL on Android.** There is no AWDL driver, so this shell is LAN-only:
  it interoperates with other AirDrop-for-Everything instances and with Macs
  that browse all interfaces, but cannot be *seen* by stock Apple devices in
  their AirDrop picker.
- **mDNS needs `WifiManager.MulticastLock`.** Without it inbound multicast
  is filtered. `MulticastLockHolder` holds it while the receiver runs and
  during each browse; the manifest declares `CHANGE_WIFI_MULTICAST_STATE`.
- **Sending files:** SAF returns `content://` URIs while `a4e_send_files`
  wants real paths — `MainViewModel.stage()` copies picks into
  `cacheDir/outbox` first. Names are sanitised to a single path component.
- **Receiving:** files land in `getExternalFilesDir(DIRECTORY_DOWNLOADS)/drops`
  (visible in Files apps under Android/data/tech.airdrop4e) — no storage
  permission needed.
- **Threading:** browse/send are called from `Dispatchers.IO`; the ask
  callback runs on a core thread and blocks (≤60 s) on the dialog answer via
  a `CompletableDeferred` — see ffi.md §6.
- **Production hardening (not in this skeleton):** a foreground service to
  keep the receiver alive when backgrounded, runtime `BLUETOOTH_ADVERTISE`
  permission handling once the BLE wake backend lands, and a Wi-Fi
  `WifiLock`/`NETWORK_MODE` check in `doctor`-style UI.
