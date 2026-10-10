# `airdrop-ffi` — C ABI contract

`airdrop-ffi` is a thin Rust crate that wraps `airdrop-core` in a plain C ABI
so the native shells (Android/Kotlin, macOS/SwiftUI, …) can drive the AirDrop
protocol — mDNS discovery, TLS, `/Discover` `/Ask` `/Upload`, DVZip+cpio —
without embedding Rust themselves.

* **Crate type:** `crate-type = ["cdylib", "staticlib"]` → produces
  `libairdrop_ffi.so`/`libairdrop_ffi.a` (and platform variants).
* **Canonical header:** [`macos/CA4e/include/a4e.h`](macos/CA4e/include/a4e.h).
  The header is the source of truth for exact declarations; this document is
  the source of truth for *semantics* (ownership, threading, errors).
* **Naming:** every exported symbol starts with `a4e_`. All functions are
  `extern "C"`, default visibility, cdecl/system calling convention.

## 1. Reference C API

```c
#include <stddef.h>
#include <stdint.h>

/* ---------- types ---------- */

/* One file entry from a sender's /Ask proposal. */
typedef struct {
    const char *name;        /* file name, no path separators */
    const char *uti;         /* Apple UTI, e.g. "public.jpeg"   */
    uint64_t    size;        /* bytes                           */
} a4e_filemeta;

/* An incoming /Ask, delivered to a4e_ask_callback. */
typedef struct {
    const char         *sender_name;   /* sender's computer name   */
    const char         *sender_model;  /* e.g. "MacBookPro18,3"    */
    const char         *transfer_id;   /* UUID for this transfer   */
    size_t              files_len;     /* number of entries        */
    const a4e_filemeta *files;         /* files_len entries        */
} a4e_ask;

/* Return 1 to accept the transfer, 0 to decline. */
typedef int (*a4e_ask_callback)(void *ctx, const a4e_ask *ask);

/* One discovered receiver (mDNS + /Discover probe). */
typedef struct {
    const char *ident;   /* 12-hex _airdrop._tcp instance id      */
    const char *name;    /* receiver display name; NULL if the
                            peer did not answer /Discover         */
    const char *addr;    /* primary IP, no port; link-local v6
                            carries its %zone (fe80::1%awdl0)     */
    uint16_t    port;    /* TLS port (usually 8771)               */
} a4e_peer;

typedef void (*a4e_peer_callback)(void *ctx, const a4e_peer *peer);

/* Optional knobs for a4e_send_files. Pass NULL for all defaults. */
typedef struct {
    uint32_t    struct_size;    /* set to sizeof(a4e_send_opts); lets the
                                   ABI grow without breaking old callers */
    const char *computer_name;  /* NULL -> name given at identity load   */
    const char *computer_model; /* NULL -> "MacBookPro18,3"              */
    const char *service_id;     /* NULL -> stable per-machine 12-hex id  */
    int32_t     has_auth_tag;   /* !=0 -> auth_tag below is sent in /Ask */
    uint8_t     auth_tag[3];    /* BLE SenderIdentityAuthTag             */
    uint64_t    ask_timeout_ms; /* 0 -> 90_000                           */
} a4e_send_opts;

/* ---------- lifecycle ---------- */

/* Load keys_dir/{certificate,key}.pem (creating a self-signed identity on
   first run) or import previously-installed Apple identity material.
   Must succeed before a4e_receiver_start or a4e_send_files. */
int  a4e_identity_load_or_create(const char *keys_dir,
                                 const char *computer_name,   /* NULL -> hostname */
                                 char **err);                 /* out, see §4 */

/* ---------- receiver (singleton) ---------- */

/* visibility: 0 = Everyone, 1 = Contacts Only.
   port:       0 = default AirDrop port 8771; otherwise an explicit port.
   cb:         NULL = auto-accept every /Ask.
   ctx:        opaque pointer passed to cb; borrowed for the receiver's
               lifetime (see §5). */
int  a4e_receiver_start(const char *name,          /* NULL -> identity name */
                        const char *model,         /* NULL -> "MacBookPro18,3" */
                        const char *dest_dir,      /* required; created if missing */
                        int         visibility,
                        unsigned short port,
                        a4e_ask_callback cb,
                        void *ctx);
void a4e_receiver_stop(void);   /* idempotent; safe when not running */

/* ---------- sender ---------- */

/* Sends all paths to the receiver at addr ("ipv4:port",
   "[v6]:port", or "[v6%zone]:port" for link-local).
   Blocks the calling thread for the whole Discover/Ask/Upload exchange. */
int  a4e_send_files(const char **paths, size_t n,
                    const char *addr,
                    const a4e_send_opts *opts,   /* NULL = defaults */
                    char **err);

/* Browses _airdrop._tcp for up to timeout_ms, /Discover-probing each
   candidate. Blocks the calling thread; cb fires on that same thread,
   sequentially, once per viable peer. cb may be NULL (pure sleep). */
int  a4e_browse(uint32_t timeout_ms, a4e_peer_callback cb, void *ctx);

/* ---------- misc ---------- */

/* Free a string the core handed back via a char** out-param. NULL-safe. */
void        a4e_string_free(char *s);

/* Thread-local message for the most recent failed call *on this thread*.
   Borrowed; do not free; NULL if the last call on this thread succeeded
   (or no call has been made). Overwritten by the next call. */
const char *a4e_last_error(void);
```

## 2. Call sequence & lifecycle rules

1. `a4e_identity_load_or_create` **first** — receiver and sender both return
   `-1` ("identity not loaded") until it has succeeded at least once.
   Idempotent: calling again re-loads/replaces the identity. `keys_dir` is
   created if missing; `computer_name` becomes the certificate CN.
2. `a4e_receiver_start` is a **singleton**. A second call while running
   returns `-1`. `a4e_receiver_stop` tears down listener + mDNS announce and
   joins the worker threads — after it returns, no callbacks will fire.
3. `a4e_send_files` / `a4e_browse` are blocking, stateless calls; any number
   may be in flight on different threads at once.
4. No `a4e_init`/`atexit` hook is required — global state is lazily
   initialised; a process may exit without calling `a4e_receiver_stop`
   (in-flight callbacks are simply abandoned).

## 3. NULL / default conventions

| Parameter | NULL / 0 means |
|---|---|
| `computer_name` (identity) | OS hostname |
| `name` (receiver) | identity's computer name |
| `model` (receiver, send opts) | `"MacBookPro18,3"` |
| `port` (receiver) | `8771` (`AIRDROP_PORT`) |
| `cb` (receiver) | auto-accept every `/Ask` |
| `opts` (send) | all defaults |
| `paths` | may not be NULL when `n > 0` |
| `dest_dir` | may not be NULL or empty |
| `addr` | `"ipv4:port"`, `"[v6]:port"`, `"[v6%zone]:port"` |

Strings handed *in* (paths, addr, opts fields) are UTF-8 filesystem paths /
ASCII names and are only borrowed for the duration of the call.

## 4. Error convention

* Functions returning `int`: **`0` = success, `-1` = failure.** There are no
  other return values; details always come from the message channel.
* Functions with a `char **err` out-param (`a4e_identity_load_or_create`,
  `a4e_send_files`): on failure `*err` is set to a heap-allocated,
  NUL-terminated UTF-8 message that the **caller frees with
  `a4e_string_free`**. On success `*err` is left untouched — initialise it
  to `NULL` before the call.
* Functions without an out-param (`a4e_receiver_start`, `a4e_browse`):
  `a4e_last_error()` returns a **borrowed, thread-local** message. Do not
  free it; it is replaced by the next FFI call on the same thread.
* Inside callbacks there is no error channel — the ask callback's return
  value *is* the channel (`1` accept / `0` decline). A callback may itself
  call `a4e_last_error()` (its own thread-local slot).
* The implementation must `catch_unwind` at every FFI boundary — panics
  never cross into the shell.

## 5. Ownership & memory rules

| Data | Owner | Rule |
|---|---|---|
| `char *err` out-params | caller | free with `a4e_string_free` (never `free(3)` — the allocator may differ) |
| `a4e_last_error()` | core | borrowed, thread-local, do not free |
| `a4e_ask` / `a4e_peer` + all strings inside | core | **borrowed — valid only for the duration of the callback.** Copy anything you keep. `ask->files` has `files_len` entries; `peer->name` may be NULL |
| `ctx` passed to `a4e_receiver_start` | caller | must stay valid from `start` until `a4e_receiver_stop` returns; the core stores but never frees it |
| `ctx` passed to `a4e_browse` | caller | must stay valid only for the duration of the `a4e_browse` call |
| `paths` array / `opts` for send | caller | borrowed for the duration of the call |

## 6. Threading model (read this before writing a shell)

* **All entry points are thread-safe** and may be called from any thread.
* `a4e_receiver_start` returns immediately; serving happens on core-owned
  worker threads.
* **`a4e_ask_callback` fires on a core HTTP worker thread**, once per
  connection's `/Ask`. It *may* block — the sender is holding its TLS
  connection open waiting for the answer — so a shell may synchronously
  prompt the user (post to the main thread, wait on a semaphore/latch).
  Return within ~60 s (senders typically time an Ask out at 90 s); on
  timeout return `0`.
* **Ask callbacks may fire concurrently** on different worker threads (two
  senders asking at once). Synchronise any shared state in the shell.
* `a4e_browse` **blocks the calling thread** for up to `timeout_ms` and
  invokes `a4e_peer_callback` on that same thread — call it from a worker
  thread/coroutine, never the UI thread.
* `a4e_send_files` **blocks** for the whole transfer — same rule.
* **Never call `a4e_receiver_stop` (or `a4e_identity_load_or_create`) from
  inside a callback on that callback's thread** — `stop` joins the worker
  threads and would deadlock. Post it to another thread instead.
* Shells must marshal callback data to the main thread themselves; the
  structs are only valid until the callback returns (see §5).

## 7. How each shell links the core

### Android — JNI shared library via cargo-ndk

Build the cdylib per ABI and drop it under `jniLibs` (Gradle packages it
automatically):

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64
cargo install cargo-ndk
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
    -o shells/android/app/src/main/jniLibs \
    build --release -p airdrop-ffi
```

Kotlin declares `external fun`s in `tech.airdrop4e.A4eCore` and calls
`System.loadLibrary("airdrop_ffi")`. The JNI glue lives **inside
`libairdrop_ffi.so`** (a `#[cfg(target_os = "android")]` module of
`airdrop-ffi`, built on the `jni` crate). Two acceptable glue styles —
this codebase uses style (a):

a) **`Java_*` exports** — the crate exports symbols matching Kotlin's
   declarations exactly, e.g.
   `Java_tech_airdrop4e_A4eCore_receiverStart(JNIEnv*, jobject, jstring, jstring, jstring, jint, jint, jobject)`.
   (Kotlin `object A4eCore` `external fun`s are *instance* natives →
   `jobject`, not `jclass`.)
b) `JNI_OnLoad` + `RegisterNatives` — keeps the C symbols name-agnostic;
   acceptable alternative if the symbol names get unwieldy.

JNI marshalling contract (what the shim constructs/reads):

| Kotlin type | JNI signature used by the shim |
|---|---|
| `A4eFileMeta(name, uti, size)` | `<init>(Ljava/lang/String;Ljava/lang/String;J)V` |
| `A4eAsk(senderName, senderModel, transferId, files)` | `<init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ltech/airdrop4e/A4eFileMeta;)V` |
| `A4ePeer(ident, name, addr, port)` | `<init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V` |
| `A4eCore.AskHandler` | `onAsk(Ltech/airdrop4e/A4eAsk;)Z` — `true` = accept |
| `A4eCore.PeerCallback` | `onPeer(Ltech/airdrop4e/A4ePeer;)V` |
| `A4eSendOpts` | read fields `computerName/model/serviceId` (`String?`), `hasAuthTag` (`Z`), `authTag` (`[B`, len 3), `askTimeoutMs` (`J`) |

* Errors: the shim converts `-1` + message into a thrown
  `tech.airdrop4e.A4eException`, so every Kotlin `external fun` returns
  `Unit`/plain values and throws on failure.
* Callbacks: the shim must `AttachCurrentThread` core worker threads before
  invoking `onAsk`/`onPeer` (use the `JavaVM` cached in `JNI_OnLoad`) and
  hold the handler/callback `jobject` as a `NewGlobalRef` for the
  registration lifetime (until `a4e_receiver_stop` returns / end of
  `a4e_browse`).
* **UniFFI alternative:** if hand-rolled JNI proves brittle, `airdrop-ffi`
  can instead expose a UniFFI proc-macro interface and generate the Kotlin
  (and Swift) bindings — `uniffi::setup_scaffolding!` plus
  `cargo uniffi-bindgen generate`. The C ABI above remains the fallback for
  platforms UniFFI doesn't cover; do not design shells that depend on
  UniFFI specifics.

### macOS — static library + bridging header

```sh
cargo build --release -p airdrop-ffi       # → target/release/libairdrop_ffi.a
```

* **SwiftPM (this repo's skeleton):** a C target `CA4e` whose
  `publicHeadersPath` is `include/` containing `a4e.h`; SwiftPM generates a
  module map automatically → `import CA4e`. The archive is linked via
  `-L`/`linkedLibrary` linker settings (see `macos/Package.swift` and its
  README).
* **Xcode:** add `a4e.h` to the target and create an
  Objective-C bridging header (`*-Bridging-Header.h`) that `#import`s it;
  add `libairdrop_ffi.a` under *Link Binary With Libraries* and the
  containing dir to *Library Search Paths*.
* Imported shape in Swift: `a4e_ask` etc. become structs; function-pointer
  typedefs become `@convention(c)` closures — pass non-capturing closures
  or globals, bridge state through the `void *ctx` with
  `Unmanaged.passRetained(...)`/`takeUnretainedValue()` (retain until
  `a4e_receiver_stop` returns).
* Sandboxed / App Store builds need `com.apple.developer.networking.multicast`
  (mDNS) plus the usual `network.client`/`network.server` entitlements.
  `awdl0` exists natively — link-local peers arrive with a `%awdl0` zone.

### Other platforms

Windows/Linux shells link the same `.dll`/`.so` or static lib; the ABI is
platform-neutral C99. `a4e_last_error` is thread-local per the C11
`_Thread_local` equivalent on each OS.

## 8. ABI stability notes

* Structs are standard C layout (natural alignment, no packing pragmas).
  `a4e_send_opts` carries `struct_size` for forward compatibility: callers
  set it to `sizeof(a4e_send_opts)`; the core ignores unknown tail fields
  when a newer shell talks to an older lib and vice versa.
* `a4e_ask`/`a4e_peer` are **inout-only** (core → shell inside a callback);
  their layout may be extended at the tail in future minor versions — new
  fields are only valid during the callback anyway.
* Version skew beyond that is out of scope for v0: shell and library are
  shipped together in one app bundle.
