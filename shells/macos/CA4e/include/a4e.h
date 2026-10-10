/*
 * a4e.h — C ABI for airdrop-ffi (the Rust airdrop-core behind a C interface).
 *
 * Canonical header — semantics (ownership, threading, errors, linking) are
 * specified in shells/ffi.md. All functions are extern "C", return 0/-1,
 * and are safe to call from any thread. Callbacks fire on core threads;
 * callback structs and their strings are borrowed for the callback only.
 */
#ifndef A4E_H
#define A4E_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------- types ---------------- */

/* One file entry from a sender's /Ask proposal. */
typedef struct {
    const char *name;        /* file name, no path separators */
    const char *uti;         /* Apple UTI, e.g. "public.jpeg"   */
    uint64_t    size;        /* bytes                           */
} a4e_filemeta;

/* An incoming /Ask, delivered to a4e_ask_callback. */
typedef struct {
    const char         *sender_name;   /* sender's computer name */
    const char         *sender_model;  /* e.g. "MacBookPro18,3"  */
    const char         *transfer_id;   /* UUID for this transfer */
    size_t              files_len;     /* number of entries      */
    const a4e_filemeta *files;         /* files_len entries      */
} a4e_ask;

/* Return 1 to accept the transfer, 0 to decline. May block (sender waits);
   fires on a core worker thread — post UI to main and wait on a semaphore. */
typedef int (*a4e_ask_callback)(void *ctx, const a4e_ask *ask);

/* One discovered receiver (mDNS + /Discover probe). */
typedef struct {
    const char *ident;   /* 12-hex _airdrop._tcp instance id            */
    const char *name;    /* display name; NULL if /Discover unanswered  */
    const char *addr;    /* primary IP, no port. Link-local v6 carries  */
                        /* its %zone suffix (e.g. fe80::1%awdl0) so the  */
                        /* shell can connect as-is                       */
    uint16_t    port;    /* TLS port (usually 8771)                     */
} a4e_peer;

typedef void (*a4e_peer_callback)(void *ctx, const a4e_peer *peer);

/* Optional knobs for a4e_send_files. Pass NULL for all defaults. */
typedef struct {
    uint32_t    struct_size;    /* callers set sizeof(a4e_send_opts)      */
    const char *computer_name;  /* NULL -> name given at identity load   */
    const char *computer_model; /* NULL -> "MacBookPro18,3"              */
    const char *service_id;     /* NULL -> stable per-machine 12-hex id  */
    int32_t     has_auth_tag;   /* !=0 -> auth_tag is sent in /Ask       */
    uint8_t     auth_tag[3];    /* BLE SenderIdentityAuthTag             */
    uint64_t    ask_timeout_ms; /* 0 -> 90_000                           */
} a4e_send_opts;

/* ---------------- lifecycle ---------------- */

/* Load keys_dir/{certificate,key}.pem, creating a self-signed identity on
   first run. Must succeed before receiver_start / send_files. Idempotent.
   computer_name may be NULL -> OS hostname. On failure *err holds a message
   the caller frees with a4e_string_free. */
int a4e_identity_load_or_create(const char *keys_dir,
                                const char *computer_name,
                                char **err);

/* ---------------- receiver (singleton) ---------------- */

/* visibility: 0 = Everyone, 1 = Contacts Only.
   port:       0 = default 8771; otherwise explicit.
   cb:         NULL = auto-accept every /Ask.
   ctx:        borrowed by the core until a4e_receiver_stop returns.
   Returns immediately; serving runs on core threads. -1 if already
   running or identity not loaded (a4e_last_error has the message). */
int a4e_receiver_start(const char *name,
                       const char *model,
                       const char *dest_dir,
                       int visibility,
                       unsigned short port,
                       a4e_ask_callback cb,
                       void *ctx);

/* Stop the receiver. Idempotent; joins workers; no callbacks afterwards.
   Never call from inside a callback on that callback's thread (deadlock). */
void a4e_receiver_stop(void);

/* ---------------- sender ---------------- */

/* Send all paths to the receiver at addr ("ipv4:port", "[v6]:port", or
   "[v6%zone]:port"). Blocks the calling thread for the whole
   Discover/Ask/Upload exchange. *err on failure (a4e_string_free it). */
int a4e_send_files(const char **paths,
                   size_t n,
                   const char *addr,
                   const a4e_send_opts *opts,
                   char **err);

/* Browse _airdrop._tcp for up to timeout_ms, /Discover-probing each
   candidate. Blocks the calling thread; cb fires on that same thread,
   sequentially, once per viable peer. cb may be NULL. */
int a4e_browse(uint32_t timeout_ms, a4e_peer_callback cb, void *ctx);

/* ---------------- misc ---------------- */

/* Free a string the core returned via a char** out-param. NULL-safe. */
void a4e_string_free(char *s);

/* Thread-local message for the most recent failed call on this thread.
   Borrowed — do not free; NULL if the last call succeeded. */
const char *a4e_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* A4E_H */
