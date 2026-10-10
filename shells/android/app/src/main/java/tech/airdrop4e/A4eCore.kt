package tech.airdrop4e

/**
 * JNI bindings for `libairdrop_ffi` — the C ABI documented in shells/ffi.md.
 *
 * The `a4e_*` C functions are plain C; the JNI glue (Java_* exports, callback
 * marshalling, thread attach) lives inside `libairdrop_ffi.so` itself — see
 * ffi.md §7 "Android". Kotlin-visible rules:
 *
 *  - `external fun`s throw [A4eException] instead of returning int/err**.
 *  - [AskHandler.onAsk] runs on a core worker thread and MAY block — the
 *    sender is waiting for the answer (≈60 s budget). Post to the UI, wait
 *    on a latch, return the decision. May be called concurrently.
 *  - [PeerCallback.onPeer] runs on the thread that called [browse].
 *  - All callback structs are copies — safe to keep in Kotlin.
 */

/** Mirrors `a4e_filemeta`. Constructed by native code. */
class A4eFileMeta(
    val name: String,
    val uti: String,
    val size: Long,
)

/** Mirrors `a4e_ask`. Constructed by native code; `files` is an array. */
class A4eAsk(
    val senderName: String,
    val senderModel: String,
    val transferId: String,
    val files: Array<A4eFileMeta>,
) {
    val totalBytes: Long get() = files.sumOf { it.size }
}

/**
 * Mirrors `a4e_peer`. `name` falls back to ident when /Discover was
 * refused; `addr` carries a %zone suffix for link-local v6 (awdl0).
 */
class A4ePeer(
    val ident: String,
    val name: String?,
    val addr: String,
    val port: Int,
) {
    /** "ip:port" form accepted by [A4eCore.sendFiles]. */
    val endpoint: String
        get() = if (addr.contains(':')) "[$addr]:$port" else "$addr:$port"
    val displayName: String get() = name ?: ident
}

/** Mirrors `a4e_send_opts` (all-null/default fields = NULL opts). */
class A4eSendOpts(
    val computerName: String? = null,
    val computerModel: String? = null,
    val serviceId: String? = null,
    val hasAuthTag: Boolean = false,
    val authTag: ByteArray = ByteArray(3),   // BLE SenderIdentityAuthTag
    val askTimeoutMs: Long = 0,              // 0 -> core default 90 s
)

class A4eException(message: String) : Exception(message)

object A4eCore {

    const val VISIBILITY_EVERYONE = 0
    const val VISIBILITY_CONTACTS = 1

    /** 0 → core default (8771). */
    const val PORT_DEFAULT = 0

    init {
        System.loadLibrary("airdrop_ffi")
    }

    fun interface AskHandler {
        /** Called on a core thread. Return true to accept the transfer. */
        fun onAsk(ask: A4eAsk): Boolean
    }

    fun interface PeerCallback {
        /** Called on the thread running [browse], sequentially. */
        fun onPeer(peer: A4ePeer)
    }

    /** Load or create the TLS identity. Call once before receiver/sender. */
    @Throws(A4eException::class)
    external fun identityLoadOrCreate(keysDir: String, computerName: String?)

    /**
     * Start the receiver (mDNS announce + TLS /Discover /Ask /Upload).
     * `name`/`model` null → core defaults. `port` 0 → 8771.
     * Returns once bound; [handler] fires on core threads afterwards.
     */
    @Throws(A4eException::class)
    external fun receiverStart(
        name: String?,
        model: String?,
        destDir: String,
        visibility: Int,
        port: Int,
        handler: AskHandler?,
    )

    /** Stop the receiver. Idempotent; no callbacks fire after it returns. */
    external fun receiverStop()

    /**
     * Browse _airdrop._tcp for up to [timeoutMs], /Discover-probing each
     * candidate. Blocks the calling thread; [cb] fires on it sequentially.
     * Hold a WifiManager.MulticastLock while browsing — see
     * [MulticastLockHolder].
     */
    @Throws(A4eException::class)
    external fun browse(timeoutMs: Int, cb: PeerCallback)

    /**
     * Send files to a receiver. [addr] is "ip:port" or "[v6%zone]:port"
     * (see [A4ePeer.endpoint]). [paths] must be real filesystem paths —
     * content:// URIs must be copied to a file first (see the ViewModel's
     * staging step). Blocks for the whole Discover/Ask/Upload exchange.
     */
    @Throws(A4eException::class)
    external fun sendFiles(paths: Array<String>, addr: String, opts: A4eSendOpts?)

    /** Borrowed thread-local error string, or null. Diagnostic only —
     *  the [A4eException]s already carry it. */
    external fun lastError(): String?
}
