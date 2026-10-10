package tech.airdrop4e

import android.app.Application
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.OpenableColumns
import android.provider.Settings
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

/**
 * App state. All FFI calls happen on Dispatchers.IO — browse/send block and
 * the ask callback runs on a core thread; nothing touches the main thread.
 */
class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val multicast = MulticastLockHolder(application)

    /** Where received files land. App-private external dir — readable in
     *  Files apps under Android/data/… without any storage permission. */
    val destDir: File =
        (application.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
            ?: application.filesDir).resolve("drops").apply { mkdirs() }

    private val _identityReady = MutableStateFlow(false)
    val identityReady: StateFlow<Boolean> = _identityReady.asStateFlow()

    private val _receiverOn = MutableStateFlow(false)
    val receiverOn: StateFlow<Boolean> = _receiverOn.asStateFlow()

    private val _peers = MutableStateFlow<List<A4ePeer>>(emptyList())
    val peers: StateFlow<List<A4ePeer>> = _peers.asStateFlow()

    private val _browsing = MutableStateFlow(false)
    val browsing: StateFlow<Boolean> = _browsing.asStateFlow()

    /** Files staged in the outbox, ready to send to the tapped peer. */
    private val _staged = MutableStateFlow<List<File>>(emptyList())
    val staged: StateFlow<List<File>> = _staged.asStateFlow()

    /** Asks awaiting a user decision (queue — senders can overlap). */
    private val _pendingAsks = MutableStateFlow<List<A4eAsk>>(emptyList())
    val pendingAsks: StateFlow<List<A4eAsk>> = _pendingAsks.asStateFlow()

    private val _log = MutableStateFlow<List<String>>(emptyList())
    val log: StateFlow<List<String>> = _log.asStateFlow()

    /** transferId -> the deferred the core thread is parked on. */
    private val askAnswers = ConcurrentHashMap<String, CompletableDeferred<Boolean>>()

    /** Runs on a core worker thread — see ffi.md §6. May block ~60 s. */
    private val askHandler = A4eCore.AskHandler { ask ->
        val answer = CompletableDeferred<Boolean>()
        askAnswers[ask.transferId] = answer
        _pendingAsks.update { it + ask }
        log("ask from ${ask.senderName}: ${ask.files.size} file(s), ${ask.totalBytes} B")
        val accepted = runBlocking {
            withTimeoutOrNull(ASK_TIMEOUT_MS) { answer.await() }
        } ?: false
        askAnswers.remove(ask.transferId)
        _pendingAsks.update { it.filterNot { a -> a.transferId == ask.transferId } }
        log("${ask.senderName}: ${if (accepted) "accepted" else "declined"}")
        accepted
    }

    init {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val keys = File(application.filesDir, "keys").apply { mkdirs() }
                A4eCore.identityLoadOrCreate(keys.absolutePath, deviceName())
                _identityReady.value = true
                log("identity ready")
            } catch (e: A4eException) {
                log("identity failed: ${e.message}")
            }
        }
    }

    fun setReceiver(on: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            if (on) {
                try {
                    multicast.acquire()
                    A4eCore.receiverStart(
                        name = null,                    // identity name
                        model = null,                   // "MacBookPro18,3"
                        destDir = destDir.absolutePath,
                        visibility = A4eCore.VISIBILITY_EVERYONE,
                        port = A4eCore.PORT_DEFAULT,
                        handler = askHandler,
                    )
                    _receiverOn.value = true
                    log("receiver up → ${destDir.absolutePath}")
                } catch (e: A4eException) {
                    multicast.release()
                    log("receiver failed: ${e.message}")
                }
            } else {
                A4eCore.receiverStop()
                multicast.release()
                _receiverOn.value = false
                log("receiver stopped")
            }
        }
    }

    fun browse(timeoutMs: Int = 3000) {
        if (_browsing.value) return
        _browsing.value = true
        _peers.value = emptyList()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                multicast.acquire()
                try {
                    A4eCore.browse(timeoutMs) { peer ->
                        _peers.update { list ->
                            if (list.any { it.ident == peer.ident }) list else list + peer
                        }
                    }
                } finally {
                    multicast.release()
                }
            } catch (e: A4eException) {
                log("browse failed: ${e.message}")
            }
            _browsing.value = false
        }
    }

    /**
     * SAF returns content:// URIs, but a4e_send_files wants filesystem
     * paths — copy the picks into a per-send outbox in the cache dir.
     */
    fun stage(uris: List<Uri>) {
        val cr = getApplication<Application>().contentResolver
        viewModelScope.launch(Dispatchers.IO) {
            val dir = File(getApplication<Application>().cacheDir, "outbox").apply {
                listFiles()?.forEach { it.delete() }
                mkdirs()
            }
            val out = mutableListOf<File>()
            for (uri in uris) {
                val name = (displayName(uri) ?: "item-${out.size}")
                    .substringAfterLast('/')
                    .let { File(it).name.ifBlank { "item-${out.size}" } }
                val dest = File(dir, name)
                try {
                    cr.openInputStream(uri)?.use { src ->
                        dest.outputStream().use { src.copyTo(it) }
                    } ?: throw A4eException("cannot open $uri")
                    out += dest
                } catch (e: Exception) {
                    log("staging $name failed: ${e.message}")
                }
            }
            _staged.value = out
            log("staged ${out.size} file(s) — tap a peer to send")
        }
    }

    fun sendTo(peer: A4ePeer) {
        val files = _staged.value
        if (files.isEmpty()) {
            log("pick files first")
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                log("sending ${files.size} file(s) to ${peer.displayName} @ ${peer.endpoint}")
                A4eCore.sendFiles(
                    files.map { it.absolutePath }.toTypedArray(),
                    peer.endpoint,
                    opts = null,
                )
                log("sent to ${peer.displayName}")
            } catch (e: A4eException) {
                log("send failed: ${e.message}")
            }
        }
    }

    fun clearStaged() {
        _staged.value.forEach { it.delete() }
        _staged.value = emptyList()
    }

    /** UI answers the head of the ask queue. */
    fun answerAsk(accept: Boolean) {
        val ask = _pendingAsks.value.firstOrNull() ?: return
        _pendingAsks.update { it - ask }
        askAnswers[ask.transferId]?.complete(accept)
    }

    private fun displayName(uri: Uri): String? =
        getApplication<Application>().contentResolver
            .query(uri, null, null, null, null)?.use { c ->
                val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (i >= 0 && c.moveToFirst()) c.getString(i) else null
            }

    private fun deviceName(): String =
        Settings.Global.getString(
            getApplication<Application>().contentResolver,
            Settings.Global.DEVICE_NAME,
        )?.takeIf { it.isNotBlank() } ?: Build.MODEL

    private fun log(msg: String) {
        val stamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        _log.update { (it + "$stamp  $msg").takeLast(LOG_MAX) }
    }

    override fun onCleared() {
        A4eCore.receiverStop()
        multicast.release()
    }

    private companion object {
        /** Sender Ask timeout is ~90 s; answer well inside it. */
        const val ASK_TIMEOUT_MS = 60_000L
        const val LOG_MAX = 200
    }
}
