import CA4e
import Foundation

public enum A4eVisibility: Int32 {
    case everyone = 0
    case contactsOnly = 1
}

public struct A4eError: Error, CustomStringConvertible {
    public let message: String
    public var description: String { message }
}

/// Retained-box types for bridging `void *ctx` — see ffi.md §5/§6.
private final class AskBox {
    let block: (A4eAsk) -> Bool
    init(_ block: @escaping (A4eAsk) -> Bool) { self.block = block }
}
private final class PeerBox {
    let block: (A4ePeer) -> Void
    init(_ block: @escaping (A4ePeer) -> Void) { self.block = block }
}

/// C trampolines: no captures, so they convert to C function pointers.
/// Both run on core threads; everything inside the structs is copied into
/// Swift values before the callback returns (ffi.md §5).
private let a4eAskTrampoline: a4e_ask_callback = { ctx, ask in
    guard let ctx, let ask else { return 0 }
    let box = Unmanaged<AskBox>.fromOpaque(ctx).takeUnretainedValue()
    return box.block(A4eAsk(ask.pointee)) ? 1 : 0
}

private let a4ePeerTrampoline: a4e_peer_callback = { ctx, peer in
    guard let ctx, let peer else { return }
    let box = Unmanaged<PeerBox>.fromOpaque(ctx).takeUnretainedValue()
    box.block(A4ePeer(peer.pointee))
}

/// Thin Swift wrapper over the `a4e_*` C API. All blocking calls run on
/// whichever thread invokes them — call them off the main thread
/// (the view model uses DispatchQueue.global()).
public final class A4eCore {

    public static let shared = A4eCore()

    /// Opaque ctx retained while the receiver runs; released on stop.
    private var askCtx: UnsafeMutableRawPointer?

    private init() {}

    // MARK: lifecycle

    /// Must succeed once before startReceiver/sendFiles.
    public func loadIdentity(keysDir: String, computerName: String?) throws {
        var err: UnsafeMutablePointer<CChar>?
        guard a4e_identity_load_or_create(keysDir, computerName, &err) == 0 else {
            throw Self.takeError(&err)
        }
    }

    // MARK: receiver

    /// `onAsk` runs on a core worker thread and MAY block while the sender
    /// waits (≤ ~60 s). Post the prompt to the main thread and wait on a
    /// semaphore — see AskGate in ContentView.swift.
    public func startReceiver(
        name: String? = nil,
        model: String? = nil,
        destDir: String,
        visibility: A4eVisibility,
        port: UInt16 = 0,
        onAsk: (@Sendable (A4eAsk) -> Bool)? = nil
    ) throws {
        precondition(askCtx == nil, "receiver already running")

        let ctx: UnsafeMutableRawPointer?
        if let onAsk {
            ctx = Unmanaged.passRetained(AskBox(onAsk)).toOpaque()
        } else {
            ctx = nil   // NULL cb = auto-accept every /Ask
        }

        guard a4e_receiver_start(name, model, destDir,
                                 visibility.rawValue, port,
                                 onAsk == nil ? nil : a4eAskTrampoline,
                                 ctx) == 0 else {
            if let ctx { Unmanaged<AskBox>.fromOpaque(ctx).release() }
            throw Self.lastError()
        }
        askCtx = ctx
    }

    /// Idempotent. Never call from inside the ask callback's thread.
    public func stopReceiver() {
        a4e_receiver_stop()
        if let ctx = askCtx {
            Unmanaged<AskBox>.fromOpaque(ctx).release()
            askCtx = nil
        }
    }

    // MARK: sender

    /// Blocks the calling thread for up to `timeoutMs`; `onPeer` fires on
    /// this same thread once per viable receiver.
    public func browse(timeoutMs: UInt32,
                       onPeer: @escaping (A4ePeer) -> Void) throws {
        let ctx = Unmanaged.passRetained(PeerBox(onPeer)).toOpaque()
        defer { Unmanaged<PeerBox>.fromOpaque(ctx).release() }

        guard a4e_browse(timeoutMs, a4ePeerTrampoline, ctx) == 0 else {
            throw Self.lastError()
        }
    }

    /// Blocks for the whole Discover/Ask/Upload exchange.
    /// `addr`: "ip:port" or "[v6%zone]:port" (see `A4ePeer.endpoint`).
    public func sendFiles(paths: [String],
                          to addr: String,
                          opts: A4eSendOpts? = nil) throws {
        var cPaths: [UnsafePointer<CChar>?] = paths.map { UnsafePointer(strdup($0)) }
        defer { cPaths.forEach { free(UnsafeMutablePointer(mutating: $0)) } }

        var allocs: [UnsafeMutablePointer<CChar>?] = []
        var cOpts = opts.map { o -> a4e_send_opts in
            let (c, a) = o.makeC()
            allocs = a
            return c
        }
        defer { allocs.forEach { free($0) } }

        var err: UnsafeMutablePointer<CChar>?
        let rc = cPaths.withUnsafeMutableBufferPointer { buf -> Int32 in
            if var c = cOpts {
                return withUnsafePointer(to: &c) {
                    a4e_send_files(buf.baseAddress, buf.count, addr, $0, &err)
                }
            }
            return a4e_send_files(buf.baseAddress, buf.count, addr, nil, &err)
        }
        guard rc == 0 else { throw Self.takeError(&err) }
    }

    // MARK: errors

    /// Consumes a `char**` out-param message (frees it with a4e_string_free).
    private static func takeError(_ err: inout UnsafeMutablePointer<CChar>?) -> A4eError {
        defer {
            if let err { a4e_string_free(err) }
            err = nil
        }
        return A4eError(message: err.map { String(cString: $0) } ?? "unknown error")
    }

    /// Borrows the thread-local message (functions without an err param).
    private static func lastError() -> A4eError {
        A4eError(message: a4e_last_error().map { String(cString: $0) } ?? "unknown error")
    }
}
