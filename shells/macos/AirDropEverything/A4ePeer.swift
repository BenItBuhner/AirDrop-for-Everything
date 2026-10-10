import CA4e
import Foundation

/// Mirrors `a4e_filemeta` (shells/ffi.md).
public struct A4eFileMeta: Hashable {
    public let name: String
    public let uti: String
    public let size: UInt64

    init(_ c: a4e_filemeta) {
        name = c.name.map { String(cString: $0) } ?? ""
        uti = c.uti.map { String(cString: $0) } ?? ""
        size = c.size
    }
}

/// Mirrors `a4e_ask` — an incoming transfer proposal.
public struct A4eAsk: Identifiable {
    public let senderName: String
    public let senderModel: String
    public let transferId: String
    public let files: [A4eFileMeta]

    public var id: String { transferId }
    public var totalBytes: UInt64 { files.reduce(0) { $0 + $1.size } }

    /// Copies all borrowed C strings — valid past the callback return.
    init(_ c: a4e_ask) {
        senderName = c.sender_name.map { String(cString: $0) } ?? "Unknown"
        senderModel = c.sender_model.map { String(cString: $0) } ?? ""
        transferId = c.transfer_id.map { String(cString: $0) } ?? UUID().uuidString
        let buf = UnsafeBufferPointer(start: c.files, count: c.files_len)
        files = buf.map(A4eFileMeta.init)
    }
}

/// Mirrors `a4e_peer` — one discovered receiver.
public struct A4ePeer: Identifiable, Hashable {
    /// 12-hex `_airdrop._tcp` instance id.
    public let ident: String
    /// Display name; falls back to ident if the peer refused /Discover.
    public let name: String
    public let addr: String
    public let port: UInt16

    public var id: String { ident }
    /// "ip:port" / "[v6]:port" form accepted by `a4e_send_files`.
    public var endpoint: String {
        addr.contains(":") ? "[\(addr)]:\(port)" : "\(addr):\(port)"
    }

    init(_ c: a4e_peer) {
        ident = c.ident.map { String(cString: $0) } ?? "?"
        name = c.name.map { String(cString: $0) } ?? ident
        addr = c.addr.map { String(cString: $0) } ?? ""
        port = c.port
    }
}

/// Mirrors `a4e_send_opts`. Pass nil to `A4eCore.sendFiles` for defaults.
public struct A4eSendOpts {
    public var computerName: String? = nil
    public var computerModel: String? = nil
    public var serviceId: String? = nil
    /// 3-byte BLE SenderIdentityAuthTag, if the shell emitted a wake advert.
    public var authTag: (UInt8, UInt8, UInt8)? = nil
    /// 0 → core default (90 s).
    public var askTimeoutMs: UInt64 = 0

    public init() {}

    /// Builds the C struct. Returns it plus the strdup'd strings so the
    /// caller can free them after the FFI call returns.
    func makeC() -> (a4e_send_opts, [UnsafeMutablePointer<CChar>?]) {
        var allocs: [UnsafeMutablePointer<CChar>?] = []
        func dup(_ s: String?) -> UnsafePointer<CChar>? {
            guard let s else { return nil }
            let p = strdup(s)
            allocs.append(p)
            return UnsafePointer(p)
        }
        var c = a4e_send_opts()
        c.struct_size = UInt32(MemoryLayout<a4e_send_opts>.size)
        c.computer_name = dup(computerName)
        c.computer_model = dup(computerModel)
        c.service_id = dup(serviceId)
        if let tag = authTag {
            c.has_auth_tag = 1
            c.auth_tag = tag
        }
        c.ask_timeout_ms = askTimeoutMs
        return (c, allocs)
    }
}
