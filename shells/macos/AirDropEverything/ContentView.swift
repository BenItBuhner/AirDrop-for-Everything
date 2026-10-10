import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Parks a core-thread ask callback until the UI answers — ffi.md §6 says
/// the callback may block (the sender is waiting), ~60 s budget.
final class AskGate {
    private let sema = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var answered = false
    private var accept = false

    /// Core thread: blocks until `respond` or the timeout elapses.
    func wait(timeout: TimeInterval) -> Bool {
        let inTime = sema.wait(timeout: .now() + timeout) == .success
        lock.lock(); defer { lock.unlock() }
        return inTime && accept
    }

    /// Main thread: deliver the user's decision.
    func respond(_ accept: Bool) {
        lock.lock()
        let first = !answered
        answered = true
        self.accept = accept
        lock.unlock()
        if first { sema.signal() }
    }
}

/// One ask + its gate, so overlapping senders each get their own prompt.
struct PendingAsk: Identifiable {
    let ask: A4eAsk
    let gate: AskGate
    var id: String { ask.id }
}

final class AppViewModel: ObservableObject {
    @Published private(set) var receiving = false
    @Published private(set) var browsing = false
    @Published private(set) var peers: [A4ePeer] = []
    @Published var selectedPeerID: String?
    @Published private(set) var stagedFiles: [URL] = []
    @Published private(set) var pendingAsks: [PendingAsk] = []
    @Published private(set) var log: [String] = []

    var selectedPeer: A4ePeer? { peers.first { $0.id == selectedPeerID } }

    private let core = A4eCore.shared
    let keysDir: URL
    let destDir: URL

    init() {
        let fm = FileManager.default
        let support = fm.urls(for: .applicationSupportDirectory,
                              in: .userDomainMask).first!
            .appendingPathComponent("AirDrop4E", isDirectory: true)
        keysDir = support.appendingPathComponent("keys", isDirectory: true)
        destDir = fm.urls(for: .downloadsDirectory, in: .userDomainMask).first!
            .appendingPathComponent("AirDrop4E", isDirectory: true)
        try? fm.createDirectory(at: keysDir, withIntermediateDirectories: true)
        try? fm.createDirectory(at: destDir, withIntermediateDirectories: true)

        let keysPath = keysDir.path
        let name = Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        DispatchQueue.global().async { [self] in
            do {
                try core.loadIdentity(keysDir: keysPath, computerName: name)
                appendLog("identity ready")
            } catch {
                appendLog("identity failed: \(error.localizedDescription)")
            }
        }
    }

    // MARK: receiver

    func setReceiving(_ on: Bool) {
        if on {
            let dest = destDir.path
            DispatchQueue.global().async { [self] in
                do {
                    try core.startReceiver(destDir: dest,
                                           visibility: .everyone) { [weak self] ask in
                        self?.handleAsk(ask) ?? false
                    }
                    DispatchQueue.main.async { self.receiving = true }
                    appendLog("receiver up → \(self.destDir.path)")
                } catch {
                    appendLog("receiver failed: \(error.localizedDescription)")
                }
            }
        } else {
            receiving = false
            // stop joins core workers — never call it on a callback thread
            DispatchQueue.global().async { [self] in core.stopReceiver() }
            appendLog("receiver stopped")
        }
    }

    /// Runs on a core worker thread — parks until the alert is answered.
    private func handleAsk(_ ask: A4eAsk) -> Bool {
        let pending = PendingAsk(ask: ask, gate: AskGate())
        DispatchQueue.main.async { self.pendingAsks.append(pending) }
        appendLog("ask from \(ask.senderName): \(ask.files.count) file(s)")
        let accepted = pending.gate.wait(timeout: 60)
        appendLog("\(ask.senderName): \(accepted ? "accepted" : "declined")")
        return accepted
    }

    func respond(to pending: PendingAsk, accept: Bool) {
        pendingAsks.removeAll { $0.id == pending.id }
        pending.gate.respond(accept)
    }

    // MARK: browse / send

    func browse(timeoutMs: UInt32 = 3000) {
        guard !browsing else { return }
        browsing = true
        peers = []
        DispatchQueue.global().async { [self] in
            defer { DispatchQueue.main.async { self.browsing = false } }
            do {
                try core.browse(timeoutMs: timeoutMs) { peer in
                    DispatchQueue.main.async {
                        if !self.peers.contains(peer) { self.peers.append(peer) }
                    }
                }
            } catch {
                appendLog("browse failed: \(error.localizedDescription)")
            }
        }
    }

    func stage(_ providers: [NSItemProvider]) {
        for provider in providers {
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url, url.isFileURL else { return }
                DispatchQueue.main.async {
                    if !self.stagedFiles.contains(url) {
                        self.stagedFiles.append(url)
                    }
                }
            }
        }
    }

    func setStaged(_ urls: [URL]) { stagedFiles = urls.filter(\.isFileURL) }

    func sendStaged() {
        guard let peer = selectedPeer, !stagedFiles.isEmpty else { return }
        let paths = stagedFiles.map(\.path)
        let endpoint = peer.endpoint
        let label = peer.name
        DispatchQueue.global().async { [self] in
            appendLog("sending \(paths.count) file(s) to \(label) @ \(endpoint)…")
            do {
                try core.sendFiles(paths: paths, to: endpoint)
                appendLog("sent to \(label)")
            } catch {
                appendLog("send failed: \(error.localizedDescription)")
            }
        }
    }

    private func appendLog(_ line: String) {
        let stamp = Self.stamp.string(from: Date())
        DispatchQueue.main.async {
            self.log.append("\(stamp)  \(line)")
            if self.log.count > 200 { self.log.removeFirst(self.log.count - 200) }
        }
    }

    private static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()
}

// MARK: - UI

struct ContentView: View {
    @StateObject private var vm = AppViewModel()
    @State private var dropTargeted = false

    var body: some View {
        VStack(spacing: 14) {
            GroupBox("Receiver") {
                HStack {
                    Toggle("Discoverable — Everyone",
                           isOn: Binding(get: { vm.receiving },
                                         set: { vm.setReceiving($0) }))
                        .toggleStyle(.switch)
                    Spacer()
                    Text("saves to \(vm.destDir.lastPathComponent)/")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            GroupBox("Peers") {
                VStack(spacing: 6) {
                    List(selection: $vm.selectedPeerID) {
                        ForEach(vm.peers) { peer in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(peer.name)
                                Text("\(peer.ident) · \(peer.endpoint)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            .tag(peer.id)
                        }
                    }
                    .frame(minHeight: 110)
                    HStack {
                        Button(vm.browsing ? "Browsing…" : "Find peers") {
                            vm.browse()
                        }
                        .disabled(vm.browsing)
                        Spacer()
                    }
                }
            }

            GroupBox("Send") {
                VStack(spacing: 8) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8)
                            .strokeBorder(
                                style: StrokeStyle(lineWidth: 1.5, dash: [6]))
                            .foregroundStyle(
                                dropTargeted ? Color.accentColor : .secondary)
                        VStack(spacing: 4) {
                            Image(systemName: "arrow.down.doc")
                            Text(vm.stagedFiles.isEmpty
                                 ? "Drop files here"
                                 : vm.stagedFiles.map(\.lastPathComponent)
                                    .joined(separator: ", "))
                                .font(.caption)
                                .multilineTextAlignment(.center)
                                .lineLimit(2)
                        }
                        .padding(8)
                    }
                    .frame(minHeight: 72)
                    .onDrop(of: [.fileURL], isTargeted: $dropTargeted) {
                        vm.stage($0)
                        return true
                    }
                    HStack {
                        Button("Choose Files…") { pickFiles() }
                        Spacer()
                        Button("Send") { vm.sendStaged() }
                            .disabled(vm.selectedPeer == nil
                                      || vm.stagedFiles.isEmpty)
                    }
                }
            }

            GroupBox("Log") {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(vm.log.indices, id: \.self) { i in
                            Text(vm.log[i])
                                .font(.system(.caption, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .padding(4)
                }
                .frame(minHeight: 110)
            }
        }
        .padding(20)
        .frame(minWidth: 540, minHeight: 620)
        // The head of the ask queue drives the prompt; the presented flag
        // is read-only — dismissal happens via the buttons (respond()).
        .alert("Incoming AirDrop",
               isPresented: Binding(
                   get: { vm.pendingAsks.isEmpty == false },
                   set: { _ in }),
               presenting: vm.pendingAsks.first) { pending in
            Button("Accept") { vm.respond(to: pending, accept: true) }
            Button("Decline", role: .cancel) {
                vm.respond(to: pending, accept: false)
            }
        } message: { pending in
            Text(askDescription(pending.ask))
        }
    }

    private func askDescription(_ ask: A4eAsk) -> String {
        let names = ask.files.prefix(4).map(\.name).joined(separator: ", ")
        let more = ask.files.count > 4 ? " +\(ask.files.count - 4) more" : ""
        let size = ByteCountFormatter.string(
            fromByteCount: Int64(ask.totalBytes), countStyle: .file)
        return "\(ask.senderName) (\(ask.senderModel)) wants to send " +
            "\(ask.files.count) file(s), \(size):\n\(names)\(more)"
    }

    private func pickFiles() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        if panel.runModal() == .OK {
            vm.setStaged(panel.urls)
        }
    }
}
