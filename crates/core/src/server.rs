//! The receiver: TLS server answering /Discover, /Ask, /Upload.
//! Port of prototype server.py (itself a port of airdrop-serve.py).
//!
//! Threaded accept loop over rustls-wrapped TcpListeners; request bodies are
//! validated before any read (`body_plan`), /Upload spools the wire body to a
//! temp file in the destination dir before DVZip-decoding into memory
//! (bounded by the receive budget) and cpio-extracting with safe_name +
//! O_EXCL-style `create_new` writes.
//!
//! Contacts-only note: the prototype verifies Apple validation records via an
//! openssl-backed contacts module that has no Rust counterpart here. This
//! port keeps the same request *shape* of the gate: /Ask must carry a
//! SenderRecordData, and /Upload requires a previously accepted Ask on the
//! same connection. See the crate docs / README for the caveat.

use crate::consts::UPLOAD_CONTENT_TYPE;
use crate::{cpio, dvzip, http, plistutil, Error, Identity, Result};
use log::{debug, info, warn};
use plist::Value;
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_METADATA_BYTES: u64 = MIB;
const MAX_ARCHIVE_MEMBERS: usize = 512;
const MIN_FREE_BYTES: u64 = GIB;
/// Used when free disk space cannot be determined at all.
const FALLBACK_BYTE_LIMIT: u64 = 32 * GIB;
const MAX_CONCURRENT_UPLOADS: usize = 2;

/// ReceiverMediaCapabilities, sent in the Discover and Ask answers: version 1
/// and no codecs/containers, so the sender converts to legacy formats.
const MEDIA_CAPABILITIES: &[u8] = b"{\"Version\": 1}";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Everyone,
    ContactsOnly,
}

/// One file entry from the /Ask Files[] array.
#[derive(Debug, Clone)]
pub struct FileMeta {
    pub name: String,
    pub uti: String,
    pub size: u64,
}

/// What a sender proposed (parsed /Ask body).
#[derive(Debug, Clone)]
pub struct Ask {
    pub sender_name: String,
    pub sender_model: String,
    pub transfer_id: String,
    pub files: Vec<FileMeta>,
    pub items_count: usize,
    pub record_data: Option<Vec<u8>>,
}

pub struct ReceiverConfig {
    pub name: String,
    pub model: String,
    pub dest: PathBuf,
    pub visibility: Visibility,
    pub port: u16,
    /// Return true to accept; None means auto-accept.
    pub on_ask: Option<Box<dyn Fn(&Ask) -> bool + Send + Sync>>,
    /// Called with (transfer_id, saved file names) after each upload.
    pub on_upload: Option<Box<dyn Fn(&str, &[String]) + Send + Sync>>,
    /// Free-disk receive budget as a percent (default 30).
    pub max_receive_percent: u32,
    /// Bind address: "::" dual-stack, "0.0.0.0", or a v6 link-local+zone.
    pub bind: String,
}

/// Running receiver. `close()` stops it.
pub struct Receiver {
    stop: Arc<AtomicBool>,
    port: u16,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl Receiver {
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn is_running(&self) -> bool {
        !self.stop.load(Ordering::Relaxed)
    }
    pub fn close(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.handles.drain(..) {
            // The accept loop polls `stop` every ~20ms, so joins are quick.
            let _ = h.join();
        }
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.close();
    }
}

/// Shared state every connection thread reads.
struct Shared {
    name: String,
    model: String,
    dest: PathBuf,
    visibility: Visibility,
    on_ask: Option<Box<dyn Fn(&Ask) -> bool + Send + Sync>>,
    on_upload: Option<Box<dyn Fn(&str, &[String]) + Send + Sync>>,
    record_data: Option<Vec<u8>>,
    max_receive_percent: u32,
    upload_inflight: AtomicUsize,
    tls: Arc<rustls::ServerConfig>,
}

/// RAII slot limiting concurrent /Upload bodies (prototype's semaphore).
struct SlotGuard<'a>(&'a AtomicUsize);
impl<'a> SlotGuard<'a> {
    fn try_acquire(counter: &'a AtomicUsize) -> Option<Self> {
        counter
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |c| {
                (c < MAX_CONCURRENT_UPLOADS).then_some(c + 1)
            })
            .ok()?;
        Some(SlotGuard(counter))
    }
}
impl<'a> Drop for SlotGuard<'a> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Byte budget for one upload, from currently free output-disk space.
struct ReceiveBudget {
    free_bytes: u64,
    byte_limit: u64,
}

impl ReceiveBudget {
    fn new(dest: &Path, percent: u32) -> std::result::Result<Self, String> {
        let free = match disk_free(dest) {
            Some(f) => f,
            None => {
                return Ok(ReceiveBudget {
                    free_bytes: 0,
                    byte_limit: FALLBACK_BYTE_LIMIT,
                })
            }
        };
        let percent_bytes = free.saturating_mul(percent as u64) / 100;
        let reservable = free.saturating_sub(MIN_FREE_BYTES);
        let byte_limit = percent_bytes.min(reservable);
        if byte_limit == 0 {
            return Err(format!(
                "not enough free space while preserving {MIN_FREE_BYTES} bytes"
            ));
        }
        Ok(ReceiveBudget {
            free_bytes: free,
            byte_limit,
        })
    }
}

/// Bind, TLS-wrap and serve. Blocks nothing — serve threads run internally.
/// Port 0 picks an ephemeral port (used by tests/GUI).
pub fn serve(cfg: ReceiverConfig, ident: &Identity) -> Result<Receiver> {
    let tls = ident.server_config()?;
    let sockaddr = parse_bind(&cfg.bind, cfg.port)?;
    let mut listeners = vec![TcpListener::bind(sockaddr)?];
    let port = listeners[0].local_addr()?.port();
    // Dual-stack like the prototype: a "::" bind must also take IPv4.
    // (IPV6_V6ONLY can't be cleared after bind on every OS, so a second
    // listener on the same port is the portable answer.)
    if matches!(sockaddr, SocketAddr::V6(a) if a.ip().is_unspecified()) {
        match TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            port,
        ))) {
            Ok(l4) => listeners.push(l4),
            Err(e) => warn!("dual-stack: IPv4 bind on port {port} failed ({e}); v6 only"),
        }
    }
    for l in &listeners {
        l.set_nonblocking(true)?;
    }

    let shared = Arc::new(Shared {
        name: cfg.name,
        model: cfg.model,
        dest: cfg.dest,
        visibility: cfg.visibility,
        on_ask: cfg.on_ask,
        on_upload: cfg.on_upload,
        record_data: ident.record_data.clone(),
        max_receive_percent: if cfg.max_receive_percent == 0 {
            30
        } else {
            cfg.max_receive_percent
        },
        upload_inflight: AtomicUsize::new(0),
        tls,
    });
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(listeners.len());
    for (i, listener) in listeners.into_iter().enumerate() {
        let stop = stop.clone();
        let shared = shared.clone();
        let th = std::thread::Builder::new()
            .name(format!("airdrop-accept-{i}"))
            .spawn(move || accept_loop(listener, shared, stop))?;
        handles.push(th);
    }
    info!("receiver listening on {sockaddr} (port {port})");
    Ok(Receiver {
        stop,
        port,
        handles,
    })
}

fn parse_bind(bind: &str, port: u16) -> Result<SocketAddr> {
    let (addr_s, zone) = match bind.split_once('%') {
        Some((a, z)) => (a, Some(z)),
        None => (bind, None),
    };
    let ip: IpAddr = addr_s
        .parse()
        .map_err(|_| Error::Protocol(format!("invalid bind address {addr_s:?}")))?;
    Ok(match ip {
        IpAddr::V4(a) => SocketAddr::V4(SocketAddrV4::new(a, port)),
        IpAddr::V6(a) => {
            let scope = zone.map(scope_id_for).unwrap_or(0);
            SocketAddr::V6(SocketAddrV6::new(a, port, 0, scope))
        }
    })
}

/// Scope id for a %zone suffix: numeric, else interface name -> index.
fn scope_id_for(zone: &str) -> u32 {
    if let Ok(n) = zone.parse() {
        return n;
    }
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .iter()
        .find(|i| i.name == zone)
        .and_then(|i| i.index)
        .unwrap_or(0)
}

fn accept_loop(listener: TcpListener, shared: Arc<Shared>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((tcp, peer)) => {
                debug!("connection from {peer}");
                let shared = shared.clone();
                let _ = std::thread::Builder::new()
                    .name(format!("airdrop-conn-{peer}"))
                    .spawn(move || {
                        // Ensure blocking mode + idle timeouts (the listener is
                        // nonblocking; flags do not propagate everywhere).
                        let _ = tcp.set_nonblocking(false);
                        let _ = tcp.set_read_timeout(Some(READ_IDLE_TIMEOUT));
                        let _ = tcp.set_write_timeout(Some(READ_IDLE_TIMEOUT));
                        let _ = tcp.set_nodelay(true);
                        match rustls::ServerConnection::new(shared.tls.clone()) {
                            Ok(conn) => {
                                let mut stream = rustls::StreamOwned::new(conn, tcp);
                                handle_conn(&mut stream, &shared, peer);
                            }
                            Err(e) => debug!("TLS init for {peer}: {e}"),
                        }
                    });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(e) => {
                warn!("accept: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn respond(s: &mut http::TlsServerStream, r: http::Response) {
    if let Err(e) = http::write_response(s, &r) {
        debug!("writing {} response: {e}", r.status);
    }
}

/// Reject with an empty body and Connection: close (prototype `reject`).
fn reject(s: &mut http::TlsServerStream, status: u16, why: &str) {
    warn!("rejected: {why}");
    let r = http::Response {
        status,
        headers: vec![
            ("Content-Length".to_string(), "0".to_string()),
            ("Connection".to_string(), "close".to_string()),
        ],
        body: Vec::new(),
    };
    respond(s, r);
}

fn wants_close(head: &http::Head) -> bool {
    head.headers
        .get("connection")
        .map(|v| v.eq_ignore_ascii_case("close"))
        .unwrap_or(false)
}

fn handle_conn(s: &mut http::TlsServerStream, shared: &Arc<Shared>, peer: SocketAddr) {
    // Contacts mode gates /Upload on an accepted /Ask on this same conn.
    let mut contacts_ok = false;
    loop {
        let head = match http::read_head(s) {
            Ok(Some(h)) => h,
            Ok(None) => return,
            Err(e) => {
                reject(s, http::err_status(&e), &e.to_string());
                return;
            }
        };
        debug!("{} {} from {peer}", head.method, head.path);
        match head.method.as_str() {
            "GET" => {
                respond(s, http::Response::ok(b"\n".to_vec()));
            }
            "HEAD" => {
                respond(
                    s,
                    http::Response {
                        status: 200,
                        headers: vec![("Content-Type".to_string(), "text/html".to_string())],
                        body: Vec::new(),
                    },
                );
            }
            "POST" => {
                let close = match head.path.as_str() {
                    "/Discover" => handle_discover(s, &head, shared),
                    "/Ask" => handle_ask(s, &head, shared, &mut contacts_ok),
                    "/Upload" => handle_upload(s, &head, shared, contacts_ok),
                    _ => {
                        reject(s, 400, &format!("{}: unknown endpoint", head.path));
                        true
                    }
                };
                if close {
                    return;
                }
            }
            _ => {
                reject(s, 501, &format!("{}: unsupported method", head.method));
                return;
            }
        }
        if wants_close(&head) {
            return;
        }
    }
}

/// Read a small (<=1MiB) request body into memory for /Discover and /Ask.
fn read_meta_body(s: &mut http::TlsServerStream, head: &http::Head) -> Result<Vec<u8>> {
    let plan = http::body_plan(&head.headers, MAX_METADATA_BYTES)?;
    if head.expect_continue {
        http::write_continue(s)?;
    }
    let mut body = Vec::new();
    http::read_body_into(s, &plan, &mut body, MAX_METADATA_BYTES)?;
    Ok(body)
}

fn handle_discover(s: &mut http::TlsServerStream, head: &http::Head, shared: &Arc<Shared>) -> bool {
    let body = match read_meta_body(s, head) {
        Ok(b) => b,
        Err(e) => {
            reject(s, http::err_status(&e), &e.to_string());
            return true;
        }
    };
    // Contacts mode: the prototype's discovery gate fails open (it answers
    // senders without records — the tile check is only cosmetic; /Ask is the
    // real gate). With no record verifier here, answer everyone too.
    if shared.visibility == Visibility::ContactsOnly {
        debug!(
            "discover (contacts only): answering, {}-byte request body",
            body.len()
        );
    }
    let mut d = plistutil::dict();
    d.insert(
        "ReceiverMediaCapabilities".into(),
        Value::Data(MEDIA_CAPABILITIES.to_vec()),
    );
    d.insert(
        "ReceiverComputerName".into(),
        Value::String(shared.name.clone()),
    );
    d.insert(
        "ReceiverModelName".into(),
        Value::String(shared.model.clone()),
    );
    if let Some(rec) = &shared.record_data {
        d.insert("ReceiverRecordData".into(), Value::Data(rec.clone()));
    }
    match plistutil::to_binary(&Value::Dictionary(d)) {
        Ok(blob) => respond(s, http::Response::ok(blob)),
        Err(e) => reject(s, 500, &format!("discover: {e}")),
    }
    false
}

fn handle_ask(
    s: &mut http::TlsServerStream,
    head: &http::Head,
    shared: &Arc<Shared>,
    contacts_ok: &mut bool,
) -> bool {
    let body = match read_meta_body(s, head) {
        Ok(b) => b,
        Err(e) => {
            reject(s, http::err_status(&e), &e.to_string());
            return true;
        }
    };
    let value = match plistutil::from_binary(&body) {
        Ok(v) => v,
        Err(e) => {
            warn!("ask: undecodable {}-byte body: {e}", body.len());
            Value::Dictionary(plistutil::dict())
        }
    };
    let empty = plistutil::dict();
    let ask = value.as_dictionary().unwrap_or(&empty);

    let files: Vec<FileMeta> = ask
        .get("Files")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| {
                    let d = f.as_dictionary()?;
                    Some(FileMeta {
                        name: d.get("FileName")?.as_string()?.to_string(),
                        uti: d
                            .get("FileType")
                            .and_then(|v| v.as_string())
                            .unwrap_or_default()
                            .to_string(),
                        size: d
                            .get("FileSize")
                            .and_then(|v| v.as_unsigned_integer())
                            .unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let items: Vec<Value> = ask
        .get("Items")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let transfer_id = ask
        .get("TransferID")
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("id"))
        .and_then(|v| v.as_string())
        .unwrap_or_default()
        .to_string();
    let sender_name = ask
        .get("SenderComputerName")
        .and_then(|v| v.as_string())
        .unwrap_or_default()
        .to_string();
    let sender_model = ask
        .get("SenderModelName")
        .and_then(|v| v.as_string())
        .unwrap_or_default()
        .to_string();
    let record_data = ask
        .get("SenderRecordData")
        .and_then(|v| v.as_data())
        .map(|d| d.to_vec());
    let transfer_types: Vec<&str> = ask
        .get("TransferType")
        .and_then(|v| v.as_dictionary())
        .map(|d| d.keys().map(String::as_str).collect())
        .unwrap_or_default();

    info!(
        "ask from {sender_name} ({sender_model}): type {}, {} item(s): {}",
        if transfer_types.is_empty() {
            "?".into()
        } else {
            transfer_types.join(",")
        },
        files.len(),
        files
            .iter()
            .map(|f| format!("{} {} {}B", f.name, f.uti, f.size))
            .collect::<Vec<_>>()
            .join("; ")
    );

    if items.len() > MAX_ARCHIVE_MEMBERS {
        reject(
            s,
            413,
            &format!("Ask exceeds {MAX_ARCHIVE_MEMBERS}-item limit"),
        );
        return true;
    }
    // Contacts gate (see module docs): a sender must at least present its
    // validation record; Apple-chain verification is not ported.
    if shared.visibility == Visibility::ContactsOnly && record_data.is_none() {
        warn!("ask REFUSED (contacts only): no validation record presented");
        reject(s, 403, "ask refused (contacts only)");
        return true;
    }
    if shared.visibility == Visibility::ContactsOnly {
        *contacts_ok = true;
    }
    if let Some(cb) = &shared.on_ask {
        let proposal = Ask {
            sender_name,
            sender_model,
            transfer_id,
            files,
            items_count: items.len(),
            record_data: record_data.clone(),
        };
        if !cb(&proposal) {
            reject(s, 403, "ask refused by consent callback");
            return true;
        }
    }
    // A `links` transfer is Ask-only: store the URLs as inert .url files.
    if transfer_types.contains(&"links") {
        for item in &items {
            match item.as_string() {
                Some(u) if u.starts_with("http://") || u.starts_with("https://") => {
                    match store_link(&shared.dest, u) {
                        Ok(name) => info!("link stored as {name} -> {u}"),
                        Err(e) => warn!("link store failed for {u:.80}: {e}"),
                    }
                }
                other => warn!("ask: ignoring non-http item {other:?}"),
            }
        }
    }
    let mut d = plistutil::dict();
    d.insert(
        "ReceiverMediaCapabilities".into(),
        Value::Data(MEDIA_CAPABILITIES.to_vec()),
    );
    d.insert(
        "ReceiverComputerName".into(),
        Value::String(shared.name.clone()),
    );
    d.insert(
        "ReceiverModelName".into(),
        Value::String(shared.model.clone()),
    );
    match plistutil::to_binary(&Value::Dictionary(d)) {
        Ok(blob) => respond(s, http::Response::ok(blob)),
        Err(e) => reject(s, 500, &format!("ask: {e}")),
    }
    false
}

fn handle_upload(
    s: &mut http::TlsServerStream,
    head: &http::Head,
    shared: &Arc<Shared>,
    contacts_ok: bool,
) -> bool {
    if shared.visibility == Visibility::ContactsOnly && !contacts_ok {
        reject(s, 403, "contacts-only upload has no accepted Ask");
        return true;
    }
    let ctype = head
        .headers
        .get("content-type")
        .map(|v| v.split(';').next().unwrap_or("").trim().to_lowercase())
        .unwrap_or_default();
    if ctype != UPLOAD_CONTENT_TYPE {
        reject(s, 415, &format!("unsupported Content-Type {ctype:?}"));
        return true;
    }
    let Some(_slot) = SlotGuard::try_acquire(&shared.upload_inflight) else {
        reject(s, 503, "too many uploads in progress");
        return true;
    };
    let tid = safe_name_fb(
        head.headers
            .get("transfer-id")
            .map(String::as_str)
            .unwrap_or(""),
        "upload",
    );
    let budget = match ReceiveBudget::new(&shared.dest, shared.max_receive_percent) {
        Ok(b) => b,
        Err(e) => {
            reject(s, 413, &e);
            return true;
        }
    };
    // Validate framing before 100-continue or any body read.
    let plan = match http::body_plan(&head.headers, budget.byte_limit) {
        Ok(p) => p,
        Err(e) => {
            reject(s, http::err_status(&e), &e.to_string());
            return true;
        }
    };
    info!(
        "upload {tid}: {}% of {} free bytes allows {} bytes",
        shared.max_receive_percent, budget.free_bytes, budget.byte_limit
    );
    if head.expect_continue && http::write_continue(s).is_err() {
        return true;
    }
    // Spool the wire body to a temp file in dest (bounded), then decode.
    let tmp_path = spool_path(&shared.dest);
    let store_result = (|| -> Result<Vec<String>> {
        let decoded = {
            let mut tmp = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            http::read_body_into(s, &plan, &mut tmp, budget.byte_limit)?;
            tmp.seek(SeekFrom::Start(0))?;
            let mut plain = Vec::new();
            let n = dvzip::decode(&mut tmp, &mut plain, budget.byte_limit)?;
            info!(
                "upload {tid}: decoded to {n} bytes (TotalBytes {})",
                head.headers
                    .get("totalbytes")
                    .map(String::as_str)
                    .unwrap_or("-")
            );
            plain
        };
        let members = cpio::read_all(
            &mut Cursor::new(&decoded[..]),
            MAX_ARCHIVE_MEMBERS,
            budget.byte_limit,
        )?;
        extract_members(members, &shared.dest, budget.byte_limit)
    })();
    let _ = std::fs::remove_file(&tmp_path);
    match store_result {
        Ok(written) => {
            info!("upload {tid}: stored {}", written.join(", "));
            respond(
                s,
                http::Response {
                    status: 200,
                    headers: vec![("Content-Length".to_string(), "0".to_string())],
                    body: Vec::new(),
                },
            );
            if let Some(cb) = &shared.on_upload {
                cb(&tid, &written);
            }
            false
        }
        Err(e) => {
            let status = match &e {
                Error::Io(ioe) if http_timeout(ioe) => 408,
                Error::Io(_) => 507,
                // Errors carrying a status prefix ("413: ...") keep it;
                // anything else is a malformed archive.
                Error::Protocol(m) if m.as_bytes().first().map_or(false, u8::is_ascii_digit) => {
                    http::err_status(&e)
                }
                _ => 422,
            };
            reject(s, status, &format!("upload {tid}: {e}"));
            true
        }
    }
}

fn http_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn spool_path(dest: &Path) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    dest.join(format!(
        ".a4e-upload-{}-{}.tmp",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Extract regular cpio members; on error every created file is removed.
fn extract_members(
    members: Vec<cpio::Member>,
    dest: &Path,
    byte_limit: u64,
) -> Result<Vec<String>> {
    let mut created: Vec<PathBuf> = Vec::new();
    let mut written: Vec<String> = Vec::new();
    let mut out_bytes = 0u64;
    let fail = |created: &[PathBuf]| {
        for p in created.iter().rev() {
            let _ = std::fs::remove_file(p);
        }
    };
    for m in members {
        if !m.is_file() {
            continue;
        }
        // AppleDouble sidecars and directories are skipped.
        let raw_base = m
            .name
            .rsplit(|c| c == '/' || c == '\\')
            .next()
            .unwrap_or("");
        if raw_base.starts_with("._") {
            continue;
        }
        let declared = m.data.len() as u64;
        if declared > byte_limit || out_bytes + declared > byte_limit {
            fail(&created);
            return Err(Error::Protocol(format!(
                "413 archive output exceeds {byte_limit}-byte limit"
            )));
        }
        let base = safe_name_fb(&m.name, "file");
        let (name, mut out) = match open_new(dest, &base) {
            Ok(v) => v,
            Err(e) => {
                fail(&created);
                return Err(e);
            }
        };
        created.push(dest.join(&name));
        if let Err(e) = out.write_all(&m.data) {
            fail(&created);
            return Err(Error::Io(e));
        }
        out_bytes += declared;
        written.push(name);
    }
    Ok(written)
}

/// A received URL becomes an inert .url shortcut (never opened).
fn store_link(dest: &Path, url: &str) -> Result<String> {
    let rest = url.splitn(2, "://").nth(1).unwrap_or(url);
    let (netloc, path) = rest.split_once('/').unwrap_or((rest, ""));
    let last_seg = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    let stem = [netloc, last_seg]
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    let base = format!("{}.url", safe_name_fb(&stem, "link"));
    let (name, mut f) = open_new(dest, &base)?;
    f.write_all(format!("[InternetShortcut]\nURL={url}\n").as_bytes())?;
    Ok(name)
}

/// Create dest/name atomically without clobbering an existing file.
fn open_new(dest: &Path, name: &str) -> Result<(String, File)> {
    let (stem, ext) = split_ext(name);
    for i in 0..10000u32 {
        let cand = if i == 0 {
            name.to_string()
        } else {
            format!("{stem}-{i}{ext}")
        };
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest.join(&cand))
        {
            Ok(f) => return Ok((cand, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Err(Error::Protocol(format!(
        "could not create {name:?} without clobbering"
    )))
}

/// os.path.splitext: split at the last '.' that isn't all leading dots.
fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        None => (name, ""),
        Some(i) => {
            if name[..i].chars().all(|c| c == '.') {
                (name, "")
            } else {
                (&name[..i], &name[i..])
            }
        }
    }
}

/// Filename safety: one component, no separators/controls/bidi, no dotfiles.
/// Port of util.safe_name.
pub fn safe_name(name: &str) -> String {
    safe_name_fb(name, "file")
}

fn safe_name_fb(name: &str, fallback: &str) -> String {
    // NOTE: Python applies NFC normalization first; skipped here (no unicode
    // normalization crate) — the unsafe-char stripping below still applies.
    let base = name.replace('\\', "/");
    let base = base.rsplit('/').next().unwrap_or("");
    let filtered: String = base.chars().filter(|&c| !unsafe_char(c)).collect();
    let trimmed = filtered.trim().trim_start_matches('.');
    let (stem, ext) = split_ext(trimmed);
    let mut stem_s = stem.to_string();
    while stem_s.len() + ext.len() > 255 && !stem_s.is_empty() {
        stem_s.pop();
    }
    let mut out = stem_s;
    out.push_str(ext);
    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

/// The util.py UNSAFE_CHAR set: separators, NUL, controls, format/bidi chars.
fn unsafe_char(c: char) -> bool {
    matches!(c,
        '/' | '\\'
        | '\u{0}'..='\u{1f}'
        | '\u{7f}'..='\u{9f}'
        | '\u{200b}'..='\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}'
        | '\u{feff}')
}

/// Free bytes on the filesystem holding `path` (shutil.disk_usage().free).
#[cfg(windows)]
fn disk_free(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(
            dir: *const u16,
            avail: *mut u64,
            total: *mut u64,
            total_free: *mut u64,
        ) -> i32;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut free = 0u64;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut free,
        )
    };
    (ok != 0).then_some(free)
}

#[cfg(unix)]
fn disk_free(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    // struct statvfs (Linux glibc/musl and modern macOS: all fields u64).
    #[repr(C)]
    struct StatVfs {
        f_bsize: u64,
        f_frsize: u64,
        f_blocks: u64,
        f_bfree: u64,
        f_bavail: u64,
        _spare: [u64; 16],
    }
    extern "C" {
        fn statvfs(path: *const u8, buf: *mut StatVfs) -> i32;
    }
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st = std::mem::MaybeUninit::<StatVfs>::uninit();
    let rc = unsafe { statvfs(c_path.as_ptr() as *const u8, st.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let st = unsafe { st.assume_init() };
    // Sanity: a bogus layout would produce nonsense; then fall back.
    if st.f_bsize == 0 || st.f_blocks == 0 || st.f_bavail > st.f_blocks {
        return None;
    }
    Some(st.f_bavail.saturating_mul(st.f_frsize))
}

#[cfg(not(any(windows, unix)))]
fn disk_free(_path: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_name_basics() {
        assert_eq!(safe_name("photo.jpg"), "photo.jpg");
        assert_eq!(safe_name("a/b/c.txt"), "c.txt");
        assert_eq!(safe_name("..\\evil"), "evil");
        assert_eq!(safe_name("\u{0}bad"), "bad");
        assert_eq!(safe_name(""), "file");
        assert_eq!(safe_name(".hidden"), "hidden");
        assert_eq!(safe_name("..\\..\\win.ini"), "win.ini");
        assert_eq!(safe_name("gpj.\u{202e}exe"), "gpj.exe");
    }

    #[test]
    fn split_ext_cases() {
        assert_eq!(split_ext("a.b"), ("a", ".b"));
        assert_eq!(split_ext("a"), ("a", ""));
        assert_eq!(split_ext(".h"), (".h", ""));
        assert_eq!(split_ext("a."), ("a", "."));
    }

    #[test]
    fn open_new_no_clobber() {
        let dir = std::env::temp_dir().join(format!("a4e-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.txt");
        std::fs::write(&f, b"old").unwrap();
        let (name, mut nf) = open_new(&dir, "x.txt").unwrap();
        assert_eq!(name, "x-1.txt");
        nf.write_all(b"new").unwrap();
        drop(nf);
        assert_eq!(std::fs::read(&f).unwrap(), b"old");
        let (name2, nf2) = open_new(&dir, "x.txt").unwrap();
        assert_eq!(name2, "x-2.txt");
        drop(nf2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
