//! The sender: /Discover, /Ask, /Upload over TLS + mDNS discovery.
//! Port of prototype client.py (of airdrop-send.py).
//!
//! One TLS connection answers /Discover, then a FRESH connection carries
//! /Ask -> /Upload — sharingd tears its Discover handler down ~1ms after
//! answering, and an /Ask on a reused connection is ACKed but never
//! dispatched. Every advertised address is tried until one connects
//! (`all-addrs fallback`); v6 link-local peers get a %zone scope, probing
//! every v6-capable local interface since adverts carry no zone.

use crate::{consts, cpio, discovery, dvzip, http, plistutil, transport, Error, Identity, Result};
use log::{debug, info};
use plist::Value;
use std::collections::HashSet;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const OP_TIMEOUT: Duration = Duration::from_secs(20);

/// Options for one transfer.
#[derive(Clone)]
pub struct SendOpts {
    pub computer_name: String,
    pub computer_model: String,
    /// 12-hex mDNS instance id (defaults to a stable per-machine id).
    pub service_id: String,
    /// 3-byte SenderIdentityAuthTag matching the BLE advert.
    pub auth_tag: Option<[u8; 3]>,
    pub ask_timeout: Duration,
}

impl Default for SendOpts {
    fn default() -> Self {
        Self {
            computer_name: String::new(),
            computer_model: crate::consts::DEFAULT_MODEL.into(),
            service_id: String::new(),
            auth_tag: None,
            ask_timeout: Duration::from_secs(90),
        }
    }
}

/// One receiver endpoint discovered over mDNS.
#[derive(Debug, Clone)]
pub struct Peer {
    /// 12-hex service instance id.
    pub ident: String,
    /// Display name, once /Discover has answered (None = pre-discover).
    pub name: Option<String>,
    /// All advertised addresses (v4+v6).
    pub addrs: Vec<IpAddr>,
    pub port: u16,
}

type TlsConn = http::TlsClientStream;

/// One receiver connection: /Discover, reconnect, /Ask, /Upload.
/// Tries every advertised address until one connects.
pub struct AirDropClient {
    ident: Identity,
    tls: Arc<rustls::ClientConfig>,
    hosts: Vec<IpAddr>,
    port: u16,
    computer_name: String,
    computer_model: String,
    service_id: String,
    auth_tag: Option<[u8; 3]>,
    ask_timeout: Duration,
    conn: Option<TlsConn>,
    connected: Option<IpAddr>,
    transfer_id: Option<String>,
}

impl AirDropClient {
    pub fn new(ident: &Identity, peer: &Peer, opts: &SendOpts) -> Result<Self> {
        let tls = ident.client_config()?;
        Ok(AirDropClient {
            ident: ident.clone(),
            tls,
            hosts: if peer.addrs.is_empty() {
                Vec::new()
            } else {
                peer.addrs.clone()
            },
            port: peer.port,
            computer_name: opts.computer_name.clone(),
            computer_model: opts.computer_model.clone(),
            service_id: opts.service_id.clone(),
            auth_tag: opts.auth_tag,
            ask_timeout: opts.ask_timeout,
            conn: None,
            connected: None,
            transfer_id: None,
        })
    }

    /// Connect (with per-address fallback) and TLS-handshake. `timeout`
    /// becomes the socket read/write timeout afterwards.
    fn connect(&mut self, timeout: Duration) -> Result<()> {
        let mut last: Option<Error> = None;
        for &host in &self.hosts {
            for sock in connect_addrs(host, self.port) {
                match try_connect(sock, host, &self.tls, timeout) {
                    Ok(stream) => {
                        self.connected = Some(host);
                        self.conn = Some(stream);
                        debug!("connected to {host}:{}", self.port);
                        return Ok(());
                    }
                    Err(e) => {
                        debug!("connect {host}:{} failed: {e}", self.port);
                        last = Some(e);
                    }
                }
            }
        }
        Err(last.unwrap_or_else(|| Error::Protocol("no receiver addresses".into())))
    }

    /// POST `body` (Content-Length) and read the answer -> (200?, bytes).
    fn post(
        &mut self,
        path: &str,
        body: &[u8],
        extra: &[(String, String)],
    ) -> Result<(bool, Vec<u8>)> {
        if self.conn.is_none() {
            self.connect(OP_TIMEOUT)?;
        }
        let host_header = self.host_header();
        let stream = self.conn.as_mut().expect("conn checked above");
        // const.HTTP_HEADERS: every request is application/octet-stream.
        let r = http::post(
            stream,
            &host_header,
            path,
            body,
            "application/octet-stream",
            extra,
        )?;
        debug!("{path} answered {}", r.status);
        Ok((r.status == 200, r.body))
    }

    /// The Host header: "ip" or "[ip]" for the connected address.
    fn host_header(&self) -> String {
        match self.connected {
            Some(IpAddr::V6(a)) => format!("[{a}]:{}", self.port),
            Some(IpAddr::V4(a)) => format!("{a}:{}", self.port),
            None => "airdrop".to_string(),
        }
    }

    /// POST /Discover -> receiver display name (None if refused).
    pub fn send_discover(&mut self) -> Result<Option<String>> {
        let mut d = plistutil::dict();
        d.insert(
            "DeviceSupportFlags".into(),
            Value::Integer(consts::DEVICE_SUPPORT_FLAGS.into()),
        );
        if let Some(rec) = &self.ident.record_data {
            d.insert("SenderRecordData".into(), Value::Data(rec.clone()));
        }
        let body = plistutil::to_binary(&Value::Dictionary(d))?;
        let (ok, resp) = self.post("/Discover", &body, &[])?;
        if !ok {
            return Ok(None);
        }
        match plistutil::from_binary(&resp) {
            Ok(v) => Ok(v
                .as_dictionary()
                .and_then(|d| d.get("ReceiverComputerName"))
                .and_then(|v| v.as_string())
                .map(str::to_string)),
            Err(_) => Ok(None),
        }
    }

    /// Drop the current connection and open a fresh one (required between
    /// Discover and Ask — sharingd never dispatches Ask on a reused conn).
    pub fn reconnect(&mut self) -> Result<()> {
        if let Some(mut s) = self.conn.take() {
            // close_notify; ignore failures.
            let _ = s.conn.send_close_notify();
            let _ = s.flush();
            let _ = s.sock.shutdown(std::net::Shutdown::Both);
        }
        self.connected = None;
        // The fresh conn gets the longer Ask timeout — the human at the
        // other end may take a while to tap Accept.
        self.connect(self.ask_timeout)
    }

    /// POST /Ask -> true if accepted.
    pub fn send_ask(&mut self, files: &[PathBuf]) -> Result<bool> {
        let mut entries = Vec::with_capacity(files.len());
        for f in files {
            let name = file_name_str(f)?;
            let size = std::fs::metadata(f).map_err(Error::Io)?.len();
            let uti = consts::uti_for_ext(
                f.extension()
                    .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
                    .as_deref()
                    .unwrap_or(""),
            );
            let mut fd = plistutil::dict();
            fd.insert("FileName".into(), Value::String(name.clone()));
            fd.insert("FileType".into(), Value::String(uti.into()));
            fd.insert("FileSize".into(), Value::Integer(size.into()));
            fd.insert("FileBomPath".into(), Value::String(format!("./{name}")));
            fd.insert("FileIsDirectory".into(), Value::Boolean(false));
            fd.insert("ConvertMediaFormats".into(), Value::Boolean(false));
            entries.push(Value::Dictionary(fd));
        }
        self.transfer_id = Some(Uuid::new_v4().to_string().to_uppercase());
        let mut transfer = plistutil::dict();
        transfer.insert(
            "id".into(),
            Value::String(self.transfer_id.clone().unwrap_or_default()),
        );
        let mut ttype = plistutil::dict();
        ttype.insert("files".into(), Value::Dictionary(plistutil::dict()));
        let sender_name = if self.computer_name.is_empty() {
            short_hostname()
        } else {
            self.computer_name.clone()
        };
        let mut d = plistutil::dict();
        d.insert("TransferID".into(), Value::Dictionary(transfer));
        d.insert("TransferType".into(), Value::Dictionary(ttype));
        d.insert("SenderID".into(), Value::String(self.service_id.clone()));
        d.insert("BundleID".into(), Value::String(consts::BUNDLE_ID.into()));
        d.insert("SenderComputerName".into(), Value::String(sender_name));
        d.insert(
            "SenderModelName".into(),
            Value::String(self.computer_model.clone()),
        );
        d.insert("Items".into(), Value::Array(Vec::new()));
        d.insert("Files".into(), Value::Array(entries));
        d.insert("ConvertMediaFormats".into(), Value::Boolean(false));
        if let Some(rec) = &self.ident.record_data {
            d.insert("SenderRecordData".into(), Value::Data(rec.clone()));
        }
        if let Some(tag) = self.auth_tag {
            d.insert("SenderIdentityAuthTag".into(), Value::Data(tag.to_vec()));
        }
        let body = plistutil::to_binary(&Value::Dictionary(d))?;
        let (ok, _) = self.post("/Ask", &body, &[])?;
        Ok(ok)
    }

    /// POST /Upload (DVZip+cpio, chunked like sharingd).
    pub fn send_upload(&mut self, files: &[PathBuf]) -> Result<bool> {
        let mut cpio_blob = Vec::new();
        let mut total = 0u64;
        let mut entries = Vec::with_capacity(files.len());
        for f in files {
            let name = file_name_str(f)?;
            total += std::fs::metadata(f).map_err(Error::Io)?.len();
            entries.push(cpio::CpioEntry::File {
                name: format!("./{name}"),
                path: f.clone(),
            });
        }
        cpio::write_newc(&mut cpio_blob, &entries)?;
        let body = dvzip::encode(&cpio_blob);
        if self.conn.is_none() {
            self.connect(OP_TIMEOUT)?;
        }
        let extra = vec![
            ("TotalBytes".to_string(), total.to_string()),
            (
                "TransferID".to_string(),
                self.transfer_id
                    .clone()
                    .unwrap_or_else(|| Uuid::new_v4().to_string().to_uppercase()),
            ),
        ];
        let host_header = self.host_header();
        let stream = self.conn.as_mut().expect("conn checked above");
        let r = http::post_chunked(
            stream,
            &host_header,
            "/Upload",
            &body,
            consts::UPLOAD_CONTENT_TYPE,
            &extra,
        )?;
        debug!("/Upload answered {}", r.status);
        Ok(r.status == 200)
    }

    /// Which advertised address connected.
    pub fn connected_addr(&self) -> Option<IpAddr> {
        self.connected
    }
}

impl Drop for AirDropClient {
    fn drop(&mut self) {
        if let Some(mut s) = self.conn.take() {
            let _ = s.conn.send_close_notify();
        }
    }
}

/// Basename of a path (UTF-8 lossy).
fn file_name_str(p: &PathBuf) -> Result<String> {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| Error::Protocol(format!("no file name in {p:?}")))
}

fn short_hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .map(|h| h.split('.').next().unwrap_or("").to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "airdrop".into())
}

/// Socket addresses to try for `host`, with link-local v6 scope probing:
/// an advert gives no zone, so every v6-carrying interface is tried.
fn connect_addrs(host: IpAddr, port: u16) -> Vec<SocketAddr> {
    match host {
        IpAddr::V4(a) => vec![SocketAddr::new(IpAddr::V4(a), port)],
        IpAddr::V6(a) if transport::is_link_local_v6(&a) => {
            let scopes = v6_iface_scopes();
            let mut out = Vec::with_capacity(scopes.len() + 1);
            for scope in &scopes {
                out.push(SocketAddr::V6(SocketAddrV6::new(a, port, 0, *scope)));
            }
            // Last resort: default routing (scope 0 — works on Windows).
            out.push(SocketAddr::V6(SocketAddrV6::new(a, port, 0, 0)));
            out
        }
        IpAddr::V6(a) => vec![SocketAddr::V6(SocketAddrV6::new(a, port, 0, 0))],
    }
}

/// Interface indices of every local interface carrying a v6 address.
fn v6_iface_scopes() -> Vec<u32> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for i in if_addrs::get_if_addrs().unwrap_or_default() {
        if !matches!(i.addr.ip(), IpAddr::V6(_)) {
            continue;
        }
        if let Some(idx) = i.index {
            if idx != 0 && seen.insert(idx) {
                out.push(idx);
            }
        }
    }
    out
}

/// TCP connect + TLS handshake for one socket address.
fn try_connect(
    sock: SocketAddr,
    host: IpAddr,
    tls: &Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<TlsConn> {
    let tcp = TcpStream::connect_timeout(&sock, timeout)?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    tcp.set_nodelay(true).ok();
    let name = rustls::pki_types::ServerName::try_from(match host {
        IpAddr::V6(a) => a.to_string(),
        IpAddr::V4(a) => a.to_string(),
    })
    .map_err(|_| Error::Protocol("invalid server name".into()))?;
    let conn = rustls::ClientConnection::new(tls.clone(), name)?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    // Drive the handshake now so failures surface as connect errors.
    stream.conn.complete_io(&mut stream.sock)?;
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    Ok(stream)
}

/// Full send to a peer: Discover, fresh conn, Ask, Upload.
/// Returns the receiver display name. Error::Declined on refusal.
pub fn send_files(
    files: &[PathBuf],
    peer: &Peer,
    ident: &Identity,
    opts: &SendOpts,
) -> Result<String> {
    let mut client = AirDropClient::new(ident, peer, opts)?;
    let name = client.send_discover()?;
    client.reconnect()?;
    if !client.send_ask(files)? {
        return Err(Error::Declined);
    }
    if !client.send_upload(files)? {
        return Err(Error::Protocol("upload failed".into()));
    }
    Ok(name.unwrap_or_else(|| peer.ident.clone()))
}

/// mDNS browser: watches `_airdrop._tcp`, filters flags & `want`,
/// /Discover-probes each candidate.
pub struct Finder {
    ident: Identity,
    interfaces: Option<Vec<IpAddr>>,
    want: String,
    opts: SendOpts,
}

impl Finder {
    /// `want`: "" | 12-hex service id | "aa:bb:.." MAC | name substring.
    /// `interfaces`: None = all; Some([..]) limits discovery to those IPs.
    pub fn new(
        ident: &Identity,
        interfaces: Option<Vec<IpAddr>>,
        want: &str,
        opts: &SendOpts,
    ) -> Result<Self> {
        Ok(Finder {
            ident: ident.clone(),
            interfaces,
            want: want.to_string(),
            opts: opts.clone(),
        })
    }

    /// Browse+probe up to `timeout`; returns the first viable peer.
    /// `on_peer` fires for every receiver that was discovered and probed.
    pub fn run(
        &mut self,
        timeout: Duration,
        on_peer: Option<&mut dyn FnMut(&Peer)>,
    ) -> Result<Option<Peer>> {
        let mut on_peer = on_peer;
        let browser = discovery::Browser::start(self.interfaces.clone())?;
        let deadline = Instant::now() + timeout;
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(remain) = deadline.checked_duration_since(Instant::now()) {
            let Some(event) = browser.next(remain) else {
                break;
            };
            let mdns_sd::ServiceEvent::ServiceResolved(info) = event else {
                continue;
            };
            let advert = discovery::advert_from(&info);
            info!(
                "advert {} host={} port={} addr={:?} flags={:#x}",
                advert.instance, advert.host, advert.port, advert.addrs, advert.flags
            );
            if !seen.insert(advert.instance.clone()) {
                continue;
            }
            if advert.addrs.is_empty() {
                continue;
            }
            if !self.match_ident(&advert) {
                continue;
            }
            // advert_from already defaults a missing "flags" key to
            // SUPPORTS_DISCOVER_MAYBE; an explicit flags=0 means "no /Discover".
            let flags = advert.flags;
            if flags & consts::SUPPORTS_DISCOVER_MAYBE == 0 {
                info!(
                    "{}: no /Discover support (flags {:#x}); skipping",
                    advert.instance, flags
                );
                continue;
            }
            let mut peer = Peer {
                ident: advert.instance.clone(),
                name: None,
                addrs: advert.addrs.clone(),
                port: advert.port,
            };
            let mut client = match AirDropClient::new(&self.ident, &peer, &self.opts) {
                Ok(c) => c,
                Err(e) => {
                    debug!("client for {}: {e}", advert.instance);
                    continue;
                }
            };
            match client.send_discover() {
                Ok(name) => peer.name = name,
                Err(e) => {
                    info!("DISCOVER {} failed: {e}", advert.instance);
                    continue;
                }
            }
            if let Some(cb) = on_peer.as_deref_mut() {
                cb(&peer);
            }
            if !self.match_name(peer.name.as_deref()) {
                continue;
            }
            if peer.name.is_some() {
                return Ok(Some(peer));
            }
        }
        Ok(None)
    }

    /// Pre-discover filters: 12-hex ident or MAC -> EUI-64 link-local.
    fn match_ident(&self, advert: &discovery::Advert) -> bool {
        let want = self.want.trim();
        if want.is_empty() {
            return true;
        }
        if want.len() == 12 && want.chars().all(|c| c.is_ascii_hexdigit()) {
            return want.eq_ignore_ascii_case(&advert.instance);
        }
        if want.contains(':') {
            if let Some(mac) = transport::parse_mac(want) {
                let want_ll = IpAddr::V6(eui64_linklocal(&mac));
                return advert.addrs.iter().any(|a| *a == want_ll);
            }
        }
        true
    }

    /// Post-discover name-substring filter (skipped for id/MAC wants).
    fn match_name(&self, name: Option<&str>) -> bool {
        let want = self.want.trim();
        if want.is_empty()
            || (want.len() == 12 && want.chars().all(|c| c.is_ascii_hexdigit()))
            || want.contains(':')
        {
            return true;
        }
        match name {
            Some(n) => n.to_lowercase().contains(&want.to_lowercase()),
            None => false,
        }
    }
}

/// fe80:: EUI-64 for a MAC: flip the U/L bit and insert ff:fe.
fn eui64_linklocal(mac: &[u8; 6]) -> Ipv6Addr {
    let mut b = *mac;
    b[0] ^= 0x02;
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfe;
    bytes[1] = 0x80;
    bytes[8..11].copy_from_slice(&b[0..3]);
    bytes[11] = 0xff;
    bytes[12] = 0xfe;
    bytes[13..16].copy_from_slice(&b[3..6]);
    Ipv6Addr::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eui64_shape() {
        // aa:bb:cc:dd:ee:ff -> U/L flip a8, ff:fe insert
        let v6 = eui64_linklocal(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(v6.to_string(), "fe80::a8bb:ccff:fedd:eeff");
    }

    #[test]
    fn match_ident_forms() {
        let f = Finder {
            ident: Identity {
                cert_pem: String::new(),
                key_pem: String::new(),
                record_data: None,
                kind: "self-signed",
            },
            interfaces: None,
            want: "AABBCCDDEEFF".into(),
            opts: SendOpts::default(),
        };
        let advert = discovery::Advert {
            instance: "aabbccddeeff".into(),
            host: "host.local".into(),
            port: 8771,
            addrs: vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            flags: 137,
        };
        assert!(f.match_ident(&advert));
        assert!(f.match_name(Some("Ben's Mac")));
        let f2 = Finder {
            want: "ben".into(),
            ..f
        };
        assert!(f2.match_name(Some("Ben's Mac")));
        assert!(!f2.match_name(Some("Alice")));
    }
}
