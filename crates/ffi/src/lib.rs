//! airdrop-ffi — C ABI over airdrop-core for native shells.
//!
//! Canonical contract: `shells/macos/CA4e/include/a4e.h`, semantics in
//! `shells/ffi.md`. All functions return 0/-1; errors land in
//! `a4e_last_error` (thread-local) and, where the signature has one, the
//! `char **err` out-param (caller frees with `a4e_string_free`).

use airdrop_core::{
    client::Finder, consts, discovery, identity, send_files, transport, Ask, Peer, Receiver,
    ReceiverConfig, SendOpts, Visibility,
};
use std::ffi::{c_char, c_int, c_uint, c_ushort, c_void, CStr, CString};
use std::net::IpAddr;
use std::path::PathBuf;
use std::ptr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

// -------------------------------------------------------------- misc

thread_local! {
    static LAST_ERR: std::cell::RefCell<CString> =
        std::cell::RefCell::new(CString::new("").unwrap());
}

fn set_err(msg: &str) {
    LAST_ERR.with(|e| *e.borrow_mut() = CString::new(msg).unwrap_or_default());
}

/// Store `msg` into a `char **err` out-param (NULL-tolerant).
unsafe fn err_out(err: *mut *mut c_char, msg: &str) {
    if !err.is_null() {
        unsafe { *err = CString::new(msg).unwrap_or_default().into_raw() };
    }
}

fn fail(err: *mut *mut c_char, msg: &str) -> c_int {
    set_err(msg);
    unsafe { err_out(err, msg) };
    -1
}

/// Borrowed C string → &str ("" for NULL).
fn cstr<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        return "";
    }
    unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("")
}

fn cstr_opt<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}

/// Borrowed C string → CString for callback lifetimes.
fn cowned(s: &str) -> *const c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

unsafe fn reclaim(p: *const c_char) {
    if !p.is_null() {
        unsafe { drop(CString::from_raw(p as *mut c_char)) };
    }
}

#[no_mangle]
pub extern "C" fn a4e_last_error() -> *const c_char {
    LAST_ERR.with(|e| {
        let b = e.borrow();
        if b.as_bytes().is_empty() {
            ptr::null()
        } else {
            b.as_ptr()
        }
    })
}

#[no_mangle]
pub extern "C" fn a4e_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}

fn short_host() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .map(|h| h.split('.').next().unwrap_or(&h).to_string())
        .unwrap_or_else(|| "airdrop".into())
}

fn host_label() -> String {
    short_host().to_lowercase().replace(' ', "-")
}

// -------------------------------------------------------------- identity

static IDENTITY: OnceLock<Mutex<Option<identity::Identity>>> = OnceLock::new();

fn ident_slot() -> &'static Mutex<Option<identity::Identity>> {
    IDENTITY.get_or_init(|| Mutex::new(None))
}

fn loaded_identity() -> Option<identity::Identity> {
    ident_slot().lock().ok()?.clone()
}

/// Load or create the TLS identity. `keys_dir`/`computer_name` NULL →
/// defaults. Idempotent. On failure `*err` gets a message to free with
/// `a4e_string_free`.
#[no_mangle]
pub extern "C" fn a4e_identity_load_or_create(
    keys_dir: *const c_char,
    computer_name: *const c_char,
    err: *mut *mut c_char,
) -> c_int {
    let dir = if keys_dir.is_null() {
        identity::default_keys_dir()
    } else {
        PathBuf::from(cstr(keys_dir))
    };
    let name = if computer_name.is_null() {
        short_host()
    } else {
        cstr(computer_name).to_string()
    };
    match identity::resolve(&dir, &name) {
        Ok(id) => {
            *ident_slot().lock().unwrap() = Some(id);
            0
        }
        Err(e) => fail(err, &e.to_string()),
    }
}

// -------------------------------------------------------------- receiver

#[repr(C)]
pub struct A4eFileMeta {
    pub name: *const c_char,
    pub uti: *const c_char,
    pub size: u64,
}

#[repr(C)]
pub struct A4eAsk {
    pub sender_name: *const c_char,
    pub sender_model: *const c_char,
    pub transfer_id: *const c_char,
    pub files_len: usize,
    pub files: *const A4eFileMeta,
}

pub type A4eAskCallback =
    Option<unsafe extern "C" fn(ctx: *mut c_void, ask: *const A4eAsk) -> c_int>;

struct ActiveRx {
    _rx: Receiver,
    _ann: discovery::Announcer,
}

static RECEIVER: OnceLock<Mutex<Option<ActiveRx>>> = OnceLock::new();

fn rx_slot() -> &'static Mutex<Option<ActiveRx>> {
    RECEIVER.get_or_init(|| Mutex::new(None))
}

/// Start receiver + mDNS announcement. `visibility` 0=Everyone 1=Contacts.
/// `port` 0 → 8771. `cb` NULL → auto-accept. `ctx` is borrowed until
/// `a4e_receiver_stop` returns.
#[no_mangle]
pub extern "C" fn a4e_receiver_start(
    name: *const c_char,
    model: *const c_char,
    dest_dir: *const c_char,
    visibility: c_int,
    port: c_ushort,
    cb: A4eAskCallback,
    ctx: *mut c_void,
) -> c_int {
    let Some(ident) = loaded_identity() else {
        set_err("identity not loaded — call a4e_identity_load_or_create first");
        return -1;
    };
    if rx_slot().lock().unwrap().is_some() {
        set_err("receiver already running");
        return -1;
    }
    let ctx_usize = ctx as usize;
    let on_ask: Option<Box<dyn Fn(&Ask) -> bool + Send + Sync>> = cb.map(|cb| {
        Box::new(move |ask: &Ask| {
            let files: Vec<A4eFileMeta> = ask
                .files
                .iter()
                .map(|f| A4eFileMeta {
                    name: cowned(&f.name),
                    uti: cowned(&f.uti),
                    size: f.size,
                })
                .collect();
            let cask = A4eAsk {
                sender_name: cowned(&ask.sender_name),
                sender_model: cowned(&ask.sender_model),
                transfer_id: cowned(&ask.transfer_id),
                files_len: files.len(),
                files: files.as_ptr(),
            };
            let accept = unsafe { cb(ctx_usize as *mut c_void, &cask) != 0 };
            unsafe {
                reclaim(cask.sender_name);
                reclaim(cask.sender_model);
                reclaim(cask.transfer_id);
                for f in files {
                    reclaim(f.name);
                    reclaim(f.uti);
                }
            }
            accept
        }) as Box<dyn Fn(&Ask) -> bool + Send + Sync>
    });
    let port = if port == 0 {
        consts::AIRDROP_PORT
    } else {
        port
    };
    let bind = match transport::pick("auto") {
        Ok(t) => t.bind,
        Err(_) => "::".to_string(),
    };
    let rx = match airdrop_core::serve(
        ReceiverConfig {
            name: if name.is_null() {
                short_host()
            } else {
                cstr(name).to_string()
            },
            model: if model.is_null() {
                consts::DEFAULT_MODEL.into()
            } else {
                cstr(model).to_string()
            },
            dest: PathBuf::from(cstr(dest_dir)),
            visibility: if visibility == 1 {
                Visibility::ContactsOnly
            } else {
                Visibility::Everyone
            },
            port,
            bind,
            max_receive_percent: 30,
            on_ask,
            on_upload: None,
        },
        &ident,
    ) {
        Ok(rx) => rx,
        Err(e) => {
            set_err(&e.to_string());
            return -1;
        }
    };
    // mDNS announcement is part of "start the receiver" — a receiver that
    // cannot be found is not AirDrop.
    let trans = transport::pick("auto").ok();
    let ann = match discovery::announce(
        &trans.as_ref().map(|t| t.service_id()).unwrap_or_default(),
        &host_label(),
        rx.port(),
        consts::FLAGS_DEFAULT,
        &trans.map(|t| t.addrs).unwrap_or_default(),
    ) {
        Ok(a) => a,
        Err(e) => {
            set_err(&format!("serve ok but announce failed: {e}"));
            return -1;
        }
    };
    *rx_slot().lock().unwrap() = Some(ActiveRx { _rx: rx, _ann: ann });
    0
}

/// Stop the receiver + withdraw the announcement. Idempotent.
#[no_mangle]
pub extern "C" fn a4e_receiver_stop() {
    *rx_slot().lock().unwrap() = None;
}

// -------------------------------------------------------------- sender

#[repr(C)]
pub struct A4ePeer {
    pub ident: *const c_char,
    pub name: *const c_char,
    pub addr: *const c_char,
    pub port: c_ushort,
}

pub type A4ePeerCallback = Option<unsafe extern "C" fn(ctx: *mut c_void, peer: *const A4ePeer)>;

#[repr(C)]
pub struct A4eSendOpts {
    pub struct_size: u32,
    pub computer_name: *const c_char,
    pub computer_model: *const c_char,
    pub service_id: *const c_char,
    pub has_auth_tag: i32,
    pub auth_tag: [u8; 3],
    pub ask_timeout_ms: u64,
}

/// Parse "ipv4:port", "[v6]:port", "[v6%zone]:port" or bare "ipv4".
fn parse_endpoint(addr: &str) -> Option<(IpAddr, u16)> {
    let s = addr.trim();
    let (host, port) = s
        .rsplit_once(':')
        .map(|(h, p)| (h, Some(p)))
        .unwrap_or((s, None));
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split('%')
        .next()?;
    let ip: IpAddr = host.parse().ok()?;
    let port = port
        .map(|p| p.parse::<u16>().ok())
        .unwrap_or(Some(consts::AIRDROP_PORT))?;
    Some((ip, port))
}

fn send_opts_from(o: Option<&A4eSendOpts>) -> SendOpts {
    let mut s = SendOpts {
        computer_name: short_host(),
        ..Default::default()
    };
    if let Some(o) = o {
        if let Some(v) = cstr_opt(o.computer_name) {
            s.computer_name = v.to_string();
        }
        if let Some(v) = cstr_opt(o.computer_model) {
            s.computer_model = v.to_string();
        }
        if let Some(v) = cstr_opt(o.service_id) {
            s.service_id = v.to_string();
        }
        if o.has_auth_tag != 0 {
            s.auth_tag = Some(o.auth_tag);
        }
        if o.ask_timeout_ms != 0 {
            s.ask_timeout = Duration::from_millis(o.ask_timeout_ms);
        }
    }
    s
}

/// Send all paths to `addr`. Blocks for the whole exchange.
/// 0 ok, -1 fail (see `*err`/`a4e_last_error`).
#[no_mangle]
pub extern "C" fn a4e_send_files(
    paths: *const *const c_char,
    n: usize,
    addr: *const c_char,
    opts: *const A4eSendOpts,
    err: *mut *mut c_char,
) -> c_int {
    let Some(ident) = loaded_identity() else {
        return fail(
            err,
            "identity not loaded — call a4e_identity_load_or_create first",
        );
    };
    if paths.is_null() && n > 0 {
        return fail(err, "paths is NULL");
    }
    let files: Vec<PathBuf> = (0..n)
        .map(|i| PathBuf::from(cstr(unsafe { *paths.add(i) })))
        .collect();
    let Some((ip, port)) = parse_endpoint(cstr(addr)) else {
        return fail(err, "addr must be ipv4:port, [v6]:port or [v6%zone]:port");
    };
    let opts = send_opts_from(unsafe { opts.as_ref() });
    let peer = Peer {
        ident: "direct".into(),
        name: None,
        addrs: vec![ip],
        port,
    };
    match send_files(&files, &peer, &ident, &opts) {
        Ok(_) => 0,
        Err(e) => fail(err, &e.to_string()),
    }
}

/// Browse `_airdrop._tcp` up to `timeout_ms`, /Discover-probing each
/// candidate; `cb` fires on this thread per viable peer (NULL → just scan).
#[no_mangle]
pub extern "C" fn a4e_browse(timeout_ms: c_uint, cb: A4ePeerCallback, ctx: *mut c_void) -> c_int {
    let Some(ident) = loaded_identity() else {
        set_err("identity not loaded — call a4e_identity_load_or_create first");
        return -1;
    };
    let mut finder = match Finder::new(&ident, None, "", &SendOpts::default()) {
        Ok(f) => f,
        Err(e) => {
            set_err(&e.to_string());
            return -1;
        }
    };
    let ctx_usize = ctx as usize;
    let mut emit = |p: &Peer| {
        let Some(cb) = cb else { return };
        // macOS link-local v6 peers need a %zone to be connectable.
        let addr = match p.addrs.first() {
            Some(IpAddr::V6(a)) if transport::is_link_local_v6(a) && cfg!(target_os = "macos") => {
                format!("{a}%awdl0")
            }
            Some(a) => a.to_string(),
            None => String::new(),
        };
        let cpeer = A4ePeer {
            ident: cowned(&p.ident),
            name: p.name.as_deref().map(cowned).unwrap_or(ptr::null()),
            addr: cowned(&addr),
            port: p.port,
        };
        unsafe { cb(ctx_usize as *mut c_void, &cpeer) };
        unsafe {
            reclaim(cpeer.ident);
            reclaim(cpeer.name);
            reclaim(cpeer.addr);
        }
    };
    let r = finder.run(Duration::from_millis(timeout_ms as u64), Some(&mut emit));
    match r {
        Ok(_) => 0,
        Err(e) => {
            set_err(&e.to_string());
            -1
        }
    }
}

/// Current transport description (caller frees with a4e_string_free).
#[no_mangle]
pub extern "C" fn a4e_transport_describe() -> *mut c_char {
    transport::pick("auto")
        .map(|t| cowned(&t.describe()))
        .map(|p| p as *mut c_char)
        .unwrap_or(ptr::null_mut())
}

mod jni_glue;
