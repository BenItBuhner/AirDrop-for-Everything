//! Exercise the C ABI the way a shell would: identity → receiver → send →
//! file on disk → stop. Runs on loopback; no radio needed.

use airdrop_ffi::*;
use std::ffi::{c_void, CStr, CString};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("a4e-ffi-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn c(s: impl AsRef<str>) -> CString {
    CString::new(s.as_ref()).unwrap()
}

unsafe fn last_err() -> String {
    let p = a4e_last_error();
    if p.is_null() {
        return "<none>".into();
    }
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

static ASK_CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn count_ask(_ctx: *mut c_void, ask: *const A4eAsk) -> i32 {
    ASK_CALLS.fetch_add(1, Ordering::SeqCst);
    assert!(!ask.is_null());
    let a = &*ask;
    assert!(!a.transfer_id.is_null());
    assert!(!a.files.is_null() || a.files_len == 0);
    assert!(a.files_len >= 1);
    let f = &*a.files;
    assert!(!f.name.is_null());
    assert_eq!(f.size, 12);
    1
}

#[test]
fn abi_roundtrip() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init();
    let keys = tmpdir("keys");
    let dest = tmpdir("dest");
    let src = tmpdir("src");
    let payload = src.join("hello.txt");
    std::fs::write(&payload, b"hello world!").unwrap();

    let kdir = c(keys.to_string_lossy());
    let name = c("ffi-test-host");
    let mut err: *mut std::ffi::c_char = ptr::null_mut();
    assert_eq!(
        unsafe { a4e_identity_load_or_create(kdir.as_ptr(), name.as_ptr(), &mut err) },
        0,
        "identity: {}",
        unsafe { last_err() }
    );

    let ddir = c(dest.to_string_lossy());
    let rname = c("ffi-receiver");
    let rmodel = c("TestMachine1,1");
    assert_eq!(
        a4e_receiver_start(
            rname.as_ptr(),
            rmodel.as_ptr(),
            ddir.as_ptr(),
            0,
            0, // default port 8771
            Some(count_ask),
            ptr::null_mut(),
        ),
        0,
        "receiver_start: {}",
        unsafe { last_err() }
    );

    // give the listener a beat to bind
    std::thread::sleep(std::time::Duration::from_millis(150));

    let path = c(payload.to_string_lossy());
    let paths = [path.as_ptr()];
    let addr = c("127.0.0.1:8771");
    let rc = unsafe {
        a4e_send_files(paths.as_ptr(), 1, addr.as_ptr(), ptr::null(), &mut err)
    };
    assert_eq!(rc, 0, "send: {}", unsafe { last_err() });
    assert_eq!(ASK_CALLS.load(Ordering::SeqCst), 1, "ask cb fired once");

    let got = dest.join("hello.txt");
    assert!(got.is_file(), "received file missing");
    assert_eq!(std::fs::read(&got).unwrap(), b"hello world!");

    a4e_receiver_stop();
    a4e_receiver_stop(); // idempotent
}

#[test]
fn errors_are_reported() {
    let mut err: *mut std::ffi::c_char = ptr::null_mut();
    // identity not loaded on a fresh keys dir? — a4e_send_files needs one,
    // so point at a dir that cannot be created.
    let bad = c(if cfg!(windows) {
        "Z:\\definitely\\missing\\a4e-keys"
    } else {
        "/proc/definitely-missing-a4e-keys"
    });
    let r = unsafe { a4e_identity_load_or_create(bad.as_ptr(), ptr::null(), &mut err) };
    assert_eq!(r, -1);
    assert!(!err.is_null(), "err out-param populated");
    a4e_string_free(err);
    assert!(!a4e_last_error().is_null());
}
