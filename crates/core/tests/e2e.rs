//! Loopback end-to-end: real rustls server + client on 127.0.0.1.
//! Mirrors prototype/tests/test_e2e.py.

use airdrop_core::identity;
use airdrop_core::{send_files, Peer, ReceiverConfig, SendOpts, Visibility};
use std::path::PathBuf;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("a4e-test-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn setup(tag: &str) -> (identity::Identity, airdrop_core::Receiver, PathBuf, PathBuf) {
    let base = tmpdir(tag);
    let keys = base.join("keys");
    let dest = base.join("dl");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    let ident = identity::resolve(&keys, "TestBox").unwrap();
    let rx = airdrop_core::serve(
        ReceiverConfig {
            name: "TestBox".into(),
            model: "MacBookPro18,3".into(),
            dest: dest.clone(),
            visibility: Visibility::Everyone,
            port: 0,
            bind: "127.0.0.1".into(),
            max_receive_percent: 30,
            on_ask: None,
            on_upload: None,
        },
        &ident,
    )
    .unwrap();
    (ident, rx, dest, base)
}

fn opts() -> SendOpts {
    SendOpts {
        computer_name: "Sender".into(),
        service_id: "aabbccddeeff".into(),
        ..Default::default()
    }
}

#[test]
fn e2e_send_one_file() {
    let (ident, mut rx, dest, base) = setup("one");
    let src = base.join("hello.txt");
    let payload: Vec<u8> = b"hello airdrop ".repeat(500);
    std::fs::write(&src, &payload).unwrap();
    let peer = Peer {
        ident: "self".into(),
        name: None,
        addrs: vec!["127.0.0.1".parse().unwrap()],
        port: rx.port(),
    };
    let name = send_files(&[src], &peer, &ident, &opts()).unwrap();
    assert_eq!(name, "TestBox");
    assert_eq!(std::fs::read(dest.join("hello.txt")).unwrap(), payload);
    rx.close();
}

#[test]
fn e2e_no_clobber() {
    let (ident, mut rx, dest, base) = setup("noclob");
    let src = base.join("dup.txt");
    let peer = Peer {
        ident: "self".into(),
        name: None,
        addrs: vec!["127.0.0.1".parse().unwrap()],
        port: rx.port(),
    };
    std::fs::write(&src, b"first").unwrap();
    send_files(&[src.clone()], &peer, &ident, &opts()).unwrap();
    std::fs::write(&src, b"second").unwrap();
    send_files(&[src], &peer, &ident, &opts()).unwrap();
    assert_eq!(std::fs::read(dest.join("dup.txt")).unwrap(), b"first");
    assert_eq!(std::fs::read(dest.join("dup-1.txt")).unwrap(), b"second");
    rx.close();
}

#[test]
fn e2e_declined() {
    let base = tmpdir("declined");
    let keys = base.join("keys");
    let dest = base.join("dl");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::create_dir_all(&dest).unwrap();
    let ident = identity::resolve(&keys, "TestBox").unwrap();
    let mut rx = airdrop_core::serve(
        ReceiverConfig {
            name: "TestBox".into(),
            model: "MacBookPro18,3".into(),
            dest: dest.clone(),
            visibility: Visibility::Everyone,
            port: 0,
            bind: "127.0.0.1".into(),
            max_receive_percent: 30,
            on_ask: Some(Box::new(|_| false)),
            on_upload: None,
        },
        &ident,
    )
    .unwrap();
    let src = base.join("nope.txt");
    std::fs::write(&src, b"x").unwrap();
    let peer = Peer {
        ident: "self".into(),
        name: None,
        addrs: vec!["127.0.0.1".parse().unwrap()],
        port: rx.port(),
    };
    let r = send_files(&[src], &peer, &ident, &opts());
    assert!(matches!(r, Err(airdrop_core::Error::Declined)));
    assert!(!dest.join("nope.txt").exists());
    rx.close();
}

#[test]
fn e2e_multi_file() {
    let (ident, mut rx, dest, base) = setup("multi");
    let a = base.join("a.txt");
    let b = base.join("b.bin");
    std::fs::write(&a, b"aaa").unwrap();
    std::fs::write(&b, (0..=255u8).cycle().take(4096).collect::<Vec<_>>()).unwrap();
    let peer = Peer {
        ident: "self".into(),
        name: None,
        addrs: vec!["127.0.0.1".parse().unwrap()],
        port: rx.port(),
    };
    send_files(&[a, b], &peer, &ident, &opts()).unwrap();
    assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"aaa");
    assert_eq!(std::fs::read(dest.join("b.bin")).unwrap().len(), 4096);
    rx.close();
}
