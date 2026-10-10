//! airdrop-core — native AirDrop protocol stack.
//!
//! Reimplementation of the behaviour reverse-engineered by t4t5/omdrop-owl,
//! brentkearney/omdrop-awdl and brentkearney/omdrop-plugin (see NOTICE).
//! Pure Rust: rustls for TLS, mdns-sd for discovery, plist for binary
//! property lists, hand-rolled HTTP/1.1, DVZip + newc cpio.

pub mod aframes;
pub mod ble;
pub mod client;
pub mod consts;
pub mod cpio;
pub mod discovery;
pub mod dvzip;
pub mod error;
pub mod http;
pub mod identity;
pub mod plistutil;
pub mod server;
pub mod transport;

pub use error::{Error, Result};

pub use client::{send_files, AirDropClient, Finder, Peer, SendOpts};
pub use identity::Identity;
pub use server::{serve, Ask, FileMeta, Receiver, ReceiverConfig, Visibility};
pub use transport::{pick, Transport};
