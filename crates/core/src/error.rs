use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("plist: {0}")]
    Plist(#[from] plist::Error),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("the receiver declined the transfer")]
    Declined,
    #[error("no receiver found")]
    NoReceiver,
    #[error("timeout")]
    Timeout,
    #[error("identity: {0}")]
    Identity(String),
    #[error("ble: {0}")]
    Ble(String),
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, Error>;
