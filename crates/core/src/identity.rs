//! AirDrop TLS identity: self-signed cert (+ optional Apple validation record).
//! Port of prototype identity.py — rcgen replaces openssl/cryptography.

use crate::{Error, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A certificate chain + key pair usable for TLS in both directions.
#[derive(Clone)]
pub struct Identity {
    /// PEM leaf certificate.
    pub cert_pem: String,
    /// PEM private key.
    pub key_pem: String,
    /// Apple validation record (Contacts Only), if imported.
    pub record_data: Option<Vec<u8>>,
    /// "self-signed" | "apple"
    pub kind: &'static str,
}

impl Identity {
    /// rustls ServerConfig (CERT_NONE posture upstream: we still present
    /// our cert; peers are not verified).
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.cert_chain()?, self.private_key()?)
            .map_err(|e| Error::Identity(format!("identity-tls-load-failed: {e}")))?;
        Ok(Arc::new(cfg))
    }
    /// rustls ClientConfig presenting our cert, verifying nothing.
    pub fn client_config(&self) -> Result<Arc<rustls::ClientConfig>> {
        let cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert::new()))
            .with_client_auth_cert(self.cert_chain()?, self.private_key()?)
            .map_err(|e| Error::Identity(format!("identity-tls-load-failed: {e}")))?;
        Ok(Arc::new(cfg))
    }

    fn cert_chain(&self) -> Result<Vec<CertificateDer<'static>>> {
        let mut rd = BufReader::new(self.cert_pem.as_bytes());
        let certs = rustls_pemfile::certs(&mut rd)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Identity(format!("identity-tls-load-failed: {e}")))?;
        if certs.is_empty() {
            return Err(Error::Identity(
                "identity-tls-load-failed: no certificates in PEM".into(),
            ));
        }
        Ok(certs)
    }

    fn private_key(&self) -> Result<PrivateKeyDer<'static>> {
        let mut rd = BufReader::new(self.key_pem.as_bytes());
        rustls_pemfile::private_key(&mut rd)
            .map_err(|e| Error::Identity(format!("identity-tls-load-failed: {e}")))?
            .ok_or_else(|| {
                Error::Identity("identity-tls-load-failed: no private key in PEM".into())
            })
    }
}

/// ssl.CERT_NONE for the client role: every certificate chain is accepted
/// (peers are self-signed), but the TLS handshake signature is still checked —
/// same guarantee Python's OpenSSL keeps under CERT_NONE.
#[derive(Debug)]
struct AcceptAnyCert {
    algs: WebPkiSupportedAlgorithms,
}

impl AcceptAnyCert {
    fn new() -> Self {
        let algs = rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms)
            .unwrap_or_else(|| {
                rustls::crypto::ring::default_provider().signature_verification_algorithms
            });
        Self { algs }
    }
}

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Resolve (or create) the identity under `keys_dir` (certificate.pem,
/// key.pem, optional record.bin). `computer_name` becomes the CN.
///
/// Mirrors the prototype: `certificate.pem`/`key.pem` (+ `record.bin`) are an
/// imported Apple identity; when absent we use — creating if needed —
/// `certificate.self-signed.pem`/`key.self-signed.pem` so a later import still
/// takes precedence and `kind` stays accurate across restarts.
pub fn resolve(keys_dir: &Path, computer_name: &str) -> Result<Identity> {
    let cert = keys_dir.join("certificate.pem");
    let key = keys_dir.join("key.pem");
    let record = keys_dir.join("record.bin");
    if cert.is_file() && key.is_file() {
        let record_data = if record.is_file() {
            Some(read_bytes(&record)?)
        } else {
            None
        };
        return Ok(Identity {
            cert_pem: read_pem(&cert)?,
            key_pem: read_pem(&key)?,
            record_data,
            kind: "apple",
        });
    }

    let scert = keys_dir.join("certificate.self-signed.pem");
    let skey = keys_dir.join("key.self-signed.pem");
    if !(scert.is_file() && skey.is_file()) {
        let id = self_signed(computer_name)?;
        std::fs::create_dir_all(keys_dir)
            .map_err(|e| Error::Identity(format!("self-signed-create-failed: mkdir {e}")))?;
        set_mode(keys_dir, 0o700);
        std::fs::write(&skey, id.key_pem.as_bytes())?;
        std::fs::write(&scert, id.cert_pem.as_bytes())?;
        set_mode(&skey, 0o600);
        set_mode(&scert, 0o600);
        return Ok(id);
    }
    Ok(Identity {
        cert_pem: read_pem(&scert)?,
        key_pem: read_pem(&skey)?,
        record_data: None,
        kind: "self-signed",
    })
}

/// Default keys directory: ~/.airdrop-everything/keys
/// Falls back to ~/.omdrop/keys when ours doesn't exist but that one does
/// (shared identity with omdrop, like the prototype).
pub fn default_keys_dir() -> PathBuf {
    let home = home_dir();
    let ours = home.join(".airdrop-everything").join("keys");
    if ours.is_dir() || !home.join(".omdrop").join("keys").is_dir() {
        ours
    } else {
        home.join(".omdrop").join("keys")
    }
}

/// Generate a fresh self-signed identity (rcgen; openssl fallback optional).
pub fn self_signed(computer_name: &str) -> Result<Identity> {
    // Upstream mints RSA-2048. rcgen can only *generate* RSA keys with the
    // aws-lc-rs backend; under the default `ring` backend `generate_for`
    // reports KeyGenerationUnavailable, so fall back to ECDSA P-256 —
    // peers don't verify the chain either way.
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
        .or_else(|_| rcgen::KeyPair::generate())
        .map_err(|e| Error::Identity(format!("self-signed-create-failed: {e}")))?;

    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, computer_name);
    // Validity: upstream uses now-5min .. now+365d. `time` isn't a direct
    // dependency, so compute civil dates from the system clock (a day of
    // slack covers the prototype's 5-minute clock-skew guard).
    let today = (now_secs() / 86_400) as i64;
    let (y, m, d) = ymd_from_days(today - 1);
    params.not_before = rcgen::date_time_ymd(y, m, d);
    let (y, m, d) = ymd_from_days(today + 365);
    params.not_after = rcgen::date_time_ymd(y, m, d);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::Identity(format!("self-signed-create-failed: {e}")))?;
    Ok(Identity {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        record_data: None,
        kind: "self-signed",
    })
}

fn read_pem(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .map_err(|e| Error::Identity(format!("identity-load-failed {}: {e}", path.display())))
}

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| Error::Identity(format!("identity-load-failed {}: {e}", path.display())))
}

/// chmod `mode` where the platform supports it; no-op elsewhere.
fn set_mode(path: &Path, mode: u32) {
    let _ = (path, mode);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
}

fn home_dir() -> PathBuf {
    #[cfg(unix)]
    let home = std::env::var_os("HOME");
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| {
            std::env::var_os("HOMEDRIVE")
                .zip(std::env::var_os("HOMEPATH"))
                .map(|(mut d, p)| {
                    d.push(&p);
                    d
                })
        })
        .or_else(|| std::env::var_os("HOME"));
    #[cfg(not(any(unix, windows)))]
    let home = std::env::var_os("HOME");
    home.map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Days since the Unix epoch → (year, month, day), civil calendar
/// (Howard Hinnant's algorithm). rcgen takes dates without a `time` dep.
fn ymd_from_days(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (if m <= 2 { y + 1 } else { y } as i32, m as u8, d as u8)
}
