//! Link selection: awdl0 when present (macOS / Linux+OWL), else LAN.
//! Port of prototype transport.py.
//!
//! MAC lookup is best effort: Linux reads /sys/class/net; elsewhere the
//! service id falls back to a stable hostname hash (12-hex), matching the
//! "stable per-machine id" contract.

use crate::{Error, Result};
use log::debug;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv6Addr, UdpSocket};

const AWDL_IFACE: &str = "awdl0";

#[derive(Debug, Clone)]
pub struct Transport {
    /// "awdl" | "lan"
    pub mode: String,
    /// Interface name, if one was chosen specifically.
    pub iface: Option<String>,
    /// Address the HTTP server binds (may carry a %zone for v6 link-local).
    pub bind: String,
    /// Addresses to advertise in mDNS.
    pub addrs: Vec<IpAddr>,
    /// MAC -> default 12-hex service id.
    pub mac: Option<[u8; 6]>,
}

impl Transport {
    /// 12-hex service id derived from the interface MAC (or host hash).
    pub fn service_id(&self) -> String {
        match self.mac {
            Some(m) => m.iter().map(|b| format!("{b:02x}")).collect(),
            // A stable per-machine id: first 6 bytes of SHA-256(hostname).
            None => {
                let host = hostname::get()
                    .ok()
                    .and_then(|h| h.into_string().ok())
                    .unwrap_or_else(|| "airdrop".into());
                let digest = Sha256::digest(host.as_bytes());
                digest[..6].iter().map(|b| format!("{b:02x}")).collect()
            }
        }
    }
    /// Human description for logs/UI.
    pub fn describe(&self) -> String {
        if self.mode == "awdl" {
            format!(
                "AWDL on {} ({})",
                self.iface.as_deref().unwrap_or(AWDL_IFACE),
                self.bind
            )
        } else if let Some(iface) = &self.iface {
            format!("LAN on {iface} ({})", self.bind)
        } else {
            "LAN on all interfaces".to_string()
        }
    }
}

/// Resolve `--iface` argument: "auto" | "lan" | "awdl"/"awdl0" | <name>.
pub fn pick(iface: &str) -> Result<Transport> {
    match iface {
        "auto" => {
            if awdl_available() {
                awdl_transport(AWDL_IFACE)
            } else {
                lan_transport(None)
            }
        }
        "awdl" | AWDL_IFACE => awdl_transport(AWDL_IFACE),
        "lan" => lan_transport(None),
        // Explicit interface name: bind to it specifically.
        name => {
            let ip6 = first_ipv6(name);
            let mac = iface_mac(name);
            match ip6 {
                None => lan_transport(Some(name)),
                Some(ip) => Ok(Transport {
                    mode: if name == AWDL_IFACE { "awdl" } else { "lan" }.to_string(),
                    iface: Some(name.to_string()),
                    bind: format!("{ip}%{name}"),
                    addrs: vec![IpAddr::V6(ip)],
                    mac,
                }),
            }
        }
    }
}

/// fe80::/10 link-local check (avoids newer std helpers for MSRV safety).
pub fn is_link_local_v6(v6: &Ipv6Addr) -> bool {
    v6.segments()[0] & 0xffc0 == 0xfe80
}

/// True when awdl0 exists with a link-local v6.
pub fn awdl_available() -> bool {
    iface_addrs(AWDL_IFACE)
        .iter()
        .any(|a| matches!(a, IpAddr::V6(v6) if is_link_local_v6(v6)))
}

/// All non-loopback local addresses (v4+v6), for mDNS publication.
pub fn default_addrs() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for i in ifaces {
            let ip = i.addr.ip();
            let keep = match ip {
                IpAddr::V4(v4) => !v4.is_loopback(),
                IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
            };
            if keep && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    if out.is_empty() {
        // Fallback: primary source address toward a public IP (UDP connect
        // sends nothing).
        for target in ["192.0.2.1:80", "[2001:db8::1]:80"] {
            if let Ok(s) = UdpSocket::bind((
                if target.starts_with('[') {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                } else {
                    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                },
                0,
            )) {
                if s.connect(target).is_ok() {
                    if let Ok(local) = s.local_addr() {
                        out.push(local.ip());
                    }
                }
            }
        }
    }
    out
}

/// MAC of a named interface, best effort (None when unknown).
pub fn iface_mac(iface: &str) -> Option<[u8; 6]> {
    // Linux (and sysfs-style systems): /sys/class/net/<iface>/address
    #[cfg(unix)]
    {
        let path = format!("/sys/class/net/{iface}/address");
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Some(m) = parse_mac(text.trim()) {
                return Some(m);
            }
        }
    }
    // Portable fallback via interface enumeration crates is not available;
    // other platforms report None and service_id() hashes the hostname.
    let _ = iface;
    None
}

/// "aa:bb:cc:dd:ee:ff" or "aabbccddeeff" -> [u8; 6].
pub(crate) fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// All addresses on one named interface.
fn iface_addrs(iface: &str) -> Vec<IpAddr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .iter()
        .filter(|i| i.name == iface)
        .map(|i| i.addr.ip())
        .collect()
}

/// First IPv6 address on an interface (prototype first_ipv6).
fn first_ipv6(iface: &str) -> Option<Ipv6Addr> {
    iface_addrs(iface).into_iter().find_map(|a| match a {
        IpAddr::V6(v6) => Some(v6),
        _ => None,
    })
}

fn awdl_transport(iface: &str) -> Result<Transport> {
    let ip6 = first_ipv6(iface)
        .ok_or_else(|| Error::Unsupported(format!("{iface} has no IPv6 address; is AWDL up?")))?;
    Ok(Transport {
        mode: "awdl".to_string(),
        iface: Some(iface.to_string()),
        bind: format!("{ip6}%{iface}"),
        addrs: vec![IpAddr::V6(ip6)],
        mac: iface_mac(iface),
    })
}

fn lan_transport(iface: Option<&str>) -> Result<Transport> {
    let bind = if v6_supported() { "::" } else { "0.0.0.0" };
    Ok(Transport {
        mode: "lan".to_string(),
        iface: iface.map(str::to_string),
        bind: bind.to_string(),
        addrs: default_addrs(),
        mac: iface.and_then(iface_mac).or_else(primary_mac),
    })
}

/// Can this host open an IPv6 socket at all?
fn v6_supported() -> bool {
    UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).is_ok()
}

/// MAC of the interface owning the default route (best effort): first
/// interface with a non-loopback IPv4 that also has a readable MAC.
fn primary_mac() -> Option<[u8; 6]> {
    let ifaces = if_addrs::get_if_addrs().ok()?;
    for i in &ifaces {
        let has_v4 = matches!(i.addr.ip(), IpAddr::V4(v4) if !v4.is_loopback());
        if has_v4 {
            if let Some(m) = iface_mac(&i.name) {
                return Some(m);
            }
        }
    }
    debug!("no readable MAC on any interface; service id will be host-derived");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_forms() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac("AA-BB-CC-DD-EE-FF"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_mac("aabbccddeeff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(parse_mac("nope"), None);
    }

    #[test]
    fn service_id_shapes() {
        let t = Transport {
            mode: "lan".into(),
            iface: None,
            bind: "0.0.0.0".into(),
            addrs: vec![],
            mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        };
        assert_eq!(t.service_id(), "aabbccddeeff");
        let t2 = Transport {
            mac: None,
            ..t.clone()
        };
        let id = t2.service_id();
        assert_eq!(id.len(), 12);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Stable across calls.
        assert_eq!(id, t2.service_id());
    }
}
