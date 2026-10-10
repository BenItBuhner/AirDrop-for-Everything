//! mDNS announce + browse for `_airdrop._tcp` via mdns-sd.
//! Port of the zeroconf path in prototype discovery.py: one registered
//! PTR/SRV/TXT/A+AAAA service set per Announcer, and resolved-service
//! browsing with an optional interface restriction.

use crate::{consts, transport, Error, Result};
use log::{debug, info, warn};
use mdns_sd::{Receiver, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Registered `_airdrop._tcp` service. Drop to unregister.
pub struct Announcer {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Announcer {
    /// The registered fullname, `<id>._airdrop._tcp.local.`.
    pub fn fullname(&self) -> &str {
        &self.fullname
    }
}

impl Drop for Announcer {
    fn drop(&mut self) {
        if let Err(e) = self.daemon.unregister(&self.fullname) {
            debug!("mdns unregister {}: {e}", self.fullname);
        }
        if let Err(e) = self.daemon.shutdown() {
            debug!("mdns shutdown: {e}");
        }
    }
}

fn mdns_err(e: impl std::fmt::Display) -> Error {
    Error::Protocol(format!("mdns: {e}"))
}

/// Advertise `<service_id>._airdrop._tcp.local` -> host:port with
/// TXT flags=<flags>. `host_label` is the mDNS hostname label
/// (e.g. "mypc" -> mypc.local). `addrs` are the IPs to publish (A/AAAA);
/// empty = all local addrs.
pub fn announce(
    service_id: &str,
    host_label: &str,
    port: u16,
    flags: u32,
    addrs: &[IpAddr],
) -> Result<Announcer> {
    let daemon = ServiceDaemon::new().map_err(mdns_err)?;
    // mdns-sd only strips a duplicated ".local.local."; fully qualify here.
    let label = host_label.trim_end_matches('.');
    let host = if label.ends_with(".local") {
        format!("{label}.")
    } else {
        format!("{label}.local.")
    };
    let owned: Vec<IpAddr> = if addrs.is_empty() {
        transport::default_addrs()
    } else {
        addrs.to_vec()
    };
    let addr_csv = owned
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut props = HashMap::new();
    props.insert("flags".to_string(), flags.to_string());
    let info = ServiceInfo::new(
        consts::SERVICE_TYPE,
        service_id,
        &host,
        &addr_csv,
        port,
        props,
    )
    .map_err(mdns_err)?;
    let fullname = info.get_fullname().to_string();
    daemon.register(info).map_err(mdns_err)?;
    info!("mDNS announcing {fullname} -> {host}:{port} flags={flags:#x} addrs={addr_csv}");
    if owned.is_empty() {
        warn!("announcer has no addresses to publish; it will not resolve");
    }
    Ok(Announcer { daemon, fullname })
}

/// One raw browse event (before /Discover probing).
#[derive(Debug, Clone)]
pub struct Advert {
    pub instance: String,
    pub host: String,
    pub port: u16,
    pub addrs: Vec<IpAddr>,
    pub flags: u32,
}

/// An active `_airdrop._tcp` browse session (daemon + event channel).
/// Reused by `browse` and the client's `Finder`.
pub(crate) struct Browser {
    daemon: ServiceDaemon,
    rx: Receiver<ServiceEvent>,
}

impl Browser {
    /// Start browsing; `interfaces` (local addrs) restricts which interfaces
    /// mdns-sd listens on. Best effort: restriction failures are logged and
    /// the browse falls back to all interfaces.
    pub(crate) fn start(interfaces: Option<Vec<IpAddr>>) -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(mdns_err)?;
        if let Some(addrs) = &interfaces {
            if !addrs.is_empty() {
                if let Err(e) = daemon.disable_interface(mdns_sd::IfKind::All) {
                    warn!("mdns interface restriction unavailable ({e}); browsing all");
                } else {
                    for a in addrs {
                        if let Err(e) = daemon.enable_interface(*a) {
                            debug!("enable_interface({a}): {e}");
                        }
                    }
                }
            }
        }
        let rx = daemon.browse(consts::SERVICE_TYPE).map_err(mdns_err)?;
        Ok(Browser { daemon, rx })
    }

    /// Wait for the next event, at most `d`. None on timeout/disconnect.
    pub(crate) fn next(&self, d: Duration) -> Option<ServiceEvent> {
        match self.rx.recv_timeout(d) {
            Ok(ev) => Some(ev),
            Err(_) => None,
        }
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        let _ = self.daemon.stop_browse(consts::SERVICE_TYPE);
        let _ = self.daemon.shutdown();
    }
}

/// A resolved service record -> Advert.
pub(crate) fn advert_from(info: &ServiceInfo) -> Advert {
    Advert {
        // instance name = first label of <id>._airdrop._tcp.local.
        instance: info
            .get_fullname()
            .split('.')
            .next()
            .unwrap_or_default()
            .to_string(),
        host: info.get_hostname().trim_end_matches('.').to_string(),
        port: info.get_port(),
        addrs: info.get_addresses().iter().copied().collect(),
        // A missing "flags" key means Discover-capable (prototype default);
        // an explicit flags=0 still parses to 0 and is skipped by callers.
        flags: info
            .get_property_val_str("flags")
            .and_then(|s| s.parse().ok())
            .unwrap_or(consts::SUPPORTS_DISCOVER_MAYBE),
    }
}

/// Browse for `_airdrop._tcp` services for up to `timeout`, calling
/// `on_advert` per resolved service.
pub fn browse(
    timeout: Duration,
    interfaces: Option<Vec<IpAddr>>,
    on_advert: &mut dyn FnMut(Advert),
) -> Result<()> {
    let browser = Browser::start(interfaces)?;
    let deadline = Instant::now() + timeout;
    while let Some(remain) = deadline.checked_duration_since(Instant::now()) {
        match browser.next(remain) {
            Some(ServiceEvent::ServiceResolved(info)) => {
                let advert = advert_from(&info);
                debug!(
                    "advert {} host={} port={} addrs={:?} flags={:#x}",
                    advert.instance, advert.host, advert.port, advert.addrs, advert.flags
                );
                on_advert(advert);
            }
            Some(_) => {}
            None => break,
        }
    }
    Ok(())
}
