//! a4e — AirDrop for every platform (CLI).
//!
//!   a4e receive        become discoverable and save incoming files
//!   a4e send FILE..    send to a discovered receiver (or --direct)
//!   a4e peers          list receivers in range
//!   a4e wake           emit the BLE AirDrop advert
//!   a4e identity       show / import our identity
//!   a4e doctor         report platform capabilities

use airdrop_core::identity;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "a4e",
    version,
    about = "AirDrop for every platform: send and receive over AWDL or plain LAN"
)]
struct Cli {
    #[arg(short, long)]
    verbose: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Become discoverable and receive files.
    Receive {
        #[arg(long, default_value = "auto")]
        iface: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        outdir: Option<PathBuf>,
        #[arg(long, default_value_t = airdrop_core::consts::AIRDROP_PORT)]
        port: u16,
        #[arg(long, help = "Contacts Only (needs an Apple identity)")]
        contacts: bool,
        #[arg(long, help = "prompt before accepting each transfer")]
        ask: bool,
        #[arg(long, default_value_t = 0.0, help = "seconds to stay up (0 = forever)")]
        duration: f64,
        #[arg(long)]
        keys: Option<PathBuf>,
        #[arg(long, default_value_t = airdrop_core::consts::FLAGS_DEFAULT)]
        flags: u32,
    },
    /// Send files to a receiver.
    Send {
        files: Vec<PathBuf>,
        #[arg(long, default_value = "auto")]
        iface: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value_t = 60.0)]
        timeout: f64,
        #[arg(long, help = "keep browsing until timeout instead of first-found")]
        wait: bool,
        #[arg(long, default_value_t = 90.0)]
        ask_timeout: f64,
        #[arg(long, help = "skip discovery; send to HOST:PORT")]
        direct: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        keys: Option<PathBuf>,
        #[arg(long, help = "don't emit the BLE wake advert")]
        no_wake: bool,
    },
    /// List discoverable receivers.
    Peers {
        #[arg(long, default_value = "auto")]
        iface: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value_t = 10.0)]
        timeout: f64,
        #[arg(long)]
        keys: Option<PathBuf>,
        #[arg(long)]
        no_wake: bool,
    },
    /// Emit the BLE AirDrop wake advert.
    Wake {
        #[arg(long, default_value = "A", value_parser = ["A", "V2", "B"])]
        arm: String,
        #[arg(long, default_value_t = 120)]
        seconds: u64,
        #[arg(long)]
        hashes: Option<String>,
    },
    /// Show or import our AirDrop identity.
    Identity {
        #[arg(long)]
        keys: Option<PathBuf>,
        #[arg(long, num_args = 2..=3, value_names = ["CERT", "KEY", "RECORD"],
              help = "import an Apple identity pair (+ optional validation record)")]
        import: Option<Vec<PathBuf>>,
    },
    /// Report platform capabilities.
    Doctor,
    /// Parse a hex-encoded AWDL action frame (offline debug).
    AfParse {
        /// hex string, or "-" to read hex lines from stdin
        frame: String,
    },
    /// Capture AWDL action frames on an interface (Linux, root).
    AfListen { iface: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::new()
        .filter_level(if cli.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .format_timestamp_secs()
        .init();
    match cli.cmd {
        Cmd::Receive { .. } => cmd_receive(&cli),
        Cmd::Send { .. } => cmd_send(&cli),
        Cmd::Peers { .. } => cmd_peers(&cli),
        Cmd::Wake { .. } => cmd_wake(&cli),
        Cmd::Identity { .. } => cmd_identity(&cli),
        Cmd::Doctor => cmd_doctor(&cli),
        Cmd::AfParse { .. } => cmd_afparse(&cli),
        Cmd::AfListen { .. } => cmd_aflisten(&cli),
    }
}

// ------------------------------------------------------------------ helpers

fn keys_dir(opt: &Option<PathBuf>) -> PathBuf {
    opt.clone().unwrap_or_else(identity::default_keys_dir)
}

fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .map(|h| h.split('.').next().unwrap_or("airdrop").to_string())
        .unwrap_or_else(|| "airdrop".into())
}

fn load_identity(keys: &Option<PathBuf>, name: &str) -> Result<identity::Identity> {
    identity::resolve(&keys_dir(keys), name).map_err(|e| anyhow::anyhow!("identity: {e}"))
}

// ------------------------------------------------------------------ receive

fn cmd_receive(cli: &Cli) -> Result<()> {
    let Cmd::Receive {
        ref iface,
        ref name,
        ref model,
        ref outdir,
        port,
        contacts,
        ask,
        duration,
        ref keys,
        flags,
    } = cli.cmd
    else {
        unreachable!()
    };

    let name = name.clone().unwrap_or_else(hostname);
    let model = model
        .clone()
        .unwrap_or_else(|| airdrop_core::consts::DEFAULT_MODEL.into());
    let dest = outdir
        .clone()
        .unwrap_or_else(|| dirs_download().unwrap_or_else(|| PathBuf::from(".")));
    if !dest.is_dir() {
        bail!("download dir {}: not a directory", dest.display());
    }
    let ident = load_identity(keys, &name)?;
    let trans = airdrop_core::transport::pick(iface)?;
    let service_id = trans.service_id();

    let visibility = if contacts {
        airdrop_core::Visibility::ContactsOnly
    } else {
        airdrop_core::Visibility::Everyone
    };

    let mut rx = airdrop_core::serve(
        airdrop_core::ReceiverConfig {
            name: name.clone(),
            model: model.clone(),
            dest: dest.clone(),
            visibility,
            port,
            bind: trans.bind.clone(),
            max_receive_percent: 30,
            on_ask: if ask {
                Some(Box::new(|a: &airdrop_core::Ask| {
                    let desc: Vec<String> = a.files.iter().map(|f| f.name.clone()).collect();
                    eprint!(
                        "AirDrop: {} wants to send {}. Accept? [Y/n] ",
                        a.sender_name,
                        if desc.is_empty() {
                            format!("{} item(s)", a.items_count)
                        } else {
                            desc.join(", ")
                        }
                    );
                    use std::io::Read;
                    let mut buf = [0u8; 8];
                    let n = std::io::stdin().read(&mut buf).unwrap_or(0);
                    let a = std::str::from_utf8(&buf[..n])
                        .unwrap_or("")
                        .trim()
                        .to_lowercase();
                    !(a == "n" || a == "no")
                }))
            } else {
                None
            },
            on_upload: Some(Box::new(|tid: &str, files: &[String]| {
                println!(
                    "received: {} ({})",
                    files.join(", "),
                    &tid[..8.min(tid.len())]
                );
            })),
        },
        &ident,
    )?;

    let host_label = name.to_lowercase().replace(' ', "-");
    let _ann = airdrop_core::discovery::announce(
        &service_id,
        &host_label,
        rx.port(),
        flags,
        &trans.addrs,
    )?;

    println!("AirDrop receiver '{name}' ({model})");
    println!(
        "  service:  {service_id}._airdrop._tcp.local :{}",
        rx.port()
    );
    println!("  via:      {}", trans.describe());
    println!("  saving:   {}", dest.display());
    println!(
        "  policy:   {}{}",
        if contacts { "contacts" } else { "everyone" },
        if ask { " (prompting per transfer)" } else { "" }
    );

    let deadline = if duration > 0.0 {
        Some(std::time::Instant::now() + Duration::from_secs_f64(duration))
    } else {
        None
    };
    while rx.is_running() {
        if let Some(d) = deadline {
            if std::time::Instant::now() >= d {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    rx.close();
    Ok(())
}

fn dirs_download() -> Option<PathBuf> {
    // HOME/Downloads, USERPROFILE/Downloads, else cwd
    for base in [std::env::var_os("HOME"), std::env::var_os("USERPROFILE")]
        .into_iter()
        .flatten()
    {
        let d = PathBuf::from(base).join("Downloads");
        if d.is_dir() {
            return Some(d);
        }
    }
    None
}

// --------------------------------------------------------------------- send

fn cmd_send(cli: &Cli) -> Result<()> {
    let Cmd::Send {
        ref files,
        ref iface,
        ref to,
        timeout,
        wait,
        ask_timeout,
        ref direct,
        ref name,
        ref keys,
        no_wake,
    } = cli.cmd
    else {
        unreachable!()
    };
    for f in files {
        if !f.is_file() {
            bail!("{}: not a file", f.display());
        }
    }
    let sender_name = name.clone().unwrap_or_else(hostname);
    let ident = load_identity(keys, &sender_name)?;
    let opts = airdrop_core::SendOpts {
        computer_name: sender_name,
        ask_timeout: Duration::from_secs_f64(ask_timeout),
        ..Default::default()
    };

    // Wake nearby receivers while we look for them.
    let mut wake = None;
    if !no_wake {
        let (value, tag) = airdrop_core::ble::advert_payload("A", &[0; 8], None);
        match airdrop_core::ble::Advertiser::start(value, 100) {
            Ok(a) => {
                log::info!(
                    "BLE wake advert up (backend={} tag={:02x?})",
                    a.backend_name(),
                    tag
                );
                wake = Some(a);
            }
            Err(e) => log::warn!("BLE wake unavailable: {e}"),
        }
    }

    let peer = if let Some(direct) = direct {
        let (host, port) = direct
            .rsplit_once(':')
            .context("--direct wants HOST:PORT")?;
        let ip: std::net::IpAddr = host
            .trim_matches(['[', ']'])
            .parse()
            .context("--direct wants a numeric host")?;
        airdrop_core::Peer {
            ident: "direct".into(),
            name: None,
            addrs: vec![ip],
            port: port.parse().context("bad port")?,
        }
    } else {
        let trans = airdrop_core::transport::pick(iface)?;
        let mut finder =
            airdrop_core::Finder::new(&ident, None, to.as_deref().unwrap_or(""), &opts)?;
        let deadline = std::time::Instant::now() + Duration::from_secs_f64(timeout);
        let mut chosen;
        loop {
            chosen = finder.run(
                deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .min(Duration::from_secs(10)),
                Some(&mut |p: &airdrop_core::Peer| {
                    println!(
                        "  peer {} {} [{}]:{}",
                        p.ident,
                        p.name.as_deref().unwrap_or("(anonymous)"),
                        p.addrs.first().map(|a| a.to_string()).unwrap_or_default(),
                        p.port
                    );
                }),
            )?;
            if chosen.is_some() || !wait || std::time::Instant::now() >= deadline {
                break;
            }
        }
        let _ = trans;
        match chosen {
            Some(p) => p,
            None => {
                eprintln!("no receiver found in {timeout:.0}s");
                std::process::exit(2);
            }
        }
    };

    let mut client = airdrop_core::AirDropClient::new(&ident, &peer, &opts)?;
    if let Some(n) = client.send_discover()? {
        println!(
            "receiver: '{n}' ({}) at {:?} - asking",
            peer.ident,
            client.connected_addr().unwrap_or(peer.addrs[0])
        );
    }
    client.reconnect()?;
    if !client.send_ask(files)? {
        eprintln!("declined");
        std::process::exit(3);
    }
    if !client.send_upload(files)? {
        eprintln!("upload failed");
        std::process::exit(4);
    }
    println!(
        "sent: {}",
        files
            .iter()
            .map(|f| f
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned())
            .collect::<Vec<_>>()
            .join(", ")
    );
    drop(wake);
    Ok(())
}

// --------------------------------------------------------------------- peers

fn cmd_peers(cli: &Cli) -> Result<()> {
    let Cmd::Peers {
        ref iface,
        ref to,
        timeout,
        ref keys,
        no_wake,
    } = cli.cmd
    else {
        unreachable!()
    };
    let sender_name = hostname();
    let ident = load_identity(keys, &sender_name)?;
    let trans = airdrop_core::transport::pick(iface)?;
    let mut wake = None;
    if !no_wake {
        let (value, _) = airdrop_core::ble::advert_payload("A", &[0; 8], None);
        wake = airdrop_core::ble::Advertiser::start(value, 100).ok();
    }
    let opts = airdrop_core::SendOpts::default();
    let mut finder = airdrop_core::Finder::new(&ident, None, to.as_deref().unwrap_or(""), &opts)?;
    let mut seen = 0usize;
    let mut on_peer = |p: &airdrop_core::Peer| {
        println!(
            "{}  {}  [{}]:{}",
            p.ident,
            p.name.as_deref().unwrap_or("(anonymous)"),
            p.addrs.first().map(|a| a.to_string()).unwrap_or_default(),
            p.port
        );
        // counter via environment outside is awkward; print suffices
    };
    finder.run(Duration::from_secs_f64(timeout), Some(&mut on_peer))?;
    let _ = trans;
    let _ = &mut seen;
    drop(wake);
    Ok(())
}

// ---------------------------------------------------------------------- wake

fn cmd_wake(cli: &Cli) -> Result<()> {
    let Cmd::Wake {
        ref arm,
        seconds,
        ref hashes,
    } = cli.cmd
    else {
        unreachable!()
    };
    let mut h = [0u8; 8];
    if let Some(hex) = hashes {
        let bytes = hex::decode(hex).context("--hashes wants 16 hex chars")?;
        if bytes.len() != 8 {
            bail!("--hashes must be 8 bytes (16 hex chars)");
        }
        h.copy_from_slice(&bytes);
    }
    let (value, tag) = airdrop_core::ble::advert_payload(arm, &h, None);
    let adv = airdrop_core::ble::Advertiser::start(value, 100)?;
    println!(
        "advertising AirDrop presence for {seconds}s (arm={arm} tag={:02x?} backend={})",
        tag,
        adv.backend_name()
    );
    std::thread::sleep(Duration::from_secs(seconds));
    drop(adv);
    Ok(())
}

// ------------------------------------------------------------------ identity

fn cmd_identity(cli: &Cli) -> Result<()> {
    let Cmd::Identity {
        ref keys,
        ref import,
    } = cli.cmd
    else {
        unreachable!()
    };
    let dir = keys_dir(keys);
    if let Some(paths) = import {
        std::fs::create_dir_all(&dir)?;
        std::fs::copy(&paths[0], dir.join("certificate.pem"))?;
        std::fs::copy(&paths[1], dir.join("key.pem"))?;
        if let Some(rec) = paths.get(2) {
            std::fs::copy(rec, dir.join("record.bin"))?;
        }
        println!("imported Apple identity into {}", dir.display());
        return Ok(());
    }
    match identity::resolve(&dir, &hostname()) {
        Ok(id) => {
            println!("identity: {}", id.kind);
            println!("  keys dir: {}", dir.display());
            println!(
                "  record:   {}",
                id.record_data
                    .as_ref()
                    .map(|r| format!("{} bytes", r.len()))
                    .unwrap_or_else(|| "none (Everyone only)".into())
            );
        }
        Err(e) => {
            eprintln!("no identity: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------- doctor

fn cmd_doctor(_cli: &Cli) -> Result<()> {
    println!(
        "platform:       {} ({}), a4e {}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "AWDL interface: {}",
        if airdrop_core::transport::awdl_available() {
            "awdl0 present"
        } else {
            "none"
        }
    );
    let (value, tag) = airdrop_core::ble::advert_payload("A", &[0; 8], None);
    let ble = match airdrop_core::ble::Advertiser::start(value, 100) {
        Ok(a) => {
            let n = a.backend_name();
            drop(a);
            n
        }
        Err(_e) => {
            let _ = tag;
            "unsupported"
        }
    };
    println!("BLE backend:    {ble}");
    println!("keys dir:       {}", identity::default_keys_dir().display());
    match std::env::consts::OS {
        "windows" | "android" => {
            println!();
            println!("note: this platform has no AWDL driver path, so Apple devices");
            println!("cannot be discovered; LAN transport talks to other devices");
            println!("running AirDrop-for-Everything (or Macs with BrowseAllInterfaces).");
        }
        _ => {}
    }
    Ok(())
}

// ------------------------------------------------------------- awdl frames

fn report_record(rec: &airdrop_core::aframes::Record, sa: &Option<String>) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let mut line = format!(
        "{ts:.3} sa={} type={} host={}",
        sa.as_deref().unwrap_or("?"),
        rec.frame_type,
        rec.host.as_deref().unwrap_or("?")
    );
    if let Some(ep) = airdrop_core::aframes::airdrop_endpoint(rec) {
        line += &format!(
            " airdrop={}@{}:{}",
            ep.id,
            ep.target.as_deref().unwrap_or("?"),
            ep.port.map(|p| p.to_string()).unwrap_or_else(|| "?".into())
        );
        if !ep.txt.is_empty() {
            line += &format!(" txt=[{}]", ep.txt.join(","));
        }
    }
    println!("{line}");
}

fn cmd_afparse(cli: &Cli) -> Result<()> {
    let Cmd::AfParse { ref frame } = cli.cmd else {
        unreachable!()
    };
    let mut lines: Vec<String> = Vec::new();
    if frame == "-" {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        lines.extend(stdin.lock().lines().map_while(|l| l.ok()));
    } else {
        lines.push(frame.clone());
    }
    for line in lines {
        let clean: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.is_empty() {
            continue;
        }
        let bytes = hex::decode(&clean).context("not hex")?;
        let (body, sa) =
            airdrop_core::aframes::extract_body(&bytes).context("no AWDL vendor magic in frame")?;
        match airdrop_core::aframes::parse_body(body) {
            Some(rec) => report_record(&rec, &sa),
            None => eprintln!("vendor magic found but not an AWDL frame"),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn cmd_aflisten(cli: &Cli) -> Result<()> {
    use std::os::unix::io::RawFd;
    let Cmd::AfListen { ref iface } = cli.cmd else {
        unreachable!()
    };
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            i32::from((libc::ETH_P_ALL as u16).to_be()),
        )
    };
    if fd < 0 {
        bail!(
            "AF_PACKET socket: {} (need root?)",
            std::io::Error::last_os_error()
        );
    }
    struct Guard(RawFd);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
    let _guard = Guard(fd);
    let ifindex = unsafe {
        libc::if_nametoindex(
            std::ffi::CString::new(iface.as_str())
                .unwrap_or_default()
                .as_ptr(),
        )
    };
    if ifindex == 0 {
        bail!("interface {iface}: {}", std::io::Error::last_os_error());
    }
    let addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    if unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    } < 0
    {
        bail!("bind {iface}: {}", std::io::Error::last_os_error());
    }
    eprintln!("listening for AWDL action frames on {iface}");
    let mut buf = vec![0u8; 65535];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut std::ffi::c_void, buf.len(), 0) };
        if n <= 0 {
            continue;
        }
        if let Some((body, sa)) = airdrop_core::aframes::extract_body(&buf[..n as usize]) {
            if let Some(rec) = airdrop_core::aframes::parse_body(body) {
                if !rec.services.is_empty() || rec.host.is_some() {
                    report_record(&rec, &sa);
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn cmd_aflisten(_cli: &Cli) -> Result<()> {
    bail!("af-listen needs Linux (AF_PACKET monitor capture)")
}

// tiny hex decode so we don't pull in a crate for one flag
mod hex {
    pub fn decode(s: &str) -> anyhow::Result<Vec<u8>> {
        if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!("not hex");
        }
        Ok((0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..2 + i], 16).unwrap())
            .collect())
    }
}
