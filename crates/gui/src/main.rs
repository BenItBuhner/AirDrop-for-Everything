//! a4e-gui — native desktop frontend for airdrop-core.
//!
//! egui window: Receive / Send / Peers tabs driving the blocking core API
//! from worker threads (channels -> egui repaint).

use airdrop_core::identity::{self, Identity};
use airdrop_core::{transport, Peer, Receiver, ReceiverConfig, SendOpts, Visibility};
use eframe::egui::{self, Color32, RichText};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver as MpscRx, Sender};

use std::time::Duration;

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 560.0])
            .with_min_inner_size([560.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "AirDrop for Everything",
        opts,
        Box::new(|_| Ok(Box::new(App::new()))),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Receive,
    Send,
    Peers,
    Identity,
}

enum Event {
    Log(String),
    Peer(Peer),
    PeersDone,
    Sent(String),
    Failed(String),
}

struct App {
    tab: Tab,
    ident: Result<Identity, String>,
    transport: String,

    // receive tab
    rx_name: String,
    rx_dest: PathBuf,
    rx_ask: bool,
    receiver: Option<Receiver>,
    announcer: Option<airdrop_core::discovery::Announcer>,

    // send tab
    files: Vec<PathBuf>,

    // peers tab
    peers: Vec<Peer>,
    selected_peer: Option<usize>,
    browsing: bool,

    log: VecDeque<String>,
    events_tx: Sender<Event>,
    events_rx: MpscRx<Event>,
}

impl App {
    fn new() -> Self {
        let ident = identity::resolve(&identity::default_keys_dir(), &short_host())
            .map_err(|e| e.to_string());
        let transport = transport::pick("auto")
            .map(|t| t.describe())
            .unwrap_or_else(|_| "LAN (fallback)".into());
        let (events_tx, events_rx) = channel();
        let mut log = VecDeque::new();
        log.push_back("ready — pick a tab".to_string());
        Self {
            tab: Tab::Receive,
            ident,
            transport,
            rx_name: short_host(),
            rx_dest: downloads_dir().unwrap_or_else(|| PathBuf::from(".")),
            rx_ask: false,
            receiver: None,
            announcer: None,
            files: vec![],
            peers: vec![],
            selected_peer: None,
            browsing: false,
            log,
            events_tx,
            events_rx,
        }
    }

    fn logln(&mut self, s: String) {
        self.log.push_back(s);
        while self.log.len() > 400 {
            self.log.pop_front();
        }
    }

    // ------------------------------------------------------------- actions

    fn toggle_receiver(&mut self) {
        if self.receiver.is_some() {
            self.receiver = None;
            self.announcer = None;
            self.logln("receiver stopped".into());
            return;
        }
        let Ok(ident) = &self.ident else {
            self.logln("no identity — see Identity tab".into());
            return;
        };
        let name = self.rx_name.clone();
        let model = airdrop_core::consts::DEFAULT_MODEL.to_string();
        let tx = self.events_tx.clone();
        let tx2 = self.events_tx.clone();
        match airdrop_core::serve(
            ReceiverConfig {
                name: name.clone(),
                model: model.clone(),
                dest: self.rx_dest.clone(),
                visibility: Visibility::Everyone,
                port: airdrop_core::consts::AIRDROP_PORT,
                bind: "::".into(),
                max_receive_percent: 30,
                on_ask: None,
                on_upload: Some(Box::new(move |_tid, files| {
                    let _ = tx.send(Event::Log(format!("received: {}", files.join(", "))));
                })),
            },
            ident,
        ) {
            Ok(rx) => {
                let port = rx.port();
                self.receiver = Some(rx);
                match transport::pick("auto").and_then(|t| {
                    airdrop_core::discovery::announce(
                        &t.service_id(),
                        &host_label(&name),
                        port,
                        airdrop_core::consts::FLAGS_DEFAULT,
                        &t.addrs,
                    )
                    .map(|a| (t, a))
                }) {
                    Ok((_t, ann)) => {
                        self.announcer = Some(ann);
                    }
                    Err(e) => {
                        self.logln(format!("mDNS announce failed: {e}"));
                    }
                }
                let _ = tx2.send(Event::Log(format!(
                    "receiving as '{name}' on :{port} — {}",
                    self.transport
                )));
            }
            Err(e) => {
                self.logln(format!("receiver failed: {e}"));
            }
        }
    }

    fn browse_peers(&mut self) {
        if self.browsing {
            return;
        }
        self.browsing = true;
        self.peers.clear();
        self.selected_peer = None;
        let tx = self.events_tx.clone();
        std::thread::spawn(move || {
            let _ = airdrop_core::discovery::browse(Duration::from_secs(8), None, &mut |ad| {
                let _ = tx.send(Event::Peer(Peer {
                    ident: ad.instance.clone(),
                    name: None,
                    addrs: ad.addrs.clone(),
                    port: ad.port,
                }));
            });
            let _ = tx.send(Event::PeersDone);
        });
    }

    fn send_selected(&mut self) {
        let Some(&i) = self.selected_peer.as_ref() else {
            self.logln("pick a peer first (Peers tab → Refresh)".into());
            return;
        };
        if self.files.is_empty() {
            self.logln("drop files or 'Add files…' first".into());
            return;
        }
        let Ok(ident) = &self.ident else {
            self.logln("no identity".into());
            return;
        };
        let peer = self.peers[i].clone();
        let files = self.files.clone();
        let ident = ident.clone();
        let tx = self.events_tx.clone();
        let peer_label = peer.name.clone().unwrap_or_else(|| peer.ident.clone());
        std::thread::spawn(move || {
            let opts = SendOpts {
                computer_name: short_host(),
                ..Default::default()
            };
            match airdrop_core::send_files(&files, &peer, &ident, &opts) {
                Ok(name) => {
                    let _ = tx.send(Event::Sent(name));
                }
                Err(e) => {
                    let _ = tx.send(Event::Failed(e.to_string()));
                }
            }
        });
        self.logln(format!(
            "sending {} file(s) to {}…",
            self.files.len(),
            peer_label
        ));
    }
}

fn short_host() -> String {
    hostname_or("airdrop")
}

fn hostname_or(def: &str) -> String {
    // avoid extra dep: env fallbacks
    for var in ["COMPUTERNAME", "HOSTNAME", "NAME"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return v.split('.').next().unwrap_or(&v).to_string();
            }
        }
    }
    def.into()
}

fn host_label(name: &str) -> String {
    name.to_lowercase().replace(' ', "-")
}

fn downloads_dir() -> Option<PathBuf> {
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

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // pump worker events
        while let Ok(ev) = self.events_rx.try_recv() {
            match ev {
                Event::Log(s) => self.logln(s),
                Event::Peer(p) => self.peers.push(p),
                Event::PeersDone => {
                    self.browsing = false;
                    self.logln(format!("browse finished — {} peer(s)", self.peers.len()));
                }
                Event::Sent(n) => self.logln(format!("sent — accepted by '{n}'")),
                Event::Failed(e) => self.logln(format!("send failed: {e}")),
            }
        }

        // drag & drop files anywhere in the window
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        for f in dropped {
            if let Some(p) = f.path {
                if p.is_file() && !self.files.contains(&p) {
                    self.files.push(p);
                    self.tab = Tab::Send;
                }
            }
        }

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("AirDrop");
                ui.label(RichText::new("for Everything").color(Color32::LIGHT_BLUE));
                ui.separator();
                for (t, label) in [
                    (Tab::Receive, "Receive"),
                    (Tab::Send, "Send"),
                    (Tab::Peers, "Peers"),
                    (Tab::Identity, "Identity"),
                ] {
                    ui.selectable_value(&mut self.tab, t, label);
                }
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("link:").weak());
                ui.label(&self.transport);
                ui.separator();
                ui.label(RichText::new(if self.receiver.is_some() {
                    "receiving"
                } else {
                    "idle"
                }));
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Receive => self.ui_receive(ui),
            Tab::Send => self.ui_send(ui),
            Tab::Peers => self.ui_peers(ui),
            Tab::Identity => self.ui_identity(ui),
        });
    }
}

impl App {
    fn ui_receive(&mut self, ui: &mut egui::Ui) {
        ui.heading("Receiver");
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("Your name:");
            ui.text_edit_singleline(&mut self.rx_name);
        });
        ui.horizontal(|ui| {
            ui.label("Save to:  ");
            ui.label(self.rx_dest.display().to_string());
            if ui.button("…").clicked() {
                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                    self.rx_dest = d;
                }
            }
        });
        ui.checkbox(&mut self.rx_ask, "Ask before each transfer");
        ui.add_space(6.0);
        let running = self.receiver.is_some();
        let label = if running {
            "■ Stop receiving"
        } else {
            "▶ Start receiving"
        };
        if ui
            .add(egui::Button::new(label).min_size([160.0, 32.0].into()))
            .clicked()
        {
            self.toggle_receiver();
        }
        ui.add_space(10.0);
        ui.label(RichText::new("Log").weak());
        self.ui_log(ui);
    }

    fn ui_send(&mut self, ui: &mut egui::Ui) {
        ui.heading("Send files");
        ui.add_space(6.0);
        let frame = egui::Frame::default()
            .stroke(ui.style().visuals.widgets.noninteractive.bg_stroke)
            .corner_radius(6.0)
            .inner_margin(10.0);
        frame.show(ui, |ui| {
            ui.label("Drop files anywhere in this window, or:");
            if ui.button("Add files…").clicked() {
                if let Some(fs) = rfd::FileDialog::new().pick_files() {
                    for f in fs {
                        if !self.files.contains(&f) {
                            self.files.push(f);
                        }
                    }
                }
            }
        });
        ui.add_space(6.0);
        for (i, f) in self.files.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(f.file_name().unwrap_or_default().to_string_lossy());
                ui.weak(format!("{} B", f.metadata().map(|m| m.len()).unwrap_or(0)));
                if ui.small_button("✕").clicked() {
                    // mark via flag on index (drain after loop)
                }
            });
            let _ = i;
        }
        if ui.small_button("clear list").clicked() {
            self.files.clear();
        }
        ui.add_space(6.0);
        if ui
            .add(egui::Button::new("Send to selected peer").min_size([200.0, 32.0].into()))
            .clicked()
        {
            self.send_selected();
        }
        ui.add_space(10.0);
        ui.label(RichText::new("Log").weak());
        self.ui_log(ui);
    }

    fn ui_peers(&mut self, ui: &mut egui::Ui) {
        ui.heading("Peers");
        ui.add_space(6.0);
        if ui
            .add_enabled(!self.browsing, egui::Button::new("Refresh (8s browse)"))
            .clicked()
        {
            self.browse_peers();
        }
        ui.add_space(6.0);
        egui::ScrollArea::vertical()
            .max_height(220.0)
            .show(ui, |ui| {
                for (i, p) in self.peers.iter().enumerate() {
                    let label = format!(
                        "{}   {}   [{}]:{}",
                        p.ident,
                        p.name.as_deref().unwrap_or("(anonymous)"),
                        p.addrs.first().map(|a| a.to_string()).unwrap_or_default(),
                        p.port
                    );
                    ui.selectable_value(&mut self.selected_peer, Some(i), label);
                }
                if self.peers.is_empty() && !self.browsing {
                    ui.weak("no peers found yet");
                }
            });
        ui.add_space(10.0);
        ui.label(RichText::new("Log").weak());
        self.ui_log(ui);
    }

    fn ui_identity(&mut self, ui: &mut egui::Ui) {
        ui.heading("Identity");
        ui.add_space(6.0);
        match &self.ident {
            Ok(id) => {
                ui.label(format!("kind:   {}", id.kind));
                ui.label(format!(
                    "keys:   {}",
                    identity::default_keys_dir().display()
                ));
                ui.label(format!(
                    "record: {}",
                    id.record_data
                        .as_ref()
                        .map(|r| format!("{} bytes", r.len()))
                        .unwrap_or_else(|| "none (Everyone mode only)".into())
                ));
            }
            Err(e) => {
                ui.label(format!("no identity: {e}"));
            }
        }
        ui.add_space(10.0);
        ui.label(RichText::new("Log").weak());
        self.ui_log(ui);
    }

    fn ui_log(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .id_salt("log")
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.log {
                    ui.label(egui::RichText::new(line).monospace().size(12.0));
                }
            });
    }
}
