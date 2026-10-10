//! AirDrop BLE wake advertisement (Apple Continuity, type 0x05).
//! Port of prototype ble.py. WinRT on Windows, raw HCI via hcitool on
//! Linux, documented stub elsewhere.
//!
//! On-air value: Manufacturer Specific Data, company 0x004C (Apple),
//! value = one Continuity TLV ``05 12 <18 bytes>``.

use crate::{consts, Error, Result};

/// Build the manufacturer-data value for an AirDrop advert.
/// `arm`: "A" | "V2" | "B". `hashes`: 8 bytes of truncated contact hashes
/// (zeros wake Everyone-mode receivers). Returns (value, 3-byte tag).
pub fn advert_payload(arm: &str, hashes: &[u8; 8], tag: Option<[u8; 3]>) -> (Vec<u8>, [u8; 3]) {
    let tag = tag.unwrap_or_else(rand_tag);
    let mut body = Vec::with_capacity(18);
    match arm {
        // OS 26 shape: 40 <tag3> 00000000 03 <hashes> 00
        "A" => {
            body.push(0x40);
            body.extend_from_slice(&tag);
            body.extend_from_slice(&[0; 4]);
            body.push(0x03);
            body.extend_from_slice(hashes);
            body.push(0);
        }
        // iPhone Aug-2025 shape: 00x8 02 <hashes> 00
        "V2" => {
            body.extend_from_slice(&[0; 8]);
            body.push(0x02);
            body.extend_from_slice(hashes);
            body.push(0);
        }
        // Published 2019/2020 shape ("B" and anything else):
        // 00x8 01 <hashes> 00
        _ => {
            body.extend_from_slice(&[0; 8]);
            body.push(0x01);
            body.extend_from_slice(hashes);
            body.push(0);
        }
    }
    debug_assert_eq!(body.len(), 18);
    let mut value = Vec::with_capacity(20);
    value.push(consts::BLE_TYPE_AIRDROP);
    value.push(body.len() as u8);
    value.extend_from_slice(&body);
    (value, tag)
}

/// Three fresh tag bytes (correlates with /Ask's SenderIdentityAuthTag).
/// RandomState's per-process seed makes these unpredictable; time+pid make
/// them unique per call.
fn rand_tag() -> [u8; 3] {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    h.write_u32(std::process::id());
    h.write_u64(counter());
    let v = h.finish();
    [v as u8, (v >> 8) as u8, (v >> 16) as u8]
}

fn counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

/// Background BLE advertiser; Drop stops advertising.
pub struct Advertiser {
    backend: &'static str,
    #[cfg(windows)]
    publisher:
        Option<windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher>,
    #[cfg(target_os = "linux")]
    hci_on: bool,
    #[cfg(target_os = "linux")]
    adapter: String,
}

impl Advertiser {
    /// Start advertising `value` (from advert_payload). Errors when no
    /// backend exists on this platform — callers should degrade to LAN.
    pub fn start(value: Vec<u8>, interval_ms: u32) -> Result<Self> {
        start_impl(value, interval_ms)
    }
    /// Backend name for diagnostics ("winrt" | "hcitool" | "unsupported").
    pub fn backend_name(&self) -> &'static str {
        self.backend
    }
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(p) = self.publisher.take() {
            let _ = p.Stop();
            log::info!("BLE AirDrop advert down (winrt)");
        }
        #[cfg(target_os = "linux")]
        if self.hci_on {
            let _ = hci_cmd(&self.adapter, &["0x08", "0x000a", "0x00"]);
            log::info!("BLE AirDrop advert down (hcitool)");
        }
    }
}

// ------------------------------------------------------------- Windows WinRT

#[cfg(windows)]
fn start_impl(value: Vec<u8>, _interval_ms: u32) -> Result<Advertiser> {
    use windows::Devices::Bluetooth::Advertisement::{
        BluetoothLEAdvertisementPublisher, BluetoothLEManufacturerData,
    };
    use windows::Storage::Streams::DataWriter;

    fn ble_err(e: impl std::fmt::Display) -> Error {
        Error::Ble(e.to_string())
    }

    let writer = DataWriter::new().map_err(ble_err)?;
    writer.WriteBytes(&value).map_err(ble_err)?;
    let mfr = BluetoothLEManufacturerData::new().map_err(ble_err)?;
    mfr.SetCompanyId(consts::APPLE_COMPANY_ID)
        .map_err(ble_err)?;
    mfr.SetData(&writer.DetachBuffer().map_err(ble_err)?)
        .map_err(ble_err)?;
    let publisher = BluetoothLEAdvertisementPublisher::new().map_err(ble_err)?;
    publisher
        .Advertisement()
        .map_err(ble_err)?
        .ManufacturerData()
        .map_err(ble_err)?
        .Append(&mfr)
        .map_err(ble_err)?;
    publisher.Start().map_err(ble_err)?;
    log::info!("BLE advert via WinRT (status={:?})", publisher.Status());
    Ok(Advertiser {
        backend: "winrt",
        publisher: Some(publisher),
    })
}

// ------------------------------------------------------------- Linux hcitool

#[cfg(target_os = "linux")]
fn start_impl(value: Vec<u8>, interval_ms: u32) -> Result<Advertiser> {
    let adapter = "hci0".to_string();
    // hcitool must exist — the BlueZ D-Bus path of the prototype has no
    // blocking-Rust counterpart, so the raw HCI trio is the only backend.
    if which("hcitool").is_none() {
        return Err(Error::Unsupported(
            "hcitool not found (install bluez tools)".into(),
        ));
    }
    // ms -> HCI units of 0.625 ms (i.e. *8/5), clamped to [32, 16384].
    let interval = ((interval_ms as u64) * 8 / 5).clamp(32, 16384) as u16;
    let iv = interval.to_le_bytes();
    // LE Set Advertising Parameters: non-connectable broadcast undirected.
    let iv0 = hx(iv[0]);
    let iv1 = hx(iv[1]);
    hci_cmd(
        &adapter,
        &[
            "0x08",
            "0x0006",
            iv0.as_str(),
            iv1.as_str(),
            iv0.as_str(),
            iv1.as_str(),
            "0x03",
            "0x00",
            "0x00",
            "0x00",
            "0x00",
            "0x00",
            "0x00",
            "0x00",
            "0x00",
            "0x07",
            "0x00",
        ],
    )?;
    // LE Set Advertising Data: [flags AD] [mfr AD], capped at 31 bytes.
    let mut adv = vec![0x02, 0x01, 0x06];
    adv.push((value.len() + 3) as u8);
    adv.push(0xFF);
    adv.extend_from_slice(&consts::APPLE_COMPANY_ID.to_le_bytes());
    adv.extend_from_slice(&value);
    adv.truncate(31);
    let mut data = vec![adv.len() as u8];
    data.extend_from_slice(&adv);
    data.resize(32, 0);
    let args: Vec<String> = std::iter::once("0x08".to_string())
        .chain(std::iter::once("0x0008".to_string()))
        .chain(data.iter().map(|b| hx(*b)))
        .collect();
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    hci_cmd(&adapter, &arg_refs)?;
    hci_cmd(&adapter, &["0x08", "0x000a", "0x01"])?;
    log::info!("BLE advert on {adapter} via hcitool ({} B AD)", adv.len());
    Ok(Advertiser {
        backend: "hcitool",
        hci_on: true,
        adapter,
    })
}

#[cfg(target_os = "linux")]
fn hx(b: u8) -> String {
    format!("0x{b:02x}")
}

#[cfg(target_os = "linux")]
fn which(prog: &str) -> Option<std::path::PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|p| p.join(prog))
        .find(|c| c.is_file())
}

#[cfg(target_os = "linux")]
fn hci_cmd(adapter: &str, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new("hcitool")
        .arg("-i")
        .arg(adapter)
        .arg("cmd")
        .args(args)
        .output()
        .map_err(|e| Error::Ble(format!("hcitool: {e}")))?;
    if !out.status.success() {
        return Err(Error::Ble(format!(
            "hcitool failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    log::debug!(
        "hcitool {} -> {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout).trim()
    );
    Ok(())
}

// ------------------------------------------------------------- unsupported

#[cfg(not(any(windows, target_os = "linux")))]
fn start_impl(_value: Vec<u8>, _interval_ms: u32) -> Result<Advertiser> {
    let why = if cfg!(target_os = "macos") {
        "CoreBluetooth cannot emit manufacturer data (Apple's own Continuity \
         adverts are not exposable)"
    } else {
        "no BLE advertisement backend for this platform"
    };
    Err(Error::Unsupported(why.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_arm_a() {
        let hashes = [1, 2, 3, 4, 5, 6, 7, 8];
        let (v, tag) = advert_payload("A", &hashes, Some([0xaa, 0xbb, 0xcc]));
        assert_eq!(tag, [0xaa, 0xbb, 0xcc]);
        assert_eq!(v.len(), 20);
        assert_eq!(v[0], 0x05);
        assert_eq!(v[1], 0x12);
        // Arm A body: 40 <tag> 00x4 03 <hashes> 00
        assert_eq!(v[2], 0x40);
        assert_eq!(&v[3..6], &[0xaa, 0xbb, 0xcc]);
        assert_eq!(&v[6..10], &[0, 0, 0, 0]);
        assert_eq!(v[10], 0x03);
        assert_eq!(&v[11..19], &hashes);
        assert_eq!(v[19], 0x00);
    }

    #[test]
    fn payload_arms_v2_b() {
        let hashes = [0xde; 8];
        let (v, _) = advert_payload("V2", &hashes, None);
        assert_eq!(&v[..2], &[0x05, 0x12]);
        assert_eq!(&v[2..10], &[0; 8]);
        assert_eq!(v[10], 0x02);
        assert_eq!(&v[11..19], &hashes);
        assert_eq!(v[19], 0x00);

        let (v, _) = advert_payload("B", &hashes, None);
        assert_eq!(&v[..2], &[0x05, 0x12]);
        assert_eq!(&v[2..10], &[0; 8]);
        assert_eq!(v[10], 0x01);
        assert_eq!(&v[11..19], &hashes);
        assert_eq!(v[19], 0x00);
    }

    #[test]
    fn payload_body_positions() {
        // Marker is always body byte 8 (v[10]); final byte is zero.
        let hashes = [9; 8];
        for arm in ["A", "V2", "B"] {
            let (v, _) = advert_payload(arm, &hashes, None);
            assert_eq!(v.len(), 20, "{arm}");
            assert_eq!(&v[11..19], &hashes, "{arm}");
            assert_eq!(v[19], 0, "{arm}");
        }
    }

    #[test]
    fn tag_randomness() {
        let (_, t1) = advert_payload("B", &[0; 8], None);
        let (_, t2) = advert_payload("B", &[0; 8], None);
        assert_ne!(t1, t2);
    }
}
