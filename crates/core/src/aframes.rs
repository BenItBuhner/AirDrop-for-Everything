//! AWDL action-frame parsing — port of prototype aframes.py (itself a port
//! of omdrop-awdl's awdl-af-parse.py). AWDL devices multicast action frames
//! (PSF type 0 / MIF type 3) carrying Service Response TLVs that advertise
//! `_airdrop._tcp` — the frame body lets a sender learn a receiver's
//! endpoint without waiting for mDNS.

use crate::consts::AF_VENDOR_MAGIC;
use std::collections::HashMap;

/// AWDL's fixed name dictionary for the c0xx tail of a compressed name.
fn dict_tail(code: u8) -> Option<&'static str> {
    match code {
        0x00 => Some(""),
        0x07 => Some("_airdrop._tcp.local"),
        0x0A => Some("_tcp.local"),
        0x0B => Some("_udp.local"),
        0x0C => Some("local"),
        _ => None,
    }
}

/// DNS-style labels with AWDL's c0xx dictionary tail → (name, next_off).
pub fn name(b: &[u8], mut off: usize) -> (String, usize) {
    let mut labels: Vec<String> = Vec::new();
    while off < b.len() {
        let ln = b[off] as usize;
        if ln == 0xC0 {
            let code = b.get(off + 1).copied().unwrap_or(0);
            match dict_tail(code) {
                Some(t) if !t.is_empty() => labels.push(t.to_string()),
                Some(_) => {}
                None => labels.push(format!("<c0{code:02x}>")),
            }
            return (labels.join("."), off + 2);
        }
        if ln == 0 {
            return (labels.join("."), off + 1);
        }
        let start = off + 1;
        let end = (start + ln).min(b.len());
        labels.push(String::from_utf8_lossy(&b[start..end]).into_owned());
        off = start + ln;
    }
    (labels.join("."), off)
}

/// Iterate (type, value) TLVs over a body.
pub fn tlvs(body: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut i = 0usize;
    std::iter::from_fn(move || {
        if i + 3 > body.len() {
            return None;
        }
        let t = body[i];
        let ln = u16::from_le_bytes([body[i + 1], body[i + 2]]) as usize;
        let v = &body[i + 3..(i + 3 + ln).min(body.len())];
        i += 3 + ln;
        Some((t, v))
    })
}

#[derive(Debug, Default, Clone)]
pub struct SrvRecord {
    pub port: u16,
    pub target: String,
}

#[derive(Debug, Default, Clone)]
pub struct ServiceRecords {
    pub ptr: Option<String>,
    pub srv: Option<SrvRecord>,
    pub txt: Vec<String>,
    /// raw rdata hex for unhandled rtypes
    pub other: HashMap<u8, String>,
}

#[derive(Debug, Default, Clone)]
pub struct Record {
    /// action-frame subtype (hdr byte 2)
    pub frame_type: u8,
    /// transmitter hostname, from the Arpa TLV (type 16)
    pub host: Option<String>,
    /// record name → records
    pub services: HashMap<String, ServiceRecords>,
    /// transmitter MAC (from extract_body)
    pub sa: Option<String>,
    /// capture epoch seconds (set by the caller)
    pub ts: f64,
}

/// One Service Response TLV → (record_name, parsed fields).
fn service_response(v: &[u8], out: &mut HashMap<String, ServiceRecords>) -> Option<()> {
    if v.len() < 4 {
        return None;
    }
    let nlen = u16::from_le_bytes([v[0], v[1]]) as usize;
    let (n, _) = name(v, 2);
    let off = 2 + nlen.checked_sub(1)?; // name_len counts the type byte
    if off + 5 > v.len() {
        return None;
    }
    let rtype = v[off];
    let dlen = u16::from_le_bytes([v[off + 1], v[off + 2]]) as usize;
    let rd = &v[(off + 5)..(off + 5 + dlen).min(v.len())];
    let rec = out.entry(n).or_default();
    match rtype {
        12 => rec.ptr = Some(name(rd, 0).0),
        33 if rd.len() >= 6 => {
            let port = u16::from_be_bytes([rd[4], rd[5]]);
            rec.srv = Some(SrvRecord {
                port,
                target: name(rd, 6).0,
            });
        }
        16 => {
            let mut j = 0usize;
            while j < rd.len() {
                let ln = rd[j] as usize;
                let s = (j + 1)..(j + 1 + ln).min(rd.len());
                rec.txt.push(String::from_utf8_lossy(&rd[s]).into_owned());
                j += 1 + ln;
            }
        }
        _ => {
            rec.other.insert(rtype, hex(rd));
        }
    }
    Some(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parse a frame body (starting at the action-frame category byte).
/// Returns None when the vendor magic or AWDL header check fails.
pub fn parse_body(body: &[u8]) -> Option<Record> {
    if body.len() < 16 || body[..4] != AF_VENDOR_MAGIC {
        return None;
    }
    let hdr = &body[4..16]; // awdl_hdr_t: magic 08, ver, subtype…
    if hdr[0] != 0x08 {
        return None;
    }
    let mut rec = Record {
        frame_type: hdr[2],
        ..Default::default()
    };
    for (t, v) in tlvs(&body[16..]) {
        if t == 16 && v.len() > 1 {
            rec.host = Some(name(v, 1).0);
        } else if t == 2 && v.len() > 5 {
            service_response(v, &mut rec.services);
        }
    }
    Some(rec)
}

#[derive(Debug, Default, Clone)]
pub struct Endpoint {
    pub id: String,
    pub port: Option<u16>,
    pub target: Option<String>,
    pub txt: Vec<String>,
    pub host: Option<String>,
}

/// The AirDrop receiver identity inside a parsed frame, if any.
pub fn airdrop_endpoint(rec: &Record) -> Option<Endpoint> {
    let ptr = rec.services.get("_airdrop._tcp.local")?.ptr.clone()?;
    let inst = rec
        .services
        .get(&ptr)
        .or_else(|| rec.services.get(&format!("{ptr}._airdrop._tcp.local")));
    let (srv, txt) = match inst {
        Some(i) => (i.srv.clone(), i.txt.clone()),
        None => (None, Vec::new()),
    };
    Some(Endpoint {
        id: ptr.split('.').next().unwrap_or("").to_string(),
        port: srv.as_ref().map(|s| s.port),
        target: srv.map(|s| s.target),
        txt,
        host: rec.host.clone(),
    })
}

/// Locate the action-frame body inside a raw 802.11/monitor capture —
/// scans for the vendor action category + Apple OUI magic, returning
/// (body, transmitter MAC) where the MAC is recovered when locatable.
pub fn extract_body(frame: &[u8]) -> Option<(&[u8], Option<String>)> {
    let p = frame
        .windows(AF_VENDOR_MAGIC.len())
        .position(|w| w == AF_VENDOR_MAGIC)?;
    let sa = if p >= 24 {
        Some(
            frame[p - 14..p - 8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        )
    } else {
        None
    };
    Some((&frame[p..], sa))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Service Response value: name_len(2) + name + rtype +
    /// dlen(2) + flags(2) + rdata.
    fn srv_tlv(rname: &[u8], rtype: u8, rdata: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let nlen = (rname.len() + 1) as u16;
        v.extend_from_slice(&nlen.to_le_bytes());
        v.extend_from_slice(rname);
        v.push(rtype);
        v.extend_from_slice(&(rdata.len() as u16).to_le_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(rdata);
        v
    }

    fn frame_with(tlvs_body: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&AF_VENDOR_MAGIC);
        b.extend_from_slice(&[0x08, 0x00, 0x00]); // hdr magic/ver/subtype
        b.extend_from_slice(&[0u8; 9]); // rest of awdl_hdr_t
        b.extend_from_slice(tlvs_body);
        b
    }

    fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
        let mut out = vec![t];
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(v);
        out
    }

    #[test]
    fn parses_ptr_and_srv() {
        // "_airdrop._tcp.local" PTR -> "abc123def456._airdrop._tcp.local"
        let ptr_target = b"\x0cabc123def456\xc0\x07";
        let ptr_v = srv_tlv(b"\xc0\x07", 12, ptr_target);
        // SRV rdata: prio weight port + target name
        let mut srv_rd = vec![0, 0, 0, 0, 0x22, 0x43]; // port 0x2243 = 8771
        srv_rd.extend_from_slice(b"\x07my-host\xc0\x0c"); // "my-host.local"
        let srv_v = srv_tlv(b"\x0cabc123def456\xc0\x07", 33, &srv_rd);
        let body = frame_with(&[tlv(2, &ptr_v), tlv(2, &srv_v)].concat());
        let rec = parse_body(&body).unwrap();
        let ep = airdrop_endpoint(&rec).unwrap();
        assert_eq!(ep.id, "abc123def456");
        assert_eq!(ep.port, Some(8771));
        assert_eq!(ep.target.as_deref(), Some("my-host.local"));
    }

    #[test]
    fn rejects_non_awdl() {
        assert!(parse_body(b"not an airdrop frame at all").is_none());
        assert!(parse_body(&[]).is_none());
    }

    #[test]
    fn extracts_from_80211() {
        let mut frame = vec![0u8; 24]; // fake 802.11 mgmt header
        frame[10] = 0xAA; // sa bytes land at p-14..p-8 => frame[10..16]
        frame[11] = 0xBB;
        let body = frame_with(&tlv(16, b"\x00\x04name"));
        frame.extend_from_slice(&body);
        let (b, sa) = extract_body(&frame).unwrap();
        assert_eq!(b, &body[..]);
        assert!(sa.unwrap().starts_with("aa:bb"));
    }

    #[test]
    fn txt_records() {
        let txt_rd = b"\x09flags=137";
        let txt_v = srv_tlv(b"\x0cabc123def456\xc0\x07", 16, txt_rd);
        let ptr_v = srv_tlv(b"\xc0\x07", 12, b"\x0cabc123def456\xc0\x07");
        let body = frame_with(&[tlv(2, &ptr_v), tlv(2, &txt_v)].concat());
        let rec = parse_body(&body).unwrap();
        let ep = airdrop_endpoint(&rec).unwrap();
        assert_eq!(ep.txt, vec!["flags=137".to_string()]);
    }
}
