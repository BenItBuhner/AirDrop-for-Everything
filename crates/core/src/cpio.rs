//! Pure-Rust `newc`/`odc` cpio writer + buffered reader.
//! Port of prototype/airdrop_everything/cpio.py.

use crate::{Error, Result};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const NEWC_MAGIC: &[u8; 6] = b"070701";
const NEWC_CRC_MAGIC: &[u8; 6] = b"070702";
const ODC_MAGIC: &[u8; 6] = b"070707";
const TRAILER: &str = "TRAILER!!!";
const BLOCK: usize = 512;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn bad(msg: impl Into<String>) -> Error {
    Error::Protocol(msg.into())
}

/// One archive member (payload buffered — callers cap sizes upstream).
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub mode: u32,
    pub mtime: u64,
    pub data: Vec<u8>,
}

impl Member {
    pub fn is_file(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

/// What to put in the archive.
pub enum CpioEntry {
    /// Stored from disk at `path` under archive `name`.
    File { name: String, path: PathBuf },
    /// Stored from memory.
    Bytes { name: String, data: Vec<u8> },
    /// Directory entry.
    Dir { name: String },
}

fn mtime_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn newc_header(name: &str, mode: u32, size: u64, ino: u32, mtime: u64) -> Vec<u8> {
    let namesize = name.len() + 1;
    let fields: [u64; 13] = [
        ino as u64,
        mode as u64,
        0,
        0,
        1,
        mtime & 0xFFFF_FFFF,
        size & 0xFFFF_FFFF,
        3,
        0,
        0,
        0,
        namesize as u64,
        0,
    ];
    let mut h = Vec::with_capacity(110 + namesize);
    h.extend_from_slice(NEWC_MAGIC);
    for f in fields {
        h.extend_from_slice(format!("{f:08x}").as_bytes());
    }
    h
}

/// Write a SVR4 "newc" archive. Names should already be "./file" style.
/// The stream is padded to a 512-byte block boundary on exit — pass a
/// counting writer if you compose archives.
pub fn write_newc<W: Write>(out: &mut W, entries: &[CpioEntry]) -> Result<()> {
    let mut written: usize = 0;
    write_newc_counted(out, entries, &mut written)?;
    let pad = (BLOCK - written % BLOCK) % BLOCK;
    out.write_all(&vec![0u8; pad])?;
    Ok(())
}

/// Same, tracking total bytes in `written` (for composition).
pub(crate) fn write_newc_counted<W: Write>(
    out: &mut W,
    entries: &[CpioEntry],
    written: &mut usize,
) -> Result<()> {
    let mtime = mtime_now();
    let mut ino: u32 = 1;
    for entry in entries {
        let (name, mode, size) = match entry {
            CpioEntry::Dir { name } => (name.clone(), S_IFDIR | 0o755, 0u64),
            CpioEntry::Bytes { name, data } => (name.clone(), S_IFREG | 0o644, data.len() as u64),
            CpioEntry::File { name, path } => {
                let size = std::fs::metadata(path)?.len();
                (name.clone(), S_IFREG | 0o644, size)
            }
        };
        let hdr = newc_header(&name, mode, size, ino, mtime);
        out.write_all(&hdr)?;
        out.write_all(name.as_bytes())?;
        out.write_all(&[0])?;
        let pad = align4(hdr.len() + name.len() + 1) - (hdr.len() + name.len() + 1);
        out.write_all(&vec![0u8; pad])?;
        *written += hdr.len() + name.len() + 1 + pad;

        match entry {
            CpioEntry::Dir { .. } => {}
            CpioEntry::Bytes { data, .. } => {
                out.write_all(data)?;
            }
            CpioEntry::File { path, .. } => {
                let mut f = std::fs::File::open(path)?;
                let mut left = size;
                let mut buf = vec![0u8; 65536];
                while left > 0 {
                    let want = left.min(buf.len() as u64) as usize;
                    let n = f.read(&mut buf[..want])?;
                    if n == 0 {
                        break;
                    }
                    out.write_all(&buf[..n])?;
                    left -= n as u64;
                }
                if left > 0 {
                    // file shrank under us — pad like the prototype does
                    out.write_all(&vec![0u8; left as usize])?;
                }
            }
        }
        let dpad = align4(size as usize) - size as usize;
        if dpad > 0 {
            out.write_all(&vec![0u8; dpad])?;
        }
        *written += size as usize + dpad;
        ino += 1;
    }
    let hdr = newc_header(TRAILER, 0, 0, 1, mtime);
    out.write_all(&hdr)?;
    out.write_all(TRAILER.as_bytes())?;
    out.write_all(&[0])?;
    let pad = align4(hdr.len() + TRAILER.len() + 1) - (hdr.len() + TRAILER.len() + 1);
    out.write_all(&vec![0u8; pad])?;
    *written += hdr.len() + TRAILER.len() + 1 + pad;
    Ok(())
}

/// Read up to `n` bytes, growing the Vec as data actually arrives — a lying
/// header can't force a huge up-front allocation. A short Vec means EOF.
fn read_exact_or_truncated<R: Read>(r: &mut R, n: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    let mut left = n;
    let mut buf = [0u8; 8192];
    while left > 0 {
        let want = left.min(buf.len());
        match read_up_to(r, &mut buf[..want])? {
            0 => break,
            got => {
                v.extend_from_slice(&buf[..got]);
                left -= got;
            }
        }
    }
    Ok(v)
}

/// Fill `buf` unless EOF hits first; returns the byte count.
fn read_up_to<R: Read>(r: &mut R, mut buf: &mut [u8]) -> Result<usize> {
    let mut n = 0usize;
    while !buf.is_empty() {
        match r.read(buf) {
            Ok(0) => break,
            Ok(m) => {
                n += m;
                buf = &mut buf[m..];
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}

fn skip<R: Read>(r: &mut R, mut n: usize) -> Result<()> {
    let mut buf = [0u8; 8192];
    while n > 0 {
        let want = n.min(buf.len());
        match r.read(&mut buf[..want]) {
            Ok(0) => return Err(bad("cpio: truncated padding")),
            Ok(m) => n -= m,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn parse_hex_field(b: &[u8]) -> Result<u64> {
    let s = std::str::from_utf8(b).map_err(|_| bad("cpio: non-ascii header field"))?;
    u64::from_str_radix(s.trim(), 16).map_err(|_| bad("cpio: bad hex header field"))
}

fn parse_oct_field(b: &[u8]) -> Result<u64> {
    let s = std::str::from_utf8(b).map_err(|_| bad("cpio: non-ascii header field"))?;
    u64::from_str_radix(s.trim(), 8).map_err(|_| bad("cpio: bad octal header field"))
}

fn read_name<R: Read>(r: &mut R, namesize: usize) -> Result<String> {
    let nb = read_exact_or_truncated(r, namesize)?;
    if nb.len() < namesize {
        return Err(bad("cpio: truncated name"));
    }
    // Python strips *trailing* NULs only (rstrip(b"\0")), not the first one.
    let end = nb.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
    String::from_utf8(nb[..end].to_vec()).map_err(|_| bad("cpio: name is not utf-8"))
}

/// Read a whole archive (newc or odc), enforcing limits.
/// Errors on bad magic, truncation, or exceeding limits.
pub fn read_all<R: Read>(r: &mut R, max_members: usize, max_bytes: u64) -> Result<Vec<Member>> {
    let mut members = Vec::new();
    let mut total_bytes: u64 = 0;
    loop {
        let magic = read_exact_or_truncated(r, 6)?;
        if magic.len() < 6 {
            // end of stream between records = clean stop (block padding)
            if magic.iter().all(|&b| b == 0) || magic.is_empty() {
                return Ok(members);
            }
            return Err(bad("cpio: truncated magic"));
        }
        if &magic[..6] == NEWC_MAGIC || &magic[..6] == NEWC_CRC_MAGIC {
            let hdr = read_exact_or_truncated(r, 104)?;
            if hdr.len() < 104 {
                return Err(bad("cpio: truncated newc header"));
            }
            let f: Vec<u64> = (0..13)
                .map(|i| parse_hex_field(&hdr[i * 8..i * 8 + 8]))
                .collect::<Result<_>>()?;
            let mode = f[1] as u32;
            let mtime = f[5];
            let size = f[6];
            let namesize = f[11] as usize;
            let name = read_name(r, namesize)?;
            skip(r, align4(110 + namesize) - (110 + namesize))?;
            if name == TRAILER {
                return Ok(members);
            }
            if members.len() >= max_members {
                return Err(bad("cpio: member limit exceeded"));
            }
            total_bytes += size;
            if total_bytes > max_bytes {
                return Err(bad("cpio: archive exceeds byte limit"));
            }
            let data = read_exact_or_truncated(r, size as usize)?;
            if data.len() < size as usize {
                return Err(bad("cpio: truncated member data"));
            }
            skip(r, align4(size as usize) - size as usize)?;
            members.push(Member {
                name,
                mode,
                mtime,
                data,
            });
        } else if &magic[..6] == ODC_MAGIC {
            let hdr = read_exact_or_truncated(r, 70)?;
            if hdr.len() < 70 {
                return Err(bad("cpio: truncated odc header"));
            }
            let mode = parse_oct_field(&hdr[12..18])? as u32;
            let mtime = parse_oct_field(&hdr[42..53])?;
            let namesize = parse_oct_field(&hdr[53..59])? as usize;
            let size = parse_oct_field(&hdr[59..70])?;
            let name = read_name(r, namesize)?;
            if name == TRAILER {
                return Ok(members);
            }
            if members.len() >= max_members {
                return Err(bad("cpio: member limit exceeded"));
            }
            total_bytes += size;
            if total_bytes > max_bytes {
                return Err(bad("cpio: archive exceeds byte limit"));
            }
            let data = read_exact_or_truncated(r, size as usize)?;
            if data.len() < size as usize {
                return Err(bad("cpio: truncated member data"));
            }
            members.push(Member {
                name,
                mode,
                mtime,
                data,
            });
        } else {
            return Err(bad(format!(
                "not a cpio archive (magic {:02x?})",
                &magic[..6]
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip() {
        let entries = vec![
            CpioEntry::Dir {
                name: "./dir".into(),
            },
            CpioEntry::Bytes {
                name: "./dir/a.txt".into(),
                data: b"hello".to_vec(),
            },
            CpioEntry::Bytes {
                name: "./b.bin".into(),
                data: vec![0xAB; 700],
            },
        ];
        let mut buf = Vec::new();
        write_newc(&mut buf, &entries).unwrap();
        assert_eq!(buf.len() % 512, 0);
        let members = read_all(&mut Cursor::new(&buf), 64, 1 << 20).unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].name, "./dir");
        assert!(members[0].is_dir());
        assert_eq!(members[1].data, b"hello");
        assert_eq!(members[2].data, vec![0xAB; 700]);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut c = Cursor::new(b"notcpio!12345678901234567890".to_vec());
        assert!(read_all(&mut c, 8, 1024).is_err());
    }

    #[test]
    fn rejects_truncated() {
        let entries = vec![CpioEntry::Bytes {
            name: "./a".into(),
            data: vec![1, 2, 3],
        }];
        let mut buf = Vec::new();
        write_newc(&mut buf, &entries).unwrap();
        // cut inside the first member record (magic+header+name = 116 bytes)
        // — slicing into the 512-byte block padding is a valid archive end
        let cut = buf[..80].to_vec();
        let mut c = Cursor::new(cut);
        assert!(read_all(&mut c, 8, 1024).is_err());
    }

    #[test]
    fn padding_cut_is_clean_eof() {
        // an archive truncated inside its trailing 512-byte block padding is
        // not an error — the trailer was already complete
        let entries = vec![CpioEntry::Bytes {
            name: "./a".into(),
            data: vec![1, 2, 3],
        }];
        let mut buf = Vec::new();
        write_newc(&mut buf, &entries).unwrap();
        let cut = buf[..buf.len() - 16].to_vec();
        let mut c = Cursor::new(cut);
        let members = read_all(&mut c, 8, 1024).unwrap();
        assert_eq!(members.len(), 1);
    }

    #[test]
    fn byte_limit_enforced() {
        let entries = vec![CpioEntry::Bytes {
            name: "./a".into(),
            data: vec![0; 4096],
        }];
        let mut buf = Vec::new();
        write_newc(&mut buf, &entries).unwrap();
        let mut c = Cursor::new(buf);
        assert!(read_all(&mut c, 8, 1024).is_err());
    }

    /// Hand-built odc member: "070707" + fixed-width octal fields, no padding.
    fn odc_entry(buf: &mut Vec<u8>, name: &[u8], mode: u32, data: &[u8]) {
        buf.extend_from_slice(ODC_MAGIC);
        // dev ino mode uid gid nlink rdev (6) | mtime(11) | namesize(6) | size(11)
        let hdr = format!(
            "{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            0u32,
            1u32,
            mode,
            0u32,
            0u32,
            1u32,
            0u32,
            0u64,
            (name.len() + 1) as u32,
            data.len() as u64,
        );
        assert_eq!(hdr.len(), 70);
        buf.extend_from_slice(hdr.as_bytes());
        buf.extend_from_slice(name);
        buf.push(0);
        buf.extend_from_slice(data);
    }

    #[test]
    fn reads_odc() {
        let mut blob = Vec::new();
        odc_entry(&mut blob, b"./a.txt", 0o100644, b"hello");
        odc_entry(&mut blob, b"./sub", 0o040755, b"");
        odc_entry(&mut blob, TRAILER.as_bytes(), 0, b"");
        let members = read_all(&mut Cursor::new(&blob), 16, 1 << 20).unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].name, "./a.txt");
        assert_eq!(members[0].data, b"hello");
        assert!(members[0].is_file());
        assert_eq!(members[1].name, "./sub");
        assert!(members[1].is_dir());
    }

    #[test]
    fn odc_truncated() {
        let mut blob = Vec::new();
        odc_entry(&mut blob, b"./a.txt", 0o100644, b"hello");
        odc_entry(&mut blob, TRAILER.as_bytes(), 0, b"");
        for cut in [3usize, 10, 78, blob.len() - 3] {
            assert!(
                read_all(&mut Cursor::new(&blob[..cut]), 16, 1 << 20).is_err(),
                "cut={cut}"
            );
        }
    }

    #[test]
    fn member_limit_enforced() {
        let entries = vec![
            CpioEntry::Bytes {
                name: "./a".into(),
                data: b"x".to_vec(),
            },
            CpioEntry::Bytes {
                name: "./b".into(),
                data: b"y".to_vec(),
            },
        ];
        let mut buf = Vec::new();
        write_newc(&mut buf, &entries).unwrap();
        let mut c = Cursor::new(&buf);
        assert!(read_all(&mut c, 1, 1 << 20).is_err());
        let mut c = Cursor::new(&buf);
        assert_eq!(read_all(&mut c, 2, 1 << 20).unwrap().len(), 2);
    }
}
