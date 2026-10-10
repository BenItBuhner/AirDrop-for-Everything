//! DVZip framing: a gzip/deflate stream wrapped in Apple's simple frame
//! header, as used for the /Upload body. Port of prototype dvzip.rs.

use crate::{Error, Result};
use flate2::{Compression, Decompress, FlushDecompress, Status};
use std::io::{BufRead, BufReader, Read};

/// Wire block size: the body is a sequence of 64 KiB frames.
const BLOCK: usize = 1 << 16;
/// Header high bit marks a *stored* (uncompressed) block.
const STORED: u32 = 0x8000_0000;
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

fn proto(msg: impl Into<String>) -> Error {
    Error::Protocol(msg.into())
}

/// zlib-compress one block (level 6, like `zlib.compress(raw, 6)`).
fn zlib_block(raw: &[u8]) -> Option<Vec<u8>> {
    let mut enc = flate2::read::ZlibEncoder::new(raw, Compression::new(6));
    let mut out = Vec::new();
    enc.read_to_end(&mut out).ok().map(|_| out)
}

/// Encode `plain` into a DVZip-framed blob.
pub fn encode(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for raw in plain.chunks(BLOCK) {
        match zlib_block(raw) {
            // Emit the zlib stream only when it actually shrinks the block.
            Some(z) if z.len() < raw.len() => {
                out.extend_from_slice(&(z.len() as u32).to_be_bytes());
                out.extend_from_slice(&z);
            }
            _ => {
                out.extend_from_slice(&(STORED | raw.len() as u32).to_be_bytes());
                out.extend_from_slice(raw);
            }
        }
    }
    out
}

/// Read at most `buf.len()` bytes, looping over partial reads.
/// A short count means EOF.
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
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(n)
}

/// Append `data` to `out` unless it would breach the decompression limit.
fn emit(out: &mut Vec<u8>, data: &[u8], total: &mut u64, limit: u64) -> Result<()> {
    if !data.is_empty() {
        if data.len() as u64 > limit.saturating_sub(*total) {
            return Err(proto("decompressed body exceeds byte limit"));
        }
        out.extend_from_slice(data);
        *total += data.len() as u64;
    }
    Ok(())
}

/// `io::Error`s raised inside the flate2 wrappers mean a corrupt or truncated
/// payload; pass real I/O failures through unchanged.
fn codec_err(e: std::io::Error) -> Error {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::InvalidData
        | std::io::ErrorKind::InvalidInput => proto(format!("corrupt or truncated gzip body: {e}")),
        _ => Error::Io(e),
    }
}

/// Whole-body gzip decode (what OpenDrop-style peers send).
fn decode_gzip<R: Read>(src: &mut R, out: &mut Vec<u8>, limit: u64) -> Result<u64> {
    let mut total = 0u64;
    // BufRead, not bare Read: unused trailing bytes stay buffered so we can
    // detect and reject them (prototype: `d.unused_data` -> ValueError).
    let mut br = BufReader::new(src);
    {
        let mut gz = flate2::bufread::GzDecoder::new(&mut br);
        let mut buf = [0u8; 65536];
        loop {
            let n = gz.read(&mut buf).map_err(codec_err)?;
            if n == 0 {
                break;
            }
            emit(out, &buf[..n], &mut total, limit)?;
        }
    } // `gz` (which borrows `br`) ends here
      // At EOF the decoder only ever consumed up to the end of the gzip member,
      // so any bytes still buffered in `br` are forbidden trailing data.
    if !br.fill_buf().map_err(Error::Io)?.is_empty() {
        return Err(proto("gzip body has trailing data"));
    }
    Ok(total)
}

/// Decode a DVZip stream into `out`, returning bytes written.
/// `limit` is a hard cap on decoded size (decompression-bomb guard).
pub fn decode<R: Read>(wire: R, out: &mut Vec<u8>, limit: u64) -> Result<u64> {
    let mut wire = wire;
    // Peek for the gzip magic without consuming it: chain the peeked bytes
    // back in front of the reader so both paths see the full stream.
    let mut magic = [0u8; 2];
    let got = read_up_to(&mut wire, &mut magic)?;
    let mut src = (&magic[..got]).chain(wire);
    if got == 2 && magic == GZIP_MAGIC {
        return decode_gzip(&mut src, out, limit);
    }

    let mut total = 0u64;
    let mut inbuf = [0u8; 65536];
    let mut obuf = [0u8; 65536];
    loop {
        let mut hdr = [0u8; 4];
        let n = read_up_to(&mut src, &mut hdr)?;
        if n == 0 {
            return Ok(total);
        }
        if n != 4 {
            return Err(proto(format!("truncated DVZip block header: {n} bytes")));
        }
        let value = u32::from_be_bytes(hdr);
        let size = (value & !STORED) as u64;
        if value & STORED != 0 {
            let mut left = size;
            while left > 0 {
                let want = left.min(inbuf.len() as u64) as usize;
                let n = read_up_to(&mut src, &mut inbuf[..want])?;
                if n == 0 {
                    return Err(proto(format!(
                        "truncated stored block: {left} bytes missing"
                    )));
                }
                emit(out, &inbuf[..n], &mut total, limit)?;
                left -= n as u64;
            }
        } else {
            // One zlib stream per block (each encode() block is its own
            // `zlib.compress`). StreamEnd must land exactly on the declared
            // size — anything else is trailing data or truncation.
            let mut d = Decompress::new(true);
            let mut left = size;
            let mut ended = false;
            'block: while left > 0 {
                let want = left.min(inbuf.len() as u64) as usize;
                let n = read_up_to(&mut src, &mut inbuf[..want])?;
                if n == 0 {
                    return Err(proto(format!(
                        "truncated compressed block: {left} bytes missing"
                    )));
                }
                left -= n as u64;
                let mut pos = 0;
                while pos < n {
                    let in0 = d.total_in();
                    let out0 = d.total_out();
                    let st = d
                        .decompress(&inbuf[pos..n], &mut obuf, FlushDecompress::None)
                        .map_err(|e| proto(format!("corrupt compressed block: {e}")))?;
                    let used = (d.total_in() - in0) as usize;
                    let wrote = (d.total_out() - out0) as usize;
                    pos += used;
                    emit(out, &obuf[..wrote], &mut total, limit)?;
                    if st == Status::StreamEnd {
                        if pos < n || left > 0 {
                            return Err(proto("compressed block has trailing data"));
                        }
                        ended = true;
                        break 'block;
                    }
                    if used == 0 && wrote == 0 {
                        // No forward progress: corrupt stream.
                        return Err(proto("corrupt compressed block"));
                    }
                }
            }
            if !ended {
                return Err(proto("truncated compressed block"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8]) -> Vec<u8> {
        let wire = encode(data);
        let mut out = Vec::new();
        let n = decode(&wire[..], &mut out, u64::MAX).unwrap();
        assert_eq!(n as usize, data.len());
        out
    }

    /// Deterministic pseudo-random bytes — zlib can't shrink them, so
    /// encode() takes the STORED path.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut x = 0x9E3779B97F4A7C15u64;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect()
    }

    #[test]
    fn round_trip_small() {
        let data = b"hello airdrop, this is dvzip";
        assert_eq!(roundtrip(data), data);
    }

    #[test]
    fn round_trip_multi_block() {
        // > 64 KiB and compressible: exercises several zlib frames.
        let data: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
        let wire = encode(&data);
        assert!(wire.len() > 8); // several frames
        assert_eq!(roundtrip(&data), data);
    }

    #[test]
    fn stored_block_when_incompressible() {
        let data = incompressible(70_000);
        let wire = encode(&data);
        // First block must be stored: high bit set, size = BLOCK.
        let h = u32::from_be_bytes(wire[..4].try_into().unwrap());
        assert_eq!(h, STORED | (BLOCK as u32));
        assert_eq!(roundtrip(&data), data);
    }

    #[test]
    fn manually_built_stored_block() {
        let mut wire = (STORED | 3).to_be_bytes().to_vec();
        wire.extend_from_slice(b"abc");
        let mut out = Vec::new();
        let n = decode(&wire[..], &mut out, u64::MAX).unwrap();
        assert_eq!(n, 3);
        assert_eq!(out, b"abc");
    }

    #[test]
    fn decodes_plain_gzip_stream() {
        let data = b"opendrop sends a plain gzip body";
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), Compression::new(6));
        std::io::Write::write_all(&mut enc, data).unwrap();
        let wire = enc.finish().unwrap();
        assert_eq!(&wire[..2], &GZIP_MAGIC);
        let mut out = Vec::new();
        let n = decode(&wire[..], &mut out, u64::MAX).unwrap();
        assert_eq!(n as usize, data.len());
        assert_eq!(out, data);
    }

    #[test]
    fn rejects_gzip_trailing_data() {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), Compression::new(6));
        std::io::Write::write_all(&mut enc, b"x").unwrap();
        let mut wire = enc.finish().unwrap();
        wire.extend_from_slice(b"junk");
        let mut out = Vec::new();
        assert!(decode(&wire[..], &mut out, u64::MAX).is_err());
    }

    #[test]
    fn rejects_truncated() {
        let wire = encode(b"some compressible data, some compressible data");
        let mut out = Vec::new();
        // 1–3 bytes: partial block header.
        for cut in [1usize, 2, 3] {
            assert!(
                decode(&wire[..cut], &mut out, u64::MAX).is_err(),
                "cut={cut}"
            );
            out.clear();
        }
        // Mid-block: header declares more than arrives.
        assert!(decode(&wire[..wire.len() - 1], &mut out, u64::MAX).is_err());
        out.clear();
        // Declared size with no payload at all.
        assert!(decode(&4u32.to_be_bytes()[..], &mut out, u64::MAX).is_err());
        out.clear();
        // Stored header with missing payload.
        let mut w = (STORED | 10u32).to_be_bytes().to_vec();
        w.extend_from_slice(b"abc");
        assert!(decode(&w[..], &mut out, u64::MAX).is_err());
    }

    #[test]
    fn rejects_trailing_bytes_in_compressed_block() {
        // A valid zlib stream plus one extra byte inside the declared size.
        let mut z = zlib_block(b"abc").unwrap();
        z.push(0);
        let mut wire = (z.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&z);
        let mut out = Vec::new();
        assert!(decode(&wire[..], &mut out, u64::MAX).is_err());
    }

    #[test]
    fn enforces_decode_limit() {
        let wire = encode(&[b'x'; 1000]);
        let mut out = Vec::new();
        assert!(decode(&wire[..], &mut out, 500).is_err());
        let mut out = Vec::new();
        assert_eq!(decode(&wire[..], &mut out, 1000).unwrap(), 1000);
    }

    #[test]
    fn empty_input_decodes_to_empty() {
        let mut out = Vec::new();
        assert_eq!(decode(&[][..], &mut out, u64::MAX).unwrap(), 0);
        assert!(out.is_empty());
    }
}
