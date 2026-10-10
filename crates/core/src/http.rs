//! Minimal blocking HTTP/1.1 over rustls — just what AirDrop needs:
//! POST with Content-Length or chunked bodies, keep-alive, headers.
//!
//! Ported from the relevant parts of prototype server.py / client.py:
//! strict framing validation, chunked decoding with line/trailer caps,
//! `Expect: 100-continue`, keep-alive across requests.
//!
//! Error convention: request-read failures that should produce a specific
//! HTTP status embed it as a `"<status>: <message>"` prefix inside
//! [`Error::Protocol`]; [`err_status`] recovers it. Socket timeouts surface
//! as `io` errors (TimedOut/WouldBlock) and map to 408.

use crate::{Error, Result};
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

pub type TlsServerStream = StreamOwned<ServerConnection, TcpStream>;
pub type TlsClientStream = StreamOwned<ClientConnection, TcpStream>;

const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 128;
const MAX_TRAILER_BYTES: usize = 8 * 1024;
const IO_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>, // lowercased names
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body,
        }
    }
    pub fn status(code: u16) -> Self {
        Self {
            status: code,
            headers: vec![],
            body: Vec::new(),
        }
    }
}

/// The request head: everything up to (and excluding) the body.
#[derive(Debug)]
pub(crate) struct Head {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub expect_continue: bool,
}

/// Framing decision for a request body (prototype `body_plan`).
#[derive(Debug, Clone, Copy)]
pub(crate) enum BodyPlan {
    Chunked,
    Length(u64),
}

fn proto_err(status: u16, msg: impl Into<String>) -> Error {
    Error::Protocol(format!("{status}: {}", msg.into()))
}

/// The HTTP status a failure should produce on the wire: the embedded code
/// for protocol errors, 408 for socket timeouts, 400 otherwise.
pub(crate) fn err_status(e: &Error) -> u16 {
    match e {
        Error::Protocol(m) => m
            .split(':')
            .next()
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or(400),
        Error::Io(ioe) if is_timeout(ioe) => 408,
        _ => 400,
    }
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

/// Read one `\n`-terminated line (bytes pushed to `out`, terminator kept).
/// Errors with InvalidData when the line exceeds `limit`.
fn read_line<S: Read>(s: &mut S, limit: usize, out: &mut Vec<u8>) -> std::io::Result<usize> {
    let mut n = 0usize;
    let mut byte = [0u8; 1];
    loop {
        match s.read(&mut byte) {
            Ok(0) => return Ok(n),
            Ok(_) => {
                out.push(byte[0]);
                n += 1;
                if byte[0] == b'\n' {
                    return Ok(n);
                }
                if n > limit {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "overlong line",
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Read a header block (lines until a blank line) -> (lowercased) pairs.
/// Handles obs-fold continuation lines and joins repeats with ", ".
fn read_headers<S: Read>(s: &mut S) -> Result<Vec<(String, String)>> {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut total = 0usize;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = read_line(s, MAX_HEADER_BYTES, &mut line).map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                proto_err(400, "overlong header line")
            } else {
                Error::Io(e)
            }
        })?;
        total += n;
        if total > MAX_HEADER_BYTES {
            return Err(proto_err(400, "headers too large"));
        }
        if n == 0 {
            return Err(proto_err(400, "connection closed in headers"));
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\r', '\n']);
        if text.is_empty() {
            return Ok(headers);
        }
        if text.starts_with(' ') || text.starts_with('\t') {
            // obs-fold: continuation of the previous header's value.
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(text.trim());
            }
            continue;
        }
        let Some(colon) = text.find(':') else {
            return Err(proto_err(400, format!("malformed header line: {text:.60}")));
        };
        let name = text[..colon].trim().to_lowercase();
        let value = text[colon + 1..].trim().to_string();
        if name.is_empty() {
            return Err(proto_err(400, "empty header name"));
        }
        match headers.iter_mut().find(|(k, _)| *k == name) {
            Some(existing) => {
                existing.1.push_str(", ");
                existing.1.push_str(&value);
            }
            None => headers.push((name, value)),
        }
    }
}

/// Read the request line + headers. Returns Ok(None) on clean close before
/// any bytes (keep-alive end), Err on malformed input.
pub(crate) fn read_head<S: Read + Write>(s: &mut S) -> Result<Option<Head>> {
    let mut line = Vec::new();
    let n = match read_line(s, MAX_REQUEST_LINE_BYTES, &mut line) {
        Ok(n) => n,
        Err(e) => {
            // Unclean shutdown (TCP reset/EOF without close_notify) on an
            // idle keep-alive connection: treat like a clean close.
            if line.is_empty()
                && matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                )
            {
                return Ok(None);
            }
            return Err(if e.kind() == std::io::ErrorKind::InvalidData {
                proto_err(400, "overlong request line")
            } else {
                Error::Io(e)
            });
        }
    };
    if n == 0 {
        return Ok(None);
    }
    if !line.ends_with(b"\n") {
        return Err(proto_err(400, "truncated request line"));
    }
    let text = String::from_utf8_lossy(&line);
    let mut parts = text.split_whitespace();
    let (method, path, _version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(p), Some(v)) if v.starts_with("HTTP/") => (m, p, v),
        _ => {
            return Err(proto_err(
                400,
                format!("malformed request line: {text:.60}"),
            ))
        }
    };
    if method.bytes().any(|b| !(b.is_ascii_graphic() && b != b'/')) {
        return Err(proto_err(400, "malformed method"));
    }
    let header_pairs = read_headers(s)?;
    let headers: HashMap<String, String> = header_pairs.into_iter().collect();
    let expect_continue = headers
        .get("expect")
        .map(|v| v.eq_ignore_ascii_case("100-continue"))
        .unwrap_or(false);
    Ok(Some(Head {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        expect_continue,
    }))
}

/// Validate body framing before any body is read (prototype `body_plan`).
/// `limit` is the maximum body size; exceeding Content-Length -> 413.
pub(crate) fn body_plan(headers: &HashMap<String, String>, limit: u64) -> Result<BodyPlan> {
    if let Some(transfer) = headers.get("transfer-encoding") {
        let encodings: Vec<String> = transfer
            .split(',')
            .map(|p| p.trim().to_lowercase())
            .collect();
        if encodings != ["chunked"] {
            return Err(proto_err(
                400,
                format!("unsupported Transfer-Encoding: {transfer}"),
            ));
        }
        return Ok(BodyPlan::Chunked);
    }
    match headers.get("content-length") {
        None => Err(proto_err(
            400,
            "request body needs Content-Length or chunked encoding",
        )),
        Some(value) => {
            let length: u64 = value
                .trim()
                .parse()
                .map_err(|_| proto_err(400, format!("invalid Content-Length: {value}")))?;
            if length > limit {
                return Err(proto_err(
                    413,
                    format!("request body exceeds {limit}-byte limit"),
                ));
            }
            Ok(BodyPlan::Length(length))
        }
    }
}

/// Emit an interim 100 Continue.
pub(crate) fn write_continue<S: Write>(s: &mut S) -> Result<()> {
    s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    s.flush()?;
    Ok(())
}

fn copy_exact<S: Read, W: Write>(s: &mut S, out: &mut W, mut left: u64) -> Result<u64> {
    let mut buf = vec![0u8; IO_CHUNK_BYTES.min(left.max(1) as usize)];
    let mut done = 0u64;
    while left > 0 {
        let want = left.min(IO_CHUNK_BYTES as u64) as usize;
        let n = s.read(&mut buf[..want])?;
        if n == 0 {
            return Err(proto_err(400, "truncated request body"));
        }
        out.write_all(&buf[..n])?;
        left -= n as u64;
        done += n as u64;
    }
    Ok(done)
}

fn read_chunked<S: Read, W: Write>(s: &mut S, out: &mut W, limit: u64) -> Result<u64> {
    let mut total = 0u64;
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = read_line(s, MAX_CHUNK_LINE_BYTES, &mut line).map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                proto_err(400, "invalid or overlong chunk-size line")
            } else {
                Error::Io(e)
            }
        })?;
        if n == 0 || !line.ends_with(b"\n") {
            return Err(proto_err(400, "invalid or overlong chunk-size line"));
        }
        let token = line.split(|b| *b == b';').next().unwrap_or(&[]);
        let token = std::str::from_utf8(token)
            .map_err(|_| proto_err(400, "invalid chunk size"))?
            .trim();
        let size = u64::from_str_radix(token, 16)
            .map_err(|_| proto_err(400, format!("invalid chunk size: {token:.40}")))?;
        if size == 0 {
            // Trailer section: lines until a blank one, bounded.
            let mut trailers = 0usize;
            loop {
                line.clear();
                let n = read_line(s, MAX_CHUNK_LINE_BYTES, &mut line).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::InvalidData {
                        proto_err(400, "invalid or overlong chunk trailers")
                    } else {
                        Error::Io(e)
                    }
                })?;
                trailers += n;
                if n == 0 || !line.ends_with(b"\n") || trailers > MAX_TRAILER_BYTES {
                    return Err(proto_err(400, "invalid or overlong chunk trailers"));
                }
                if line == b"\r\n" || line == b"\n" {
                    return Ok(total);
                }
            }
        }
        if size > limit.saturating_sub(total) {
            return Err(proto_err(
                413,
                format!("request body exceeds {limit}-byte limit"),
            ));
        }
        total += copy_exact(s, out, size)?;
        let mut ending = [0u8; 2];
        s.read_exact(&mut ending).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => proto_err(400, "chunk data missing CRLF"),
            _ => Error::Io(e),
        })?;
        if ending != *b"\r\n" {
            return Err(proto_err(400, "chunk data missing CRLF"));
        }
    }
}

/// Stream one framed body into `out` under `limit`; returns bytes written.
pub(crate) fn read_body_into<S: Read, W: Write>(
    s: &mut S,
    plan: &BodyPlan,
    out: &mut W,
    limit: u64,
) -> Result<u64> {
    match plan {
        &BodyPlan::Length(n) => copy_exact(s, out, n),
        BodyPlan::Chunked => read_chunked(s, out, limit),
    }
}

/// Write a response on any stream (factored out for tests + reuse).
pub(crate) fn write_response_inner<S: Read + Write>(s: &mut S, r: &Response) -> Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", r.status, reason(r.status));
    let mut has_content_length = false;
    for (k, v) in &r.headers {
        if k.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    if !has_content_length {
        head.push_str(&format!("Content-Length: {}\r\n", r.body.len()));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes())?;
    s.write_all(&r.body)?;
    s.flush()?;
    Ok(())
}

/// Read one request (handles Content-Length and Transfer-Encoding: chunked,
/// keeps-alive across calls). Returns Ok(None) on clean close.
/// `max_body` caps the buffered body.
pub fn read_request(stream: &mut TlsServerStream, max_body: u64) -> Result<Option<Request>> {
    let head = match read_head(stream)? {
        Some(h) => h,
        None => return Ok(None),
    };
    if head.expect_continue {
        write_continue(stream)?;
    }
    // Only POST-style methods carry bodies; GET/HEAD have none.
    let body = if matches!(head.method.as_str(), "POST" | "PUT" | "PATCH") {
        let plan = body_plan(&head.headers, max_body)?;
        let mut body = Vec::new();
        read_body_into(stream, &plan, &mut body, max_body)?;
        body
    } else {
        Vec::new()
    };
    Ok(Some(Request {
        method: head.method,
        path: head.path,
        headers: head.headers,
        body,
    }))
}

/// Write a response.
pub fn write_response(stream: &mut TlsServerStream, r: &Response) -> Result<()> {
    write_response_inner(stream, r)
}

/// Read a response status line + headers + framed body (client side).
pub(crate) fn read_response_inner<S: Read>(s: &mut S) -> Result<Response> {
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = read_line(s, MAX_REQUEST_LINE_BYTES, &mut line).map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                proto_err(400, "overlong status line")
            } else {
                Error::Io(e)
            }
        })?;
        if n == 0 {
            return Err(proto_err(400, "connection closed before response"));
        }
        if !line.ends_with(b"\n") {
            return Err(proto_err(400, "truncated status line"));
        }
        let text = String::from_utf8_lossy(&line);
        let mut parts = text.splitn(3, ' ');
        let status: u16 = parts
            .nth(1)
            .and_then(|c| c.trim().parse().ok())
            .ok_or_else(|| proto_err(400, format!("malformed status line: {text:.60}")))?;
        let headers = read_headers(s)?;
        if (100..200).contains(&status) {
            continue; // interim response (e.g. 100 Continue): read the real one
        }
        let mut body = Vec::new();
        match body_plan(&headers.iter().cloned().collect(), u64::MAX) {
            Ok(plan) => {
                read_body_into(s, &plan, &mut body, u64::MAX)?;
            }
            Err(_) => {
                // No framing headers: body runs to connection close.
                let _ = s.read_to_end(&mut body);
            }
        }
        return Ok(Response {
            status,
            headers,
            body,
        });
    }
}

/// The request head every client POST shares (sharingd's header set).
fn write_request_head<S: Read + Write>(
    stream: &mut S,
    host_header: &str,
    path: &str,
    content_type: &str,
    extra_headers: &[(String, String)],
) -> Result<()> {
    let mut head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Content-Type: {content_type}\r\n\
         Connection: keep-alive\r\n\
         Accept: */*\r\n\
         User-Agent: AirDrop/1.0\r\n\
         Accept-Language: en-us\r\n\
         Accept-Encoding: br, gzip, deflate\r\n"
    );
    for (k, v) in extra_headers {
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    stream.write_all(head.as_bytes())?;
    Ok(())
}

/// Client: POST `body` to `path` on an already-connected TLS stream.
pub fn post<S: Read + Write>(
    stream: &mut S,
    host_header: &str,
    path: &str,
    body: &[u8],
    content_type: &str,
    extra_headers: &[(String, String)],
) -> Result<Response> {
    write_request_head(stream, host_header, path, content_type, extra_headers)?;
    stream.write_all(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    read_response_inner(stream)
}

/// Client: POST `body` with Transfer-Encoding: chunked — the framing
/// sharingd (and therefore the receiver here) uses for /Upload.
pub(crate) fn post_chunked<S: Read + Write>(
    stream: &mut S,
    host_header: &str,
    path: &str,
    body: &[u8],
    content_type: &str,
    extra_headers: &[(String, String)],
) -> Result<Response> {
    write_request_head(stream, host_header, path, content_type, extra_headers)?;
    stream.write_all(b"Transfer-Encoding: chunked\r\n\r\n")?;
    for chunk in body.chunks(IO_CHUNK_BYTES) {
        stream.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())?;
        stream.write_all(chunk)?;
        stream.write_all(b"\r\n")?;
    }
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()?;
    read_response_inner(stream)
}

/// Reason phrase for statuses we emit.
pub fn reason(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;

    /// Chunked body decode: the framing parser works on any Read+Write, so a
    /// Cursor stands in for the TLS stream.
    #[test]
    fn chunked_body_roundtrip() {
        let wire = b"POST /Upload HTTP/1.1\r\n\
                     Transfer-Encoding: chunked\r\n\
                     \r\n\
                     4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let mut c = Cursor::new(wire.to_vec());
        let head = read_head(&mut c).unwrap().unwrap();
        assert_eq!(head.method, "POST");
        assert_eq!(head.path, "/Upload");
        let plan = body_plan(&head.headers, 1024).unwrap();
        assert!(matches!(plan, BodyPlan::Chunked));
        let mut body = Vec::new();
        let n = read_body_into(&mut c, &plan, &mut body, 1024).unwrap();
        assert_eq!(n, 9);
        assert_eq!(body, b"Wikipedia");
    }

    #[test]
    fn fixed_length_body() {
        let wire = b"POST /Discover HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let mut c = Cursor::new(wire.to_vec());
        let head = read_head(&mut c).unwrap().unwrap();
        let plan = body_plan(&head.headers, 1024).unwrap();
        assert!(matches!(plan, BodyPlan::Length(5)));
        let mut body = Vec::new();
        read_body_into(&mut c, &plan, &mut body, 1024).unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn content_length_over_limit_rejected() {
        let mut h = HashMap::new();
        h.insert("content-length".to_string(), "2048".to_string());
        let e = body_plan(&h, 1024).unwrap_err();
        assert_eq!(err_status(&e), 413);
    }

    #[test]
    fn bad_transfer_encoding_rejected() {
        let mut h = HashMap::new();
        h.insert("transfer-encoding".to_string(), "gzip".to_string());
        let e = body_plan(&h, 1024).unwrap_err();
        assert_eq!(err_status(&e), 400);
    }

    #[test]
    fn write_response_bytes() {
        let r = Response {
            status: 200,
            headers: vec![("X-Test".to_string(), "1".to_string())],
            body: b"hi".to_vec(),
        };
        let mut c = Cursor::new(Vec::new());
        write_response_inner(&mut c, &r).unwrap();
        assert_eq!(
            c.into_inner(),
            b"HTTP/1.1 200 OK\r\nX-Test: 1\r\nContent-Length: 2\r\n\r\nhi".to_vec()
        );
    }

    #[test]
    fn post_over_loopback() {
        // A real socket pair exercises post() -> read_response_inner end to end.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            // Read the request head, then the declared body.
            let head = read_head(&mut sock).unwrap().unwrap();
            assert_eq!(head.path, "/Discover");
            let plan = body_plan(&head.headers, 1 << 20).unwrap();
            let mut body = Vec::new();
            read_body_into(&mut sock, &plan, &mut body, 1 << 20).unwrap();
            assert_eq!(body, b"{}");
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\npong",
            )
            .unwrap();
            sock.flush().unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        let resp = post(
            &mut client,
            "localhost",
            "/Discover",
            b"{}",
            "application/octet-stream",
            &[],
        )
        .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn read_response_chunked() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                     3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let mut c = Cursor::new(wire.to_vec());
        let resp = read_response_inner(&mut c).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"abcde");
    }
}
