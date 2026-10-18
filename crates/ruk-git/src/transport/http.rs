//! Minimal HTTP/1.1 client for the git-lfs batch API only.
//!
//! `std::net::TcpStream` plus TLS via `rustls`+`webpki-roots` (pure Rust,
//! Mozilla roots; no platform glue). Scope is exactly what batch download
//! needs: POST a JSON body, GET a payload URL streaming into a writer,
//! `Content-Length` or chunked bodies, Basic/Bearer auth from the
//! environment. No cookies, no keep-alive (every request sends
//! `Connection: close` on a fresh connection), no git smart-http: the
//! smart protocol over HTTP stays a named gap in [`super::net`]
//! (`Endpoint::Http` keeps refusing for git verbs) and only LFS payload
//! fetch gets HTTP.
//!
//! Oracle anchors: the git-lfs batch API
//! (`https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md`:
//! `POST <endpoint>/objects/batch` with
//! `Content-Type: application/vnd.git-lfs+json`, per-object
//! `actions.download.href` plus `actions.download.header` echo, and
//! per-object `error` entries).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::GitError;

/// The media type the batch API speaks on both arms.
pub const LFS_JSON: &str = "application/vnd.git-lfs+json";

/// How long one connect, write, or read may take before the call fails.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on a buffered response body (batch documents are small JSON; the
/// payload GET streams instead and never lands here).
const MAX_BUFFERED_BYTES: u64 = 16 << 20;

/// Cap on response header bytes before the blank line.
const MAX_HEADER_BYTES: usize = 64 << 10;

/// Redirect hops one GET follows before refusing.
const MAX_REDIRECTS: u8 = 3;

/// One buffered HTTP response: status plus headers plus the full body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    /// Numeric status (200, 404, ...).
    pub status: u16,
    /// Response headers with lowercased names, in wire order.
    pub headers: Vec<(String, String)>,
    /// The full response body.
    pub body: Vec<u8>,
}

/// Whether `status` is a 2xx success.
#[must_use]
pub fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Fetches the first `name` response header (names are stored lowercase).
#[must_use]
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// The `host:port` authority of an `http(s)` URL for credential scoping:
/// the environment Bearer token authenticates the batch endpoint, and a
/// download `href` receives it only when it stays on the batch endpoint's
/// authority, so a token never leaks to a presigned-URL host.
///
/// # Errors
/// [`GitError::Invalid`] for a non-HTTP URL.
pub fn url_authority(url: &str) -> Result<String, GitError> {
    let parsed = parse_url(url)?;
    Ok(format!("{}:{}", parsed.host, parsed.port))
}

/// An `Authorization` header from the LFS auth environment, when set.
///
/// `GIT_LFS_AUTH_BEARER` wins and is sent verbatim as `Bearer <value>`;
/// otherwise `GIT_LFS_AUTH_BASIC` is sent as `Basic <base64>`, encoding
/// `user:pass` here and passing an already-encoded value through when it
/// has no colon. Git credential helpers stay out of scope: CI-style static
/// tokens are what this adapter needs, and anything fancier keeps working
/// through presigned `href` URLs that need no header at all.
#[must_use]
pub fn auth_header(vars: &HashMap<String, String>) -> Option<(String, String)> {
    if let Some(token) = vars.get("GIT_LFS_AUTH_BEARER").filter(|v| !v.is_empty()) {
        return Some(("authorization".to_owned(), format!("Bearer {token}")));
    }
    vars.get("GIT_LFS_AUTH_BASIC")
        .filter(|v| !v.is_empty())
        .map(|value| {
            let encoded = if value.contains(':') {
                base64_encode(value.as_bytes())
            } else {
                value.clone()
            };
            ("authorization".to_owned(), format!("Basic {encoded}"))
        })
}

/// Standard-alphabet base64 with padding, so Basic credentials need no new
/// dependency for one short header value.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut word: u32 = 0;
        for (index, byte) in chunk.iter().enumerate() {
            word |= u32::from(*byte) << (16 - 8 * index);
        }
        let pad = 3 - chunk.len();
        for index in 0..4 - pad {
            out.push(ALPHABET[((word >> (18 - 6 * index)) & 0x3F) as usize] as char);
        }
        for _ in 0..pad {
            out.push('=');
        }
    }
    out
}

/// A parsed `http(s)://` URL: this client speaks nothing else, and ports
/// default the way browsers do.
struct Url {
    secure: bool,
    host: String,
    port: u16,
    path: String,
}

/// Splits `http(s)://host[:port][/path?query]` without a URL crate: LFS
/// download `href`s are often presigned URLs whose query string must reach
/// the server byte-identical, so the path is never re-encoded.
///
/// # Errors
/// [`GitError::Invalid`] for a missing scheme, a non-HTTP scheme, or an
/// empty host.
fn parse_url(url: &str) -> Result<Url, GitError> {
    let invalid = |why: &str| GitError::Invalid {
        detail: format!("bad http url {url:?}: {why}"),
    };
    let (scheme, rest) = url.split_once("://").ok_or_else(|| invalid("no scheme"))?;
    let secure = match scheme.to_ascii_lowercase().as_str() {
        "http" => false,
        "https" => true,
        _ => return Err(invalid("scheme is not http(s)")),
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (rest[..index].to_owned(), rest[index..].to_owned()),
        None => (rest.to_owned(), "/".to_owned()),
    };
    if authority.is_empty() || authority.starts_with([':', '@']) {
        return Err(invalid("empty host"));
    }
    // The userinfo half never authenticates here (tokens travel in
    // headers); strip it so it cannot leak into Host or SNI.
    let hostport = match authority.rsplit('@').next() {
        Some(kept) => kept,
        // `rsplit` always yields one item; the empty host fails below.
        None => "",
    };
    let (host, port) = if let Some(bracketed) = hostport.strip_prefix('[') {
        let end = bracketed.find(']').ok_or_else(|| invalid("bad ipv6"))?;
        let port = match bracketed[end + 1..].strip_prefix(':') {
            Some(text) => text.parse::<u16>().map_err(|_| invalid("bad port"))?,
            None if end + 1 == bracketed.len() => 0,
            None => return Err(invalid("bad ipv6")),
        };
        (bracketed[..end].to_owned(), port)
    } else if let Some((host, port_text)) = hostport.rsplit_once(':') {
        if host.is_empty() {
            return Err(invalid("empty host"));
        }
        if port_text.is_empty() || !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid("bad port"));
        }
        let port = port_text.parse::<u16>().map_err(|_| invalid("bad port"))?;
        (host.to_owned(), port)
    } else {
        (hostport.to_owned(), 0)
    };
    if host.is_empty() {
        return Err(invalid("empty host"));
    }
    let port = if port == 0 {
        if secure { 443 } else { 80 }
    } else {
        port
    };
    Ok(Url {
        secure,
        host,
        port,
        path,
    })
}

/// One request stream: plaintext or a TLS session over the same socket.
enum Stream {
    Plain(TcpStream),
    Tls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

/// Mozilla roots once per process: `RootCertStore` is cheap to fill but
/// there is no reason to rebuild it per object download.
fn tls_config() -> Result<Arc<rustls::ClientConfig>, GitError> {
    use std::sync::LazyLock;
    static CONFIG: LazyLock<Result<Arc<rustls::ClientConfig>, String>> = LazyLock::new(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .map(|builder| Arc::new(builder.with_root_certificates(roots).with_no_client_auth()))
            .map_err(|err| format!("tls provider refused: {err}"))
    });
    CONFIG.clone().map_err(|detail| GitError::Io {
        detail: detail.clone(),
    })
}

/// Dials `parsed` with connect/read/write timeouts and runs the TLS
/// handshake up front on `https`, so a certificate failure reports before
/// any request bytes move.
///
/// # Errors
/// [`GitError::Invalid`] for an unusable server name, [`GitError::Io`]
/// when the peer cannot be reached or the handshake fails.
fn connect(parsed: &Url) -> Result<Stream, GitError> {
    let addr = format!("{}:{}", parsed.host, parsed.port);
    let socket = TcpStream::connect(addr.as_str()).map_err(|err| GitError::Io {
        detail: format!("cannot reach {addr}: {err}"),
    })?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .and(socket.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|err| GitError::Io {
            detail: format!("cannot arm timeouts on {addr}: {err}"),
        })?;
    if !parsed.secure {
        return Ok(Stream::Plain(socket));
    }
    let name = if let Ok(ip) = parsed.host.parse::<std::net::IpAddr>() {
        rustls::pki_types::ServerName::IpAddress(ip.into())
    } else {
        rustls::pki_types::ServerName::try_from(parsed.host.clone()).map_err(|_| {
            GitError::Invalid {
                detail: format!("bad tls server name {:?}", parsed.host),
            }
        })?
    };
    let connection =
        rustls::ClientConnection::new(tls_config()?, name).map_err(|err| GitError::Io {
            detail: format!("cannot start tls to {}: {err}", parsed.host),
        })?;
    let mut tls = rustls::StreamOwned::new(connection, socket);
    // The handshake runs lazily inside rustls; one flush forces it now so
    // certificate errors report as connection failures, not request ones.
    tls.flush().map_err(|err| GitError::Io {
        detail: format!("tls handshake with {} failed: {err}", parsed.host),
    })?;
    Ok(Stream::Tls(tls))
}

/// Writes one HTTP/1.1 request: method line, Host, caller headers,
/// `Connection: close`, then the optional body.
fn send_request(
    stream: &mut Stream,
    method: &str,
    parsed: &Url,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<(), GitError> {
    let what = format!("{method} {}", parsed.path);
    let mut head = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        parsed.path, parsed.host
    );
    for (name, value) in headers {
        if value.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
            return Err(GitError::Invalid {
                detail: format!("header {name:?} carries a line break"),
            });
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .map_err(|err| GitError::Io {
            detail: format!("cannot send {what}: {err}"),
        })?;
    if let Some(body) = body {
        stream.write_all(body).map_err(|err| GitError::Io {
            detail: format!("cannot send {what} body: {err}"),
        })?;
    }
    stream.flush().map_err(|err| GitError::Io {
        detail: format!("cannot flush {what}: {err}"),
    })
}

/// Reads one status line plus headers through `reader`, returning the
/// status and the lowercased header list.
///
/// # Errors
/// [`GitError::Invalid`] for a malformed status line, [`GitError::Limit`]
/// past [`MAX_HEADER_BYTES`].
fn read_head(reader: &mut BufReader<Stream>) -> Result<(u16, Vec<(String, String)>), GitError> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        reader
            .read_until(b'\n', &mut line)
            .map_err(|err| GitError::Io {
                detail: format!("cannot read response head: {err}"),
            })?;
        if line.is_empty() {
            return Err(GitError::Io {
                detail: "response ended mid-head".to_owned(),
            });
        }
        head.extend_from_slice(&line);
        if head.len() > MAX_HEADER_BYTES {
            return Err(GitError::Limit {
                detail: "response head exceeds 64 KiB".to_owned(),
            });
        }
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
    }
    let text = String::from_utf8(head).map_err(|_| GitError::Invalid {
        detail: "response head is not UTF-8".to_owned(),
    })?;
    let mut lines = text.lines();
    let status_line = lines.next().ok_or_else(|| GitError::Invalid {
        detail: "empty response".to_owned(),
    })?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| GitError::Invalid {
            detail: format!("bad status line {status_line:?}"),
        })?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| GitError::Invalid {
            detail: format!("bad header line {line:?}"),
        })?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok((status, headers))
}

/// Reads one `Content-Length` body, at most `limit` bytes into `sink`.
///
/// # Errors
/// [`GitError::Limit`] when the declared length exceeds `limit`,
/// [`GitError::Io`] on a short body.
fn read_sized(
    reader: &mut BufReader<Stream>,
    declared: u64,
    sink: &mut dyn Write,
    limit: Option<u64>,
) -> Result<(), GitError> {
    if let Some(limit) = limit
        && declared > limit
    {
        return Err(GitError::Limit {
            detail: format!("response body of {declared} bytes exceeds the {limit}-byte cap"),
        });
    }
    let mut rest = declared;
    let mut chunk = [0_u8; 65536];
    while rest > 0 {
        let want = usize::try_from(rest.min(chunk.len() as u64)).map_err(|_| GitError::Limit {
            detail: "response chunk exceeds addressable memory".to_owned(),
        })?;
        let got = reader
            .read(&mut chunk[..want])
            .map_err(|err| GitError::Io {
                detail: format!("cannot read response body: {err}"),
            })?;
        if got == 0 {
            return Err(GitError::Io {
                detail: format!("response body ended {rest} bytes early"),
            });
        }
        sink.write_all(&chunk[..got]).map_err(|err| GitError::Io {
            detail: format!("cannot sink response body: {err}"),
        })?;
        rest -= got as u64;
    }
    Ok(())
}

/// Reads one CRLF-terminated line, stripped of the terminator.
///
/// # Errors
/// [`GitError::Io`] on EOF or read failure.
fn read_line(reader: &mut BufReader<Stream>) -> Result<Vec<u8>, GitError> {
    let mut line = Vec::new();
    reader
        .read_until(b'\n', &mut line)
        .map_err(|err| GitError::Io {
            detail: format!("cannot read chunk line: {err}"),
        })?;
    if line.is_empty() {
        return Err(GitError::Io {
            detail: "chunked body ended mid-stream".to_owned(),
        });
    }
    while line
        .last()
        .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
    {
        line.pop();
    }
    Ok(line)
}

/// Reads one chunked body into `sink`: chunk-size lines name hex bytes
/// (extensions past `;` are ignored), a zero size ends the body, and
/// trailers are consumed and dropped.
///
/// # Errors
/// [`GitError::Invalid`] for a bad chunk size, [`GitError::Limit`] past
/// `limit` total bytes, [`GitError::Io`] on a short chunk.
fn read_chunked(
    reader: &mut BufReader<Stream>,
    sink: &mut dyn Write,
    limit: Option<u64>,
) -> Result<(), GitError> {
    let mut total: u64 = 0;
    loop {
        let line = read_line(reader)?;
        let size_text = line
            .iter()
            .take_while(|byte| **byte != b';')
            .copied()
            .collect::<Vec<u8>>();
        let size = u64::from_str_radix(
            std::str::from_utf8(&size_text).map_err(|_| GitError::Invalid {
                detail: "chunk size is not UTF-8".to_owned(),
            })?,
            16,
        )
        .map_err(|_| GitError::Invalid {
            detail: "bad chunk size".to_owned(),
        })?;
        if size == 0 {
            // Trailers end at the first blank line.
            loop {
                if read_line(reader)?.is_empty() {
                    return Ok(());
                }
            }
        }
        total = total.saturating_add(size);
        if let Some(limit) = limit
            && total > limit
        {
            return Err(GitError::Limit {
                detail: format!("chunked body exceeds the {limit}-byte cap"),
            });
        }
        read_sized(reader, size, sink, None)?;
        // Every chunk closes with its own CRLF.
        let crlf = read_line(reader)?;
        if !crlf.is_empty() {
            return Err(GitError::Invalid {
                detail: "chunk misses its trailing CRLF".to_owned(),
            });
        }
    }
}

/// Reads one response body per its framing into `sink`: chunked wins over
/// `Content-Length` (RFC 9112 §6.3), an absent length reads to EOF on the
/// closed connection, and `limit` caps buffered callers only.
///
/// # Errors
/// [`GitError::Invalid`] for a bad declared length, [`GitError::Limit`]
/// past `limit`, [`GitError::Io`] on a truncated body.
fn read_body(
    reader: &mut BufReader<Stream>,
    headers: &[(String, String)],
    sink: &mut dyn Write,
    limit: Option<u64>,
) -> Result<(), GitError> {
    if header(headers, "transfer-encoding")
        .is_some_and(|value| value.split(',').any(|token| token.trim() == "chunked"))
    {
        return read_chunked(reader, sink, limit);
    }
    if let Some(length) = header(headers, "content-length") {
        let declared: u64 = length.parse().map_err(|_| GitError::Invalid {
            detail: format!("bad Content-Length {length:?}"),
        })?;
        return read_sized(reader, declared, sink, limit);
    }
    let mut chunk = [0_u8; 65536];
    let mut total: u64 = 0;
    loop {
        let got = reader.read(&mut chunk).map_err(|err| GitError::Io {
            detail: format!("cannot read response body: {err}"),
        })?;
        if got == 0 {
            return Ok(());
        }
        total = total.saturating_add(got as u64);
        if let Some(limit) = limit
            && total > limit
        {
            return Err(GitError::Limit {
                detail: format!("response body exceeds the {limit}-byte cap"),
            });
        }
        sink.write_all(&chunk[..got]).map_err(|err| GitError::Io {
            detail: format!("cannot sink response body: {err}"),
        })?;
    }
}

/// Sends one request and returns the open response: status, headers, and
/// the reader positioned at the body. The caller picks the sink by
/// passing it to [`read_body`], so redirect hops and error pages can
/// discard while successes stream.
///
/// # Errors
/// Routing, framing, and transport failures as [`GitError`].
fn request_head(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<(BufReader<Stream>, u16, Vec<(String, String)>), GitError> {
    let parsed = parse_url(url)?;
    let mut stream = connect(&parsed)?;
    send_request(&mut stream, method, &parsed, headers, body)?;
    let mut reader = BufReader::new(stream);
    let (status, headers) = read_head(&mut reader)?;
    Ok((reader, status, headers))
}

/// POSTs `body` as JSON and buffers the reply, capped at
/// [`MAX_BUFFERED_BYTES`].
///
/// # Errors
/// Routing, framing, and transport failures as [`GitError`].
pub fn post_json(
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<HttpResponse, GitError> {
    let (mut reader, status, headers) = request_head(url, "POST", headers, Some(body))?;
    let mut reply = Vec::new();
    read_body(&mut reader, &headers, &mut reply, Some(MAX_BUFFERED_BYTES))?;
    Ok(HttpResponse {
        status,
        headers,
        body: reply,
    })
}

/// GETs `url` streaming the body into `sink` (no size cap: the caller
/// verifies what lands), following up to [`MAX_REDIRECTS`] hops. An
/// `authorization` header is dropped when a hop changes host, so a token
/// for the LFS server never leaks to a presigned-URL host. Error statuses
/// return without sinking anything; the caller reports the status.
///
/// Returns the final status and headers.
///
/// # Errors
/// Routing, framing, and transport failures as [`GitError`]; too many
/// hops are [`GitError::Invalid`].
pub fn get_to_writer(
    url: &str,
    headers: &[(&str, &str)],
    sink: &mut dyn Write,
) -> Result<(u16, Vec<(String, String)>), GitError> {
    let mut current = url.to_owned();
    let mut owned: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    for _ in 0..=MAX_REDIRECTS {
        let borrowed: Vec<(&str, &str)> = owned
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let (mut reader, status, reply) = request_head(&current, "GET", &borrowed, None)?;
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let next = header(&reply, "location")
                .ok_or_else(|| GitError::Invalid {
                    detail: format!("GET {current} redirects without a Location"),
                })?
                .to_owned();
            let next_parsed = parse_url(&next)?;
            let prev_parsed = parse_url(&current)?;
            if next_parsed.host != prev_parsed.host || next_parsed.port != prev_parsed.port {
                owned.retain(|(name, _)| name.to_ascii_lowercase() != "authorization");
            }
            current = next;
            continue;
        }
        if is_success(status) {
            read_body(&mut reader, &reply, sink, None)?;
        }
        return Ok((status, reply));
    }
    Err(GitError::Invalid {
        detail: format!("GET {url} exceeds {MAX_REDIRECTS} redirects"),
    })
}

/// GETs `url` buffering the reply, capped at [`MAX_BUFFERED_BYTES`].
///
/// # Errors
/// Routing, framing, and transport failures as [`GitError`].
pub fn get(url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, GitError> {
    let mut body = Vec::new();
    let (status, headers) =
        request_head(url, "GET", headers, None).and_then(|(mut reader, status, headers)| {
            if is_success(status) {
                read_body(&mut reader, &headers, &mut body, Some(MAX_BUFFERED_BYTES))?;
            }
            Ok((status, headers))
        })?;
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------
// git-lfs batch API shapes
// ---------------------------------------------------------------------------

/// One object the batch request asks about: content hash plus byte size,
/// exactly as the batch spec's `objects[]` entries read.
pub fn batch_request_body(objects: &[(String, u64)]) -> Result<Vec<u8>, GitError> {
    for (oid, _) in objects {
        if !ruk_core::store::lfs::valid_oid_hex(oid) {
            return Err(GitError::Invalid {
                detail: format!("lfs batch oid is not 64 hex digits: {oid:?}"),
            });
        }
    }
    let mut out =
        String::from("{\"operation\":\"download\",\"transfers\":[\"basic\"],\"objects\":[");
    for (index, (oid, size)) in objects.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!("{{\"oid\":\"{oid}\",\"size\":{size}}}"));
    }
    out.push_str("]}");
    Ok(out.into_bytes())
}

/// One batch answer: either a download action or a server-side refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchEntry {
    /// The object may be fetched from `href`, echoing `headers` on the
    /// GET the way `actions.download.header` demands.
    Ready {
        /// Content hash of the object.
        oid: String,
        /// Declared byte size.
        size: u64,
        /// Where the payload bytes live.
        href: String,
        /// Extra headers the GET must carry.
        headers: Vec<(String, String)>,
    },
    /// The server refused this object; the caller reports it missing with
    /// `detail` (never fatal to the other objects).
    Failed {
        /// Content hash of the refused object.
        oid: String,
        /// `"<code>: <message>"` from the entry's `error` object.
        detail: String,
    },
}

/// Batch response documents, mirroring the spec shape; every field but the
/// object `oid` is optional because servers omit sizes, actions, and error
/// details freely.
#[derive(Debug, serde::Deserialize)]
struct BatchResponseDoc {
    #[serde(default)]
    objects: Vec<BatchObjectDoc>,
}

/// One object entry of a batch response.
#[derive(Debug, serde::Deserialize)]
struct BatchObjectDoc {
    #[serde(default)]
    oid: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    actions: Option<BatchActionsDoc>,
    #[serde(default)]
    error: Option<BatchErrorDoc>,
}

/// The `actions` map of one object entry; only `download` matters here.
#[derive(Debug, Default, serde::Deserialize)]
struct BatchActionsDoc {
    #[serde(default)]
    download: Option<DownloadActionDoc>,
}

/// One `actions.download` entry: the payload URL plus headers the GET
/// must echo. `expires_in`/`expires_at` need no client clock: hrefs are
/// used immediately and never cached, which honors expiry by
/// construction.
#[derive(Debug, serde::Deserialize)]
struct DownloadActionDoc {
    #[serde(default)]
    href: String,
    #[serde(default)]
    header: HashMap<String, String>,
}

/// One object-level `error` entry.
#[derive(Debug, serde::Deserialize)]
struct BatchErrorDoc {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

/// Reads one batch response document into per-object answers.
///
/// Entries for unknown oids are kept as failures (`"not requested"`), so
/// a confused server cannot smuggle payloads past verification: the sync
/// still stages every download under the requested hash.
///
/// # Errors
/// [`GitError::Corrupt`] for a non-JSON or misshapen document.
pub fn parse_batch_response(body: &[u8]) -> Result<Vec<BatchEntry>, GitError> {
    let text = std::str::from_utf8(body).map_err(|_| GitError::Corrupt {
        detail: "lfs batch response is not UTF-8".to_owned(),
    })?;
    let document: BatchResponseDoc = sonic_rs::from_str(text).map_err(|err| GitError::Corrupt {
        detail: format!("lfs batch response does not parse: {err}"),
    })?;
    let mut entries = Vec::with_capacity(document.objects.len());
    for object in document.objects {
        if object.oid.is_empty() {
            return Err(GitError::Corrupt {
                detail: "lfs batch response holds an object without an oid".to_owned(),
            });
        }
        if let Some(error) = object.error {
            let message = error.message.trim();
            let detail = if message.is_empty() {
                format!("code {}", error.code)
            } else {
                format!("code {}: {message}", error.code)
            };
            entries.push(BatchEntry::Failed {
                oid: object.oid,
                detail,
            });
            continue;
        }
        match object.actions.and_then(|actions| actions.download) {
            Some(action) if !action.href.is_empty() => entries.push(BatchEntry::Ready {
                oid: object.oid,
                size: object.size,
                href: action.href,
                headers: action.header.into_iter().collect(),
            }),
            _ => entries.push(BatchEntry::Failed {
                oid: object.oid,
                detail: "no download action".to_owned(),
            }),
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn base64_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn auth_prefers_bearer_and_encodes_basic() {
        let vars = HashMap::from([
            ("GIT_LFS_AUTH_BEARER".to_owned(), "tok".to_owned()),
            ("GIT_LFS_AUTH_BASIC".to_owned(), "user:pass".to_owned()),
        ]);
        assert_eq!(
            auth_header(&vars),
            Some(("authorization".to_owned(), "Bearer tok".to_owned()))
        );
        let vars = HashMap::from([("GIT_LFS_AUTH_BASIC".to_owned(), "user:pass".to_owned())]);
        assert_eq!(
            auth_header(&vars),
            Some(("authorization".to_owned(), "Basic dXNlcjpwYXNz".to_owned()))
        );
        // An already-encoded value without a colon passes through.
        let vars = HashMap::from([("GIT_LFS_AUTH_BASIC".to_owned(), "dXNlcjpwYXNz".to_owned())]);
        assert_eq!(
            auth_header(&vars),
            Some(("authorization".to_owned(), "Basic dXNlcjpwYXNz".to_owned()))
        );
        assert_eq!(auth_header(&HashMap::new()), None);
    }

    #[test]
    fn url_parse_keeps_queries_and_defaults_ports() {
        let parsed = parse_url("http://127.0.0.1:18080/a/b?token=x&y=2").expect("parse");
        assert!(!parsed.secure);
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 18080);
        assert_eq!(parsed.path, "/a/b?token=x&y=2");
        let parsed = parse_url("https://host.x/lfs").expect("parse");
        assert!(parsed.secure);
        assert_eq!(parsed.port, 443);
        assert!(parse_url("ftp://host.x/a").is_err());
        assert!(parse_url("http:///a").is_err());
        assert!(parse_url("http://host.x:abc/a").is_err());
    }

    /// Reads one request head plus its declared body from `socket`,
    /// returning the head text and the raw body bytes.
    fn read_request(socket: &std::net::TcpStream) -> (String, Vec<u8>) {
        let mut reader = BufReader::new(socket.try_clone().expect("split"));
        let mut head = Vec::new();
        loop {
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).expect("request line");
            if line.is_empty() {
                panic!("client hung up mid-request");
            }
            head.extend_from_slice(&line);
            if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        // Header names are case-insensitive on the wire; match loosely.
        let length = text
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().to_ascii_lowercase() == "content-length")
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0_u8; length];
        if length > 0 {
            reader.read_exact(&mut body).expect("request body");
        }
        (text, body)
    }

    /// Serves canned HTTP replies on loopback: each connection gets the
    /// next `(status, extra headers, body)` triple with head and body
    /// written on the same accepted socket, and each request head is
    /// recorded for assertions. Returns the port plus the join handle for
    /// the recorded request heads.
    fn fake_server(
        replies: Vec<(u16, Vec<(String, String)>, Vec<u8>)>,
    ) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, headers, body) in replies {
                let (mut socket, _) = listener.accept().expect("accept");
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .expect("timeout");
                let (head, _) = read_request(&socket);
                requests.push(head);
                let reason = match status {
                    200 => "OK",
                    302 => "Found",
                    404 => "Not Found",
                    _ => "Error",
                };
                let mut reply = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n",
                    body.len()
                );
                for (name, value) in &headers {
                    reply.push_str(&format!("{name}: {value}\r\n"));
                }
                reply.push_str("Connection: close\r\n\r\n");
                socket.write_all(reply.as_bytes()).expect("reply head");
                socket.write_all(&body).expect("reply body");
                // Drop closes the connection, framing the body end.
            }
            requests
        });
        (port, server)
    }

    /// Serves raw reply bytes on loopback (for chunked framing, which the
    /// framed helper above never emits): each connection gets the next
    /// byte string verbatim on its accepted socket.
    fn fake_raw_server(replies: Vec<Vec<u8>>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut socket, _) = listener.accept().expect("accept");
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .expect("timeout");
                let (head, _) = read_request(&socket);
                requests.push(head);
                socket.write_all(&reply).expect("raw reply");
            }
            requests
        });
        (port, server)
    }

    #[test]
    fn posts_json_and_reads_content_length() {
        let (port, server) = fake_server(vec![(
            200,
            vec![("Content-Type".to_owned(), LFS_JSON.to_owned())],
            b"{\"objects\":[]}".to_vec(),
        )]);
        let url = format!("http://127.0.0.1:{port}/info/lfs/objects/batch");
        let reply = post_json(
            &url,
            &[
                ("Content-Type", LFS_JSON),
                ("Accept", LFS_JSON),
                ("Authorization", "Bearer tok"),
            ],
            b"{\"operation\":\"download\"}",
        )
        .expect("post");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, b"{\"objects\":[]}");
        assert_eq!(header(&reply.headers, "content-type"), Some(LFS_JSON));
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        let head = &requests[0];
        assert!(
            head.starts_with("POST /info/lfs/objects/batch HTTP/1.1\r\n"),
            "{head:?}"
        );
        assert!(head.contains("Authorization: Bearer tok"), "{head:?}");
        assert!(
            head.contains(&format!("Content-Type: {LFS_JSON}")),
            "{head:?}"
        );
    }

    #[test]
    fn gets_stream_and_decodes_chunked() {
        let (port, server) = fake_raw_server(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec(),
        ]);
        let mut sunk = Vec::new();
        let (status, _) =
            get_to_writer(&format!("http://127.0.0.1:{port}/payload"), &[], &mut sunk)
                .expect("get");
        assert_eq!(status, 200);
        assert_eq!(sunk, b"hello world");
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].starts_with("GET /payload HTTP/1.1\r\n"),
            "{:?}",
            requests[0]
        );
    }

    #[test]
    fn get_follows_redirects_and_drops_cross_host_auth() {
        // Hop one redirects cross-host (port differs, so the host key
        // differs): the Authorization header must not follow.
        let (second_port, second) = fake_server(vec![(200, vec![], b"payload-bytes".to_vec())]);
        let (first_port, first) = fake_server(vec![(
            302,
            vec![(
                "Location".to_owned(),
                format!("http://127.0.0.1:{second_port}/real"),
            )],
            b"moved".to_vec(),
        )]);
        let mut sunk = Vec::new();
        let (status, _) = get_to_writer(
            &format!("http://127.0.0.1:{first_port}/signed"),
            &[("Authorization", "Bearer tok")],
            &mut sunk,
        )
        .expect("get");
        assert_eq!(status, 200);
        assert_eq!(sunk, b"payload-bytes");
        let first_requests = first.join().expect("first server");
        let second_requests = second.join().expect("second server");
        assert_eq!(first_requests.len(), 1);
        assert!(first_requests[0].contains("Authorization: Bearer tok"));
        assert_eq!(second_requests.len(), 1);
        assert!(
            !second_requests[0].contains("Authorization:"),
            "token leaked: {:?}",
            second_requests[0]
        );
    }

    #[test]
    fn authority_scopes_credentials() {
        assert_eq!(
            url_authority("http://127.0.0.1:18080/a?x=1").expect("authority"),
            "127.0.0.1:18080"
        );
        assert_eq!(
            url_authority("https://host.x/lfs").expect("authority"),
            "host.x:443"
        );
        assert_ne!(
            url_authority("http://127.0.0.1:18080/a").expect("a"),
            url_authority("http://127.0.0.1:19090/b").expect("b")
        );
        assert!(url_authority("ftp://host.x/a").is_err());
    }

    #[test]
    fn batch_shapes_round_trip() {
        let oid = "a".repeat(64);
        let body = batch_request_body(&[(oid.clone(), 11)]).expect("request");
        assert_eq!(
            String::from_utf8(body).expect("utf8"),
            format!(
                "{{\"operation\":\"download\",\"transfers\":[\"basic\"],\"objects\":[{{\"oid\":\"{oid}\",\"size\":11}}]}}"
            )
        );
        assert!(batch_request_body(&[("short".to_owned(), 1)]).is_err());
        let entries = parse_batch_response(
            format!(
                "{{\"objects\":[{{\"oid\":\"{oid}\",\"size\":11,\"actions\":{{\"download\":{{\"href\":\"http://x/p\",\"header\":{{\"Authorization\":\"tok\"}}}}}}}}]}}"
            )
            .as_bytes(),
        )
        .expect("parse");
        assert_eq!(
            entries,
            vec![BatchEntry::Ready {
                oid: oid.clone(),
                size: 11,
                href: "http://x/p".to_owned(),
                headers: vec![("Authorization".to_owned(), "tok".to_owned())],
            }]
        );
        // Error entries and missing actions become failures with detail.
        let entries = parse_batch_response(
            format!(
                "{{\"objects\":[{{\"oid\":\"{oid}\",\"size\":11,\"error\":{{\"code\":404,\"message\":\"nope\"}}}},{{\"oid\":\"{}\",\"size\":1}}]}}",
                "b".repeat(64),
            )
            .as_bytes(),
        )
        .expect("parse");
        assert_eq!(
            entries,
            vec![
                BatchEntry::Failed {
                    oid,
                    detail: "code 404: nope".to_owned(),
                },
                BatchEntry::Failed {
                    oid: "b".repeat(64),
                    detail: "no download action".to_owned(),
                },
            ]
        );
        assert!(parse_batch_response(b"not json").is_err());
        assert!(parse_batch_response(b"{\"objects\":[{}]}").is_err());
    }
}
