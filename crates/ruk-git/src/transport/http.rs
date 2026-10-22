//! Minimal HTTP/1.1 client for the git-lfs batch API and git smart-http.
//!
//! `std::net::TcpStream` plus TLS via `rustls`+`webpki-roots` (pure Rust,
//! Mozilla roots; no platform glue). Scope is exactly what batch transfer
//! and [`super::smart_http`] need: POST a JSON body, GET a payload URL
//! streaming into a writer, buffered or streaming raw POSTs for pkt-line
//! RPC bodies, `Content-Length` or chunked bodies, Basic/Bearer auth from
//! the environment. No cookies, no keep-alive (every request sends
//! `Connection: close` on a fresh connection); dumb-http file fetches go
//! through [`super::dumb_http`], and only LFS payloads plus smart-http and
//! dumb-http get HTTP.
//!
//! Oracle anchors: the git-lfs batch API
//! (`https://github.com/git-lfs/git-lfs/blob/main/docs/api/batch.md`:
//! `POST <endpoint>/objects/batch` with
//! `Content-Type: application/vnd.git-lfs+json`, per-object
//! `actions.download.href` plus `actions.download.header` echo, and
//! per-object `error` entries).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
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

/// One `http.extraHeader` config row: `scope` is the `[http "<base>"]`
/// subsection when present (`None` is bare `http.extraHeader`), `value`
/// the raw header line (`""` resets the accumulated list, per git).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtraHeaderRow {
    /// URL-prefix scope from the config subsection, if any.
    pub scope: Option<String>,
    /// Raw `Name: value` header line, or `""` to reset the list.
    pub value: String,
}

/// Parses one `http.extraHeader` line into its `(name, value)` header.
/// The split is at the first colon; one leading blank on the value is
/// stripped and the rest travels verbatim, the way curl takes `-H` lines.
/// `None` for lines without a colon, with an empty name, or carrying a
/// line break (curl would send those raw; this client refuses line breaks
/// in [`send_head`], so one bad row must not fail the request).
fn parse_extra_header(line: &str) -> Option<(String, String)> {
    let (name, value) = line.split_once(':')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    if name.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
        return None;
    }
    let value = value.strip_prefix([' ', '\t']).unwrap_or(value);
    if value.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
        return None;
    }
    Some((name.to_owned(), value.to_owned()))
}

/// Resolves the `http.extraHeader` request headers for `url` from `rows`
/// in precedence order (git-config files, then repo config, then `-c`
/// overrides). The longest scope matching `url` (prefix ending on a URL
/// boundary, see [`super::credentials::scope_matches`]) wins outright and
/// only its rows apply; with no matching scope the unscoped rows apply.
/// Rows apply in order: an empty value resets the list
/// (`git/http.c` `http_options`), any other value joins verbatim.
///
/// Documented simplifications against git's `urlmatch` machinery: scopes
/// compare as plain prefixes with no scheme/host case-folding, no
/// percent-decoding, and no default-port folding; and unscoped rows never
/// mix with scoped ones (git's mix is order-dependent, this wins cleanly).
#[must_use]
pub fn extra_headers_for_url(url: &str, rows: &[ExtraHeaderRow]) -> Vec<(String, String)> {
    let mut winner: Option<&str> = None;
    let mut winner_len = 0usize;
    for row in rows {
        let Some(scope) = row.scope.as_deref() else {
            continue;
        };
        if !super::credentials::scope_matches(scope, url) {
            continue;
        }
        let len = scope.trim_end_matches('/').len();
        if winner.is_none() || len > winner_len {
            winner = Some(scope);
            winner_len = len;
        }
    }
    let selected = |row: &ExtraHeaderRow| match (winner, row.scope.as_deref()) {
        (Some(want), Some(have)) => have.trim_end_matches('/') == want.trim_end_matches('/'),
        (None, None) => true,
        _ => false,
    };
    let mut out = Vec::new();
    for row in rows.iter().filter(|row| selected(row)) {
        if row.value.is_empty() {
            out.clear();
            continue;
        }
        if let Some(header) = parse_extra_header(&row.value) {
            out.push(header);
        }
    }
    out
}

/// An `Authorization` header from the git smart-http auth environment,
/// when set.
///
/// `GIT_AUTH_TOKEN` wins and is sent verbatim as `Bearer <value>`;
/// otherwise `GIT_AUTH_USER` plus `GIT_AUTH_PASSWORD` are sent as
/// `Basic <base64(user:pass)>`. This is the environment half of auth: the
/// helper half lives in [`super::credentials::auth_header_for_url`], which
/// tries the configured helper first and falls back here. Configured
/// `http.<url>.extraHeader` lines join every request separately through
/// [`extra_headers_for_url`]; when both carry `Authorization`, both are
/// sent, the way curl sends custom headers alongside its own auth.
#[must_use]
pub fn git_auth_header(vars: &HashMap<String, String>) -> Option<(String, String)> {
    if let Some(token) = vars.get("GIT_AUTH_TOKEN").filter(|v| !v.is_empty()) {
        return Some(("authorization".to_owned(), format!("Bearer {token}")));
    }
    let user = vars.get("GIT_AUTH_USER").filter(|v| !v.is_empty())?;
    let password = vars.get("GIT_AUTH_PASSWORD").cloned().unwrap_or_default();
    let encoded = base64_encode(format!("{user}:{password}").as_bytes());
    Some(("authorization".to_owned(), format!("Basic {encoded}")))
}
#[cfg(test)]
mod extra_header_tests {
    use super::*;

    fn row(scope: Option<&str>, value: &str) -> ExtraHeaderRow {
        ExtraHeaderRow {
            scope: scope.map(str::to_owned),
            value: value.to_owned(),
        }
    }

    #[test]
    fn unscoped_rows_accumulate_verbatim() {
        let headers = extra_headers_for_url(
            "https://host.x/a.git",
            &[
                row(None, "X-One: 1"),
                row(None, "Authorization: Bearer scoped-token"),
            ],
        );
        assert_eq!(
            headers,
            vec![
                ("X-One".to_owned(), "1".to_owned()),
                ("Authorization".to_owned(), "Bearer scoped-token".to_owned()),
            ]
        );
        assert!(extra_headers_for_url("https://host.x/a.git", &[]).is_empty());
    }

    #[test]
    fn longest_matching_scope_wins_outright() {
        let rows = vec![
            row(None, "X-Global: g"),
            row(Some("https://host.x"), "X-Host: h"),
            row(Some("https://host.x/sub"), "X-Sub: s"),
        ];
        assert_eq!(
            extra_headers_for_url("https://host.x/sub/a", &rows),
            vec![("X-Sub".to_owned(), "s".to_owned())]
        );
        assert_eq!(
            extra_headers_for_url("https://host.x/other", &rows),
            vec![("X-Host".to_owned(), "h".to_owned())]
        );
        assert_eq!(
            extra_headers_for_url("https://elsewhere.x/a", &rows),
            vec![("X-Global".to_owned(), "g".to_owned())]
        );
        // Boundary, not substring: no match on a hostile hostname.
        assert_eq!(
            extra_headers_for_url("https://host.x.evil/a", &rows),
            vec![("X-Global".to_owned(), "g".to_owned())]
        );
    }

    #[test]
    fn empty_value_resets_and_malformed_lines_drop() {
        let headers = extra_headers_for_url(
            "https://host.x/a",
            &[
                row(None, "X-One: 1"),
                row(None, ""),
                row(None, "X-Two: 2"),
                row(None, "no-colon-here"),
                row(None, ": empty-name"),
                row(None, "X-Evil: a\rb"),
            ],
        );
        assert_eq!(headers, vec![("X-Two".to_owned(), "2".to_owned())]);
    }
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
    // `rsplit` always yields one item; the empty host fails below.
    let hostport: &str = authority.rsplit('@').next().unwrap_or_default();
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
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
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
        tls_client_config(roots).map_err(|err| format!("tls provider refused: {err}"))
    });
    CONFIG.clone().map_err(|detail| GitError::Io {
        detail: detail.clone(),
    })
}

fn tls_client_config(
    roots: rustls::RootCertStore,
) -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
    rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .map(|builder| Arc::new(builder.with_root_certificates(roots).with_no_client_auth()))
}

/// Builds a client config from one PEM bundle instead of the Mozilla set:
/// private-CA servers whose chains never touch the public roots. Fails
/// closed on bundles with no usable certificate.
///
/// # Errors
/// [`GitError::Invalid`] for an empty bundle or one with no parsable
/// `CERTIFICATE` block.
fn tls_config_with_roots(pem: &[u8]) -> Result<Arc<rustls::ClientConfig>, GitError> {
    let certs = parse_pem_certs(pem)?;
    if certs.is_empty() {
        return Err(GitError::Invalid {
            detail: "tls trust bundle holds no certificate".to_owned(),
        });
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|err| GitError::Invalid {
            detail: format!("tls trust bundle holds an unusable certificate: {err}"),
        })?;
    }
    tls_client_config(roots).map_err(|err| GitError::Io {
        detail: format!("tls provider refused bundle roots: {err}"),
    })
}

/// Splits the `CERTIFICATE` blocks out of one PEM bundle: headers and
/// trailers delimit, blank lines and foreign blocks are skipped, and each
/// body must be valid padded base64.
fn parse_pem_certs(
    pem: &[u8],
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, GitError> {
    let text = std::str::from_utf8(pem).map_err(|_| GitError::Invalid {
        detail: "tls trust bundle is not UTF-8".to_owned(),
    })?;
    let mut certs = Vec::new();
    let mut body = String::new();
    let mut in_block = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            if in_block {
                return Err(GitError::Invalid {
                    detail: "tls trust bundle nests certificate blocks".to_owned(),
                });
            }
            in_block = true;
            body.clear();
        } else if line == "-----END CERTIFICATE-----" {
            if !in_block {
                return Err(GitError::Invalid {
                    detail: "tls trust bundle ends a block never begun".to_owned(),
                });
            }
            in_block = false;
            certs.push(rustls::pki_types::CertificateDer::from(base64_decode(
                &body,
            )?));
            body.clear();
        } else if in_block && !line.is_empty() {
            body.push_str(line);
        }
    }
    if in_block {
        return Err(GitError::Invalid {
            detail: "tls trust bundle ends inside a certificate block".to_owned(),
        });
    }
    Ok(certs)
}

/// Decodes standard-alphabet padded base64: the inverse of the Basic
/// credential encoder, strict about trailing bits and padding.
fn base64_decode(text: &str) -> Result<Vec<u8>, GitError> {
    fn value(byte: u8) -> Result<u8, GitError> {
        match byte {
            b'A'..=b'Z' => Ok(byte - b'A'),
            b'a'..=b'z' => Ok(byte - b'a' + 26),
            b'0'..=b'9' => Ok(byte - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(GitError::Invalid {
                detail: "tls trust bundle body is not base64".to_owned(),
            }),
        }
    }
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(GitError::Invalid {
            detail: "tls trust bundle body length is not base64".to_owned(),
        });
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().rev().take_while(|b| **b == b'=').count();
        if pad > 2 {
            return Err(GitError::Invalid {
                detail: "tls trust bundle body is not base64".to_owned(),
            });
        }
        let mut word: u32 = 0;
        for (index, byte) in chunk.iter().enumerate() {
            let position = u32::try_from(index).expect("four-byte chunk keeps small indexes");
            let bits = if *byte == b'=' {
                if index < 4 - pad {
                    return Err(GitError::Invalid {
                        detail: "tls trust bundle body is not base64".to_owned(),
                    });
                }
                0
            } else {
                if index >= 4 - pad {
                    return Err(GitError::Invalid {
                        detail: "tls trust bundle body is not base64".to_owned(),
                    });
                }
                u32::from(value(*byte)?)
            };
            word |= bits << (18 - 6 * position);
        }
        out.push(u8::try_from(word >> 16).expect("four sextets keep 24 bits"));
        if pad < 2 {
            out.push(u8::try_from((word >> 8) & 0xff).expect("four sextets keep 24 bits"));
        }
        if pad < 1 {
            out.push(u8::try_from(word & 0xff).expect("four sextets keep 24 bits"));
        }
    }
    Ok(out)
}

/// Compares the credential scope of two URLs: scheme, host, and port all
/// match, so a token for an `https` endpoint never follows a downgrade to
/// `http` on the same host.
///
/// # Errors
/// [`GitError::Invalid`] for a non-HTTP URL on either side.
pub fn same_origin(a: &str, b: &str) -> Result<bool, GitError> {
    let a = parse_url(a)?;
    let b = parse_url(b)?;
    Ok(a.secure == b.secure && a.host == b.host && a.port == b.port)
}

/// Dials `parsed` with a bounded connect plus read/write timeouts and runs
/// the TLS handshake up front on `https`, so a certificate failure reports
/// before any request bytes move. Every resolved address is tried in order
/// (resolution, not string splicing, builds the dial address, so IPv6
/// hosts dial correctly).
///
/// # Errors
/// [`GitError::Invalid`] for an unusable server name, [`GitError::Io`]
/// when no address resolves or none connects within the timeout.
fn connect(
    parsed: &Url,
    policy: &super::net::EgressPolicy,
    tls_roots: Option<&[u8]>,
) -> Result<Stream, GitError> {
    let label = format!("{}:{}", parsed.host, parsed.port);
    let addrs: Vec<std::net::SocketAddr> = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()
        .map_err(|err| GitError::Io {
            detail: format!("cannot resolve {label}: {err}"),
        })?
        .collect();
    if addrs.is_empty() {
        return Err(GitError::Io {
            detail: format!("cannot resolve {label}: no addresses"),
        });
    }
    let addrs = policy.filter_addrs(&label, &addrs)?;
    let mut last_err = String::from("no addresses tried");
    let mut socket = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, IO_TIMEOUT) {
            Ok(dialed) => {
                socket = Some(dialed);
                break;
            }
            Err(err) => last_err = err.to_string(),
        }
    }
    let socket = socket.ok_or_else(|| GitError::Io {
        detail: format!(
            "cannot reach {label} within {}s: {last_err}",
            IO_TIMEOUT.as_secs()
        ),
    })?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .and(socket.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|err| GitError::Io {
            detail: format!("cannot arm timeouts on {label}: {err}"),
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
    let connection = rustls::ClientConnection::new(
        match tls_roots {
            Some(pem) => tls_config_with_roots(pem)?,
            None => tls_config()?,
        },
        name,
    )
    .map_err(|err| GitError::Io {
        detail: format!("cannot start tls to {}: {err}", parsed.host),
    })?;
    let mut tls = rustls::StreamOwned::new(connection, socket);
    // The handshake runs lazily inside rustls; one flush forces it now so
    // certificate errors report as connection failures, not request ones.
    tls.flush().map_err(|err| GitError::Io {
        detail: format!("tls handshake with {} failed: {err}", parsed.host),
    })?;
    Ok(Stream::Tls(Box::new(tls)))
}

/// Writes one HTTP/1.1 request head: method line, Host, caller headers,
/// `Connection: close`, and `Content-Length` when `content_len` is known.
fn send_head(
    stream: &mut Stream,
    method: &str,
    parsed: &Url,
    headers: &[(&str, &str)],
    content_len: Option<u64>,
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
    if let Some(len) = content_len {
        head.push_str(&format!("Content-Length: {len}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .map_err(|err| GitError::Io {
            detail: format!("cannot send {what}: {err}"),
        })
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
    let content_len = body
        .map(|body| {
            u64::try_from(body.len()).map_err(|_| GitError::Limit {
                detail: "request body exceeds addressable length".to_owned(),
            })
        })
        .transpose()?;
    send_head(stream, method, parsed, headers, content_len)?;
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

/// One open response head: the reader positioned at the body, the status,
/// and the headers.
type ResponseHead = (BufReader<Stream>, u16, Vec<(String, String)>);

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
    policy: &super::net::EgressPolicy,
    tls_roots: Option<&[u8]>,
) -> Result<ResponseHead, GitError> {
    let parsed = parse_url(url)?;
    let mut stream = connect(&parsed, policy, tls_roots)?;
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
    policy: &super::net::EgressPolicy,
    tls_roots: Option<&[u8]>,
) -> Result<HttpResponse, GitError> {
    let (mut reader, status, headers) =
        request_head(url, "POST", headers, Some(body), policy, tls_roots)?;
    let mut reply = Vec::new();
    read_body(&mut reader, &headers, &mut reply, Some(MAX_BUFFERED_BYTES))?;
    Ok(HttpResponse {
        status,
        headers,
        body: reply,
    })
}

/// How one open response body ends: chunked wins over `Content-Length`
/// (RFC 9112 §6.3), an absent length reads to EOF on the closed
/// connection — the same precedence [`read_body`] uses for sinks.
enum BodyFraming {
    /// Exactly `rest` more bytes belong to the body.
    Sized {
        /// Bytes still owed.
        rest: u64,
    },
    /// Chunked framing at `state`.
    Chunked {
        /// Where the next read resumes.
        state: ChunkState,
    },
    /// The body ends with the connection.
    ToEof,
}

/// Where a chunked read resumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChunkState {
    /// Parse the next chunk-size line.
    Size,
    /// Emit `rest` more bytes of the current chunk.
    Data {
        /// Bytes still owed in this chunk.
        rest: u64,
    },
    /// Consume the CRLF closing the current chunk.
    DataEnd,
    /// Consume trailers to the blank line.
    Trailers,
    /// The zero chunk and trailers are past: all reads are EOF.
    Done,
}

/// One open response body: the reader positioned at the first body byte,
/// owning the connection, decoding its framing as it reads, so pkt-line
/// never sees chunk-size text. Dropping it closes the connection, so
/// error statuses need no draining; the caller reports the status.
///
/// No derived `Debug`: the inner stream (notably the TLS session) has none.
pub struct HttpBodyReader {
    reader: BufReader<Stream>,
    framing: BodyFraming,
}

impl std::fmt::Debug for HttpBodyReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpBodyReader").finish_non_exhaustive()
    }
}

/// One open response: the framing body reader, the status, and the headers.
type OpenResponse = (HttpBodyReader, u16, Vec<(String, String)>);

fn io_failed(what: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, what.to_owned())
}

fn io_git(err: GitError) -> std::io::Error {
    std::io::Error::other(err.to_string())
}

impl Read for HttpBodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match &mut self.framing {
            BodyFraming::Sized { rest } => {
                if *rest == 0 {
                    return Ok(0);
                }
                let want = usize::try_from((*rest).min(buf.len() as u64))
                    .map_err(|_| io_failed("response length exceeds addressable memory"))?;
                let got = self.reader.read(&mut buf[..want])?;
                if got == 0 {
                    return Err(io_failed("response body ended early"));
                }
                *rest -= got as u64;
                Ok(got)
            }
            BodyFraming::ToEof => self.reader.read(buf),
            BodyFraming::Chunked { state } => loop {
                match *state {
                    ChunkState::Done => return Ok(0),
                    ChunkState::Size => {
                        let line = read_line(&mut self.reader).map_err(io_git)?;
                        let size_text = line
                            .iter()
                            .take_while(|byte| **byte != b';')
                            .copied()
                            .collect::<Vec<u8>>();
                        let text = std::str::from_utf8(&size_text)
                            .map_err(|_| io_failed("chunk size is not UTF-8"))?;
                        let size = u64::from_str_radix(text, 16)
                            .map_err(|_| io_failed("bad chunk size"))?;
                        *state = if size == 0 {
                            ChunkState::Trailers
                        } else {
                            ChunkState::Data { rest: size }
                        };
                    }
                    ChunkState::Data { ref mut rest } => {
                        let want = usize::try_from((*rest).min(buf.len() as u64))
                            .map_err(|_| io_failed("chunk exceeds addressable memory"))?;
                        let got = self.reader.read(&mut buf[..want])?;
                        if got == 0 {
                            return Err(io_failed("chunked body ended mid-chunk"));
                        }
                        *rest -= got as u64;
                        if *rest == 0 {
                            *state = ChunkState::DataEnd;
                        }
                        return Ok(got);
                    }
                    ChunkState::DataEnd => {
                        if !read_line(&mut self.reader).map_err(io_git)?.is_empty() {
                            return Err(io_failed("chunk misses its trailing CRLF"));
                        }
                        *state = ChunkState::Size;
                    }
                    ChunkState::Trailers => {
                        if read_line(&mut self.reader).map_err(io_git)?.is_empty() {
                            *state = ChunkState::Done;
                        }
                    }
                }
            },
        }
    }
}

/// POSTs `body` and returns the open response: status, headers, and a
/// reader positioned at the body, decoding its framing as it reads. The
/// caller reads straight into pkt-line framing and the pack ingest, which
/// bounds memory no buffered cap could. Single-shot like [`put_bytes`]:
/// smart RPC endpoints never redirect a POST, and re-sending a request
/// body to a redirected host would need fresh credential scoping the
/// caller cannot do blindly; a 3xx status surfaces for the caller to
/// report.
///
/// # Errors
/// Routing, framing, and transport failures as [`GitError`].
pub fn post_open(
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    policy: &super::net::EgressPolicy,
    tls_roots: Option<&[u8]>,
) -> Result<OpenResponse, GitError> {
    let (reader, status, headers) =
        request_head(url, "POST", headers, Some(body), policy, tls_roots)?;
    let framing = open_framing(&headers)?;
    Ok((HttpBodyReader { reader, framing }, status, headers))
}

/// Picks the body framing for one open response from its headers: chunked
/// wins over `Content-Length`, an absent length reads to EOF.
///
/// # Errors
/// [`GitError::Invalid`] for a bad declared length.
fn open_framing(headers: &[(String, String)]) -> Result<BodyFraming, GitError> {
    if header(headers, "transfer-encoding")
        .is_some_and(|value| value.split(',').any(|token| token.trim() == "chunked"))
    {
        return Ok(BodyFraming::Chunked {
            state: ChunkState::Size,
        });
    }
    if let Some(length) = header(headers, "content-length") {
        let declared: u64 = length.parse().map_err(|_| GitError::Invalid {
            detail: format!("bad Content-Length {length:?}"),
        })?;
        return Ok(BodyFraming::Sized { rest: declared });
    }
    Ok(BodyFraming::ToEof)
}

/// PUTs `body` bytes and buffers the reply, capped at
/// [`MAX_BUFFERED_BYTES`]: the LFS upload half of [`post_json`].
/// Single-shot (no redirect follow): upload `href`s are presigned URLs
/// used immediately, and re-sending a payload to a redirected host would
/// need fresh credential scoping the caller cannot do blindly. Payloads
/// that must never sit buffered in memory use [`put_stream`] instead.
///
/// # Errors
/// Routing, framing, and transport failures as [`GitError`].
pub fn put_bytes(
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    policy: &super::net::EgressPolicy,
    tls_roots: Option<&[u8]>,
) -> Result<HttpResponse, GitError> {
    let (mut reader, status, headers) =
        request_head(url, "PUT", headers, Some(body), policy, tls_roots)?;
    let mut reply = Vec::new();
    read_body(&mut reader, &headers, &mut reply, Some(MAX_BUFFERED_BYTES))?;
    Ok(HttpResponse {
        status,
        headers,
        body: reply,
    })
}

/// PUTs `len` bytes streamed from `body` and buffers the reply, capped at
/// [`MAX_BUFFERED_BYTES`]: the streaming sibling of [`put_bytes`] for
/// payloads that must never sit buffered in memory. Single-shot (no
/// redirect follow) for the same reason as [`put_bytes`].
///
/// Exactly `len` bytes are sent; a short reader fails the PUT instead of
/// sending a truncated body under a declared length.
///
/// # Errors
/// Routing, framing, and transport failures as [`GitError`].
pub fn put_stream(
    url: &str,
    headers: &[(&str, &str)],
    len: u64,
    body: &mut dyn Read,
    policy: &super::net::EgressPolicy,
    tls_roots: Option<&[u8]>,
) -> Result<HttpResponse, GitError> {
    let parsed = parse_url(url)?;
    let mut stream = connect(&parsed, policy, tls_roots)?;
    send_head(&mut stream, "PUT", &parsed, headers, Some(len))?;
    let sent = std::io::copy(&mut body.take(len), &mut stream).map_err(|err| GitError::Io {
        detail: format!("cannot send PUT {} body: {err}", parsed.path),
    })?;
    if sent != len {
        return Err(GitError::Io {
            detail: format!("PUT {} body ended after {sent} of {len} bytes", parsed.path),
        });
    }
    stream.flush().map_err(|err| GitError::Io {
        detail: format!("cannot flush PUT {}: {err}", parsed.path),
    })?;
    let mut reader = BufReader::new(stream);
    let (status, headers) = read_head(&mut reader)?;
    let mut reply = Vec::new();
    read_body(&mut reader, &headers, &mut reply, Some(MAX_BUFFERED_BYTES))?;
    Ok(HttpResponse {
        status,
        headers,
        body: reply,
    })
}

/// GETs `url` streaming the body into `sink` (no size cap: the caller
/// verifies what lands), following up to [`MAX_REDIRECTS`] same-origin
/// hops and reporting the final URL. A hop to another origin on a call
/// carrying `authorization` is refused instead of followed: the credential
/// never leaves its origin, and the caller re-bases from the reported
/// target. Error statuses return without sinking anything; the caller
/// reports the status.
///
/// Returns the final status, headers, and URL.
///
/// # Errors
/// Routing, framing, and transport failures as [`GitError`]; too many
/// hops are [`GitError::Invalid`], and refused cross-origin hops are
/// [`GitError::RemoteMoved`] naming the target.
pub fn get_to_writer(
    url: &str,
    headers: &[(&str, &str)],
    sink: &mut dyn Write,
    policy: &super::net::EgressPolicy,
    tls_roots: Option<&[u8]>,
) -> Result<(u16, Vec<(String, String)>, String), GitError> {
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
        let (mut reader, status, reply) =
            request_head(&current, "GET", &borrowed, None, policy, tls_roots)?;
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let next = header(&reply, "location")
                .ok_or_else(|| GitError::Invalid {
                    detail: format!("GET {current} redirects without a Location"),
                })?
                .to_owned();
            if !same_origin(&current, &next)? {
                if owned
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                {
                    return Err(GitError::RemoteMoved {
                        detail: format!(
                            "GET {current} refuses a credentialed redirect to {}",
                            super::credentials::scrub_userinfo(&next),
                        ),
                    });
                }
                owned.retain(|(name, _)| !name.eq_ignore_ascii_case("authorization"));
            }
            current = next;
            continue;
        }
        if is_success(status) {
            read_body(&mut reader, &reply, sink, None)?;
        }
        return Ok((status, reply, current));
    }
    Err(GitError::Invalid {
        detail: format!("GET {url} exceeds {MAX_REDIRECTS} redirects"),
    })
}

/// GETs `url` buffering the reply, capped at [`MAX_BUFFERED_BYTES`].
///
/// # Errors
/// Routing, framing, and transport failures as [`GitError`].
pub fn get(
    url: &str,
    headers: &[(&str, &str)],
    policy: &super::net::EgressPolicy,
    tls_roots: Option<&[u8]>,
) -> Result<HttpResponse, GitError> {
    let mut body = Vec::new();
    let (status, headers) = request_head(url, "GET", headers, None, policy, tls_roots).and_then(
        |(mut reader, status, headers)| {
            if is_success(status) {
                read_body(&mut reader, &headers, &mut body, Some(MAX_BUFFERED_BYTES))?;
            }
            Ok((status, headers))
        },
    )?;
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
    batch_request_body_for("download", objects)
}

/// One batch upload request: the same object list with
/// `"operation":"upload"`. The server answers each object with an
/// `actions.upload` href when it lacks the payload and omits actions for
/// objects it already holds, so the caller PUTs only what is missing.
pub fn batch_upload_request_body(objects: &[(String, u64)]) -> Result<Vec<u8>, GitError> {
    batch_request_body_for("upload", objects)
}

/// Renders one batch request document for `operation`: the shared shape
/// behind [`batch_request_body`] and [`batch_upload_request_body`].
fn batch_request_body_for(operation: &str, objects: &[(String, u64)]) -> Result<Vec<u8>, GitError> {
    for (oid, _) in objects {
        if !ruk_core::store::lfs::valid_oid_hex(oid) {
            return Err(GitError::Invalid {
                detail: format!("lfs batch oid is not 64 hex digits: {oid:?}"),
            });
        }
    }
    let mut out =
        format!("{{\"operation\":\"{operation}\",\"transfers\":[\"basic\"],\"objects\":[");
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

/// The `actions` map of one object entry: `download` for fetch, `upload`
/// for push.
#[derive(Debug, Default, serde::Deserialize)]
struct BatchActionsDoc {
    #[serde(default)]
    download: Option<DownloadActionDoc>,
    #[serde(default)]
    upload: Option<UploadActionDoc>,
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
/// One `actions.upload` entry: where the payload bytes go via PUT plus
/// headers the PUT must echo. Expiry needs no client clock for the same
/// reason as [`DownloadActionDoc`]: hrefs are used immediately and never
/// cached.
#[derive(Debug, serde::Deserialize)]
struct UploadActionDoc {
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

/// One batch upload answer: either a PUT target, an already-present
/// object needing nothing, or a server-side refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UploadEntry {
    /// The remote lacks this object: PUT its bytes to `href`, echoing
    /// `headers` the way `actions.upload.header` demands.
    NeedsUpload {
        /// Content hash of the object.
        oid: String,
        /// Declared byte size.
        size: u64,
        /// Where the payload bytes go.
        href: String,
        /// Extra headers the PUT must carry.
        headers: Vec<(String, String)>,
    },
    /// The remote already holds this object (no actions answered):
    /// nothing to send.
    Present {
        /// Content hash of the object.
        oid: String,
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

/// Reads one batch upload response document into per-object answers.
///
/// An entry with an `error` object is a refusal; an entry with an
/// `actions.upload.href` needs a PUT; anything else means the remote
/// already holds the object. Unlike the download half, a missing action
/// is success (nothing to send), not failure.
///
/// # Errors
/// [`GitError::Corrupt`] for a non-JSON or misshapen document.
pub fn parse_batch_upload_response(body: &[u8]) -> Result<Vec<UploadEntry>, GitError> {
    let text = std::str::from_utf8(body).map_err(|_| GitError::Corrupt {
        detail: "lfs batch upload response is not UTF-8".to_owned(),
    })?;
    let document: BatchResponseDoc = sonic_rs::from_str(text).map_err(|err| GitError::Corrupt {
        detail: format!("lfs batch upload response does not parse: {err}"),
    })?;
    let mut entries = Vec::with_capacity(document.objects.len());
    for object in document.objects {
        if object.oid.is_empty() {
            return Err(GitError::Corrupt {
                detail: "lfs batch upload response holds an object without an oid".to_owned(),
            });
        }
        if let Some(error) = object.error {
            let message = error.message.trim();
            let detail = if message.is_empty() {
                format!("code {}", error.code)
            } else {
                format!("code {}: {message}", error.code)
            };
            entries.push(UploadEntry::Failed {
                oid: object.oid,
                detail,
            });
            continue;
        }
        match object.actions.and_then(|actions| actions.upload) {
            Some(action) if !action.href.is_empty() => entries.push(UploadEntry::NeedsUpload {
                oid: object.oid,
                size: object.size,
                href: action.href,
                headers: action.header.into_iter().collect(),
            }),
            _ => entries.push(UploadEntry::Present { oid: object.oid }),
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
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
    type CannedReply = (u16, Vec<(String, String)>, Vec<u8>);

    fn fake_server(replies: Vec<CannedReply>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
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
            &super::super::net::EgressPolicy::deny_private().allow_loopback(),
            None,
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
        let (status, _, final_url) = get_to_writer(
            &format!("http://127.0.0.1:{port}/payload"),
            &[],
            &mut sunk,
            &super::super::net::EgressPolicy::deny_private().allow_loopback(),
            None,
        )
        .expect("get");
        assert_eq!(final_url, format!("http://127.0.0.1:{port}/payload"));
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
    fn git_auth_env_surface() {
        let vars = HashMap::from([("GIT_AUTH_TOKEN".to_owned(), "tok".to_owned())]);
        assert_eq!(
            git_auth_header(&vars),
            Some(("authorization".to_owned(), "Bearer tok".to_owned()))
        );
        // A bearer token wins over a user/password pair.
        let vars = HashMap::from([
            ("GIT_AUTH_TOKEN".to_owned(), "tok".to_owned()),
            ("GIT_AUTH_USER".to_owned(), "user".to_owned()),
            ("GIT_AUTH_PASSWORD".to_owned(), "pass".to_owned()),
        ]);
        assert_eq!(
            git_auth_header(&vars).map(|(_, value)| value),
            Some("Bearer tok".to_owned())
        );
        let vars = HashMap::from([
            ("GIT_AUTH_USER".to_owned(), "user".to_owned()),
            ("GIT_AUTH_PASSWORD".to_owned(), "pass".to_owned()),
        ]);
        assert_eq!(
            git_auth_header(&vars),
            Some(("authorization".to_owned(), "Basic dXNlcjpwYXNz".to_owned()))
        );
        assert_eq!(git_auth_header(&HashMap::new()), None);
    }

    #[test]
    fn post_open_decodes_chunked_before_pktline() {
        let (port, server) = fake_raw_server(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8\r\n0008NAK\n\r\n4\r\n0000\r\n0\r\n\r\n".to_vec(),
        ]);
        let (mut body, status, _) = post_open(
            &format!("http://127.0.0.1:{port}/a.git/git-upload-pack"),
            &[("Content-Type", "application/x-git-upload-pack-request")],
            b"0000",
            &super::super::net::EgressPolicy::deny_private().allow_loopback(),
            None,
        )
        .expect("post");
        assert_eq!(status, 200);
        let mut decoded = Vec::new();
        body.read_to_end(&mut decoded).expect("read");
        assert_eq!(decoded, b"0008NAK\n0000");
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].starts_with("POST /a.git/git-upload-pack HTTP/1.1\r\n"),
            "{:?}",
            requests[0]
        );
    }

    #[test]
    fn post_open_honors_content_length() {
        let (port, server) = fake_raw_server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n0008NAK\n0000TRAILING".to_vec(),
        ]);
        let (mut body, status, _) = post_open(
            &format!("http://127.0.0.1:{port}/a.git/git-upload-pack"),
            &[],
            b"0000",
            &super::super::net::EgressPolicy::deny_private().allow_loopback(),
            None,
        )
        .expect("post");
        assert_eq!(status, 200);
        let mut decoded = Vec::new();
        body.read_to_end(&mut decoded).expect("read");
        // Exactly the declared 12 bytes: pkt-line never sees framing
        // spill or the trailing connection bytes.
        assert_eq!(decoded, b"0008NAK\n0000");
        server.join().expect("server");
    }

    #[test]
    fn post_open_refuses_a_truncated_body() {
        let (port, server) = fake_raw_server(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n0008NAK\n".to_vec(),
        ]);
        let (mut body, status, _) = post_open(
            &format!("http://127.0.0.1:{port}/a.git/git-upload-pack"),
            &[],
            b"0000",
            &super::super::net::EgressPolicy::deny_private().allow_loopback(),
            None,
        )
        .expect("post");
        assert_eq!(status, 200);
        let mut decoded = Vec::new();
        let err = body
            .read_to_end(&mut decoded)
            .expect_err("truncated body must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        server.join().expect("server");
    }

    #[test]
    fn post_open_reads_an_undelimited_body_to_eof() {
        let (port, server) = fake_raw_server(vec![
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n0008NAK\n0000".to_vec(),
        ]);
        let (mut body, status, _) = post_open(
            &format!("http://127.0.0.1:{port}/a.git/git-upload-pack"),
            &[],
            b"0000",
            &super::super::net::EgressPolicy::deny_private().allow_loopback(),
            None,
        )
        .expect("post");
        assert_eq!(status, 200);
        let mut decoded = Vec::new();
        body.read_to_end(&mut decoded).expect("read");
        assert_eq!(decoded, b"0008NAK\n0000");
        server.join().expect("server");
    }

    #[test]
    fn egress_denies_loopback_dial() {
        let (port, _server) = fake_server(vec![(200, vec![], b"payload".to_vec())]);
        let mut sunk = Vec::new();
        let err = get_to_writer(
            &format!("http://127.0.0.1:{port}/payload"),
            &[],
            &mut sunk,
            &super::super::net::EgressPolicy::deny_private(),
            None,
        )
        .expect_err("loopback must not dial under default-deny");
        assert!(
            err.to_string().contains("egress policy refuses 127.0.0.1"),
            "{err:?}"
        );
    }

    #[test]
    fn egress_rechecks_every_redirect_hop() {
        let (first_port, first) = fake_server(vec![(
            302,
            vec![("Location".to_owned(), "http://10.9.9.9:1/real".to_owned())],
            b"moved".to_vec(),
        )]);
        let mut sunk = Vec::new();
        let err = get_to_writer(
            &format!("http://127.0.0.1:{first_port}/start"),
            &[],
            &mut sunk,
            &super::super::net::EgressPolicy::deny_private().allow_loopback(),
            None,
        )
        .expect_err("redirect to private space must not dial");
        assert!(
            err.to_string().contains("egress policy refuses 10.9.9.9"),
            "{err:?}"
        );
        first.join().expect("first server");
    }

    #[test]
    fn get_refuses_credentialed_cross_host_redirect() {
        // Hop one redirects cross-host (port differs, so the host key
        // differs) on an auth-bearing call: the credential must not follow,
        // so the redirect is refused with its target for re-basing.
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
        let err = get_to_writer(
            &format!("http://127.0.0.1:{first_port}/signed"),
            &[("Authorization", "Bearer tok")],
            &mut sunk,
            &super::super::net::EgressPolicy::deny_private().allow_loopback(),
            None,
        )
        .expect_err("credentialed redirect must not follow");
        assert_eq!(err.code(), ruk_core::error::ErrorCode::ERemoteMoved);
        assert!(
            err.to_string().contains(&format!("{second_port}")),
            "{err:?}"
        );
        assert!(sunk.is_empty(), "nothing sinks on refusal");
        let first_requests = first.join().expect("first server");
        assert_eq!(first_requests.len(), 1);
        assert!(first_requests[0].contains("Authorization: Bearer tok"));
        drop(second);
    }

    #[test]
    fn get_follows_anonymous_cross_host_redirect() {
        // The same hop without credentials still follows: presigned-URL
        // chains carry no Authorization header.
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
        let (status, _, final_url) = get_to_writer(
            &format!("http://127.0.0.1:{first_port}/signed"),
            &[],
            &mut sunk,
            &super::super::net::EgressPolicy::deny_private().allow_loopback(),
            None,
        )
        .expect("get");
        assert_eq!(status, 200);
        assert_eq!(sunk, b"payload-bytes");
        assert_eq!(final_url, format!("http://127.0.0.1:{second_port}/real"));
        let first_requests = first.join().expect("first server");
        let second_requests = second.join().expect("second server");
        assert_eq!(first_requests.len(), 1);
        assert_eq!(second_requests.len(), 1);
    }

    #[test]
    fn origin_scopes_credentials_by_scheme_host_and_port() {
        assert!(same_origin("http://h.x/a", "http://h.x:80/b").expect("same"));
        assert!(!same_origin("http://h.x/a", "https://h.x:443/a").expect("downgrade"));
        assert!(!same_origin("http://h.x:1/a", "http://h.x:2/a").expect("port"));
        assert!(!same_origin("http://a.x/", "http://b.x/").expect("host"));
        assert!(same_origin("http://h.x/a", "http://h.x/a").expect("self"));
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

    #[test]
    fn upload_shapes_round_trip() {
        let oid = "c".repeat(64);
        let body = batch_upload_request_body(&[(oid.clone(), 7)]).expect("request");
        assert_eq!(
            String::from_utf8(body).expect("utf8"),
            format!(
                "{{\"operation\":\"upload\",\"transfers\":[\"basic\"],\"objects\":[{{\"oid\":\"{oid}\",\"size\":7}}]}}"
            )
        );
        assert!(batch_upload_request_body(&[("short".to_owned(), 1)]).is_err());
        // An upload href means PUT; a bare entry means already present;
        // an error entry is a refusal.
        let entries = parse_batch_upload_response(
            format!(
                "{{\"objects\":[{{\"oid\":\"{oid}\",\"size\":7,\"actions\":{{\"upload\":{{\"href\":\"http://x/u\",\"header\":{{\"Authorization\":\"tok\"}}}}}}}},{{\"oid\":\"{}\",\"size\":1}},{{\"oid\":\"{}\",\"size\":2,\"error\":{{\"code\":403,\"message\":\"no\"}}}}]}}",
                "d".repeat(64),
                "e".repeat(64),
            )
            .as_bytes(),
        )
        .expect("parse");
        assert_eq!(
            entries,
            vec![
                UploadEntry::NeedsUpload {
                    oid: oid.clone(),
                    size: 7,
                    href: "http://x/u".to_owned(),
                    headers: vec![("Authorization".to_owned(), "tok".to_owned())],
                },
                UploadEntry::Present {
                    oid: "d".repeat(64),
                },
                UploadEntry::Failed {
                    oid: "e".repeat(64),
                    detail: "code 403: no".to_owned(),
                },
            ]
        );
        assert!(parse_batch_upload_response(b"not json").is_err());
        assert!(parse_batch_upload_response(b"{\"objects\":[{}]}").is_err());
    }

    #[test]
    fn puts_bytes_with_method_and_length() {
        let (port, server) = fake_server(vec![(200, vec![], b"{}".to_vec())]);
        let url = format!("http://127.0.0.1:{port}/up/abcd");
        let reply = put_bytes(
            &url,
            &[("Content-Type", "application/octet-stream")],
            b"payload-bytes",
            &super::super::net::EgressPolicy::deny_private().allow_loopback(),
            None,
        )
        .expect("put");
        assert_eq!(reply.status, 200);
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        let head = &requests[0];
        assert!(head.starts_with("PUT /up/abcd HTTP/1.1\r\n"), "{head:?}");
        assert!(head.contains("Content-Length: 13"), "{head:?}");
        assert!(
            head.contains("Content-Type: application/octet-stream"),
            "{head:?}"
        );
    }
    #[test]
    fn puts_stream_with_declared_length() {
        let (port, server) = fake_server(vec![(200, vec![], b"{}".to_vec())]);
        let url = format!("http://127.0.0.1:{port}/up/stream");
        let payload = b"streamed-payload-bytes";
        let mut body: &[u8] = payload;
        let reply = put_stream(
            &url,
            &[("Content-Type", "application/octet-stream")],
            u64::try_from(payload.len()).expect("payload fits"),
            &mut body,
            &super::super::net::EgressPolicy::deny_private().allow_loopback(),
            None,
        )
        .expect("put");
        assert_eq!(reply.status, 200);
        assert!(body.is_empty(), "reader is consumed");
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        let head = &requests[0];
        assert!(head.starts_with("PUT /up/stream HTTP/1.1\r\n"), "{head:?}");
        assert!(head.contains("Content-Length: 22"), "{head:?}");
    }

    #[test]
    fn pem_splits_blocks_and_decodes_bodies() {
        let bundle = "-----BEGIN CERTIFICATE-----\nTWE=\n-----END CERTIFICATE-----\n-----BEGIN FOO-----\nignored\n-----END FOO-----\n-----BEGIN CERTIFICATE-----\nTQ==\n-----END CERTIFICATE-----\n";
        let certs = parse_pem_certs(bundle.as_bytes()).expect("bundle parses");
        assert_eq!(
            certs
                .iter()
                .map(|cert| cert.as_ref().to_vec())
                .collect::<Vec<_>>(),
            vec![vec![b'M', b'a'], vec![b'M']]
        );
        assert!(parse_pem_certs(b"").expect("empty parses").is_empty());
    }

    #[test]
    fn pem_rejects_bad_framing() {
        for bad in [
            "-----BEGIN CERTIFICATE-----\nMAMCABU=\n-----BEGIN CERTIFICATE-----\nMAMCABU=\n-----END CERTIFICATE-----\n",
            "-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMAMCABU=\n",
            "-----BEGIN CERTIFICATE-----\n****\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAB=C\n-----END CERTIFICATE-----\n",
        ] {
            assert!(parse_pem_certs(bad.as_bytes()).is_err(), "{bad:?}");
        }
        assert!(
            parse_pem_certs("not pem at all".as_bytes())
                .expect("text")
                .is_empty()
        );
    }

    #[test]
    fn tls_roots_reject_unusable_bundles() {
        assert!(tls_config_with_roots(b"").is_err());
        assert!(
            tls_config_with_roots(
                b"-----BEGIN CERTIFICATE-----\nTQ==\n-----END CERTIFICATE-----\n"
            )
            .is_err()
        );
        assert!(parse_pem_certs(b"caf\xe9").is_err());
    }
}
