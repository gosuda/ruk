//! git smart-http client: stateless upload-pack and receive-pack over
//! HTTP(S).
//!
//! One `GET <base>/info/refs?service=<svc>` returns the pkt-line
//! advertisement (parsed by the same [`crate::transport::refadv`] grammar
//! as the stateful transports), then one `POST <base>/<svc>` carries the
//! whole request — wants, haves and `done`, or ref commands plus the pack
//! — and the response carries the same bytes the stateful server would
//! have written (NAK/ACK lines plus a side-band pack, or a report-status
//! document). Pack ingest, closure verification and push-plan states are
//! the shared [`crate::transport::fetch`] and [`crate::transport::push`]
//! halves; only the framing round-trips are HTTP.
//!
//! Negotiation mirrors the stateful v0 clients byte for byte (capability
//! lists, warning strings, report coverage), except the fetch ACK loop:
//! the single POST already contains `done`, so per-have verdicts (which
//! always carry a `continue`/`common`/`ready` suffix) are consumed and
//! only the bare post-`done` verdict ends the preamble. Stateful clients
//! break on the first verdict to send `done`; there is no second round
//! here.
//!
//! Auth follows the per-call [`credentials::AuthPolicy`] every RPC takes:
//! `Explicit` sends only the injected credential inside its origin and
//! never consults a helper or the environment, while `Ambient` resolves
//! the helper chain from the caller map, then that map's Bearer/Basic.
//! `http.<url>.extraHeader` lines join every request: the caller resolves
//! them from config for the base through
//! [`extra_headers_for_url`](crate::transport::http::extra_headers_for_url)
//! and passes them in as `extra_headers`.
//!
//! Fetch tries protocol v2 first ([`discover_v2_caps`] plus the
//! [`ls_refs_v2`]/[`fetch_pack_v2`] command RPCs in
//! [`crate::transport::proto_v2`]) and falls back to the v0 document
//! below when the server answers one.
//!
//! Named gaps beside this module: dumb-http (a server answering
//! `info/refs` without the smart advertisement document; fetch falls back
//! to [`crate::transport::dumb_http`]), `git-upload-archive` over
//! HTTP (the client lives in [`fetch_archive`] but no archive-reading
//! verb consumes it), and POST redirects (smart RPC endpoints never emit
//! them; a 3xx names its `Location` in the error).
//!
//! Oracle anchors: `git/remote-curl.c` (`discover_refs`, `check_smart_http`,
//! `rpc_service`, `fetch_git`), `git/fetch-pack.c` (`--stateless-rpc`
//! request shape, `send_request`), `git/send-pack.c` (stateless command
//! plus pack body), `git/upload-pack.c` (`--stateless-rpc` single-round
//! contract: wants to flush, haves to `done`), `git/builtin/receive-pack.c`
//! (commands to flush, pack to end of body), `git/Documentation/gitprotocol-http.adoc`.

use std::collections::HashMap;
use std::io::{Cursor, Read as _};

use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::Store;

use super::Interrupt;
use super::credentials;
use super::fetch::{self, FetchWireRequest, ReceivedPack};
use super::http;
use super::net;
use super::pack::IngestLimits;
use super::pktline::{self, PktReader};
use super::proto_v2;
use super::push::{self, PushPlanRecord, PushWireRequest, RefOutcome};
use super::refadv::{self, AdvertisedRef, Advertisement, Capabilities, Initial};
use crate::{GitError, parse_oid_for};

/// Which smart service one RPC round trip speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmartService {
    /// `git-upload-pack`: the server sends objects.
    UploadPack,
    /// `git-receive-pack`: the server accepts objects.
    ReceivePack,
    /// `git-upload-archive`: the server streams a tar archive. Only the
    /// RPC half uses this name. Default servers refuse discovery through
    /// it (`Service not enabled`, `git/http-backend.c` `select_service`;
    /// archive discovery needs `http.uploadarchive`), and the oracle
    /// probes protocol support through `git-upload-pack` instead
    /// (`git/remote-curl.c` `stateless_connect`), so no client here
    /// requires archive discovery.
    UploadArchive,
}

impl SmartService {
    /// The service name in URLs and `# service=` preambles.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
            Self::UploadArchive => "git-upload-archive",
        }
    }

    /// The `Content-Type` a discovery response must carry
    /// (`git/remote-curl.c` `check_smart_http` matches it exactly, and so
    /// does this client: anything else is dumb-http).
    #[must_use]
    pub fn advertisement_type(self) -> String {
        format!("application/x-{}-advertisement", self.name())
    }

    /// The `Content-Type` one RPC request carries.
    #[must_use]
    pub fn request_type(self) -> String {
        format!("application/x-{}-request", self.name())
    }

    /// The `Content-Type` one RPC response must carry.
    #[must_use]
    pub fn result_type(self) -> String {
        format!("application/x-{}-result", self.name())
    }
}

/// Normalizes an endpoint URL to the RPC base: the URL as spelled minus
/// trailing slashes, so `info/refs` and service paths join with one `/`.
///
/// # Errors
/// [`GitError::Invalid`] for a non-HTTP URL (checked through
/// [`http::url_authority`], which owns URL validation).
pub fn normalize_base(url: &str) -> Result<String, GitError> {
    http::url_authority(url)?;
    let base = url.trim_end_matches('/');
    if base.is_empty() {
        return Err(GitError::Invalid {
            detail: format!("http remote {url:?} has no usable base"),
        });
    }
    Ok(base.to_owned())
}

/// The discovery URL: `<base>/info/refs?service=<svc>`. A base that
/// already carries a query string keeps it after the service parameter,
/// so no server-side parameter is lost.
#[must_use]
pub fn refs_url(base: &str, service: SmartService) -> String {
    let (path, query) = match base.split_once('?') {
        Some((path, query)) => (path, format!("&{query}")),
        None => (base, String::new()),
    };
    format!("{path}/info/refs?service={}{query}", service.name())
}

/// The RPC URL: `<base>/<svc>`.
#[must_use]
pub fn rpc_url(base: &str, service: SmartService) -> String {
    format!("{base}/{}", service.name())
}

/// Builds owned request headers from `extra_headers` (resolved
/// `http.extraHeader` rows for `url`) plus `extra` plus the helper-then-
/// environment auth header for `url`, when either carries credentials.
/// [`request_headers_with`] is the pure seam tests inject a stub helper
/// through; live callers pass the process environment.
#[must_use]
pub fn request_headers(
    url: &str,
    vars: &HashMap<String, String>,
    extra: &[(&str, &str)],
    extra_headers: &[(String, String)],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = extra_headers.to_vec();
    out.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    if let Some((name, value)) = credentials::auth_header_for_url(url, vars) {
        out.push((name, value));
    }
    out
}

/// Builds owned request headers from `extra_headers` plus `extra` plus the
/// auth header the `runner` helper chain (or, failing that, `vars`) yields
/// for `url`.
#[must_use]
pub fn request_headers_with(
    url: &str,
    vars: &HashMap<String, String>,
    extra: &[(&str, &str)],
    helpers: &[(String, Vec<String>)],
    runner: impl Fn(&str, &[String], &[u8]) -> Option<Vec<u8>>,
    extra_headers: &[(String, String)],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = extra_headers.to_vec();
    out.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    if let Some((name, value)) = credentials::auth_header_for_url_with(url, vars, helpers, runner) {
        out.push((name, value));
    }
    out
}

/// Builds owned request headers under `auth`: the `Explicit` policy sends
/// only the injected credential inside its origin and never consults a
/// helper or the environment, while `Ambient` resolves the helper chain
/// from its own vars map, then falls back to that map's Bearer/Basic.
#[must_use]
pub fn policy_headers(
    url: &str,
    auth: &credentials::AuthPolicy,
    extra: &[(&str, &str)],
    extra_headers: &[(String, String)],
) -> Vec<(String, String)> {
    match auth {
        credentials::AuthPolicy::Explicit { auth } => {
            let mut out: Vec<(String, String)> = extra_headers.to_vec();
            out.extend(
                extra
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
            );
            if let Some(header) = auth.header_for(url) {
                out.push(header);
            }
            out
        }
        credentials::AuthPolicy::Ambient { vars } => {
            credentials::ambient_headers_for_url(url, vars, extra, extra_headers)
        }
    }
}

/// The per-call controls every smart-http RPC takes together: the resolved
/// `http.extraHeader` rows for the base, the credential policy the call
/// authenticates under, and the cancellation/deadline interrupt. No `Debug`:
/// the extra rows can carry credentials, so the context never prints.
#[derive(Clone, Copy)]
pub struct RpcCall<'a> {
    /// Resolved `http.extraHeader` rows for the base.
    pub extra: &'a [(String, String)],
    /// The credential policy this call authenticates under.
    pub auth: &'a credentials::AuthPolicy,
    /// Deadline and cancellation shared by the call's transfer steps.
    pub interrupt: &'a Interrupt,
}

impl std::fmt::Debug for RpcCall<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RpcCall")
            .field("extra", &format_args!("<{} rows>", self.extra.len()))
            .field("auth", self.auth)
            .field("interrupt", self.interrupt)
            .finish()
    }
}

/// Borrows owned headers for the HTTP client.
fn borrow(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

/// The injected credential this call authenticates with, if any: a server
/// echoing it back in an error body must not leak it into the refusal.
fn auth_secrets(auth: &credentials::AuthPolicy) -> Vec<String> {
    match auth {
        credentials::AuthPolicy::Explicit { auth } if !auth.credential.is_empty() => {
            vec![auth.credential.clone()]
        }
        _ => Vec::new(),
    }
}

/// Scrubs one raw response body for refusal text: userinfo shapes first,
/// then the call's own credential, capped at 512 bytes on a boundary.
fn scrubbed_preview(preview: &[u8], secrets: &[String]) -> String {
    let scrubbed = credentials::scrub_secrets(&credentials::scrub_userinfo_bytes(preview), secrets);
    let text = String::from_utf8_lossy(&scrubbed);
    let mut end = text.len().min(512);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// The honest refusal behind one non-2xx RPC status: 401/403 forbid
/// (rotate the token), 404 misses, 429 limits, 3xx moves, anything else is
/// offline. The status classifies the [`GitError::Http`] code, and the
/// scrubbed facts travel into the core error detail for reply builders.
fn http_failure(
    url: &str,
    status: u16,
    retry_after_seconds: Option<u64>,
    location: Option<String>,
    preview_text: &str,
) -> GitError {
    let detail = match status {
        401 | 403 => format!("{url}: authentication failed with status {status}"),
        404 => format!("{url}: repository not found"),
        429 => match retry_after_seconds {
            Some(secs) => format!("{url}: rate limited with status 429, retry after {secs}s"),
            None => format!("{url}: rate limited with status 429"),
        },
        300..=399 => match &location {
            Some(target) => format!("{url}: remote moved to {target}"),
            None => format!("{url}: redirect without a location"),
        },
        _ => format!("{url}: smart-http endpoint refused status {status}"),
    };
    let detail = if preview_text.is_empty() {
        detail
    } else {
        format!("{detail}; body: {preview_text}")
    };
    GitError::Http {
        detail,
        status,
        retry_after_seconds,
        location,
        body_preview: preview_text.to_owned(),
    }
}

/// Reads the retry delay and redirect target off one refusal's headers.
/// The target is scrubbed like a body: a redirect may echo the credential.
fn refusal_facts(reply: &[(String, String)], secrets: &[String]) -> (Option<u64>, Option<String>) {
    let retry_after_seconds =
        http::header(reply, "retry-after").and_then(|value| value.trim().parse::<u64>().ok());
    let location = http::header(reply, "location").map(|target| {
        String::from_utf8_lossy(&credentials::scrub_secrets(
            credentials::scrub_userinfo_bytes(target.as_bytes()).as_slice(),
            secrets,
        ))
        .into_owned()
    });
    (retry_after_seconds, location)
}

/// Maps a non-2xx RPC status to its honest error: 401/403 forbid (rotate
/// the token), 404 misses, 429 limits, 3xx moves, anything else is offline.
/// GET responses carry no body, so the preview is empty there.
fn check_status(
    url: &str,
    status: u16,
    reply: &[(String, String)],
    auth: &credentials::AuthPolicy,
) -> Result<(), GitError> {
    if http::is_success(status) {
        return Ok(());
    }
    let (retry_after_seconds, location) = refusal_facts(reply, &auth_secrets(auth));
    Err(http_failure(url, status, retry_after_seconds, location, ""))
}

/// Maps a non-2xx POST status, draining a bounded body preview first so
/// the refusal can name what the server said. The drain is one capped
/// read scrubbed against the call's own credential; framing errors yield
/// an empty preview rather than a failure.
fn check_post_status(
    url: &str,
    reader: &mut http::HttpBodyReader,
    status: u16,
    reply: &[(String, String)],
    auth: &credentials::AuthPolicy,
) -> Result<(), GitError> {
    if http::is_success(status) {
        return Ok(());
    }
    let mut raw = [0u8; 1024];
    let len = reader.read(&mut raw).unwrap_or(0);
    let secrets = auth_secrets(auth);
    let preview = scrubbed_preview(&raw[..len], &secrets);
    let (retry_after_seconds, location) = refusal_facts(reply, &secrets);
    Err(http_failure(
        url,
        status,
        retry_after_seconds,
        location,
        &preview,
    ))
}

/// Discovers one smart-http endpoint's refs: GETs the advertisement and
/// parses it with the shared v0 grammar. A response without the smart
/// content type is dumb-http, the remaining HTTP gap. Callers that speak
/// v2 probe with [`discover_v2_caps`] first and only reach this fallback
/// on v0 servers.
///
/// # Errors
/// Transport failures from the HTTP client, [`GitError::Unsupported`] for
/// dumb-http servers and for v2 advertisements arriving without the
/// `Git-Protocol` probe, grammar failures from the advertisement parse.
pub fn discover(
    base: &str,
    service: SmartService,
    kind: HashKind,
    extra_headers: &[(String, String)],
    auth: &credentials::AuthPolicy,
) -> Result<Advertisement, GitError> {
    let url = refs_url(base, service);
    let owned = policy_headers(&url, auth, &[("Accept", "*/*")], extra_headers);
    let mut body = Vec::new();
    let (status, reply) = http::get_to_writer(&url, &borrow(&owned), &mut body)?;
    check_status(&url, status, &reply, auth)?;
    if http::header(&reply, "content-type") != Some(service.advertisement_type().as_str()) {
        return Err(net::dumb_http_gap(&url));
    }
    let mut pkt = PktReader::new(Cursor::new(body), Interrupt::none());
    match refadv::read_initial(&mut pkt, kind)? {
        Initial::Refs(adv) => Ok(adv),
        Initial::V2(_) => Err(GitError::Unsupported {
            command:
                "protocol v2 without the Git-Protocol header: probe with discover_v2_caps first"
                    .to_owned(),
        }),
    }
}

/// What one `Git-Protocol` advertisement GET established: the v2
/// capability advertisement, or the parsed v0 document from a server
/// that ignored the header — from that single response, with no second
/// round trip for the fallback.
#[derive(Debug)]
pub enum VersionedDiscovery {
    /// The server speaks v2: refs come from one [`ls_refs_v2`] RPC.
    V2(Capabilities),
    /// The server answered v0: the parsed advertisement, reused directly.
    V0(Advertisement),
}

/// Discovers one smart-http endpoint at the highest protocol the server
/// offers: GETs the advertisement with `Git-Protocol: version=2`
/// (`gitprotocol-v2.adoc`, "HTTP Transport") and parses whatever answers —
/// the v2 capability advertisement, or the v0 document when the server
/// ignored the header. A response without the smart content type is
/// dumb-http, the remaining HTTP gap.
///
/// # Errors
/// Transport failures from the HTTP client, [`GitError::Unsupported`] for
/// dumb-http servers, grammar failures from the advertisement parse.
pub fn discover_versioned(
    base: &str,
    service: SmartService,
    kind: HashKind,
    extra_headers: &[(String, String)],
    auth: &credentials::AuthPolicy,
) -> Result<VersionedDiscovery, GitError> {
    let url = refs_url(base, service);
    let owned = policy_headers(
        &url,
        auth,
        &[
            ("Accept", "*/*"),
            (
                proto_v2::GIT_PROTOCOL_HEADER,
                proto_v2::GIT_PROTOCOL_V2_VALUE,
            ),
        ],
        extra_headers,
    );
    let mut body = Vec::new();
    let (status, reply) = http::get_to_writer(&url, &borrow(&owned), &mut body)?;
    check_status(&url, status, &reply, auth)?;
    if http::header(&reply, "content-type") != Some(service.advertisement_type().as_str()) {
        return Err(net::dumb_http_gap(&url));
    }
    let mut pkt = PktReader::new(Cursor::new(body), Interrupt::none());
    match refadv::read_initial(&mut pkt, kind)? {
        Initial::V2(caps) => Ok(VersionedDiscovery::V2(caps)),
        Initial::Refs(adv) => Ok(VersionedDiscovery::V0(adv)),
    }
}

/// Reads one smart-http endpoint's refs over protocol v2: POSTs
/// `command=ls-refs` and parses the response. `caps` is the
/// [`discover_v2_caps`] probe for this base.
///
/// # Errors
/// Transport failures from the HTTP client and grammar failures from the
/// `ls-refs` parse.
pub fn ls_refs_v2(
    base: &str,
    caps: &Capabilities,
    kind: HashKind,
    prefixes: &[&[u8]],
    call: RpcCall<'_>,
) -> Result<Vec<AdvertisedRef>, GitError> {
    let RpcCall {
        extra: extra_headers,
        auth,
        interrupt,
    } = call;
    let body = proto_v2::ls_refs_request(
        caps,
        kind,
        &proto_v2::LsRefsCommand::advertisement(
            prefixes.iter().map(|prefix| prefix.to_vec()).collect(),
        ),
    )?;
    let url = rpc_url(base, SmartService::UploadPack);
    let request_type = SmartService::UploadPack.request_type();
    let result_type = SmartService::UploadPack.result_type();
    let owned = policy_headers(
        &url,
        auth,
        &[
            ("Content-Type", request_type.as_str()),
            ("Accept", result_type.as_str()),
            (
                proto_v2::GIT_PROTOCOL_HEADER,
                proto_v2::GIT_PROTOCOL_V2_VALUE,
            ),
        ],
        extra_headers,
    );
    let (mut reader, status, reply) = http::post_open(&url, &borrow(&owned), &body)?;
    check_post_status(&url, &mut reader, status, &reply, auth)?;
    if http::header(&reply, "content-type") != Some(result_type.as_str()) {
        return Err(GitError::Corrupt {
            detail: format!("{url}: ls-refs RPC answered a non-pack content type"),
        });
    }
    let mut pkt = PktReader::new(reader, interrupt.clone());
    refadv::read_ls_refs(&mut pkt, kind)
}

/// Fetches one pack over smart-http with protocol v2: POSTs
/// `command=fetch` and ingests the sectioned response, returning the
/// staging without publishing anything. Capability gating and fallback
/// warnings match the stateful v2 client; `caps` is the
/// [`discover_v2_caps`] probe for this base. `list_refs` needs no arm
/// here: refs arrive through [`ls_refs_v2`], a separate RPC, before the
/// fetch POST.
///
/// # Errors
/// Grammar failures are [`GitError::Corrupt`]; see
/// [`super::pack::ingest_pack`] for pack errors.
pub fn fetch_pack_v2(
    base: &str,
    caps: &Capabilities,
    store: &Store,
    req: &FetchWireRequest,
    limits: IngestLimits,
    call: RpcCall<'_>,
) -> Result<ReceivedPack, GitError> {
    let RpcCall {
        extra: extra_headers,
        auth,
        interrupt,
    } = call;
    if req.wants.is_empty() {
        return Err(GitError::Invalid {
            detail: "fetch needs at least one want".to_owned(),
        });
    }
    let kind = store.hash_kind();
    let mut warnings = Vec::new();
    let filter = match req.filter {
        Some(filter) if caps.feature("fetch", "filter") => Some(filter),
        Some(filter) => {
            warnings.push(format!(
                "server lacks filter; fetched full objects instead of {}",
                filter.spec()
            ));
            None
        }
        None => None,
    };
    let depth = match req.depth {
        Some(depth) if caps.feature("fetch", "shallow") => Some(depth),
        Some(_) => {
            warnings.push("server lacks shallow; fetched complete history".to_owned());
            None
        }
        None => None,
    };
    let cmd = proto_v2::FetchCommand {
        wants: &req.wants,
        haves: &req.haves,
        shallows: &req.shallow,
        depth,
        filter,
        thin_pack: caps.feature("fetch", "thin-pack"),
        ofs_delta: caps.feature("fetch", "ofs-delta"),
        sideband_all: caps.feature("fetch", "sideband-all"),
    };
    let body = proto_v2::fetch_request(caps, kind, &cmd)?;
    let url = rpc_url(base, SmartService::UploadPack);
    let request_type = SmartService::UploadPack.request_type();
    let result_type = SmartService::UploadPack.result_type();
    let owned = policy_headers(
        &url,
        auth,
        &[
            ("Content-Type", request_type.as_str()),
            ("Accept", result_type.as_str()),
            (
                proto_v2::GIT_PROTOCOL_HEADER,
                proto_v2::GIT_PROTOCOL_V2_VALUE,
            ),
        ],
        extra_headers,
    );
    let (mut reader, status, reply) = http::post_open(&url, &borrow(&owned), &body)?;
    check_post_status(&url, &mut reader, status, &reply, auth)?;
    if http::header(&reply, "content-type") != Some(result_type.as_str()) {
        return Err(GitError::Corrupt {
            detail: format!("{url}: fetch RPC answered a non-pack content type"),
        });
    }
    let mut pkt = PktReader::new(reader, interrupt.clone());
    let sections = proto_v2::read_fetch_response(&mut pkt, kind, store, limits, interrupt)?;
    Ok(ReceivedPack {
        staged: sections.staged,
        shallow: sections.shallow,
        unshallow: sections.unshallow,
        warnings,
        progress: sections.progress,
        refs: Vec::new(),
    })
}

/// Exact equality with `NAK`, mirroring the stateful fetch client.
fn is_nak(line: &[u8]) -> bool {
    line.len() == 3 && line.starts_with(b"NAK")
}

/// Reads a server OID the way the stateful fetch client does.
fn parse_server_oid(field: &[u8], kind: HashKind) -> Result<Oid, GitError> {
    let text = std::str::from_utf8(field).map_err(|_| GitError::Corrupt {
        detail: "server sent a non-ASCII object id".to_owned(),
    })?;
    parse_oid_for(text, kind).map_err(|err| match err {
        GitError::ObjectFormat { detail } => GitError::ObjectFormat { detail },
        other => GitError::Corrupt {
            detail: other.to_string(),
        },
    })
}

/// Fetches one pack over smart-http: POSTs the whole v0 request (wants,
/// haves, `done`) and ingests the streamed response, returning the
/// staging without publishing anything. The caller verifies and publishes
/// exactly like the stateful fetch half.
///
/// Capability lists and fallback warnings match the stateful client byte
/// for byte; `adv` is the [`discover`] document for this base.
///
/// # Errors
/// Grammar failures are [`GitError::Corrupt`]; see
/// [`super::pack::ingest_pack`] for pack errors.
pub fn fetch_pack(
    base: &str,
    adv: &Advertisement,
    store: &Store,
    req: &FetchWireRequest,
    limits: IngestLimits,
    call: RpcCall<'_>,
) -> Result<ReceivedPack, GitError> {
    let RpcCall {
        extra: extra_headers,
        auth,
        interrupt,
    } = call;
    if req.wants.is_empty() {
        return Err(GitError::Invalid {
            detail: "fetch needs at least one want".to_owned(),
        });
    }
    let kind = store.hash_kind();
    let caps = &adv.capabilities;
    let mut warnings = Vec::new();
    let filter = match req.filter {
        Some(filter) if caps.has("filter") => Some(filter),
        Some(filter) => {
            warnings.push(format!(
                "server lacks filter; fetched full objects instead of {}",
                filter.spec()
            ));
            None
        }
        None => None,
    };
    let depth = match req.depth {
        Some(depth) if caps.has("shallow") => Some(depth),
        Some(_) => {
            warnings.push("server lacks shallow; fetched complete history".to_owned());
            None
        }
        None => None,
    };
    let mut caps_list = vec!["multi_ack_detailed", "thin-pack", "ofs-delta"];
    let sideband = if caps.has("side-band-64k") {
        caps_list.push("side-band-64k");
        Some(pktline::LARGE_PACKET_MAX)
    } else if caps.has("side-band") {
        caps_list.push("side-band");
        Some(pktline::SMALL_SIDEBAND_MAX)
    } else {
        None
    };
    if filter.is_some() {
        caps_list.push("filter");
    }
    if caps.has("object-format") {
        caps_list.push(match kind {
            HashKind::Sha1 => "object-format=sha1",
            HashKind::Sha256 => "object-format=sha256",
        });
    }
    caps_list.push("agent=ruk");
    let mut out = Vec::new();
    for (index, want) in req.wants.iter().enumerate() {
        let mut line = format!("want {want}");
        if index == 0 {
            line.push(' ');
            line.push_str(&caps_list.join(" "));
        }
        line.push('\n');
        pktline::encode_data(&mut out, line.as_bytes())?;
    }
    for oid in &req.shallow {
        pktline::encode_data(&mut out, format!("shallow {oid}\n").as_bytes())?;
    }
    if let Some(depth) = depth {
        pktline::encode_data(&mut out, format!("deepen {depth}\n").as_bytes())?;
    }
    if let Some(filter) = filter {
        pktline::encode_data(&mut out, format!("filter {}\n", filter.spec()).as_bytes())?;
    }
    pktline::encode_flush(&mut out);
    for oid in &req.haves {
        pktline::encode_data(&mut out, format!("have {oid}\n").as_bytes())?;
    }
    pktline::encode_data(&mut out, b"done\n")?;
    // Closes the single stateless round the way `send_request` does in
    // `git/fetch-pack.c`: the server breaks on `done` and leaves this
    // flush unread.
    pktline::encode_flush(&mut out);
    let url = rpc_url(base, SmartService::UploadPack);
    let request_type = SmartService::UploadPack.request_type();
    let result_type = SmartService::UploadPack.result_type();
    let owned = policy_headers(
        &url,
        auth,
        &[
            ("Content-Type", request_type.as_str()),
            ("Accept", result_type.as_str()),
        ],
        extra_headers,
    );
    let (mut reader, status, reply) = http::post_open(&url, &borrow(&owned), &out)?;
    check_post_status(&url, &mut reader, status, &reply, auth)?;
    if http::header(&reply, "content-type") != Some(SmartService::UploadPack.result_type().as_str())
    {
        return Err(GitError::Corrupt {
            detail: format!("{url}: upload-pack RPC answered a non-pack content type"),
        });
    }
    let mut pkt = PktReader::new(reader, interrupt.clone());
    let mut shallow = Vec::new();
    let mut unshallow = Vec::new();
    let mut ack_bytes = 0usize;
    loop {
        interrupt.check("negotiating the fetch")?;
        let line = pkt.read_line("an acknowledgement")?.to_vec();
        ack_bytes += line.len();
        if ack_bytes > ruk_core::MAX_CONTROL_FRAME_BYTES {
            return Err(GitError::Limit {
                detail: "fetch negotiation exceeds the control bound".to_owned(),
            });
        }
        if let Some(rest) = line.strip_prefix(b"shallow ") {
            shallow.push(parse_server_oid(rest, kind)?);
        } else if let Some(rest) = line.strip_prefix(b"unshallow ") {
            unshallow.push(parse_server_oid(rest, kind)?);
        } else if is_nak(&line) {
            break;
        } else if line.starts_with(b"ACK ") {
            // Single-round stateless: per-have verdicts always carry a
            // suffix, so only the bare post-`done` verdict ends the
            // preamble. Stateful clients break on the first verdict to
            // send `done`; ours is already sent.
            let suffixed = line.ends_with(b"continue")
                || line.ends_with(b"common")
                || line.ends_with(b"ready");
            if !suffixed {
                break;
            }
        } else {
            return Err(GitError::Corrupt {
                detail: format!("unexpected acknowledgement {}", line.escape_ascii()),
            });
        }
    }
    let (staged, progress) =
        fetch::read_pack_section(&mut pkt, sideband, kind, store, limits, interrupt)?;
    Ok(ReceivedPack {
        staged,
        shallow,
        unshallow,
        warnings,
        progress,
        refs: Vec::new(),
    })
}

/// Pushes over smart-http: POSTs the ref commands plus the pack in one
/// body and parses the streamed report, walking the same plan states as
/// the stateful push half. `adv` is the [`discover`] document for the
/// receive-pack service at this base.
///
/// # Errors
/// Capability, grammar, transport and store failures. Any error from
/// [`PushPlanRecord::begin_send`] onward persists `Uncertain` best-effort
/// before returning, exactly like [`super::push::push_over`].
pub fn push_pack(
    base: &str,
    adv: &Advertisement,
    store: &Store,
    plan: &mut PushPlanRecord,
    req: &PushWireRequest,
    call: RpcCall<'_>,
) -> Result<Vec<RefOutcome>, GitError> {
    if req.updates.is_empty() {
        return Err(GitError::Invalid {
            detail: "push needs at least one update".to_owned(),
        });
    }
    if plan.updates != req.updates || plan.atomic != req.atomic {
        return Err(GitError::Invalid {
            detail: "push plan does not match the push request".to_owned(),
        });
    }
    for update in &req.updates {
        if update.name.is_empty() || update.name.iter().any(|b| *b == 0 || *b == b'\n') {
            return Err(GitError::Invalid {
                detail: "push update carries a malformed ref name".to_owned(),
            });
        }
    }
    let kind = store.hash_kind();
    push::persist(store, plan, kind, None)?;
    let outcome = push_pack_inner(base, adv, store, plan, req, call);
    match outcome {
        Ok(outcomes) => Ok(outcomes),
        Err(err) => {
            plan.mark_uncertain();
            push::persist_best_effort(store, plan, kind);
            Err(err)
        }
    }
}

fn push_pack_inner(
    base: &str,
    adv: &Advertisement,
    store: &Store,
    plan: &mut PushPlanRecord,
    req: &PushWireRequest,
    call: RpcCall<'_>,
) -> Result<Vec<RefOutcome>, GitError> {
    let RpcCall {
        extra: extra_headers,
        auth,
        interrupt,
    } = call;
    let kind = store.hash_kind();
    let caps = &adv.capabilities;
    let report_v2 = caps.has("report-status-v2");
    if !report_v2 && !caps.has("report-status") {
        plan.begin_send()?;
        push::persist(store, plan, kind, push::current_encoding(store, plan)?)?;
        return Err(GitError::PushUncertain {
            detail: "server reports no push status; outcomes cannot be confirmed".to_owned(),
        });
    }
    let zero = kind.zero_oid();
    if req.updates.iter().any(|u| u.new == zero) && !caps.has("delete-refs") {
        return Err(GitError::Invalid {
            detail: "server does not advertise delete-refs".to_owned(),
        });
    }
    if req.atomic && !caps.has("atomic") {
        return Err(GitError::Invalid {
            detail: "server does not advertise atomic".to_owned(),
        });
    }
    let advertised: HashMap<&[u8], Oid> = adv
        .refs
        .iter()
        .filter_map(|r| r.oid.map(|oid| (r.name.as_slice(), oid)))
        .collect();
    let mut live: Vec<&push::PushUpdate> = Vec::with_capacity(req.updates.len());
    let mut outcomes: Vec<RefOutcome> = Vec::with_capacity(req.updates.len());
    for update in &req.updates {
        match advertised.get(update.name.as_slice()) {
            Some(current) if *current != update.old => outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: super::push::RefResult::Rejected {
                    reason: format!(
                        "remote ref moved: advertised {current}, expected {}",
                        update.old
                    ),
                },
            }),
            None if update.old != zero => outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: super::push::RefResult::Rejected {
                    reason: "remote ref is absent".to_owned(),
                },
            }),
            _ => live.push(update),
        }
    }
    if !outcomes.is_empty() && req.atomic {
        for update in live {
            outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: super::push::RefResult::Rejected {
                    reason: "atomic push refused locally: a sibling ref moved".to_owned(),
                },
            });
        }
        plan.refuse_locally(outcomes.clone())?;
        push::persist(store, plan, kind, push::current_encoding(store, plan)?)?;
        return Ok(outcomes);
    }
    if live.is_empty() {
        plan.refuse_locally(outcomes.clone())?;
        push::persist(store, plan, kind, push::current_encoding(store, plan)?)?;
        return Ok(outcomes);
    }
    let sideband = if caps.has("side-band-64k") {
        Some(pktline::LARGE_PACKET_MAX)
    } else if caps.has("side-band") {
        Some(pktline::SMALL_SIDEBAND_MAX)
    } else {
        None
    };
    let mut caps_list = vec![if report_v2 {
        "report-status-v2"
    } else {
        "report-status"
    }];
    if sideband == Some(pktline::LARGE_PACKET_MAX) {
        caps_list.push("side-band-64k");
    } else if sideband.is_some() {
        caps_list.push("side-band");
    }
    if caps.has("ofs-delta") {
        caps_list.push("ofs-delta");
    }
    if caps.has("atomic") && req.atomic {
        caps_list.push("atomic");
    }
    if caps.has("object-format") {
        caps_list.push(match kind {
            HashKind::Sha1 => "object-format=sha1",
            HashKind::Sha256 => "object-format=sha256",
        });
    }
    caps_list.push("agent=ruk");
    let mut out = Vec::new();
    for (index, update) in live.iter().enumerate() {
        let mut line = format!(
            "{} {} {}",
            update.old.to_hex(),
            update.new.to_hex(),
            String::from_utf8_lossy(&update.name)
        );
        if index == 0 {
            line.push('\0');
            line.push_str(&caps_list.join(" "));
        }
        line.push('\n');
        pktline::encode_data(&mut out, line.as_bytes())?;
    }
    pktline::encode_flush(&mut out);
    plan.begin_send()?;
    push::persist(store, plan, kind, push::current_encoding(store, plan)?)?;
    let mut entries = push::push_closure(store, kind, &live, interrupt)?;
    push::pair_thin_bases(store, kind, &live, &mut entries, interrupt)?;
    if !entries.is_empty() {
        let pack_entries: Vec<super::pack::PackEntry<'_>> =
            entries.iter().map(|entry| entry.as_entry()).collect();
        interrupt.check("sending the pack")?;
        if entries.iter().any(|entry| entry.base.is_some()) {
            super::pack::write_thin_pack(&mut out, kind, &pack_entries, interrupt)?;
        } else {
            super::pack::write_pack(&mut out, kind, &pack_entries, interrupt)?;
        }
    }
    // Closes the stateless round after the pack (`git/send-pack.c`
    // appends it the same way); the server reads the pack to the end of
    // the POST body and this flush stays unread.
    pktline::encode_flush(&mut out);
    let url = rpc_url(base, SmartService::ReceivePack);
    let request_type = SmartService::ReceivePack.request_type();
    let result_type = SmartService::ReceivePack.result_type();
    let owned = policy_headers(
        &url,
        auth,
        &[
            ("Content-Type", request_type.as_str()),
            ("Accept", result_type.as_str()),
        ],
        extra_headers,
    );
    let (mut reader, status, reply) = http::post_open(&url, &borrow(&owned), &out)?;
    check_post_status(&url, &mut reader, status, &reply, auth)?;
    if http::header(&reply, "content-type")
        != Some(SmartService::ReceivePack.result_type().as_str())
    {
        plan.mark_uncertain();
        push::persist_best_effort(store, plan, kind);
        return Err(GitError::Corrupt {
            detail: format!("{url}: receive-pack RPC answered a non-report content type"),
        });
    }
    let mut pkt = PktReader::new(reader, interrupt.clone());
    let server = push::read_report(&mut pkt, sideband)?;
    push::check_report_covers_live(&live, &server)?;
    let mut report = server;
    report.extend(outcomes);
    plan.finalize(report.clone())?;
    push::persist(store, plan, kind, push::current_encoding(store, plan)?)?;
    Ok(report)
}

/// One `git-upload-archive` request: the revision to archive. Only `tar`
/// is spoken (the server default when the format line is absent), so the
/// request carries no format choice.
#[derive(Debug)]
pub struct ArchiveWireRequest {
    /// Revision as spelled (`HEAD`, a ref, or a full OID).
    pub rev: String,
}

/// Builds the `git-upload-archive` RPC body: one `argument --format=tar`
/// line, one `argument <rev>` line, and the closing flush, the same
/// framing `git/builtin/archive.c` (`run_remote_archiver`) sends, and
/// [`crate::transport::archive::serve_upload_archive`] reads.
pub fn archive_request_body(rev: &str) -> Result<Vec<u8>, GitError> {
    if rev.is_empty() || rev.bytes().any(|byte| byte == b'\n' || byte == 0) {
        return Err(GitError::Invalid {
            detail: format!("archive revision is not one line: {rev:?}"),
        });
    }
    let mut out = Vec::new();
    pktline::encode_data(&mut out, b"argument --format=tar\n")?;
    pktline::encode_data(&mut out, format!("argument {rev}\n").as_bytes())?;
    pktline::encode_flush(&mut out);
    Ok(out)
}

/// One fetched archive: the raw tar stream plus any progress text the
/// server sent on band 2.
#[derive(Debug)]
pub struct ArchiveOutput {
    /// The tar bytes in arrival order.
    pub tar: Vec<u8>,
    /// Progress text gathered from side-band 2.
    pub progress: pktline::RemoteMessages,
}

/// Fetches one tar archive over smart-http: POSTs the argument payload to
/// `<base>/git-upload-archive` and demuxes the sideband tar. This POST half
/// needs no advertisement caps, so it takes the base directly and skips the
/// discovery round trip; the oracle likewise probes protocol support
/// through `git-upload-pack`, not this service (`git/remote-curl.c`
/// `stateless_connect`, and protocol v2 over HTTP is already a named gap
/// here).
///
/// A `NACK` line naming an unknown revision is [`GitError::NotFound`]; any
/// other refusal is [`GitError::Corrupt`]. No verb consumes this yet: the
/// `archive` verb writes no archives, local or remote, so the client stays
/// a named gap at the verb layer.
///
/// # Errors
/// Grammar failures are [`GitError::Corrupt`]; see [`check_status`] for
/// transport failures.
pub fn fetch_archive(
    base: &str,
    req: &ArchiveWireRequest,
    interrupt: &Interrupt,
    extra_headers: &[(String, String)],
    auth: &credentials::AuthPolicy,
) -> Result<ArchiveOutput, GitError> {
    let body = archive_request_body(&req.rev)?;
    let url = rpc_url(base, SmartService::UploadArchive);
    let request_type = SmartService::UploadArchive.request_type();
    let result_type = SmartService::UploadArchive.result_type();
    let owned = policy_headers(
        &url,
        auth,
        &[
            ("Content-Type", request_type.as_str()),
            ("Accept", result_type.as_str()),
        ],
        extra_headers,
    );
    let (mut reader, status, reply) = http::post_open(&url, &borrow(&owned), &body)?;
    check_post_status(&url, &mut reader, status, &reply, auth)?;
    if http::header(&reply, "content-type") != Some(result_type.as_str()) {
        return Err(GitError::Corrupt {
            detail: format!("{url}: upload-archive RPC answered a non-archive content type"),
        });
    }
    let mut pkt = PktReader::new(reader, interrupt.clone());
    let first = pkt.read_line("the archive acknowledgement")?.to_vec();
    if let Some(rest) = first.strip_prefix(b"NACK ") {
        let message = String::from_utf8_lossy(rest).into_owned();
        if message.contains("unknown revision") {
            return Err(GitError::NotFound {
                detail: format!("{url}: unknown revision {:?}", req.rev),
            });
        }
        return Err(GitError::Corrupt {
            detail: format!("{url}: upload-archive refused: {message}"),
        });
    }
    if first != b"ACK" {
        return Err(GitError::Corrupt {
            detail: format!("{url}: upload-archive answered {}", first.escape_ascii()),
        });
    }
    match pkt.read_packet()? {
        pktline::Packet::Flush => {}
        other => {
            return Err(GitError::Corrupt {
                detail: format!("{url}: upload-archive misses its flush, got {other:?}"),
            });
        }
    }
    let mut sideband = pktline::SidebandReader::new(&mut pkt, pktline::LARGE_PACKET_MAX);
    let mut tar = Vec::new();
    sideband.read_to_end(&mut tar).map_err(|err| GitError::Io {
        detail: format!("{url}: cannot read the archive stream: {err}"),
    })?;
    let progress = sideband.messages().clone();
    Ok(ArchiveOutput { tar, progress })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).expect("hex")
    }

    fn no_auth() -> credentials::AuthPolicy {
        credentials::AuthPolicy::explicit(credentials::TransportAuth::none())
    }

    #[test]
    fn base_and_url_shapes() {
        assert_eq!(
            normalize_base("https://host.x/a.git/").expect("base"),
            "https://host.x/a.git"
        );
        assert_eq!(
            normalize_base("http://127.0.0.1:8080/a").expect("base"),
            "http://127.0.0.1:8080/a"
        );
        assert!(normalize_base("ftp://host.x/a").is_err());
        assert!(normalize_base("not a url").is_err());
        assert_eq!(
            refs_url("https://host.x/a.git", SmartService::UploadPack),
            "https://host.x/a.git/info/refs?service=git-upload-pack"
        );
        assert_eq!(
            refs_url("https://host.x/a?token=t", SmartService::ReceivePack),
            "https://host.x/a/info/refs?service=git-receive-pack&token=t"
        );
        assert_eq!(
            rpc_url("https://host.x/a.git", SmartService::UploadPack),
            "https://host.x/a.git/git-upload-pack"
        );
        assert_eq!(
            SmartService::UploadPack.advertisement_type(),
            "application/x-git-upload-pack-advertisement"
        );
        assert_eq!(
            SmartService::ReceivePack.request_type(),
            "application/x-git-receive-pack-request"
        );
        assert_eq!(
            SmartService::UploadPack.result_type(),
            "application/x-git-upload-pack-result"
        );
    }

    #[test]
    fn auth_header_surface() {
        // Failing runner plus empty chain: pure environment behavior,
        // hermetic against any configured helper.
        let vars = HashMap::from([("GIT_AUTH_TOKEN".to_owned(), "tok".to_owned())]);
        let headers = request_headers_with(
            "https://host.x/a.git",
            &vars,
            &[("Accept", "*/*")],
            &[],
            |_, _, _| None,
            &[],
        );
        assert!(headers.contains(&("Accept".to_owned(), "*/*".to_owned())));
        assert!(headers.contains(&("authorization".to_owned(), "Bearer tok".to_owned())));
        // A bearer token wins over a user/password pair.
        let vars = HashMap::from([
            ("GIT_AUTH_TOKEN".to_owned(), "tok".to_owned()),
            ("GIT_AUTH_USER".to_owned(), "user".to_owned()),
            ("GIT_AUTH_PASSWORD".to_owned(), "pass".to_owned()),
        ]);
        let headers =
            request_headers_with("https://host.x/a.git", &vars, &[], &[], |_, _, _| None, &[]);
        assert_eq!(headers.len(), 1);
        let vars = HashMap::from([
            ("GIT_AUTH_USER".to_owned(), "user".to_owned()),
            ("GIT_AUTH_PASSWORD".to_owned(), "pass".to_owned()),
        ]);
        let headers =
            request_headers_with("https://host.x/a.git", &vars, &[], &[], |_, _, _| None, &[]);
        assert_eq!(
            headers,
            vec![("authorization".to_owned(), "Basic dXNlcjpwYXNz".to_owned())]
        );
        assert!(
            request_headers_with(
                "https://host.x/a.git",
                &HashMap::new(),
                &[],
                &[],
                |_, _, _| None,
                &[]
            )
            .is_empty()
        );
    }

    #[test]
    fn helper_answer_wins_over_the_environment() {
        let helpers = vec![("/bin/helper".to_owned(), Vec::new())];
        let vars = HashMap::from([("GIT_AUTH_TOKEN".to_owned(), "tok".to_owned())]);
        let headers = request_headers_with(
            "https://host.x/a.git",
            &vars,
            &[],
            &helpers,
            |_, _, _| Some(b"username=alice\npassword=s3cret\n".to_vec()),
            &[],
        );
        assert_eq!(
            headers,
            vec![(
                "authorization".to_owned(),
                "Basic YWxpY2U6czNjcmV0".to_owned()
            )]
        );
    }

    #[test]
    fn explicit_auth_sends_exactly_one_header() {
        let tip = "0123456789abcdef0123456789abcdef01234567";
        let (base, server) = fake_smart_server(vec![(
            200,
            vec![(
                "Content-Type".to_owned(),
                SmartService::UploadPack.advertisement_type(),
            )],
            advertisement_bytes(tip, "side-band-64k"),
            false,
        )]);
        let origin =
            credentials::TransportAuth::origin_of(&base).expect("loopback base has an origin");
        let auth = credentials::AuthPolicy::explicit(credentials::TransportAuth {
            kind: credentials::TransportAuthKind::Bearer,
            credential: "injected".to_owned(),
            origin,
        });
        discover(&base, SmartService::UploadPack, HashKind::Sha1, &[], &auth)
            .expect("authed discover");
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        let auth_lines: Vec<&str> = requests[0]
            .head
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            .collect();
        assert_eq!(auth_lines, ["authorization: Bearer injected"]);
    }

    fn assert_only_injected_auth(head: &str) {
        let auth_lines: Vec<&str> = head
            .lines()
            .filter(|line| line.to_ascii_lowercase().starts_with("authorization:"))
            .collect();
        assert_eq!(auth_lines, ["authorization: Bearer injected"], "{head:?}");
    }

    #[test]
    fn explicit_auth_sends_one_header_on_a_smart_post() {
        use super::super::session::test_support::test_store;

        let (base, server) = fake_smart_server(vec![(500, Vec::new(), Vec::new(), false)]);
        let adv = Advertisement {
            version: super::super::refadv::ProtocolVersion::V0,
            capabilities: super::super::refadv::Capabilities::default(),
            refs: Vec::new(),
            shallow: Vec::new(),
        };
        let dest = test_store(HashKind::Sha1);
        let req = FetchWireRequest {
            wants: vec![oid(FOUR)],
            haves: Vec::new(),
            filter: None,
            depth: None,
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        };
        let auth = credentials::AuthPolicy::explicit(credentials::TransportAuth {
            kind: credentials::TransportAuthKind::Bearer,
            credential: "injected".to_owned(),
            origin: credentials::TransportAuth::origin_of(&base).expect("loopback origin"),
        });
        let err = fetch_pack(
            &base,
            &adv,
            &dest,
            &req,
            IngestLimits::default(),
            RpcCall {
                extra: &[],
                auth: &auth,
                interrupt: &Interrupt::none(),
            },
        )
        .expect_err("a 500 refuses the POST");
        assert_eq!(err.code(), ruk_core::error::ErrorCode::EOffline);
        let GitError::Http {
            status,
            retry_after_seconds,
            location,
            body_preview,
            ..
        } = err
        else {
            panic!("a 500 is an HTTP refusal: {err:?}");
        };
        assert_eq!(
            (status, retry_after_seconds, location, body_preview),
            (500, None, None, String::new())
        );
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .head
                .starts_with("POST /a.git/git-upload-pack HTTP/1.1\r\n"),
            "{:?}",
            requests[0].head
        );
        assert_only_injected_auth(&requests[0].head);
    }

    #[test]
    fn status_matrix_maps_honest_codes_with_scrubbed_detail() {
        use super::super::session::test_support::test_store;

        let adv = || Advertisement {
            version: super::super::refadv::ProtocolVersion::V0,
            capabilities: super::super::refadv::Capabilities::default(),
            refs: Vec::new(),
            shallow: Vec::new(),
        };
        let req = || FetchWireRequest {
            wants: vec![oid(FOUR)],
            haves: Vec::new(),
            filter: None,
            depth: None,
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        };
        let post = |base: &str, auth: &credentials::AuthPolicy| {
            let dest = test_store(HashKind::Sha1);
            fetch_pack(
                base,
                &adv(),
                &dest,
                &req(),
                IngestLimits::default(),
                RpcCall {
                    extra: &[],
                    auth,
                    interrupt: &Interrupt::none(),
                },
            )
            .expect_err("refusal")
        };
        struct StatusCase {
            status: u16,
            headers: Vec<(String, String)>,
            body: Vec<u8>,
            code: ruk_core::error::ErrorCode,
            retry: Option<u64>,
            location: Option<&'static str>,
        }
        let cases = vec![
            StatusCase {
                status: 401,
                headers: Vec::new(),
                body: b"token CANARY-tok expired; see https://ada:sect@host/x".to_vec(),
                code: ruk_core::error::ErrorCode::EForbidden,
                retry: None,
                location: None,
            },
            StatusCase {
                status: 403,
                headers: Vec::new(),
                body: Vec::new(),
                code: ruk_core::error::ErrorCode::EForbidden,
                retry: None,
                location: None,
            },
            StatusCase {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
                code: ruk_core::error::ErrorCode::ENotFound,
                retry: None,
                location: None,
            },
            StatusCase {
                status: 429,
                headers: vec![("Retry-After".to_owned(), "120".to_owned())],
                body: b"slow down".to_vec(),
                code: ruk_core::error::ErrorCode::ELimit,
                retry: Some(120),
                location: None,
            },
            StatusCase {
                status: 301,
                headers: vec![(
                    "Location".to_owned(),
                    "https://new.example/r.git".to_owned(),
                )],
                body: Vec::new(),
                code: ruk_core::error::ErrorCode::ERemoteMoved,
                retry: None,
                location: Some("https://new.example/r.git"),
            },
            StatusCase {
                status: 500,
                headers: Vec::new(),
                body: b"boom https://root:pw@internal/x".to_vec(),
                code: ruk_core::error::ErrorCode::EOffline,
                retry: None,
                location: None,
            },
        ];
        for case in cases {
            let StatusCase {
                status,
                headers,
                body,
                code,
                retry,
                location,
            } = case;
            let (base, server) = fake_smart_server(vec![(status, headers, body, false)]);
            let auth = credentials::AuthPolicy::explicit(credentials::TransportAuth {
                kind: credentials::TransportAuthKind::Bearer,
                credential: "CANARY-tok".to_owned(),
                origin: credentials::TransportAuth::origin_of(&base).expect("loopback origin"),
            });
            let err = post(&base, &auth);
            assert_eq!(err.code(), code, "status {status}");
            assert!(
                !err.to_string().contains("CANARY-tok"),
                "status {status}: {err}"
            );
            assert!(
                matches!(&err, GitError::Http { status: s, .. } if *s == status),
                "status {status} is an HTTP refusal: {err:?}"
            );
            let core = ruk_core::error::CoreError::from(err);
            assert_eq!(core.code, code, "status {status}");
            assert!(!core.message.contains("CANARY-tok"), "status {status}");
            let ruk_core::protocol::ErrorReply { detail, .. } =
                ruk_core::protocol::ErrorReply::from_core(&core);
            let Some(ruk_core::protocol::ErrorDetail::Http {
                status: detail_status,
                retry_after_seconds: detail_retry,
                location: detail_location,
                body_preview,
            }) = detail
            else {
                panic!("status {status} keeps its detail through the reply");
            };
            assert_eq!(detail_status, status);
            assert_eq!(detail_retry, retry, "status {status}");
            assert_eq!(detail_location.as_deref(), location, "status {status}");
            for secret in ["CANARY-tok", "ada:sect@", "root:pw@"] {
                assert!(!body_preview.contains(secret), "status {status}");
            }
            assert!(body_preview.len() <= 512, "status {status}");
            server.join().expect("server");
        }
    }

    #[test]
    fn explicit_auth_refuses_a_cross_origin_endpoint() {
        let (base, server) = fake_smart_server(vec![(
            200,
            vec![(
                "Content-Type".to_owned(),
                SmartService::UploadPack.advertisement_type(),
            )],
            advertisement_bytes(FOUR, "side-band-64k"),
            false,
        )]);
        let auth = credentials::AuthPolicy::explicit(credentials::TransportAuth {
            kind: credentials::TransportAuthKind::Bearer,
            credential: "injected".to_owned(),
            origin: "https://elsewhere.x:443".to_owned(),
        });
        discover(&base, SmartService::UploadPack, HashKind::Sha1, &[], &auth)
            .expect("discover succeeds without the credential");
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0]
                .head
                .to_ascii_lowercase()
                .contains("authorization:"),
            "{:?}",
            requests[0].head
        );
    }

    /// One recorded request: head text plus raw body bytes.
    struct Recorded {
        head: String,
        body: Vec<u8>,
    }

    /// Canned reply: status, headers, body, and whether to frame it chunked.
    type CannedReply = (u16, Vec<(String, String)>, Vec<u8>, bool);

    /// Serves canned replies on loopback, recording every request head
    /// plus body. Each reply names its framing: `chunked` emits
    /// `Transfer-Encoding: chunked` with the body in two chunks (so the
    /// client proves it never parses chunk-size text as pkt-line),
    /// otherwise `Content-Length`. Returns the base URL plus the join
    /// handle.
    fn fake_smart_server(
        replies: Vec<CannedReply>,
    ) -> (String, std::thread::JoinHandle<Vec<Recorded>>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, headers, body, chunked) in replies {
                let (socket, _) = listener.accept().expect("accept");
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .expect("timeout");
                let (head, request_body) = read_request(&socket);
                requests.push(Recorded {
                    head,
                    body: request_body,
                });
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    _ => "Error",
                };
                let mut reply = format!("HTTP/1.1 {status} {reason}\r\n");
                if chunked {
                    reply.push_str("Transfer-Encoding: chunked\r\n");
                } else {
                    reply.push_str(&format!("Content-Length: {}\r\n", body.len()));
                }
                for (name, value) in &headers {
                    reply.push_str(&format!("{name}: {value}\r\n"));
                }
                reply.push_str("Connection: close\r\n\r\n");
                let mut socket = socket;
                socket.write_all(reply.as_bytes()).expect("reply head");
                if chunked {
                    let (first, second) = body.split_at(body.len() / 2);
                    for chunk in [first, second] {
                        socket
                            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                            .expect("chunk size");
                        socket.write_all(chunk).expect("chunk");
                        socket.write_all(b"\r\n").expect("chunk end");
                    }
                    socket.write_all(b"0\r\n\r\n").expect("last chunk");
                } else {
                    socket.write_all(&body).expect("reply body");
                }
            }
            requests
        });
        (format!("http://127.0.0.1:{port}/a.git"), server)
    }

    /// Reads one request head plus its declared body from `socket`.
    fn read_request(socket: &std::net::TcpStream) -> (String, Vec<u8>) {
        let mut reader = std::io::BufReader::new(socket.try_clone().expect("split"));
        let mut head = Vec::new();
        loop {
            let mut line = Vec::new();
            use std::io::BufRead as _;
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

    /// One pkt-line advertisement document for `tip` under `HEAD` plus one
    /// branch, with the given capability words.
    fn advertisement_bytes(tip: &str, caps: &str) -> Vec<u8> {
        let mut out = Vec::new();
        pktline::encode_data(&mut out, b"# service=git-upload-pack\n").expect("frame");
        pktline::encode_flush(&mut out);
        let first = format!("{tip} HEAD\0{caps}\n");
        pktline::encode_data(&mut out, first.as_bytes()).expect("frame");
        let second = format!("{tip} refs/heads/main\n");
        pktline::encode_data(&mut out, second.as_bytes()).expect("frame");
        pktline::encode_flush(&mut out);
        out
    }

    /// Wraps `payload` in one side-band band-1 frame.
    fn sideband_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        let len = payload.len() + 5;
        frame.extend_from_slice(format!("{len:04x}").as_bytes());
        frame.push(1);
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn discover_parses_the_advertisement() {
        let body = advertisement_bytes(
            FOUR,
            "multi_ack_detailed side-band-64k thin-pack ofs-delta symref=HEAD:refs/heads/main object-format=sha1",
        );
        let (base, server) = fake_smart_server(vec![(
            200,
            vec![(
                "Content-Type".to_owned(),
                SmartService::UploadPack.advertisement_type(),
            )],
            body,
            false,
        )]);
        let adv = discover(
            &base,
            SmartService::UploadPack,
            HashKind::Sha1,
            &[],
            &no_auth(),
        )
        .expect("discover");
        assert!(adv.capabilities.has("side-band-64k"));
        assert_eq!(adv.refs.len(), 2);
        assert_eq!(adv.refs[0].oid, Some(oid(FOUR)));
        assert_eq!(
            adv.refs[0].symref_target.as_deref(),
            Some(b"refs/heads/main".as_slice())
        );
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .head
                .starts_with("GET /a.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"),
            "{:?}",
            requests[0].head
        );
    }

    #[test]
    fn extra_headers_join_the_wire_verbatim() {
        let body = advertisement_bytes(
            FOUR,
            "multi_ack_detailed side-band-64k thin-pack ofs-delta symref=HEAD:refs/heads/main object-format=sha1",
        );
        let (base, server) = fake_smart_server(vec![(
            200,
            vec![(
                "Content-Type".to_owned(),
                SmartService::UploadPack.advertisement_type(),
            )],
            body,
            false,
        )]);
        let configured = vec![
            ("X-Token".to_owned(), "Bearer scoped-token".to_owned()),
            ("X-Empty".to_owned(), String::new()),
        ];
        discover(
            &base,
            SmartService::UploadPack,
            HashKind::Sha1,
            &configured,
            &no_auth(),
        )
        .expect("discover");
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .head
                .contains("X-Token: Bearer scoped-token\r\n"),
            "{:?}",
            requests[0].head
        );
        assert!(
            requests[0].head.contains("X-Empty: \r\n"),
            "{:?}",
            requests[0].head
        );
    }

    #[test]
    fn discover_names_dumb_http_as_the_gap() {
        let (base, server) = fake_smart_server(vec![(
            200,
            vec![("Content-Type".to_owned(), "text/plain".to_owned())],
            format!("{FOUR}\trefs/heads/main\n").into_bytes(),
            false,
        )]);
        let err = discover(
            &base,
            SmartService::UploadPack,
            HashKind::Sha1,
            &[],
            &no_auth(),
        )
        .expect_err("dumb");
        assert!(
            matches!(err, GitError::Unsupported { .. }),
            "unexpected {err:?}"
        );
        assert!(err.to_string().contains("dumb-http"), "{err}");
        server.join().expect("server");
    }

    #[test]
    fn fetch_ingests_a_canned_pack() {
        use super::super::fetch::verify_closure;
        use super::super::session::test_support::test_store;

        let kind = HashKind::Sha1;
        let pack = include_bytes!("fixtures/basic.pack").to_vec();
        let adv_body = advertisement_bytes(
            FOUR,
            "multi_ack_detailed side-band-64k thin-pack ofs-delta object-format=sha1",
        );
        let mut result = b"0008NAK\n".to_vec();
        result.extend_from_slice(&sideband_frame(&pack));
        result.extend_from_slice(b"0000");
        // The pack reply is chunked: pkt-line must decode framing first
        // and never parse chunk-size text.
        let (base, server) = fake_smart_server(vec![
            (
                200,
                vec![(
                    "Content-Type".to_owned(),
                    SmartService::UploadPack.advertisement_type(),
                )],
                adv_body,
                false,
            ),
            (
                200,
                vec![(
                    "Content-Type".to_owned(),
                    SmartService::UploadPack.result_type(),
                )],
                result,
                true,
            ),
        ]);
        let adv =
            discover(&base, SmartService::UploadPack, kind, &[], &no_auth()).expect("discover");
        let dest = test_store(kind);
        let req = FetchWireRequest {
            wants: vec![oid(FOUR)],
            haves: Vec::new(),
            filter: None,
            depth: None,
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        };
        let received = fetch_pack(
            &base,
            &adv,
            &dest,
            &req,
            IngestLimits::default(),
            RpcCall {
                extra: &[],
                auth: &no_auth(),
                interrupt: &Interrupt::none(),
            },
        )
        .expect("fetch");
        assert!(received.warnings.is_empty());
        verify_closure(
            &dest,
            &received.staged,
            &[oid(FOUR)],
            None,
            &[],
            &Interrupt::none(),
        )
        .expect("closure");
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 2);
        let post = &requests[1];
        assert!(
            post.head
                .starts_with("POST /a.git/git-upload-pack HTTP/1.1\r\n"),
            "{:?}",
            post.head
        );
        assert!(
            post.head
                .contains("Content-Type: application/x-git-upload-pack-request"),
            "{:?}",
            post.head
        );
        assert!(
            post.head
                .contains("Accept: application/x-git-upload-pack-result"),
            "{:?}",
            post.head
        );
        assert!(
            post.body
                .windows(FOUR.len() + 6)
                .any(|w| w.starts_with(b"want ") && &w[5..5 + FOUR.len()] == FOUR.as_bytes()),
            "no want line in {:?}",
            post.body.escape_ascii().to_string()
        );
        assert!(post.body.windows(5).any(|w| w == b"done\n"), "no done line");
        assert!(post.body.ends_with(b"0000"), "no closing flush");
    }

    #[test]
    fn v2_discovery_lists_refs_through_ls_refs() {
        use super::super::proto_v2;

        let kind = HashKind::Sha1;
        let mut caps = Capabilities::default();
        caps.push_entry(b"agent=git/2.50");
        caps.push_entry(b"ls-refs=unborn");
        caps.push_entry(b"fetch=shallow filter sideband-all");
        caps.push_entry(b"object-format=sha1");
        let caps_body = proto_v2::encode_capability_advertisement(&caps).expect("caps");
        let mut ls_body = Vec::new();
        pktline::encode_data(
            &mut ls_body,
            format!("{FOUR} HEAD symref-target:refs/heads/main\n").as_bytes(),
        )
        .expect("frame");
        pktline::encode_data(&mut ls_body, format!("{FOUR} refs/heads/main\n").as_bytes())
            .expect("frame");
        pktline::encode_flush(&mut ls_body);
        let (base, server) = fake_smart_server(vec![
            (
                200,
                vec![(
                    "Content-Type".to_owned(),
                    SmartService::UploadPack.advertisement_type(),
                )],
                caps_body,
                false,
            ),
            (
                200,
                vec![(
                    "Content-Type".to_owned(),
                    SmartService::UploadPack.result_type(),
                )],
                ls_body,
                false,
            ),
        ]);
        let VersionedDiscovery::V2(probed) =
            discover_versioned(&base, SmartService::UploadPack, kind, &[], &no_auth())
                .expect("probe")
        else {
            panic!("expected v2");
        };
        assert!(probed.feature("fetch", "filter"));
        let refs = ls_refs_v2(
            &base,
            &probed,
            kind,
            &[],
            RpcCall {
                extra: &[],
                auth: &no_auth(),
                interrupt: &Interrupt::none(),
            },
        )
        .expect("ls-refs");
        assert_eq!(refs.len(), 2);
        assert_eq!(
            refs[0].symref_target.as_deref(),
            Some(b"refs/heads/main".as_slice())
        );
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 2);
        assert!(
            requests[0]
                .head
                .starts_with("GET /a.git/info/refs?service=git-upload-pack"),
            "{:?}",
            requests[0].head
        );
        assert!(
            requests[0].head.contains("Git-Protocol: version=2"),
            "{:?}",
            requests[0].head
        );
        assert!(
            requests[1]
                .head
                .starts_with("POST /a.git/git-upload-pack HTTP/1.1\r\n"),
            "{:?}",
            requests[1].head
        );
        assert!(
            requests[1].head.contains("Git-Protocol: version=2"),
            "{:?}",
            requests[1].head
        );
        assert!(
            requests[1]
                .body
                .windows(b"command=ls-refs\n".len())
                .any(|w| w == b"command=ls-refs\n"),
            "no ls-refs command in {:?}",
            requests[1].body.escape_ascii().to_string()
        );
    }

    #[test]
    fn versioned_discovery_parses_v0_in_one_round_trip() {
        // A server that ignores `Git-Protocol` answers v0: the single
        // GET parses it directly, with no second round trip. This is
        // the regression net for the double-GET probe, which consumed
        // one-shot servers' first scripted reply.
        let body = advertisement_bytes(
            FOUR,
            "multi_ack_detailed side-band-64k thin-pack ofs-delta object-format=sha1",
        );
        let (base, server) = fake_smart_server(vec![(
            200,
            vec![(
                "Content-Type".to_owned(),
                SmartService::UploadPack.advertisement_type(),
            )],
            body,
            false,
        )]);
        let VersionedDiscovery::V0(adv) = discover_versioned(
            &base,
            SmartService::UploadPack,
            HashKind::Sha1,
            &[],
            &no_auth(),
        )
        .expect("v0") else {
            panic!("expected v0");
        };
        assert_eq!(adv.refs.len(), 2);
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1, "one GET, no fallback round trip");
        assert!(
            requests[0].head.contains("Git-Protocol: version=2"),
            "{:?}",
            requests[0].head
        );
    }

    #[test]
    fn v2_fetch_ingests_a_canned_pack() {
        use super::super::fetch::verify_closure;
        use super::super::session::test_support::test_store;

        let kind = HashKind::Sha1;
        let pack = include_bytes!("fixtures/basic.pack").to_vec();
        let mut caps = Capabilities::default();
        caps.push_entry(b"ls-refs=unborn");
        caps.push_entry(b"fetch=shallow filter sideband-all");
        caps.push_entry(b"object-format=sha1");
        let mut result = Vec::new();
        pktline::encode_data(&mut result, b"packfile\n").expect("section");
        result.extend_from_slice(&sideband_frame(&pack));
        result.extend_from_slice(b"0000");
        // Chunked like the v0 fetch test: pkt-line must decode framing
        // first and never parse chunk-size text.
        let (base, server) = fake_smart_server(vec![(
            200,
            vec![(
                "Content-Type".to_owned(),
                SmartService::UploadPack.result_type(),
            )],
            result,
            true,
        )]);
        let dest = test_store(kind);
        let req = FetchWireRequest {
            wants: vec![oid(FOUR)],
            haves: Vec::new(),
            filter: None,
            depth: None,
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        };
        let received = fetch_pack_v2(
            &base,
            &caps,
            &dest,
            &req,
            IngestLimits::default(),
            RpcCall {
                extra: &[],
                auth: &no_auth(),
                interrupt: &Interrupt::none(),
            },
        )
        .expect("fetch");
        verify_closure(
            &dest,
            &received.staged,
            &[oid(FOUR)],
            None,
            &[],
            &Interrupt::none(),
        )
        .expect("closure");
        assert!(received.shallow.is_empty());
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        let post = &requests[0];
        assert!(
            post.head
                .starts_with("POST /a.git/git-upload-pack HTTP/1.1\r\n"),
            "{:?}",
            post.head
        );
        assert!(
            post.head.contains("Git-Protocol: version=2"),
            "{:?}",
            post.head
        );
        assert!(
            post.body
                .windows(b"command=fetch\n".len())
                .any(|w| w == b"command=fetch\n"),
            "no fetch command in {:?}",
            post.body.escape_ascii().to_string()
        );
        assert!(post.body.windows(5).any(|w| w == b"done\n"), "no done line");
        assert!(post.body.ends_with(b"0000"), "no closing flush");
    }

    #[test]
    fn push_reports_ref_status() {
        use super::super::push::{PushUpdate, PushWireRequest};
        use super::super::session::test_support::store_with_pack;
        use ruk_core::change::PlanId;

        let kind = HashKind::Sha1;
        let pack = include_bytes!("fixtures/basic.pack").to_vec();
        let store = store_with_pack(kind, &pack);
        let zero = kind.zero_oid();
        let mut adv_body = Vec::new();
        pktline::encode_data(&mut adv_body, b"# service=git-receive-pack\n").expect("frame");
        pktline::encode_flush(&mut adv_body);
        let first = format!(
            "{} capabilities^{{}}\0report-status-v2 report-status side-band-64k delete-refs ofs-delta object-format=sha1\n",
            zero.to_hex()
        );
        pktline::encode_data(&mut adv_body, first.as_bytes()).expect("frame");
        pktline::encode_flush(&mut adv_body);
        let mut report = sideband_frame(b"unpack ok\n");
        report.extend_from_slice(&sideband_frame(b"ok refs/heads/x\n"));
        report.extend_from_slice(b"0000");
        let (base, server) = fake_smart_server(vec![
            (
                200,
                vec![(
                    "Content-Type".to_owned(),
                    SmartService::ReceivePack.advertisement_type(),
                )],
                adv_body,
                false,
            ),
            (
                200,
                vec![(
                    "Content-Type".to_owned(),
                    SmartService::ReceivePack.result_type(),
                )],
                report,
                false,
            ),
        ]);
        // The test drives discovery itself so the advertisement (with its
        // capabilities) reaches the push half the way the verbs pass it.
        let adv =
            discover(&base, SmartService::ReceivePack, kind, &[], &no_auth()).expect("discover");
        let updates = vec![PushUpdate {
            name: b"refs/heads/x".to_vec(),
            old: zero,
            new: oid(FOUR),
        }];
        let req = PushWireRequest {
            updates: updates.clone(),
            atomic: false,
        };
        let mut plan =
            PushPlanRecord::prepare(PlanId::generate(), b"origin".to_vec(), false, updates);
        let outcomes = push_pack(
            &base,
            &adv,
            &store,
            &mut plan,
            &req,
            RpcCall {
                extra: &[],
                auth: &no_auth(),
                interrupt: &Interrupt::none(),
            },
        )
        .expect("push");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].name, b"refs/heads/x");
        assert!(
            matches!(outcomes[0].result, super::super::push::RefResult::Ok),
            "{:?}",
            outcomes[0].result
        );
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 2);
        let post = &requests[1];
        assert!(
            post.head
                .starts_with("POST /a.git/git-receive-pack HTTP/1.1\r\n"),
            "{:?}",
            post.head
        );
        assert!(
            post.body
                .windows(b"refs/heads/x".len())
                .any(|w| w == b"refs/heads/x"),
            "no command line"
        );
        assert!(post.body.windows(4).any(|w| w == b"PACK"), "no pack bytes");
    }

    #[test]
    fn push_without_report_status_is_uncertain() {
        use super::super::push::{PushUpdate, PushWireRequest};
        use super::super::session::test_support::test_store;
        use ruk_core::change::PlanId;

        let kind = HashKind::Sha1;
        let store = test_store(kind);
        let zero = kind.zero_oid();
        let updates = vec![PushUpdate {
            name: b"refs/heads/x".to_vec(),
            old: zero,
            new: oid(FOUR),
        }];
        let req = PushWireRequest {
            updates: updates.clone(),
            atomic: false,
        };
        let mut plan =
            PushPlanRecord::prepare(PlanId::generate(), b"origin".to_vec(), false, updates);
        let adv = Advertisement {
            version: super::super::refadv::ProtocolVersion::V0,
            capabilities: super::super::refadv::Capabilities::default(),
            refs: Vec::new(),
            shallow: Vec::new(),
        };
        let err = push_pack(
            "http://127.0.0.1:9/a.git",
            &adv,
            &store,
            &mut plan,
            &req,
            RpcCall {
                extra: &[],
                auth: &no_auth(),
                interrupt: &Interrupt::none(),
            },
        )
        .expect_err("no report-status");
        assert!(
            matches!(err, GitError::PushUncertain { .. }),
            "unexpected {err:?}"
        );
    }

    #[test]
    fn archive_shapes_match_the_service() {
        assert_eq!(SmartService::UploadArchive.name(), "git-upload-archive");
        assert_eq!(
            SmartService::UploadArchive.advertisement_type(),
            "application/x-git-upload-archive-advertisement"
        );
        assert_eq!(
            SmartService::UploadArchive.request_type(),
            "application/x-git-upload-archive-request"
        );
        assert_eq!(
            SmartService::UploadArchive.result_type(),
            "application/x-git-upload-archive-result"
        );
        assert_eq!(
            refs_url("https://host.x/a.git", SmartService::UploadArchive),
            "https://host.x/a.git/info/refs?service=git-upload-archive"
        );
        assert_eq!(
            rpc_url("https://host.x/a.git", SmartService::UploadArchive),
            "https://host.x/a.git/git-upload-archive"
        );
        assert!(archive_request_body("").is_err());
        assert!(archive_request_body("HEAD\nevil").is_err());
    }

    #[test]
    fn archive_fetches_a_sideband_tar() {
        let tar = b"fake-tar-bytes".to_vec();
        let mut body = Vec::new();
        pktline::encode_data(&mut body, b"ACK\n").expect("ack");
        pktline::encode_flush(&mut body);
        body.extend_from_slice(&sideband_frame(&tar));
        body.extend_from_slice(b"0000");
        let (base, server) = fake_smart_server(vec![(
            200,
            vec![(
                "Content-Type".to_owned(),
                SmartService::UploadArchive.result_type(),
            )],
            body,
            false,
        )]);
        let out = fetch_archive(
            &base,
            &ArchiveWireRequest {
                rev: "HEAD".to_owned(),
            },
            &Interrupt::none(),
            &[],
            &no_auth(),
        )
        .expect("archive");
        assert_eq!(out.tar, tar);
        let requests = server.join().expect("server");
        assert_eq!(requests.len(), 1);
        let post = &requests[0];
        assert!(
            post.head
                .starts_with("POST /a.git/git-upload-archive HTTP/1.1\r\n"),
            "{:?}",
            post.head
        );
        assert!(
            post.head
                .contains("Content-Type: application/x-git-upload-archive-request"),
            "{:?}",
            post.head
        );
        assert!(
            post.head
                .contains("Accept: application/x-git-upload-archive-result"),
            "{:?}",
            post.head
        );
        assert!(
            post.body
                .windows(b"argument --format=tar\n".len())
                .any(|w| w == b"argument --format=tar\n"),
            "no format line in {:?}",
            post.body.escape_ascii().to_string()
        );
        assert!(
            post.body
                .windows(b"argument HEAD\n".len())
                .any(|w| w == b"argument HEAD\n"),
            "no revision line in {:?}",
            post.body.escape_ascii().to_string()
        );
        assert!(post.body.ends_with(b"0000"), "no closing flush");
    }

    #[test]
    fn archive_maps_unknown_revisions_to_not_found() {
        let mut body = Vec::new();
        pktline::encode_data(&mut body, b"NACK unknown revision nope\n").expect("nack");
        let (base, server) = fake_smart_server(vec![(
            200,
            vec![(
                "Content-Type".to_owned(),
                SmartService::UploadArchive.result_type(),
            )],
            body,
            false,
        )]);
        let err = fetch_archive(
            &base,
            &ArchiveWireRequest {
                rev: "nope".to_owned(),
            },
            &Interrupt::none(),
            &[],
            &no_auth(),
        )
        .expect_err("unknown revision");
        assert!(
            matches!(err, GitError::NotFound { .. }),
            "unexpected {err:?}"
        );
        server.join().expect("server");
    }
}
