//! Dumb HTTP byte producers: `info/refs` text and loose objects.
//!
//! The HTTP layer lives outside this crate (Forgejo/daemon); this module
//! owns only the byte shapes a dumb client (`git clone` over plain HTTP)
//! reads, mirroring the oracle's dumb handlers:
//!
//! - `info/refs` is `text/plain` with one `<hex>\t<name>\n` line per ref
//!   in C-locale name order, plus a `<hex>\t<name>^{}\n` peel line for
//!   annotated tags. There is deliberately **no `HEAD` line**: the protocol
//!   document states the file "SHOULD NOT include the default ref named
//!   `HEAD`" (`git/Documentation/gitprotocol-http.adoc`, "Dumb Clients"),
//!   and live `git update-server-info` output confirms the same shape.
//!   Clients discover the default branch through the separate `HEAD`
//!   resource (`get_head` in `git/http-backend.c`), not this file.
//! - Loose objects at `objects/xx/rest` are the zlib of
//!   `<type> <len>\0<body>` (`get_loose_object` in `git/http-backend.c`).
//! - `objects/info/packs` is out of scope: Ruk holds no pack files, so the
//!   HTTP layer answers that route with the oracle's empty body (a single
//!   `\n`; `get_info_packs` in `git/http-backend.c` always terminates the
//!   list with one). Dumb clients then fetch every object loose, which a
//!   live `git clone` against a pack-less repository confirms works.
//!
//! Oracle anchors: `git/http-backend.c` (`get_info_refs`, `show_text_ref`,
//! `get_loose_object`, `get_info_packs`), `git/server-info.c`
//! (`add_info_ref`), `git/Documentation/gitprotocol-http.adoc`.

use std::io::Write;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use ruk_core::ids::Oid;
use ruk_core::refdata::{RefRead, RefTarget};
use ruk_core::refs::StoreRefs;
use ruk_core::store::ObjectKind;
use ruk_core::store::Store;

use super::pack::{IngestLimits, object_links};
use super::serve::HeadAdvertisement;
use super::session::advertise;
use super::read_object;
#[cfg(test)]
use super::stage_object;
use crate::{GitError, parse_oid_for};

fn corrupt(detail: impl Into<String>) -> GitError {
    GitError::Corrupt {
        detail: detail.into(),
    }
}

/// Largest single object materialized for a dumb response.
///
/// Reuses the pack ingest ceiling so dumb serving never buffers more than
/// a pack entry could already hold.
fn max_bytes() -> u64 {
    IngestLimits::default().max_object_bytes
}

/// Git spelling of one object kind for loose framing.
///
/// [`ObjectKind::Conflict`] is native-only and has none.
fn type_name(kind: ObjectKind) -> Option<&'static str> {
    match kind {
        ObjectKind::Commit => Some("commit"),
        ObjectKind::Tree => Some("tree"),
        ObjectKind::Blob => Some("blob"),
        ObjectKind::Tag => Some("tag"),
        ObjectKind::Conflict => None,
    }
}

/// Follows a symbolic target to a direct OID, bounding the chain.
///
/// Returns `None` when the chain breaks or cycles: like the oracle's dumb
/// handlers, which skip refs whose objects do not parse, the caller drops
/// the ref instead of failing the whole advertisement.
fn resolve(store: &Store, target: &RefTarget) -> Option<Oid> {
    if let RefTarget::Direct(oid) = target {
        return Some(*oid);
    }
    // Symbolic chains walk through one owned cursor; each hop moves in
    // and the next lookup moves out, so no per-hop allocation remains.
    let mut cursor = target.clone();
    for _ in 0..16 {
        match cursor {
            RefTarget::Direct(oid) => return Some(oid),
            RefTarget::Symbolic(name) => {
                cursor = StoreRefs::new(store).get(&name).ok()??;
            }
        }
    }
    None
}

/// Peels a tag to its ultimate non-tag target, mirroring the oracle's
/// `deref_tag` behind the `^{}` line.
///
/// Returns `None` when any link is missing or malformed; the caller keeps
/// the tag line and drops only the peel, exactly like `show_text_ref`.
fn peel(store: &Store, mut current: Oid) -> Option<Oid> {
    for _ in 0..32 {
        let (kind, bytes) = read_object(store, current, max_bytes()).ok()?;
        if kind != ObjectKind::Tag {
            return Some(current);
        }
        let links = object_links(kind, &bytes, store.hash_kind()).ok()?;
        current = links.tag_target?.0;
    }
    None
}

/// Writes the dumb `info/refs` body: one `<hex>\t<name>\n` line per
/// resolvable ref in byte (C-locale) name order, each annotated tag
/// followed by its `<hex>\t<name>^{}\n` peel.
///
///
/// `head` carries the symbolic `HEAD` for API symmetry with the serve
/// halves; it contributes no line because the oracle forbids a `HEAD` line
/// in this file (see the module docs). Refs whose objects are missing are
/// skipped, mirroring `show_text_ref` in `git/http-backend.c`.
///
/// # Errors
/// Store failures, and [`GitError::Io`] when `out` fails.
pub fn dumb_info_refs(
    store: &Store,
    _head: &HeadAdvertisement,
    out: &mut dyn Write,
) -> Result<(), GitError> {
    let mut refs = advertise(store)?;
    refs.sort_by(|a, b| a.name.cmp(&b.name));
    let mut body = Vec::new();
    for entry in &refs {
        if entry.name == b"HEAD" {
            continue;
        }
        let Some(oid) = resolve(store, &entry.target) else {
            continue;
        };
        let kind = match read_object(store, oid, max_bytes()) {
            Ok((kind, _)) => kind,
            Err(GitError::NotFound { .. }) => continue,
            Err(err) => return Err(err),
        };
        body.extend_from_slice(oid.to_hex().as_bytes());
        body.push(b'\t');
        body.extend_from_slice(&entry.name);
        body.push(b'\n');
        if kind != ObjectKind::Tag {
            continue;
        }
        let Some(peeled) = peel(store, oid) else {
            continue;
        };
        body.extend_from_slice(peeled.to_hex().as_bytes());
        body.push(b'\t');
        body.extend_from_slice(&entry.name);
        body.extend_from_slice(b"^{}\n");
    }
    out.write_all(&body).map_err(|err| GitError::Io {
        detail: format!("writing dumb info/refs: {err}"),
    })?;
    out.flush().map_err(|err| GitError::Io {
        detail: format!("flushing dumb info/refs: {err}"),
    })?;
    Ok(())
}

/// Parses a dumb object locator: a bare hex OID or an
/// `objects/<fanout>/<rest>` path.
///
/// A path whose fanout disagrees with the OID is [`GitError::Corrupt`];
/// anything else malformed is [`GitError::InvalidOid`] via the OID parse.
fn parse_locator(store: &Store, oid_or_path: &str) -> Result<Oid, GitError> {
    let Some(rest) = oid_or_path.strip_prefix("objects/") else {
        return parse_oid_for(oid_or_path, store.hash_kind());
    };
    let Some((fan, tail)) = rest.split_once('/') else {
        return Err(corrupt(format!(
            "malformed dumb object path {oid_or_path:?}"
        )));
    };
    if fan.len() != 2 || !fan.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(corrupt(format!(
            "malformed dumb object fanout {oid_or_path:?}"
        )));
    }
    let joined = format!("{fan}{tail}");
    if !joined.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(corrupt(format!(
            "malformed dumb object path {oid_or_path:?}"
        )));
    }
    if !joined
        .get(..2)
        .is_some_and(|head| head.eq_ignore_ascii_case(fan))
    {
        return Err(corrupt(format!(
            "dumb object path fanout disagrees with its OID {oid_or_path:?}"
        )));
    }
    parse_oid_for(&joined, store.hash_kind())
}

/// Streams one loose object: the zlib of `<type> <len>\0<body>`, the exact
/// bytes `git/http-backend.c` serves for `objects/xx/rest`.
///
/// `oid_or_path` is a bare hex OID or an `objects/<fanout>/<rest>` path;
/// pack routes (`objects/pack/…`, `objects/info/packs`) are not object
/// locators and are rejected. A missing object is [`GitError::NotFound`]
/// (the HTTP layer answers 404); a native-only [`ObjectKind::Conflict`]
/// has no loose spelling and is [`GitError::Invalid`].
///
/// # Errors
/// Store failures, [`GitError::NotFound`] for a missing object,
/// [`GitError::Limit`] above the ingest ceiling, [`GitError::Corrupt`]
/// for a malformed locator, and [`GitError::Io`] when `out` fails.
pub fn dumb_object(
    store: &Store,
    oid_or_path: &str,
    out: &mut dyn Write,
) -> Result<(), GitError> {
    if oid_or_path.starts_with("objects/pack/") || oid_or_path.starts_with("objects/info/") {
        return Err(GitError::NotFound {
            detail: format!("no pack route serves {oid_or_path:?} over dumb HTTP"),
        });
    }
    let oid = parse_locator(store, oid_or_path)?;
    let (kind, bytes) = read_object(store, oid, max_bytes())?;
    let Some(type_name) = type_name(kind) else {
        return Err(GitError::Invalid {
            detail: format!("object {oid} has no loose spelling"),
        });
    };
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    write!(encoder, "{type_name} {}\0", bytes.len()).map_err(|err| GitError::Io {
        detail: format!("framing dumb object {oid}: {err}"),
    })?;
    encoder
        .write_all(&bytes)
        .map_err(|err| GitError::Io {
            detail: format!("framing dumb object {oid}: {err}"),
        })?;
    let framed = encoder.finish().map_err(|err| GitError::Io {
        detail: format!("deflating dumb object {oid}: {err}"),
    })?;
    out.write_all(&framed).map_err(|err| GitError::Io {
        detail: format!("writing dumb object {oid}: {err}"),
    })?;
    out.flush().map_err(|err| GitError::Io {
        detail: format!("flushing dumb object {oid}: {err}"),
    })?;
    Ok(())
}

/// Stages one raw object for tests, returning its OID.
#[cfg(test)]
pub(crate) fn stage_for_test(store: &Store, kind: ObjectKind, bytes: &[u8]) -> Oid {
    let prepared = stage_object(store, kind, bytes, None).expect("stage");
    let oid = prepared.oid();
    store.publish(vec![prepared], &[]).expect("publish");
    oid
}

#[cfg(test)]
mod tests {
    use super::super::serve::HeadAdvertisement;
    use super::super::session::test_support::{store_with_pack, test_store};
    use super::*;
    use ruk_core::ids::HashKind;
    use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTransaction, RefUpdate};
    use ruk_core::refs::prepare_checked_transaction;

    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).expect("hex")
    }

    fn head() -> HeadAdvertisement {
        HeadAdvertisement {
            oid: oid(FOUR),
            symref: Some(b"refs/heads/main".to_vec()),
        }
    }

    fn set_ref(store: &Store, kind: HashKind, name: &[u8], target: Oid) {
        let update = RefUpdate {
            expected: RefExpect::Absent,
            change: RefChange::Set(RefTarget::Direct(target)),
            name: RefName::new(name.to_vec()).expect("ref name"),
        };
        let transaction = RefTransaction::new(kind, vec![update]).expect("transaction");
        let prepared = prepare_checked_transaction(store, &transaction).expect("prepare");
        store
            .publish(Vec::new(), &prepared.into_mutations())
            .expect("publish ref");
    }

    /// Mirrors the live oracle run (`git init`, one commit, lightweight tag
    /// `v1`, annotated tag `v2`, `git update-server-info`): sorted lines,
    /// tab separators, LF endings, no `HEAD` line, peel after its tag.
    #[test]
    fn info_refs_matches_update_server_info_shape() {
        let kind = HashKind::Sha1;
        let store = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        set_ref(&store, kind, b"refs/heads/main", oid(FOUR));
        set_ref(&store, kind, b"refs/tags/v1", oid(FOUR));
        let commit = read_object(&store, oid(FOUR), u64::MAX).expect("commit");
        assert_eq!(commit.0, ObjectKind::Commit);
        let tag_bytes =
            format!("object {FOUR}\ntype commit\ntag v2\ntagger t <t@t> 0 +0000\n\nsecond\n");
        let tag = stage_for_test(&store, ObjectKind::Tag, tag_bytes.as_bytes());
        set_ref(&store, kind, b"refs/tags/v2", tag);

        let mut out = Vec::new();
        dumb_info_refs(&store, &head(), &mut out).expect("info/refs");
        let body = String::from_utf8(out).expect("utf8");
        let expected = format!(
            "{FOUR}\trefs/heads/main\n{FOUR}\trefs/tags/v1\n{tag}\trefs/tags/v2\n{FOUR}\trefs/tags/v2^{{}}\n"
        );
        assert_eq!(body, expected);
    }

    /// Refs whose objects are absent are skipped, like the oracle's
    /// `show_text_ref` dropping refs that do not parse.
    #[test]
    fn info_refs_skips_dangling_refs() {
        let kind = HashKind::Sha1;
        let store = test_store(kind);
        set_ref(&store, kind, b"refs/heads/main", oid(FOUR));
        let mut out = Vec::new();
        dumb_info_refs(&store, &head(), &mut out).expect("info/refs");
        assert!(out.is_empty(), "dangling ref leaked: {out:?}");
    }

    /// A loose blob round-trips through zlib framing `blob <len>\0<body>`.
    #[test]
    fn object_streams_a_real_blob() {
        use flate2::read::ZlibDecoder;
        use std::io::Read as _;

        let kind = HashKind::Sha1;
        let store = test_store(kind);
        let blob = stage_for_test(&store, ObjectKind::Blob, b"hello\n");

        for locator in [
            blob.to_hex(),
            format!("objects/{}/{}", &blob.to_hex()[..2], &blob.to_hex()[2..]),
        ] {
            let mut out = Vec::new();
            dumb_object(&store, &locator, &mut out).expect("blob");
            let mut inflated = Vec::new();
            ZlibDecoder::new(&out[..])
                .read_to_end(&mut inflated)
                .expect("inflate");
            assert_eq!(inflated, b"blob 6\0hello\n");
        }
    }

    #[test]
    fn object_rejects_pack_routes_and_missing_objects() {
        let kind = HashKind::Sha1;
        let store = test_store(kind);
        let mut out = Vec::new();
        assert!(matches!(
            dumb_object(&store, oid(FOUR).to_hex().as_str(), &mut out),
            Err(GitError::NotFound { .. })
        ));
        assert!(matches!(
            dumb_object(&store, "objects/pack/pack-abc.pack", &mut out),
            Err(GitError::NotFound { .. })
        ));
        assert!(matches!(
            dumb_object(&store, "objects/info/packs", &mut out),
            Err(GitError::NotFound { .. })
        ));
    }
}
