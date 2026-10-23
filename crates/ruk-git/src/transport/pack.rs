//! Pack streams: ingest into store staging and emission for push.
//!
//! Ingest frames and inflates with [`gix_pack::data::input::BytesToEntriesIter`]
//! in `Verify` mode, so the pack header, every entry and the trailer
//! checksum are checked by tested code; delta resolution on top is owned
//! here. `OFS_DELTA` bases must lie earlier in the same pack; `REF_DELTA`
//! bases resolve against already-resolved pack entries first and against
//! committed store objects second, which is exactly the thin-pack rule: a
//! thin base is always an object the receiver already holds (it sent it as
//! a have). Unknown bases are [`GitError::Corrupt`], never guessed.
//!
//! Every resolved object enters staging through [`Store::prepare`], which
//! recomputes its identity; the OID the pack implies is checked, not
//! trusted.
//!
//! Emission writes pack v2 with full entries and, for thin packs,
//! `REF_DELTA` entries whose bases the caller guarantees are permitted
//! (reachable from the receiver's advertised tips). The writer cannot see
//! the negotiation, so the permitted-base contract lives with its callers
//! ([`crate::transport::push`], [`crate::transport::session`]).
//!
//! Memory: ingest holds one decompressed copy of every entry until it is
//! staged, bounded by [`IngestLimits`]. Streaming ingest that stages
//! delta-free entries early is future work; the bound, not silence,
//! covers large packs.

use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read, Write};

use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use gix_pack::data::entry::Header as PackHeader;
use gix_pack::data::input::{BytesToEntriesIter, EntryDataMode, Mode};
use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::types::ObjectKind;
#[cfg(test)]
use ruk_core::store::{EventContext, EventSource};
use ruk_core::store::{PreparedObject, Store};

use super::{Interrupt, stage_object};
use crate::GitError;

/// One staged pack entry: index order, kind, and decompressed bytes.
type StagedPackEntry = Result<(usize, ObjectKind, Vec<u8>), GitError>;

/// Bounds for one ingested pack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IngestLimits {
    /// Largest total compressed entry bytes accepted.
    pub max_pack_bytes: u64,
    /// Largest entry count accepted.
    pub max_objects: u64,
    /// Largest single decompressed object accepted.
    pub max_object_bytes: u64,
    /// Deepest delta chain followed before refusing.
    pub max_delta_depth: u64,
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self {
            max_pack_bytes: 1 << 31,
            max_objects: 5_000_000,
            max_object_bytes: 512 << 20,
            max_delta_depth: 128,
        }
    }
}

fn corrupt(detail: impl Into<String>) -> GitError {
    GitError::Corrupt {
        detail: detail.into(),
    }
}

/// One staged pack: verified objects invisible until published with the
/// ref facts they justify (see the module-level staging boundary).
///
/// The resolved payloads stay resident for closure verification; staging
/// holds them and the prepared spools together, bounded by
/// [`IngestLimits`].
#[derive(Debug, Default)]
pub struct StagedPack {
    oids: Vec<Oid>,
    objects: Vec<PreparedObject>,
    payloads: HashMap<Oid, (ObjectKind, Vec<u8>)>,
}

impl StagedPack {
    /// Staged identities in pack order.
    #[must_use]
    pub fn oids(&self) -> &[Oid] {
        &self.oids
    }

    /// Staged objects in pack order, parallel to [`Self::oids`].
    #[must_use]
    pub fn objects(&self) -> &[PreparedObject] {
        &self.objects
    }

    /// Whether `oid` arrived in this pack.
    pub(crate) fn contains(&self, oid: Oid) -> bool {
        self.payloads.contains_key(&oid)
    }

    /// The staged payload of `oid`, if it arrived in this pack.
    pub(crate) fn payload(&self, oid: Oid) -> Option<(ObjectKind, &[u8])> {
        self.payloads
            .get(&oid)
            .map(|(kind, bytes)| (*kind, bytes.as_slice()))
    }

    /// Consumes the staging into its prepared objects.
    #[must_use]
    pub fn into_objects(self) -> Vec<PreparedObject> {
        self.objects
    }
}

/// Links of one object for closure walks. Semantics match the sibling
/// `import::walk::object_links` (commit: tree then parents; tree: entries
/// minus gitlinks; tag: declared target; blob: empty); the parent
/// consolidates the two parsers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Links {
    pub tree: Option<Oid>,
    pub parents: Vec<Oid>,
    pub entries: Vec<(Oid, ObjectKind)>,
    pub tag_target: Option<(Oid, ObjectKind)>,
}

/// Parses the links of one object payload without panicking.
///
/// # Errors
/// [`GitError::Corrupt`] for malformed payloads or OIDs of the wrong width.
pub(crate) fn object_links(
    kind: ObjectKind,
    payload: &[u8],
    hash: HashKind,
) -> Result<Links, GitError> {
    let mut links = Links::default();
    match kind {
        ObjectKind::Blob | ObjectKind::Conflict => return Ok(links),
        ObjectKind::Commit => parse_commit_links(payload, hash, &mut links)?,
        ObjectKind::Tree => parse_tree_links(payload, hash, &mut links)?,
        ObjectKind::Tag => parse_tag_links(payload, hash, &mut links)?,
    }
    Ok(links)
}

fn field_oid(field: &[u8], hash: HashKind, what: &str) -> Result<Oid, GitError> {
    let text = std::str::from_utf8(field).map_err(|_| corrupt(format!("{what} is not ASCII")))?;
    let oid = Oid::from_hex(text).map_err(|err| corrupt(format!("{what}: {err}")))?;
    if oid.kind() != hash {
        return Err(corrupt(format!("{what} has the wrong width")));
    }
    Ok(oid)
}

fn parse_commit_links(payload: &[u8], hash: HashKind, links: &mut Links) -> Result<(), GitError> {
    let header = payload
        .windows(2)
        .position(|w| w == b"\n\n")
        .map(|at| &payload[..at + 1])
        .unwrap_or(payload);
    for line in header.split(|b| *b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"tree ") {
            if links.tree.is_some() {
                return Err(corrupt("commit has two trees"));
            }
            links.tree = Some(field_oid(rest, hash, "commit tree")?);
        } else if let Some(rest) = line.strip_prefix(b"parent ") {
            links.parents.push(field_oid(rest, hash, "commit parent")?);
        }
    }
    if links.tree.is_none() {
        return Err(corrupt("commit has no tree"));
    }
    Ok(())
}

fn parse_tree_links(payload: &[u8], hash: HashKind, links: &mut Links) -> Result<(), GitError> {
    let hash_len = hash.oid_len();
    let mut rest = payload;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|b| *b == b' ')
            .ok_or_else(|| corrupt("tree entry without mode"))?;
        if rest[..space].is_empty()
            || rest[..space]
                .iter()
                .any(|b| !b.is_ascii_digit() || *b > b'7')
        {
            return Err(corrupt("tree entry has a non-octal mode"));
        }
        let mode = rest[..space].iter().fold(0u32, |acc, b| {
            acc.saturating_mul(8).saturating_add(u32::from(b - b'0'))
        });
        let after_mode = &rest[space + 1..];
        let nul = after_mode
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| corrupt("tree entry without name"))?;
        let after_name = &after_mode[nul + 1..];
        if after_name.len() < hash_len {
            return Err(corrupt("tree entry truncates its oid"));
        }
        if mode != 0o160000 {
            let oid = Oid::from_bytes(&after_name[..hash_len])
                .map_err(|_| corrupt("tree entry has a bad oid"))?;
            let kind = if mode == 0o040000 {
                ObjectKind::Tree
            } else {
                ObjectKind::Blob
            };
            links.entries.push((oid, kind));
        }
        rest = &after_name[hash_len..];
    }
    Ok(())
}

fn parse_tag_links(payload: &[u8], hash: HashKind, links: &mut Links) -> Result<(), GitError> {
    let mut target = None;
    let mut target_kind = None;
    let header = payload
        .windows(2)
        .position(|w| w == b"\n\n")
        .map(|at| &payload[..at + 1])
        .unwrap_or(payload);
    for line in header.split(|b| *b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"object ") {
            target = Some(field_oid(rest, hash, "tag target")?);
        } else if let Some(rest) = line.strip_prefix(b"type ") {
            target_kind = Some(match rest {
                b"commit" => ObjectKind::Commit,
                b"tree" => ObjectKind::Tree,
                b"blob" => ObjectKind::Blob,
                b"tag" => ObjectKind::Tag,
                _ => return Err(corrupt("tag has an unknown target type")),
            });
        }
    }
    match (target, target_kind) {
        (Some(oid), Some(kind)) => {
            links.tag_target = Some((oid, kind));
            Ok(())
        }
        _ => Err(corrupt("tag lacks its target")),
    }
}

fn pack_kind(header: &PackHeader) -> Option<ObjectKind> {
    match header {
        PackHeader::Commit => Some(ObjectKind::Commit),
        PackHeader::Tree => Some(ObjectKind::Tree),
        PackHeader::Blob => Some(ObjectKind::Blob),
        PackHeader::Tag => Some(ObjectKind::Tag),
        PackHeader::RefDelta { .. } | PackHeader::OfsDelta { .. } => None,
    }
}

fn git_type_name(kind: ObjectKind) -> Option<&'static str> {
    match kind {
        ObjectKind::Blob => Some("blob"),
        ObjectKind::Tree => Some("tree"),
        ObjectKind::Commit => Some("commit"),
        ObjectKind::Tag => Some("tag"),
        ObjectKind::Conflict => None,
    }
}

struct RawEntry {
    header: PackHeader,
    pack_offset: u64,
    compressed: Vec<u8>,
    declared: u64,
}

/// Ingests one pack stream into staging.
///
/// `reader` starts at the `PACK` magic and runs through the trailer; the
/// iterator verifies the trailer checksum in `Verify` mode. Framing errors
/// are [`GitError::Corrupt`], including a trailer mismatch; an I/O failure
/// mid-stream surfaces inside that corruption message with its cause, since
/// the framing layer cannot separate a cut connection from cut bytes.
///
/// # Errors
/// [`GitError::Corrupt`] for framing, delta, size-declaration or identity
/// failures, [`GitError::Limit`] past `limits`, [`GitError::Cancelled`]
/// from `interrupt`, and store failures from staging.
pub fn ingest_pack<R: Read>(
    reader: R,
    kind: HashKind,
    store: &Store,
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<StagedPack, GitError> {
    let mut stream = BufReader::new(reader);
    let iter = BytesToEntriesIter::new_from_header(
        &mut stream,
        Mode::Verify,
        EntryDataMode::Keep,
        kind.gix(),
    )
    .map_err(|err| corrupt(format!("pack header is malformed: {err}")))?;
    let profile = std::env::var_os("RUK_PROFILE").is_some_and(|value| value == "1");
    let ingest_start = profile.then(std::time::Instant::now);
    let mut raw: Vec<RawEntry> = Vec::new();
    let mut compressed_total = 0u64;
    for item in iter {
        interrupt.check("receiving the pack")?;
        let entry = item.map_err(|err| corrupt(format!("pack stream failed: {err}")))?;
        let count = u64::try_from(raw.len()).map_err(|_| GitError::Limit {
            detail: "pack entry count does not fit".to_owned(),
        })?;
        if count >= limits.max_objects {
            return Err(GitError::Limit {
                detail: format!("pack holds more than {} objects", limits.max_objects),
            });
        }
        if entry.decompressed_size > limits.max_object_bytes {
            return Err(GitError::Limit {
                detail: format!(
                    "pack entry of {} bytes exceeds the {}-byte object limit",
                    entry.decompressed_size, limits.max_object_bytes
                ),
            });
        }
        compressed_total = compressed_total.saturating_add(entry.compressed_size);
        if compressed_total > limits.max_pack_bytes {
            return Err(GitError::Limit {
                detail: format!(
                    "pack exceeds the {}-byte ingest bound",
                    limits.max_pack_bytes
                ),
            });
        }
        raw.push(RawEntry {
            header: entry.header,
            pack_offset: entry.pack_offset,
            compressed: entry.compressed.unwrap_or_default(),
            declared: entry.decompressed_size,
        });
    }
    let stream_ms = ingest_start
        .map(|start| start.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let resolve_start = profile.then(std::time::Instant::now);
    let resolved = resolve_all(&raw, kind, store, limits, interrupt)?;
    let resolve_ms = resolve_start
        .map(|start| start.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let stage_start = profile.then(std::time::Instant::now);
    // CPU-heavy staging (hash plus zstd in `Store::prepare`) fans out
    // across workers and rejoins in pack order; the serial loop below
    // applies the first error in pack order, exactly as before.
    let staged = stage_resolved(store, &resolved, interrupt);
    let entry_count = resolved.len();
    let mut oids = Vec::with_capacity(entry_count);
    let mut objects = Vec::with_capacity(entry_count);
    let mut payloads = HashMap::with_capacity(entry_count);
    for ((oid, kind, bytes), staged) in resolved.into_iter().zip(staged) {
        interrupt.check("staging the pack")?;
        objects.push(staged?);
        oids.push(oid);
        payloads.insert(oid, (kind, bytes));
    }
    if let Some(start) = ingest_start {
        eprintln!(
            "[ruk-profile] ingest_pack entries={entry_count} stream={stream_ms:.1}ms resolve={resolve_ms:.1}ms stage={:.1}ms total={:.1}ms",
            stage_start
                .map(|start| start.elapsed().as_secs_f64() * 1000.0)
                .unwrap_or(0.0),
            start.elapsed().as_secs_f64() * 1000.0,
        );
    }
    Ok(StagedPack {
        oids,
        objects,
        payloads,
    })
}

/// Stages a local closure directly, skipping the pack encode/decode
/// round-trip.
///
/// The triples are already full objects (no deltas), so there is nothing
/// to resolve: each entry goes through [`stage_object`] with its announced
/// OID as the expectation, exactly like [`ingest_pack`]'s staging tail.
/// Verification is not weakened: [`Store::prepare`] recomputes the
/// identity and a mismatch is [`GitError::Corrupt`]; delta-base refusal is
/// vacuous here because no entry names a base. [`IngestLimits`] still
/// apply: entry count against `max_objects`, each payload against
/// `max_object_bytes`, and the summed raw bytes (conservative: raw is an
/// upper bound on what the deflated pack would have carried) against
/// `max_pack_bytes`. `max_delta_depth` has no work: there are no deltas.
/// `interrupt` is honored per object, and staging fans out across
/// `pack_threads` workers rejoining in order with the first error in
/// closure order surfacing, matching [`ingest_pack`].
///
/// # Errors
/// [`GitError::Limit`] past `limits`, [`GitError::Corrupt`] on identity
/// mismatch, [`GitError::Cancelled`] from `interrupt`, and store failures
/// from staging.
pub fn stage_local_objects(
    objects: Vec<(Oid, ObjectKind, Vec<u8>)>,
    store: &Store,
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<StagedPack, GitError> {
    let count = u64::try_from(objects.len()).map_err(|_| GitError::Limit {
        detail: "closure entry count does not fit".to_owned(),
    })?;
    if count > limits.max_objects {
        return Err(GitError::Limit {
            detail: format!("closure holds more than {} objects", limits.max_objects),
        });
    }
    let mut raw_total = 0u64;
    for (_, _, bytes) in &objects {
        interrupt.check("staging the closure")?;
        let len = u64::try_from(bytes.len()).map_err(|_| GitError::Limit {
            detail: "object length does not fit in 64 bits".to_owned(),
        })?;
        if len > limits.max_object_bytes {
            return Err(GitError::Limit {
                detail: format!(
                    "closure entry of {len} bytes exceeds the {}-byte object limit",
                    limits.max_object_bytes
                ),
            });
        }
        raw_total = raw_total.saturating_add(len);
        if raw_total > limits.max_pack_bytes {
            return Err(GitError::Limit {
                detail: format!(
                    "closure exceeds the {}-byte ingest bound",
                    limits.max_pack_bytes
                ),
            });
        }
    }
    let staged = stage_resolved(store, &objects, interrupt);
    let entry_count = objects.len();
    let mut oids = Vec::with_capacity(entry_count);
    let mut prepared = Vec::with_capacity(entry_count);
    let mut payloads = HashMap::with_capacity(entry_count);
    for ((oid, kind, bytes), staged) in objects.into_iter().zip(staged) {
        interrupt.check("staging the closure")?;
        prepared.push(staged?);
        oids.push(oid);
        payloads.insert(oid, (kind, bytes));
    }
    Ok(StagedPack {
        oids,
        objects: prepared,
        payloads,
    })
}

/// Prepares every resolved entry across `pack_threads` workers: hashing
/// and zstd compression per object. The returned vector aligns 1:1 with
/// `resolved`; the caller rejoins it in order. `Store::prepare` is
/// thread-safe (the import lane already stages from scoped workers
/// against the shared budget and uniquely named scratch spools).
fn stage_resolved(
    store: &Store,
    resolved: &[(Oid, ObjectKind, Vec<u8>)],
    interrupt: &Interrupt,
) -> Vec<Result<PreparedObject, GitError>> {
    fn stage_one(
        store: &Store,
        entry: &(Oid, ObjectKind, Vec<u8>),
        interrupt: &Interrupt,
    ) -> Result<PreparedObject, GitError> {
        interrupt.check("staging the pack")?;
        stage_object(store, entry.1, &entry.2, Some(entry.0))
    }

    let width = pack_threads();
    if width <= 1 || resolved.len() <= 1 {
        return resolved
            .iter()
            .map(|entry| stage_one(store, entry, interrupt))
            .collect();
    }
    let piece = resolved.len().div_ceil(width);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for part in resolved.chunks(piece) {
            handles.push(scope.spawn(move || {
                part.iter()
                    .map(|entry| stage_one(store, entry, interrupt))
                    .collect::<Vec<_>>()
            }));
        }
        let mut staged = Vec::with_capacity(resolved.len());
        for handle in handles {
            match handle.join() {
                Ok(part) => staged.extend(part),
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        staged
    })
}

/// Inflates and hashes every base-kind entry, leaving deltas for the
/// serial fixpoint. Workers return `(index, kind, bytes)` triples; the
/// caller applies them through [`Resolver::finish`] in index order, so a
/// corrupt entry surfaces in pack order. Narrow packs stay serial.
fn pre_resolve_independent(
    resolver: &mut Resolver<'_>,
    interrupt: &Interrupt,
) -> Result<(), GitError> {
    let independent: Vec<(usize, ObjectKind)> = resolver
        .raw
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| pack_kind(&entry.header).map(|kind| (index, kind)))
        .collect();
    if independent.len() < 2 {
        return Ok(());
    }
    let width = pack_threads();
    let staged: Vec<StagedPackEntry> = if width <= 1 || independent.len() < 32 {
        independent
            .iter()
            .map(|(index, kind)| {
                interrupt.check("resolving pack deltas")?;
                inflate(
                    &resolver.raw[*index].compressed,
                    resolver.raw[*index].declared,
                    resolver.limits.max_object_bytes,
                )
                .map(|bytes| (*index, *kind, bytes))
            })
            .collect()
    } else {
        let piece = independent.len().div_ceil(width);
        let raw = &resolver.raw;
        let max_object_bytes = resolver.limits.max_object_bytes;
        std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for part in independent.chunks(piece) {
                handles.push(scope.spawn(move || {
                    part.iter()
                        .map(|(index, kind)| {
                            if interrupt.check("resolving pack deltas").is_err() {
                                return Err(GitError::Cancelled {
                                    detail: "resolving pack deltas was cancelled".to_owned(),
                                });
                            }
                            inflate(
                                &raw[*index].compressed,
                                raw[*index].declared,
                                max_object_bytes,
                            )
                            .map(|bytes| (*index, *kind, bytes))
                        })
                        .collect::<Vec<_>>()
                }));
            }
            let mut staged = Vec::with_capacity(independent.len());
            for handle in handles {
                match handle.join() {
                    Ok(part) => staged.extend(part),
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            }
            staged
        })
    };
    for entry in staged {
        let (index, kind, bytes) = entry?;
        resolver.finish(index, kind, bytes)?;
    }
    Ok(())
}

enum Resolution {
    Done,
    Deferred,
}

struct Resolver<'a> {
    raw: &'a [RawEntry],
    offsets: HashMap<u64, usize>,
    payloads: Vec<Option<Vec<u8>>>,
    kinds: Vec<ObjectKind>,
    oids: Vec<Option<Oid>>,
    oid_index: HashMap<Oid, usize>,
    resolving: Vec<bool>,
    kind: HashKind,
    store: &'a Store,
    limits: IngestLimits,
}

fn resolve_all(
    raw: &[RawEntry],
    kind: HashKind,
    store: &Store,
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<Vec<(Oid, ObjectKind, Vec<u8>)>, GitError> {
    let mut offsets = HashMap::with_capacity(raw.len());
    for (index, entry) in raw.iter().enumerate() {
        offsets.insert(entry.pack_offset, index);
    }
    let mut resolver = Resolver {
        raw,
        offsets,
        payloads: (0..raw.len()).map(|_| None).collect(),
        kinds: vec![ObjectKind::Blob; raw.len()],
        oids: (0..raw.len()).map(|_| None).collect(),
        oid_index: HashMap::new(),
        resolving: vec![false; raw.len()],
        kind,
        store,
        limits,
    };
    // Base-kind entries need no delta base: inflate and hash them across
    // workers, rejoining in index order. Delta entries (and whole thin
    // packs) fall through to the serial fixpoint below with their bases
    // already cached. Pure per entry: no store reads, no shared state.
    pre_resolve_independent(&mut resolver, interrupt)?;
    let mut deferred: HashSet<usize> = (0..raw.len()).collect();
    while !deferred.is_empty() {
        interrupt.check("resolving pack deltas")?;
        let mut progress = false;
        for index in (0..raw.len()).rev() {
            if !deferred.contains(&index) {
                continue;
            }
            match resolver.resolve(index, 0)? {
                Resolution::Done => {
                    deferred.remove(&index);
                    progress = true;
                }
                Resolution::Deferred => {}
            }
        }
        if !progress {
            return Err(corrupt("pack has deltas against unknown bases"));
        }
    }
    let mut out = Vec::with_capacity(raw.len());
    for index in 0..raw.len() {
        let oid = resolver.oids[index].ok_or_else(|| corrupt("pack entry never resolved"))?;
        let bytes = resolver.payloads[index]
            .take()
            .ok_or_else(|| corrupt("pack entry never resolved"))?;
        out.push((oid, resolver.kinds[index], bytes));
    }
    Ok(out)
}

impl Resolver<'_> {
    fn resolve(&mut self, index: usize, depth: u32) -> Result<Resolution, GitError> {
        if self.payloads[index].is_some() {
            return Ok(Resolution::Done);
        }
        if u64::from(depth) > self.limits.max_delta_depth {
            return Err(corrupt("pack delta chain exceeds its depth bound"));
        }
        if self.resolving[index] {
            return Err(corrupt("pack delta chain is cyclic"));
        }
        self.resolving[index] = true;
        let result = self.resolve_inner(index, depth);
        self.resolving[index] = false;
        result
    }

    fn resolve_inner(&mut self, index: usize, depth: u32) -> Result<Resolution, GitError> {
        // The header is copied so delta recursion can borrow `self`
        // mutably; offsets below are plain copies for the same reason.
        let header = self.raw[index].header;
        let pack_offset = self.raw[index].pack_offset;
        let declared = self.raw[index].declared;
        if let Some(kind) = pack_kind(&header) {
            let bytes = inflate(
                &self.raw[index].compressed,
                declared,
                self.limits.max_object_bytes,
            )?;
            self.finish(index, kind, bytes)?;
            return Ok(Resolution::Done);
        }
        match &header {
            PackHeader::OfsDelta { base_distance } => {
                let base_offset = pack_offset
                    .checked_sub(*base_distance)
                    .filter(|off| *off >= 12)
                    .ok_or_else(|| corrupt("ofs-delta base lies outside the pack"))?;
                let base_index = *self
                    .offsets
                    .get(&base_offset)
                    .ok_or_else(|| corrupt("ofs-delta base is not a pack entry"))?;
                match self.resolve(base_index, depth + 1)? {
                    Resolution::Deferred => return Ok(Resolution::Deferred),
                    Resolution::Done => (),
                }
            }
            PackHeader::RefDelta { base_id } => {
                let base_oid = Oid::from(*base_id);
                if base_oid.kind() != self.kind {
                    return Err(corrupt("ref-delta base has the wrong width"));
                }
                if !self.oid_index.contains_key(&base_oid) {
                    match self.store.read(base_oid) {
                        Ok(_) => {
                            let entry_depth = 1u64;
                            if entry_depth > self.limits.max_delta_depth {
                                return Err(corrupt("pack delta chain exceeds its depth bound"));
                            }
                        }
                        Err(err) if err.code() == ruk_core::error::ErrorCode::ENotFound => {
                            return Ok(Resolution::Deferred);
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
            }
            _ => return Err(corrupt("unreachable pack entry shape")),
        }
        let base = self.base_bytes(index)?;
        let delta = inflate(
            &self.raw[index].compressed,
            declared,
            self.limits.max_object_bytes,
        )?;
        let result = apply_delta(&base, &delta)?;
        let kind = self.delta_kind(index)?;
        self.finish(index, kind, result)?;
        Ok(Resolution::Done)
    }

    fn base_bytes(&self, index: usize) -> Result<Vec<u8>, GitError> {
        match &self.raw[index].header {
            PackHeader::OfsDelta { base_distance } => {
                let base_offset = self.raw[index].pack_offset.saturating_sub(*base_distance);
                let base_index = *self
                    .offsets
                    .get(&base_offset)
                    .ok_or_else(|| corrupt("ofs-delta base is not a pack entry"))?;
                self.payloads[base_index]
                    .clone()
                    .ok_or_else(|| corrupt("ofs-delta base is unresolved"))
            }
            PackHeader::RefDelta { base_id } => {
                let base_oid = Oid::from(*base_id);
                if let Some(base_index) = self.oid_index.get(&base_oid) {
                    return self.payloads[*base_index]
                        .clone()
                        .ok_or_else(|| corrupt("ref-delta base is unresolved"));
                }
                let mut read = self.store.read(base_oid)?;
                let mut bytes = Vec::new();
                read.bytes
                    .read_to_end(&mut bytes)
                    .map_err(|err| GitError::Io {
                        detail: format!("reading delta base {base_oid}: {err}"),
                    })?;
                Ok(bytes)
            }
            _ => Err(corrupt("not a delta entry")),
        }
    }

    fn delta_kind(&self, index: usize) -> Result<ObjectKind, GitError> {
        match &self.raw[index].header {
            PackHeader::OfsDelta { base_distance } => {
                let base_offset = self.raw[index].pack_offset.saturating_sub(*base_distance);
                let base_index = *self
                    .offsets
                    .get(&base_offset)
                    .ok_or_else(|| corrupt("ofs-delta base is not a pack entry"))?;
                Ok(self.kinds[base_index])
            }
            PackHeader::RefDelta { base_id } => {
                let base_oid = Oid::from(*base_id);
                if let Some(base_index) = self.oid_index.get(&base_oid) {
                    return Ok(self.kinds[*base_index]);
                }
                Ok(self.store.read(base_oid)?.kind)
            }
            _ => Err(corrupt("not a delta entry")),
        }
    }

    fn finish(&mut self, index: usize, kind: ObjectKind, bytes: Vec<u8>) -> Result<(), GitError> {
        let type_name =
            git_type_name(kind).ok_or_else(|| corrupt("pack cannot carry a native conflict"))?;
        let oid = self
            .kind
            .hash_git_object(type_name, &bytes)
            .map_err(|err| corrupt(format!("hashing a pack object: {err}")))?;
        self.kinds[index] = kind;
        self.oids[index] = Some(oid);
        self.oid_index.insert(oid, index);
        self.payloads[index] = Some(bytes);
        Ok(())
    }
}

/// Inflates one entry, refusing more than `declared` bytes followed by a
/// strict size check: the declared size is untrusted until proven.
fn inflate(compressed: &[u8], declared: u64, max_object_bytes: u64) -> Result<Vec<u8>, GitError> {
    if declared > max_object_bytes {
        return Err(GitError::Limit {
            detail: format!(
                "pack entry declares {declared} bytes, above the {max_object_bytes}-byte limit"
            ),
        });
    }
    let capacity = usize::try_from(declared).map_err(|_| GitError::Limit {
        detail: "pack entry size does not fit in memory".to_owned(),
    })?;
    let mut out = Vec::with_capacity(capacity);
    let mut decoder = ZlibDecoder::new(compressed);
    let mut limited = decoder.by_ref().take(max_object_bytes + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|err| corrupt(format!("pack entry does not inflate: {err}")))?;
    if out.len() as u64 > max_object_bytes {
        return Err(GitError::Limit {
            detail: "pack entry inflates past the object limit".to_owned(),
        });
    }
    if out.len() as u64 != declared {
        return Err(corrupt(format!(
            "pack entry inflates to {} bytes but declares {declared}",
            out.len()
        )));
    }
    Ok(out)
}

/// Applies a canonical Git delta to `base` with every bound checked.
///
/// # Errors
/// [`GitError::Corrupt`] for truncated data, the reserved opcode, copies
/// past the base end, or size headers that disagree with reality.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, GitError> {
    let (base_len, mut rest) =
        read_varint(delta).ok_or_else(|| corrupt("delta truncates its base size"))?;
    let (result_len, rest2) =
        read_varint(rest).ok_or_else(|| corrupt("delta truncates its result size"))?;
    rest = rest2;
    if base_len != base.len() as u64 {
        return Err(corrupt(format!(
            "delta wants a {base_len}-byte base but has {} bytes",
            base.len()
        )));
    }
    if result_len > 512 << 20 {
        return Err(GitError::Limit {
            detail: format!("delta result of {result_len} bytes exceeds the ingest object bound"),
        });
    }
    let capacity = usize::try_from(result_len).map_err(|_| GitError::Limit {
        detail: "delta result size does not fit in memory".to_owned(),
    })?;
    let mut out = Vec::with_capacity(capacity);
    while !rest.is_empty() {
        let op = rest[0];
        rest = &rest[1..];
        if op & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    let byte = *rest
                        .first()
                        .ok_or_else(|| corrupt("delta truncates a copy offset"))?;
                    rest = &rest[1..];
                    offset |= usize::from(byte) << (8 * i);
                }
            }
            for i in 0..3 {
                if op & (0x10 << i) != 0 {
                    let byte = *rest
                        .first()
                        .ok_or_else(|| corrupt("delta truncates a copy size"))?;
                    rest = &rest[1..];
                    size |= usize::from(byte) << (8 * i);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset.saturating_add(size);
            if end > base.len() {
                return Err(corrupt("delta copies past the base end"));
            }
            out.extend_from_slice(&base[offset..end]);
        } else if op != 0 {
            let len = usize::from(op & 0x7f);
            if rest.len() < len {
                return Err(corrupt("delta truncates an insert"));
            }
            out.extend_from_slice(&rest[..len]);
            rest = &rest[len..];
        } else {
            return Err(corrupt("delta uses the reserved opcode"));
        }
    }
    if out.len() as u64 != result_len {
        return Err(corrupt(format!(
            "delta builds {} bytes but declares {result_len}",
            out.len()
        )));
    }
    Ok(out)
}

/// Encodes a delta from `base` to `target`: longest common prefix, longest
/// common suffix, one insert between. Small and bounded; not an optimal
/// delta search (the plan records that search as unimplemented in gix).
#[must_use]
pub fn encode_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    let mut prefix = 0;
    while prefix < base.len() && prefix < target.len() && base[prefix] == target[prefix] {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < base.len() - prefix
        && suffix < target.len() - prefix
        && base[base.len() - 1 - suffix] == target[target.len() - 1 - suffix]
    {
        suffix += 1;
    }
    let mut out = Vec::new();
    write_varint(&mut out, base.len() as u64);
    write_varint(&mut out, target.len() as u64);
    if prefix > 0 {
        write_copy(&mut out, 0, prefix);
    }
    let middle = &target[prefix..target.len() - suffix];
    for chunk in middle.chunks(127) {
        // Chunks hold at most 127 bytes, so the narrowing cast is exact.
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    if suffix > 0 {
        write_copy(&mut out, base.len() - suffix, suffix);
    }
    if prefix == 0 && middle.is_empty() && suffix == 0 && !target.is_empty() {
        out.push(target.len().min(127) as u8);
        out.extend_from_slice(&target[..target.len().min(127)]);
    }
    out
}

fn write_copy(out: &mut Vec<u8>, mut offset: usize, mut size: usize) {
    while size > 0 {
        let chunk = size.min(0x10000);
        size -= chunk;
        let start = offset;
        offset += chunk;
        let chunk_size = if chunk == 0x10000 { 0 } else { chunk };
        let mut op = 0x80u8;
        let mut extra = Vec::new();
        for i in 0..4 {
            let byte = ((start >> (8 * i)) & 0xff) as u8;
            if byte != 0 {
                op |= 1 << i;
                extra.push(byte);
            }
        }
        for i in 0..3 {
            let byte = ((chunk_size >> (8 * i)) & 0xff) as u8;
            if byte != 0 {
                op |= 0x10 << i;
                extra.push(byte);
            }
        }
        out.push(op);
        out.extend_from_slice(&extra);
    }
}

fn read_varint(mut input: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *input.first()?;
        input = &input[1..];
        if shift >= 64 && byte & 0x7f != 0 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, input));
        }
        shift += 7;
    }
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// One object for pack emission.
#[derive(Clone, Debug)]
pub struct PackEntry<'a> {
    /// Identity; must hash to `bytes` under `kind`.
    pub oid: Oid,
    /// Git object kind (never `Conflict`).
    pub kind: ObjectKind,
    /// Canonical object payload.
    pub bytes: &'a [u8],
    /// Thin-pack base: `(base oid, base bytes)`. The caller guarantees the
    /// base is permitted (reachable from the receiver's tips); the writer
    /// emits a full entry when the delta is not smaller.
    pub base: Option<(Oid, &'a [u8])>,
}

/// Where one emitted entry landed, for index building.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedEntry {
    /// Entry identity.
    pub oid: Oid,
    /// Byte offset of the entry header in the pack.
    pub offset: u64,
    /// Total entry length including the header.
    pub len: u64,
}

fn pack_type_id(kind: ObjectKind) -> Result<u8, GitError> {
    match kind {
        ObjectKind::Commit => Ok(1),
        ObjectKind::Tree => Ok(2),
        ObjectKind::Blob => Ok(3),
        ObjectKind::Tag => Ok(4),
        ObjectKind::Conflict => Err(GitError::Invalid {
            detail: "a native conflict cannot travel on the Git wire".to_owned(),
        }),
    }
}

fn deflate(data: &[u8]) -> Result<Vec<u8>, GitError> {
    let io = |err: std::io::Error| GitError::Io {
        detail: format!("deflating a pack entry: {err}"),
    };
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).map_err(io)?;
    encoder.finish().map_err(io)
}

/// Emits a self-contained pack v2 stream: `entries` in the caller's order,
/// then the trailer checksum. Per-entry thin bases are ignored.
///
/// # Errors
/// [`GitError::Invalid`] for a native conflict entry, [`GitError::Io`]
/// when `out` fails.
pub fn write_pack<W: Write>(
    out: &mut W,
    kind: HashKind,
    entries: &[PackEntry<'_>],
    interrupt: &Interrupt,
) -> Result<Vec<PackedEntry>, GitError> {
    write_pack_inner(out, kind, entries, false, interrupt)
}

/// Emits a thin pack v2 stream: an entry with a permitted base becomes a
/// `REF_DELTA` when the delta is smaller, else a full object. The caller
/// guarantees every base is permitted (reachable from the receiver's
/// advertised tips).
///
/// # Errors
/// [`GitError::Invalid`] for a native conflict entry, [`GitError::Io`]
/// when `out` fails.
pub fn write_thin_pack<W: Write>(
    out: &mut W,
    kind: HashKind,
    entries: &[PackEntry<'_>],
    interrupt: &Interrupt,
) -> Result<Vec<PackedEntry>, GitError> {
    write_pack_inner(out, kind, entries, true, interrupt)
}

/// Compression workers: twin of `import::walk::import_threads`, kept local
/// so the transport layer does not depend on the import lane.
pub(crate) fn pack_threads() -> usize {
    std::thread::available_parallelism()
        .map(|width| width.get())
        .unwrap_or(1)
        .min(16)
}

/// One entry framed and compressed, ready for serial assembly.
struct StagedEntry {
    header_bytes: Vec<u8>,
    base_prefix: Vec<u8>,
    compressed: Vec<u8>,
}

/// Frames and compresses every entry across `pack_threads` workers. Pure
/// per entry (delta selection, header encoding, zlib deflate); the
/// returned vector aligns 1:1 with `entries`, so the serial assembly in
/// [`write_pack_inner`] applies the first error in entry order, exactly as
/// the serial loop would. A cancelled wave finishes its in-flight entries
/// before the rejoin reports it; nothing is written until assembly.
fn stage_entry(
    entry: &PackEntry<'_>,
    thin: bool,
    interrupt: &Interrupt,
) -> Result<StagedEntry, GitError> {
    interrupt.check("writing the pack")?;
    let type_id = pack_type_id(entry.kind)?;
    // Pack entry headers declare the *decompressed* size. For a thin
    // REF_DELTA the base object id travels between the header and the
    // compressed delta, never inside the compressed payload.
    let mut base_prefix = Vec::new();
    let (emit_type, payload) = match (thin, entry.base) {
        (true, Some((base_oid, base_bytes))) => {
            let delta = encode_delta(base_bytes, entry.bytes);
            if delta.len() < entry.bytes.len() {
                base_prefix.extend_from_slice(base_oid.as_bytes());
                (7u8, delta)
            } else {
                (type_id, entry.bytes.to_vec())
            }
        }
        _ => (type_id, entry.bytes.to_vec()),
    };
    let compressed = deflate(&payload)?;
    let declared = payload.len();
    // The mask bounds the value to four bits, so the narrowing cast is exact.
    let mut first = (emit_type << 4) | ((declared & 0x0f) as u8);
    let mut size = declared;
    size >>= 4;
    if size != 0 {
        first |= 0x80;
    }
    let mut header_bytes = vec![first];
    while size != 0 {
        // The mask bounds the value to seven bits, so the narrowing cast is exact.
        let mut byte = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        header_bytes.push(byte);
    }
    Ok(StagedEntry {
        header_bytes,
        base_prefix,
        compressed,
    })
}

fn compress_entries(
    entries: &[PackEntry<'_>],
    thin: bool,
    interrupt: &Interrupt,
) -> Vec<Result<StagedEntry, GitError>> {
    fn stage_one(
        entry: &PackEntry<'_>,
        thin: bool,
        interrupt: &Interrupt,
    ) -> Result<StagedEntry, GitError> {
        stage_entry(entry, thin, interrupt)
    }

    let width = pack_threads();
    if width <= 1 || entries.len() <= 1 {
        return entries
            .iter()
            .map(|entry| stage_one(entry, thin, interrupt))
            .collect();
    }
    let piece = entries.len().div_ceil(width);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for part in entries.chunks(piece) {
            handles.push(scope.spawn(move || {
                part.iter()
                    .map(|entry| stage_one(entry, thin, interrupt))
                    .collect::<Vec<_>>()
            }));
        }
        let mut staged = Vec::with_capacity(entries.len());
        for handle in handles {
            match handle.join() {
                Ok(part) => staged.extend(part),
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        staged
    })
}

fn write_pack_inner<W: Write>(
    out: &mut W,
    kind: HashKind,
    entries: &[PackEntry<'_>],
    thin: bool,
    interrupt: &Interrupt,
) -> Result<Vec<PackedEntry>, GitError> {
    use gix_hash::Hasher;
    let io = |err: std::io::Error| GitError::Io {
        detail: format!("writing the pack: {err}"),
    };
    let count = u32::try_from(entries.len()).map_err(|_| GitError::Invalid {
        detail: "pack entry count exceeds u32".to_owned(),
    })?;
    let mut hasher: Hasher = gix_hash::hasher(kind.gix());
    let mut header = [0u8; 12];
    header[..4].copy_from_slice(b"PACK");
    header[4..8].copy_from_slice(&2u32.to_be_bytes());
    header[8..12].copy_from_slice(&count.to_be_bytes());
    hasher.update(&header);
    out.write_all(&header).map_err(io)?;
    // Byte assembly stays serial: the pack hash chains every byte in
    // entry order, so only the compression above fans out.
    let staged = compress_entries(entries, thin, interrupt);
    let mut offset = 12u64;
    let mut index = Vec::with_capacity(entries.len());
    for (entry, staged) in entries.iter().zip(staged) {
        let staged = staged?;
        let entry_offset = offset;
        hasher.update(&staged.header_bytes);
        out.write_all(&staged.header_bytes).map_err(io)?;
        if !staged.base_prefix.is_empty() {
            hasher.update(&staged.base_prefix);
            out.write_all(&staged.base_prefix).map_err(io)?;
        }
        hasher.update(&staged.compressed);
        out.write_all(&staged.compressed).map_err(io)?;
        let entry_len =
            (staged.header_bytes.len() + staged.base_prefix.len() + staged.compressed.len()) as u64;
        offset += entry_len;
        index.push(PackedEntry {
            oid: entry.oid,
            offset: entry_offset,
            len: entry_len,
        });
    }
    let checksum = hasher
        .try_finalize()
        .map_err(|err| corrupt(format!("finishing the pack hash: {err}")))?;
    out.write_all(checksum.as_bytes()).map_err(io)?;
    out.flush().map_err(io)?;
    Ok(index)
}

/// A pack stream written one entry at a time: the header carries the
/// total count up front, then each staged entry is hashed and emitted
/// before the next loads, so peak memory stays near one entry instead of
/// the whole pack. Assembly order and bytes are identical to
/// [`write_pack_inner`]; only the worker fan-out is gone.
pub struct PackStreamWriter<'w, W: Write> {
    out: &'w mut W,
    hasher: gix_hash::Hasher,
    thin: bool,
    offset: u64,
    index: Vec<PackedEntry>,
}

impl<W: Write> std::fmt::Debug for PackStreamWriter<'_, W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PackStreamWriter")
            .field("thin", &self.thin)
            .field("offset", &self.offset)
            .field("entries", &self.index.len())
            .finish_non_exhaustive()
    }
}

impl<'w, W: Write> PackStreamWriter<'w, W> {
    /// Emits the pack header for `count` entries.
    ///
    /// # Errors
    /// [`GitError::Invalid`] past the u32 entry count, [`GitError::Io`]
    /// when `out` fails.
    pub fn begin(
        out: &'w mut W,
        kind: HashKind,
        count: usize,
        thin: bool,
    ) -> Result<Self, GitError> {
        let io = |err: std::io::Error| GitError::Io {
            detail: format!("writing the pack: {err}"),
        };
        let count = u32::try_from(count).map_err(|_| GitError::Invalid {
            detail: "pack entry count exceeds u32".to_owned(),
        })?;
        let mut hasher = gix_hash::hasher(kind.gix());
        let mut header = [0u8; 12];
        header[..4].copy_from_slice(b"PACK");
        header[4..8].copy_from_slice(&2u32.to_be_bytes());
        header[8..12].copy_from_slice(&count.to_be_bytes());
        hasher.update(&header);
        out.write_all(&header).map_err(io)?;
        Ok(Self {
            out,
            hasher,
            thin,
            offset: 12,
            index: Vec::new(),
        })
    }

    /// Stages, hashes, and emits one entry, then drops its bytes: the
    /// only entry resident at a time.
    ///
    /// # Errors
    /// [`GitError::Invalid`] for a native conflict entry, [`GitError::Io`]
    /// when `out` fails.
    pub fn entry(&mut self, entry: &PackEntry<'_>, interrupt: &Interrupt) -> Result<(), GitError> {
        let io = |err: std::io::Error| GitError::Io {
            detail: format!("writing the pack: {err}"),
        };
        let staged = stage_entry(entry, self.thin, interrupt)?;
        let entry_offset = self.offset;
        self.hasher.update(&staged.header_bytes);
        self.out.write_all(&staged.header_bytes).map_err(io)?;
        if !staged.base_prefix.is_empty() {
            self.hasher.update(&staged.base_prefix);
            self.out.write_all(&staged.base_prefix).map_err(io)?;
        }
        self.hasher.update(&staged.compressed);
        self.out.write_all(&staged.compressed).map_err(io)?;
        let entry_len =
            (staged.header_bytes.len() + staged.base_prefix.len() + staged.compressed.len()) as u64;
        self.offset += entry_len;
        self.index.push(PackedEntry {
            oid: entry.oid,
            offset: entry_offset,
            len: entry_len,
        });
        Ok(())
    }

    /// Emits the trailer checksum over every streamed byte.
    ///
    /// # Errors
    /// [`GitError::Io`] when `out` fails.
    pub fn finish(self) -> Result<Vec<PackedEntry>, GitError> {
        let io = |err: std::io::Error| GitError::Io {
            detail: format!("writing the pack: {err}"),
        };
        let checksum = self
            .hasher
            .try_finalize()
            .map_err(|err| corrupt(format!("finishing the pack hash: {err}")))?;
        self.out.write_all(checksum.as_bytes()).map_err(io)?;
        self.out.flush().map_err(io)?;
        Ok(self.index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_round_trips() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"a", b"a"),
            (b"hello world", b"hello brave new world"),
            (
                b"prefix-same-middle-differs-suffix-same",
                b"prefix-same-CHANGED-suffix-same",
            ),
            (&[0u8; 300], &[0u8; 299]),
            (b"short", b"a much longer target with common prefix s"),
        ];
        for (base, target) in cases {
            let delta = encode_delta(base, target);
            let back = apply_delta(base, &delta).expect("round trip");
            assert_eq!(&back, target, "base {base:?}");
        }
    }

    #[test]
    fn streaming_writer_matches_batched_bytes() {
        let blob = b"hello world, hello brave new world".to_vec();
        let blob_oid = HashKind::Sha1.hash_git_object("blob", &blob).expect("hash");
        let changed = b"hello world, hello CHANGED new world".to_vec();
        let changed_oid = HashKind::Sha1
            .hash_git_object("blob", &changed)
            .expect("hash");
        let entries = [
            PackEntry {
                oid: blob_oid,
                kind: ObjectKind::Blob,
                bytes: &blob,
                base: None,
            },
            PackEntry {
                oid: changed_oid,
                kind: ObjectKind::Blob,
                bytes: &changed,
                base: Some((blob_oid, blob.as_slice())),
            },
        ];
        for thin in [false, true] {
            let mut batched = Vec::new();
            if thin {
                write_thin_pack(&mut batched, HashKind::Sha1, &entries, &Interrupt::none())
                    .expect("write");
            } else {
                write_pack(&mut batched, HashKind::Sha1, &entries, &Interrupt::none())
                    .expect("write");
            }
            let mut streamed = Vec::new();
            let mut writer =
                PackStreamWriter::begin(&mut streamed, HashKind::Sha1, entries.len(), thin)
                    .expect("begin");
            for entry in &entries {
                writer.entry(entry, &Interrupt::none()).expect("entry");
            }
            writer.finish().expect("finish");
            assert_eq!(streamed, batched, "thin={thin}");
        }
        assert!(
            entries[1]
                .bytes
                .windows(b"hello".len())
                .any(|w| w == b"hello")
        );
    }

    #[test]
    fn delta_rejects_malformed_input() {
        let base = b"0123456789abcdef";
        let good = encode_delta(base, b"0123XY89abcdef!");
        assert!(apply_delta(base, &good).is_ok());
        let bad: &[&[u8]] = &[
            b"",
            b"\x10",
            b"\x10\x05\x00",
            b"\x11\x05copy",
            b"\x10\x05\x91\x0f",
            b"\x10\x06hello!",
            b"\x10\x05\xf0",
        ];
        for input in bad {
            assert!(apply_delta(base, input).is_err(), "{input:?} must fail");
        }
    }

    #[test]
    fn link_parsers_reject_garbage() {
        let sha1 = HashKind::Sha1;
        assert!(object_links(ObjectKind::Commit, b"no headers here", sha1).is_err());
        assert!(object_links(ObjectKind::Tree, b"\xff", sha1).is_err());
        assert!(object_links(ObjectKind::Tag, b"type blob\n", sha1).is_err());
        let blob = object_links(ObjectKind::Blob, b"anything", sha1).expect("blob");
        assert_eq!(blob, Links::default());
    }

    #[test]
    fn write_then_ingest_round_trip() {
        let store = crate::transport::session::test_support::test_store(HashKind::Sha1);
        let blob = b"hello\n".to_vec();
        let tree = {
            let mut t = Vec::new();
            t.extend_from_slice(b"100644 a\x00");
            let oid = HashKind::Sha1.hash_git_object("blob", &blob).expect("hash");
            t.extend_from_slice(oid.as_bytes());
            t
        };
        let tree_oid = HashKind::Sha1.hash_git_object("tree", &tree).expect("hash");
        let commit = format!(
            "tree {}\nauthor a <a@x> 0 +0000\ncommitter a <a@x> 0 +0000\n\nmsg\n",
            tree_oid.to_hex()
        )
        .into_bytes();
        let entries = [
            PackEntry {
                oid: HashKind::Sha1.hash_git_object("blob", &blob).expect("hash"),
                kind: ObjectKind::Blob,
                bytes: &blob,
                base: None,
            },
            PackEntry {
                oid: tree_oid,
                kind: ObjectKind::Tree,
                bytes: &tree,
                base: None,
            },
            PackEntry {
                oid: HashKind::Sha1
                    .hash_git_object("commit", &commit)
                    .expect("hash"),
                kind: ObjectKind::Commit,
                bytes: &commit,
                base: None,
            },
        ];
        let mut pack = Vec::new();
        write_pack(&mut pack, HashKind::Sha1, &entries, &Interrupt::none()).expect("write");
        let staged = ingest_pack(
            &pack[..],
            HashKind::Sha1,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("ingest");
        assert_eq!(staged.oids().len(), 3);
        for (want, got) in entries.iter().map(|e| e.oid).zip(staged.oids()) {
            assert_eq!(want, *got);
        }
    }

    #[test]
    fn fixture_pack_ingests_with_deltas() {
        let store = crate::transport::session::test_support::test_store(HashKind::Sha1);
        let pack = include_bytes!("fixtures/basic.pack");
        let staged = ingest_pack(
            &pack[..],
            HashKind::Sha1,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("fixture ingests");
        assert!(
            staged.oids().len() >= 4,
            "fixture holds blob/tree/commit/tag"
        );
        let kinds: Vec<ObjectKind> = staged.objects().iter().map(|o| o.kind()).collect();
        assert!(kinds.contains(&ObjectKind::Commit));
        assert!(kinds.contains(&ObjectKind::Tag));
    }

    #[test]
    fn thin_fixture_resolves_against_the_store() {
        let store = crate::transport::session::test_support::test_store(HashKind::Sha1);
        let base_pack = include_bytes!("fixtures/base.pack");
        let staged = ingest_pack(
            &base_pack[..],
            HashKind::Sha1,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("base ingests");
        // Commit "three" and its big blob are the thin pack's bases but are
        // not in base.pack: stage them from the full-history fixture so the
        // store holds every base the thin pack may name.
        let basic = include_bytes!("fixtures/basic.pack");
        let staged_basic = ingest_pack(
            &basic[..],
            HashKind::Sha1,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("history ingests");
        let mut objects = staged.into_objects();
        objects.extend(staged_basic.into_objects());
        let publication = store
            .publish(
                objects,
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("bases publish");
        assert!(!publication.objects.is_empty());
        let thin = include_bytes!("fixtures/thin.pack");
        let staged = ingest_pack(
            &thin[..],
            HashKind::Sha1,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("thin ingests against stored bases");
        assert_eq!(staged.oids().len(), 3);
    }

    #[test]
    fn thin_fixture_fails_without_its_base() {
        let store = crate::transport::session::test_support::test_store(HashKind::Sha1);
        let thin = include_bytes!("fixtures/thin.pack");
        let err = ingest_pack(
            &thin[..],
            HashKind::Sha1,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect_err("external base is absent");
        assert!(matches!(err, GitError::Corrupt { .. }), "got {err:?}");
    }

    #[test]
    fn in_pack_ref_delta_fixture_ingests_standalone() {
        let store = crate::transport::session::test_support::test_store(HashKind::Sha1);
        let pack = include_bytes!("fixtures/delta.pack");
        let staged = ingest_pack(
            &pack[..],
            HashKind::Sha1,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("in-pack ref-delta ingests");
        assert_eq!(staged.oids().len(), 5);
    }

    #[test]
    fn own_thin_pack_round_trips() {
        let base = b"the quick brown fox jumps over the lazy dog".to_vec();
        let target = b"the quick brown fox JUMPS over the lazy dog!".to_vec();
        let base_oid = HashKind::Sha1.hash_git_object("blob", &base).expect("hash");
        let target_oid = HashKind::Sha1
            .hash_git_object("blob", &target)
            .expect("hash");
        let entries = [PackEntry {
            oid: target_oid,
            kind: ObjectKind::Blob,
            bytes: &target,
            base: Some((base_oid, &base)),
        }];
        let mut pack = Vec::new();
        write_thin_pack(&mut pack, HashKind::Sha1, &entries, &Interrupt::none()).expect("write");
        let store = crate::transport::session::test_support::test_store(HashKind::Sha1);
        let prepared = store
            .prepare(ObjectKind::Blob, base.len() as u64, &base[..], None)
            .expect("stage base");
        store
            .publish(
                vec![prepared],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish base");
        let staged = ingest_pack(
            &pack[..],
            HashKind::Sha1,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("thin ingests");
        assert_eq!(staged.oids().len(), 1);
        assert_eq!(staged.oids()[0], target_oid);
    }
}
