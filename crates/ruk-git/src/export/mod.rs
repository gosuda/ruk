//! `ruk export <dir>`: a bare Git repository with exact refs and a
//! self-contained pack, without invoking system Git.
//!
//! [`export_repository`] pages every ref and ref conflict, walks every
//! reachable Git object through [`Store::read`], streams the pack and its
//! index, writes the refs and the reflogs of exported refs, then reopens
//! the pack and index with gix readers and checks every object back
//! against the store before writing `HEAD`. `HEAD` is the commit point:
//! without it Git does not recognize the directory, so a failed export is
//! never a complete-looking corrupt repository.
//!
//! The one invariant: export reports every unexportable fact. Native
//! records, conflicted bookmarks, workspaces, claims, the operation log,
//! capability policy, and shallow/promisor flags are named in the
//! [`ExportReport`]; nothing is silently dropped or rendered as a
//! placeholder. See `local://ruk-git-export-api.md` for the integration
//! surface.
//!
//! # Preconditions
//!
//! The caller holds exclusive repository ownership (the coordinator lane):
//! refs are paged across transactions, and objects are walked after, so a
//! concurrent writer could otherwise move the export under itself. Each
//! read observes committed state and fails closed on corruption through
//! [`Store::read`].

pub mod layout;
pub mod objects;
pub mod pack;
pub mod refs;
pub mod report;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::RefName;
use ruk_core::refs::{ReflogEntry, page_reflogs};
use ruk_core::store::durability::install_file;
use ruk_core::store::{ObjectKind, Store, StoreError};
use ruk_core::workspace::HeadRef;

pub use pack::{PackedEntry, PackWriter, pack_name, write_idx_v2};
pub use report::{
    DroppedReflog, ExportReport, HeadReport, Loss, LossCategory, PackReport, ReflogDropReason,
    ReflogsReport, RefsReport, UnexportedReason, UnexportedRef, disposition, object_format,
};

use layout::{Layout, config_bytes, description_bytes, log_path, reflog_line};
use objects::Closure;
use refs::{RefPlan, packed_line, peel_line, symbolic_bytes};

use crate::GitError;

/// Rows read per reflog page.
const REFLOG_PAGE: usize = 1000;
/// Bytes compared per chunk while verifying.
const VERIFY_CHUNK: usize = 64 * 1024;
/// Placeholder for `install_file`'s error channel; the real error travels
/// beside it (see [`write_pack_file`]).
const PACK_WRITE_FAILED: &str = "pack write failed; see export error";

/// What to export, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportRequest {
    /// The new repository directory. Must not exist; its parent must exist
    /// (and, on Windows, be durable).
    pub target: PathBuf,
    /// The HEAD to write: symbolic, or a detached object id.
    pub head: HeadRef,
    /// The `.ruk/store` directory, used only to detect the capability
    /// policy file for the loss report.
    pub store_root: PathBuf,
}

/// Writes a bare Git repository of the store's Git-exportable state.
///
/// Publication order is pack, index, shallow, refs, reflogs, config,
/// description, verification, then `HEAD` last.
///
/// # Errors
/// [`GitError::Invalid`] for an existing target or a detached HEAD at a
/// native record; [`GitError::NotFound`] for a promisor-omitted object the
/// caller must fetch first; [`GitError::Corrupt`] for a missing or
/// malformed reachable object or a failed verification; store and I/O
/// failures.
pub fn export_repository(store: &Store, request: &ExportRequest) -> Result<ExportReport, GitError> {
    let kind = store.hash_kind();
    let mut layout = Layout::create(&request.target, kind)?;
    let mut closure = Closure::new(store);
    let mut plan = RefPlan::build(store, &request.head, &mut closure)?;
    let count = u32::try_from(closure.objects().len()).map_err(|_| GitError::Limit {
        detail: format!("{} objects exceed one pack", closure.objects().len()),
    })?;

    let sorted: Vec<Oid> = closure.objects().keys().copied().collect();
    let stem = format!("pack-{}", pack_name(kind, &sorted)?.to_hex());
    let kinds: BTreeMap<Oid, ObjectKind> = closure.objects().clone();
    let (entries, pack_checksum) =
        write_pack_file(store, &mut layout, &stem, kind, count, &sorted, &kinds)?;
    let mut entries_sorted = entries;
    let mut idx_bytes = Vec::new();
    write_idx_v2(&mut entries_sorted, pack_checksum, kind, &mut idx_bytes)?;
    layout.install(&Layout::idx_relative(&stem), &idx_bytes)?;

    if !closure.shallow().is_empty() {
        let mut shallow = Vec::new();
        for oid in closure.shallow() {
            shallow.extend_from_slice(oid.to_hex().as_bytes());
            shallow.push(b'\n');
        }
        layout.install(Path::new("shallow"), &shallow)?;
    }

    let mut packed_refs = b"# pack-refs with: peeled fully-peeled sorted \n".to_vec();
    for (name, &(target, peeled)) in &plan.direct {
        packed_refs.extend_from_slice(&packed_line(name, &target));
        if peeled != target {
            packed_refs.extend_from_slice(&peel_line(&peeled));
        }
    }
    layout.install(Path::new("packed-refs"), &packed_refs)?;
    for (name, target) in &plan.symbolic {
        layout.install(&loose_path(name)?, &symbolic_bytes(target))?;
    }

    let reflogs = write_reflogs(store, &mut layout, &plan, kind)?;
    layout.install(Path::new("config"), &config_bytes(kind))?;
    layout.install(Path::new("description"), &description_bytes())?;

    verify_export(store, &layout, &stem, kind, &kinds, pack_checksum)?;

    let head_bytes = match &request.head {
        HeadRef::Symbolic(name) => symbolic_bytes(name),
        HeadRef::Detached(oid) => {
            let mut line = oid.to_hex().into_bytes();
            line.push(b'\n');
            line
        }
    };
    layout.install(Path::new("HEAD"), &head_bytes)?;

    plan.unexported.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    Ok(ExportReport {
        version: report::REPORT_VERSION,
        object_format: object_format(kind),
        head: HeadReport {
            target: request.head.clone(),
            exported: plan.head_exported,
        },
        pack: PackReport {
            name: stem,
            objects: u64::from(count),
            checksum: pack_checksum,
        },
        refs: RefsReport {
            packed: u64::try_from(plan.direct.len()).unwrap_or(u64::MAX),
            symbolic: u64::try_from(plan.symbolic.len()).unwrap_or(u64::MAX),
        },
        reflogs,
        shallow: closure.shallow().iter().copied().collect(),
        unexported_refs: plan.unexported,
        losses: report::census(store, &request.store_root)?,
    })
}

/// The loose file path of a ref: its name bytes as a relative path.
fn loose_path(name: &RefName) -> Result<PathBuf, GitError> {
    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;
        Ok(Path::new(OsStr::from_bytes(name.as_bytes())).to_path_buf())
    }
    #[cfg(not(unix))]
    {
        let text = std::str::from_utf8(name.as_bytes()).map_err(|_| GitError::Invalid {
            detail: "non-UTF-8 ref names need a UTF-8 filesystem".to_owned(),
        })?;
        Ok(PathBuf::from(text))
    }
}

/// Streams the pack through `install_file` under its final name (known
/// upfront from [`pack_name`]), reading each object from the store.
///
/// `install_file`'s closure returns only `Result<(), StoreError>`, so the
/// entries, the checksum, and any [`GitError`] travel through captured
/// slots; a pack failure leaves no final entry, and the stashed error is
/// returned after.
fn write_pack_file(
    store: &Store,
    layout: &mut Layout,
    stem: &str,
    kind: HashKind,
    count: u32,
    sorted: &[Oid],
    kinds: &BTreeMap<Oid, ObjectKind>,
) -> Result<(Vec<PackedEntry>, Oid), GitError> {
    let path = layout.pack_path(stem);
    let mut entries_out: Vec<PackedEntry> = Vec::new();
    let mut checksum_out: Option<Oid> = None;
    let mut stashed: Option<GitError> = None;
    install_file(&path, |file| {
        let out = BufWriter::new(&mut *file);
        match run_pack(store, out, kind, count, sorted, kinds) {
            Ok((entries, checksum)) => {
                entries_out = entries;
                checksum_out = Some(checksum);
                Ok(())
            }
            Err(err) => {
                stashed = Some(err);
                Err(StoreError::Invalid(PACK_WRITE_FAILED.to_owned()))
            }
        }
    })
    .map_err(layout::store_io)?;
    if let Some(err) = stashed {
        return Err(err);
    }
    let Some(checksum) = checksum_out else {
        return Err(GitError::Corrupt {
            detail: "the pack writer finished without a checksum".to_owned(),
        });
    };
    let len = std::fs::metadata(&path).map_err(pack::io_error)?.len();
    layout.note(&Layout::pack_relative(stem), len);
    Ok((entries_out, checksum))
}

/// Appends every object and seals the pack.
fn run_pack<W: Write>(
    store: &Store,
    out: W,
    kind: HashKind,
    count: u32,
    sorted: &[Oid],
    kinds: &BTreeMap<Oid, ObjectKind>,
) -> Result<(Vec<PackedEntry>, Oid), GitError> {
    let mut writer = PackWriter::new(out, kind, count)?;
    for &oid in sorted {
        let want = kinds.get(&oid).copied().unwrap_or(ObjectKind::Blob);
        let object = objects::read_object(store, oid)?;
        if object.kind != want {
            return Err(GitError::Corrupt {
                detail: format!("object {oid} changed kind between walk and pack"),
            });
        }
        writer.append_stream(oid, want, object.bytes.len(), object.bytes)?;
    }
    writer.finish()
}

/// Writes `logs/<ref>` for every exported ref that has reflog rows.
/// Entries whose message has a newline cannot use the line format and are
/// counted as dropped, never normalized.
fn write_reflogs(
    store: &Store,
    layout: &mut Layout,
    plan: &RefPlan,
    kind: HashKind,
) -> Result<ReflogsReport, GitError> {
    let mut report = ReflogsReport::default();
    for name in plan.direct.keys() {
        let mut lines = Vec::new();
        let mut entries = 0u64;
        let mut dropped = 0u64;
        let mut after: Option<ruk_core::refs::ReflogKey> = None;
        loop {
            let page = page_reflogs(store, name, after.as_ref(), REFLOG_PAGE)?;
            let more = page.more;
            for ReflogEntry { key, record } in page.entries {
                after = Some(key);
                if record.message.as_bytes().iter().any(|&byte| byte == b'\n') {
                    dropped += 1;
                    continue;
                }
                lines.extend_from_slice(&reflog_line(
                    record.old_oid,
                    record.new_oid,
                    &record.committer,
                    record.message.as_bytes(),
                    kind,
                )?);
                entries += 1;
            }
            if !more {
                break;
            }
        }
        if dropped > 0 {
            report.dropped.push(DroppedReflog {
                name: name.clone(),
                reason: ReflogDropReason::MultiLineMessage,
                entries: dropped,
            });
        }
        if entries == 0 {
            continue;
        }
        layout.install(&log_path(name), &lines)?;
        report.refs += 1;
        report.entries += entries;
    }
    Ok(report)
}

/// Reopens the written pack and index and checks everything: both
/// trailers, the index checksum against the pack checksum, the object
/// count, every expected id present in the index, each entry's type, CRC,
/// re-hashed identity, and byte equality with the store.
fn verify_export(
    store: &Store,
    layout: &Layout,
    stem: &str,
    kind: HashKind,
    expected: &BTreeMap<Oid, ObjectKind>,
    pack_checksum: Oid,
) -> Result<(), GitError> {
    let pack_path = layout.pack_path(stem);
    let idx_path = layout.idx_path(stem);
    let (pack_computed, pack_stored) = hash_trailer(&pack_path, kind)?;
    if pack_computed != pack_stored || pack_stored != pack_checksum {
        return Err(GitError::Corrupt {
            detail: "the written pack trailer does not match its bytes".to_owned(),
        });
    }
    let (idx_computed, idx_stored) = hash_trailer(&idx_path, kind)?;
    if idx_computed != idx_stored {
        return Err(GitError::Corrupt {
            detail: "the written index trailer does not match its bytes".to_owned(),
        });
    }
    let pack = gix_pack::data::File::at(&pack_path, kind.gix())
        .map_err(|err| corrupt(format!("the written pack does not parse: {err}")))?;
    let index = gix_pack::index::File::at(&idx_path, kind.gix())
        .map_err(|err| corrupt(format!("the written index does not parse: {err}")))?;
    if pack.version() != gix_pack::data::Version::V2 {
        return Err(corrupt("the written pack is not version 2".to_owned()));
    }
    if index.version() != gix_pack::index::Version::V2 {
        return Err(corrupt("the written index is not version 2".to_owned()));
    }
    let count = expected.len();
    let pack_count =
        usize::try_from(pack.num_objects()).map_err(|_| corrupt("the pack is too large".to_owned()))?;
    let index_count =
        usize::try_from(index.num_objects()).map_err(|_| corrupt("the index is too large".to_owned()))?;
    if pack_count != count || index_count != count {
        return Err(corrupt(format!(
            "the written pack holds {pack_count} objects, expected {count}"
        )));
    }
    if Oid::from(index.pack_checksum()) != pack_checksum {
        return Err(corrupt("the index names a different pack".to_owned()));
    }
    verify_entries(store, &pack, &index, expected, kind)
}

/// Checks every entry: index presence, type, CRC, identity, and bytes.
fn verify_entries(
    store: &Store,
    pack: &gix_pack::data::File,
    index: &gix_pack::index::File,
    expected: &BTreeMap<Oid, ObjectKind>,
    kind: HashKind,
) -> Result<(), GitError> {
    let mut by_offset: Vec<(u64, Oid, ObjectKind, u32)> = Vec::with_capacity(expected.len());
    for (&oid, &want) in expected {
        let gix_id = gix_hash::ObjectId::from(oid);
        let at = index
            .lookup(&gix_id)
            .ok_or_else(|| corrupt(format!("object {oid} is missing from the index")))?;
        by_offset.push((index.pack_offset_at_index(at), oid, want, at));
    }
    by_offset.sort_unstable_by_key(|&(offset, _, _, _)| offset);
    let end = u64::try_from(pack.pack_end())
        .map_err(|_| corrupt("the pack is too large".to_owned()))?;
    for (position, &(offset, oid, want, at)) in by_offset.iter().enumerate() {
        let next = by_offset.get(position + 1).map_or(end, |&(next, ..)| next);
        if next < offset {
            return Err(corrupt(format!("object {oid} has a backwards offset")));
        }
        verify_entry(store, pack, index, offset, next - offset, oid, want, at, kind)?;
    }
    Ok(())
}

/// Checks one entry's type, CRC, hash identity, and store bytes.
fn verify_entry(
    store: &Store,
    pack: &gix_pack::data::File,
    index: &gix_pack::index::File,
    offset: u64,
    size: u64,
    oid: Oid,
    want: ObjectKind,
    at: u32,
    kind: HashKind,
) -> Result<(), GitError> {
    let entry = pack
        .entry(offset)
        .map_err(|err| corrupt(format!("object {oid} does not parse: {err}")))?;
    let actual = match entry.header {
        gix_pack::data::entry::Header::Commit => ObjectKind::Commit,
        gix_pack::data::entry::Header::Tree => ObjectKind::Tree,
        gix_pack::data::entry::Header::Blob => ObjectKind::Blob,
        gix_pack::data::entry::Header::Tag => ObjectKind::Tag,
        gix_pack::data::entry::Header::RefDelta { .. }
        | gix_pack::data::entry::Header::OfsDelta { .. } => {
            return Err(corrupt(format!("object {oid} is deltified in a stored pack")));
        }
    };
    if actual != want {
        return Err(corrupt(format!(
            "object {oid} packs as {actual:?}, expected {want:?}"
        )));
    }
    let Some(want_crc) = index.crc32_at_index(at) else {
        return Err(corrupt(format!("object {oid} has no CRC in the index")));
    };
    let size_usize = usize::try_from(size).map_err(|_| corrupt(format!("object {oid} is too large")))?;
    if pack.entry_crc32(offset, size_usize) != want_crc {
        return Err(corrupt(format!("object {oid} fails its index CRC")));
    }
    let range = offset..offset + size;
    let Some(slice) = pack.entry_slice(range) else {
        return Err(corrupt(format!("object {oid} runs past the pack end")));
    };
    // The zlib stream starts after the entry's varint header, at the
    // absolute `data_offset`; the slice starts at the header, so skip the
    // difference.
    let prefix = entry.data_offset.checked_sub(offset).ok_or_else(|| {
        corrupt(format!("object {oid} has its data before its header"))
    })?;
    let start = usize::try_from(prefix)
        .map_err(|_| corrupt(format!("object {oid} is too large")))?;
    let Some(compressed) = slice.get(start..) else {
        return Err(corrupt(format!("object {oid} has its data past its end")));
    };
    verify_bytes(
        store,
        compressed,
        entry.decompressed_size,
        oid,
        want,
        kind,
    )
}

/// Inflates one entry, re-hashes it, and byte-compares it with the store.
fn verify_bytes(
    store: &Store,
    compressed: &[u8],
    decompressed_size: u64,
    oid: Oid,
    want: ObjectKind,
    kind: HashKind,
) -> Result<(), GitError> {
    let object = objects::read_object(store, oid)?;
    if object.kind != want {
        return Err(corrupt(format!("object {oid} changed kind during export")));
    }
    let Some(header_name) = want.git_header_name() else {
        return Err(corrupt(format!("object {oid} is not a Git object")));
    };
    let mut decoder = ZlibDecoder::new(compressed);
    let mut hasher = gix_hash::hasher(kind.gix());
    hasher.update(header_name.as_bytes());
    hasher.update(b" ");
    hasher.update(object.bytes.len().to_string().as_bytes());
    hasher.update(b"\0");
    let stored_len = object.bytes.len();
    let mut stored = object.bytes;
    let mut inflated = vec![0u8; VERIFY_CHUNK];
    let mut total = 0u64;
    loop {
        let read = decoder
            .read(&mut inflated)
            .map_err(|err| corrupt(format!("object {oid} does not inflate: {err}")))?;
        if read == 0 {
            break;
        }
        let chunk = inflated.get(..read).unwrap_or_default();
        hasher.update(chunk);
        total = total.saturating_add(pack::to_u64(chunk.len()));
        let mut chunk_stored = vec![0u8; read];
        stored
            .read_exact(&mut chunk_stored)
            .map_err(|_| corrupt(format!("object {oid} differs from the store")))?;
        if chunk != chunk_stored.as_slice() {
            return Err(corrupt(format!("object {oid} differs from the store")));
        }
    }
    if total != decompressed_size || total != stored_len {
        return Err(corrupt(format!("object {oid} has a wrong size")));
    }
    if stored.read(&mut [0u8; 1]).unwrap_or(0) != 0 {
        return Err(corrupt(format!("object {oid} differs from the store")));
    }
    let recomputed = hasher
        .try_finalize()
        .map(Oid::from)
        .map_err(|err| corrupt(format!("object {oid} hash refused: {err}")))?;
    if recomputed != oid {
        return Err(corrupt(format!("object {oid} re-hashes differently")));
    }
    Ok(())
}

/// Hashes every byte of `path` except its trailing hash, and reads that
/// trailing hash back.
fn hash_trailer(path: &Path, kind: HashKind) -> Result<(Oid, Oid), GitError> {
    let file = File::open(path).map_err(pack::io_error)?;
    let len = file.metadata().map_err(pack::io_error)?.len();
    let hash_len = kind.oid_len() as u64;
    if len < hash_len {
        return Err(corrupt(format!(
            "{} is shorter than its own trailer",
            path.display()
        )));
    }
    let mut hasher = gix_hash::hasher(kind.gix());
    let mut reader = BufReader::new(file);
    let mut remaining = len - hash_len;
    let mut buf = vec![0u8; VERIFY_CHUNK];
    while remaining > 0 {
        let capped = u64::try_from(VERIFY_CHUNK)
            .unwrap_or(u64::MAX)
            .min(remaining);
        let want =
            usize::try_from(capped).map_err(|_| corrupt("a hash chunk is too large".to_owned()))?;
        reader.read_exact(&mut buf[..want]).map_err(pack::io_error)?;
        hasher.update(&buf[..want]);
        remaining -= capped;
    }
    drop(reader);
    let computed = hasher.try_finalize().map(Oid::from).map_err(|err| {
        corrupt(format!("{} hash refused: {err}", path.display()))
    })?;
    let mut file = File::open(path).map_err(pack::io_error)?;
    use std::io::Seek as _;
    file.seek(std::io::SeekFrom::Start(len - hash_len))
        .map_err(pack::io_error)?;
    let mut trailer = vec![0u8; kind.oid_len()];
    file.read_exact(&mut trailer).map_err(pack::io_error)?;
    let stored = Oid::from_bytes(&trailer).map_err(|err| {
        corrupt(format!("{} has a malformed trailer: {err}", path.display()))
    })?;
    Ok((computed, stored))
}

fn corrupt(detail: String) -> GitError {
    GitError::Corrupt { detail }
}
