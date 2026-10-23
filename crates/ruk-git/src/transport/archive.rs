//! Server half of `upload-archive`: serves `git archive --remote` (tar only).
//!
//! The client sends `argument <value>` pkt-lines and a flush; the server
//! answers `ACK` plus a flush and then the tar stream sideband-multiplexed
//! on band 1, ending with a flush. Validation failures before `ACK` are
//! refused with a `NACK` line instead; failures mid-stream go out on band 3
//! and abort the connection. The tar layout is ustar: 512-byte records, a
//! `ustar\0`/`00` magic, `root`/`root` ownership, every file mode normalized
//! the way the oracle normalizes it (regular `0664` or `0775` when the owner
//! execute bit is set, symlink `0777`, directory `0775`), directory records
//! with trailing slashes, names over 100 bytes split across the ustar prefix
//! (or a `x` pax header when they cannot split), and two zero blocks last.
//!
//! Directory emission is lazy like the oracle's: a directory record is
//! written only when the first non-directory entry beneath it arrives, so a
//! childless (empty-tree) directory leaves no record at all. Gitlinks become
//! plain directory records and are never descended into. File bodies stream
//! in bounded slices via `Store::read_chunks` (the header carries the size
//! from `object_len` first, so the length is known before the body flows);
//! only trees, commits, tags, and symlink targets materialize in full.
//!
//! Deliberate deviations from the oracle, all client-compatible:
//!
//! - Request errors are refused with `NACK` before `ACK`. The oracle sends
//!   `ACK` unconditionally and reports bad arguments over band 3; both end
//!   the session, and `NACK` names the cause on the first line the way the
//!   spawn-failure path already does.
//! - Raw commit and tree OIDs are accepted as revisions. The oracle's remote
//!   entry point only resolves refs unless `uploadArchive.allowUnreachable`
//!   is set; accepting OIDs behaves exactly like that option enabled.
//! - Only `--format=tar` (the default when absent) is accepted; every other
//!   option (`--prefix`, `--mtime`, `--add-file`, ...) is refused as
//!   unsupported. There is no `.gitattributes` handling, so `export-ignore`
//!   and `export-subst` do not apply.
//! - A bare tree revision carries mtime 0 on every record. The oracle stamps
//!   `time(NULL)` there; a fixed zero keeps the stream deterministic.
//! - Records stream back-to-back with no 10 KiB block padding; readers only
//!   need the two zero blocks, which are always present.
//!
//! Oracle anchors: `git/builtin/upload-archive.c` (`cmd_upload_archive`
//! `ACK`/flush/sideband loop, `cmd_upload_archive_writer` `argument` loop),
//! `git/builtin/archive.c` (`run_remote_archiver` client grammar),
//! `git/archive.c` (`write_archive_entry` trailing slashes, the lazy
//! directory queue, `parse_treeish_arg` commit-date mtime),
//! `git/archive-tar.c` (`write_tar_entry` modes/names/pax policy,
//! `write_global_extended_header`), `git/tar.h` (header layout).
//!
//! Live-git evidence (git 2.53.0 `git-upload-archive`, framed `argument`
//! lines on stdin): the reply is `0008ACK\n` + `0000`, then band-1
//! sideband frames carrying the tar, then `0000`. The tar opens with a `g`
//! `pax_global_header` holding `comment=<commit hex>`, lists directories
//! with trailing slashes and type `5` (regular `0664`, exec `0775`,
//! symlink `0777`), splits a 135-byte path across prefix/name, and drops
//! a childless linked empty tree without a record.

use std::io::{Read, Write};

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::RefTarget;
use ruk_core::store::types::ObjectKind;
use ruk_core::store::{ChunkDecision, Store};
#[cfg(test)]
use ruk_core::store::{EventContext, EventSource};

use super::pack::object_links;
use super::pktline::{Packet, PktReader, encode_data, encode_flush, send};
use super::serve::HeadAdvertisement;
use super::{Interrupt, read_object};
use crate::{GitError, parse_oid, require_kind};

/// Largest client argument count, mirroring the oracle's `MAX_ARGS`.
const MAX_ARGS: usize = 64;
/// Verified-read bound for structural objects and archived blobs, matching
/// the walk bound the push and fetch halves use.
const WALK_OBJECT_BYTES: u64 = 512 << 20;
/// Tar payload bytes per band-1 sideband frame, far below the pkt-line cap.
const SIDEBAND_CHUNK: usize = 32 * 1024;
/// Largest size a ustar header carries inline; larger files (and mtimes)
/// move to a pax extended header, mirroring `USTAR_MAX_SIZE`.
const USTAR_MAX: u64 = 0o77777777777;

fn corrupt(detail: impl Into<String>) -> GitError {
    GitError::Corrupt {
        detail: detail.into(),
    }
}

fn unsupported(detail: impl Into<String>) -> GitError {
    GitError::Unsupported {
        command: detail.into(),
    }
}

fn malformed(tree: Oid, detail: &str) -> GitError {
    corrupt(format!("object {tree}: {detail}"))
}

/// Flattens a message onto one short line for `NACK` and band-3 reports,
/// mirroring the serve half's sanitizer.
fn sanitize(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(512)
        .collect()
}

/// Sends a `NACK` refusal for a request that fails before `ACK`, returning
/// the original error. Best-effort: when the peer is already gone the
/// refusal cannot land and the original failure is still the verdict.
fn refuse<W: Write>(writer: &mut W, err: GitError) -> GitError {
    let mut buf = Vec::new();
    if encode_data(
        &mut buf,
        format!("NACK {}\n", sanitize(&err.to_string())).as_bytes(),
    )
    .is_ok()
    {
        let _ = send(writer, &buf);
    }
    err
}

/// Serves one `upload-archive` session: reads `argument` lines up to the
/// flush, resolves the single revision, answers `ACK` plus a flush, and
/// streams the tar on sideband band 1 with a flush terminator.
///
/// Pre-`ACK` failures are refused with `NACK`; post-`ACK` failures go out on
/// band 3 without a terminator, so the client never mistakes a truncated
/// stream for a complete archive.
///
/// # Errors
/// [`GitError::Corrupt`] for grammar violations (including non-tar shapes
/// the walker rejects mid-stream), [`GitError::Unsupported`] for non-tar
/// formats and options, [`GitError::NotFound`] for an unknown revision,
/// [`GitError::ObjectFormat`] for store/kind mismatch, plus store,
/// transport and cancellation failures.
pub fn serve_upload_archive<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    store: &Store,
    kind: HashKind,
    head: &HeadAdvertisement,
    interrupt: &Interrupt,
) -> Result<(), GitError> {
    if store.hash_kind() != kind {
        return Err(refuse(
            &mut writer,
            GitError::ObjectFormat {
                detail: "serving store uses another object format".to_owned(),
            },
        ));
    }
    let args = match read_arguments(reader, interrupt) {
        Ok(args) => args,
        Err(err) => return Err(refuse(&mut writer, err)),
    };
    let request = match parse_arguments(&args) {
        Ok(request) => request,
        Err(err) => return Err(refuse(&mut writer, err)),
    };
    let resolved = match resolve_rev(store, kind, head, &request.rev) {
        Ok(resolved) => resolved,
        Err(err) => return Err(refuse(&mut writer, err)),
    };
    let mut ack = Vec::new();
    encode_data(&mut ack, b"ACK\n")?;
    encode_flush(&mut ack);
    send(&mut writer, &ack)?;
    let (root, mtime, commit) = match resolved {
        Resolved::Commit {
            tree,
            mtime,
            commit,
        } => (tree, mtime, Some(commit)),
        Resolved::Tree { tree } => (tree, 0, None),
    };
    let mut walk = TreeWalk {
        store,
        kind,
        tar: TarWriter {
            sink: BandWriter {
                writer,
                pending: Vec::new(),
            },
            mtime,
        },
        pending: Vec::new(),
        interrupt,
        measure: false,
        zip_bound: 0,
    };
    if let Some(commit) = commit
        && let Err(err) = walk.tar.emit_global(commit)
    {
        return Err(stream_failed(walk, err));
    }
    if let Err(err) = walk.walk_tree(root, b"") {
        return Err(stream_failed(walk, err));
    }
    // A still-pending directory had no file beneath it; like the oracle's
    // end-of-walk free loop, it leaves no record. `walk` drops it here.
    walk.finish()
}

/// Reports a mid-stream failure on band 3 and returns the original error.
fn stream_failed<S: TarSink>(mut walk: TreeWalk<'_, S>, err: GitError) -> GitError {
    let _ = walk.tar.sink.fail(&sanitize(&err.to_string()));
    err
}

/// The pinned inputs one archived commit streams from: the commit the
/// `Accepted` frame names, its tree, and its committer timestamp. The
/// count and the streaming walk share one plan, so the streamed body always
/// matches the announced metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchivePlan {
    /// The archived commit, named by the stream's global header.
    pub commit: Oid,
    /// The commit's tree, walked in stored order.
    pub tree: Oid,
    /// The commit's committer timestamp, stamped on every record.
    pub mtime: u64,
}

/// Plans the stream behind one commit: its tree plus its committer
/// timestamp, mirroring the oracle's commit-date archive time.
///
/// # Errors
/// [`GitError::NotFound`] for an unpublished object, [`GitError::Corrupt`]
/// for a commit without a tree or timestamp, or a non-commit behind the id.
pub fn plan_commit_archive(
    store: &Store,
    kind: HashKind,
    commit: Oid,
) -> Result<ArchivePlan, GitError> {
    let (obj_kind, bytes) = read_object(store, commit, WALK_OBJECT_BYTES)?;
    if obj_kind != ObjectKind::Commit {
        return Err(corrupt(format!("archive commit {commit} is not a commit")));
    }
    let links = object_links(obj_kind, &bytes, kind)?;
    let tree = links
        .tree
        .ok_or_else(|| corrupt(format!("archive commit {commit} has no tree")))?;
    Ok(ArchivePlan {
        commit,
        tree,
        mtime: commit_mtime(&bytes, commit)?,
    })
}

/// Writes `len` zero bytes to `sink` in fixed-size slices. A counting pass
/// charges a body's length this way without reading the body.
fn write_zeros<S: TarSink>(sink: &mut S, len: u64) -> Result<(), GitError> {
    static ZEROS: [u8; SIDEBAND_CHUNK] = [0; SIDEBAND_CHUNK];
    let chunk = u64::try_from(ZEROS.len()).expect("slice length fits in u64");
    let mut left = len;
    while left > 0 {
        let take = left.min(chunk);
        let width = usize::try_from(take).expect("take is at most the slice length");
        sink.write_tar(&ZEROS[..width])?;
        left -= take;
    }
    Ok(())
}

/// Zip bytes one entry adds beyond its payload: a 30-byte local header, a
/// 24-byte data descriptor, a 46-byte central-directory record, and up to 40
/// bytes of zip64 or extended-timestamp extra data in each record.
const ZIP_ENTRY_FIXED: u64 = 30 + 24 + 40 + 46 + 40;

/// Zip bytes the archive's end records add: the end of central directory
/// (22), a zip64 end record (56), and its locator (20).
const ZIP_END_FIXED: u64 = 22 + 56 + 20;

/// Smallest payload a non-final deflate block carries under the flate2
/// miniz backend the zip writer uses: miniz flushes a block once its input
/// passes 31 KiB (`total_bytes > 31 * 1024` in miniz_oxide's deflate core).
/// A stored block costs at most five bytes of framing, so the block count is
/// at most payload / this + 1.
const DEFLATE_MIN_BLOCK_PAYLOAD: u64 = 31 * 1024;

/// Slack for deflate block framing beyond the stored-block fallback.
const DEFLATE_SLACK: u64 = 16;

/// Upper bound on the zip bytes one entry adds: its fixed records, the name
/// (written in both the local and central records), and a payload bounded by
/// the deflate stored-block worst case. An empty payload is stored, so it
/// adds no payload bytes.
fn zip_entry_bound(name_len: u64, data_len: u64) -> u64 {
    let data = if data_len == 0 {
        0
    } else {
        data_len + DEFLATE_SLACK + 5 * (data_len / DEFLATE_MIN_BLOCK_PAYLOAD + 1)
    };
    ZIP_ENTRY_FIXED + 2 * name_len + data
}

/// What one archived commit weighs in each format, measured before the first
/// byte is emitted.
///
/// `tar` is the exact byte count the streaming walk emits.
///
/// `zip` is an upper bound on the zip the transcoder produces for the same
/// commit: the sum over entries of `ZIP_ENTRY_FIXED + 2·name + payload`, where
/// a non-empty payload adds `payload + 16 + 5·(payload/31744 + 1)` bytes, plus
/// `ZIP_END_FIXED`. Exact zip size is unknowable without a full deflate pass,
/// which per request would be a CPU amplifier under the byte cap. The bound
/// exceeds the true size by at most 180 bytes per entry, about five bytes per
/// 31 KiB of payload, and 98 bytes for the end records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveSize {
    /// Exact tar bytes the stream emits.
    pub tar: u64,
    /// Upper bound on the zip bytes the transcode emits.
    pub zip: u64,
}

/// Counts tar bytes without emitting them: every header, body, pax record,
/// and closing zero block is tallied, and no payload is read.
struct CountSink {
    count: u64,
}

impl TarSink for CountSink {
    fn write_tar(&mut self, bytes: &[u8]) -> Result<(), GitError> {
        let width = u64::try_from(bytes.len()).map_err(|_| GitError::Limit {
            detail: "archive chunk does not fit the byte count".to_owned(),
        })?;
        self.count = self.count.saturating_add(width);
        Ok(())
    }

    fn fail(&mut self, _message: &str) -> Result<(), GitError> {
        Ok(())
    }

    fn finish(&mut self) -> Result<(), GitError> {
        Ok(())
    }
}

/// Measures the stream one archived commit produces, without emitting any
/// byte. Blob bodies are charged by `object_len` and never read; the walk
/// reads only trees and symlink targets. The daemon compares the figure for
/// the requested format against `archive_max_bytes` before the first frame.
///
/// # Errors
/// The walk's own failures: unpublished objects, corrupt trees, interrupts.
pub fn count_commit_tar(
    store: &Store,
    kind: HashKind,
    plan: &ArchivePlan,
    interrupt: &Interrupt,
) -> Result<ArchiveSize, GitError> {
    let mut walk = TreeWalk {
        store,
        kind,
        tar: TarWriter {
            sink: CountSink { count: 0 },
            mtime: plan.mtime,
        },
        pending: Vec::new(),
        interrupt,
        measure: true,
        zip_bound: 0,
    };
    if let Err(err) = walk.tar.emit_global(plan.commit) {
        return Err(stream_failed(walk, err));
    }
    if let Err(err) = walk.walk_tree(plan.tree, b"") {
        return Err(stream_failed(walk, err));
    }
    walk.tar.sink.write_tar(&[0u8; 1024])?;
    let tar = walk.tar.sink.count;
    let zip = walk.zip_bound.saturating_add(ZIP_END_FIXED);
    walk.tar.sink.finish()?;
    Ok(ArchiveSize { tar, zip })
}

/// Streams the tar bytes of one archived commit through `sink`, chunked by
/// the sink: the git wire frames sideband bands while the daemon emits
/// bounded raw chunks.
///
/// Callers count first with [`count_commit_tar`] and refuse past their cap
/// before the first byte.
///
/// # Errors
/// The walk's own failures, reported through the sink before returning.
pub fn stream_commit_tar<S: TarSink>(
    store: &Store,
    kind: HashKind,
    plan: &ArchivePlan,
    interrupt: &Interrupt,
    sink: S,
) -> Result<(), GitError> {
    let mut walk = TreeWalk {
        store,
        kind,
        tar: TarWriter {
            sink,
            mtime: plan.mtime,
        },
        pending: Vec::new(),
        interrupt,
        measure: false,
        zip_bound: 0,
    };
    if let Err(err) = walk.tar.emit_global(plan.commit) {
        return Err(stream_failed(walk, err));
    }
    if let Err(err) = walk.walk_tree(plan.tree, b"") {
        return Err(stream_failed(walk, err));
    }
    walk.finish()
}

/// Reads `argument` lines up to the terminating flush.
fn read_arguments<R: Read>(reader: R, interrupt: &Interrupt) -> Result<Vec<Vec<u8>>, GitError> {
    let mut pkt = PktReader::new(reader, interrupt.clone());
    let mut args = Vec::new();
    loop {
        match pkt.read_packet()? {
            Packet::Flush => return Ok(args),
            Packet::Data(_) => args.push(pkt.last_line().unwrap_or_default().to_vec()),
            other => {
                return Err(corrupt(format!("expected argument lines, got {other:?}")));
            }
        }
    }
}

struct ArchiveRequest {
    rev: String,
}

/// Parses the `argument` bodies: at most one bare revision plus an optional
/// `--format=tar`. Every other option is refused; tar is also the default
/// when no format arrives, mirroring the oracle's archiver default.
fn parse_arguments(args: &[Vec<u8>]) -> Result<ArchiveRequest, GitError> {
    if args.len() > MAX_ARGS {
        return Err(corrupt(format!("too many arguments (>{MAX_ARGS})")));
    }
    let mut format: Option<Vec<u8>> = None;
    let mut rev: Option<String> = None;
    for arg in args {
        let body = arg.strip_prefix(b"argument ").ok_or_else(|| {
            corrupt(format!(
                "expected 'argument' line, got {}",
                arg.escape_ascii()
            ))
        })?;
        if let Some(value) = body.strip_prefix(b"--format=") {
            if format.replace(value.to_vec()).is_some() {
                return Err(corrupt("archive format given twice"));
            }
        } else if body.starts_with(b"--") {
            return Err(unsupported(format!(
                "archive option {}",
                body.escape_ascii()
            )));
        } else {
            if rev.is_some() {
                return Err(corrupt("more than one archive revision"));
            }
            let text = std::str::from_utf8(body)
                .map_err(|_| corrupt(format!("revision is not UTF-8: {}", body.escape_ascii())))?;
            rev = Some(text.to_owned());
        }
    }
    if let Some(name) = &format
        && name.as_slice() != &b"tar"[..]
    {
        return Err(unsupported(format!(
            "archive format {}",
            name.escape_ascii()
        )));
    }
    rev.map(|rev| ArchiveRequest { rev })
        .ok_or_else(|| corrupt("archive needs one revision"))
}

enum Resolved {
    Commit { commit: Oid, tree: Oid, mtime: u64 },
    Tree { tree: Oid },
}

/// Resolves the revision: `HEAD`, an exact ref, the `refs/heads/` and
/// `refs/tags/` shorthands, or a raw commit/tree OID (peeled through tags).
/// Abbreviations are not expanded: only full OIDs resolve.
fn resolve_rev(
    store: &Store,
    kind: HashKind,
    head: &HeadAdvertisement,
    rev: &str,
) -> Result<Resolved, GitError> {
    if rev == "HEAD" {
        return peel(store, kind, head.oid, rev);
    }
    if let Some(oid) = lookup_ref(store, rev)? {
        return peel(store, kind, oid, rev);
    }
    match parse_oid(rev) {
        Ok(oid) => peel(store, kind, require_kind(oid, kind)?, rev),
        Err(_) => Err(GitError::NotFound {
            detail: format!("unknown revision {rev:?}"),
        }),
    }
}

/// Looks up the exact ref name plus the branch and tag shorthands,
/// following symbolic hops. Unresolvable names are a miss, not an error.
fn lookup_ref(store: &Store, rev: &str) -> Result<Option<Oid>, GitError> {
    let refs = super::session::advertise(store)?;
    let mut candidates = Vec::with_capacity(3);
    candidates.push(rev.as_bytes().to_vec());
    candidates.push(format!("refs/heads/{rev}").into_bytes());
    candidates.push(format!("refs/tags/{rev}").into_bytes());
    for candidate in &candidates {
        let mut target = refs
            .iter()
            .find(|entry| entry.name == *candidate)
            .map(|entry| &entry.target);
        for _ in 0..4 {
            match target {
                None => break,
                Some(RefTarget::Direct(oid)) => return Ok(Some(*oid)),
                Some(RefTarget::Symbolic(name)) => {
                    target = refs
                        .iter()
                        .find(|entry| entry.name.as_slice() == name.as_bytes())
                        .map(|entry| &entry.target);
                }
            }
        }
    }
    Ok(None)
}

/// Peels tags to the commit or tree behind `oid`, recording the commit's
/// tree and committer timestamp. Anything else is not archivable.
fn peel(store: &Store, kind: HashKind, oid: Oid, rev: &str) -> Result<Resolved, GitError> {
    let mut current = oid;
    for _ in 0..32 {
        let (obj_kind, bytes) = match read_object(store, current, WALK_OBJECT_BYTES) {
            Ok(found) => found,
            Err(GitError::NotFound { .. }) => {
                return Err(GitError::NotFound {
                    detail: format!("unknown revision {rev:?}"),
                });
            }
            Err(err) => return Err(err),
        };
        match obj_kind {
            ObjectKind::Commit => {
                let links = object_links(obj_kind, &bytes, kind)?;
                let tree = links
                    .tree
                    .ok_or_else(|| malformed(current, "commit has no tree"))?;
                return Ok(Resolved::Commit {
                    commit: current,
                    tree,
                    mtime: commit_mtime(&bytes, current)?,
                });
            }
            ObjectKind::Tag => {
                let links = object_links(obj_kind, &bytes, kind)?;
                match links.tag_target {
                    Some((target, _)) => current = target,
                    None => return Err(corrupt(format!("tag {current} names no target"))),
                }
            }
            ObjectKind::Tree => return Ok(Resolved::Tree { tree: current }),
            ObjectKind::Blob | ObjectKind::Conflict => {
                return Err(corrupt(format!("not a tree object: {current}")));
            }
        }
    }
    Err(corrupt(format!("tag chain behind {rev:?} does not end")))
}

/// Reads the committer timestamp out of a commit payload for record mtimes,
/// mirroring the oracle's commit-date archive time.
fn commit_mtime(bytes: &[u8], oid: Oid) -> Result<u64, GitError> {
    let mut mtime = None;
    for line in bytes.split(|b| *b == b'\n') {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix(b"committer ") {
            let fields: Vec<&[u8]> = rest.split(|b| *b == b' ').collect();
            if fields.len() >= 2 {
                let stamp = fields[fields.len() - 2];
                if let Ok(text) = std::str::from_utf8(stamp)
                    && let Ok(value) = text.parse::<u64>()
                {
                    mtime = Some(value);
                }
            }
        }
    }
    mtime.ok_or_else(|| malformed(oid, "commit has no committer timestamp"))
}

/// One parsed tree entry, keeping the raw mode: the archive maps modes to
/// tar types instead of dropping them like the closure walkers do.
struct TreeEntry {
    name: Vec<u8>,
    mode: u32,
    oid: Oid,
}

/// Parses raw tree bytes with the same framing validation the link parsers
/// use, plus archive-specific name rules: names are plain single-path
/// components, never empty, `.`/`..`, or slash-bearing.
fn parse_tree_entries(tree: Oid, bytes: &[u8], kind: HashKind) -> Result<Vec<TreeEntry>, GitError> {
    let width = kind.oid_len();
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|b| *b == b' ')
            .ok_or_else(|| malformed(tree, "tree entry has no mode"))?;
        let digits = &rest[..space];
        if digits.is_empty() || digits.len() > 6 || !digits.iter().all(|b| b'0' <= *b && *b <= b'7')
        {
            return Err(malformed(tree, "tree entry mode is not octal"));
        }
        let mode = digits
            .iter()
            .fold(0u32, |acc, b| acc * 8 + u32::from(b - b'0'));
        let after_mode = &rest[space + 1..];
        let nul = after_mode
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| malformed(tree, "tree entry name is not terminated"))?;
        let name = &after_mode[..nul];
        if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
            return Err(malformed(tree, "tree entry name is not a plain file name"));
        }
        let after_name = &after_mode[nul + 1..];
        if after_name.len() < width {
            return Err(malformed(tree, "tree entry id is truncated"));
        }
        let oid = Oid::from_bytes(&after_name[..width])
            .map_err(|err| malformed(tree, &err.to_string()))?;
        rest = &after_name[width..];
        out.push(TreeEntry {
            name: name.to_vec(),
            mode,
            oid,
        });
    }
    Ok(out)
}

/// A directory seen but not yet written: the record goes out only when the
/// first non-directory entry beneath it arrives, mirroring the oracle's
/// pending-directory queue.
struct PendingDir {
    oid: Oid,
    /// Full path with trailing slash, exactly as the tar record wants it.
    path: Vec<u8>,
    mode: u32,
}

struct TreeWalk<'s, S: TarSink> {
    store: &'s Store,
    kind: HashKind,
    tar: TarWriter<S>,
    pending: Vec<PendingDir>,
    interrupt: &'s Interrupt,
    /// Counting pass: blob bodies are charged by their `object_len` instead
    /// of being read, so sizing an archive costs no payload I/O.
    measure: bool,
    /// Counting pass: the running zip upper bound over entries seen so far.
    zip_bound: u64,
}

impl<S: TarSink> TreeWalk<'_, S> {
    /// Walks one tree depth-first in stored order. Directories queue their
    /// record and recurse; ascending past a still-queued directory drops it,
    /// which is how childless directories leave no record.
    fn walk_tree(&mut self, tree: Oid, base: &[u8]) -> Result<(), GitError> {
        let (obj_kind, bytes) = read_object(self.store, tree, WALK_OBJECT_BYTES)?;
        if obj_kind != ObjectKind::Tree {
            return Err(corrupt(format!("object {tree} is not a tree")));
        }
        for entry in parse_tree_entries(tree, &bytes, self.kind)? {
            self.interrupt.check("archiving the tree")?;
            if entry.mode & 0o170000 == 0o040000 {
                let mut path = base.to_vec();
                path.extend_from_slice(&entry.name);
                path.push(b'/');
                let depth = self.pending.len();
                self.pending.push(PendingDir {
                    oid: entry.oid,
                    path: path.clone(),
                    mode: entry.mode,
                });
                self.walk_tree(entry.oid, &path)?;
                self.pending.truncate(depth);
            } else {
                self.flush_pending()?;
                self.emit_entry(&entry, base)?;
            }
        }
        Ok(())
    }

    /// Charges one entry to the zip bound. Only the counting pass measures;
    /// the streaming walk pays nothing.
    fn charge_zip(&mut self, name_len: usize, data_len: u64) {
        if self.measure {
            let name = u64::try_from(name_len).expect("usize fits in u64");
            self.zip_bound = self
                .zip_bound
                .saturating_add(zip_entry_bound(name, data_len));
        }
    }

    /// Writes every queued directory record, outermost first.
    fn flush_pending(&mut self) -> Result<(), GitError> {
        for dir in std::mem::take(&mut self.pending) {
            self.charge_zip(dir.path.len(), 0);
            self.tar.emit_dir(dir.oid, &dir.path, dir.mode)?;
        }
        Ok(())
    }

    fn emit_entry(&mut self, entry: &TreeEntry, base: &[u8]) -> Result<(), GitError> {
        let mut path = base.to_vec();
        path.extend_from_slice(&entry.name);
        match entry.mode & 0o170000 {
            0o160000 => {
                // Gitlinks become plain directory records and are never
                // descended into, exactly like the oracle.
                path.push(b'/');
                self.charge_zip(path.len(), 0);
                self.tar.emit_dir(entry.oid, &path, entry.mode)?;
            }
            0o120000 => {
                let (obj_kind, target) = read_object(self.store, entry.oid, WALK_OBJECT_BYTES)?;
                if obj_kind != ObjectKind::Blob {
                    return Err(corrupt(format!("symlink {} is not a blob", entry.oid)));
                }
                self.tar
                    .emit_symlink(entry.oid, &path, entry.mode, &target)?;
                self.charge_zip(
                    path.len(),
                    u64::try_from(target.len()).expect("usize fits in u64"),
                );
            }
            0o100000 => {
                let len = self.blob_len(entry.oid)?;
                self.charge_zip(path.len(), len);
                self.tar.begin_file(entry.oid, &path, entry.mode, len)?;
                self.stream_blob(entry.oid, len)?;
                self.tar.end_body(len)?;
            }
            _ => {
                return Err(corrupt(format!(
                    "object {}: unsupported file mode {:o}",
                    entry.oid, entry.mode
                )));
            }
        }
        Ok(())
    }

    /// Committed decoded length of a file blob, without payload I/O, so
    /// the header can go out before the body streams.
    fn blob_len(&self, oid: Oid) -> Result<u64, GitError> {
        match self.store.object_len(oid)? {
            Some(len) => Ok(len),
            None => Err(GitError::NotFound {
                detail: format!("blob {oid} is not in the store"),
            }),
        }
    }

    /// Streams one blob body in bounded slices straight into sideband
    /// frames: the body is never materialized, mirroring the oracle's
    /// big-file path at every size. The header already carries the length
    /// from [`Self::blob_len`], and the closed stream proves the same
    /// byte count arrived verified.
    fn stream_blob(&mut self, oid: Oid, len: u64) -> Result<(), GitError> {
        if self.measure {
            return write_zeros(&mut self.tar.sink, len);
        }
        let store = self.store;
        let tar = &mut self.tar;
        let interrupt = self.interrupt;
        let mut failure: Option<GitError> = None;
        let meta = store.read_chunks(oid, &mut |chunk| {
            if let Err(err) = interrupt.check("archiving the tree") {
                failure = Some(err);
                return Ok(ChunkDecision::Stop);
            }
            match tar.sink.write_tar(chunk) {
                Ok(()) => Ok(ChunkDecision::Continue),
                Err(err) => {
                    failure = Some(err);
                    Ok(ChunkDecision::Stop)
                }
            }
        })?;
        if let Some(err) = failure {
            return Err(err);
        }
        if !meta.complete {
            return Err(corrupt(format!("blob {oid} stopped before its end")));
        }
        if meta.kind != ObjectKind::Blob {
            return Err(corrupt(format!("file {oid} is not a blob")));
        }
        if meta.decoded_len != len || meta.streamed_bytes != len {
            return Err(corrupt(format!("blob {oid} changed length mid-archive")));
        }
        Ok(())
    }

    /// Ends the stream with the two zero blocks and the flush terminator.
    fn finish(mut self) -> Result<(), GitError> {
        self.tar.sink.write_tar(&[0u8; 1024])?;
        self.tar.sink.finish()
    }
}

/// Builds one pax extended-header record: `%u %s=%s\n` where `%u` counts
/// itself, mirroring `strbuf_append_ext_header`.
fn ext_record(keyword: &str, value: &[u8]) -> Vec<u8> {
    let mut len = 1 + 1 + keyword.len() + 1 + value.len() + 1;
    loop {
        let grown = len.to_string().len() + 1 + keyword.len() + 1 + value.len() + 1;
        if grown == len {
            break;
        }
        len = grown;
    }
    let mut out = format!("{len} {keyword}=").into_bytes();
    out.extend_from_slice(value);
    out.push(b'\n');
    debug_assert_eq!(out.len(), len);
    out
}

fn ext_record_uint(keyword: &str, value: u64) -> Vec<u8> {
    ext_record(keyword, value.to_string().as_bytes())
}

/// Splits a long path across the ustar prefix and name fields at the last
/// slash within the first 155 bytes, mirroring `get_path_prefix`. Returns
/// `None` when no split fits and the caller must use a pax header instead.
fn split_name(path: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut i = path.len();
    if i > 1 && path[i - 1] == b'/' {
        i -= 1;
    }
    if i > 155 {
        i = 155;
    }
    loop {
        if i == 0 {
            break;
        }
        i -= 1;
        if path[i] == b'/' {
            break;
        }
    }
    if i == 0 {
        return None;
    }
    let (prefix, rest) = (&path[..i], &path[i + 1..]);
    if rest.len() <= 100 {
        Some((prefix, rest))
    } else {
        None
    }
}

/// Writes an octal field `snprintf`-style: zero-padded digits plus the
/// NUL terminator the 512-byte header is pre-filled with.
fn octal_field(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    let bytes = text.as_bytes();
    let n = bytes.len().min(digits);
    field[..n].copy_from_slice(&bytes[..n]);
}

/// Builds one 512-byte ustar header with git's exact field shapes: `%07o`
/// modes/ids, `%011o` size/mtime, `ustar\0` + `00`, `root` ownership, and
/// the `%07o` checksum over spaces.
fn ustar_header(
    name: &[u8],
    prefix: &[u8],
    mode: u32,
    size: u64,
    mtime: u64,
    typeflag: u8,
    linkname: &[u8],
) -> [u8; 512] {
    debug_assert!(name.len() <= 100 && prefix.len() <= 155 && linkname.len() <= 100);
    let mut header = [0u8; 512];
    let n = name.len().min(100);
    header[..n].copy_from_slice(&name[..n]);
    octal_field(&mut header[100..108], u64::from(mode & 0o7777));
    octal_field(&mut header[108..116], 0);
    octal_field(&mut header[116..124], 0);
    octal_field(&mut header[124..136], size);
    octal_field(&mut header[136..148], mtime);
    header[156] = typeflag;
    let l = linkname.len().min(100);
    header[157..157 + l].copy_from_slice(&linkname[..l]);
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[265..269].copy_from_slice(b"root");
    header[297..301].copy_from_slice(b"root");
    let p = prefix.len().min(155);
    header[345..345 + p].copy_from_slice(&prefix[..p]);
    let mut sum: u32 = 0;
    for (index, byte) in header.iter().enumerate() {
        sum += if (148..156).contains(&index) {
            u32::from(b' ')
        } else {
            u32::from(*byte)
        };
    }
    octal_field(&mut header[148..156], u64::from(sum));
    header
}

/// The sink a tar walk writes through: sideband frames on the git wire,
/// raw chunks for the daemon's streamed reads. The daemon's sink emits
/// one bounded chunk per call and never buffers the archive.
pub trait TarSink {
    /// Appends tar bytes to the sink.
    ///
    /// # Errors
    /// [`GitError::Limit`] when the sink's cap rejects the bytes, plus the
    /// sink's own transport failures.
    fn write_tar(&mut self, bytes: &[u8]) -> Result<(), GitError>;

    /// Reports a mid-stream failure the way the sink's framing demands.
    /// Sinks without an error channel report success and let the caller
    /// return the original error instead.
    fn fail(&mut self, message: &str) -> Result<(), GitError>;

    /// Closes the stream after the two zero blocks are written.
    ///
    /// # Errors
    /// The sink's own transport failures.
    fn finish(&mut self) -> Result<(), GitError>;
}

struct TarWriter<S: TarSink> {
    sink: S,
    mtime: u64,
}

impl<S: TarSink> TarWriter<S> {
    fn write_raw(&mut self, bytes: &[u8]) -> Result<(), GitError> {
        self.sink.write_tar(bytes)
    }

    fn write_padded(&mut self, bytes: &[u8]) -> Result<(), GitError> {
        self.write_raw(bytes)?;
        let pad = (512 - bytes.len() % 512) % 512;
        if pad > 0 {
            self.write_raw(&vec![0u8; pad])?;
        }
        Ok(())
    }

    /// Zero padding closing a streamed body of declared length `len`.
    fn end_body(&mut self, len: u64) -> Result<(), GitError> {
        let pad = usize::try_from((512 - len % 512) % 512).map_err(|_| GitError::Limit {
            detail: format!("archive padding for {len} bytes does not fit"),
        })?;
        if pad > 0 {
            self.write_raw(&vec![0u8; pad])?;
        }
        Ok(())
    }

    /// The `g` global header naming the archived commit, exactly like the
    /// oracle; absent for bare tree revisions, where there is no commit.
    fn emit_global(&mut self, commit: Oid) -> Result<(), GitError> {
        let record = ext_record("comment", commit.to_hex().as_bytes());
        let header = ustar_header(
            b"pax_global_header",
            b"",
            0o100666,
            record.len() as u64,
            self.mtime,
            b'g',
            b"",
        );
        self.write_raw(&header)?;
        self.write_padded(&record)
    }

    /// The shared header writer behind dirs, files and symlinks: ustar
    /// prefix split with a `x` pax fallback for unsplittable paths,
    /// `linkpath` fallback for long targets, and a `size` fallback past
    /// the inline octal range. File bodies stream after the header through
    /// [`TreeWalk::stream_blob`]; every other entry has no body.
    fn emit_head(
        &mut self,
        oid: Oid,
        path: &[u8],
        stored_mode: u32,
        typeflag: u8,
        size: u64,
        link_target: Option<&[u8]>,
    ) -> Result<(), GitError> {
        let mut ext = Vec::new();
        let (header_name, header_prefix) = if path.len() > 100 {
            match split_name(path) {
                Some((prefix, name)) => (name.to_vec(), prefix.to_vec()),
                None => {
                    ext.extend_from_slice(&ext_record("path", path));
                    (format!("{}.data", oid.to_hex()).into_bytes(), Vec::new())
                }
            }
        } else {
            (path.to_vec(), Vec::new())
        };
        let linkname = match link_target {
            None => Vec::new(),
            Some(target) if target.len() > 100 => {
                ext.extend_from_slice(&ext_record("linkpath", target));
                format!("see {}.paxheader", oid.to_hex()).into_bytes()
            }
            Some(target) => target.to_vec(),
        };
        let mut size_in_header = size;
        if typeflag == b'0' && size > USTAR_MAX {
            size_in_header = 0;
            ext.extend_from_slice(&ext_record_uint("size", size));
        }
        let mut mtime = self.mtime;
        if mtime > USTAR_MAX {
            ext.extend_from_slice(&ext_record_uint("mtime", mtime));
            mtime = USTAR_MAX;
        }
        if !ext.is_empty() {
            let xname = format!("{}.paxheader", oid.to_hex()).into_bytes();
            let xheader = ustar_header(&xname, b"", 0o100666, ext.len() as u64, mtime, b'x', b"");
            self.write_raw(&xheader)?;
            self.write_padded(&ext)?;
        }
        let header = ustar_header(
            &header_name,
            &header_prefix,
            stored_mode,
            size_in_header,
            mtime,
            typeflag,
            &linkname,
        );
        self.write_raw(&header)
    }

    fn emit_dir(&mut self, oid: Oid, path: &[u8], mode: u32) -> Result<(), GitError> {
        self.emit_head(oid, path, (mode | 0o777) & !0o002, b'5', 0, None)
    }

    /// Writes a file header for a body of `len` bytes; the caller streams
    /// the body next and closes it with [`Self::end_body`].
    fn begin_file(&mut self, oid: Oid, path: &[u8], mode: u32, len: u64) -> Result<(), GitError> {
        let adjust = if mode & 0o100 != 0 { 0o777 } else { 0o666 };
        self.emit_head(oid, path, (mode | adjust) & !0o002, b'0', len, None)
    }

    fn emit_symlink(
        &mut self,
        oid: Oid,
        path: &[u8],
        mode: u32,
        target: &[u8],
    ) -> Result<(), GitError> {
        self.emit_head(oid, path, mode | 0o777, b'2', 0, Some(target))
    }
}

/// Chunks tar bytes into band-1 sideband frames; band 3 carries one fatal
/// message and never a terminator.
struct BandWriter<W: Write> {
    writer: W,
    pending: Vec<u8>,
}

impl<W: Write> TarSink for BandWriter<W> {
    fn write_tar(&mut self, bytes: &[u8]) -> Result<(), GitError> {
        self.pending.extend_from_slice(bytes);
        while self.pending.len() >= SIDEBAND_CHUNK {
            self.emit_frame(SIDEBAND_CHUNK)?;
        }
        Ok(())
    }

    fn fail(&mut self, message: &str) -> Result<(), GitError> {
        let mut frame = Vec::with_capacity(message.len() + 1);
        frame.push(3u8);
        frame.extend_from_slice(message.as_bytes());
        let mut out = Vec::with_capacity(frame.len() + 4);
        encode_data(&mut out, &frame)?;
        send(&mut self.writer, &out)
    }

    fn finish(&mut self) -> Result<(), GitError> {
        if !self.pending.is_empty() {
            let len = self.pending.len();
            self.emit_frame(len)?;
        }
        let mut out = Vec::new();
        encode_flush(&mut out);
        send(&mut self.writer, &out)
    }
}

impl<W: Write> BandWriter<W> {
    fn emit_frame(&mut self, len: usize) -> Result<(), GitError> {
        let mut frame = Vec::with_capacity(len + 1);
        frame.push(1u8);
        frame.extend_from_slice(&self.pending[..len]);
        self.pending.drain(..len);
        let mut out = Vec::with_capacity(len + 5);
        encode_data(&mut out, &frame)?;
        send(&mut self.writer, &out)
    }
}

#[cfg(test)]
mod tests {
    use super::super::pktline::encode_data;
    use super::super::session::test_support::test_store;
    use super::*;
    use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefTransaction, RefUpdate};
    use ruk_core::refs::prepare_checked_transaction;

    const MTIME: u64 = 1_700_000_000;

    fn put(store: &Store, kind: ObjectKind, bytes: &[u8]) -> Oid {
        let len = u64::try_from(bytes.len()).expect("fixture fits");
        let prepared = store.prepare(kind, len, bytes, None).expect("prepare");
        let oid = prepared.oid();
        store
            .publish(
                vec![prepared],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish");
        oid
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
            .publish(
                Vec::new(),
                &prepared.into_mutations(),
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish ref");
    }

    /// Git tree sort: directory names compare with a trailing slash.
    fn tree_bytes(entries: &[(&[u8], u32, Oid)]) -> Vec<u8> {
        let mut sorted = entries.to_vec();
        sorted.sort_by(|a, b| {
            let mut ka = a.0.to_vec();
            let mut kb = b.0.to_vec();
            if a.1 & 0o170000 == 0o040000 {
                ka.push(b'/');
            }
            if b.1 & 0o170000 == 0o040000 {
                kb.push(b'/');
            }
            ka.cmp(&kb)
        });
        let mut out = Vec::new();
        for (name, mode, oid) in sorted {
            out.extend_from_slice(format!("{mode:o} ").as_bytes());
            out.extend_from_slice(name);
            out.push(0);
            out.extend_from_slice(oid.as_bytes());
        }
        out
    }

    fn commit_bytes(tree: Oid, parents: &[Oid], timestamp: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"tree ");
        out.extend_from_slice(tree.to_hex().as_bytes());
        out.push(b'\n');
        for parent in parents {
            out.extend_from_slice(b"parent ");
            out.extend_from_slice(parent.to_hex().as_bytes());
            out.push(b'\n');
        }
        out.extend_from_slice(format!("author a <a@example.com> {timestamp} +0000\n").as_bytes());
        out.extend_from_slice(
            format!("committer a <a@example.com> {timestamp} +0000\n").as_bytes(),
        );
        out.extend_from_slice(b"\nsubject\n");
        out
    }

    /// Fixture tree: plain and exec files, a symlink, a long-target
    /// symlink, an unsplittable long name (pax), a nested dir chain, and a
    /// gitlink at a real commit.
    struct Fixture {
        store: Store,
        kind: HashKind,
        head: HeadAdvertisement,
        commit: Oid,
        tree: Oid,
        tag: Oid,
        /// `deep/` + 60 `d`s: the ustar prefix of the doubly-nested dir.
        deep_dir1: Vec<u8>,
        /// `deep/` + 60 `d`s + `/` + 60 `e`s: the ustar prefix of the file.
        deep_prefix: Vec<u8>,
        /// 60 `e`s + `/`: the split name of the doubly-nested dir.
        deep_dir2_name: Vec<u8>,
        /// `<blob hex>.data`: the pax placeholder of the unsplittable name.
        pax_name: Vec<u8>,
    }

    fn fixture() -> Fixture {
        let kind = HashKind::Sha1;
        let store = test_store(kind);
        let blob_a = put(&store, ObjectKind::Blob, b"hello\n");
        let blob_exec = put(&store, ObjectKind::Blob, b"#!/bin/sh\necho hi\n");
        let blob_deep = put(&store, ObjectKind::Blob, b"deep contents\n");
        let blob_pax = put(&store, ObjectKind::Blob, b"pax file\n");
        let blob_link = put(&store, ObjectKind::Blob, b"a.txt");
        let long_target = vec![b't'; 120];
        let blob_long_link = put(&store, ObjectKind::Blob, &long_target);
        let long_name = vec![b'p'; 120];

        let tree_deep3 = put(
            &store,
            ObjectKind::Tree,
            &tree_bytes(&[(b"deep.txt", 0o100644, blob_deep)]),
        );
        let dir2 = vec![b'e'; 60];
        let tree_deep2 = put(
            &store,
            ObjectKind::Tree,
            &tree_bytes(&[(dir2.as_slice(), 0o040000, tree_deep3)]),
        );
        let dir1 = vec![b'd'; 60];
        let tree_deep1 = put(
            &store,
            ObjectKind::Tree,
            &tree_bytes(&[(dir1.as_slice(), 0o040000, tree_deep2)]),
        );
        let tree1 = put(
            &store,
            ObjectKind::Tree,
            &tree_bytes(&[
                (b"a.txt".as_slice(), 0o100644, blob_a),
                (b"deep".as_slice(), 0o040000, tree_deep1),
                (b"exec.sh".as_slice(), 0o100755, blob_exec),
                (b"link.txt".as_slice(), 0o120000, blob_link),
                (b"llink".as_slice(), 0o120000, blob_long_link),
                (long_name.as_slice(), 0o100644, blob_pax),
            ]),
        );
        let commit1 = put(&store, ObjectKind::Commit, &commit_bytes(tree1, &[], MTIME));
        let tree = put(
            &store,
            ObjectKind::Tree,
            &tree_bytes(&[
                (b"a.txt".as_slice(), 0o100644, blob_a),
                (b"deep".as_slice(), 0o040000, tree_deep1),
                (b"exec.sh".as_slice(), 0o100755, blob_exec),
                (b"link.txt".as_slice(), 0o120000, blob_link),
                (b"llink".as_slice(), 0o120000, blob_long_link),
                (long_name.as_slice(), 0o100644, blob_pax),
                (b"submod".as_slice(), 0o160000, commit1),
            ]),
        );
        let commit = put(
            &store,
            ObjectKind::Commit,
            &commit_bytes(tree, &[commit1], MTIME),
        );
        let mut tag_bytes = Vec::new();
        tag_bytes.extend_from_slice(b"object ");
        tag_bytes.extend_from_slice(commit.to_hex().as_bytes());
        tag_bytes.extend_from_slice(
            b"\ntype commit\ntag v1\ntagger a <a@example.com> 1700000000 +0000\n\nrelease\n",
        );
        let tag = put(&store, ObjectKind::Tag, &tag_bytes);
        set_ref(&store, kind, b"refs/heads/main", commit);
        let mut deep_dir1 = b"deep/".to_vec();
        deep_dir1.extend_from_slice(&dir1);
        let mut deep_prefix = deep_dir1.clone();
        deep_prefix.push(b'/');
        deep_prefix.extend_from_slice(&dir2);
        let mut deep_dir2_name = dir2.clone();
        deep_dir2_name.push(b'/');
        let pax_name = format!("{}.data", blob_pax.to_hex()).into_bytes();
        Fixture {
            store,
            kind,
            head: HeadAdvertisement {
                oid: commit,
                symref: Some(b"refs/heads/main".to_vec()),
            },
            commit,
            tree,
            tag,
            deep_dir1,
            deep_prefix,
            deep_dir2_name,
            pax_name,
        }
    }

    fn framed(line: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_data(&mut out, line).expect("frame");
        out
    }

    fn request(args: &[&str]) -> Vec<u8> {
        let mut input = Vec::new();
        for arg in args {
            input.extend_from_slice(&framed(format!("argument {arg}\n").as_bytes()));
        }
        input.extend_from_slice(b"0000");
        input
    }

    fn serve(input: &[u8], fx: &Fixture) -> Vec<u8> {
        let mut out = Vec::new();
        serve_upload_archive(
            input,
            &mut out,
            &fx.store,
            fx.kind,
            &fx.head,
            &Interrupt::none(),
        )
        .expect("serve");
        out
    }

    /// Splits the reply into `ACK`, the demuxed band-1 tar, and asserts the
    /// exact `ACK` + flush + sideband-frames + flush framing.
    fn demux(out: &[u8]) -> Vec<u8> {
        assert!(out.starts_with(b"0008ACK\n0000"), "framing: {out:?}");
        let mut pos = 12;
        let mut tar = Vec::new();
        loop {
            let len =
                usize::from_str_radix(std::str::from_utf8(&out[pos..pos + 4]).expect("hex"), 16)
                    .expect("length");
            if len == 0 {
                pos += 4;
                break;
            }
            assert_eq!(out[pos + 4], 1, "band 1 only");
            tar.extend_from_slice(&out[pos + 5..pos + len]);
            pos += len;
        }
        assert_eq!(pos, out.len(), "nothing follows the terminator");
        tar
    }

    struct TarEntry {
        name: Vec<u8>,
        prefix: Vec<u8>,
        mode: u32,
        size: u64,
        mtime: u64,
        typeflag: u8,
        linkname: Vec<u8>,
        data: Vec<u8>,
    }

    fn octal(bytes: &[u8]) -> u64 {
        let text = std::str::from_utf8(bytes.split(|b| *b == 0).next().unwrap_or_default())
            .expect("octal");
        u64::from_str_radix(text.trim_start_matches('0'), 8).unwrap_or(0)
    }

    fn checksum_ok(header: &[u8]) -> bool {
        let mut sum: u32 = 0;
        for (index, byte) in header.iter().enumerate() {
            sum += if (148..156).contains(&index) {
                u32::from(b' ')
            } else {
                u32::from(*byte)
            };
        }
        octal(&header[148..156]) == u64::from(sum)
    }

    /// Walks 512-byte records, skipping `x` pax headers (their effect is
    /// asserted separately) and returning `(globals, entries, trailer_len)`.
    fn walk_tar(tar: &[u8]) -> (Vec<TarEntry>, Vec<TarEntry>, usize) {
        let mut pos = 0;
        let mut globals = Vec::new();
        let mut entries = Vec::new();
        while pos + 512 <= tar.len() {
            let header = &tar[pos..pos + 512];
            pos += 512;
            if header.iter().all(|b| *b == 0) {
                assert!(
                    tar[pos - 512..].iter().all(|b| *b == 0),
                    "zero block must end a zero trailer"
                );
                return (globals, entries, tar.len() - (pos - 512));
            }
            assert!(checksum_ok(header), "header checksum");
            let typeflag = header[156];
            let size = octal(&header[124..136]);
            let body_len = usize::try_from(size).expect("tar size fits");
            let data = tar[pos..pos + body_len].to_vec();
            let pad = (512 - body_len % 512) % 512;
            assert!(
                tar[pos + body_len..pos + body_len + pad]
                    .iter()
                    .all(|b| *b == 0),
                "payload padding is zero"
            );
            pos += body_len + pad;
            let entry = TarEntry {
                name: header[..100]
                    .split(|b| *b == 0)
                    .next()
                    .unwrap_or_default()
                    .to_vec(),
                prefix: header[345..500]
                    .split(|b| *b == 0)
                    .next()
                    .unwrap_or_default()
                    .to_vec(),
                mode: u32::try_from(octal(&header[100..108])).expect("mode fits"),
                size,
                mtime: octal(&header[136..148]),
                typeflag,
                linkname: header[157..257]
                    .split(|b| *b == 0)
                    .next()
                    .unwrap_or_default()
                    .to_vec(),
                data,
            };
            assert_eq!(&header[257..263], b"ustar\0", "magic");
            assert_eq!(&header[263..265], b"00", "version");
            if typeflag == b'g' {
                globals.push(entry);
            } else if typeflag != b'x' {
                entries.push(entry);
            }
        }
        panic!("tar ends without a zero trailer");
    }

    #[test]
    fn archive_streams_git_exact_tar() {
        let fx = fixture();
        let tar = demux(&serve(&request(&["HEAD"]), &fx));
        let (globals, entries, trailer) = walk_tar(&tar);
        assert_eq!(trailer, 1024, "two zero blocks close the stream");
        assert_eq!(globals.len(), 1, "one global header for a commit rev");
        assert_eq!(globals[0].name, b"pax_global_header");
        assert_eq!(globals[0].typeflag, b'g');
        assert!(
            globals[0]
                .data
                .windows(fx.commit.to_hex().len())
                .any(|w| w == fx.commit.to_hex().as_bytes()),
            "global header names the commit"
        );
        let kinds: Vec<(&[u8], &[u8], u8, u32)> = entries
            .iter()
            .map(|e| (e.prefix.as_slice(), e.name.as_slice(), e.typeflag, e.mode))
            .collect();
        let mut deep_dir1_slash = fx.deep_dir1.clone();
        deep_dir1_slash.push(b'/');
        let expected: Vec<(&[u8], &[u8], u8, u32)> = vec![
            (&b""[..], &b"a.txt"[..], b'0', 0o664),
            (&b""[..], &b"deep/"[..], b'5', 0o775),
            (&b""[..], &deep_dir1_slash[..], b'5', 0o775),
            (&fx.deep_dir1[..], &fx.deep_dir2_name[..], b'5', 0o775),
            (&fx.deep_prefix[..], &b"deep.txt"[..], b'0', 0o664),
            (&b""[..], &b"exec.sh"[..], b'0', 0o775),
            (&b""[..], &b"link.txt"[..], b'2', 0o777),
            (&b""[..], &b"llink"[..], b'2', 0o777),
            (&b""[..], &fx.pax_name[..], b'0', 0o664),
            (&b""[..], &b"submod/"[..], b'5', 0o775),
        ];
        assert_eq!(kinds, expected, "entry order, names, types and modes");
        for entry in &entries {
            assert_eq!(entry.mtime, MTIME, "commit-date mtime everywhere");
        }
        let by_name = |name: &[u8]| {
            entries
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("missing {}", String::from_utf8_lossy(name)))
        };
        assert_eq!(by_name(b"a.txt").data, b"hello\n");
        assert_eq!(by_name(b"a.txt").size, 6);
        assert_eq!(by_name(b"exec.sh").data, b"#!/bin/sh\necho hi\n");
        assert_eq!(by_name(b"link.txt").linkname, b"a.txt");
        assert_eq!(by_name(b"link.txt").size, 0);
        assert_eq!(by_name(b"submod/").size, 0);
        let deep = entries
            .iter()
            .find(|e| e.name == b"deep.txt")
            .expect("deep file");
        assert_eq!(deep.prefix, fx.deep_prefix);
        assert_eq!(deep.data, b"deep contents\n");
    }

    #[test]
    fn archive_pax_fallbacks_carry_real_paths() {
        let fx = fixture();
        let tar = demux(&serve(&request(&["HEAD"]), &fx));
        // Raw scan for the pax extended headers: one `path` (long file
        // name) and one `linkpath` (long symlink target).
        let long_name = vec![b'p'; 120];
        let long_target = vec![b't'; 120];
        let text = String::from_utf8_lossy(&tar);
        assert!(
            text.contains(&format!(" path={}\n", String::from_utf8_lossy(&long_name))),
            "pax path record holds the 120-byte name"
        );
        assert!(
            text.contains(&format!(
                " linkpath={}\n",
                String::from_utf8_lossy(&long_target)
            )),
            "pax linkpath record holds the 120-byte target"
        );
        // Both placeholders name their object: `<hex>.data` for the file,
        // `see <hex>.paxheader` for the link.
        let (_, entries, _) = walk_tar(&tar);
        let pax_file = entries
            .iter()
            .find(|e| e.data == b"pax file\n")
            .expect("pax file payload");
        assert!(
            pax_file.name.ends_with(b".data"),
            "placeholder name: {:?}",
            pax_file.name
        );
        let long_link = entries.iter().find(|e| e.name == b"llink").expect("llink");
        assert!(
            long_link.linkname.starts_with(b"see ") && long_link.linkname.ends_with(b".paxheader"),
            "link placeholder: {:?}",
            long_link.linkname
        );
    }

    #[test]
    fn archive_resolves_every_rev_form() {
        let fx = fixture();
        let via_head = demux(&serve(&request(&["HEAD"]), &fx));
        let commit_hex = fx.commit.to_hex();
        let tag_hex = fx.tag.to_hex();
        let tree_hex = fx.tree.to_hex();
        for rev in ["HEAD", "refs/heads/main", "main", commit_hex.as_str()] {
            let tar = demux(&serve(&request(&[rev]), &fx));
            assert_eq!(tar, via_head, "rev {rev} archives like HEAD");
        }
        // An annotated tag peels to its commit, keeping the commit's
        // global header and mtime.
        let tagged = demux(&serve(&request(&[tag_hex.as_str()]), &fx));
        assert_eq!(tagged, via_head, "tag peels to its commit");
        // A bare tree has no commit: no global header, zero mtimes.
        let tree_tar = demux(&serve(&request(&[tree_hex.as_str()]), &fx));
        let (globals, entries, trailer) = walk_tar(&tree_tar);
        assert!(globals.is_empty(), "no commit, no global header");
        assert_eq!(trailer, 1024);
        assert!(
            entries.iter().all(|e| e.mtime == 0),
            "tree rev stamps zero mtimes"
        );
        assert!(
            entries.iter().any(|e| e.name == b"a.txt"),
            "tree contents archived"
        );
    }

    #[test]
    fn archive_refuses_bad_requests_with_nack() {
        let fx = fixture();
        let short_hex = fx.commit.to_hex()[..8].to_owned();
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (request(&["--format=zip", "HEAD"]), "non-tar format"),
            (request(&["--prefix=p/", "HEAD"]), "extra option"),
            (request(&["HEAD", "HEAD"]), "two revisions"),
            (request(&[]), "no revision"),
            (request(&["deadbeef"]), "unknown revision"),
            (request(&[short_hex.as_str()]), "abbreviated oid"),
        ];
        for (input, what) in cases {
            let mut out = Vec::new();
            let err = serve_upload_archive(
                &input[..],
                &mut out,
                &fx.store,
                fx.kind,
                &fx.head,
                &Interrupt::none(),
            )
            .expect_err(what);
            let frame_len = usize::from_str_radix(
                std::str::from_utf8(&out[..4]).expect("NACK frame is ASCII"),
                16,
            )
            .expect("frame length");
            assert_eq!(frame_len, out.len(), "{what}: exactly one NACK frame");
            assert!(out[4..].starts_with(b"NACK"), "{what}: {:?}", &out[4..]);
            assert!(
                matches!(
                    err,
                    GitError::Unsupported { .. }
                        | GitError::NotFound { .. }
                        | GitError::Corrupt { .. }
                ),
                "{what}: {err:?}"
            );
        }
        // A blob is not archivable, and a non-argument line breaks the grammar.
        let blob = put(&fx.store, ObjectKind::Blob, b"lone\n");
        let blob_hex = blob.to_hex();
        let mut framed_want = framed(b"want abc\n");
        framed_want.extend_from_slice(b"0000");
        for (input, what) in [
            (request(&[blob_hex.as_str()]), "blob revision"),
            (framed_want, "non-argument line"),
        ] {
            let mut out = Vec::new();
            let err = serve_upload_archive(
                &input[..],
                &mut out,
                &fx.store,
                fx.kind,
                &fx.head,
                &Interrupt::none(),
            )
            .expect_err(what);
            assert!(matches!(err, GitError::Corrupt { .. }), "{what}: {err:?}");
            assert!(out.windows(4).any(|w| w == b"NACK"), "{what}: no NACK");
        }
    }

    /// Appends every emitted byte to a caller-owned buffer.
    struct Collect<'a>(&'a mut Vec<u8>);

    impl TarSink for Collect<'_> {
        fn write_tar(&mut self, bytes: &[u8]) -> Result<(), GitError> {
            self.0.extend_from_slice(bytes);
            Ok(())
        }

        fn fail(&mut self, _message: &str) -> Result<(), GitError> {
            Ok(())
        }

        fn finish(&mut self) -> Result<(), GitError> {
            Ok(())
        }
    }

    #[test]
    fn measured_count_matches_streamed_bytes() {
        let fx = fixture();
        let plan = plan_commit_archive(&fx.store, fx.kind, fx.commit).expect("plan");
        let counted =
            count_commit_tar(&fx.store, fx.kind, &plan, &Interrupt::none()).expect("count");
        let mut streamed = Vec::new();
        stream_commit_tar(
            &fx.store,
            fx.kind,
            &plan,
            &Interrupt::none(),
            Collect(&mut streamed),
        )
        .expect("stream");
        assert!(counted.tar > 0, "the fixture archive has bytes");
        assert_eq!(
            counted.tar,
            u64::try_from(streamed.len()).expect("length fits in u64"),
            "the count pass charges exactly the bytes the stream emits"
        );
    }

    #[test]
    fn archive_dispatch_routes_upload_archive() {
        let fx = fixture();
        let mut out = Vec::new();
        super::super::serve::serve_command(
            "upload-archive",
            &request(&["HEAD"])[..],
            &mut out,
            &fx.store,
            fx.kind,
            &fx.head,
            &Interrupt::none(),
            &super::super::policy::NoPolicy,
        )
        .expect("dispatch");
        assert!(out.starts_with(b"0008ACK\n0000"), "dispatched framing");
        let mut out = Vec::new();
        let err = super::super::serve::serve_command(
            "no-such-command",
            &[][..],
            &mut out,
            &fx.store,
            fx.kind,
            &fx.head,
            &Interrupt::none(),
            &super::super::policy::NoPolicy,
        )
        .expect_err("unknown command");
        assert!(matches!(err, GitError::Unsupported { .. }), "{err:?}");
    }
}
