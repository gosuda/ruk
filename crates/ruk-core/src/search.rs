//! Core-owned code search over one revision tree.
//!
//! The pool lives here so hosted reads never lend the daemon executor to
//! scans: [`HostedCoordinator::read`] awaits [`SearchPool`] permits and runs
//! shard scans in `spawn_blocking` closures. Shards cover contiguous ranges
//! of the path-ordered unique-blob list and emit strictly in shard order,
//! so completion order never changes emitted rows.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant as StdInstant};

use regex::bytes::{Regex, RegexBuilder};
use sha2::{Digest as _, Sha256};

use crate::ByteString;
use crate::coord::Cancel;
use crate::coord::reads::{blob_bytes, tree_items};
use crate::error::{CoreError, ErrorCode};
use crate::ids::{HashKind, Oid};
use crate::index::RepoPath;
use crate::protocol::{
    MAX_CURSOR_POSITION_BYTES, PathSelection, QueryDigest, SEARCH_PREVIEW_MAX_BYTES,
    SEARCH_SKIP_BLOB_BYTES, ScanExhaustion, SearchArgs, SearchBudget, SearchHit, SearchPattern,
    Validate,
};
use crate::revset::eval::glob_match;
use crate::store::Store;
use crate::workcopy::tree::TreeMode;

/// Most undecided files one `search` walk collects before it seals the
/// page. Decided files skip free, so resumption always advances.
pub(crate) const SEARCH_MAX_WALK_FILES: usize = 100_000;

/// Deepest directory one `search` walk descends; deeper trees refuse.
pub(crate) const SEARCH_MAX_TREE_DEPTH: usize = 32;

/// Paths per scan shard; shard count stays bounded on large trees.
pub(crate) const SEARCH_SHARD_PATHS: usize = 4096;

/// Most shards one `search` page scans; larger trees seal at the frontier.
pub(crate) const SEARCH_MAX_SHARDS: usize = 64;

/// Decoded bytes a fresh coordinator scans per `search` page before the
/// page seals, mirroring the daemon default.
pub(crate) const DEFAULT_SEARCH_MAX_SCAN_BYTES: u64 = 67_108_864;

/// Permits bound for concurrent search shard scans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SearchPoolConfig {
    /// Concurrent shard scans; 1 to [`SearchPoolConfig::MAX_PERMITS`].
    pub permits: u32,
}

impl SearchPoolConfig {
    /// Permits a fresh coordinator scans with.
    pub const DEFAULT_PERMITS: u32 = 8;

    /// Most permits any pool holds.
    pub const MAX_PERMITS: u32 = 64;
}

impl Default for SearchPoolConfig {
    fn default() -> Self {
        Self {
            permits: Self::DEFAULT_PERMITS,
        }
    }
}

/// Core-owned semaphore gating concurrent search shard scans.
///
/// Cloned `Arc`s share one pool; dropping the pool closes the gate.
#[derive(Debug)]
pub struct SearchPool {
    permits: usize,
    sem: Arc<tokio::sync::Semaphore>,
}

impl SearchPool {
    /// Builds one pool over `config`.
    ///
    /// # Errors
    /// `E_INVALID` for zero permits or more than
    /// [`SearchPoolConfig::MAX_PERMITS`].
    pub fn new(config: SearchPoolConfig) -> Result<Self, CoreError> {
        if config.permits == 0 || config.permits > SearchPoolConfig::MAX_PERMITS {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "search pool holds 1..={} permits, got {}",
                    SearchPoolConfig::MAX_PERMITS,
                    config.permits
                ),
            ));
        }
        let permits = usize::try_from(config.permits)
            .map_err(|_| CoreError::new(ErrorCode::EInvalid, "search permits overflow usize"))?;
        Ok(Self {
            permits,
            sem: Arc::new(tokio::sync::Semaphore::new(permits)),
        })
    }

    /// Permits the pool was built with.
    #[must_use]
    pub fn permits(&self) -> usize {
        self.permits
    }

    /// Waits for one shard slot.
    ///
    /// # Errors
    /// `E_IO` once the pool is closed.
    pub async fn acquire_owned(&self) -> Result<tokio::sync::OwnedSemaphorePermit, CoreError> {
        Arc::clone(&self.sem)
            .acquire_owned()
            .await
            .map_err(|_| CoreError::new(ErrorCode::EIo, "search pool is closed"))
    }
}

/// One emitted row: the path carrying the match with its 1-based line.
pub(crate) type EmittedRow = (Vec<u8>, u32);

/// Decoded cursor position: the last fully sealed path with the last
/// emitted row inside it. A missing path starts a fresh walk; a missing
/// row means a zero-hit page sealed at the path.
pub(crate) type SearchPosition = (Option<Vec<u8>>, Option<EmittedRow>);

/// Sealed page frontier: the resume position when more rows or unscanned
/// paths remain.
pub(crate) type SearchResume = Option<(Vec<u8>, Option<EmittedRow>)>;

/// One enumerated path with the blob it names.
pub(crate) type SearchEntry = (Vec<u8>, Oid);

/// One enumerated tree with its sealed frontier.
#[derive(Clone, Debug)]
pub(crate) struct SearchWalk {
    /// Path-ordered `(path, blob)` entries.
    pub entries: Vec<SearchEntry>,
    /// False when the walk bound sealed the walk early.
    pub complete: bool,
    /// Last fully decided path when the walk sealed early.
    pub frontier: Option<Vec<u8>>,
    /// Blobs skipped past [`SEARCH_SKIP_BLOB_BYTES`] without payload reads.
    pub prefilter_skipped: u64,
}

/// Decides whether `path` survives the §2 filter: under the selected paths,
/// matching an include glob when any exist, and matching no exclude glob.
fn path_selected(
    paths: &PathSelection,
    globs: &[String],
    exclude_globs: &[String],
    path: &[u8],
) -> bool {
    let under_paths = match paths {
        PathSelection::All => true,
        PathSelection::Paths(wanted) => wanted.iter().any(|prefix| {
            let bytes = prefix.as_bytes();
            path == bytes
                || path
                    .strip_prefix(bytes)
                    .is_some_and(|rest| rest.first() == Some(&b'/'))
        }),
    };
    if !under_paths {
        return false;
    }
    if !globs.is_empty() && !globs.iter().any(|glob| glob_match(glob.as_bytes(), path)) {
        return false;
    }
    !exclude_globs
        .iter()
        .any(|glob| glob_match(glob.as_bytes(), path))
}

/// Decides whether directory `dir` (without trailing slash) can hold a
/// selected path: either side prefixes the other.
fn dir_selected(paths: &PathSelection, dir: &[u8]) -> bool {
    match paths {
        PathSelection::All => true,
        PathSelection::Paths(wanted) => wanted.iter().any(|prefix| {
            let bytes = prefix.as_bytes();
            bytes == dir
                || bytes
                    .strip_prefix(dir)
                    .is_some_and(|rest| rest.first() == Some(&b'/'))
                || dir
                    .strip_prefix(bytes)
                    .is_some_and(|rest| rest.first() == Some(&b'/'))
        }),
    }
}

/// Where one `search` walk resumes: files at or below the ceiling stay
/// undecided, everything else skips free without counting at the bound.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WalkResume<'a> {
    /// Files below this path skip; files equal to it skip when `equal` is set.
    pub below: &'a [u8],
    /// Whether files equal to `below` skip too.
    pub equal: bool,
}

/// Walk state threaded through one recursive descent.
struct WalkState<'a> {
    args: &'a SearchArgs,
    resume: WalkResume<'a>,
    ordered: Vec<(Vec<u8>, Oid)>,
    collected: usize,
    prefilter_skipped: u64,
    frontier: Option<Vec<u8>>,
    complete: bool,
}

/// Descends one tree level in place, so visited paths stay in global
/// byte order: levels parse in git order and each selected subdirectory
/// is walked before its later siblings. The bound therefore seals at a
/// true prefix frontier, and resumption never skips an unvisited path.
///
/// # Errors
/// `E_CORRUPT` for a damaged tree, `E_LIMIT` past the depth bound.
fn walk_tree_level(
    store: &Store,
    kind: HashKind,
    oid: Oid,
    prefix: &[u8],
    depth: usize,
    state: &mut WalkState<'_>,
) -> Result<(), CoreError> {
    if depth > SEARCH_MAX_TREE_DEPTH {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("search tree is deeper than {SEARCH_MAX_TREE_DEPTH}"),
        ));
    }
    for item in tree_items(store, kind, oid)? {
        if !state.complete {
            return Ok(());
        }
        let mut path = prefix.to_vec();
        path.extend_from_slice(&item.name);
        match item.mode {
            TreeMode::Tree => {
                if dir_selected(&state.args.paths, &path) {
                    path.push(b'/');
                    walk_tree_level(store, kind, item.oid, &path, depth + 1, state)?;
                } else {
                    state.frontier = Some(path);
                }
            }
            TreeMode::File(
                crate::index::FileMode::Regular | crate::index::FileMode::Executable,
            ) => {
                state.frontier = Some(path.clone());
                if path.as_slice() < state.resume.below
                    || (state.resume.equal && path.as_slice() == state.resume.below)
                    || !path_selected(
                        &state.args.paths,
                        &state.args.globs,
                        &state.args.exclude_globs,
                        &path,
                    )
                {
                    continue;
                }
                match store.object_len(item.oid).map_err(CoreError::from)? {
                    None => {
                        return Err(CoreError::new(
                            ErrorCode::ECorrupt,
                            "tree entry links a missing object",
                        ));
                    }
                    Some(len) if len > SEARCH_SKIP_BLOB_BYTES => {
                        state.prefilter_skipped = state.prefilter_skipped.saturating_add(1);
                    }
                    Some(_) => {
                        state.collected = state.collected.saturating_add(1);
                        if state.collected > SEARCH_MAX_WALK_FILES {
                            state.complete = false;
                            return Ok(());
                        }
                        state.ordered.push((path, item.oid));
                    }
                }
            }
            TreeMode::File(_) => {
                state.frontier = Some(path);
            }
        }
    }
    Ok(())
}

/// Enumerates one root tree into path-ordered `(path, blob)` entries.
///
/// The descent recurses in place, so visited paths stay in global byte
/// order: a bound seal always names a true prefix frontier, and
/// resumption never skips an unvisited path. Only undecided files count
/// at the bound, so resumption always advances past the sealed frontier.
/// Blobs past [`SEARCH_SKIP_BLOB_BYTES`] never load; the walk reports
/// their count instead of refusing.
///
/// # Errors
/// `E_CORRUPT` for a damaged tree, `E_LIMIT` past the depth bound.
pub(crate) fn collect_search_candidates(
    store: &Store,
    kind: HashKind,
    root: Oid,
    args: &SearchArgs,
    resume: WalkResume<'_>,
) -> Result<SearchWalk, CoreError> {
    let mut state = WalkState {
        args,
        resume,
        ordered: Vec::new(),
        collected: 0,
        prefilter_skipped: 0,
        frontier: None,
        complete: true,
    };
    walk_tree_level(store, kind, root, &[], 0, &mut state)?;
    state.ordered.sort();
    Ok(SearchWalk {
        entries: state.ordered,
        complete: state.complete,
        frontier: state.frontier,
        prefilter_skipped: state.prefilter_skipped,
    })
}

/// Builds the byte matcher for one pattern: literals escape exactly like
/// [`regex::escape`], regexes compile as-is, both case-fold on request.
///
/// # Errors
/// `E_INVALID` for a regex the engine refuses.
pub(crate) fn build_search_matcher(
    pattern: &SearchPattern,
    case_insensitive: bool,
) -> Result<Regex, CoreError> {
    let source: String = match pattern {
        SearchPattern::Literal(needle) => match core::str::from_utf8(needle.as_bytes()) {
            Ok(text) => regex::escape(text),
            Err(_) => escape_bytes(needle.as_bytes()),
        },
        SearchPattern::Regex(pattern) => pattern.clone(),
    };
    RegexBuilder::new(&source)
        .case_insensitive(case_insensitive)
        .build()
        .map_err(|err| CoreError::new(ErrorCode::EInvalid, format!("search regex: {err}")))
}

/// Escapes arbitrary bytes like [`regex::escape`] escapes text: ASCII regex
/// metacharacters take a backslash, and non-UTF-8 bytes become `\xNN`
/// escapes so the pattern stays valid UTF-8 for the builder.
fn escape_bytes(needle: &[u8]) -> String {
    const META: &[u8] = b"\\.^+*$?()[]{}|";
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(needle.len());
    for &byte in needle {
        if META.contains(&byte) {
            out.push('\\');
            out.push(byte as char);
        } else if byte < 0x80 {
            out.push(byte as char);
        } else {
            out.push_str("\\x");
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
    }
    out
}

/// One matching line: 1-based line and byte-column numbers with a preview
/// of at most [`SEARCH_PREVIEW_MAX_BYTES`] bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LineHit {
    pub line: u32,
    pub column: u32,
    pub preview: ByteString,
}

/// Scans decoded blob bytes into matching lines, or `None` for binaries.
///
/// Lines split on `\n` like the CLI scanner: a trailing newline leaves no
/// empty final line, and any NUL skips the whole blob. The preview keeps
/// the first kibibyte of the line, marking longer lines with `...`.
///
/// # Errors
/// `E_INVALID` for a line count or column overflowing `u32`.
pub(crate) fn scan_blob_lines(
    bytes: &[u8],
    matcher: &Regex,
) -> Result<Option<Vec<LineHit>>, CoreError> {
    if bytes.contains(&0) {
        return Ok(None);
    }
    let mut lines: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').collect();
    if bytes.ends_with(b"\n") {
        lines.pop();
    }
    let mut hits = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(found) = matcher.find(line) else {
            continue;
        };
        let line_no = u32::try_from(index.saturating_add(1))
            .map_err(|_| CoreError::new(ErrorCode::EInvalid, "search line number overflows u32"))?;
        let column = u32::try_from(found.start().saturating_add(1))
            .map_err(|_| CoreError::new(ErrorCode::EInvalid, "search column overflows u32"))?;
        let preview = if line.len() > SEARCH_PREVIEW_MAX_BYTES {
            let mut cut = line[..SEARCH_PREVIEW_MAX_BYTES.saturating_sub(3)].to_vec();
            cut.extend_from_slice(b"...");
            ByteString::from(cut)
        } else {
            ByteString::from(line.to_vec())
        };
        hits.push(LineHit {
            line: line_no,
            column,
            preview,
        });
    }
    Ok(Some(hits))
}

/// One emitted row: the path carrying the match with its blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScannedRow {
    pub path: Vec<u8>,
    pub line: u32,
    pub column: u32,
    pub preview: ByteString,
    pub blob: Oid,
}

/// One finished shard: capped rows with scan totals and the last fully
/// processed path. Blob decodes count every decode: a blob shared by
/// non-adjacent paths decodes once per adjacency run.
#[derive(Clone, Debug)]
pub(crate) struct ShardOutput {
    /// First rows in path order, capped at the page limit plus one.
    pub rows: Vec<ScannedRow>,
    /// Blob decodes performed.
    pub scanned_blobs: u64,
    /// Decoded bytes inspected, including binary-skipped blobs.
    pub scanned_bytes: u64,
    /// Blobs skipped past the size bound or for binary content.
    pub skipped_blobs: u64,
    /// Whether the deadline passed mid-shard.
    pub deadline_hit: bool,
    /// Last fully processed candidate path, if any.
    pub end_path: Option<Vec<u8>>,
}

/// One shard scan: owned inputs so blocking tasks take the whole job.
#[derive(Debug)]
pub(crate) struct ShardScan {
    /// Contiguous slice of the path-ordered entry list.
    pub shard: Vec<SearchEntry>,
    /// Compiled needle or regex.
    pub matcher: Regex,
    /// Most rows the shard keeps; the fold needs the limit plus one.
    pub row_cap: usize,
    /// Rows at or before this resume point are decided: paths skip free
    /// without payload reads, and matching lines skip before the row cap
    /// counts them, so the cap never drops an undecided row.
    pub skip_before: (Vec<u8>, u32),
    /// Set once the page seals; the shard stops at its next path.
    pub stop: Arc<AtomicBool>,
    /// Caller cancellation.
    pub cancel: Cancel,
    /// The page seals once this passes.
    pub deadline: StdInstant,
}

/// Scans one shard in path order, emitting rows path-ordered so the
/// concatenated shards stay globally ordered and resumption never skips
/// an unemitted row.
///
/// One blob's hits stay cached while consecutive paths name it; a repeat
/// after other blobs rescans the blob. Rescans keep every decode in the
/// totals: adjacent duplicates share one decode, the common duplicate
/// layout, while correctness never depends on adjacency.
///
/// # Errors
/// `E_CANCELLED` once cancelled, `E_INVALID` for a non-blob entry or an
/// overflowing line number.
pub(crate) fn scan_search_shard(store: &Store, job: &ShardScan) -> Result<ShardOutput, CoreError> {
    let mut out = ShardOutput {
        rows: Vec::new(),
        scanned_blobs: 0,
        scanned_bytes: 0,
        skipped_blobs: 0,
        deadline_hit: false,
        end_path: None,
    };
    let mut cached: Option<(Oid, Vec<LineHit>)> = None;
    let (skip_path, skip_line) = &job.skip_before;
    for (path, oid) in &job.shard {
        if job.stop.load(Ordering::SeqCst) {
            break;
        }
        job.cancel.check()?;
        if path.as_slice() < skip_path.as_slice()
            || (*skip_line == 0 && !skip_path.is_empty() && path.as_slice() == skip_path.as_slice())
        {
            out.end_path = Some(path.clone());
            continue;
        }
        let fresh = cached
            .as_ref()
            .is_none_or(|(cached_oid, _)| *cached_oid != *oid);
        if fresh {
            let bytes = blob_bytes(store, *oid)?;
            out.scanned_blobs = out.scanned_blobs.saturating_add(1);
            out.scanned_bytes = out
                .scanned_bytes
                .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
            match scan_blob_lines(&bytes, &job.matcher)? {
                None => {
                    out.skipped_blobs = out.skipped_blobs.saturating_add(1);
                    cached = None;
                    out.end_path = Some(path.clone());
                    continue;
                }
                Some(hits) => {
                    cached = Some((*oid, hits));
                }
            }
        }
        if let Some((_, hits)) = cached.as_ref() {
            for hit in hits {
                if path.as_slice() == skip_path.as_slice() && hit.line <= *skip_line {
                    continue;
                }
                if out.rows.len() < job.row_cap {
                    out.rows.push(ScannedRow {
                        path: path.clone(),
                        line: hit.line,
                        column: hit.column,
                        preview: hit.preview.clone(),
                        blob: *oid,
                    });
                }
            }
        }
        out.end_path = Some(path.clone());
        if StdInstant::now() >= job.deadline {
            out.deadline_hit = true;
        }
    }
    Ok(out)
}

/// Folds ordered shard outputs into the page decision.
#[derive(Debug)]
pub(crate) struct SearchFold {
    limit: usize,
    max_bytes: u64,
    max_blobs: u64,
    deadline: StdInstant,
    skip_before: (Vec<u8>, u32),
    rows: Vec<ScannedRow>,
    scanned_blobs: u64,
    scanned_bytes: u64,
    skipped_blobs: u64,
    limit_sealed: bool,
    budget_sealed: bool,
    deadline_hit: bool,
    frontier: Option<Vec<u8>>,
}

impl SearchFold {
    /// Starts one fold over at most `limit` emitted rows, skipping rows at
    /// or before `skip_before` (empty path skips nothing).
    pub(crate) fn new(
        limit: usize,
        budget: &SearchBudget,
        max_bytes: u64,
        deadline: StdInstant,
        skip_before: (Vec<u8>, u32),
    ) -> Self {
        Self {
            limit,
            max_bytes,
            max_blobs: u64::from(budget.effective_max_blobs()),
            deadline,
            skip_before,
            rows: Vec::new(),
            scanned_blobs: 0,
            scanned_bytes: 0,
            skipped_blobs: 0,
            limit_sealed: false,
            budget_sealed: false,
            deadline_hit: false,
            frontier: None,
        }
    }

    /// Whether the page sealed and trailing shards stop early.
    #[must_use]
    pub(crate) fn sealed(&self) -> bool {
        self.limit_sealed || self.budget_sealed
    }

    /// Counts blobs the walk skipped without payload reads.
    pub(crate) fn add_skipped(&mut self, skipped: u64) {
        self.skipped_blobs = self.skipped_blobs.saturating_add(skipped);
    }

    /// Folds one shard output in shard order; post-seal outputs are ignored
    /// so totals describe the sealed prefix deterministically.
    pub(crate) fn push_shard(&mut self, out: ShardOutput) {
        if self.sealed() {
            return;
        }
        self.scanned_blobs = self.scanned_blobs.saturating_add(out.scanned_blobs);
        self.scanned_bytes = self.scanned_bytes.saturating_add(out.scanned_bytes);
        self.skipped_blobs = self.skipped_blobs.saturating_add(out.skipped_blobs);
        if out.deadline_hit {
            self.deadline_hit = true;
        }
        if let Some(end) = out.end_path {
            self.frontier = Some(end);
        }
        for row in out.rows {
            let (path, line) = &self.skip_before;
            if row.path.as_slice() < path.as_slice()
                || (row.path.as_slice() == path.as_slice() && row.line <= *line)
            {
                continue;
            }
            if self.rows.len() <= self.limit {
                self.rows.push(row);
            }
        }
        if self.rows.len() > self.limit {
            self.limit_sealed = true;
        } else if self.deadline_hit || StdInstant::now() >= self.deadline {
            self.deadline_hit = true;
            self.budget_sealed = true;
        } else if self.scanned_bytes > self.max_bytes || self.scanned_blobs > self.max_blobs {
            self.budget_sealed = true;
        }
    }
}

/// One sealed page: capped rows with totals and the resume position.
/// A resume position means more rows or unscanned paths remain.
#[derive(Clone, Debug)]
pub(crate) struct SealedSearchPage {
    /// First rows in path order, at most the limit plus one.
    pub rows: Vec<ScannedRow>,
    /// Why the page sealed early.
    pub exhausted: crate::protocol::ScanExhaustion,
    /// Resume frontier: last emitted row, or the sealed path for zero-hit pages.
    pub resume: SearchResume,
    pub scanned_blobs: u64,
    pub scanned_bytes: u64,
    pub skipped_blobs: u64,
}

/// Seals one fold: caps rows at the limit, derives the resume position,
/// and reports exhaustion. A complete walk without a seal covers its
/// tree; callers pass `walk_complete`.
pub(crate) fn seal_search_fold(
    mut fold: SearchFold,
    walk_complete: bool,
    walk_frontier: Option<Vec<u8>>,
) -> SealedSearchPage {
    let truncated = fold.sealed() || !walk_complete;
    let exhausted = if fold.deadline_hit {
        ScanExhaustion::Deadline
    } else if fold.budget_sealed {
        ScanExhaustion::Budget
    } else {
        ScanExhaustion::None
    };
    let resume = if !truncated {
        None
    } else if fold.rows.len() > fold.limit {
        fold.rows.truncate(fold.limit);
        fold.rows
            .last()
            .map(|last| (last.path.clone(), Some((last.path.clone(), last.line))))
    } else {
        let frontier = fold.frontier.or(walk_frontier);
        frontier.map(|scan_after| (scan_after, None))
    };
    SealedSearchPage {
        rows: fold.rows,
        exhausted: if resume.is_some() {
            exhausted
        } else {
            ScanExhaustion::None
        },
        resume,
        scanned_blobs: fold.scanned_blobs,
        scanned_bytes: fold.scanned_bytes,
        skipped_blobs: fold.skipped_blobs,
    }
}

/// Deadline one page scans until: the start plus the effective budget.
pub(crate) fn search_deadline(start: StdInstant, budget: &SearchBudget) -> StdInstant {
    start + Duration::from_millis(budget.effective_deadline_ms())
}

/// Binds one query to its lease: the v1 domain, resolved tree, pattern,
/// case flag, canonical paths, sorted globs, and budget triple.
pub(crate) fn search_query_digest(root: Oid, args: &SearchArgs) -> QueryDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"ruk.search/v1\x00");
    hasher.update(root.as_bytes());
    match &args.pattern {
        SearchPattern::Literal(needle) => {
            hasher.update([0x00]);
            hasher.update(needle.as_bytes());
        }
        SearchPattern::Regex(pattern) => {
            hasher.update([0x01]);
            hasher.update(pattern.as_bytes());
        }
    }
    hasher.update([u8::from(args.case_insensitive)]);
    match &args.paths {
        PathSelection::All => hasher.update([0x00]),
        PathSelection::Paths(wanted) => {
            hasher.update([0x01]);
            let mut sorted: Vec<&[u8]> = wanted.iter().map(RepoPath::as_bytes).collect();
            sorted.sort();
            for path in sorted {
                hasher.update(u64::try_from(path.len()).unwrap_or(u64::MAX).to_be_bytes());
                hasher.update(path);
            }
        }
    }
    let mut globs: Vec<&str> = args.globs.iter().map(String::as_str).collect();
    globs.sort();
    hasher.update([0x02]);
    for glob in globs {
        hasher.update(u64::try_from(glob.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(glob.as_bytes());
    }
    let mut exclude: Vec<&str> = args.exclude_globs.iter().map(String::as_str).collect();
    exclude.sort();
    hasher.update([0x03]);
    for glob in exclude {
        hasher.update(u64::try_from(glob.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(glob.as_bytes());
    }
    hasher.update(args.budget.effective_max_bytes().to_be_bytes());
    hasher.update(args.budget.effective_max_blobs().to_be_bytes());
    hasher.update(args.budget.effective_deadline_ms().to_be_bytes());
    QueryDigest::from_bytes(hasher.finalize().into())
}

/// Encodes the resume position: the last fully sealed path with the last
/// emitted row inside it. Empty input encodes the walk start.
///
/// # Errors
/// `E_LIMIT` past [`MAX_CURSOR_POSITION_BYTES`].
pub(crate) fn encode_search_position(
    scan_after: Option<&[u8]>,
    emit_after: Option<(&[u8], u32)>,
) -> Result<ByteString, CoreError> {
    let scan = scan_after.unwrap_or_default();
    let mut out = Vec::with_capacity(scan.len().saturating_add(16));
    out.extend_from_slice(
        &u32::try_from(scan.len())
            .map_err(|_| {
                CoreError::new(ErrorCode::ELimit, "search path exceeds its position bound")
            })?
            .to_be_bytes(),
    );
    out.extend_from_slice(scan);
    match emit_after {
        None => out.push(0x00),
        Some((path, line)) => {
            out.push(0x01);
            out.extend_from_slice(
                &u32::try_from(path.len())
                    .map_err(|_| {
                        CoreError::new(ErrorCode::ELimit, "search path exceeds its position bound")
                    })?
                    .to_be_bytes(),
            );
            out.extend_from_slice(path);
            out.extend_from_slice(&line.to_be_bytes());
        }
    }
    if out.len() > MAX_CURSOR_POSITION_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("search resume position exceeds {MAX_CURSOR_POSITION_BYTES} bytes"),
        ));
    }
    Ok(ByteString::from(out))
}

/// Decodes a resume position, refusing shape mismatches.
///
/// # Errors
/// `E_INVALID` for a truncated or trailing-padded position.
pub(crate) fn decode_search_position(position: &ByteString) -> Result<SearchPosition, CoreError> {
    let bytes = position.as_bytes();
    if bytes.is_empty() {
        return Ok((None, None));
    }
    fn take_field(rest: &[u8]) -> Result<(Vec<u8>, &[u8]), CoreError> {
        let invalid = || CoreError::new(ErrorCode::EInvalid, "search cursor position is malformed");
        let (len, rest) = rest.split_at_checked(4).ok_or_else(invalid)?;
        let len = usize::try_from(u32::from_be_bytes(len.try_into().map_err(|_| invalid())?))
            .map_err(|_| invalid())?;
        let (field, rest) = rest.split_at_checked(len).ok_or_else(invalid)?;
        Ok((field.to_vec(), rest))
    }
    let invalid = || CoreError::new(ErrorCode::EInvalid, "search cursor position is malformed");
    let (scan_after, rest) = take_field(bytes)?;
    let (flag, rest) = rest.split_at_checked(1).ok_or_else(invalid)?;
    let emit_after = match flag[0] {
        0x00 => {
            if !rest.is_empty() {
                return Err(invalid());
            }
            None
        }
        0x01 => {
            let (path, rest) = take_field(rest)?;
            let (line, rest) = rest.split_at_checked(4).ok_or_else(invalid)?;
            if !rest.is_empty() {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    "search cursor position is malformed",
                ));
            }
            Some((
                path,
                u32::from_be_bytes(line.try_into().map_err(|_| invalid())?),
            ))
        }
        _ => return Err(invalid()),
    };
    Ok((Some(scan_after).filter(|path| !path.is_empty()), emit_after))
}

/// Splits ordered entries into contiguous path shards of at most
/// [`SEARCH_SHARD_PATHS`] paths, keeping the shard count at most
/// [`SEARCH_MAX_SHARDS`]. Contiguity keeps every shard's rows
/// path-ordered, so concatenated shards stay globally ordered.
pub(crate) fn shard_search_entries(entries: Vec<SearchEntry>) -> Vec<Vec<SearchEntry>> {
    let per_shard = SEARCH_SHARD_PATHS.max(entries.len().div_ceil(SEARCH_MAX_SHARDS).max(1));
    entries
        .chunks(per_shard)
        .map(<[SearchEntry]>::to_vec)
        .collect()
}

/// Maps one scanned row to its wire hit.
///
/// # Errors
/// `E_CORRUPT` for a path the tree should never have held.
pub(crate) fn search_hit(row: &ScannedRow) -> Result<SearchHit, CoreError> {
    Ok(SearchHit {
        path: RepoPath::new(row.path.clone()).map_err(|err| {
            CoreError::new(
                ErrorCode::ECorrupt,
                format!("search path is invalid: {err}"),
            )
        })?,
        line: row.line,
        column: row.column,
        preview: row.preview.clone(),
        blob: row.blob,
    })
}

/// One locally served search page: first-page hits with a stateless resume
/// position and no lease binding.
#[derive(Clone, Debug)]
pub struct LocalSearchPage {
    /// Matching lines in path-byte order, at most the requested limit.
    pub hits: Vec<SearchHit>,
    /// True when more rows or unscanned paths remain.
    pub truncated: bool,
    /// Why the page sealed early.
    pub exhausted: ScanExhaustion,
    /// Blob decodes performed; a blob shared by non-adjacent paths
    /// decodes once per adjacency run.
    pub scanned_blobs: u64,
    /// Decoded bytes inspected, including binary-skipped blobs.
    pub scanned_bytes: u64,
    /// Blobs skipped past the size bound or for binary content.
    pub skipped_blobs: u64,
    /// Resume position for the next call; pass back as the cursor position.
    pub next: Option<ByteString>,
}

/// Serves one local search against an open store without a coordinator:
/// validates, resolves the revision, and scans serially on the calling
/// thread. Cursor bindings are not enforced locally; continuations carry
/// only the resume position. Workspace revisions refuse.
///
/// # Errors
/// `E_INVALID` for a bad pattern, glob, budget, or cursor position, or a
/// workspace revision; `E_NOT_FOUND` for an unknown revision; `E_LIMIT`
/// past the depth bound; `E_CORRUPT` for a damaged tree.
pub fn search_content_local(
    store: &Store,
    args: &SearchArgs,
) -> Result<LocalSearchPage, CoreError> {
    use crate::coord::cancellation;
    args.validate()?;
    let root = crate::coord::reads::revision_tree(store, &args.at)?;
    let skip_before = match args.page.cursor.as_ref() {
        None => (Vec::new(), 0),
        Some(cursor) => {
            let (scan_after, emit_after) = decode_search_position(&cursor.position)?;
            match (scan_after, emit_after) {
                (Some(scan), Some((_, line))) => (scan, line),
                (Some(scan), None) => (scan, 0),
                (None, _) => (Vec::new(), 0),
            }
        }
    };
    let limit = args.page.effective_limit();
    let max_bytes = args.budget.effective_max_bytes();
    let now = StdInstant::now();
    let deadline = search_deadline(now, &args.budget);
    let matcher = build_search_matcher(&args.pattern, args.case_insensitive)?;
    let resume = WalkResume {
        below: skip_before.0.as_slice(),
        equal: skip_before.1 == 0 && !skip_before.0.is_empty(),
    };
    let walk = collect_search_candidates(store, store.hash_kind(), root, args, resume)?;
    let (_guard, cancel) = cancellation();
    let stop = Arc::new(AtomicBool::new(false));
    let mut fold = SearchFold::new(
        limit,
        &args.budget,
        max_bytes,
        deadline,
        skip_before.clone(),
    );
    fold.add_skipped(walk.prefilter_skipped);
    for shard in shard_search_entries(walk.entries) {
        cancel.check()?;
        if fold.sealed() {
            break;
        }
        let job = ShardScan {
            shard,
            matcher: matcher.clone(),
            row_cap: limit.saturating_add(1),
            skip_before: skip_before.clone(),
            stop: Arc::clone(&stop),
            cancel: cancel.clone(),
            deadline,
        };
        fold.push_shard(scan_search_shard(store, &job)?);
    }
    let sealed = seal_search_fold(fold, walk.complete, walk.frontier);
    let mut hits = Vec::with_capacity(sealed.rows.len().min(limit));
    for row in sealed.rows.iter().take(limit) {
        hits.push(search_hit(row)?);
    }
    let next = match sealed.resume {
        None => None,
        Some((scan_after, emit_after)) => {
            let emit = emit_after
                .as_ref()
                .map(|(path, line)| (path.as_slice(), *line));
            Some(encode_search_position(Some(&scan_after), emit)?)
        }
    };
    let truncated = next.is_some();
    Ok(LocalSearchPage {
        hits,
        truncated,
        exhausted: if truncated {
            sealed.exhausted
        } else {
            ScanExhaustion::None
        },
        scanned_blobs: sealed.scanned_blobs,
        scanned_bytes: sealed.scanned_bytes,
        skipped_blobs: sealed.skipped_blobs,
        next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn literal(text: &str) -> SearchPattern {
        SearchPattern::Literal(ByteString::from(text.as_bytes().to_vec()))
    }

    fn search_args(pattern: SearchPattern) -> SearchArgs {
        SearchArgs {
            at: crate::protocol::RevisionRef::Workspace {
                workspace: crate::change::WorkspaceId::from_bytes([7; 16]),
            },
            pattern,
            case_insensitive: false,
            paths: PathSelection::All,
            globs: Vec::new(),
            exclude_globs: Vec::new(),
            budget: SearchBudget::default(),
            page: crate::protocol::PageRequest::default(),
        }
    }

    #[test]
    fn literal_matches_bytes_case_matrix() {
        let lower = build_search_matcher(&literal("fn main"), false).expect("literal compiles");
        assert!(lower.find(b"fn main").is_some());
        assert!(lower.find(b"FN MAIN").is_none());
        let folded = build_search_matcher(&literal("fn main"), true).expect("folded compiles");
        assert!(folded.find(b"FN MAIN").is_some());
        let regex = build_search_matcher(&SearchPattern::Regex("fn\\s+main".to_string()), false)
            .expect("regex compiles");
        assert!(regex.find(b"fn   main").is_some());
        assert!(regex.find(b"fnmain").is_none());
        build_search_matcher(&SearchPattern::Regex("(".to_string()), false)
            .expect_err("bad regex refuses");
    }

    #[test]
    fn literal_escapes_regex_syntax() {
        let escaped = match build_search_matcher(&literal("a+b"), false) {
            Ok(matcher) => matcher,
            Err(err) => panic!("literal compiles: {err}"),
        };
        assert!(escaped.find(b"a+b").is_some());
        assert!(escaped.find(b"aab").is_none());
        let dot = build_search_matcher(&literal("a.c"), false).expect("dot literal compiles");
        assert!(dot.find(b"a.c").is_some());
        assert!(dot.find(b"axc").is_none());
    }

    #[test]
    fn scan_skips_binary_and_counts_lines() {
        let matcher = build_search_matcher(&literal("hi"), false).expect("literal compiles");
        assert!(scan_blob_lines(b"a\0b", &matcher).expect("scan").is_none());
        let hits = scan_blob_lines(b"hi\nsay hi\nbye\n", &matcher)
            .expect("scan")
            .expect("text scans");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].line, 1);
        assert_eq!(hits[0].column, 1);
        assert_eq!(hits[1].line, 2);
        assert_eq!(hits[1].column, 5);
        let empty = scan_blob_lines(b"", &matcher)
            .expect("scan")
            .expect("empty scans");
        assert!(empty.is_empty());
    }

    #[test]
    fn preview_truncates_long_lines() {
        let matcher = build_search_matcher(&literal("x"), false).expect("literal compiles");
        let mut line = vec![b'x'; SEARCH_PREVIEW_MAX_BYTES + 40];
        line.push(b'\n');
        let hits = scan_blob_lines(&line, &matcher)
            .expect("scan")
            .expect("text scans");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].preview.as_bytes().len(), SEARCH_PREVIEW_MAX_BYTES);
        assert!(hits[0].preview.as_bytes().ends_with(b"..."));
    }

    #[test]
    fn position_codec_round_trips_and_refuses_mismatch() {
        let encoded =
            encode_search_position(Some(b"src/a"), Some((b"src/a", 7))).expect("position encodes");
        let (scan, emit) = decode_search_position(&encoded).expect("position decodes");
        assert_eq!(scan, Some(b"src/a".to_vec()));
        assert_eq!(emit, Some((b"src/a".to_vec(), 7)));
        let start = encode_search_position(None, None).expect("start encodes");
        let (scan, emit) = decode_search_position(&start).expect("start decodes");
        assert_eq!(scan, None);
        assert_eq!(emit, None);
        decode_search_position(&ByteString::from(vec![0, 1]))
            .expect_err("truncated position refuses");
        let mut trailing = encoded.as_bytes().to_vec();
        trailing.push(0x00);
        decode_search_position(&ByteString::from(trailing)).expect_err("padded position refuses");
    }

    #[test]
    fn digest_changes_with_every_binding() {
        let root = Oid::from_bytes(&[3; 20]).expect("test oid");
        let base = search_args(literal("needle"));
        let digest = search_query_digest(root, &base);
        let mut other = base.clone();
        other.case_insensitive = true;
        assert_ne!(digest, search_query_digest(root, &other));
        let mut other = base.clone();
        other.paths =
            PathSelection::Paths(vec![RepoPath::new(b"src".to_vec()).expect("test path")]);
        assert_ne!(digest, search_query_digest(root, &other));
        other = base.clone();
        other.globs = vec!["*.rs".to_string()];
        assert_ne!(digest, search_query_digest(root, &other));
        other = base.clone();
        other.budget = SearchBudget {
            max_bytes_scanned: Some(1),
            max_blobs: None,
            deadline_ms: None,
        };
        assert_ne!(digest, search_query_digest(root, &other));
        assert_eq!(digest, search_query_digest(root, &base));
    }

    #[test]
    fn combination_rule_filters_prefix_include_exclude() {
        let all = PathSelection::All;
        assert!(path_selected(&all, &[], &[], b"src/main.rs"));
        assert!(!path_selected(
            &PathSelection::Paths(vec![RepoPath::new(b"src".to_vec()).expect("test path")]),
            &[],
            &[],
            b"other/lib.rs"
        ));
        assert!(path_selected(
            &PathSelection::All,
            &[String::from("**/*.rs")],
            &[],
            b"src/main.rs"
        ));
        assert!(path_selected(
            &PathSelection::All,
            &[String::from("*.rs")],
            &[],
            b"main.rs"
        ));
        assert!(!path_selected(
            &PathSelection::All,
            &[String::from("*.rs")],
            &[],
            b"src/main.rs"
        ));
        assert!(!path_selected(
            &PathSelection::All,
            &[String::from("*.rs")],
            &[],
            b"src/main.txt"
        ));
        assert!(!path_selected(
            &PathSelection::All,
            &[],
            &[String::from("src/**")],
            b"src/main.rs"
        ));
    }

    #[test]
    fn pool_refuses_empty_and_oversized_permits() {
        SearchPool::new(SearchPoolConfig { permits: 0 }).expect_err("zero refuses");
        SearchPool::new(SearchPoolConfig {
            permits: SearchPoolConfig::MAX_PERMITS + 1,
        })
        .expect_err("oversized refuses");
        assert_eq!(
            SearchPool::new(SearchPoolConfig { permits: 3 })
                .expect("bounded pool builds")
                .permits(),
            3
        );
    }

    #[test]
    fn validate_rejects_bad_inputs() {
        use crate::protocol::Validate as _;
        let mut args = search_args(literal("needle"));
        args.validate().expect("control validates");
        let bad = [
            SearchPattern::Literal(ByteString::from(Vec::new())),
            SearchPattern::Regex(String::new()),
            SearchPattern::Regex("(".to_string()),
        ];
        for pattern in bad {
            let args = search_args(pattern);
            assert_eq!(
                args.validate().expect_err("bad pattern refuses").code,
                ErrorCode::EInvalid
            );
        }
        args = search_args(literal(&"x".repeat(SEARCH_PATTERN_MAX_BYTES + 1)));
        assert_eq!(
            args.validate().expect_err("oversized pattern refuses").code,
            ErrorCode::EInvalid
        );
        args = search_args(literal("needle"));
        args.globs = vec![String::new()];
        assert_eq!(
            args.validate().expect_err("empty glob refuses").code,
            ErrorCode::EInvalid
        );
        args.globs = vec!["x".repeat(SEARCH_GLOB_MAX_BYTES + 1)];
        assert_eq!(
            args.validate().expect_err("oversized glob refuses").code,
            ErrorCode::EInvalid
        );
        args.globs = vec!["*".to_string(); SEARCH_MAX_GLOBS + 1];
        assert_eq!(
            args.validate().expect_err("glob overflow refuses").code,
            ErrorCode::EInvalid
        );
        args = search_args(literal("needle"));
        args.budget.max_bytes_scanned = Some(SEARCH_MAX_BYTES_SCANNED + 1);
        assert_eq!(
            args.validate().expect_err("byte overflow refuses").code,
            ErrorCode::EInvalid
        );
        args.budget = SearchBudget::default();
        args.budget.deadline_ms = Some(SEARCH_MAX_DEADLINE_MS + 1);
        assert_eq!(
            args.validate().expect_err("deadline overflow refuses").code,
            ErrorCode::EInvalid
        );
    }

    #[test]
    fn encode_position_rejects_oversized_paths() {
        let long = vec![b'p'; MAX_CURSOR_POSITION_BYTES];
        assert_eq!(
            encode_search_position(Some(&long), None)
                .expect_err("oversized position refuses")
                .code,
            ErrorCode::ELimit
        );
    }

    #[test]
    fn search_hit_rejects_invalid_paths() {
        let row = ScannedRow {
            path: b".git/config".to_vec(),
            line: 1,
            column: 1,
            preview: ByteString::from(b"hit".to_vec()),
            blob: Oid::from_bytes(&[9; 20]).expect("test oid"),
        };
        assert_eq!(
            search_hit(&row).expect_err("dot-git path refuses").code,
            ErrorCode::ECorrupt
        );
    }

    struct TempRoot(std::path::PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ruk-search-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_nanos())
            ));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self(dir)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_store(tag: &str) -> (TempRoot, Arc<Store>) {
        use crate::store::PreparationBudget;
        let temp = TempRoot::new(tag);
        let store = Arc::new(
            Store::create(
                &temp.0,
                HashKind::Sha1,
                Arc::new(PreparationBudget::reference_defaults()),
            )
            .expect("create store"),
        );
        (temp, store)
    }

    fn put_blob(store: &Store, bytes: &[u8]) -> Oid {
        use crate::store::types::ObjectKind;
        let prepared = store
            .prepare(
                ObjectKind::Blob,
                u64::try_from(bytes.len()).expect("object length"),
                bytes,
                None,
            )
            .expect("prepare blob");
        let oid = prepared.oid();
        store
            .publish(
                vec![prepared],
                &[],
                crate::store::EventSource::LocalPush,
                &crate::store::EventContext::default(),
            )
            .expect("publish blob");
        oid
    }

    fn put_tree(store: &Store, items: &[(&str, crate::workcopy::tree::TreeMode, Oid)]) -> Oid {
        use crate::store::types::ObjectKind;
        use crate::workcopy::tree::{TreeItem, encode_tree};
        let encoded = encode_tree(
            &items
                .iter()
                .map(|(name, mode, oid)| TreeItem {
                    name: name.as_bytes().to_vec(),
                    mode: *mode,
                    oid: *oid,
                })
                .collect::<Vec<_>>(),
        );
        let prepared = store
            .prepare(
                ObjectKind::Tree,
                u64::try_from(encoded.len()).expect("object length"),
                encoded.as_slice(),
                None,
            )
            .expect("prepare tree");
        let oid = prepared.oid();
        store
            .publish(
                vec![prepared],
                &[],
                crate::store::EventSource::LocalPush,
                &crate::store::EventContext::default(),
            )
            .expect("publish tree");
        oid
    }

    fn commit_tree(
        store: &Store,
        tree: Oid,
        parents: Vec<crate::heads::Head>,
    ) -> crate::heads::Head {
        use crate::conflict::{Signature, TzOffset};
        let signature = || Signature {
            name: ByteString::from("ada"),
            email: ByteString::from("ada@example.com"),
            timestamp: 1_700_000_000,
            offset: TzOffset::new(false, 0).expect("tz offset"),
        };
        crate::ops::new(
            store,
            crate::ops::NewRequest {
                tree,
                parents,
                author: signature(),
                committer: signature(),
                message: ByteString::from("search fixture"),
                change_id: None,
                predecessor: None,
                provenance: None,
            },
        )
        .expect("new commit")
        .head
    }

    #[test]
    fn walk_counts_skips_and_orders_paths() {
        use crate::index::FileMode;
        use crate::workcopy::tree::TreeMode;
        let (_temp, store) = test_store("walk");
        let text = put_blob(&store, b"needle here\n");
        let binary = put_blob(&store, b"needle\0binary\n");
        let big = put_blob(&store, &vec![b'x'; SEARCH_SKIP_BLOB_BYTES as usize + 8]);
        let root = put_tree(
            &store,
            &[
                ("a.txt", TreeMode::File(FileMode::Regular), text),
                ("b.txt", TreeMode::File(FileMode::Regular), text),
                ("c.bin", TreeMode::File(FileMode::Regular), binary),
                ("d.big", TreeMode::File(FileMode::Regular), big),
            ],
        );
        let args = search_args(literal("needle"));
        let resume = WalkResume {
            below: &[],
            equal: false,
        };
        let walk = collect_search_candidates(&store, store.hash_kind(), root, &args, resume)
            .expect("walk collects");
        assert!(walk.complete);
        assert_eq!(walk.entries.len(), 3);
        assert_eq!(walk.prefilter_skipped, 1);
        let matcher = build_search_matcher(&args.pattern, false).expect("matcher compiles");
        let (_guard, cancel) = crate::coord::cancellation();
        let job = ShardScan {
            shard: walk.entries,
            matcher,
            row_cap: 100,
            skip_before: (Vec::new(), 0),
            stop: Arc::new(AtomicBool::new(false)),
            cancel,
            deadline: StdInstant::now() + Duration::from_secs(60),
        };
        let out = scan_search_shard(&store, &job).expect("shard scans");
        assert_eq!(out.scanned_blobs, 2);
        assert_eq!(out.skipped_blobs, 1);
        assert_eq!(out.rows.len(), 2);
        assert_eq!(out.rows[0].path, b"a.txt");
        assert_eq!(out.rows[1].path, b"b.txt");
    }

    #[test]
    fn walk_applies_paths_and_glob_filters() {
        use crate::index::FileMode;
        use crate::workcopy::tree::TreeMode;
        let (_temp, store) = test_store("filter");
        let blob = put_blob(&store, b"needle\n");
        let src = put_tree(
            &store,
            &[
                ("a.rs", TreeMode::File(FileMode::Regular), blob),
                ("b.txt", TreeMode::File(FileMode::Regular), blob),
            ],
        );
        let vendor = put_tree(&store, &[("c.rs", TreeMode::File(FileMode::Regular), blob)]);
        let root = put_tree(
            &store,
            &[
                ("src", TreeMode::Tree, src),
                ("vendor", TreeMode::Tree, vendor),
            ],
        );
        let resume = WalkResume {
            below: &[],
            equal: false,
        };
        let mut args = search_args(literal("needle"));
        args.globs = vec!["**/*.rs".to_string()];
        args.exclude_globs = vec!["vendor/**".to_string()];
        let walk = collect_search_candidates(&store, store.hash_kind(), root, &args, resume)
            .expect("walk collects");
        let mut paths: Vec<Vec<u8>> = walk.entries.iter().map(|(path, _)| path.clone()).collect();
        paths.sort();
        assert_eq!(paths, vec![b"src/a.rs".to_vec()]);
        let mut args = search_args(literal("needle"));
        args.paths = PathSelection::Paths(vec![RepoPath::new(b"src".to_vec()).expect("test path")]);
        let walk = collect_search_candidates(
            &store,
            store.hash_kind(),
            root,
            &args,
            WalkResume {
                below: &[],
                equal: false,
            },
        )
        .expect("walk collects");
        let mut paths: Vec<Vec<u8>> = walk.entries.iter().map(|(path, _)| path.clone()).collect();
        paths.sort();
        assert_eq!(paths, vec![b"src/a.rs".to_vec(), b"src/b.txt".to_vec()]);
    }

    #[test]
    fn shard_sizing_bounds_task_counts() {
        let entries = (0..200u32)
            .map(|index| {
                (
                    format!("f{index:04}").into_bytes(),
                    Oid::from_bytes(&[0; 20]).expect("test oid"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(shard_search_entries(entries).len(), 1);
        let entries = (0..100_000u32)
            .map(|index| {
                (
                    format!("f{index:06}").into_bytes(),
                    Oid::from_bytes(&[0; 20]).expect("test oid"),
                )
            })
            .collect::<Vec<_>>();
        let shards = shard_search_entries(entries);
        assert_eq!(shards.len(), 25);
        assert!(shards.iter().all(|shard| shard.len() <= 4096));
        let entries = (0..300_000u32)
            .map(|index| {
                (
                    format!("f{index:06}").into_bytes(),
                    Oid::from_bytes(&[0; 20]).expect("test oid"),
                )
            })
            .collect::<Vec<_>>();
        let shards = shard_search_entries(entries);
        assert_eq!(shards.len(), SEARCH_MAX_SHARDS);
        assert!(shards.iter().all(|shard| shard.len() <= 100_000));
        let flat: Vec<Vec<u8>> = shards
            .iter()
            .flat_map(|shard| shard.iter().map(|(path, _)| path.clone()))
            .collect();
        let mut sorted = flat.clone();
        sorted.sort();
        assert_eq!(flat, sorted);
    }

    #[test]
    fn fan_out_interleave_paginates_without_loss() {
        use crate::index::FileMode;
        use crate::protocol::{PageLimit, PageRequest, RevisionRef};
        use crate::workcopy::tree::TreeMode;
        let (_temp, store) = test_store("interleave");
        let shared = put_blob(&store, b"needle shared\n");
        let other = put_blob(&store, b"needle other\n");
        let root = put_tree(
            &store,
            &[
                ("a.txt", TreeMode::File(FileMode::Regular), shared),
                ("b.txt", TreeMode::File(FileMode::Regular), other),
                ("z.txt", TreeMode::File(FileMode::Regular), shared),
            ],
        );
        let head = commit_tree(&store, root, Vec::new());
        let at_revision = || SearchArgs {
            at: RevisionRef::Head { head },
            pattern: literal("needle"),
            case_insensitive: false,
            paths: PathSelection::All,
            globs: Vec::new(),
            exclude_globs: Vec::new(),
            budget: SearchBudget::default(),
            page: PageRequest::default(),
        };
        let mut single_args = at_revision();
        single_args.page.limit = PageLimit::try_from(100).ok();
        let single = search_content_local(&store, &single_args).expect("single page scans");
        assert!(!single.truncated);
        assert_eq!(single.hits.len(), 3);
        let mut walked = Vec::new();
        let mut cursor = None;
        for _ in 0..16 {
            let mut args = at_revision();
            args.page.limit = PageLimit::try_from(1).ok();
            if let Some(position) = cursor {
                args.page.cursor = Some(crate::protocol::PageCursor {
                    store: store.store_id(),
                    view: crate::change::OperationId(0),
                    query: crate::protocol::QueryDigest::from_bytes([0; 32]),
                    lease: crate::change::LeaseId::nil(),
                    position,
                });
            }
            let page = search_content_local(&store, &args).expect("page scans");
            walked.extend(page.hits.iter().cloned());
            cursor = page.next.clone();
            if cursor.is_none() {
                break;
            }
        }
        assert!(cursor.is_none());
        let walked_paths: Vec<Vec<u8>> = walked
            .iter()
            .map(|hit| hit.path.as_bytes().to_vec())
            .collect();
        let single_paths: Vec<Vec<u8>> = single
            .hits
            .iter()
            .map(|hit| hit.path.as_bytes().to_vec())
            .collect();
        assert_eq!(walked_paths, single_paths);
        assert_eq!(
            walked_paths,
            vec![b"a.txt".to_vec(), b"b.txt".to_vec(), b"z.txt".to_vec()]
        );
    }

    use crate::coord::{HostedCoordinator, Principal, cancellation};
    use crate::protocol::{
        PageLimit, PageRequest, Request, SEARCH_GLOB_MAX_BYTES, SEARCH_MAX_BYTES_SCANNED,
        SEARCH_MAX_DEADLINE_MS, SEARCH_MAX_GLOBS, SEARCH_PATTERN_MAX_BYTES,
    };

    fn hosted_search_args(
        head: crate::heads::Head,
        pattern: SearchPattern,
        limit: u32,
    ) -> SearchArgs {
        SearchArgs {
            at: crate::protocol::RevisionRef::Head { head },
            pattern,
            case_insensitive: false,
            paths: PathSelection::All,
            globs: Vec::new(),
            exclude_globs: Vec::new(),
            budget: SearchBudget::default(),
            page: PageRequest {
                limit: PageLimit::try_from(limit).ok(),
                cursor: None,
            },
        }
    }

    async fn search_fixture() -> (
        TempRoot,
        Arc<HostedCoordinator>,
        Principal,
        crate::change::SessionId,
        crate::heads::Head,
    ) {
        use crate::index::FileMode;
        use crate::workcopy::tree::TreeMode;
        let (temp, store) = test_store("hosted");
        let blob = |bytes: &[u8]| put_blob(&store, bytes);
        let first = blob(b"alpha needle one\n");
        let second = blob(b"beta needle two\nneedle again\n");
        let third = blob(b"gamma clean\n");
        let root = put_tree(
            &store,
            &[
                ("a.txt", TreeMode::File(FileMode::Regular), first),
                ("b.txt", TreeMode::File(FileMode::Regular), second),
                ("c.txt", TreeMode::File(FileMode::Regular), third),
            ],
        );
        let head = commit_tree(&store, root, Vec::new());
        let owner = Principal::from_peer_uid(1000);
        let coord = Arc::new(
            HostedCoordinator::open(Arc::clone(&store), owner.clone(), temp.0.clone())
                .expect("open coordinator"),
        );
        coord
            .spawn_on(&tokio::runtime::Handle::current())
            .expect("spawn lane");
        let (_guard, cancel) = cancellation();
        let (session, _) = coord
            .open_session(
                &owner,
                &crate::protocol::SessionOpenArgs::default(),
                &cancel,
            )
            .await
            .expect("open session");
        (temp, coord, owner, session, head)
    }

    async fn search_once(
        coord: &HostedCoordinator,
        owner: &Principal,
        session: crate::change::SessionId,
        args: SearchArgs,
    ) -> crate::protocol::SearchReply {
        let (_guard, cancel) = cancellation();
        let reply = coord
            .read(owner, session, Request::Search(Box::new(args)), &cancel)
            .await
            .expect("search serves");
        let crate::protocol::Reply::Search(reply) = reply else {
            panic!("search answers its own reply");
        };
        *reply
    }

    #[tokio::test]
    async fn read_walks_cursors_to_single_page() {
        let (_temp, coord, owner, session, head) = search_fixture().await;
        let single = search_once(
            &coord,
            &owner,
            session,
            hosted_search_args(head, literal("needle"), 100),
        )
        .await;
        assert!(!single.truncated);
        assert_eq!(single.hits.items.len(), 3);
        let mut walked = Vec::new();
        let mut cursor = None;
        for _ in 0..16 {
            let mut args = hosted_search_args(head, literal("needle"), 2);
            args.page.cursor = cursor;
            let page = search_once(&coord, &owner, session, args).await;
            walked.extend(page.hits.items.iter().cloned());
            cursor = page.hits.next.clone();
            assert_eq!(page.truncated, cursor.is_some());
            if cursor.is_none() {
                break;
            }
        }
        assert!(cursor.is_none());
        let single_paths: Vec<Vec<u8>> = single
            .hits
            .items
            .iter()
            .map(|hit| hit.path.as_bytes().to_vec())
            .collect();
        let walked_paths: Vec<Vec<u8>> = walked
            .iter()
            .map(|hit| hit.path.as_bytes().to_vec())
            .collect();
        assert_eq!(walked_paths, single_paths);
    }

    #[tokio::test]
    async fn read_refuses_workspace_revision() {
        let (_temp, coord, owner, session, _head) = search_fixture().await;
        let (_guard, cancel) = cancellation();
        let args = search_args(literal("needle"));
        let err = coord
            .read(&owner, session, Request::Search(Box::new(args)), &cancel)
            .await
            .expect_err("workspace refuses");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[tokio::test]
    async fn read_exhaustion_seals_and_resumes_to_cover() {
        let (_temp, coord, owner, session, head) = search_fixture().await;
        let mut args = hosted_search_args(head, literal("needle"), 100);
        args.budget.max_bytes_scanned = Some(1);
        let first = search_once(&coord, &owner, session, args.clone()).await;
        assert!(first.truncated);
        assert_eq!(first.exhausted, crate::protocol::ScanExhaustion::Budget);
        let mut hits = first.hits.items.clone();
        let mut cursor = first.hits.next.clone();
        for _ in 0..32 {
            let Some(resume) = cursor else { break };
            let mut next_args = hosted_search_args(head, literal("needle"), 100);
            next_args.budget.max_bytes_scanned = Some(1);
            next_args.page.cursor = Some(resume);
            let page = search_once(&coord, &owner, session, next_args).await;
            hits.extend(page.hits.items.iter().cloned());
            cursor = page.hits.next.clone();
        }
        assert!(cursor.is_none());
        let single = search_once(
            &coord,
            &owner,
            session,
            hosted_search_args(head, literal("needle"), 100),
        )
        .await;
        let mut hits_paths: Vec<Vec<u8>> = hits
            .iter()
            .map(|hit| hit.path.as_bytes().to_vec())
            .collect();
        hits_paths.sort();
        let mut single_paths: Vec<Vec<u8>> = single
            .hits
            .items
            .iter()
            .map(|hit| hit.path.as_bytes().to_vec())
            .collect();
        single_paths.sort();
        assert_eq!(hits_paths, single_paths);
    }

    #[tokio::test]
    async fn read_rejects_mismatched_query() {
        let (_temp, coord, owner, session, head) = search_fixture().await;
        let first = search_once(
            &coord,
            &owner,
            session,
            hosted_search_args(head, literal("needle"), 1),
        )
        .await;
        let cursor = first.hits.next.clone().expect("limit seals");
        let mut args = hosted_search_args(head, literal("other"), 1);
        args.page.cursor = Some(cursor);
        let (_guard, cancel) = cancellation();
        let err = coord
            .read(&owner, session, Request::Search(Box::new(args)), &cancel)
            .await
            .expect_err("mismatched query refuses");
        assert_eq!(err.code, ErrorCode::EForbidden);
    }

    #[tokio::test]
    async fn read_refuses_stale_view() {
        use crate::protocol::TagSetArgs;
        use crate::refdata::{RefExpect, RefName};
        let (_temp, coord, owner, session, head) = search_fixture().await;
        let first = search_once(
            &coord,
            &owner,
            session,
            hosted_search_args(head, literal("needle"), 1),
        )
        .await;
        let cursor = first.hits.next.clone().expect("limit seals");
        let prepared = crate::coord::prepare_mutation(
            coord.store(),
            session,
            Request::TagSet(Box::new(crate::protocol::Mutation {
                request_id: crate::change::RequestId::generate(),
                args: TagSetArgs {
                    name: RefName::new("refs/tags/s1").expect("tag name"),
                    target: crate::ids::Oid::from_bytes(&[0x11; 20]).expect("tag target"),
                    annotation: None,
                    expected: RefExpect::Absent,
                },
            })),
        )
        .expect("tag prepares");
        let (_guard, cancel) = cancellation();
        coord
            .submit_prepared(&owner, prepared, &cancel)
            .await
            .expect("tag publishes");
        let mut args = hosted_search_args(head, literal("needle"), 1);
        args.page.cursor = Some(cursor);
        let err = coord
            .read(&owner, session, Request::Search(Box::new(args)), &cancel)
            .await
            .expect_err("stale view refuses");
        assert_eq!(err.code, ErrorCode::EForbidden);
    }

    #[tokio::test]
    async fn concurrent_pooled_reads_agree() {
        let (_temp, coord, owner, session, head) = search_fixture().await;
        let mut handles = Vec::new();
        for _ in 0..20 {
            let coord = Arc::clone(&coord);
            let owner = owner.clone();
            let args = hosted_search_args(head, literal("needle"), 100);
            handles.push(tokio::spawn(async move {
                search_once(&coord, &owner, session, args).await
            }));
        }
        let mut first: Option<(Vec<crate::protocol::SearchHit>, u64, u64, u64)> = None;
        for handle in handles {
            let page = handle.await.expect("read joins");
            let key = (
                page.hits.items.clone(),
                page.scanned_blobs,
                page.scanned_bytes,
                page.skipped_blobs,
            );
            if let Some(expected) = &first {
                assert_eq!(&key, expected);
            } else {
                first = Some(key);
            }
        }
    }

    #[tokio::test]
    async fn pool_permits_bound_concurrent_scans() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        let pool = Arc::new(
            SearchPool::new(SearchPoolConfig { permits: 2 }).expect("bounded pool builds"),
        );
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let pool = Arc::clone(&pool);
            let live = Arc::clone(&live);
            let peak = Arc::clone(&peak);
            handles.push(tokio::spawn(async move {
                let _permit = pool.acquire_owned().await.expect("pool opens");
                let held = live.fetch_add(1, AtomicOrdering::SeqCst).saturating_add(1);
                peak.fetch_max(held, AtomicOrdering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                live.fetch_sub(1, AtomicOrdering::SeqCst);
            }));
        }
        for handle in handles {
            handle.await.expect("scan joins");
        }
        assert!(peak.load(AtomicOrdering::SeqCst) <= 2);
    }
}
