//! Native-store state for the interpreter: workspace row, index rows,
//! config records, sequencer records, stash slots, and ref transactions.
//!
//! HEAD is a workspace field, never a `Refs` entry: the CLI workspace row
//! holds a [`GitCompatWorkspace`] whose [`HeadRef`] resolves through the ref
//! namespace on demand (`refdata` documents `HEAD` out of that namespace).
//! The row lives in `FactTable::Workspaces` under a CLI-namespaced key so it
//! can never collide with the coordinator's 16-byte workspace keys; every
//! replacement carries the read bytes as its CAS expectation, mirroring
//! `coord/workspace.rs:observe`/`replace` without the coordinator's lease
//! holder, which has no meaning for a single-invocation CLI.
//!
//! Index rows live in `FactTable::WsIndex` under `cli/index/row/` with the
//! stage as the final key byte; the workspace row's `index_generation`
//! advances in the one transaction that writes the rows, as
//! `GitCompatWorkspace::mutate_index` requires. Config, sequencer, and stash
//! records live in `FactTable::Pins`, the table with no typed readers, under
//! `cli/` prefixes.

use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};

use ruk_core::commit::CommitRecord;
use ruk_core::conflict::{Signature, TzOffset};
use ruk_core::error::CoreError;
use ruk_core::heads::Head;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::index::{
    FileMode, IndexEntry, PathEntries, RepoPath, Stage, StatData, StatTime, row_delta,
};
use ruk_core::records::Records;
use ruk_core::refdata::{
    RefChange, RefExpect, RefName, RefRead, RefTarget, RefTransaction, RefUpdate, resolve,
};
use ruk_core::refs::{StoreRefs, page_refs, prepare_checked_transaction};
use ruk_core::store::{
    FactExpectation, FactMutation, FactPageBudget, FactTable, ObjectKind, Store,
};
pub(crate) use ruk_core::workspace::ResolvedHead;
use ruk_core::workspace::{GitCompatWorkspace, HeadRef, Scope};
use ruk_git::GitError;
use serde::{Deserialize, Serialize};

use super::Ctx;
use std::path::PathBuf;

/// Workspace-row key: CLI-owned, disjoint from coordinator 16-byte keys.
const WORKSPACE_KEY: &[u8] = b"cli/workspaces/git-compat";
/// Index-row prefix; the stage number is the final key byte.
const INDEX_ROW_PREFIX: &[u8] = b"cli/index/row/";
/// Config-record prefix; the full `section[.sub.]key` name follows.
const CONFIG_PREFIX: &[u8] = b"cli/config/";
/// Sequencer-record prefix; the verb name follows.
const SEQUENCER_PREFIX: &[u8] = b"cli/sequencer/";
/// Stash-slot prefix; the decimal slot number follows.
const STASH_PREFIX: &[u8] = b"cli/stash/";
/// Stash-slot counter key.
const STASH_NEXT_KEY: &[u8] = b"cli/stash-next";
/// Monotonic counter backing reflog operation ids.
const REFLOG_NEXT_KEY: &[u8] = b"cli/reflog-next";
/// Default branch created by `init`.
pub(crate) const DEFAULT_BRANCH: &str = "refs/heads/main";
/// Largest object body buffered for inspection verbs.
pub(crate) const MAX_OBJECT_BYTES: u64 = 512 << 20;

/// In-progress multi-step operation, one record per verb name.
///
/// The merge lane writes one when content resolution stops at conflicts;
/// `--continue` resumes it, `--abort` reverts it, `--quit` drops it, and the
/// `--abort`/`--quit`/`--continue` spellings without state report the absence
/// the way Git does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SequencerState {
    /// Verb that owns the state (`merge`, `rebase`, `cherry-pick`, `revert`).
    pub(crate) verb: String,
    /// `HEAD` when the operation started, as hex.
    pub(crate) head_hex: String,
    /// Tip the operation is working toward, as hex.
    pub(crate) target_hex: String,
    /// Human reason recorded at creation.
    pub(crate) message: String,
}

/// One stash slot: the stashed index plus the commit that holds its tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StashSlot {
    /// Stash commit message.
    pub(crate) message: String,
    /// `HEAD` oid hex when stashed.
    pub(crate) base_hex: String,
    /// Stash commit oid hex.
    pub(crate) commit_hex: String,
    /// `(path bytes, stage, entry)` rows captured from the index.
    pub(crate) rows: Vec<(Vec<u8>, Stage, IndexEntry)>,
}

/// Which identity a signature is for. A named type, never a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityRole {
    /// `GIT_AUTHOR_*`, the `author` header.
    Author,
    /// `GIT_COMMITTER_*`, the `committer` header.
    Committer,
}

/// Loads the CLI workspace row with its raw bytes for CAS.
pub(crate) fn load_workspace(
    store: &Store,
) -> Result<Option<(GitCompatWorkspace, Vec<u8>)>, GitError> {
    let raw = store.fact(FactTable::Workspaces, WORKSPACE_KEY)?;
    raw.map(|bytes| {
        let workspace: GitCompatWorkspace =
            sonic_rs::from_slice(&bytes).map_err(|err| GitError::Corrupt {
                detail: format!("cli workspace row does not decode: {err}"),
            })?;
        Ok((workspace, bytes))
    })
    .transpose()
}

/// Loads the workspace row or the fresh default, for verbs that accept an
/// untouched repository the way Git accepts an unborn `HEAD`.
pub(crate) fn load_or_default(
    store: &Store,
) -> Result<(GitCompatWorkspace, Option<Vec<u8>>), GitError> {
    match load_workspace(store)? {
        Some((workspace, raw)) => Ok((workspace, Some(raw))),
        None => {
            let name = RefName::new(DEFAULT_BRANCH).map_err(to_core_invalid)?;
            Ok((
                GitCompatWorkspace::new(HeadRef::Symbolic(name), Scope::Full),
                None,
            ))
        }
    }
}

/// Builds the workspace-row mutation for `next`, CAS-fenced on `expected`.
pub(crate) fn workspace_mutation(
    expected: Option<&[u8]>,
    next: &GitCompatWorkspace,
) -> Result<FactMutation, GitError> {
    let value = sonic_rs::to_vec(next).map_err(|err| GitError::Io {
        detail: format!("workspace row encode: {err}"),
    })?;
    Ok(FactMutation {
        table: FactTable::Workspaces,
        key: WORKSPACE_KEY.to_vec(),
        expected: expected.map_or(FactExpectation::Absent, |raw| {
            FactExpectation::Value(raw.to_vec())
        }),
        value: Some(value),
    })
}

/// Maps a model validation failure into the interpreter error space.
fn to_core_invalid(err: ruk_core::error::CoreModelError) -> GitError {
    GitError::from(CoreError::from(err))
}

/// Index-row key for `path` at `stage`.
fn index_key(path: &RepoPath, stage: Stage) -> Vec<u8> {
    let mut key = Vec::with_capacity(INDEX_ROW_PREFIX.len() + path.as_bytes().len() + 2);
    key.extend_from_slice(INDEX_ROW_PREFIX);
    key.extend_from_slice(path.as_bytes());
    key.push(0);
    key.push(stage.as_u8());
    key
}

/// Reads every stored stage row for `path`, with each row's raw bytes.
pub(crate) fn read_path_rows(
    store: &Store,
    kind: HashKind,
    path: &RepoPath,
) -> Result<Vec<(Stage, IndexEntry, Vec<u8>)>, GitError> {
    let mut out = Vec::new();
    for stage in Stage::ALL {
        let key = index_key(path, stage);
        let Some(raw) = store.fact(FactTable::WsIndex, &key)? else {
            continue;
        };
        let entry: IndexEntry = sonic_rs::from_slice(&raw).map_err(|err| GitError::Corrupt {
            detail: format!("index row for {} does not decode: {err}", path_shown(path)),
        })?;
        entry.validate(kind).map_err(to_core_invalid)?;
        out.push((stage, entry, raw));
    }
    Ok(out)
}

/// Builds index-row mutations moving `path` from `before` to `after`.
pub(crate) fn path_row_mutations(
    path: &RepoPath,
    before: &[(Stage, IndexEntry, Vec<u8>)],
    after: &[(Stage, IndexEntry)],
) -> Result<Vec<FactMutation>, GitError> {
    let before_pairs: Vec<(Stage, IndexEntry)> = before
        .iter()
        .map(|(stage, entry, _)| (*stage, entry.clone()))
        .collect();
    let before_entries = if before_pairs.is_empty() {
        None
    } else {
        Some(PathEntries::from_rows(before_pairs).map_err(to_core_invalid)?)
    };
    let after_entries = if after.is_empty() {
        None
    } else {
        let pairs: Vec<(Stage, IndexEntry)> = after.to_vec();
        Some(PathEntries::from_rows(pairs).map_err(to_core_invalid)?)
    };
    let delta = row_delta(before_entries.as_ref(), after_entries.as_ref());
    let mut mutations = Vec::new();
    for stage in delta.delete {
        let key = index_key(path, stage);
        let raw = before
            .iter()
            .find(|(known, _, _)| *known == stage)
            .map(|(_, _, raw)| raw.clone())
            .unwrap_or_default();
        mutations.push(FactMutation {
            table: FactTable::WsIndex,
            key,
            expected: FactExpectation::Value(raw),
            value: None,
        });
    }
    for (stage, entry) in delta.put {
        let key = index_key(path, stage);
        let value = sonic_rs::to_vec(entry).map_err(|err| GitError::Io {
            detail: format!("index row encode: {err}"),
        })?;
        mutations.push(FactMutation {
            table: FactTable::WsIndex,
            key,
            expected: FactExpectation::Any,
            value: Some(value),
        });
    }
    Ok(mutations)
}

/// Index write-stamp key: wall-clock seconds of the last index-row mutation,
/// written in the same publication as the rows (git's `.git/index` mtime).
/// Dirty scans trust a matching stat tuple only when the file's mtime
/// predates this stamp; an equal-or-newer mtime rehashes (racy-clean).
const INDEX_STAMP_KEY: &[u8] = b"cli/index/stamp";

/// Builds the index write-stamp mutation for the current wall time. Callers
/// push exactly one per index publication, next to the workspace mutation:
/// one publication carries one stamp key, and duplicate keys are rejected.
///
/// Required for every publication that writes rows carrying worktree stat
/// (`add`, dirty-scan refreshes, post-write backfills): the stamp is the
/// racy-clean floor those rows are trusted against. Publications of
/// stat-less rows (checkouts and resets from trees, `--cacheinfo`) need no
/// stamp since their rows always rehash; row-less publications must not
/// stamp since that would only retire live cache entries early.
pub(crate) fn index_stamp_mutation() -> Result<FactMutation, GitError> {
    let value = sonic_rs::to_vec(&now_seconds()?).map_err(|err| GitError::Io {
        detail: format!("index stamp encode: {err}"),
    })?;
    Ok(FactMutation {
        table: FactTable::WsIndex,
        key: INDEX_STAMP_KEY.to_vec(),
        expected: FactExpectation::Any,
        value: Some(value),
    })
}

/// Reads the index write stamp: `None` for pre-upgrade stores or unreadable
/// rows, where every dirty scan rehashes until the next index write stamps.
pub(crate) fn read_index_stamp(store: &Store) -> Option<i64> {
    let raw = store.fact(FactTable::WsIndex, INDEX_STAMP_KEY).ok()??;
    sonic_rs::from_slice::<i64>(&raw).ok()
}

/// Captures a worktree path's lstat tuple without following symlinks, the
/// way git stats the link itself. Device, inode, and owner stay zero off
/// Unix; there the modification time stands in for a missing creation time,
/// mirroring the workcopy stat cache.
///
/// # Errors
/// [`GitError::Io`] when a filesystem timestamp does not fit the stat tuple.
pub(crate) fn stat_from_meta(meta: &std::fs::Metadata) -> Result<StatData, GitError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let nanos = |value: i64, what: &str| {
            u32::try_from(value).map_err(|_| GitError::Io {
                detail: format!("filesystem reported a bad {what} time"),
            })
        };
        Ok(StatData {
            ctime: StatTime {
                secs: meta.ctime(),
                nanos: nanos(meta.ctime_nsec(), "creation")?,
            },
            mtime: StatTime {
                secs: meta.mtime(),
                nanos: nanos(meta.mtime_nsec(), "modification")?,
            },
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            size: meta.len(),
        })
    }
    #[cfg(not(unix))]
    {
        let convert = |time: std::time::SystemTime| -> Result<StatTime, GitError> {
            let out_of_range = || GitError::Io {
                detail: "filesystem reported a bad timestamp".to_owned(),
            };
            match time.duration_since(std::time::UNIX_EPOCH) {
                Ok(after) => Ok(StatTime {
                    secs: i64::try_from(after.as_secs()).map_err(|_| out_of_range())?,
                    nanos: after.subsec_nanos(),
                }),
                Err(before) => {
                    let back = before.duration();
                    let secs = i64::try_from(back.as_secs()).map_err(|_| out_of_range())?;
                    if back.subsec_nanos() == 0 {
                        return Ok(StatTime {
                            secs: -secs,
                            nanos: 0,
                        });
                    }
                    Ok(StatTime {
                        secs: -secs - 1,
                        nanos: 1_000_000_000 - back.subsec_nanos(),
                    })
                }
            }
        };
        let mtime = meta
            .modified()
            .map_err(|err| GitError::Io {
                detail: format!("reading a modification time: {err}"),
            })
            .and_then(convert)?;
        let ctime = meta
            .created()
            .ok()
            .map(convert)
            .transpose()?
            .unwrap_or(mtime);
        Ok(StatData {
            ctime,
            mtime,
            dev: 0,
            ino: 0,
            uid: 0,
            gid: 0,
            size: meta.len(),
        })
    }
}

/// What the stat cache says about one worktree file. A named type, never a flag.
pub(crate) enum StatTrust {
    /// The cached stat proves the bytes unchanged: skip the content read.
    Clean,
    /// Hash the bytes and compare, exactly as without the cache.
    Rehash,
}

/// Applies the trust rule to an index row and a fresh lstat tuple: clean
/// only when the row names real worktree state (no intent, assume-unchanged,
/// or skip-worktree flags, no gitlink), the mode matches, the full tuple is
/// unchanged, and the file's mtime predates the index write stamp. An
/// equal-or-newer mtime rehashes: a same-second edit could otherwise keep
/// the tuple unchanged (racy-clean). Missing stats or stamps always rehash.
pub(crate) fn trust_index_entry(
    entry: &IndexEntry,
    fresh: &StatData,
    mode: FileMode,
    stamp_secs: Option<i64>,
) -> StatTrust {
    let flags = entry.flags();
    if flags.intent_to_add || flags.assume_unchanged || flags.skip_worktree {
        return StatTrust::Rehash;
    }
    if entry.mode() == FileMode::Gitlink || mode != entry.mode() {
        return StatTrust::Rehash;
    }
    if entry.stat() != Some(*fresh) {
        return StatTrust::Rehash;
    }
    match stamp_secs {
        Some(stamp) if fresh.mtime.secs < stamp => StatTrust::Clean,
        _ => StatTrust::Rehash,
    }
}

/// Re-reads lstat data for freshly-written worktree paths into their
/// stage-zero rows, so the next dirty scan trusts them. A row is refreshed
/// only after its current bytes are read back and match the row's blob:
/// an edit between the write and the lstat then fails the comparison and
/// leaves the row stale instead of validating foreign bytes. Paths without
/// a stage-zero row, with an unchanged tuple, or that fail to stat or
/// verify keep their rows untouched; unmerged and gitlink rows are never
/// rewritten.
pub(crate) fn refresh_stats_after_write(
    ctx: &Ctx,
    store: &Store,
    kind: HashKind,
    paths: &[Vec<u8>],
) -> Result<(), GitError> {
    let (workspace, raw) = load_or_default(store)?;
    let mut mutations = Vec::new();
    for path_bytes in paths {
        let Ok(path) = RepoPath::new(path_bytes.clone()) else {
            continue;
        };
        let Ok(full) = super::tree::join_base(&ctx.file_base, path_bytes) else {
            continue;
        };
        let Ok(meta) = std::fs::symlink_metadata(&full) else {
            continue;
        };
        let Ok(fresh) = stat_from_meta(&meta) else {
            continue;
        };
        let before = read_path_rows(store, kind, &path)?;
        if before.iter().any(|(stage, _, _)| *stage != Stage::Zero) {
            continue;
        }
        let Some((_, entry, _)) = before.iter().find(|(stage, _, _)| *stage == Stage::Zero) else {
            continue;
        };
        if entry.mode() == FileMode::Gitlink || entry.stat() == Some(fresh) {
            continue;
        }
        let current = if entry.mode() == FileMode::Symlink {
            std::fs::read_link(&full)
                .map(|target| target.as_os_str().as_encoded_bytes().to_vec())
                .ok()
        } else {
            std::fs::read(&full).ok()
        };
        let Some(current) = current else {
            continue;
        };
        let (_, want) = super::tree::read_object_bytes(store, entry.oid())?;
        if current != want {
            continue;
        }
        let next = IndexEntry::new(entry.oid(), entry.mode(), Some(fresh), entry.flags())
            .map_err(to_core_invalid)?;
        mutations.extend(path_row_mutations(&path, &before, &[(Stage::Zero, next)])?);
    }
    if mutations.is_empty() {
        return Ok(());
    }
    let next = workspace
        .mutate_index(workspace.stamp)
        .map_err(GitError::from)?;
    mutations.push(workspace_mutation(raw.as_deref(), &next)?);
    mutations.push(index_stamp_mutation()?);
    store
        .publish(Vec::new(), &mutations)
        .map_err(GitError::from)?;
    Ok(())
}

/// Scans every CLI index row in key order.
pub(crate) fn scan_index(
    store: &Store,
    kind: HashKind,
) -> Result<Vec<(RepoPath, Stage, IndexEntry)>, GitError> {
    let mut out = Vec::new();
    let mut after: Option<Vec<u8>> = Some(INDEX_ROW_PREFIX.to_vec());
    loop {
        let page = store.fact_page(
            FactTable::WsIndex,
            after.as_deref(),
            FactPageBudget::new(1024, 1 << 20),
        )?;
        if page.rows.is_empty() {
            return Ok(out);
        }
        for row in &page.rows {
            if !row.key.starts_with(INDEX_ROW_PREFIX) {
                return Ok(out);
            }
            let Some((path, stage)) = decode_index_key(&row.key) else {
                continue;
            };
            let entry: IndexEntry =
                sonic_rs::from_slice(&row.value).map_err(|err| GitError::Corrupt {
                    detail: format!("index row for {} does not decode: {err}", path_shown(&path)),
                })?;
            entry.validate(kind).map_err(to_core_invalid)?;
            out.push((path, stage, entry));
        }
        if !page.more {
            return Ok(out);
        }
        after = page.rows.last().map(|row| row.key.clone());
    }
}

/// Splits an index-row key back into its path and stage.
fn decode_index_key(key: &[u8]) -> Option<(RepoPath, Stage)> {
    let tail = key.strip_prefix(INDEX_ROW_PREFIX)?;
    let (path_bytes, suffix) = tail.split_at_checked(tail.len().checked_sub(2)?)?;
    if suffix.first() != Some(&0) {
        return None;
    }
    let stage = Stage::from_u8(*suffix.last()?).ok()?;
    let path = RepoPath::new(path_bytes.to_vec()).ok()?;
    Some((path, stage))
}

/// Renders untrusted path bytes for diagnostics, escaped and bounded.
fn path_shown(path: &RepoPath) -> String {
    let bytes = path.as_bytes();
    let shown = &bytes[..bytes.len().min(128)];
    let mut text = shown.escape_ascii().to_string();
    if bytes.len() > 128 {
        text.push_str("...");
    }
    text
}

/// Reads one config value.
pub(crate) fn config_read(store: &Store, name: &str) -> Result<Option<String>, GitError> {
    let mut key = CONFIG_PREFIX.to_vec();
    key.extend_from_slice(name.as_bytes());
    let raw = store.fact(FactTable::Pins, &key)?;
    Ok(raw.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
}

/// Writes one config value, CAS-fenced on the current bytes.
pub(crate) fn config_write(store: &Store, name: &str, value: &str) -> Result<(), GitError> {
    let mut key = CONFIG_PREFIX.to_vec();
    key.extend_from_slice(name.as_bytes());
    let expected = store
        .fact(FactTable::Pins, &key)?
        .map_or(FactExpectation::Absent, FactExpectation::Value);
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key,
                expected,
                value: Some(value.as_bytes().to_vec()),
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Deletes one config value, refusing when absent.
pub(crate) fn config_unset(store: &Store, name: &str) -> Result<(), GitError> {
    let mut key = CONFIG_PREFIX.to_vec();
    key.extend_from_slice(name.as_bytes());
    let Some(raw) = store.fact(FactTable::Pins, &key)? else {
        return Err(GitError::NotFound {
            detail: format!("config {name} is not set"),
        });
    };
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key,
                expected: FactExpectation::Value(raw),
                value: None,
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Lists every stored config pair in key order.
pub(crate) fn config_list(store: &Store) -> Result<Vec<(String, String)>, GitError> {
    let mut out = Vec::new();
    let mut after: Option<Vec<u8>> = Some(CONFIG_PREFIX.to_vec());
    loop {
        let page = store.fact_page(
            FactTable::Pins,
            after.as_deref(),
            FactPageBudget::new(1024, 1 << 20),
        )?;
        if page.rows.is_empty() {
            return Ok(out);
        }
        for row in &page.rows {
            if !row.key.starts_with(CONFIG_PREFIX) {
                return Ok(out);
            }
            let name = String::from_utf8_lossy(&row.key[CONFIG_PREFIX.len()..]).into_owned();
            let value = String::from_utf8_lossy(&row.value).into_owned();
            out.push((name, value));
        }
        if !page.more {
            return Ok(out);
        }
        after = page.rows.last().map(|row| row.key.clone());
    }
}

/// Reads one sequencer record.
pub(crate) fn sequencer_read(
    store: &Store,
    verb: &str,
) -> Result<Option<SequencerState>, GitError> {
    let mut key = SEQUENCER_PREFIX.to_vec();
    key.extend_from_slice(verb.as_bytes());
    let raw = store.fact(FactTable::Pins, &key)?;
    raw.map(|bytes| {
        sonic_rs::from_slice(&bytes).map_err(|err| GitError::Corrupt {
            detail: format!("sequencer record for {verb} does not decode: {err}"),
        })
    })
    .transpose()
}

/// Writes one sequencer record, replacing any record the verb left behind.
pub(crate) fn sequencer_write(
    store: &Store,
    verb: &str,
    state: &SequencerState,
) -> Result<(), GitError> {
    let mut key = SEQUENCER_PREFIX.to_vec();
    key.extend_from_slice(verb.as_bytes());
    let value = sonic_rs::to_vec(state).map_err(|err| GitError::Io {
        detail: format!("sequencer record encode: {err}"),
    })?;
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key,
                expected: FactExpectation::Any,
                value: Some(value),
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Deletes one sequencer record, tolerating an already-absent row.
pub(crate) fn sequencer_delete(store: &Store, verb: &str) -> Result<(), GitError> {
    let mut key = SEQUENCER_PREFIX.to_vec();
    key.extend_from_slice(verb.as_bytes());
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key,
                expected: FactExpectation::Any,
                value: None,
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Pseudo-head key: `MERGE_HEAD`, `ORIG_HEAD`, `CHERRY_PICK_HEAD`,
/// `REVERT_HEAD`, `MERGE_MSG`, and per-verb todo lists all live under
/// `cli/pseudo/`, the same table as `FETCH_HEAD`.
fn pseudo_key(name: &str) -> Vec<u8> {
    let mut key = b"cli/pseudo/".to_vec();
    key.extend_from_slice(name.as_bytes());
    key
}

/// Reads one pseudo-head record as raw bytes.
pub(crate) fn pseudo_read(store: &Store, name: &str) -> Result<Option<Vec<u8>>, GitError> {
    store
        .fact(FactTable::Pins, &pseudo_key(name))
        .map_err(GitError::from)
}

/// Writes one pseudo-head record, replacing any previous value.
pub(crate) fn pseudo_write(store: &Store, name: &str, value: Vec<u8>) -> Result<(), GitError> {
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key: pseudo_key(name),
                expected: FactExpectation::Any,
                value: Some(value),
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Deletes one pseudo-head record, tolerating an already-absent row.
pub(crate) fn pseudo_delete(store: &Store, name: &str) -> Result<(), GitError> {
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key: pseudo_key(name),
                expected: FactExpectation::Any,
                value: None,
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Reads one pseudo-head record as an object id.
pub(crate) fn pseudo_read_oid(store: &Store, name: &str) -> Result<Option<Oid>, GitError> {
    let Some(raw) = pseudo_read(store, name)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&raw).map_err(|_| GitError::Corrupt {
        detail: format!("{name} is not valid UTF-8"),
    })?;
    Oid::from_hex(text.trim()).map_or_else(
        |_| {
            Err(GitError::Corrupt {
                detail: format!("{name} does not hold an object id"),
            })
        },
        |oid| Ok(Some(oid)),
    )
}

/// Reads one stash slot by number.
pub(crate) fn stash_read(store: &Store, slot: u64) -> Result<Option<StashSlot>, GitError> {
    let key = stash_key(slot);
    let raw = store.fact(FactTable::Pins, &key)?;
    raw.map(|bytes| {
        sonic_rs::from_slice(&bytes).map_err(|err| GitError::Corrupt {
            detail: format!("stash slot {slot} does not decode: {err}"),
        })
    })
    .transpose()
}

/// Writes one stash slot.
pub(crate) fn stash_write(store: &Store, slot: u64, entry: &StashSlot) -> Result<(), GitError> {
    let key = stash_key(slot);
    let value = sonic_rs::to_vec(entry).map_err(|err| GitError::Io {
        detail: format!("stash slot encode: {err}"),
    })?;
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key,
                expected: FactExpectation::Any,
                value: Some(value),
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Deletes one stash slot, refusing when absent.
pub(crate) fn stash_drop(store: &Store, slot: u64) -> Result<(), GitError> {
    let key = stash_key(slot);
    let Some(raw) = store.fact(FactTable::Pins, &key)? else {
        return Err(GitError::NotFound {
            detail: format!("stash slot {slot} does not exist"),
        });
    };
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key,
                expected: FactExpectation::Value(raw),
                value: None,
            }],
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Stash-slot key for `slot`.
fn stash_key(slot: u64) -> Vec<u8> {
    let mut key = STASH_PREFIX.to_vec();
    key.extend_from_slice(slot.to_string().as_bytes());
    key
}

/// Allocates the next stash slot number.
pub(crate) fn stash_alloc(store: &Store) -> Result<u64, GitError> {
    counter_alloc(store, STASH_NEXT_KEY)
}

/// Reads the stash high-water mark: slots below it may live.
pub(crate) fn stash_high_water(store: &Store) -> Result<u64, GitError> {
    let raw = store.fact(FactTable::Pins, STASH_NEXT_KEY)?;
    raw.as_deref().map_or(Ok(0), |bytes| {
        bytes
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| GitError::Corrupt {
                detail: "stash counter does not decode".to_owned(),
            })
    })
}

/// Allocates the next reflog operation id.
pub(crate) fn reflog_alloc(store: &Store) -> Result<u64, GitError> {
    counter_alloc(store, REFLOG_NEXT_KEY)
}

/// Atomically bumps a little-endian `u64` counter, returning the prior value.
fn counter_alloc(store: &Store, key: &[u8]) -> Result<u64, GitError> {
    let raw = store.fact(FactTable::Pins, key)?;
    let current = raw.as_deref().map_or(Ok(0), |bytes| {
        bytes
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| GitError::Corrupt {
                detail: "counter row does not decode".to_owned(),
            })
    })?;
    let next = current.checked_add(1).ok_or_else(|| GitError::Capacity {
        detail: "counter exhausted".to_owned(),
    })?;
    let expected = raw.map_or(FactExpectation::Absent, FactExpectation::Value);
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key: key.to_vec(),
                expected,
                value: Some(next.to_le_bytes().to_vec()),
            }],
        )
        .map_err(GitError::from)?;
    Ok(current)
}

/// One applied ref change with its before and after targets for reflog and
/// report callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AppliedRef {
    /// The ref that moved.
    pub(crate) name: RefName,
    /// Target before publication, when the ref existed.
    pub(crate) before: Option<RefTarget>,
    /// Target after publication, when the ref exists now.
    pub(crate) after: Option<RefTarget>,
}

/// Prepares and publishes one ref transaction, returning each change with
/// its before and after targets.
pub(crate) fn apply_refs(
    store: &Store,
    kind: HashKind,
    updates: Vec<RefUpdate>,
) -> Result<Vec<AppliedRef>, GitError> {
    let reader = StoreRefs::new(store);
    let mut before_targets = Vec::with_capacity(updates.len());
    for update in &updates {
        before_targets.push(reader.get(&update.name).map_err(ref_to_git)?);
    }
    let transaction =
        RefTransaction::new(kind, updates).map_err(|err| GitError::from(CoreError::from(err)))?;
    let prepared = prepare_checked_transaction(store, &transaction)?;
    let updates_back: Vec<RefUpdate> = prepared
        .updates()
        .iter()
        .map(|prepared| prepared.update.clone())
        .collect();
    store
        .publish(Vec::new(), &prepared.into_mutations())
        .map_err(GitError::from)?;
    Ok(updates_back
        .into_iter()
        .zip(before_targets)
        .map(|(update, before)| {
            let after = match update.change {
                RefChange::Set(target) => Some(target),
                RefChange::Delete => None,
            };
            AppliedRef {
                name: update.name,
                before,
                after,
            }
        })
        .collect())
}

/// Reads one ref target without resolving it.
pub(crate) fn read_ref(store: &Store, name: &RefName) -> Result<Option<RefTarget>, GitError> {
    StoreRefs::new(store).get(name).map_err(ref_to_git)
}

/// Resolves `HEAD` through the ref namespace on demand.
pub(crate) fn resolve_head(store: &Store, head: &HeadRef) -> Result<ResolvedHead, GitError> {
    head.resolve(&StoreRefs::new(store)).map_err(ref_to_git)
}

/// Resolves a branch name to its full ref name.
pub(crate) fn branch_name(name: &str) -> Result<RefName, GitError> {
    RefName::new(format!("refs/heads/{name}")).map_err(to_core_invalid)
}

/// Resolves a branch start point, defaulting to `HEAD`.
pub(crate) fn resolve_branch_target(
    store: &Store,
    kind: HashKind,
    start: Option<&str>,
) -> Result<Oid, GitError> {
    match start {
        Some(rev) => resolve_rev(store, kind, rev),
        None => head_oid(store),
    }
}

/// Creates a branch ref the way `branch` does, for `checkout -b` reuse.
pub(crate) fn create_branch(
    store: &Store,
    kind: HashKind,
    name: &str,
    target: Oid,
) -> Result<(), GitError> {
    let refname = branch_name(name)?;
    apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: refname,
            expected: RefExpect::Absent,
            change: RefChange::Set(RefTarget::Direct(target)),
        }],
    )?;
    Ok(())
}

/// Lists every ref in name order.
pub(crate) fn list_refs(store: &Store) -> Result<Vec<(RefName, RefTarget)>, GitError> {
    let mut out = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let page = page_refs(store, after.as_deref(), 1000).map_err(GitError::from)?;
        for entry in &page.entries {
            out.push((entry.name.clone(), entry.target.clone()));
        }
        if !page.more {
            return Ok(out);
        }
        after = out.last().map(|(name, _)| name.as_bytes().to_vec());
        if after.is_none() {
            return Ok(out);
        }
    }
}

/// Maps a ref-layer failure into the interpreter error space.
fn ref_to_git(err: impl Into<CoreError>) -> GitError {
    GitError::from(err.into())
}

/// Resolves user revision syntax to one object id.
///
/// Accepts full ref names, `HEAD`, short branch names, raw hex, `<rev>~<n>`,
/// `<rev>^<n>`, and one trailing `^{<type>}` / `^{}` peel; anything else
/// fails the way `rev-parse --verify` fails. Never consults
/// `refs/replace/*`: replacement-aware verbs redirect explicitly, and the
/// `replace` verb itself resolves through [`resolve_rev_raw`].
pub(crate) fn resolve_rev(store: &Store, kind: HashKind, rev: &str) -> Result<Oid, GitError> {
    resolve_rev_raw(store, kind, rev)
}

/// Resolves user revision syntax without replace redirection, for the
/// `replace` verb (which names stored objects) and the `notes` verb (which
/// annotates stored objects, not their replacements).
pub(crate) fn resolve_rev_raw(store: &Store, kind: HashKind, rev: &str) -> Result<Oid, GitError> {
    let (inner, peel) = split_peel_suffix(rev);
    let (base, steps) = split_suffix_steps(inner)?;
    let oid = resolve_base(store, kind, base)?;
    let oid = walk_parents(store, oid, steps)?;
    let Some(want) = peel else {
        return Ok(oid);
    };
    peel_object(store, oid, want)
}

/// Splits one trailing `^{<type>}` / `^{}` peel suffix from a revision.
///
/// Returns the inner revision and the wanted type (`""` for bare `^{}`).
/// A tail that is not a well-formed peel passes through untouched and fails
/// downstream as an unknown revision.
fn split_peel_suffix(rev: &str) -> (&str, Option<&str>) {
    if !rev.ends_with('}') {
        return (rev, None);
    }
    let Some(open) = rev.rfind("^{") else {
        return (rev, None);
    };
    let want = &rev[open + 2..rev.len() - 1];
    if want.contains('{') || want.contains('}') {
        return (rev, None);
    }
    if !matches!(want, "" | "commit" | "tag" | "tree" | "blob") {
        return (rev, None);
    }
    (&rev[..open], Some(want))
}

/// Peels one object to the wanted type: `^{}` dereferences tags to any
/// non-tag, `^{commit}` peels tags to their commit, `^{tree}` steps from a
/// commit to its tree, and every other mismatch refuses. Repeats the walk
/// until the type holds, at most 32 dereferences. Git semantics,
/// `git/rev-parse.c` peel onion.
fn peel_object(store: &Store, oid: Oid, want: &str) -> Result<Oid, GitError> {
    let mut cur = oid;
    for _ in 0..32 {
        let (kind, _) = super::tree::read_object_bytes(store, cur)?;
        if peel_matches(kind, want) {
            return Ok(cur);
        }
        if kind == ObjectKind::Tag {
            cur = tag_target(store, cur)?;
            continue;
        }
        if kind == ObjectKind::Commit && (want == "tree" || want.is_empty()) {
            cur = commit_tree(store, cur)?;
            continue;
        }
        return Err(GitError::NotFound {
            detail: format!("{} does not peel to {want:?}", oid.to_hex()),
        });
    }
    Err(GitError::Invalid {
        detail: format!(
            "{} does not peel to {want:?} (chain too deep)",
            oid.to_hex()
        ),
    })
}

/// Reports whether an object type already satisfies a peel target.
fn peel_matches(kind: ObjectKind, want: &str) -> bool {
    match want {
        "" => kind != ObjectKind::Tag,
        "commit" => kind == ObjectKind::Commit,
        "tag" => kind == ObjectKind::Tag,
        "tree" => kind == ObjectKind::Tree,
        "blob" => kind == ObjectKind::Blob,
        _ => false,
    }
}

/// Reads the target of one tag object.
fn tag_target(store: &Store, oid: Oid) -> Result<Oid, GitError> {
    let (_, bytes) = super::tree::read_object_bytes(store, oid)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| GitError::Corrupt {
        detail: format!("tag {} is not utf-8", oid.to_hex()),
    })?;
    for line in text.lines() {
        if let Some(hex) = line.strip_prefix("object ") {
            return Oid::from_hex(hex.trim()).map_err(|_| GitError::Corrupt {
                detail: format!("tag {} bad object line", oid.to_hex()),
            });
        }
    }
    Err(GitError::Corrupt {
        detail: format!("tag {} missing object line", oid.to_hex()),
    })
}

/// Reads the tree of one commit object.
fn commit_tree(store: &Store, oid: Oid) -> Result<Oid, GitError> {
    let (_, bytes) = super::tree::read_object_bytes(store, oid)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| GitError::Corrupt {
        detail: format!("commit {} is not utf-8", oid.to_hex()),
    })?;
    for line in text.lines() {
        if let Some(hex) = line.strip_prefix("tree ") {
            return Oid::from_hex(hex.trim()).map_err(|_| GitError::Corrupt {
                detail: format!("commit {} bad tree line", oid.to_hex()),
            });
        }
    }
    Err(GitError::Corrupt {
        detail: format!("commit {} missing tree line", oid.to_hex()),
    })
}

/// One ancestor step: `~n` walks first parents, `^n` names a parent by index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SuffixStep {
    /// First parent `count` times.
    Tilde(usize),
    /// `count`-th parent (`0` is the commit itself).
    Caret(usize),
}

/// Splits trailing `~n` / `^n` steps from a revision.
fn split_suffix_steps(rev: &str) -> Result<(&str, Vec<SuffixStep>), GitError> {
    let bytes = rev.as_bytes();
    let mut end = bytes.len();
    let mut steps: Vec<SuffixStep> = Vec::new();
    loop {
        if end == 0 {
            break;
        }
        let bare_mark = bytes[end - 1];
        if bare_mark == b'~' || bare_mark == b'^' {
            steps.push(if bare_mark == b'~' {
                SuffixStep::Tilde(1)
            } else {
                SuffixStep::Caret(1)
            });
            end -= 1;
            continue;
        }
        let mut digits_start = end;
        while digits_start > 0 && bytes[digits_start - 1].is_ascii_digit() {
            digits_start -= 1;
        }
        if digits_start == end || digits_start == 0 {
            break;
        }
        let mark = bytes[digits_start - 1];
        if mark != b'~' && mark != b'^' {
            break;
        }
        let count: usize = rev[digits_start..end]
            .parse()
            .map_err(|_| GitError::Invalid {
                detail: format!("bad revision {rev:?}"),
            })?;
        steps.push(if mark == b'~' {
            SuffixStep::Tilde(count.max(1))
        } else {
            SuffixStep::Caret(count)
        });
        end = digits_start - 1;
    }
    steps.reverse();
    Ok((&rev[..end], steps))
}

/// Resolves the base of a revision (no suffix steps).
fn resolve_base(store: &Store, kind: HashKind, base: &str) -> Result<Oid, GitError> {
    if base == "HEAD" {
        return head_oid(store);
    }
    if let Ok(oid) = ruk_git::parse_oid(base) {
        return ruk_git::require_kind(oid, kind);
    }
    for candidate in [
        base.to_owned(),
        format!("refs/heads/{base}"),
        format!("refs/tags/{base}"),
    ] {
        let Ok(name) = RefName::new(candidate) else {
            continue;
        };
        let target = read_ref(store, &name)?;
        if let Some(oid) = peel_to_oid(store, target)? {
            return Ok(oid);
        }
    }
    Err(GitError::NotFound {
        detail: format!("unknown revision {base:?}"),
    })
}

/// Follows one optional target to its object id.
fn peel_to_oid(store: &Store, target: Option<RefTarget>) -> Result<Option<Oid>, GitError> {
    match target {
        None => Ok(None),
        Some(RefTarget::Direct(oid)) => Ok(Some(oid)),
        Some(RefTarget::Symbolic(name)) => {
            let resolved = resolve(&StoreRefs::new(store), &name).map_err(ref_to_git)?;
            Ok(resolved.oid)
        }
    }
}

/// Walks ancestor steps from `oid`.
fn walk_parents(store: &Store, mut oid: Oid, steps: Vec<SuffixStep>) -> Result<Oid, GitError> {
    for step in steps {
        match step {
            SuffixStep::Tilde(count) => {
                for _ in 0..count {
                    oid = nth_parent(store, oid, 1)?;
                }
            }
            SuffixStep::Caret(0) => {}
            SuffixStep::Caret(count) => {
                oid = nth_parent(store, oid, count)?;
            }
        }
    }
    Ok(oid)
}

/// Reads the `count`-th parent (1-based) of one stored commit, following
/// `refs/replace/*` so `~`/`^` steps walk replacement parents.
fn nth_parent(store: &Store, oid: Oid, count: usize) -> Result<Oid, GitError> {
    let records = Records::new(store);
    let record = walk_record(store, &records, oid)?;
    record
        .parents()
        .iter()
        .filter_map(head_oid_of)
        .nth(count.saturating_sub(1))
        .ok_or_else(|| GitError::NotFound {
            detail: format!("commit {} has no parent #{count}", oid.to_hex()),
        })
}

/// Extracts the git oid behind one parent head.
fn head_oid_of(head: &Head) -> Option<Oid> {
    head.as_git().copied()
}

/// Resolves the workspace `HEAD` to its current commit oid.
pub(crate) fn head_oid(store: &Store) -> Result<Oid, GitError> {
    let (workspace, _) = load_or_default(store)?;
    match resolve_head(store, &workspace.head)? {
        ResolvedHead::Detached(oid) => Ok(oid),
        ResolvedHead::Symbolic(resolved) => resolved.oid.ok_or_else(|| GitError::NotFound {
            detail: format!("unborn HEAD on {}", resolved.terminal),
        }),
    }
}

/// Follows `refs/replace/<hex>` chains, returning the effective object id.
///
/// With no replace refs the lookup misses and the input returns unchanged,
/// so callers keep their behavior until a `replace` ref lands. Loops stop
/// at the first repeated id instead of spinning; raw revision resolution
/// (`resolve_rev`), blob/tree bytes, and transport paths never call this,
/// so pack integrity and `rev-parse` spellings are unaffected.
pub(crate) fn replace_redirect(store: &Store, oid: Oid) -> Oid {
    let mut current = oid;
    let mut seen: Vec<Oid> = Vec::new();
    for _ in 0..16 {
        if seen.contains(&current) {
            return current;
        }
        seen.push(current);
        let name = match RefName::new(format!("refs/replace/{}", current.to_hex())) {
            Ok(name) => name,
            Err(_) => return current,
        };
        let target = match StoreRefs::new(store).get(&name) {
            Ok(target) => target,
            Err(_) => return current,
        };
        let Some(next) = peel_replace_target(store, target) else {
            return current;
        };
        if next == current {
            return current;
        }
        current = next;
    }
    current
}

/// Follows one replace target through symbolic links, giving up on loops.
fn peel_replace_target(store: &Store, mut target: Option<RefTarget>) -> Option<Oid> {
    for _ in 0..16 {
        match target {
            None => return None,
            Some(RefTarget::Direct(oid)) => return Some(oid),
            Some(RefTarget::Symbolic(name)) => {
                target = StoreRefs::new(store).get(&name).ok()?;
            }
        }
    }
    None
}

/// Reads the commit record behind one object id, following `refs/replace/*`
/// so history walks render the replacement commit.
pub(crate) fn commit_record(store: &Store, oid: Oid) -> Result<CommitRecord, GitError> {
    let oid = replace_redirect(store, oid);
    Records::new(store)
        .get_commit(&Head::Git { oid })
        .map_err(GitError::from)?
        .ok_or_else(|| GitError::NotFound {
            detail: format!("object {} is not a stored commit", oid.to_hex()),
        })
}

/// One queued commit in a date-ordered history walk: committer timestamp
/// plus insertion sequence. The heap pops the newest timestamp first;
/// equal timestamps pop in push order, so the first parent wins ties.
#[derive(PartialEq, Eq)]
pub(crate) struct PendingCommit {
    stamp: i64,
    seq: u64,
    oid: Oid,
}

impl PendingCommit {
    /// The queued commit this entry represents.
    pub(crate) const fn oid(&self) -> Oid {
        self.oid
    }
}

impl Ord for PendingCommit {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.stamp
            .cmp(&other.stamp)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

impl PartialOrd for PendingCommit {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Best-effort committer timestamp for walk ordering. An unparsable ident
/// sorts before every real commit instead of failing the walk; rendering
/// still reports the raw bytes it cannot parse.
pub(crate) fn commit_stamp(record: &CommitRecord) -> i64 {
    record
        .committer()
        .map(|sig| sig.timestamp)
        .unwrap_or(i64::MIN)
}

/// Fetches one commit record for a history walk, naming the missing object
/// the way the walk callers report it. Follows `refs/replace/*` so every
/// walk step renders the replacement commit, not just the tips.
pub(crate) fn walk_record(
    store: &Store,
    records: &Records<'_>,
    oid: Oid,
) -> Result<CommitRecord, GitError> {
    let oid = replace_redirect(store, oid);
    records
        .get_commit(&Head::Git { oid })
        .map_err(GitError::from)?
        .ok_or_else(|| GitError::NotFound {
            detail: format!("object {} is not a stored commit", oid.to_hex()),
        })
}

/// Date-ordered walk queue: committer-timestamp heap with insertion order
/// breaking ties, so a child always precedes its parents while unrelated
/// branches interleave strictly by date.
pub(crate) struct WalkQueue {
    seen: HashSet<Oid>,
    pending: HashMap<Oid, CommitRecord>,
    heap: BinaryHeap<PendingCommit>,
    seq: u64,
}

impl WalkQueue {
    /// Starts an empty queue.
    pub(crate) fn new() -> Self {
        Self {
            seen: HashSet::new(),
            pending: HashMap::new(),
            heap: BinaryHeap::new(),
            seq: 0,
        }
    }

    /// Queues one unseen commit, fetching its record for the timestamp key.
    /// Already-seen oids are a no-op. The oid passes through
    /// `refs/replace/*` first, so every walk step follows replacements.
    pub(crate) fn enqueue(
        &mut self,
        store: &Store,
        records: &Records<'_>,
        oid: Oid,
    ) -> Result<(), GitError> {
        let oid = replace_redirect(store, oid);
        if !self.seen.insert(oid) {
            return Ok(());
        }
        let record = walk_record(store, records, oid)?;
        self.heap.push(PendingCommit {
            stamp: commit_stamp(&record),
            seq: self.seq,
            oid,
        });
        self.seq += 1;
        self.pending.insert(oid, record);
        Ok(())
    }

    /// Marks one oid as already visited without queueing it, so excluded
    /// tips never emit. Callers pass replacement-space oids.
    pub(crate) fn mark_seen(&mut self, oid: Oid) {
        self.seen.insert(oid);
    }

    /// Pops the next queued commit with its record, skipping drained entries.
    pub(crate) fn pop(&mut self) -> Option<(Oid, CommitRecord)> {
        while let Some(next) = self.heap.pop() {
            let oid = next.oid();
            if let Some(record) = self.pending.remove(&oid) {
                return Some((oid, record));
            }
        }
        None
    }
}

impl Default for WalkQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Collects every ancestor of `tips` in `git log` order: committer-date
/// descending, ties by discovery order.
///
/// This mirrors git's default revision walk: a max-heap on committer
/// timestamp into which a parent enters only once one of its children has
/// been emitted. Unrelated branches therefore interleave strictly by date
/// while a child always precedes its parents; equal timestamps keep
/// first-parent-first discovery order. Callers that only need the reachable
/// set (merge-base search, object sweeps) are unaffected by the ordering.
pub(crate) fn walk_history(
    store: &Store,
    tips: &[Oid],
    limit: Option<usize>,
) -> Result<Vec<(Oid, CommitRecord)>, GitError> {
    let records = Records::new(store);
    let mut queue = WalkQueue::new();
    for tip in tips {
        queue.enqueue(store, &records, *tip)?;
    }
    let mut out = Vec::new();
    while let Some((oid, record)) = queue.pop() {
        for parent in record.parents() {
            let Some(parent_oid) = head_oid_of(parent) else {
                continue;
            };
            queue.enqueue(store, &records, parent_oid)?;
        }
        out.push((oid, record));
        if limit.is_some_and(|max| out.len() >= max) {
            return Ok(out);
        }
    }
    Ok(out)
}

/// Decides whether `ancestor` reaches `descendant` through first-or-later
/// parent links.
pub(crate) fn is_ancestor(store: &Store, ancestor: Oid, descendant: Oid) -> Result<bool, GitError> {
    let ancestor = replace_redirect(store, ancestor);
    let mut queue = vec![replace_redirect(store, descendant)];
    if ancestor == queue[0] {
        return Ok(true);
    }
    let records = Records::new(store);
    let mut seen: HashMap<Oid, bool> = HashMap::new();
    while let Some(oid) = queue.pop() {
        let oid = replace_redirect(store, oid);
        if oid == ancestor {
            return Ok(true);
        }
        if seen.contains_key(&oid) {
            continue;
        }
        seen.insert(oid, true);
        let record = walk_record(store, &records, oid)?;
        for parent in record.parents() {
            if let Some(parent_oid) = head_oid_of(parent) {
                queue.push(parent_oid);
            }
        }
    }
    Ok(false)
}

/// Finds the first common ancestor of `left` and `right` by breadth-first
/// paint-down from both tips.
pub(crate) fn merge_base(store: &Store, left: Oid, right: Oid) -> Result<Oid, GitError> {
    if left == right {
        return Ok(left);
    }
    let left = replace_redirect(store, left);
    let right = replace_redirect(store, right);
    let records = Records::new(store);
    let mut left_seen: HashMap<Oid, bool> = HashMap::new();
    let mut queue = vec![left];
    while let Some(oid) = queue.pop() {
        let oid = replace_redirect(store, oid);
        if left_seen.contains_key(&oid) {
            continue;
        }
        left_seen.insert(oid, true);
        let record = walk_record(store, &records, oid)?;
        for parent in record.parents() {
            if let Some(parent_oid) = head_oid_of(parent) {
                queue.push(parent_oid);
            }
        }
    }
    let mut queue = vec![right];
    let mut right_seen: HashMap<Oid, bool> = HashMap::new();
    while let Some(oid) = queue.pop() {
        let oid = replace_redirect(store, oid);
        if left_seen.contains_key(&oid) {
            return Ok(oid);
        }
        if right_seen.contains_key(&oid) {
            continue;
        }
        right_seen.insert(oid, true);
        let record = walk_record(store, &records, oid)?;
        for parent in record.parents() {
            if let Some(parent_oid) = head_oid_of(parent) {
                queue.push(parent_oid);
            }
        }
    }
    Err(GitError::NotFound {
        detail: "no merge base".to_owned(),
    })
}

/// Builds an author or committer signature from environment and config.
///
/// `GIT_*_NAME`/`GIT_*_EMAIL`/`GIT_*_DATE` win; stored
/// `user.name`/`user.email` follow; without a name and email the command
/// fails exactly where Git fails instead of inventing an identity.
pub(crate) fn identity(ctx: &Ctx, role: IdentityRole) -> Result<Signature, GitError> {
    let prefix = match role {
        IdentityRole::Author => "GIT_AUTHOR",
        IdentityRole::Committer => "GIT_COMMITTER",
    };
    let name = ctx
        .env
        .get(&format!("{prefix}_NAME"))
        .map(str::to_owned)
        .or_else(|| ctx.config_get("user.name"))
        .ok_or_else(|| GitError::Invalid {
            detail: "identity unknown: set user.name or GIT_*_NAME".to_owned(),
        })?;
    let email = ctx
        .env
        .get(&format!("{prefix}_EMAIL"))
        .map(str::to_owned)
        .or_else(|| ctx.config_get("user.email"))
        .ok_or_else(|| GitError::Invalid {
            detail: "identity unknown: set user.email or GIT_*_EMAIL".to_owned(),
        })?;
    let date = ctx.env.get(&format!("{prefix}_DATE")).map(str::to_owned);
    let (timestamp, offset) = parse_date(date.as_deref())?;
    Signature::parse(format!("{name} <{email}> {timestamp} {offset}").as_bytes()).map_err(|err| {
        GitError::Invalid {
            detail: format!("bad identity: {err}"),
        }
    })
}

/// Parses a `GIT_*_DATE` value or stamps the current time in UTC.
fn parse_date(date: Option<&str>) -> Result<(i64, TzOffset), GitError> {
    let Some(date) = date else {
        return Ok((now_seconds()?, TzOffset::UTC));
    };
    let trimmed = date.strip_prefix('@').map_or(date, |rest| rest.trim());
    let mut parts = trimmed.split_whitespace();
    let timestamp: i64 = parts.next().map_or_else(
        || {
            Err(GitError::Invalid {
                detail: format!("bad date {date:?}"),
            })
        },
        |text| {
            text.parse().map_err(|_| GitError::Invalid {
                detail: format!("bad date {date:?}"),
            })
        },
    )?;
    let offset = parts.next().map_or(Ok(TzOffset::UTC), |text| {
        TzOffset::parse(text.as_bytes()).map_err(|err| GitError::Invalid {
            detail: format!("bad date offset: {err}"),
        })
    })?;
    Ok((timestamp, offset))
}

/// Reads the current Unix time without inventing precision.
pub(crate) fn now_seconds() -> Result<i64, GitError> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| GitError::Io {
            detail: format!("system clock: {err}"),
        })?
        .as_secs();
    i64::try_from(seconds).map_err(|_| GitError::Limit {
        detail: "system clock is past the timestamp range".to_owned(),
    })
}

/// Looks up the configured fetch refspec lines for a remote.
pub(crate) fn remote_fetch_specs(ctx: &Ctx, remote: &str) -> Vec<String> {
    let key = format!("remote.{remote}.fetch");
    ctx.config_get(&key)
        .map(|value| vec![value])
        .unwrap_or_else(|| vec![format!("+refs/heads/*:refs/remotes/{remote}/*")])
}

/// Reads the URL configured for a remote.
pub(crate) fn remote_url(ctx: &Ctx, remote: &str) -> Result<String, GitError> {
    ctx.config_get(&format!("remote.{remote}.url"))
        .ok_or_else(|| GitError::NotFound {
            detail: format!("remote {remote:?} does not exist"),
        })
}

/// Maps a local path or remote name to a repository root holding `.ruk`.
///
/// `file://` URLs route to their local path; anything that does not
/// resolve to a local store keeps the old `Offline` refusal.
pub(crate) fn remote_root(ctx: &Ctx, target: &str) -> Result<PathBuf, GitError> {
    let raw = ctx
        .config_get(&format!("remote.{target}.url"))
        .unwrap_or_else(|| target.to_owned());
    let path = match ruk_git::transport::net::parse_endpoint(&raw) {
        Ok(ruk_git::transport::net::Endpoint::Local { path }) => path,
        Ok(ruk_git::transport::net::Endpoint::Http { url, .. }) => {
            return Err(ruk_git::transport::net::dumb_http_gap(&url));
        }
        _ => PathBuf::from(raw),
    };
    let base = if path.is_absolute() {
        path
    } else {
        ctx.env.cwd.join(path)
    };
    if base.join(".ruk").is_dir() {
        return Ok(base);
    }
    if base.is_dir() && base.join("store").is_dir() {
        return Ok(base
            .parent()
            .map_or_else(|| base.clone(), |root| root.to_path_buf()));
    }
    Err(GitError::Offline {
        detail: format!("remote {target:?} is not a local repository path"),
    })
}

/// Opens the native store at one repository root.
pub(crate) fn open_store_at(root: &std::path::Path) -> Result<Store, GitError> {
    Store::open(
        &root.join(".ruk"),
        std::sync::Arc::new(ruk_core::store::PreparationBudget::reference_defaults()),
    )
    .map_err(GitError::from)
}

/// Renders one file mode the way `ls-files -s` spells it.
#[must_use]
pub(crate) fn mode_text(mode: FileMode) -> String {
    format!("{:06o}", mode.octal())
}

/// Collects `(path, entry)` stage-zero rows for tree building.
#[must_use]
pub(crate) fn merged_rows(rows: &[(RepoPath, Stage, IndexEntry)]) -> Vec<(Vec<u8>, IndexEntry)> {
    let mut out = Vec::new();
    for (path, stage, entry) in rows {
        if *stage == Stage::Zero {
            out.push((path.as_bytes().to_vec(), entry.clone()));
        }
    }
    out
}

/// Groups index rows by path for conflict reporting.
#[must_use]
pub(crate) fn unmerged_paths(
    rows: &[(RepoPath, Stage, IndexEntry)],
) -> BTreeMap<Vec<u8>, Vec<Stage>> {
    let mut out: BTreeMap<Vec<u8>, Vec<Stage>> = BTreeMap::new();
    for (path, stage, _) in rows {
        if *stage != Stage::Zero {
            out.entry(path.as_bytes().to_vec())
                .or_default()
                .push(*stage);
        }
    }
    out
}
