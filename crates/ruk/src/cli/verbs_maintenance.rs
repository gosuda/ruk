//! Housekeeping verbs: `prune`, `pack-refs`, `repack`, `maintenance`,
//! `commit-graph`, `update-server-info`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `prune` | ref closure plus workspace pins through `Store::prune_unreachable` (no compaction) | implemented (`-n`/`--dry-run`, `-v`/`--verbose`, `--expire=now`/`never`, `--progress` inert) |
//! | `pack-refs` | refs already live packed in the ref table; one `Store::compact` pass as the compaction trigger | implemented (`--all`, `--prune` accepted, nothing loose to delete) |
//! | `repack` | prune phase for `-d`, `Store::compact` loop for `-a`, single pass otherwise, plus a silent server-info refresh unless `-n` | implemented (`-a`/`--all`, `-d`, `-n`/`--no-update-server-info`, `-q`/`--quiet`, `-l`/`--local` and `--pack-kept-objects` inert, `--keep-unreachable` skips the `-d` prune) |
//! | `maintenance` | task runner over `gc`/`pack-refs` (default `run` set) with `commit-graph`/`prefetch`/`loose-objects`/`incremental-repack` on `--task`; `start`/`stop`/`register`/`unregister` persist `maintenance.*` config | implemented |
//! | `commit-graph` | no commit-graph file is kept; `verify` checks the reachable-commit closure and `list` prints it, `write`/`read` are honest gaps | partial (`verify`/`list` real; `write`/`read` are `Unsupported`) |
//! | `update-server-info` | `dumb_info_refs` bytes plus the oracle's empty `objects/info/packs` body under `.ruk/` | implemented (`--force`) |
//!
//! Oracle anchors: `git/builtin/prune.c`, `git/builtin/pack-refs.c`,
//! `git/builtin/repack.c`, `git/builtin/maintenance.c`,
//! `git/builtin/commit-graph.c`, `git/builtin/update-server-info.c`.

use std::collections::HashSet;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::RefTarget;
use ruk_core::refs::{StoreRefs, all_reflog_oids};
use ruk_core::store::{ObjectKind, Store};
use ruk_git::GitError;
use ruk_git::transport::dumb::dumb_info_refs;
use ruk_git::transport::serve::HeadAdvertisement;

use super::{Ctx, FlagSpec, collect, line};

/// Tasks `maintenance run --task=` accepts, in listed order.
const KNOWN_TASKS: &[&str] = &[
    "gc",
    "pack-refs",
    "commit-graph",
    "prefetch",
    "loose-objects",
    "incremental-repack",
];

/// Default `maintenance run` set: collection plus ref packing, the way the
/// oracle's default strategy runs `gc` and `pack-refs` on its schedule.
const DEFAULT_RUN_TASKS: &[&str] = &["gc", "pack-refs"];

// ---------------------------------------------------------------------------
// reachability (mirrors the `gc` verb's closure)
// ---------------------------------------------------------------------------

/// Every object id collection must keep: the ref closure plus workspace
/// pins beyond refs.
///
/// This mirrors `verbs_transport::gc_reachable` (ref tips peeled through
/// tags and walked through history, plus detached `HEAD`, index blobs,
/// stash commits and their captured rows, `FETCH_HEAD` tips, sequencer
/// tips, and reflog oids) without touching that module's private helpers,
/// so `prune` and `repack -d` never prune what `gc` would keep.
fn maintenance_reachable(store: &Store, kind: HashKind) -> Result<HashSet<Oid>, GitError> {
    let mut reachable = HashSet::new();
    let mut commits = Vec::new();
    let mut tips = Vec::new();
    for (_, target) in super::state::list_refs(store)? {
        match target {
            RefTarget::Direct(oid) => tips.push(oid),
            RefTarget::Symbolic(name) => {
                let resolved = ruk_core::refdata::resolve(&StoreRefs::new(store), &name)
                    .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
                if let Some(oid) = resolved.oid {
                    tips.push(oid);
                }
            }
        }
    }
    let (workspace, _) = super::state::load_or_default(store)?;
    if let ruk_core::workspace::HeadRef::Detached(oid) = workspace.head {
        tips.push(oid);
    }
    for tip in tips {
        let (visited, commit) = peel_chain(store, kind, tip)?;
        reachable.extend(visited.iter().copied());
        match commit {
            Some(commit) => commits.push(commit),
            None => {
                if let Some(&terminal) = visited.last()
                    && super::tree::read_object_bytes(store, terminal)?.0 == ObjectKind::Tree
                {
                    mark_subtree(store, kind, terminal, &mut reachable)?;
                }
            }
        }
    }
    for (oid, record) in super::state::walk_history(store, &commits, None)? {
        let tree = super::tree::commit_tree_oid(&record)?;
        reachable.insert(oid);
        mark_subtree(store, kind, tree, &mut reachable)?;
    }
    let mut pin_tips = Vec::new();
    for (_, _, entry) in super::state::scan_index(store, kind)? {
        reachable.insert(entry.oid());
    }
    let high_water = super::state::stash_high_water(store)?;
    for slot in 0..high_water {
        if let Some(slot_entry) = super::state::stash_read(store, slot)? {
            if let Ok(oid) = ruk_git::parse_oid_for(&slot_entry.commit_hex, kind) {
                pin_tips.push(oid);
            }
            for (_, _, index_entry) in &slot_entry.rows {
                reachable.insert(index_entry.oid());
            }
        }
    }
    if let Some(raw) = store
        .fact(ruk_core::store::FactTable::Pins, b"cli/pseudo/FETCH_HEAD")
        .map_err(GitError::from)?
    {
        for span in raw.split(|byte| *byte == b'\n') {
            let field = span
                .split(|byte| *byte == b'\t' || *byte == b' ')
                .next()
                .unwrap_or_default();
            if field.is_empty() {
                continue;
            }
            if let Ok(text) = std::str::from_utf8(field)
                && let Ok(oid) = ruk_git::parse_oid_for(text, kind)
            {
                pin_tips.push(oid);
            }
        }
    }
    for verb in ["merge", "rebase", "cherry-pick", "revert"] {
        if let Some(state) = super::state::sequencer_read(store, verb)? {
            for hex in [&state.head_hex, &state.target_hex] {
                if let Ok(oid) = ruk_git::parse_oid_for(hex, kind) {
                    pin_tips.push(oid);
                }
            }
        }
    }
    pin_tips.extend(all_reflog_oids(store).map_err(GitError::from)?);
    // One absent pin cannot abort the rest; any other failure aborts the
    // collection, since an incomplete reachable set would delete blind.
    for tip in pin_tips {
        reachable.insert(tip);
        walk_pin_tip(store, kind, &mut reachable, tip)?;
    }
    Ok(reachable)
}

/// Peels one tip through tag objects to its commit, recording every link.
///
/// Oracle shape: `verbs_transport::peel_tip_chain` (at most 32 hops, the
/// same bound the rev-parse peel uses).
fn peel_chain(
    store: &Store,
    kind: HashKind,
    tip: Oid,
) -> Result<(Vec<Oid>, Option<Oid>), GitError> {
    let mut visited = vec![tip];
    let mut current = tip;
    for _ in 0..32 {
        let (object_kind, bytes) = super::tree::read_object_bytes(store, current)?;
        match object_kind {
            ObjectKind::Commit => return Ok((visited, Some(current))),
            ObjectKind::Tag => {
                let first = bytes
                    .split(|byte| *byte == b'\n')
                    .next()
                    .unwrap_or_default();
                let hex = first
                    .strip_prefix(b"object ")
                    .ok_or_else(|| GitError::Corrupt {
                        detail: format!("tag {} has no object header", current.to_hex()),
                    })?;
                let text = std::str::from_utf8(hex).map_err(|_| GitError::Corrupt {
                    detail: format!("tag {} has a non-UTF-8 object header", current.to_hex()),
                })?;
                current = ruk_git::parse_oid_for(text, kind)?;
                visited.push(current);
            }
            _ => return Ok((visited, None)),
        }
    }
    Err(GitError::Corrupt {
        detail: format!("tag chain from {} does not end", tip.to_hex()),
    })
}

/// Marks one tree and its subtree reachable: the tree itself plus every
/// entry oid, recursing into subtrees. Missing trees stay silent (the
/// corruption half already reported them); anything else propagates.
fn mark_subtree(
    store: &Store,
    kind: HashKind,
    tree: Oid,
    reachable: &mut HashSet<Oid>,
) -> Result<(), GitError> {
    if !reachable.insert(tree) {
        return Ok(());
    }
    let body = match super::tree::read_object_bytes(store, tree) {
        Ok((ObjectKind::Tree, body)) => body,
        Ok(_) => {
            return Err(GitError::Invalid {
                detail: format!("object {} is not a tree", tree.to_hex()),
            });
        }
        Err(GitError::NotFound { .. }) => return Ok(()),
        Err(err) => return Err(err),
    };
    for entry in super::tree::parse_tree(kind, &body)? {
        if entry.mode.is_tree() {
            mark_subtree(store, kind, entry.oid, reachable)?;
        } else {
            reachable.insert(entry.oid);
        }
    }
    Ok(())
}

/// Walks one pin tip into `reachable`: tags peel, commits walk history,
/// trees walk their subtree. Only an absent tip is tolerated; every other
/// failure propagates, since the reachable set decides deletions.
fn walk_pin_tip(
    store: &Store,
    kind: HashKind,
    reachable: &mut HashSet<Oid>,
    tip: Oid,
) -> Result<(), GitError> {
    let (visited, commit) = match peel_chain(store, kind, tip) {
        Err(GitError::NotFound { .. }) => return Ok(()),
        other => other?,
    };
    reachable.extend(visited.iter().copied());
    let Some(commit) = commit else {
        if let Some(&terminal) = visited.last()
            && super::tree::read_object_bytes(store, terminal)?.0 == ObjectKind::Tree
        {
            mark_subtree(store, kind, terminal, reachable)?;
        }
        return Ok(());
    };
    for (oid, record) in super::state::walk_history(store, &[commit], None)? {
        reachable.insert(oid);
        mark_subtree(
            store,
            kind,
            super::tree::commit_tree_oid(&record)?,
            reachable,
        )?;
    }
    Ok(())
}

/// Prunes census objects outside the maintenance reachable set, returning
/// the pruned oids in census (digest) order. No compaction follows: that
/// is `gc`/`repack` territory, not `prune`'s.
fn prune_unreachable_objects(store: &Store, kind: HashKind) -> Result<Vec<Oid>, GitError> {
    let reachable = maintenance_reachable(store, kind)?;
    let doomed = store.unreachable_oids(&reachable).map_err(GitError::from)?;
    if doomed.is_empty() {
        return Ok(Vec::new());
    }
    let stats = store
        .prune_unreachable(&reachable)
        .map_err(GitError::from)?;
    debug_assert_eq!(stats.objects_pruned, doomed.len());
    Ok(doomed)
}

// ---------------------------------------------------------------------------
// prune
// ---------------------------------------------------------------------------

/// Drops unreachable objects without compacting.
///
/// Oracle: `git/builtin/prune.c`. The reachable set is the same closure
/// `gc` prunes against, so the two verbs never disagree about what is
/// garbage. The oracle prints one oid per pruned object under `--verbose`
/// (and `--dry-run` implies that listing without deleting); `--expire`
/// accepts only `now` (the default: no object ages exist, so unreachable
/// prunes immediately) and `never` (prunes nothing). Any other date is
/// `Unsupported`, the same gap `gc --prune=<date>` reports. `--progress`
/// is accepted inert: there is no tty progress meter to drive.
pub(crate) fn prune(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "dry-run",
            short: Some('n'),
            takes_value: false,
        },
        FlagSpec {
            long: "verbose",
            short: Some('v'),
            takes_value: false,
        },
        FlagSpec {
            long: "expire",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "progress",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: prune [-n] [-v] [--expire=now|never] [--progress]".to_owned(),
        });
    }
    match opts.single("expire")?.as_deref() {
        None | Some("now") => {}
        Some("never") => return Ok(Vec::new()),
        Some(other) => {
            return Err(GitError::Unsupported {
                command: format!(
                    "prune: --expire={other} needs object ages this store does not track (use --expire=now or --expire=never)"
                ),
            });
        }
    }
    let _ = opts.is_set("progress");
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let reachable = maintenance_reachable(store, kind)?;
    let doomed = store.unreachable_oids(&reachable).map_err(GitError::from)?;
    let verbose = opts.is_set("verbose") || opts.is_set("dry-run");
    if opts.is_set("dry-run") {
        let mut out = Vec::new();
        for oid in &doomed {
            out.extend_from_slice(oid.to_hex().as_bytes());
            out.push(b'\n');
        }
        return Ok(out);
    }
    if doomed.is_empty() {
        return Ok(Vec::new());
    }
    let stats = store
        .prune_unreachable(&reachable)
        .map_err(GitError::from)?;
    debug_assert_eq!(stats.objects_pruned, doomed.len());
    if !verbose {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for oid in &doomed {
        out.extend_from_slice(oid.to_hex().as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// pack-refs
// ---------------------------------------------------------------------------

/// Packs refs: a census plus the compaction trigger.
///
/// Oracle: `git/builtin/pack-refs.c`. Refs already live packed in the ref
/// table (there is no loose/packed split), so `--all` has nothing to fold:
/// the verb verifies every ref still resolves and runs one `Store::compact`
/// pass as its compaction trigger, reporting the packed count. `--prune`
/// is accepted and deletes nothing, since no loose rows exist to retire.
pub(crate) fn pack_refs(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "all",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "prune",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: pack-refs [--all] [--prune]".to_owned(),
        });
    }
    let _ = (opts.is_set("all"), opts.is_set("prune"));
    let store = ctx.store()?;
    let refs = super::state::list_refs(store)?;
    // Every packed ref must still resolve: a dangling ref is corruption
    // the pack must report, not silently carry.
    let direct = StoreRefs::new(store);
    for (name, target) in &refs {
        match target {
            RefTarget::Direct(_) => {}
            RefTarget::Symbolic(link) => {
                ruk_core::refdata::resolve(&direct, link)
                    .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
            }
        }
        let _ = name;
    }
    let stats = store.compact().map_err(GitError::from)?;
    let mut out = format!("Packed {} refs.\n", refs.len()).into_bytes();
    if stats.did_work() {
        out.extend_from_slice(
            format!(
                "Compacted {} segments into {} ({} objects, {} bytes freed).\n",
                stats.segments_retired,
                stats.segments_created,
                stats.objects_copied,
                stats.bytes_freed
            )
            .as_bytes(),
        );
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// update-server-info
// ---------------------------------------------------------------------------

/// Writes the dumb-http server files under `.ruk/`: `info/refs` from the
/// same byte producer the HTTP layer serves, plus `objects/info/packs`
/// holding the oracle's empty body (a single `\n`: this store keeps no
/// pack files, so dumb clients fetch every object loose).
///
/// Oracle: `git/builtin/update-server-info.c`. Without `--force`, files
/// whose bytes would not change are left untouched; with `--force` both
/// are rewritten unconditionally. Success is silent, like the oracle.
pub(crate) fn update_server_info(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "force",
        short: Some('f'),
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: update-server-info [--force]".to_owned(),
        });
    }
    let store = ctx.store()?;
    refresh_server_info(store, &ctx.root, opts.is_set("force"))?;
    Ok(Vec::new())
}

/// Writes both dumb-http files, skipping unchanged bytes unless `force`.
fn refresh_server_info(store: &Store, root: &std::path::Path, force: bool) -> Result<(), GitError> {
    let kind = store.hash_kind();
    let mut refs_body = Vec::new();
    dumb_info_refs(
        store,
        &HeadAdvertisement {
            oid: kind.zero_oid(),
            symref: None,
        },
        &mut refs_body,
    )?;
    let packs_body = b"\n".to_vec();
    write_server_file(&root.join(".ruk/info/refs"), &refs_body, force)?;
    write_server_file(&root.join(".ruk/objects/info/packs"), &packs_body, force)?;
    Ok(())
}

/// Writes one server file, creating parents, leaving identical bytes alone
/// unless `force` demands a rewrite.
fn write_server_file(path: &std::path::Path, body: &[u8], force: bool) -> Result<(), GitError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| GitError::Io {
            detail: format!("creating {}: {err}", parent.display()),
        })?;
    }
    if !force
        && let Ok(current) = std::fs::read(path)
        && current == body
    {
        return Ok(());
    }
    std::fs::write(path, body).map_err(|err| GitError::Io {
        detail: format!("writing {}: {err}", path.display()),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// repack
// ---------------------------------------------------------------------------

/// Repacks the object store: prune plus compaction over segments.
///
/// Oracle: `git/builtin/repack.c`. The store keeps no pack files, so the
/// pack-file machinery maps onto segment passes: `-d` prunes unreachable
/// objects first (skipped under `--keep-unreachable`), `-a`/`--all`
/// compacts until a pass does no work, and a bare run takes one compact
/// pass. `--pack-kept-objects` and `-l`/`--local` are accepted inert (no
/// kept packs and a single store exist); `-n`/`--no-update-server-info`
/// skips the silent server-info refresh a successful repack otherwise
/// performs, mirroring the oracle's own post-pass hook. Pack-tuning and
/// pack-listing flags (`--window`, `--depth`, `--max-pack-size`,
/// `--keep-pack`, `--write-bitmap-index`, `--no-write-bitmap-index`,
/// `--write-midx`, `--geometric`, `--cruft`, `--expiration`,
/// `--unpack-unreachable`) are `Unsupported`: there are no pack files to
/// tune or list.
pub(crate) fn repack(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "all",
            short: Some('a'),
            takes_value: false,
        },
        FlagSpec {
            long: "d",
            short: Some('d'),
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
        FlagSpec {
            long: "local",
            short: Some('l'),
            takes_value: false,
        },
        FlagSpec {
            long: "no-update-server-info",
            short: Some('n'),
            takes_value: false,
        },
        FlagSpec {
            long: "pack-kept-objects",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "keep-unreachable",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "window",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "depth",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "max-pack-size",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "keep-pack",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "write-bitmap-index",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-write-bitmap-index",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "write-midx",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "geometric",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "cruft",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "expiration",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "unpack-unreachable",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail:
                "usage: repack [-a] [-d] [-q] [-l] [-n] [--pack-kept-objects] [--keep-unreachable]"
                    .to_owned(),
        });
    }
    for flag in [
        "window",
        "depth",
        "max-pack-size",
        "keep-pack",
        "write-bitmap-index",
        "no-write-bitmap-index",
        "write-midx",
        "geometric",
        "cruft",
        "expiration",
        "unpack-unreachable",
    ] {
        if opts.is_set(flag) {
            return Err(GitError::Unsupported {
                command: format!(
                    "repack: --{flag} tunes pack files this segment store does not keep"
                ),
            });
        }
    }
    let _ = (opts.is_set("local"), opts.is_set("pack-kept-objects"));
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let quiet = opts.is_set("quiet");
    let mut out = Vec::new();
    if opts.is_set("d") && !opts.is_set("keep-unreachable") {
        let doomed = prune_unreachable_objects(store, kind)?;
        if !doomed.is_empty() {
            out.extend_from_slice(
                format!("Pruned {} unreachable objects.\n", doomed.len()).as_bytes(),
            );
        }
    }
    let mut copied = 0usize;
    let mut bytes_copied = 0u64;
    let mut created = 0usize;
    let mut retired = 0usize;
    let mut unlinked = 0usize;
    let mut bytes_freed = 0u64;
    loop {
        let stats = store.compact().map_err(GitError::from)?;
        let worked = stats.did_work();
        copied += stats.objects_copied;
        bytes_copied += stats.bytes_copied;
        created += stats.segments_created;
        retired += stats.segments_retired;
        unlinked += stats.segments_unlinked;
        bytes_freed += stats.bytes_freed;
        if !opts.is_set("all") || !worked {
            break;
        }
    }
    if retired > 0 || unlinked > 0 {
        out.extend_from_slice(
            format!(
                "Repacked {retired} segments into {created} ({copied} objects, {bytes_copied} bytes copied, {bytes_freed} bytes freed).\n"
            )
            .as_bytes(),
        );
    } else if out.is_empty() {
        out.extend_from_slice(b"Nothing to repack.\n");
    }
    if !opts.is_set("no-update-server-info") {
        refresh_server_info(store, &ctx.root, false)?;
    }
    Ok(if quiet { Vec::new() } else { out })
}

// ---------------------------------------------------------------------------
// commit-graph
// ---------------------------------------------------------------------------

/// Manages the commit-graph: verification and listing over the store.
///
/// Oracle: `git/builtin/commit-graph.c`. The store keeps no commit-graph
/// file (history walks read commits directly), so `write` and `read` are
/// honest named gaps. `verify` checks the reachable-commit closure every
/// graph file would cover — each commit's parents and tree must resolve —
/// and `list` prints every reachable commit oid in history-walk order.
pub(crate) fn commit_graph(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "reachable",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "changed-paths",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "split",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "shallow",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "progress",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-progress",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "verbose",
            short: Some('v'),
            takes_value: false,
        },
        FlagSpec {
            long: "size-multiple",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "max-new-filters",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "expire-to",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    let Some(subcommand) = opts.positionals.first().cloned() else {
        return Err(GitError::Invalid {
            detail: "usage: commit-graph <write|read|verify|list>".to_owned(),
        });
    };
    if opts.positionals.len() > 1 {
        return Err(GitError::Invalid {
            detail: format!("commit-graph {subcommand} takes no arguments"),
        });
    }
    match subcommand.as_str() {
        "write" => Err(GitError::Unsupported {
            command: "commit-graph write: the store keeps no commit-graph file; history walks read commits directly"
                .to_owned(),
        }),
        "read" => Err(GitError::Unsupported {
            command: "commit-graph read: the store keeps no commit-graph file to dump"
                .to_owned(),
        }),
        "verify" => commit_graph_verify(ctx),
        "list" => commit_graph_list(ctx),
        other => Err(GitError::Invalid {
            detail: format!("unknown commit-graph subcommand {other:?}"),
        }),
    }
}

/// Collects every ref tip peeled to commits for closure verbs.
fn closure_commits(store: &Store, kind: HashKind) -> Result<Vec<Oid>, GitError> {
    let mut commits = Vec::new();
    for (_, target) in super::state::list_refs(store)? {
        let tip = match target {
            RefTarget::Direct(oid) => oid,
            RefTarget::Symbolic(name) => {
                match ruk_core::refdata::resolve(&StoreRefs::new(store), &name)
                    .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?
                    .oid
                {
                    Some(oid) => oid,
                    None => continue,
                }
            }
        };
        if let (_, Some(commit)) = peel_chain(store, kind, tip)? {
            commits.push(commit);
        }
    }
    Ok(commits)
}

/// Verifies the reachable-commit closure: every commit's parents and tree
/// must resolve from the store.
fn commit_graph_verify(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let commits = closure_commits(store, kind)?;
    let history = super::state::walk_history(store, &commits, None)?;
    for (oid, record) in &history {
        // Native (conflicted) parents carry no object id; the history walk
        // above already skips them the same way, so only Git parents resolve.
        for parent in record.parents() {
            let Some(parent_oid) = parent.as_git() else {
                continue;
            };
            match super::tree::read_object_bytes(store, *parent_oid) {
                Ok(_) => {}
                Err(GitError::NotFound { .. }) => {
                    return Err(GitError::Corrupt {
                        detail: format!(
                            "commit {} names missing parent {}",
                            oid.to_hex(),
                            parent_oid.to_hex()
                        ),
                    });
                }
                Err(other) => return Err(other),
            }
        }
        let tree = super::tree::commit_tree_oid(record)?;
        match super::tree::read_object_bytes(store, tree) {
            Ok(_) => {}
            Err(GitError::NotFound { .. }) => {
                return Err(GitError::Corrupt {
                    detail: format!(
                        "commit {} names missing tree {}",
                        oid.to_hex(),
                        tree.to_hex()
                    ),
                });
            }
            Err(other) => return Err(other),
        }
    }
    Ok(line(
        format!("Verified {} commits.\n", history.len()).into_bytes(),
    ))
}

/// Prints every reachable commit oid in history-walk order.
fn commit_graph_list(ctx: &Ctx) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let commits = closure_commits(store, kind)?;
    let mut out = Vec::new();
    for (oid, _) in super::state::walk_history(store, &commits, None)? {
        out.extend_from_slice(oid.to_hex().as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// maintenance
// ---------------------------------------------------------------------------

/// Runs scheduled housekeeping and records its configuration.
///
/// Oracle: `git/builtin/maintenance.c`. `run` executes tasks now: with no
/// `--task` the default set (`gc` with `--auto` semantics plus
/// `pack-refs --all`); with repeatable `--task=<name>` exactly those
/// tasks. The runnable set is `gc`, `pack-refs`, `commit-graph`
/// (verification), `prefetch` (fetches every configured remote, reporting
/// calmly when none exists), `loose-objects` (prune without compaction),
/// and `incremental-repack` (one compact pass). `start`/`stop` persist
/// `maintenance.<task>.enabled` plus `maintenance.strategy`, and
/// `register`/`unregister` persist `maintenance.registered`: no background
/// scheduler exists, so these rows record intent for a future scheduler
/// and for `for-each-repo` runners; only `run` performs work. `task`
/// lists the known tasks with their enabled state (unset means enabled).
pub(crate) fn maintenance(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "task",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "auto",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let Some(subcommand) = opts.positionals.first().cloned() else {
        return Err(GitError::Invalid {
            detail: "usage: maintenance <run|start|stop|register|unregister|task> [--task=<name>] [--auto] [--quiet]"
                .to_owned(),
        });
    };
    let tail: &[String] = opts.positionals.get(1..).unwrap_or(&[]);
    match subcommand.as_str() {
        "run" => {
            reject_tail(&subcommand, tail)?;
            maintenance_run(ctx, &opts)
        }
        "start" => {
            reject_tail(&subcommand, tail)?;
            maintenance_start(ctx, &opts)
        }
        "stop" => {
            reject_tail(&subcommand, tail)?;
            maintenance_stop(ctx, &opts)
        }
        "register" => {
            reject_tail(&subcommand, tail)?;
            maintenance_register(ctx, &opts)
        }
        "unregister" => {
            reject_tail(&subcommand, tail)?;
            maintenance_unregister(ctx, &opts)
        }
        "task" => maintenance_list_tasks(ctx, &opts, tail),
        other => Err(GitError::Invalid {
            detail: format!("unknown maintenance subcommand {other:?}"),
        }),
    }
}

/// Checks task names against the known set.
fn check_tasks(tasks: &[String]) -> Result<(), GitError> {
    for task in tasks {
        if !KNOWN_TASKS.contains(&task.as_str()) {
            return Err(GitError::Invalid {
                detail: format!(
                    "unknown maintenance task {task:?} (tasks: {})",
                    KNOWN_TASKS.join(", ")
                ),
            });
        }
    }
    Ok(())
}

/// Executes maintenance tasks now, concatenating their reports.
fn maintenance_run(ctx: &mut Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let requested = opts.all("task")?;
    check_tasks(&requested)?;
    let tasks: Vec<String> = if requested.is_empty() {
        DEFAULT_RUN_TASKS
            .iter()
            .map(|task| (*task).to_owned())
            .collect()
    } else {
        requested
    };
    let quiet = opts.is_set("quiet");
    let auto = opts.is_set("auto");
    let mut out = Vec::new();
    for task in &tasks {
        let bytes: Vec<u8> = match task.as_str() {
            "gc" => {
                let mut gc_args = Vec::new();
                if auto {
                    gc_args.push("--auto".to_owned());
                }
                if quiet {
                    gc_args.push("--quiet".to_owned());
                }
                super::verbs_transport::gc(ctx, &gc_args)?
            }
            "pack-refs" => pack_refs(ctx, &["--all".to_owned()])?,
            "commit-graph" => commit_graph(ctx, &["verify".to_owned()])?,
            "prefetch" => maintenance_prefetch(ctx, quiet)?,
            "loose-objects" => {
                let store = ctx.store()?;
                let kind = ctx.kind()?;
                let doomed = prune_unreachable_objects(store, kind)?;
                if quiet || doomed.is_empty() {
                    Vec::new()
                } else {
                    format!("Pruned {} loose objects.\n", doomed.len()).into_bytes()
                }
            }
            "incremental-repack" => {
                let store = ctx.store()?;
                let stats = store.compact().map_err(GitError::from)?;
                if quiet || !stats.did_work() {
                    Vec::new()
                } else {
                    format!(
                        "Repacked {} segments into {}.\n",
                        stats.segments_retired, stats.segments_created
                    )
                    .into_bytes()
                }
            }
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("unknown maintenance task {task:?}"),
                });
            }
        };
        out.extend_from_slice(&bytes);
    }
    Ok(if quiet { Vec::new() } else { out })
}

/// Fetches every configured remote for the `prefetch` task.
///
/// With no remotes there is nothing to fetch; otherwise each remote's
/// configured refspecs fetch through the shared fetch lane, so local and
/// network remotes behave exactly as `fetch <name>` would.
fn maintenance_prefetch(ctx: &mut Ctx, quiet: bool) -> Result<Vec<u8>, GitError> {
    let names = {
        let store = ctx.store()?;
        let mut names = Vec::new();
        for (key, _) in super::state::config_list(store)? {
            if let Some(rest) = key.strip_prefix("remote.") {
                if let Some((name, _)) = rest.split_once('.') {
                    if !names.iter().any(|known| known == name) {
                        names.push(name.to_owned());
                    }
                }
            }
        }
        names
    };
    if names.is_empty() {
        return Ok(if quiet {
            Vec::new()
        } else {
            line(b"Nothing to prefetch: no remotes configured.".to_vec())
        });
    }
    let mut out = Vec::new();
    for name in &names {
        out.extend_from_slice(&super::verbs_transport::fetch(ctx, &[name.clone()])?);
    }
    Ok(out)
}

/// Enables scheduled tasks, recording `start` intent.
///
/// With no `--task` the default run set flips; otherwise exactly the named
/// tasks do. `start` also records the `simple` strategy, the oracle's own
/// default when no `--scheduler` platform support exists.
fn maintenance_start(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    set_tasks_enabled(ctx, opts, true)
}

/// Disables scheduled tasks, recording `stop` intent.
///
/// Flips the same rows `start` sets; see [`maintenance_start`].
fn maintenance_stop(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    set_tasks_enabled(ctx, opts, false)
}

/// Flips `maintenance.<task>.enabled` rows one way, shared by `start` and
/// `stop`.
fn set_tasks_enabled(
    ctx: &Ctx,
    opts: &super::Collected,
    enabled: bool,
) -> Result<Vec<u8>, GitError> {
    let requested = opts.all("task")?;
    check_tasks(&requested)?;
    if opts.is_set("auto") || opts.is_set("quiet") {
        return Err(GitError::Invalid {
            detail: "maintenance start/stop take only --task".to_owned(),
        });
    }
    let tasks: Vec<String> = if requested.is_empty() {
        DEFAULT_RUN_TASKS
            .iter()
            .map(|task| (*task).to_owned())
            .collect()
    } else {
        requested
    };
    let store = ctx.store()?;
    if enabled {
        super::state::config_write(store, "maintenance.strategy", "simple")?;
    }
    let mut out = Vec::new();
    for task in &tasks {
        super::state::config_write(
            store,
            &format!("maintenance.{task}.enabled"),
            if enabled { "true" } else { "false" },
        )?;
        out.extend_from_slice(
            format!(
                "{} maintenance task '{task}'.\n",
                if enabled { "Enabled" } else { "Disabled" }
            )
            .as_bytes(),
        );
    }
    Ok(out)
}

/// Registers the repository for background maintenance.
///
/// Only the `maintenance.registered` row flips: no scheduler exists to
/// enroll with, so the row records intent for a future scheduler and for
/// `for-each-repo` runners over `maintenance.repo` rows.
fn maintenance_register(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    set_registered(ctx, opts, true)
}

/// Unregisters the repository for background maintenance.
///
/// Clears the same row `register` sets; see [`maintenance_register`].
fn maintenance_unregister(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    set_registered(ctx, opts, false)
}

/// Flips the `maintenance.registered` row one way, shared by `register`
/// and `unregister`.
fn set_registered(
    ctx: &Ctx,
    opts: &super::Collected,
    registered: bool,
) -> Result<Vec<u8>, GitError> {
    if !opts.all("task")?.is_empty() || opts.is_set("auto") || opts.is_set("quiet") {
        return Err(GitError::Invalid {
            detail: "maintenance register/unregister take no options".to_owned(),
        });
    }
    let store = ctx.store()?;
    super::state::config_write(
        store,
        "maintenance.registered",
        if registered { "true" } else { "false" },
    )?;
    Ok(line(
        format!("Registered for background maintenance: {registered}.\n",).into_bytes(),
    ))
}

/// Rejects trailing positionals for subcommands that take none.
fn reject_tail(subcommand: &str, tail: &[String]) -> Result<(), GitError> {
    if tail.is_empty() {
        return Ok(());
    }
    Err(GitError::Invalid {
        detail: format!("maintenance {subcommand} takes no arguments"),
    })
}

/// Lists the known tasks with their enabled state (unset means enabled).
///
/// Bare `task` and `task list` print every task; `task <name>` prints the
/// one named row, refusing unknown names the way `run --task=` does.
fn maintenance_list_tasks(
    ctx: &Ctx,
    opts: &super::Collected,
    tail: &[String],
) -> Result<Vec<u8>, GitError> {
    if !opts.all("task")?.is_empty() || opts.is_set("auto") || opts.is_set("quiet") {
        return Err(GitError::Invalid {
            detail: "maintenance task takes no options".to_owned(),
        });
    }
    let wanted: &[&str] = match tail {
        [] => KNOWN_TASKS,
        [one] if one == "list" => KNOWN_TASKS,
        [one] => {
            if !KNOWN_TASKS.contains(&one.as_str()) {
                return Err(GitError::Invalid {
                    detail: format!(
                        "unknown maintenance task {one:?} (tasks: {})",
                        KNOWN_TASKS.join(", ")
                    ),
                });
            }
            KNOWN_TASKS
                .iter()
                .find(|task| *task == one)
                .map(std::slice::from_ref)
                .unwrap_or(KNOWN_TASKS)
        }
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: maintenance task [list|<name>]".to_owned(),
            });
        }
    };
    let mut out = Vec::new();
    for task in wanted {
        let enabled = ctx
            .config_get(&format!("maintenance.{task}.enabled"))
            .is_none_or(|value| value != "false");
        out.extend_from_slice(
            format!("{task}: {}\n", if enabled { "enabled" } else { "disabled" }).as_bytes(),
        );
    }
    Ok(out)
}
