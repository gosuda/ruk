//! Bulk import/export and range comparison verbs: `fast-export`,
//! `fast-import`, `range-diff`, `request-pull`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `fast-export` | history walk plus tree flattening | implemented (git stream subset: `commit`/`blob`/`tag`/`reset` with `:mark` ids, topo order, `--all`/ref args, `--import-marks`/`--export-marks`, trailing `done`) |
//! | `fast-import` | stream parser into the object store | implemented (`blob`/`commit` with `M`/`D`/`R`/`C`/`deleteall`, `from`/`merge`, explicit idents or env fallback; lightweight and annotated `tag`; `reset`; `--import-marks`/`--export-marks`) |
//! | `range-diff` | per-commit content fingerprints plus an order-preserving match | implemented (mapping lines only, no patch-of-patch hunks) |
//! | `request-pull` | history walk plus tree stat | implemented (template with shortlog and diffstat; `-p` refused) |
//!
//! Oracle anchors: `git/builtin/fast-export.c`, `git/builtin/fast-import.c`,
//! `git/builtin/range-diff.c`, `git/git-request-pull.sh`.
//!
//! Divergences from the oracles:
//! - The stream subset omits notes (`N` file ops), `ls`/`cat-blob`/`get-mark`
//!   side-channel commands, and `alias`: they fail as `Unsupported` with the
//!   reason instead of half-working. `feature`/`option`/`checkpoint`/
//!   `progress` lines are accepted and ignored.
//! - `fast-import` always overwrites refs (`--force` is accepted and inert);
//!   it never touches the worktree or the index, so a `checkout` is needed
//!   to materialize imported history.
//! - `fast-import` commit/tag/reset names must be full `refs/` names; idents
//!   must use the canonical `name <email> timestamp tz` grammar the store
//!   already parses. A missing author and committer falls back to the
//!   configured identity instead of failing.
//! - `fast-export` needs at least one named ref (`--all`, an explicit ref,
//!   or `HEAD` on a branch); raw-oid tips only widen the emitted history,
//!   and commits reachable only through exported tags ride on the first
//!   named ref. Paths use C-quoting only when they leave printable ASCII.
//! - `range-diff` takes exactly two `A..B` ranges and prints only the
//!   pairing lines (`=` same patch, `!` same subject, `<` old-only,
//!   `>` new-only), the way `--no-patch` reads. `...` ranges are refused.
//! - `request-pull -p` is `Unsupported`: patch text has no cross-module
//!   renderer to reuse, so only the shortlog-plus-diffstat template ships.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;

use ruk_core::commit::CommitRecord;
use ruk_core::conflict::Signature;
use ruk_core::heads::Head;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::index::{IndexEntry, IndexFlags};
use ruk_core::records::Records;
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use ruk_core::store::{EventContext, EventSource, ObjectKind, Store};
use ruk_git::GitError;

use super::state::{
    IdentityRole, apply_refs, commit_record, head_oid, identity, list_refs, load_or_default,
    read_ref, resolve_rev,
};
use super::tree::{
    TreeMode, build_index_tree, commit_payload, commit_tree_oid, flatten_tree, read_object_bytes,
    store_object, tag_payload,
};
use super::verbs_history::{
    render_file_stat, resolve_local, tree_file_changes, walk_history_excluding,
};
use super::{Ctx, FlagSpec, collect};

/// First mark handed out when no marks file seeds the sequence.
const FIRST_MARK: u64 = 1;

/// Top-level stream commands the importer dispatches on.
const COMMANDS: &[&str] = &[
    "blob",
    "checkpoint",
    "commit",
    "tag",
    "reset",
    "progress",
    "feature",
    "option",
    "alias",
    "done",
    "ls",
    "cat-blob",
    "get-mark",
];

/// Dumps history as a fast-import stream.
///
/// Oracle: `git/builtin/fast-export.c`.
pub(crate) fn fast_export(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "all",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "export-marks",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "import-marks",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let import_marks = opts
        .single("import-marks")?
        .map(|path| ctx.env.cwd.join(path));
    let export_marks = opts
        .single("export-marks")?
        .map(|path| ctx.env.cwd.join(path));
    let mut export = Exporter::new();
    if let Some(path) = &import_marks {
        export.load_marks(path, kind)?;
    }
    let plan = export_plan(store, kind, &opts)?;
    if plan.named.is_empty() {
        return Err(GitError::Usage {
            detail: "usage: fast-export [--all] [<ref>...]".to_owned(),
        });
    }
    let first_ref = plan.named[0].0.clone();
    let history = walk_history_excluding(store, &plan.tips, &plan.exclude, None)?;
    let order = topo_oldest_first(&history);
    let claim = claim_commits(store, &plan)?;
    let context = ExportCx { store, kind };
    let mut out = Vec::new();
    let mut claimed: HashSet<String> = HashSet::new();
    for (oid, record) in &order {
        let ref_name = claim.get(oid).map(String::as_str).unwrap_or(&first_ref);
        if export.emit_commit(&context, ref_name, *oid, record, &mut out)? {
            claimed.insert(ref_name.to_owned());
        }
    }
    export.emit_tags(&plan.tags, &mut out);
    for (name, tip) in &plan.named {
        // Refs no commit block named (pre-seeded tips, excluded
        // boundaries, tips shared with another ref) still need their ref
        // update, as a reset.
        if !claimed.contains(name) {
            push_reset(&mut out, name, *tip, export.id_of(*tip));
        }
    }
    for (name, tip) in &plan.lightweight {
        push_reset(&mut out, name, *tip, export.id_of(*tip));
    }
    out.extend_from_slice(b"done\n");
    if let Some(path) = &export_marks {
        export.save_marks(path)?;
    }
    Ok(out)
}

/// Shared store access for one export run.
struct ExportCx<'a> {
    /// Open native store.
    store: &'a Store,
    /// Object format of the open repository.
    kind: HashKind,
}

/// One annotated tag found under an exported ref.
#[derive(Clone, Debug)]
struct ExportTag {
    /// Full ref name (`refs/tags/<name>`).
    name: String,
    /// Peeled target commit.
    target: Oid,
    /// Raw tag payload for the tagger/message split.
    payload: Vec<u8>,
}

/// Refs and tips selected for one export run.
#[derive(Debug, Default)]
struct ExportPlan {
    /// Named exporting refs in emission order.
    named: Vec<(String, Oid)>,
    /// Annotated tags in ref order.
    tags: Vec<ExportTag>,
    /// Lightweight tags in ref order.
    lightweight: Vec<(String, Oid)>,
    /// Every tip whose history is emitted (named plus anonymous).
    tips: Vec<Oid>,
    /// Excluded boundary commits.
    exclude: Vec<Oid>,
}

/// Resolves export arguments to named refs, anonymous tips, and exclusions.
fn export_plan(
    store: &Store,
    kind: HashKind,
    opts: &super::Collected,
) -> Result<ExportPlan, GitError> {
    let mut plan = ExportPlan::default();
    let mut seen: HashSet<String> = HashSet::new();
    if opts.positionals.is_empty() && !opts.is_set("all") {
        let (workspace, _) = load_or_default(store)?;
        match &workspace.head {
            ruk_core::workspace::HeadRef::Symbolic(name) => {
                let text = String::from_utf8_lossy(name.as_bytes()).into_owned();
                let tip = head_oid(store)?;
                commit_record(store, tip)?;
                add_named(&mut plan, &mut seen, text, tip);
            }
            ruk_core::workspace::HeadRef::Detached(_) => {
                return Err(GitError::Invalid {
                    detail: "HEAD is detached; name a ref or pass --all".to_owned(),
                });
            }
        }
    }
    for item in &opts.positionals {
        if let Some(rest) = item.strip_prefix('^') {
            plan.exclude.push(resolve_local(store, kind, rest)?);
            continue;
        }
        if let Some(name) = ref_lookup(store, item)? {
            let target = read_ref(store, &name)?.ok_or_else(|| GitError::NotFound {
                detail: format!("unknown ref {item:?}"),
            })?;
            classify_export_ref(store, &mut plan, &mut seen, name, target)?;
            continue;
        }
        let oid = resolve_local(store, kind, item)?;
        commit_record(store, oid)?;
        if !plan.tips.contains(&oid) {
            plan.tips.push(oid);
        }
    }
    if opts.is_set("all") {
        for (name, target) in list_refs(store)? {
            let text = String::from_utf8_lossy(name.as_bytes()).into_owned();
            if seen.contains(&text) {
                continue;
            }
            classify_export_ref(store, &mut plan, &mut seen, name, target)?;
        }
    }
    Ok(plan)
}

/// Records one named exporting ref unless already present.
fn add_named(plan: &mut ExportPlan, seen: &mut HashSet<String>, name: String, oid: Oid) {
    if seen.insert(name.clone()) {
        plan.named.push((name, oid));
        plan.tips.push(oid);
    }
}

/// Looks up one export argument as a ref name: the full spelling first,
/// then `refs/heads/<item>`.
fn ref_lookup(store: &Store, item: &str) -> Result<Option<RefName>, GitError> {
    for candidate in [item.to_owned(), format!("refs/heads/{item}")] {
        let Ok(name) = RefName::new(candidate) else {
            continue;
        };
        if read_ref(store, &name)?.is_some() {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

/// Files one ref target as a named tip, an annotated tag, or a
/// lightweight tag. Tag refs always export as tags (annotated blocks or
/// lightweight resets), never as `commit` lines; non-commit, non-tag
/// targets are skipped.
fn classify_export_ref(
    store: &Store,
    plan: &mut ExportPlan,
    seen: &mut HashSet<String>,
    name: RefName,
    target: RefTarget,
) -> Result<(), GitError> {
    let text = String::from_utf8_lossy(name.as_bytes()).into_owned();
    let RefTarget::Direct(oid) = target else {
        return Ok(());
    };
    if text.starts_with("refs/tags/") {
        return classify_tag_ref(store, plan, text, oid);
    }
    if commit_record(store, oid).is_ok() {
        add_named(plan, seen, text, oid);
        return Ok(());
    }
    // A non-tag ref pointing at a tag object exports under its peeled
    // commit, the way the oracle peels tip tags.
    let mut peeled = oid;
    for _ in 0..32 {
        let Ok((ObjectKind::Tag, payload)) = read_object_bytes(store, peeled) else {
            break;
        };
        let Some(target_oid) = tag_object_target(&payload) else {
            return Ok(());
        };
        peeled = target_oid;
    }
    if commit_record(store, peeled).is_ok() {
        add_named(plan, seen, text, peeled);
    }
    Ok(())
}

/// Files one `refs/tags/*` target as an annotated tag block or a
/// lightweight reset. Direct commits become lightweight tags; tag objects
/// become annotated tags; anything else is skipped.
fn classify_tag_ref(
    store: &Store,
    plan: &mut ExportPlan,
    text: String,
    oid: Oid,
) -> Result<(), GitError> {
    if commit_record(store, oid).is_ok() {
        if !plan.tips.contains(&oid) {
            plan.tips.push(oid);
        }
        if !plan.lightweight.iter().any(|(name, _)| name == &text) {
            plan.lightweight.push((text, oid));
        }
        return Ok(());
    }
    let Ok((ObjectKind::Tag, payload)) = read_object_bytes(store, oid) else {
        return Ok(());
    };
    let Some(target_oid) = tag_object_target(&payload) else {
        return Ok(());
    };
    if commit_record(store, target_oid).is_err() {
        return Ok(());
    }
    if !plan.tips.contains(&target_oid) {
        plan.tips.push(target_oid);
    }
    if !plan.tags.iter().any(|tag| tag.name == text) {
        plan.tags.push(ExportTag {
            name: text,
            target: target_oid,
            payload,
        });
    }
    Ok(())
}

/// Reads the `object <hex>` line of an annotated tag payload.
fn tag_object_target(payload: &[u8]) -> Option<Oid> {
    for line in payload.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix(b"object ") {
            let text = std::str::from_utf8(rest).ok()?;
            return text.parse::<Oid>().ok();
        }
    }
    None
}

/// Claims every walked commit for the first exporting ref that reaches
/// it, so each `commit` line names a real ref. Tag-only commits (beyond
/// every named tip) ride under their tag's name; the tag's own trailing
/// `tag`/`reset` block pins the ref, so the import converges.
fn claim_commits(store: &Store, plan: &ExportPlan) -> Result<HashMap<Oid, String>, GitError> {
    let mut claim: HashMap<Oid, String> = HashMap::new();
    for (name, tip) in &plan.named {
        let closure = walk_history_excluding(store, &[*tip], &plan.exclude, None)?;
        for (oid, _) in &closure {
            claim.entry(*oid).or_insert_with(|| name.clone());
        }
    }
    let mut tag_tips: Vec<(&str, Oid)> = plan
        .tags
        .iter()
        .map(|tag| (tag.name.as_str(), tag.target))
        .collect();
    for (name, tip) in &plan.lightweight {
        tag_tips.push((name.as_str(), *tip));
    }
    for (name, tip) in tag_tips {
        let closure = walk_history_excluding(store, &[tip], &plan.exclude, None)?;
        for (oid, _) in &closure {
            claim.entry(*oid).or_insert_with(|| name.to_owned());
        }
    }
    Ok(claim)
}

/// Orders walked commits oldest-first with parents before children.
///
/// The date-ordered walk already runs newest-first, so the reversal is
/// nearly topological; the insertion pass then holds back any child whose
/// in-set parent is still pending.
fn topo_oldest_first(history: &[(Oid, CommitRecord)]) -> Vec<(Oid, CommitRecord)> {
    let in_set: HashSet<Oid> = history.iter().map(|(oid, _)| *oid).collect();
    let mut pending: VecDeque<(Oid, CommitRecord)> = history
        .iter()
        .rev()
        .map(|(oid, record)| (*oid, record.clone()))
        .collect();
    let mut emitted: HashSet<Oid> = HashSet::new();
    let mut out = Vec::with_capacity(pending.len());
    while !pending.is_empty() {
        let mut rest = VecDeque::with_capacity(pending.len());
        let mut progressed = false;
        while let Some((oid, record)) = pending.pop_front() {
            let ready = record
                .parents()
                .iter()
                .filter_map(Head::as_git)
                .copied()
                .all(|parent| !in_set.contains(&parent) || emitted.contains(&parent));
            if ready {
                emitted.insert(oid);
                out.push((oid, record));
                progressed = true;
            } else {
                rest.push_back((oid, record));
            }
        }
        if !progressed {
            // Parent links are acyclic, so a stuck pass means a parent the
            // walk never produced; emit in walk order rather than drop it.
            out.extend(rest);
            break;
        }
        pending = rest;
    }
    out
}

/// Emits one `reset <ref>` block pointing at a mark or a raw oid.
fn push_reset(out: &mut Vec<u8>, name: &str, tip: Oid, mark: Option<u64>) {
    out.extend_from_slice(format!("reset {name}\n").as_bytes());
    match mark {
        Some(number) => out.extend_from_slice(format!("from :{number}\n").as_bytes()),
        None => out.extend_from_slice(format!("from {}\n", tip.to_hex()).as_bytes()),
    }
}

/// Stateful mark allocator and blob/commit emitter for one export run.
#[derive(Debug, Default)]
struct Exporter {
    /// Mark number by object id (pre-seeded marks included).
    ids: HashMap<Oid, u64>,
    /// Next fresh mark number.
    next: u64,
}

impl Exporter {
    /// Starts with an empty mark table.
    fn new() -> Self {
        Self {
            ids: HashMap::new(),
            next: FIRST_MARK,
        }
    }

    /// Loads a marks file, continuing numbering past its highest mark.
    fn load_marks(&mut self, path: &Path, kind: HashKind) -> Result<(), GitError> {
        for (mark, oid) in read_marks_file(path, kind)? {
            self.ids.insert(oid, mark);
            self.next = self.next.max(mark.saturating_add(1));
        }
        Ok(())
    }

    /// Writes every assigned mark ordered by mark number.
    fn save_marks(&self, path: &Path) -> Result<(), GitError> {
        let mut rows: Vec<(u64, Oid)> = self.ids.iter().map(|(oid, mark)| (*mark, *oid)).collect();
        rows.sort();
        write_marks_file(path, &rows)
    }

    /// Looks up the mark already assigned to one object.
    fn id_of(&self, oid: Oid) -> Option<u64> {
        self.ids.get(&oid).copied()
    }

    /// Assigns the next fresh mark to one object.
    fn assign(&mut self, oid: Oid) -> u64 {
        if let Some(mark) = self.ids.get(&oid).copied() {
            return mark;
        }
        let mark = self.next;
        self.next = self.next.saturating_add(1);
        self.ids.insert(oid, mark);
        mark
    }

    /// Emits one commit block with its file operations. New blobs land in
    /// the output ahead of the commit that references them, so the
    /// operation scan runs before any commit byte is emitted. Objects that
    /// arrived with pre-seeded marks are referenced but never re-emitted.
    fn emit_commit(
        &mut self,
        context: &ExportCx<'_>,
        ref_name: &str,
        oid: Oid,
        record: &CommitRecord,
        out: &mut Vec<u8>,
    ) -> Result<bool, GitError> {
        let preseeded = self.id_of(oid).is_some();
        let mark = self.assign(oid);
        let parents: Vec<Oid> = record
            .parents()
            .iter()
            .filter_map(Head::as_git)
            .copied()
            .collect();
        let new_tree = commit_tree_oid(record)?;
        let old_tree = first_parent_tree(context.store, &parents)?;
        let ops = self.plan_file_ops(context, old_tree, new_tree, out)?;
        if preseeded {
            return Ok(false);
        }
        out.extend_from_slice(format!("commit {ref_name}\nmark :{mark}\n").as_bytes());
        let author = record.author().map_err(|err| GitError::Corrupt {
            detail: format!("commit {} has a bad author: {err}", oid.to_hex()),
        })?;
        let committer = record.committer().map_err(|err| GitError::Corrupt {
            detail: format!("commit {} has a bad committer: {err}", oid.to_hex()),
        })?;
        out.extend_from_slice(b"author ");
        out.extend_from_slice(&author.render());
        out.push(b'\n');
        out.extend_from_slice(b"committer ");
        out.extend_from_slice(&committer.render());
        out.push(b'\n');
        let message = record.message();
        out.extend_from_slice(format!("data {}\n", message.len()).as_bytes());
        out.extend_from_slice(message);
        out.push(b'\n');
        for (index, parent) in parents.iter().enumerate() {
            let word = if index == 0 { "from" } else { "merge" };
            match self.id_of(*parent) {
                Some(parent_mark) => {
                    out.extend_from_slice(format!("{word} :{parent_mark}\n").as_bytes());
                }
                None => {
                    out.extend_from_slice(format!("{word} {}\n", parent.to_hex()).as_bytes());
                }
            }
        }
        for op in &ops {
            match op {
                FileOp::Modify { mode, oid, path } => {
                    let reference = match self.id_of(*oid) {
                        Some(blob_mark) => format!(":{blob_mark}"),
                        None => oid.to_hex(),
                    };
                    let quoted = quote_path(path);
                    out.extend_from_slice(b"M ");
                    out.extend_from_slice(format!("{mode:o} {reference} ").as_bytes());
                    out.extend_from_slice(&quoted);
                    out.push(b'\n');
                }
                FileOp::Delete { path } => {
                    out.extend_from_slice(b"D ");
                    out.extend_from_slice(&quote_path(path));
                    out.push(b'\n');
                }
            }
        }
        Ok(true)
    }

    /// Diffs two trees into modify/delete operations, emitting new blobs
    /// into the output ahead of the commit that references them.
    fn plan_file_ops(
        &mut self,
        context: &ExportCx<'_>,
        old_tree: Option<Oid>,
        new_tree: Oid,
        out: &mut Vec<u8>,
    ) -> Result<Vec<FileOp>, GitError> {
        let old_map = flat_records(context.store, context.kind, old_tree)?;
        let new_map = flat_records(context.store, context.kind, Some(new_tree))?;
        let mut keys: Vec<Vec<u8>> = old_map.keys().cloned().collect();
        for path in new_map.keys() {
            if !keys.contains(path) {
                keys.push(path.clone());
            }
        }
        keys.sort();
        let mut ops = Vec::new();
        for path in keys {
            let old = old_map.get(&path).copied();
            let new = new_map.get(&path).copied();
            match (old, new) {
                (Some(old), Some(new)) if old == new => {}
                (_, Some((mode, oid))) => {
                    if mode != TreeMode::Gitlink && self.id_of(oid).is_none() {
                        self.emit_blob(context.store, oid, out)?;
                    }
                    ops.push(FileOp::Modify {
                        mode: mode.octal(),
                        oid,
                        path,
                    });
                }
                (Some(_), None) => ops.push(FileOp::Delete { path }),
                (None, None) => {}
            }
        }
        Ok(ops)
    }

    /// Emits one `blob` block for an object the stream has not named yet.
    fn emit_blob(&mut self, store: &Store, oid: Oid, out: &mut Vec<u8>) -> Result<(), GitError> {
        let mark = self.assign(oid);
        let (object_kind, body) = read_object_bytes(store, oid)?;
        if object_kind != ObjectKind::Blob {
            return Err(GitError::Corrupt {
                detail: format!("tree entry {} is not a blob", oid.to_hex()),
            });
        }
        out.extend_from_slice(format!("blob\nmark :{mark}\ndata {}\n", body.len()).as_bytes());
        out.extend_from_slice(&body);
        out.push(b'\n');
        Ok(())
    }

    /// Emits annotated tag blocks after their targets carry marks.
    fn emit_tags(&self, tags: &[ExportTag], out: &mut Vec<u8>) {
        for tag in tags {
            let short = tag.name.trim_start_matches("refs/tags/");
            out.extend_from_slice(format!("tag {short}\n").as_bytes());
            match self.id_of(tag.target) {
                Some(mark) => out.extend_from_slice(format!("from :{mark}\n").as_bytes()),
                None => {
                    out.extend_from_slice(format!("from {}\n", tag.target.to_hex()).as_bytes());
                }
            }
            let (header, message) = split_tag_message(&tag.payload);
            for line in header {
                if let Some(tagger) = line.strip_prefix(b"tagger ") {
                    out.extend_from_slice(b"tagger ");
                    out.extend_from_slice(tagger);
                    out.push(b'\n');
                }
            }
            out.extend_from_slice(format!("data {}\n", message.len()).as_bytes());
            out.extend_from_slice(message);
            out.push(b'\n');
        }
    }
}

/// Reads the first parent's tree when the parent record is available.
fn first_parent_tree(store: &Store, parents: &[Oid]) -> Result<Option<Oid>, GitError> {
    parents
        .first()
        .map(|parent| commit_record(store, *parent))
        .transpose()?
        .map(|record| commit_tree_oid(&record))
        .transpose()
}

/// One export file operation: a modify or a delete.
#[derive(Clone, Debug)]
enum FileOp {
    /// `M <mode> <blob> <path>` with the octal mode spelling.
    Modify {
        /// Octal mode (`100644`, `100755`, `120000`, `160000`).
        mode: u32,
        /// Blob or gitlink-commit oid.
        oid: Oid,
        /// Full path bytes.
        path: Vec<u8>,
    },
    /// `D <path>`.
    Delete {
        /// Full path bytes.
        path: Vec<u8>,
    },
}

/// C-quotes a path when it leaves printable ASCII or carries quotes or
/// backslashes; the importer reverses exactly this spelling.
fn quote_path(path: &[u8]) -> Vec<u8> {
    let plain = !path.is_empty()
        && path
            .iter()
            .all(|byte| matches!(byte, 0x20..=0x7e) && *byte != b'"' && *byte != b'\\');
    if plain {
        return path.to_vec();
    }
    let mut out = vec![b'"'];
    for byte in path {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x20..=0x7e => out.push(*byte),
            _ => out.extend_from_slice(format!("\\{byte:03o}").as_bytes()),
        }
    }
    out.push(b'"');
    out
}

/// Splits a tag payload into its header lines and its message bytes.
fn split_tag_message(payload: &[u8]) -> (Vec<&[u8]>, &[u8]) {
    let split_at = payload
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .map(|index| index + 2);
    match split_at {
        Some(offset) => (
            payload[..offset - 2].split(|byte| *byte == b'\n').collect(),
            &payload[offset..],
        ),
        None => (payload.split(|byte| *byte == b'\n').collect(), &[]),
    }
}

/// Reads a marks file (`:mark SP hex` per line, blanks skipped).
fn read_marks_file(path: &Path, kind: HashKind) -> Result<Vec<(u64, Oid)>, GitError> {
    let bytes = std::fs::read(path).map_err(|err| GitError::Io {
        detail: format!("reading marks {}: {err}", path.display()),
    })?;
    let mut rows = Vec::new();
    for raw in bytes.split(|byte| *byte == b'\n') {
        let line = strip_cr(raw);
        if line.is_empty() {
            continue;
        }
        rows.push(parse_marks_line(line, kind)?);
    }
    Ok(rows)
}

/// Writes a marks file (`:mark SP hex` per line, ordered by mark).
fn write_marks_file(path: &Path, rows: &[(u64, Oid)]) -> Result<(), GitError> {
    let mut out = Vec::new();
    for (mark, oid) in rows {
        out.extend_from_slice(format!(":{mark} {}\n", oid.to_hex()).as_bytes());
    }
    std::fs::write(path, out).map_err(|err| GitError::Io {
        detail: format!("writing marks {}: {err}", path.display()),
    })
}

/// Reads a fast-import stream from stdin into the object store.
///
/// Oracle: `git/builtin/fast-import.c`.
pub(crate) fn fast_import(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "force",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "import-marks",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "export-marks",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Usage {
            detail: "usage: fast-import [--import-marks=<file>] [--export-marks=<file>]".to_owned(),
        });
    }
    // `--force` and `--quiet` are accepted and inert: refs are always
    // overwritten and the importer prints nothing on success.
    let _ = (opts.is_set("force"), opts.is_set("quiet"));
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let import_marks = opts
        .single("import-marks")?
        .map(|path| ctx.env.cwd.join(path));
    let export_marks = opts
        .single("export-marks")?
        .map(|path| ctx.env.cwd.join(path));
    let mut import = Importer::new();
    if let Some(path) = &import_marks {
        import.load_marks(path, kind)?;
    }
    let input = super::read_stdin_bytes(&ctx.env)?;
    let context = ImportCx { ctx, store, kind };
    import.run(&context, &input)?;
    let mut updates = Vec::with_capacity(import.refs.len());
    for (name, oid) in &import.refs {
        let refname = RefName::new(name.clone()).map_err(|err| GitError::Invalid {
            detail: format!("bad ref name: {err}"),
        })?;
        updates.push(RefUpdate {
            name: refname,
            expected: RefExpect::Any,
            change: match oid {
                Some(target) => RefChange::Set(RefTarget::Direct(*target)),
                None => RefChange::Delete,
            },
        });
    }
    if !updates.is_empty() {
        apply_refs(store, kind, updates)?;
    }
    if let Some(path) = &export_marks {
        import.save_marks(path)?;
    }
    Ok(Vec::new())
}

/// Shared read-only access for one import run.
struct ImportCx<'a> {
    /// Process environment snapshot for identity fallback.
    ctx: &'a Ctx,
    /// Open native store.
    store: &'a Store,
    /// Object format of the open repository.
    kind: HashKind,
}

/// Byte cursor over one fast-import stream with one line of pushback.
struct Cursor<'a> {
    /// Remaining input bytes.
    data: &'a [u8],
    /// Current offset.
    pos: usize,
    /// Pushed-back command line.
    pushed: Option<Vec<u8>>,
}

impl<'a> Cursor<'a> {
    /// Starts reading at the first input byte.
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            pushed: None,
        }
    }

    /// Reads one `\n`-terminated line without its newline, or `None` at
    /// end of input. A trailing `\r` is stripped for CRLF tolerance.
    fn read_line(&mut self) -> Result<Option<Vec<u8>>, GitError> {
        if let Some(line) = self.pushed.take() {
            return Ok(Some(line));
        }
        if self.pos >= self.data.len() {
            return Ok(None);
        }
        let start = self.pos;
        match self.data[start..].iter().position(|byte| *byte == b'\n') {
            Some(offset) => {
                self.pos = start + offset + 1;
                Ok(Some(strip_cr(&self.data[start..start + offset]).to_vec()))
            }
            None => {
                self.pos = self.data.len();
                Ok(Some(strip_cr(&self.data[start..]).to_vec()))
            }
        }
    }

    /// Returns one line to the stream; the next read replays it.
    fn push_back(&mut self, line: Vec<u8>) {
        self.pushed = Some(line);
    }

    /// Reads exactly `count` raw bytes for a `data <count>` block plus its
    /// one trailing newline, which is not part of the payload.
    fn read_exact(&mut self, count: usize) -> Result<Vec<u8>, GitError> {
        let end = self.pos.saturating_add(count);
        if end > self.data.len() {
            return Err(GitError::Invalid {
                detail: "data block runs past end of input".to_owned(),
            });
        }
        let body = self.data[self.pos..end].to_vec();
        self.pos = end;
        // One trailing newline ends the block when present, matching the
        // oracle's `skip_optional_lf`; empty `data 0` blocks carry none.
        if self.pos < self.data.len() && self.data[self.pos] == b'\n' {
            self.pos += 1;
        }
        Ok(body)
    }
}

/// Strips one trailing carriage return for CRLF tolerance.
fn strip_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Stateful importer: the mark table plus pending ref updates.
#[derive(Debug, Default)]
struct Importer {
    /// Mark number by object id.
    marks: HashMap<u64, Oid>,
    /// Next fresh mark number.
    next: u64,
    /// Pending ref updates in name order (`None` deletes).
    refs: BTreeMap<Vec<u8>, Option<Oid>>,
}

impl Importer {
    /// Starts with an empty mark table.
    fn new() -> Self {
        Self {
            marks: HashMap::new(),
            next: FIRST_MARK,
            refs: BTreeMap::new(),
        }
    }

    /// Loads a marks file with the numbering continuing past it.
    fn load_marks(&mut self, path: &Path, kind: HashKind) -> Result<(), GitError> {
        for (mark, oid) in read_marks_file(path, kind)? {
            self.remember(mark, oid);
        }
        Ok(())
    }

    /// Writes every assigned mark ordered by mark number.
    fn save_marks(&self, path: &Path) -> Result<(), GitError> {
        let mut rows: Vec<(u64, Oid)> =
            self.marks.iter().map(|(mark, oid)| (*mark, *oid)).collect();
        rows.sort();
        write_marks_file(path, &rows)
    }

    /// Records a mark pointing at one object.
    fn remember(&mut self, mark: u64, oid: Oid) {
        self.marks.insert(mark, oid);
        self.next = self.next.max(mark.saturating_add(1));
    }

    /// Runs the stream to `done` or end of input.
    fn run(&mut self, context: &ImportCx<'_>, input: &[u8]) -> Result<(), GitError> {
        let mut cursor = Cursor::new(input);
        while let Some(line) = cursor.read_line()? {
            if line.is_empty() {
                continue;
            }
            let (command, rest) = split_command(&line);
            match command {
                "blob" => self.read_blob(context, &mut cursor)?,
                "commit" => self.read_commit(context, &mut cursor, rest)?,
                "tag" => self.read_tag(context, &mut cursor, rest)?,
                "reset" => self.read_reset(context, &mut cursor, rest)?,
                "checkpoint" | "progress" | "feature" | "option" => {}
                "done" => break,
                "alias" | "ls" | "cat-blob" | "get-mark" => {
                    return Err(GitError::Unsupported {
                        command: format!(
                            "fast-import {command} needs a side channel this importer does not implement"
                        ),
                    });
                }
                _ => {
                    return Err(GitError::Invalid {
                        detail: format!("unknown fast-import command {command:?}"),
                    });
                }
            }
        }
        Ok(())
    }

    /// Reads a `blob` command: an optional mark plus one data block.
    fn read_blob(
        &mut self,
        context: &ImportCx<'_>,
        cursor: &mut Cursor<'_>,
    ) -> Result<(), GitError> {
        let mut mark = None;
        let mut body = None;
        while let Some(line) = cursor.read_line()? {
            if is_command(&line) {
                cursor.push_back(line);
                break;
            }
            if line.is_empty() {
                continue;
            }
            let (word, rest) = split_command(&line);
            match word {
                "mark" => mark = Some(parse_mark(rest)?),
                "data" => {
                    body = Some(read_data(cursor, rest)?);
                    break;
                }
                "original-oid" => {
                    return Err(GitError::Unsupported {
                        command: "fast-import blob original-oid is not implemented".to_owned(),
                    });
                }
                _ => {
                    return Err(GitError::Invalid {
                        detail: format!("bad blob line {word:?}"),
                    });
                }
            }
        }
        let Some(body) = body else {
            return Err(GitError::Invalid {
                detail: "blob needs a data block".to_owned(),
            });
        };
        let oid = store_blob(context.store, &body)?;
        if let Some(mark) = mark {
            self.remember(mark, oid);
        }
        Ok(())
    }

    /// Reads a `commit <ref>` command with its idents, parents, message,
    /// and file operations.
    fn read_commit(
        &mut self,
        context: &ImportCx<'_>,
        cursor: &mut Cursor<'_>,
        rest: &[u8],
    ) -> Result<(), GitError> {
        let ref_text = std::str::from_utf8(rest).map_err(|_| GitError::Invalid {
            detail: "commit ref is not UTF-8".to_owned(),
        })?;
        if !ref_text.starts_with("refs/") {
            return Err(GitError::Invalid {
                detail: format!("commit ref {ref_text:?} is not a full refs/ name"),
            });
        }
        RefName::new(ref_text).map_err(|err| GitError::Invalid {
            detail: format!("bad commit ref: {err}"),
        })?;
        let mut head = CommitHead::default();
        let mut tree: BTreeMap<Vec<u8>, (TreeMode, Oid)> = BTreeMap::new();
        while let Some(line) = cursor.read_line()? {
            if is_command(&line) {
                cursor.push_back(line);
                break;
            }
            if line.is_empty() {
                continue;
            }
            if is_file_op(&line) {
                if head.message.is_none() {
                    return Err(GitError::Invalid {
                        detail: "commit file operations need the message data first".to_owned(),
                    });
                }
                self.apply_file_op(context, &line, &mut tree)?;
                continue;
            }
            self.read_commit_header(context, cursor, &line, &mut head, &mut tree)?;
        }
        finish_commit(self, context, ref_text, head, &tree)
    }

    /// Reads one non-file-operation line of a `commit` command.
    fn read_commit_header(
        &self,
        context: &ImportCx<'_>,
        cursor: &mut Cursor<'_>,
        line: &[u8],
        head: &mut CommitHead,
        tree: &mut BTreeMap<Vec<u8>, (TreeMode, Oid)>,
    ) -> Result<(), GitError> {
        let (word, arg) = split_command(line);
        match word {
            "mark" => head.mark = Some(parse_mark(arg)?),
            "author" => head.author = Some(parse_ident(arg)?),
            "committer" => head.committer = Some(parse_ident(arg)?),
            "encoding" => {}
            "from" => {
                let oid = self.resolve_ref(context, arg)?;
                *tree = tree_of(context, oid)?;
                head.parents.push(oid);
            }
            "merge" => head.parents.push(self.resolve_ref(context, arg)?),
            "data" => head.message = Some(read_data(cursor, arg)?),
            "N" => {
                return Err(GitError::Unsupported {
                    command: "fast-import note modifications are not implemented".to_owned(),
                });
            }
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("bad commit line {word:?}"),
                });
            }
        }
        Ok(())
    }

    /// Applies one `M`/`D`/`R`/`C`/`deleteall` line to a commit tree map.
    fn apply_file_op(
        &mut self,
        context: &ImportCx<'_>,
        line: &[u8],
        tree: &mut BTreeMap<Vec<u8>, (TreeMode, Oid)>,
    ) -> Result<(), GitError> {
        if line == b"deleteall".as_slice() {
            tree.clear();
            return Ok(());
        }
        let (word, arg) = split_command(line);
        match word {
            "M" => {
                let (mode_text, data_path) = split_field(arg)?;
                let (ref_text, path_text) = split_field(data_path)?;
                let mode = parse_file_mode(mode_text)?;
                let oid = self.resolve_data_ref(context, mode, ref_text)?;
                let path = unquote_path(path_text)?;
                if path.is_empty() {
                    return Err(GitError::Invalid {
                        detail: "M needs a path".to_owned(),
                    });
                }
                tree.insert(path, (mode, oid));
            }
            "D" => {
                let path = unquote_path(arg)?;
                if tree.remove(&path).is_none() {
                    return Err(GitError::Invalid {
                        detail: format!("D removes missing path {path:?}"),
                    });
                }
            }
            "R" | "C" => {
                let (source, dest) = split_quoted_pair(arg)?;
                let entry = tree
                    .get(&source)
                    .copied()
                    .ok_or_else(|| GitError::Invalid {
                        detail: format!("{word} reads missing path {source:?}"),
                    })?;
                if word == "R" {
                    tree.remove(&source);
                }
                tree.insert(dest, entry);
            }
            _ => {
                return Err(GitError::Invalid {
                    detail: format!("bad file operation {word:?}"),
                });
            }
        }
        Ok(())
    }

    /// Resolves a `from`/`merge` value: a mark, a pending ref, or any
    /// revision the store already resolves. The result must be a commit.
    fn resolve_ref(&self, context: &ImportCx<'_>, arg: &[u8]) -> Result<Oid, GitError> {
        let text = std::str::from_utf8(arg).map_err(|_| GitError::Invalid {
            detail: "from value is not UTF-8".to_owned(),
        })?;
        if let Some(digits) = text.strip_prefix(':') {
            let oid = self.mark_oid(digits, text)?;
            commit_record(context.store, oid)?;
            return Ok(oid);
        }
        if text.starts_with("refs/") || !text.contains(' ') {
            for candidate in [text.to_owned(), format!("refs/heads/{text}")] {
                if candidate.starts_with("refs/")
                    && let Some(oid) = self.refs.get(candidate.as_bytes()).copied().flatten()
                {
                    commit_record(context.store, oid)?;
                    return Ok(oid);
                }
            }
        }
        let oid = resolve_rev(context.store, context.kind, text)?;
        commit_record(context.store, oid)?;
        Ok(oid)
    }

    /// Looks up one `:mark` digits string in the mark table.
    fn mark_oid(&self, digits: &str, text: &str) -> Result<Oid, GitError> {
        let number: u64 = digits.parse().map_err(|_| GitError::Invalid {
            detail: format!("bad mark {text:?}"),
        })?;
        self.marks
            .get(&number)
            .copied()
            .ok_or_else(|| GitError::Invalid {
                detail: format!("mark :{number} is not defined"),
            })
    }

    /// Resolves an `M` data reference: a defined mark or a stored object.
    /// Gitlink entries may name any object id; blob modes need the stored
    /// bytes to exist.
    fn resolve_data_ref(
        &self,
        context: &ImportCx<'_>,
        mode: TreeMode,
        arg: &[u8],
    ) -> Result<Oid, GitError> {
        let text = std::str::from_utf8(arg).map_err(|_| GitError::Invalid {
            detail: "M data reference is not UTF-8".to_owned(),
        })?;
        if let Some(digits) = text.strip_prefix(':') {
            return self.mark_oid(digits, text);
        }
        let oid = ruk_git::parse_oid_for(text, context.kind)?;
        if mode != TreeMode::Gitlink {
            read_object_bytes(context.store, oid)?;
        }
        Ok(oid)
    }

    /// Reads a `tag <name>` command: lightweight without data, annotated
    /// with it.
    fn read_tag(
        &mut self,
        context: &ImportCx<'_>,
        cursor: &mut Cursor<'_>,
        rest: &[u8],
    ) -> Result<(), GitError> {
        let name_text = std::str::from_utf8(rest).map_err(|_| GitError::Invalid {
            detail: "tag name is not UTF-8".to_owned(),
        })?;
        let full = if name_text.starts_with("refs/") {
            name_text.to_owned()
        } else {
            format!("refs/tags/{name_text}")
        };
        RefName::new(full.as_str()).map_err(|err| GitError::Invalid {
            detail: format!("bad tag name: {err}"),
        })?;
        let mut from = None;
        let mut tagger: Option<Signature> = None;
        let mut message = None;
        while let Some(line) = cursor.read_line()? {
            if is_command(&line) {
                cursor.push_back(line);
                break;
            }
            if line.is_empty() {
                continue;
            }
            let (word, arg) = split_command(&line);
            match word {
                "from" => from = Some(self.resolve_ref(context, arg)?),
                "tagger" => tagger = Some(parse_ident(arg)?),
                "data" => message = Some(read_data(cursor, arg)?),
                _ => {
                    return Err(GitError::Invalid {
                        detail: format!("bad tag line {word:?}"),
                    });
                }
            }
        }
        let pointed = match (from, message) {
            (Some(target), Some(message)) => {
                let (object_kind, _) = read_object_bytes(context.store, target)?;
                let type_name = match object_kind {
                    ObjectKind::Blob => "blob",
                    ObjectKind::Tree => "tree",
                    ObjectKind::Commit => "commit",
                    ObjectKind::Tag => "tag",
                    ObjectKind::Conflict => {
                        return Err(GitError::Invalid {
                            detail: "cannot tag a conflict object".to_owned(),
                        });
                    }
                };
                let short = full.trim_start_matches("refs/tags/");
                let payload = tag_payload(
                    &target.to_hex(),
                    type_name,
                    short,
                    tagger.as_ref(),
                    &message,
                );
                store_object(context.store, ObjectKind::Tag, payload)?
            }
            (Some(target), None) => target,
            (None, _) => {
                return Err(GitError::Invalid {
                    detail: "tag needs a from line".to_owned(),
                });
            }
        };
        self.refs.insert(full.into_bytes(), Some(pointed));
        Ok(())
    }

    /// Reads a `reset <ref>` command with its optional `from` line.
    fn read_reset(
        &mut self,
        context: &ImportCx<'_>,
        cursor: &mut Cursor<'_>,
        rest: &[u8],
    ) -> Result<(), GitError> {
        let ref_text = std::str::from_utf8(rest).map_err(|_| GitError::Invalid {
            detail: "reset ref is not UTF-8".to_owned(),
        })?;
        if !ref_text.starts_with("refs/") {
            return Err(GitError::Invalid {
                detail: format!("reset ref {ref_text:?} is not a full refs/ name"),
            });
        }
        RefName::new(ref_text).map_err(|err| GitError::Invalid {
            detail: format!("bad reset ref: {err}"),
        })?;
        let mut target = None;
        if let Some(line) = cursor.read_line()? {
            if line.is_empty() {
                // A blank line ends the command without a target.
            } else if is_command(&line) {
                cursor.push_back(line);
            } else {
                let (word, arg) = split_command(&line);
                if word == "from" {
                    target = Some(self.resolve_ref(context, arg)?);
                } else {
                    cursor.push_back(line);
                }
            }
        }
        self.refs.insert(ref_text.as_bytes().to_vec(), target);
        Ok(())
    }
}

/// One commit command's headers: idents, parents, message, and mark.
#[derive(Debug, Default)]
struct CommitHead {
    /// Optional `mark` number for later references.
    mark: Option<u64>,
    /// Explicit `author` ident, if given.
    author: Option<Signature>,
    /// Explicit `committer` ident, if given.
    committer: Option<Signature>,
    /// `from` parent first, then `merge` parents.
    parents: Vec<Oid>,
    /// Message `data` block.
    message: Option<Vec<u8>>,
}

/// Builds the tree, stores the commit, and records its ref and mark.
fn finish_commit(
    import: &mut Importer,
    context: &ImportCx<'_>,
    ref_text: &str,
    head: CommitHead,
    tree: &BTreeMap<Vec<u8>, (TreeMode, Oid)>,
) -> Result<(), GitError> {
    let Some(message) = head.message else {
        return Err(GitError::Invalid {
            detail: "commit needs a message data block".to_owned(),
        });
    };
    let author = match head.author {
        Some(ident) => ident,
        None => identity(context.ctx, IdentityRole::Author)?,
    };
    let committer = match head.committer {
        Some(ident) => ident,
        None => author.clone(),
    };
    let tree_oid = build_tree(context, tree)?;
    let parents: Vec<String> = head.parents.iter().map(|parent| parent.to_hex()).collect();
    let payload = commit_payload(&tree_oid.to_hex(), &parents, &author, &committer, &message);
    let oid = store_commit(context.store, &payload)?;
    if let Some(mark) = head.mark {
        import.remember(mark, oid);
    }
    import.refs.insert(ref_text.as_bytes().to_vec(), Some(oid));
    Ok(())
}

/// Reports whether a commit-body line is a file operation.
fn is_file_op(line: &[u8]) -> bool {
    if line == b"deleteall".as_slice() {
        return true;
    }
    let (word, _) = split_command(line);
    matches!(word, "M" | "D" | "R" | "C")
}

/// Splits one stream line into its first word and the remaining bytes.
fn split_command(line: &[u8]) -> (&str, &[u8]) {
    match line.iter().position(|byte| *byte == b' ') {
        Some(index) => (
            std::str::from_utf8(&line[..index]).unwrap_or(""),
            &line[index + 1..],
        ),
        None => (std::str::from_utf8(line).unwrap_or(""), &[]),
    }
}

/// Splits one `M`-line remainder into its next field and the rest.
fn split_field(arg: &[u8]) -> Result<(&[u8], &[u8]), GitError> {
    arg.iter()
        .position(|byte| *byte == b' ')
        .map(|index| (&arg[..index], &arg[index + 1..]))
        .ok_or_else(|| GitError::Invalid {
            detail: format!("bad M line {arg:?}"),
        })
}

/// Reports whether a line opens a new top-level stream command.
fn is_command(line: &[u8]) -> bool {
    let (word, _) = split_command(line);
    COMMANDS.contains(&word)
}

/// Parses a `:mark` number from a `mark` line argument.
fn parse_mark(arg: &[u8]) -> Result<u64, GitError> {
    let text = std::str::from_utf8(arg).map_err(|_| GitError::Invalid {
        detail: "mark is not UTF-8".to_owned(),
    })?;
    text.strip_prefix(':')
        .ok_or_else(|| GitError::Invalid {
            detail: format!("bad mark {text:?}"),
        })
        .and_then(|digits| {
            digits.parse().map_err(|_| GitError::Invalid {
                detail: format!("bad mark {text:?}"),
            })
        })
}

/// Parses one marks-file line (`:mark SP hex`).
fn parse_marks_line(line: &[u8], kind: HashKind) -> Result<(u64, Oid), GitError> {
    let (mark_text, hex) = split_field(line).map_err(|_| GitError::Invalid {
        detail: format!("bad marks line {line:?}"),
    })?;
    let mark = parse_mark(mark_text)?;
    let text = std::str::from_utf8(hex).map_err(|_| GitError::Invalid {
        detail: format!("bad marks line {line:?}"),
    })?;
    Ok((mark, ruk_git::parse_oid_for(text, kind)?))
}

/// Parses an `author`/`committer`/`tagger` ident line.
fn parse_ident(arg: &[u8]) -> Result<Signature, GitError> {
    Signature::parse(arg).map_err(|err| GitError::Invalid {
        detail: format!("bad ident: {err}"),
    })
}

/// Reads a `data` block: `data <count>` raw bytes or a `data <<marker`
/// heredoc.
fn read_data(cursor: &mut Cursor<'_>, arg: &[u8]) -> Result<Vec<u8>, GitError> {
    let text = std::str::from_utf8(arg).map_err(|_| GitError::Invalid {
        detail: "data line is not UTF-8".to_owned(),
    })?;
    if let Some(marker) = text.strip_prefix("<<") {
        let mut out = Vec::new();
        loop {
            let line = cursor.read_line()?.ok_or_else(|| GitError::Invalid {
                detail: "heredoc data runs past end of input".to_owned(),
            })?;
            if line.as_slice() == marker.as_bytes() {
                return Ok(out);
            }
            out.extend_from_slice(&line);
            out.push(b'\n');
        }
    }
    let count: usize = text.parse().map_err(|_| GitError::Invalid {
        detail: format!("bad data count {text:?}"),
    })?;
    let limit = usize::try_from(super::state::MAX_OBJECT_BYTES).unwrap_or(usize::MAX);
    if count > limit {
        return Err(GitError::Limit {
            detail: "data block exceeds the object limit".to_owned(),
        });
    }
    cursor.read_exact(count)
}

/// Parses a fast-import file mode: full octal spellings plus the `644`
/// and `755` shorthands.
fn parse_file_mode(arg: &[u8]) -> Result<TreeMode, GitError> {
    if let Some(mode) = TreeMode::parse(arg)
        && mode != TreeMode::Tree
    {
        return Ok(mode);
    }
    match arg {
        b"644" => Ok(TreeMode::Regular),
        b"755" => Ok(TreeMode::Executable),
        _ => Err(GitError::Invalid {
            detail: format!("bad file mode {arg:?}"),
        }),
    }
}

/// Reverses [`quote_path`]: plain paths pass through, quoted paths decode
/// C escapes (`\\`, `\"`, `\n`, `\t`, `\ooo`).
fn unquote_path(arg: &[u8]) -> Result<Vec<u8>, GitError> {
    if !arg.starts_with(b"\"") {
        return Ok(arg.to_vec());
    }
    if arg.len() < 2 || !arg.ends_with(b"\"") {
        return Err(GitError::Invalid {
            detail: format!("bad quoted path {arg:?}"),
        });
    }
    let mut out = Vec::new();
    let mut bytes = &arg[1..arg.len() - 1];
    while let Some((first, rest)) = bytes.split_first() {
        bytes = rest;
        if *first != b'\\' {
            out.push(*first);
            continue;
        }
        let (escaped, tail) = bytes.split_first().ok_or_else(|| GitError::Invalid {
            detail: format!("bad quoted path {arg:?}"),
        })?;
        bytes = tail;
        match escaped {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'\\' => out.push(b'\\'),
            b'"' => out.push(b'"'),
            _ => out.push(parse_octal_escape(arg, *escaped, &mut bytes)?),
        }
    }
    Ok(out)
}

/// Parses one `\ooo` octal escape, returning the byte and advancing past
/// its two trailing digits.
fn parse_octal_escape(arg: &[u8], first: u8, bytes: &mut &[u8]) -> Result<u8, GitError> {
    if !first.is_ascii_digit() || bytes.len() < 2 {
        return Err(GitError::Invalid {
            detail: format!("bad quoted path {arg:?}"),
        });
    }
    let bad = || GitError::Invalid {
        detail: format!("bad quoted path {arg:?}"),
    };
    let mut value = u32::from(first - b'0');
    for _ in 0..2 {
        let (digit, tail) = bytes.split_first().ok_or_else(bad)?;
        if !digit.is_ascii_digit() {
            return Err(bad());
        }
        value = value * 8 + u32::from(*digit - b'0');
        *bytes = tail;
    }
    u8::try_from(value).map_err(|_| bad())
}

/// Splits an `R`/`C` line into its source and destination paths, decoding
/// either side's quoting.
fn split_quoted_pair(arg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), GitError> {
    if arg.starts_with(b"\"") {
        let end = find_quoted_end(arg)?;
        let source = unquote_path(&arg[..end])?;
        let dest_text = arg
            .get(end..)
            .and_then(|tail| tail.strip_prefix(b" "))
            .ok_or_else(|| GitError::Invalid {
                detail: format!("bad rename line {arg:?}"),
            })?;
        return Ok((source, unquote_path(dest_text)?));
    }
    let (source, dest) = split_field(arg).map_err(|_| GitError::Invalid {
        detail: format!("bad rename line {arg:?}"),
    })?;
    Ok((source.to_vec(), unquote_path(dest)?))
}

/// Finds the end offset (one past the closing quote) of a quoted path at
/// the start of a rename line.
fn find_quoted_end(arg: &[u8]) -> Result<usize, GitError> {
    let mut tail = &arg[1..];
    while let Some((byte, rest)) = tail.split_first() {
        tail = rest;
        match byte {
            b'\\' => {
                tail = tail.get(1..).ok_or_else(|| GitError::Invalid {
                    detail: format!("bad rename line {arg:?}"),
                })?;
            }
            b'"' => return Ok(arg.len() - tail.len()),
            _ => {}
        }
    }
    Err(GitError::Invalid {
        detail: format!("bad rename line {arg:?}"),
    })
}

/// Flattens one commit's tree into a path map for file-operation editing.
fn tree_of(
    context: &ImportCx<'_>,
    oid: Oid,
) -> Result<BTreeMap<Vec<u8>, (TreeMode, Oid)>, GitError> {
    let tree = commit_tree_oid(&commit_record(context.store, oid)?)?;
    let mut map = BTreeMap::new();
    for (path, mode, entry) in flatten_tree(context.store, context.kind, tree)? {
        map.insert(path, (mode, entry));
    }
    Ok(map)
}

/// Builds and publishes the tree for one imported commit's file map.
fn build_tree(
    context: &ImportCx<'_>,
    tree: &BTreeMap<Vec<u8>, (TreeMode, Oid)>,
) -> Result<Oid, GitError> {
    let mut rows = Vec::with_capacity(tree.len());
    for (path, (mode, oid)) in tree {
        let entry = IndexEntry::new(*oid, mode.as_index_mode()?, None, IndexFlags::default())
            .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
        rows.push((path.clone(), entry));
    }
    build_index_tree(context.store, context.kind, &rows)
}

/// Stores one blob body, returning its object id.
fn store_blob(store: &Store, body: &[u8]) -> Result<Oid, GitError> {
    let body_len = u64::try_from(body.len()).map_err(|_| GitError::Limit {
        detail: "blob body exceeds the length range".to_owned(),
    })?;
    let prepared = store
        .prepare(ObjectKind::Blob, body_len, std::io::Cursor::new(body), None)
        .map_err(GitError::from)?;
    let oid = prepared.oid();
    store
        .publish(
            vec![prepared],
            &[],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .map_err(GitError::from)?;
    Ok(oid)
}

/// Stores one commit payload with its change record, mirroring
/// `hash-object -t commit` so history walks see imported commits.
fn store_commit(store: &Store, payload: &[u8]) -> Result<Oid, GitError> {
    let kind = store.hash_kind();
    let oid = kind
        .hash_git_object("commit", payload)
        .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
    let records = Records::new(store);
    if records
        .get_commit(&Head::Git { oid })
        .map_err(GitError::from)?
        .is_some()
    {
        return store_object(store, ObjectKind::Commit, payload.to_vec()).map(|_| oid);
    }
    let mut batch = records.batch_preparer();
    batch
        .add_import_git(payload.to_vec(), None)
        .map_err(GitError::from)?;
    let done = batch.finish().map_err(GitError::from)?;
    store
        .publish(
            done.prepared_objects,
            &done.mutations,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .map_err(GitError::from)?;
    Ok(oid)
}

/// Compares two commit ranges commit-by-commit.
///
/// Oracle: `git/builtin/range-diff.c`. Each range is `old..new`; commits
/// pair by first-parent content fingerprint, then by subject. The output
/// is only the pairing (`=` same patch, `!` same subject, `<` old-only,
/// `>` new-only): patch-of-patch hunks are a named gap.
pub(crate) fn range_diff(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "no-patch",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-color",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    // Mapping lines are the only output, so `--no-patch` is trivially
    // satisfied; `--no-color` matches the never-colorized renderer.
    let _ = (opts.is_set("no-patch"), opts.is_set("no-color"));
    if opts.positionals.len() != 2 {
        return Err(GitError::Usage {
            detail: "usage: range-diff <old..new> <old..new>".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let left = range_commits(store, kind, &opts.positionals[0])?;
    let right = range_commits(store, kind, &opts.positionals[1])?;
    let left_prints = print_list(store, kind, &left)?;
    let right_prints = print_list(store, kind, &right)?;
    let pair_of = match_ranges(&left_prints, &right_prints);
    let mut out = Vec::new();
    let paired_right: HashSet<usize> = pair_of.iter().filter_map(|slot| *slot).collect();
    for (left_index, (oid, _)) in left.iter().enumerate() {
        let left_num = left_index + 1;
        match pair_of[left_index] {
            Some(right_index) => {
                let (right_oid, right_record) = &right[right_index];
                let mark = if left_prints[left_index].0 == right_prints[right_index].0 {
                    "="
                } else {
                    "!"
                };
                out.extend_from_slice(
                    format!(
                        "{left_num}:  {} {mark} {}:  {} {}\n",
                        short_hex(oid),
                        right_index + 1,
                        short_hex(right_oid),
                        subject_of(right_record)
                    )
                    .as_bytes(),
                );
            }
            None => {
                out.extend_from_slice(
                    format!(
                        "{left_num}:  {} < -:  -------- {}\n",
                        short_hex(oid),
                        left_prints[left_index].1
                    )
                    .as_bytes(),
                );
            }
        }
    }
    for (right_index, (oid, record)) in right.iter().enumerate() {
        if !paired_right.contains(&right_index) {
            out.extend_from_slice(
                format!(
                    "-:  -------- > {}:  {} {}\n",
                    right_index + 1,
                    short_hex(oid),
                    subject_of(record)
                )
                .as_bytes(),
            );
        }
    }
    Ok(out)
}

/// Fingerprints and subjects for one range, oldest first.
fn print_list(
    store: &Store,
    kind: HashKind,
    commits: &[(Oid, CommitRecord)],
) -> Result<Vec<(String, String)>, GitError> {
    commits
        .iter()
        .map(|(oid, record)| Ok((fingerprint(store, kind, *oid, record)?, subject_of(record))))
        .collect()
}

/// Pairs two ranges: identical fingerprints first, then equal subjects,
/// both in range order. Returns the right index per left index.
fn match_ranges(
    left_prints: &[(String, String)],
    right_prints: &[(String, String)],
) -> Vec<Option<usize>> {
    let mut waiting: HashMap<&str, VecDeque<usize>> = HashMap::new();
    for (index, (print, _)) in right_prints.iter().enumerate() {
        waiting.entry(print.as_str()).or_default().push_back(index);
    }
    let mut pair_of: Vec<Option<usize>> = vec![None; left_prints.len()];
    let mut taken = vec![false; right_prints.len()];
    for (left_index, (print, _)) in left_prints.iter().enumerate() {
        if let Some(queue) = waiting.get_mut(print.as_str()) {
            pair_queued(queue, &mut taken, &mut pair_of[left_index]);
        }
    }
    let mut subject_waiting: HashMap<&str, VecDeque<usize>> = HashMap::new();
    for (index, (_, subject)) in right_prints.iter().enumerate() {
        if !taken[index] {
            subject_waiting
                .entry(subject.as_str())
                .or_default()
                .push_back(index);
        }
    }
    for (left_index, (_, subject)) in left_prints.iter().enumerate() {
        if pair_of[left_index].is_some() {
            continue;
        }
        if let Some(queue) = subject_waiting.get_mut(subject.as_str()) {
            pair_queued(queue, &mut taken, &mut pair_of[left_index]);
        }
    }
    pair_of
}

/// Takes the first untaken queue entry as the pair for one side.
fn pair_queued(queue: &mut VecDeque<usize>, taken: &mut [bool], slot: &mut Option<usize>) {
    while let Some(index) = queue.pop_front() {
        if !taken[index] {
            taken[index] = true;
            *slot = Some(index);
            return;
        }
    }
}

/// Lists the commits of one `old..new` range, oldest first.
fn range_commits(
    store: &Store,
    kind: HashKind,
    range: &str,
) -> Result<Vec<(Oid, CommitRecord)>, GitError> {
    if range.contains("...") {
        return Err(GitError::Usage {
            detail: format!("range-diff needs A..B ranges, got {range:?}"),
        });
    }
    let (old, new) = range.split_once("..").ok_or_else(|| GitError::Usage {
        detail: format!("range-diff needs A..B ranges, got {range:?}"),
    })?;
    if old.is_empty() || new.is_empty() {
        return Err(GitError::Usage {
            detail: format!("range-diff needs A..B ranges, got {range:?}"),
        });
    }
    let from = resolve_local(store, kind, old)?;
    let to = resolve_local(store, kind, new)?;
    commit_record(store, from)?;
    commit_record(store, to)?;
    let mut commits = walk_history_excluding(store, &[to], &[from], None)?;
    commits.reverse();
    Ok(commits)
}

/// Hashes one commit's first-parent content change the way `cherry`
/// builds patch ids: sorted `path NUL old NUL new NUL` bytes per changed
/// path, hashed as a blob.
fn fingerprint(
    store: &Store,
    kind: HashKind,
    oid: Oid,
    record: &CommitRecord,
) -> Result<String, GitError> {
    let new_tree = commit_tree_oid(record)?;
    let new_map = flat_records(store, kind, Some(new_tree))?;
    let old_map = match record
        .parents()
        .iter()
        .filter_map(Head::as_git)
        .copied()
        .next()
    {
        None => BTreeMap::new(),
        Some(parent) => {
            let tree = commit_tree_oid(&commit_record(store, parent)?)?;
            flat_records(store, kind, Some(tree))?
        }
    };
    let mut keys: Vec<&Vec<u8>> = new_map.keys().chain(old_map.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut canonical = Vec::new();
    for key in keys {
        let old = old_map.get(key);
        let new = new_map.get(key);
        if old == new {
            continue;
        }
        canonical.extend_from_slice(b"path:");
        canonical.extend_from_slice(key);
        canonical.push(0);
        for side in [old, new] {
            match side {
                None => canonical.extend_from_slice(b"absent\0"),
                Some((mode, entry)) => {
                    let bytes = blob_bytes(store, *mode, *entry)?;
                    canonical.extend_from_slice(&bytes);
                    canonical.push(0);
                }
            }
        }
    }
    kind.hash_git_object("blob", &canonical)
        .map(|print| print.to_hex())
        .map_err(|err| GitError::Invalid {
            detail: format!("patch fingerprint failed for {}: {err}", oid.to_hex()),
        })
}

/// Reads the bytes one fingerprint side hashes: blob contents, or the
/// commit hex for gitlinks.
fn blob_bytes(store: &Store, mode: TreeMode, oid: Oid) -> Result<Vec<u8>, GitError> {
    if mode == TreeMode::Gitlink {
        return Ok(oid.to_hex().into_bytes());
    }
    Ok(read_object_bytes(store, oid)?.1)
}

/// Flattens one optional tree into a path map, empty when absent.
fn flat_records(
    store: &Store,
    kind: HashKind,
    tree: Option<Oid>,
) -> Result<BTreeMap<Vec<u8>, (TreeMode, Oid)>, GitError> {
    match tree {
        None => Ok(BTreeMap::new()),
        Some(oid) => flatten_tree(store, kind, oid).map(|entries| {
            entries
                .into_iter()
                .map(|(path, mode, entry)| (path, (mode, entry)))
                .collect()
        }),
    }
}

/// Takes the first message line for one-line output.
fn subject_of(record: &CommitRecord) -> String {
    let message = String::from_utf8_lossy(record.message());
    message.split('\n').next().unwrap_or("").to_owned()
}

/// Shortens one object id for one-line output.
fn short_hex(oid: &Oid) -> String {
    oid.to_hex().chars().take(7).collect()
}

/// Prints the pull-request mail template for a range.
///
/// Oracle: `git/builtin/request-pull.c`. The template names the base, the
/// end subject, the source URL, one shortlog line per commit (oldest
/// first), and the overall diffstat. `-p` is refused: patch text has no
/// cross-module renderer to reuse.
pub(crate) fn request_pull(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "patch",
        short: Some('p'),
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if opts.is_set("patch") {
        return Err(GitError::Unsupported {
            command: "request-pull -p needs patch text this store does not render".to_owned(),
        });
    }
    let (start_text, url, end_text) = match opts.positionals.as_slice() {
        [start, url] => (start.clone(), url.clone(), None),
        [start, url, end] => (start.clone(), url.clone(), Some(end.clone())),
        _ => {
            return Err(GitError::Usage {
                detail: "usage: request-pull <start> <url> [<end>]".to_owned(),
            });
        }
    };
    if url.is_empty() {
        return Err(GitError::Invalid {
            detail: "request-pull needs a source url".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let start = resolve_local(store, kind, &start_text)?;
    let start_record = commit_record(store, start)?;
    let end = match end_text {
        Some(text) => {
            let oid = resolve_local(store, kind, &text)?;
            commit_record(store, oid)?;
            oid
        }
        None => {
            let oid = head_oid(store)?;
            commit_record(store, oid)?;
            oid
        }
    };
    let end_record = commit_record(store, end)?;
    let mut commits = walk_history_excluding(store, &[end], &[start], None)?;
    commits.reverse();
    let mut out = format!(
        "The following changes since commit {}:\n\n  {}\n\nare available in the Git repository at:\n\n  {}\n\nfor you to fetch changes up to {}:\n\n",
        start.to_hex(),
        subject_of(&end_record),
        url,
        end.to_hex()
    )
    .into_bytes();
    for (oid, record) in &commits {
        out.extend_from_slice(format!("{} {}\n", short_hex(oid), subject_of(record)).as_bytes());
    }
    out.extend_from_slice(b"----------------------------------------------------------------\n");
    let start_tree = commit_tree_oid(&start_record)?;
    let end_tree = commit_tree_oid(&end_record)?;
    out.extend_from_slice(&render_file_stat(&tree_file_changes(
        ctx,
        Some(start_tree),
        end_tree,
    )?));
    Ok(out)
}
