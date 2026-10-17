use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::apply::fault;
use super::*;
use crate::bytes::ByteString;
use crate::ids::{HashKind, Oid};
use crate::index::{FileMode, RepoPath};
use crate::store::{
    FactExpectation, FactMutation, FactTable, ObjectKind, PreparationBudget, Store,
};
use crate::workcopy::journal_state::{ApplyPhase, JournalState, ensure_idle};
use crate::workcopy::lfs::LfsMode;
use crate::workspace::{Scope, WorkspaceStamp};
use crate::{CoreError, ErrorCode, WorkspaceId};

struct Fixture {
    dir: PathBuf,
    store: Option<Store>,
    ws: WorkspaceId,
    row: std::cell::RefCell<Vec<u8>>,
    epoch: std::cell::Cell<u64>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.store.take());
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("ruk-wcj-{}", WorkspaceId::generate()));
        fs::create_dir_all(dir.join(".ruk")).expect("workspace root");
        let store =
            Store::create(&dir.join(".ruk/store"), HashKind::Sha1, budget()).expect("create store");
        let ws = WorkspaceId::generate();
        let row = b"workspace-row-0".to_vec();
        let insert = FactMutation {
            table: FactTable::Workspaces,
            key: ws.as_bytes().to_vec(),
            expected: FactExpectation::Absent,
            value: Some(row.clone()),
        };
        store
            .publish(Vec::new(), &[insert])
            .expect("register workspace");
        Self {
            dir,
            store: Some(store),
            ws,
            row: std::cell::RefCell::new(row),
            epoch: std::cell::Cell::new(0),
        }
    }

    fn store(&self) -> &Store {
        self.store.as_ref().expect("store is open")
    }

    fn reopen(&mut self) {
        drop(self.store.take());
        self.store =
            Some(Store::open(&self.dir.join(".ruk/store"), budget()).expect("reopen store"));
    }

    fn fence(&self) -> WorkspaceFence {
        WorkspaceFence::new(
            self.ws,
            self.row.borrow().clone(),
            WorkspaceStamp {
                sequence: 0,
                lease_epoch: self.epoch.get(),
            },
        )
    }

    /// Simulates `ws.take`: the workspace row moves to a new epoch.
    fn take(&self) {
        let next = format!("workspace-row-{}", self.epoch.get() + 1).into_bytes();
        let swap = FactMutation {
            table: FactTable::Workspaces,
            key: self.ws.as_bytes().to_vec(),
            expected: FactExpectation::Value(self.row.borrow().clone()),
            value: Some(next.clone()),
        };
        self.store()
            .publish(Vec::new(), &[swap])
            .expect("take workspace");
        *self.row.borrow_mut() = next;
        self.epoch.set(self.epoch.get() + 1);
    }

    fn blob(&self, bytes: &[u8]) -> Oid {
        let len = u64::try_from(bytes.len()).expect("length");
        let prepared = self
            .store()
            .prepare(ObjectKind::Blob, len, bytes, None)
            .expect("prepare blob");
        let oid = prepared.oid();
        self.store()
            .publish(vec![prepared], &[])
            .expect("publish blob");
        oid
    }

    fn full(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }

    fn put(&self, rel: &str, bytes: &[u8]) {
        let full = self.full(rel);
        fs::create_dir_all(full.parent().expect("parent")).expect("parents");
        fs::write(full, bytes).expect("write file");
    }

    fn get(&self, rel: &str) -> Option<Vec<u8>> {
        fs::read(self.full(rel)).ok()
    }

    fn open_journals(&self) -> Vec<WorkspaceId> {
        open_journals(self.store()).expect("scan journals")
    }
}

fn budget() -> Arc<PreparationBudget> {
    Arc::new(PreparationBudget::reference_defaults())
}

fn path(text: &str) -> RepoPath {
    RepoPath::new(text.as_bytes()).expect("valid path")
}

fn entry(mode: FileMode, oid: Oid) -> ManifestEntry {
    ManifestEntry { mode, oid }
}

fn plan_entry(
    text: &str,
    expected: Option<ManifestEntry>,
    target: Option<ManifestEntry>,
) -> PlanEntry {
    PlanEntry {
        path: path(text),
        expected,
        target,
        target_link: None,
    }
}

fn plan(fx: &Fixture, entries: Vec<PlanEntry>, discard: &[&str]) -> MaterializePlan {
    MaterializePlan {
        workspace: fx.ws,
        root: fx.dir.clone(),
        scope: Scope::Full,
        entries,
        discard: discard.iter().map(|text| path(text)).collect(),
        target_objects: Vec::new(),
        lfs: LfsMode::Deny,
    }
}

fn code<T: std::fmt::Debug>(result: Result<T, CoreError>) -> CoreError {
    match result {
        Ok(value) => panic!("unexpected success: {value:?}"),
        Err(error) => error,
    }
}

#[cfg(unix)]
fn is_exec(fx: &Fixture, rel: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(fx.full(rel))
        .expect("stat")
        .permissions()
        .mode()
        & 0o100
        != 0
}

#[cfg(unix)]
fn link_of(fx: &Fixture, rel: &str) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStringExt;
    fs::read_link(fx.full(rel))
        .ok()
        .map(|target| target.into_os_string().into_vec())
}

/// Seeds the preimage worktree and returns a plan covering every
/// transition kind.
fn seed(fx: &Fixture) -> Vec<PlanEntry> {
    let regular = |bytes: &[u8]| entry(FileMode::Regular, fx.blob(bytes));
    fx.put("keep.txt", b"keep");
    fx.put("mod.txt", b"old");
    fx.put("del.txt", b"gone");
    fx.put("exec.sh", b"run");
    fx.put("swap", b"f");
    fx.put("dir/a.txt", b"a");
    fx.put("ren-from.txt", b"same");
    let mut entries = vec![
        plan_entry("mod.txt", Some(regular(b"old")), Some(regular(b"new"))),
        plan_entry("del.txt", Some(regular(b"gone")), None),
        plan_entry(
            "exec.sh",
            Some(regular(b"run")),
            Some(entry(FileMode::Executable, fx.blob(b"run"))),
        ),
        plan_entry("swap", Some(regular(b"f")), None),
        plan_entry("swap/inner.txt", None, Some(regular(b"inner"))),
        plan_entry("dir/a.txt", Some(regular(b"a")), None),
        plan_entry("dir", None, Some(regular(b"now file"))),
        plan_entry("new/deep/n.txt", None, Some(regular(b"created"))),
        plan_entry("ren-from.txt", Some(regular(b"same")), None),
        plan_entry("ren-to.txt", None, Some(regular(b"same"))),
        plan_entry(
            "sub",
            None,
            Some(entry(FileMode::Gitlink, fx.blob(b"foreign commit"))),
        ),
    ];
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("mod.txt", fx.full("link")).expect("symlink");
        entries.push(plan_entry(
            "link",
            Some(entry(FileMode::Symlink, fx.blob(b"mod.txt"))),
            Some(entry(FileMode::Symlink, fx.blob(b"keep.txt"))),
        ));
    }
    entries
}

fn assert_target(fx: &Fixture) {
    assert_eq!(fx.get("keep.txt").as_deref(), Some(&b"keep"[..]));
    assert_eq!(fx.get("mod.txt").as_deref(), Some(&b"new"[..]));
    assert_eq!(fx.get("del.txt"), None);
    assert_eq!(fx.get("exec.sh").as_deref(), Some(&b"run"[..]));
    assert_eq!(fx.get("swap/inner.txt").as_deref(), Some(&b"inner"[..]));
    assert_eq!(fx.get("dir").as_deref(), Some(&b"now file"[..]));
    assert_eq!(fx.get("new/deep/n.txt").as_deref(), Some(&b"created"[..]));
    assert_eq!(fx.get("ren-from.txt"), None);
    assert_eq!(fx.get("ren-to.txt").as_deref(), Some(&b"same"[..]));
    assert!(fx.full("sub").is_dir());
    #[cfg(unix)]
    {
        assert!(is_exec(fx, "exec.sh"));
        assert_eq!(link_of(fx, "link").as_deref(), Some(&b"keep.txt"[..]));
    }
    assert_no_temps(&fx.dir);
}

fn assert_preimage(fx: &Fixture) {
    assert_eq!(fx.get("keep.txt").as_deref(), Some(&b"keep"[..]));
    assert_eq!(fx.get("mod.txt").as_deref(), Some(&b"old"[..]));
    assert_eq!(fx.get("del.txt").as_deref(), Some(&b"gone"[..]));
    assert_eq!(fx.get("exec.sh").as_deref(), Some(&b"run"[..]));
    assert_eq!(fx.get("swap").as_deref(), Some(&b"f"[..]));
    assert_eq!(fx.get("dir/a.txt").as_deref(), Some(&b"a"[..]));
    assert!(!fx.full("new").exists());
    assert_eq!(fx.get("ren-from.txt").as_deref(), Some(&b"same"[..]));
    assert_eq!(fx.get("ren-to.txt"), None);
    assert!(!fx.full("sub").exists());
    #[cfg(unix)]
    {
        assert!(!is_exec(fx, "exec.sh"));
        assert_eq!(link_of(fx, "link").as_deref(), Some(&b"mod.txt"[..]));
    }
    assert_no_temps(&fx.dir);
}

fn assert_no_temps(dir: &Path) {
    for child in fs::read_dir(dir).expect("list") {
        let child = child.expect("entry");
        let name = child.file_name().to_string_lossy().into_owned();
        assert!(
            !name.starts_with(".ruk-apply-"),
            "leftover temporary {name}"
        );
        let file_type = child.file_type().expect("type");
        if file_type.is_dir() && name != ".ruk" {
            assert_no_temps(&child.path());
        }
    }
}

/// Counts the physical steps of a full apply of the seeded plan.
fn step_count() -> u64 {
    let fx = Fixture::new();
    let entries = seed(&fx);
    let _armed = fault::arm(None);
    let mut session =
        begin_apply(fx.store(), plan(&fx, entries, &[]), fx.fence(), Vec::new()).expect("begin");
    session.execute().expect("execute");
    let steps = fault::count();
    session.finish(FinishBatch::default()).expect("finish");
    steps
}

/// Seeds, begins and crashes at `step`; returns the fixture with an open
/// journal after a reopen.
fn crashed_at(step: u64) -> Fixture {
    let mut fx = Fixture::new();
    let entries = seed(&fx);
    {
        let _armed = fault::arm(Some(step));
        let mut session = begin_apply(fx.store(), plan(&fx, entries, &[]), fx.fence(), Vec::new())
            .expect("begin");
        let error = code(session.execute());
        assert_eq!(error.code, ErrorCode::ECancelled, "step {step}");
    }
    assert!(is_applying(fx.store(), fx.ws).expect("applying"));
    let observed = JournalReader.observe(fx.store(), fx.ws).expect("observe");
    assert_eq!(observed.phase, ApplyPhase::Applying);
    assert_eq!(
        code(ensure_idle(&JournalReader, fx.store(), fx.ws)).code,
        ErrorCode::EWorkspaceApplying
    );
    fx.reopen();
    assert_eq!(fx.open_journals(), vec![fx.ws]);
    fx
}

#[test]
fn apply_records_transitions_reaches_target_and_clears_journal() {
    let fx = Fixture::new();
    let entries = seed(&fx);
    let mut session =
        begin_apply(fx.store(), plan(&fx, entries, &[]), fx.fence(), Vec::new()).expect("begin");
    let transition = |text: &str| {
        session
            .journal()
            .entries
            .iter()
            .find(|entry| entry.path == path(text))
            .map(|entry| entry.transition.clone())
    };
    assert_eq!(transition("mod.txt"), Some(Transition::Modify));
    assert_eq!(transition("del.txt"), Some(Transition::Delete));
    assert_eq!(transition("exec.sh"), Some(Transition::ModeChange));
    assert_eq!(transition("swap"), Some(Transition::DirFileSwap));
    assert_eq!(transition("dir"), Some(Transition::DirFileSwap));
    assert_eq!(transition("swap/inner.txt"), Some(Transition::Create));
    assert_eq!(
        transition("ren-to.txt"),
        Some(Transition::Rename {
            from: path("ren-from.txt")
        })
    );
    assert_eq!(transition("keep.txt"), None);
    #[cfg(unix)]
    assert_eq!(transition("link"), Some(Transition::SymlinkChange));
    assert_eq!(session.journal().state, ApplyState::Applying);
    session.execute().expect("execute");
    let next = b"workspace-row-moved".to_vec();
    let outcome = session
        .finish(FinishBatch {
            next_row: Some(next.clone()),
            extra: Vec::new(),
        })
        .expect("finish");
    assert!(outcome.changed.contains(&path("dir")));
    assert!(outcome.unresolved.is_empty());
    assert_target(&fx);
    assert!(!is_applying(fx.store(), fx.ws).expect("idle"));
    assert!(ensure_idle(&JournalReader, fx.store(), fx.ws).is_ok());
    assert_eq!(
        fx.store()
            .fact(FactTable::Workspaces, fx.ws.as_bytes())
            .expect("row"),
        Some(next)
    );
}

#[test]
fn crash_after_every_step_resumes_to_target() {
    let steps = step_count();
    assert!(
        steps > 10,
        "the seeded plan must exercise many steps, got {steps}"
    );
    for step in 0..steps {
        let fx = crashed_at(step);
        let report = recover(
            fx.store(),
            &fx.dir,
            fx.fence(),
            RecoveryAction::Resume,
            FinishBatch::default(),
        )
        .unwrap_or_else(|error| panic!("resume after step {step}: {error:?}"));
        assert!(report.unresolved.is_empty());
        assert_target(&fx);
        assert!(fx.open_journals().is_empty(), "step {step}");
    }
}

#[test]
fn crash_after_every_step_aborts_to_preimage() {
    let steps = step_count();
    for step in 0..steps {
        let fx = crashed_at(step);
        let report = recover(
            fx.store(),
            &fx.dir,
            fx.fence(),
            RecoveryAction::Abort,
            FinishBatch::default(),
        )
        .unwrap_or_else(|error| panic!("abort after step {step}: {error:?}"));
        assert!(report.unresolved.is_empty(), "step {step}: {report:?}");
        if fx.full("new").exists() {
            let kids: Vec<String> = std::fs::read_dir(fx.full("new"))
                .map(|rd| {
                    rd.flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            panic!("step {step} leaves new/ containing {kids:?}");
        }
        assert_preimage(&fx);
        assert!(fx.open_journals().is_empty());
    }
}

/// Executes every write, then "crashes" before the completing batch.
fn applied_unfinished() -> Fixture {
    let mut fx = Fixture::new();
    let entries = seed(&fx);
    {
        let mut session = begin_apply(fx.store(), plan(&fx, entries, &[]), fx.fence(), Vec::new())
            .expect("begin");
        session.execute().expect("execute");
    }
    fx.reopen();
    fx
}

#[test]
fn crash_before_finish_is_still_applying_and_resumes() {
    let fx = applied_unfinished();
    assert!(is_applying(fx.store(), fx.ws).expect("applying"));
    let report = recover(
        fx.store(),
        &fx.dir,
        fx.fence(),
        RecoveryAction::Resume,
        FinishBatch::default(),
    )
    .expect("resume");
    assert!(
        report.converged.is_empty(),
        "everything was already at target: {report:?}"
    );
    assert_target(&fx);
}

#[test]
fn external_edit_blocks_resume_and_survives_abort() {
    let fx = applied_unfinished();
    fx.put("mod.txt", b"mine");
    let error = code(recover(
        fx.store(),
        &fx.dir,
        fx.fence(),
        RecoveryAction::Resume,
        FinishBatch::default(),
    ));
    assert_eq!(error.code, ErrorCode::EWorkspaceRecovery);
    assert!(error.message.contains("mod.txt"), "{}", error.message);
    assert!(is_applying(fx.store(), fx.ws).expect("still applying"));
    let listed = inspect(fx.store(), &fx.dir, fx.ws)
        .expect("inspect")
        .expect("journal open");
    let edited: Vec<&RepoPath> = listed
        .iter()
        .filter(|report| report.external_edit)
        .map(|report| &report.path)
        .collect();
    assert_eq!(edited, vec![&path("mod.txt")]);

    let report = recover(
        fx.store(),
        &fx.dir,
        fx.fence(),
        RecoveryAction::Abort,
        FinishBatch::default(),
    )
    .expect("abort");
    assert_eq!(report.unresolved, vec![path("mod.txt")]);
    assert_eq!(fx.get("mod.txt").as_deref(), Some(&b"mine"[..]));
    assert_eq!(fx.get("del.txt").as_deref(), Some(&b"gone"[..]));
    assert_eq!(fx.get("dir/a.txt").as_deref(), Some(&b"a"[..]));
    assert_eq!(fx.get("swap").as_deref(), Some(&b"f"[..]));
    assert!(!fx.full("new").exists());
    assert!(fx.open_journals().is_empty());
}

#[test]
fn discard_overwrites_only_listed_external_edits() {
    let fx = applied_unfinished();
    fx.put("mod.txt", b"mine");
    let unlisted = RecoveryAction::Discard(BTreeSet::from([path("del.txt")]));
    let error = code(recover(
        fx.store(),
        &fx.dir,
        fx.fence(),
        unlisted,
        FinishBatch::default(),
    ));
    assert_eq!(error.code, ErrorCode::EWorkspaceRecovery);
    assert_eq!(fx.get("mod.txt").as_deref(), Some(&b"mine"[..]));
    let listed = RecoveryAction::Discard(BTreeSet::from([path("mod.txt")]));
    recover(
        fx.store(),
        &fx.dir,
        fx.fence(),
        listed,
        FinishBatch::default(),
    )
    .expect("discard");
    assert_target(&fx);
    assert!(fx.open_journals().is_empty());
}

#[test]
fn unsafe_overwrite_is_rejected_before_any_write_unless_discarded() {
    let fx = Fixture::new();
    let entries = seed(&fx);
    fx.put("mod.txt", b"dirty");
    let error = code(begin_apply(
        fx.store(),
        plan(&fx, entries.clone(), &[]),
        fx.fence(),
        Vec::new(),
    ));
    assert_eq!(error.code, ErrorCode::EDirty);
    assert!(error.message.contains("mod.txt"), "{}", error.message);
    assert!(!is_applying(fx.store(), fx.ws).expect("no journal"));
    assert!(!fx.full("new").exists());
    assert_eq!(fx.get("del.txt").as_deref(), Some(&b"gone"[..]));

    {
        let _armed = fault::arm(Some(3));
        let mut session = begin_apply(
            fx.store(),
            plan(&fx, entries, &["mod.txt"]),
            fx.fence(),
            Vec::new(),
        )
        .expect("begin with discard");
        assert_eq!(code(session.execute()).code, ErrorCode::ECancelled);
    }
    recover(
        fx.store(),
        &fx.dir,
        fx.fence(),
        RecoveryAction::Abort,
        FinishBatch::default(),
    )
    .expect("abort");
    assert_eq!(
        fx.get("mod.txt").as_deref(),
        Some(&b"dirty"[..]),
        "abort restores the captured dirty bytes"
    );
}

#[test]
fn untracked_blockers_need_discard() {
    let fx = Fixture::new();
    let target = entry(FileMode::Regular, fx.blob(b"n"));
    fx.put("new", b"untracked blocker");
    fx.put("swapdir/untracked.txt", b"stray");
    let entries = vec![
        plan_entry("new/deep/n.txt", None, Some(target)),
        plan_entry("swapdir", None, Some(target)),
    ];
    let error = code(begin_apply(
        fx.store(),
        plan(&fx, entries.clone(), &[]),
        fx.fence(),
        Vec::new(),
    ));
    assert_eq!(error.code, ErrorCode::EDirty);
    assert!(error.message.contains("new"), "{}", error.message);
    assert!(
        error.message.contains("swapdir/untracked.txt"),
        "{}",
        error.message
    );

    let discard = ["new", "swapdir/untracked.txt"];
    materialize(
        fx.store(),
        plan(&fx, entries, &discard),
        fx.fence(),
        Vec::new(),
        FinishBatch::default(),
    )
    .expect("materialize with discard");
    assert_eq!(fx.get("new/deep/n.txt").as_deref(), Some(&b"n"[..]));
    assert_eq!(fx.get("swapdir").as_deref(), Some(&b"n"[..]));
}

#[cfg(unix)]
#[test]
fn symlinked_ancestors_are_never_followed() {
    let fx = Fixture::new();
    let outside = std::env::temp_dir().join(format!("ruk-wcj-outside-{}", WorkspaceId::generate()));
    fs::create_dir_all(&outside).expect("outside dir");
    std::os::unix::fs::symlink(&outside, fx.full("esc")).expect("escape link");
    let link_bytes = outside.as_os_str().as_encoded_bytes().to_vec();
    let link = entry(FileMode::Symlink, fx.blob(&link_bytes));
    let target = entry(FileMode::Regular, fx.blob(b"payload"));

    let root = safety::WorkRoot::open(&fx.dir).expect("root");
    assert_eq!(
        code(root.resolve_clear(&path("esc/x"))).code,
        ErrorCode::EInvalid
    );

    let blocked = vec![plan_entry("esc/x", None, Some(target))];
    assert_eq!(
        code(begin_apply(
            fx.store(),
            plan(&fx, blocked, &[]),
            fx.fence(),
            Vec::new()
        ))
        .code,
        ErrorCode::EDirty
    );
    assert!(!outside.join("x").exists());

    let entries = vec![
        plan_entry("esc", Some(link), None),
        plan_entry("esc/x", None, Some(target)),
    ];
    materialize(
        fx.store(),
        plan(&fx, entries, &[]),
        fx.fence(),
        Vec::new(),
        FinishBatch::default(),
    )
    .expect("replace link with directory");
    assert!(fs::symlink_metadata(fx.full("esc")).expect("esc").is_dir());
    assert_eq!(fx.get("esc/x").as_deref(), Some(&b"payload"[..]));
    assert!(
        !outside.join("x").exists(),
        "nothing was written through the link"
    );
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn reserved_and_out_of_scope_paths_are_rejected() {
    let fx = Fixture::new();
    let target = entry(FileMode::Regular, fx.blob(b"x"));
    for reserved in [".ruk/store/x", ".RUK/x", ".ruk./x"] {
        let entries = vec![plan_entry(reserved, None, Some(target))];
        let error = code(begin_apply(
            fx.store(),
            plan(&fx, entries, &[]),
            fx.fence(),
            Vec::new(),
        ));
        assert_eq!(error.code, ErrorCode::EInvalid, "{reserved}");
    }
    let mut scoped = plan(&fx, vec![plan_entry("out/x", None, Some(target))], &[]);
    scoped.scope = Scope::cone([path("in")]);
    assert_eq!(
        code(begin_apply(fx.store(), scoped, fx.fence(), Vec::new())).code,
        ErrorCode::EInvalid
    );
    let below_file = vec![
        plan_entry("f", None, Some(target)),
        plan_entry("f/g", None, Some(target)),
    ];
    assert_eq!(
        code(begin_apply(
            fx.store(),
            plan(&fx, below_file, &[]),
            fx.fence(),
            Vec::new()
        ))
        .code,
        ErrorCode::EInvalid
    );
    assert!(!is_applying(fx.store(), fx.ws).expect("no journal"));
}

#[test]
fn second_begin_and_reserved_extra_are_refused() {
    let fx = Fixture::new();
    let target = entry(FileMode::Regular, fx.blob(b"x"));
    let reserved = FactMutation {
        table: FactTable::WsApply,
        key: fx.ws.as_bytes().to_vec(),
        expected: FactExpectation::Any,
        value: None,
    };
    let error = code(begin_apply(
        fx.store(),
        plan(&fx, vec![plan_entry("a", None, Some(target))], &[]),
        fx.fence(),
        vec![reserved],
    ));
    assert_eq!(error.code, ErrorCode::EInvalid);
    let _first = begin_apply(
        fx.store(),
        plan(&fx, vec![plan_entry("a", None, Some(target))], &[]),
        fx.fence(),
        Vec::new(),
    )
    .expect("first begin");
    let error = code(begin_apply(
        fx.store(),
        plan(&fx, vec![plan_entry("b", None, Some(target))], &[]),
        fx.fence(),
        Vec::new(),
    ));
    assert_eq!(error.code, ErrorCode::EWorkspaceApplying);
}

#[test]
fn symlink_target_bytes_must_hash_to_the_target_oid() {
    let fx = Fixture::new();
    let mut wrong = plan_entry("l", None, Some(entry(FileMode::Symlink, fx.blob(b"right"))));
    wrong.target_link = Some(ByteString::new(b"wrong".to_vec()));
    assert_eq!(
        code(begin_apply(
            fx.store(),
            plan(&fx, vec![wrong], &[]),
            fx.fence(),
            Vec::new()
        ))
        .code,
        ErrorCode::EInvalid
    );
}

#[test]
fn lease_epoch_fences_begin_steps_finish_and_recovery() {
    let fx = Fixture::new();
    let entries = seed(&fx);
    let stale = fx.fence();
    fx.take();
    let error = code(begin_apply(
        fx.store(),
        plan(&fx, entries.clone(), &[]),
        stale,
        Vec::new(),
    ));
    assert_eq!(error.code, ErrorCode::EStale);
    assert!(!is_applying(fx.store(), fx.ws).expect("no journal"));

    let owner = fx.fence();
    {
        let mut session = begin_apply(
            fx.store(),
            plan(&fx, entries, &[]),
            owner.clone(),
            Vec::new(),
        )
        .expect("begin");
        fx.take();
        assert_eq!(code(session.execute()).code, ErrorCode::ELeaseLost);
    }
    assert!(is_applying(fx.store(), fx.ws).expect("journal stays"));
    assert_eq!(
        code(recover(
            fx.store(),
            &fx.dir,
            owner.clone(),
            RecoveryAction::Resume,
            FinishBatch::default()
        ))
        .code,
        ErrorCode::ELeaseLost
    );
    let older = WorkspaceFence::new(
        fx.ws,
        fx.row.borrow().clone(),
        WorkspaceStamp {
            sequence: 0,
            lease_epoch: owner.lease_epoch() - 1,
        },
    );
    assert_eq!(
        code(recover(
            fx.store(),
            &fx.dir,
            older,
            RecoveryAction::Resume,
            FinishBatch::default()
        ))
        .code,
        ErrorCode::ELeaseLost
    );
    recover(
        fx.store(),
        &fx.dir,
        fx.fence(),
        RecoveryAction::Resume,
        FinishBatch::default(),
    )
    .expect("new owner recovers");
    assert_target(&fx);
    let journal_gone = current_journal(fx.store(), fx.ws).expect("read");
    assert!(journal_gone.is_none());
}

#[test]
fn finish_is_fenced_by_the_lease_epoch() {
    let fx = Fixture::new();
    let entries = seed(&fx);
    let mut session =
        begin_apply(fx.store(), plan(&fx, entries, &[]), fx.fence(), Vec::new()).expect("begin");
    session.execute().expect("execute");
    let journal = session.journal().clone();
    assert_eq!(journal.lease_epoch, 0);
    assert!(
        journal.cursor > StepCursor::START,
        "cursor advanced: {:?}",
        journal.cursor
    );
    fx.take();
    assert_eq!(
        code(session.finish(FinishBatch::default())).code,
        ErrorCode::ELeaseLost
    );
    assert!(is_applying(fx.store(), fx.ws).expect("journal stays open"));
    let rebound_before = current_journal(fx.store(), fx.ws)
        .expect("read")
        .expect("open");
    assert_eq!(rebound_before.lease_epoch, 0);
    recover(
        fx.store(),
        &fx.dir,
        fx.fence(),
        RecoveryAction::Resume,
        FinishBatch::default(),
    )
    .expect("recover");
    assert_target(&fx);
}

#[test]
fn deny_mode_refuses_pointer_targets_before_the_journal() {
    let fx = Fixture::new();
    let pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d0b46e9c\nsize 14\n";
    let oid = fx.blob(pointer);
    let entries = vec![plan_entry(
        "asset.bin",
        None,
        Some(entry(FileMode::Regular, oid)),
    )];
    let error = code(begin_apply(
        fx.store(),
        plan(&fx, entries, &[]),
        fx.fence(),
        Vec::new(),
    ));
    assert_eq!(error.code, ErrorCode::EUnsupportedLfs);
    assert!(
        !is_applying(fx.store(), fx.ws).expect("no journal"),
        "a refused target leaves no Applying journal"
    );
    assert!(fx.get("asset.bin").is_none(), "the worktree is untouched");
}

#[test]
fn pointer_mode_materializes_pointer_bytes_plainly() {
    let fx = Fixture::new();
    let pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d0b46e9c\nsize 14\n";
    let oid = fx.blob(pointer);
    let entries = vec![plan_entry(
        "asset.bin",
        None,
        Some(entry(FileMode::Regular, oid)),
    )];
    let mut request = plan(&fx, entries, &[]);
    request.lfs = LfsMode::Pointers;
    materialize(
        fx.store(),
        request,
        fx.fence(),
        Vec::new(),
        FinishBatch::default(),
    )
    .expect("pointer bytes materialize under pointer mode");
    assert_eq!(fx.get("asset.bin").as_deref(), Some(pointer.as_slice()));
}
