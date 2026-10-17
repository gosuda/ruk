use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::crawl::CrawlLimits;
use super::journal_state::{
    ApplyObservation, ApplyPhase, JournalState, NoJournal, guard_for, ws_apply_key,
};
use super::snapshot::{
    DirtySource, SnapshotInput, SnapshotOutcome, StatusReport, snapshot, status,
};
use super::statcache::{
    FileStat, StatClock, StatusRow, Trust, decode_row, encode_row, system_time, trust,
};
use super::tree::{TreeMode, parse_tree};
use super::watcher::{DirtySet, WatchBatch, WatchEvent, WatchEventKind, WatchToken, reduce};
use super::write::{WriteInput, WriteOutcome, write};
use super::{NoIgnore, cache_key};
use crate::change::ChangeId;
use crate::heads::Head;
use crate::ids::{HashKind, Oid};
use crate::index::{FileMode, RepoPath, StatData, StatTime};
use crate::store::{
    FactExpectation, FactMutation, FactTable, ObjectKind, PreparationBudget, Store, StoreError,
};
use crate::workspace::{NativeWorkspace, Scope, WorkspaceStamp, WorkspaceState};
use crate::{ErrorCode, WorkspaceId};

const INSTANCE: [u8; 16] = [7; 16];

static NO_IGNORE: NoIgnore = NoIgnore;
static NO_JOURNAL: NoJournal = NoJournal;

struct Fixture {
    root: PathBuf,
    store: Store,
    workspace: WorkspaceId,
    state: WorkspaceState,
    change: ChangeId,
    head: Head,
    empty_tree: Oid,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn path(text: &str) -> RepoPath {
    RepoPath::new(text.as_bytes()).expect("valid path")
}

fn at(cursor: u64) -> WatchToken {
    WatchToken::At {
        instance: INSTANCE,
        cursor,
    }
}

fn changed(text: &str) -> WatchEvent {
    WatchEvent {
        path: text.as_bytes().to_vec(),
        kind: WatchEventKind::Changed,
    }
}

fn batch(since: WatchToken, until: WatchToken, events: Vec<WatchEvent>) -> WatchBatch {
    WatchBatch {
        since,
        until,
        events,
        overflowed: false,
    }
}

impl Fixture {
    fn new(scope: Scope) -> Self {
        let root = std::env::temp_dir().join(format!("ruk-workcopy-test-{}", WorkspaceId::generate()));
        std::fs::create_dir_all(root.join(".ruk")).expect("internal dir");
        let store = Store::create(
            &root.join(".ruk").join("store"),
            HashKind::Sha1,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("create store");
        let empty = store
            .prepare(ObjectKind::Tree, 0, &[][..], None)
            .expect("prepare empty tree");
        let empty_tree = empty.oid();
        store.publish(vec![empty], &[]).expect("publish empty tree");
        let change = ChangeId::generate();
        let head = Head::Git { oid: empty_tree };
        let state = WorkspaceState::Native(NativeWorkspace::new(change, head, scope));
        Self {
            root,
            store,
            workspace: WorkspaceId::generate(),
            state,
            change,
            head,
            empty_tree,
        }
    }

    fn put(&self, rel: &str, bytes: &[u8]) {
        let file = self.root.join(rel);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).expect("parent dirs");
        }
        std::fs::write(file, bytes).expect("write file");
    }

    /// Ten seconds after now with one-second granularity: files written by
    /// the test are old enough not to be racy.
    fn settled_clock() -> StatClock {
        let now = system_time(SystemTime::now() + Duration::from_secs(10)).expect("now");
        StatClock::new(now, 1_000_000_000).expect("clock")
    }

    fn input<'a>(&'a self, base: Oid, watch: Option<&'a WatchBatch>) -> SnapshotInput<'a> {
        SnapshotInput {
            workspace: self.workspace,
            state: &self.state,
            root: &self.root,
            base_tree: base,
            watch,
            clock: Self::settled_clock(),
            limits: CrawlLimits::reference(),
            ignore: &NO_IGNORE,
            journal: &NO_JOURNAL,
        }
    }

    fn snapshot(&self, base: Oid, watch: Option<&WatchBatch>) -> SnapshotOutcome {
        snapshot(&self.store, &self.input(base, watch)).expect("snapshot")
    }

    /// Snapshots and publishes; returns the tree the worktree now mirrors.
    fn commit(&self, base: Oid, watch: Option<&WatchBatch>) -> Oid {
        match self.snapshot(base, watch) {
            SnapshotOutcome::NoChange { cache } => {
                self.store.publish(Vec::new(), &cache).expect("publish cache");
                base
            }
            SnapshotOutcome::Changed(prepared) => {
                let tree = prepared.descriptor.tree;
                self.store
                    .publish(prepared.objects, &prepared.facts)
                    .expect("publish snapshot");
                tree
            }
        }
    }

    fn files(&self, tree: Oid) -> BTreeMap<String, Oid> {
        let mut out = BTreeMap::new();
        self.walk(tree, String::new(), &mut out);
        out
    }

    fn walk(&self, tree: Oid, prefix: String, out: &mut BTreeMap<String, Oid>) {
        for item in self.items(tree) {
            let name = format!("{prefix}{}", String::from_utf8(item.name).expect("utf8"));
            match item.mode {
                TreeMode::Tree => self.walk(item.oid, format!("{name}/"), out),
                TreeMode::File(_) => {
                    out.insert(name, item.oid);
                }
            }
        }
    }

    fn items(&self, tree: Oid) -> Vec<super::tree::TreeItem> {
        let mut object = self.store.read(tree).expect("read tree");
        assert_eq!(object.kind, ObjectKind::Tree);
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut object.bytes, &mut bytes).expect("tree bytes");
        parse_tree(HashKind::Sha1, &bytes).expect("parse tree")
    }

    fn subtree(&self, tree: Oid, name: &str) -> Oid {
        self.items(tree)
            .into_iter()
            .find(|item| item.name == name.as_bytes())
            .map(|item| item.oid)
            .expect("subtree present")
    }

    fn blob(&self, bytes: &[u8]) -> Oid {
        HashKind::Sha1.hash_git_object("blob", bytes).expect("hash")
    }
}

fn stat_at(secs: i64, nanos: u32) -> FileStat {
    let time = StatTime { secs, nanos };
    FileStat {
        data: StatData {
            ctime: time,
            mtime: time,
            dev: 1,
            ino: 2,
            uid: 3,
            gid: 4,
            size: 5,
        },
        mode: 0o100_644,
    }
}

fn row(stat: FileStat, racy: bool) -> StatusRow {
    StatusRow {
        stat,
        mode: FileMode::Regular,
        blob: HashKind::Sha1.hash_git_object("blob", b"bytes").expect("hash"),
        racy,
        conflict: None,
    }
}

#[test]
fn racy_and_future_timestamps_are_never_trusted() {
    let clock = StatClock::new(StatTime { secs: 100, nanos: 0 }, 1_000_000_000).expect("clock");
    assert!(clock.is_racy(&stat_at(99, 500_000_000)), "within one tick of now");
    assert!(clock.is_racy(&stat_at(99, 0)), "exactly one tick before now");
    assert!(!clock.is_racy(&stat_at(98, 999_999_999)));
    assert!(clock.is_racy(&stat_at(101, 0)), "future timestamps are racy");

    let old = stat_at(50, 0);
    assert!(matches!(trust(Some(&row(old, false)), &old, &clock), Trust::Clean { .. }));
    assert_eq!(trust(Some(&row(old, true)), &old, &clock), Trust::Rehash);
    assert_eq!(trust(None, &old, &clock), Trust::Rehash);
    let mut grown = old;
    grown.data.size += 1;
    assert_eq!(trust(Some(&row(old, false)), &grown, &clock), Trust::Rehash);
    let future = stat_at(200, 0);
    assert_eq!(
        trust(Some(&row(future, false)), &future, &clock),
        Trust::Rehash,
        "a future tuple stays untrusted even when a row claims it is clean"
    );

    let coarse = StatClock::new(StatTime { secs: 100, nanos: 0 }, StatClock::COARSE_RESOLUTION_NS)
        .expect("clock");
    assert!(coarse.is_racy(&stat_at(98, 0)), "two-second filesystems widen the window");
    let recorded = StatusRow::observed(stat_at(99, 0), FileMode::Regular, row(old, false).blob, true, &clock, None);
    assert!(recorded.racy);
    let unstable = StatusRow::observed(old, FileMode::Regular, recorded.blob, false, &clock, None);
    assert!(unstable.racy, "bytes read while the tuple moved are racy");
}

#[test]
fn reducer_excludes_internal_out_of_scope_and_invalid_paths() {
    let scope = Scope::cone([path("a")]);
    let events = vec![
        changed(".ruk/store/meta.redb"),
        changed(".ruk"),
        changed("a/f"),
        changed("b/f"),
        changed("top"),
        changed("x/.git/HEAD"),
        WatchEvent {
            path: b"a/gone".to_vec(),
            kind: WatchEventKind::Removed,
        },
        WatchEvent {
            path: b"a/sub/".to_vec(),
            kind: WatchEventKind::Rescan,
        },
    ];
    let dirty = reduce(at(1), &batch(at(1), at(2), events), &scope);
    assert!(dirty.exhaustive);
    assert_eq!(
        dirty.paths.into_iter().collect::<Vec<_>>(),
        vec![path("a/f"), path("a/gone"), path("top")]
    );
    assert_eq!(dirty.subtrees.into_iter().collect::<Vec<_>>(), vec![path("a/sub")]);
}

#[test]
fn reducer_requires_crawl_on_overflow_gap_or_new_instance() {
    let scope = Scope::Full;
    let mut overflowed = batch(at(1), at(2), vec![changed("f")]);
    overflowed.overflowed = true;
    assert_eq!(reduce(at(1), &overflowed, &scope), DirtySet::crawl());
    assert_eq!(reduce(at(0), &batch(at(1), at(2), Vec::new()), &scope), DirtySet::crawl());
    assert_eq!(reduce(at(3), &batch(at(3), at(2), Vec::new()), &scope), DirtySet::crawl());
    let other = WatchToken::At {
        instance: [9; 16],
        cursor: 2,
    };
    assert_eq!(reduce(at(1), &batch(at(1), other, Vec::new()), &scope), DirtySet::crawl());
    assert_eq!(
        reduce(WatchToken::Invalid, &batch(WatchToken::Invalid, at(1), Vec::new()), &scope),
        DirtySet::crawl()
    );
    let root_rescan = WatchEvent {
        path: Vec::new(),
        kind: WatchEventKind::Rescan,
    };
    assert_eq!(reduce(at(1), &batch(at(1), at(2), vec![root_rescan]), &scope), DirtySet::crawl());
    assert!(reduce(at(1), &batch(at(1), at(2), Vec::new()), &scope).is_clean());
    assert!(at(1).precedes(at(5)));
    assert!(!at(1).precedes(at(0)));
    assert!(!at(1).precedes(WatchToken::Invalid));
    assert!(!WatchToken::Invalid.precedes(at(1)));
}

#[test]
fn first_snapshot_crawls_and_never_records_the_internal_directory() {
    let fixture = Fixture::new(Scope::Full);
    fixture.put("a.txt", b"alpha\n");
    fixture.put("d/b.txt", b"beta\n");
    fixture.put(".ruk/scratch", b"internal\n");
    let first = batch(WatchToken::Invalid, at(1), Vec::new());
    let SnapshotOutcome::Changed(prepared) = fixture.snapshot(fixture.empty_tree, Some(&first)) else {
        panic!("a populated worktree must change the empty tree");
    };
    assert_eq!(prepared.descriptor.source, DirtySource::Crawl);
    assert_eq!(prepared.descriptor.changed, vec![path("a.txt"), path("d/b.txt")]);
    assert!(prepared.descriptor.removed.is_empty());
    assert!(prepared.descriptor.conflict_edits.is_empty());
    assert_eq!(prepared.descriptor.base_tree, fixture.empty_tree);
    assert_eq!(prepared.descriptor.change, fixture.change);
    assert_eq!(prepared.descriptor.head, fixture.head);
    assert_eq!(prepared.descriptor.stamp, WorkspaceStamp::INITIAL);
    assert_eq!(prepared.descriptor.workspace, fixture.workspace);
    let tree = prepared.descriptor.tree;
    fixture
        .store
        .publish(prepared.objects, &prepared.facts)
        .expect("publish");
    let files = fixture.files(tree);
    assert_eq!(
        files.keys().cloned().collect::<Vec<_>>(),
        vec!["a.txt".to_owned(), "d/b.txt".to_owned()]
    );
    assert_eq!(files["d/b.txt"], fixture.blob(b"beta\n"));
    assert!(
        fixture
            .store
            .fact(FactTable::WsStatus, &cache_key(fixture.workspace, b".ruk/scratch"))
            .expect("lookup")
            .is_none()
    );
}

#[test]
fn an_empty_dirty_set_produces_no_mutations() {
    let fixture = Fixture::new(Scope::Full);
    fixture.put("f", b"one\n");
    let tree = fixture.commit(fixture.empty_tree, Some(&batch(WatchToken::Invalid, at(1), Vec::new())));
    let quiet = batch(at(1), at(2), Vec::new());
    let SnapshotOutcome::NoChange { cache } = fixture.snapshot(tree, Some(&quiet)) else {
        panic!("no events must not change the tree");
    };
    assert!(cache.is_empty(), "an empty dirty set writes nothing");
    assert_eq!(
        status(&fixture.store, &fixture.input(tree, Some(&quiet))).expect("status"),
        StatusReport::Clean
    );
}

#[test]
fn watcher_overflow_falls_back_to_a_crawl_that_finds_unreported_edits() {
    let fixture = Fixture::new(Scope::Full);
    fixture.put("d/b.txt", b"beta\n");
    let tree = fixture.commit(fixture.empty_tree, Some(&batch(WatchToken::Invalid, at(1), Vec::new())));
    fixture.put("d/b.txt", b"BETA, longer\n");
    let mut lost = batch(at(1), at(2), Vec::new());
    lost.overflowed = true;
    assert_eq!(
        status(&fixture.store, &fixture.input(tree, Some(&lost))).expect("status"),
        StatusReport::Dirty {
            changed: vec![path("d/b.txt")],
            removed: Vec::new(),
            conflict_edits: Vec::new(),
        }
    );
    let SnapshotOutcome::Changed(prepared) = fixture.snapshot(tree, Some(&lost)) else {
        panic!("the crawl must find the edit the watcher lost");
    };
    assert_eq!(prepared.descriptor.source, DirtySource::Crawl);
    assert_eq!(prepared.descriptor.changed, vec![path("d/b.txt")]);

    let gap = batch(at(5), at(6), Vec::new());
    let SnapshotOutcome::Changed(prepared) = fixture.snapshot(tree, Some(&gap)) else {
        panic!("a token gap must crawl too");
    };
    assert_eq!(prepared.descriptor.source, DirtySource::Crawl);
}

#[test]
fn rebuild_touches_only_dirty_ancestors_and_reuses_untouched_subtrees() {
    let fixture = Fixture::new(Scope::Full);
    fixture.put("x/f", b"x one\n");
    fixture.put("y/g", b"y one\n");
    let tree = fixture.commit(fixture.empty_tree, Some(&batch(WatchToken::Invalid, at(1), Vec::new())));
    let y_before = fixture.subtree(tree, "y");
    fixture.put("x/f", b"x two, different length\n");
    let events = batch(at(1), at(2), vec![changed("x/f")]);
    let SnapshotOutcome::Changed(prepared) = fixture.snapshot(tree, Some(&events)) else {
        panic!("the reported edit must change the tree");
    };
    assert_eq!(prepared.descriptor.source, DirtySource::Watcher);
    let kinds: Vec<ObjectKind> = prepared.objects.iter().map(|object| object.kind()).collect();
    assert_eq!(
        kinds.iter().filter(|kind| **kind == ObjectKind::Tree).count(),
        2,
        "only x and the root are re-encoded"
    );
    assert_eq!(kinds.iter().filter(|kind| **kind == ObjectKind::Blob).count(), 1);
    let next = prepared.descriptor.tree;
    fixture
        .store
        .publish(prepared.objects, &prepared.facts)
        .expect("publish");
    assert_eq!(fixture.subtree(next, "y"), y_before);
    assert_eq!(fixture.files(next)["x/f"], fixture.blob(b"x two, different length\n"));

    std::fs::remove_file(fixture.root.join("x/f")).expect("remove");
    std::fs::remove_dir(fixture.root.join("x")).expect("remove dir");
    let removal = batch(at(2), at(3), vec![changed("x/f"), changed("x")]);
    let after = fixture.commit(next, Some(&removal));
    assert_eq!(
        fixture.files(after).keys().cloned().collect::<Vec<_>>(),
        vec!["y/g".to_owned()],
        "an emptied directory leaves the tree"
    );
    assert!(
        fixture
            .store
            .fact(FactTable::WsDirs, &cache_key(fixture.workspace, b"x"))
            .expect("lookup")
            .is_none(),
        "the removed directory's cache row is purged"
    );
}

#[test]
fn an_open_journal_blocks_snapshot_and_status_reports_it() {
    let fixture = Fixture::new(Scope::Full);
    fixture.put("f", b"one\n");
    fixture
        .store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::WsApply,
                key: ws_apply_key(fixture.workspace),
                expected: FactExpectation::Absent,
                value: Some(b"journal".to_vec()),
            }],
        )
        .expect("open journal");
    let error = snapshot(&fixture.store, &fixture.input(fixture.empty_tree, None))
        .expect_err("applying must refuse");
    assert_eq!(error.code, ErrorCode::EWorkspaceApplying);
    assert_eq!(
        status(&fixture.store, &fixture.input(fixture.empty_tree, None)).expect("status"),
        StatusReport::Materializing(super::journal_state::ApplyPhase::Applying)
    );
}

#[test]
fn a_journal_opened_after_the_check_fails_the_snapshot_publication() {
    let fixture = Fixture::new(Scope::Full);
    fixture.put("f", b"one\n");
    let SnapshotOutcome::Changed(prepared) = fixture.snapshot(fixture.empty_tree, None) else {
        panic!("expected a change");
    };
    fixture
        .store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::WsApply,
                key: ws_apply_key(fixture.workspace),
                expected: FactExpectation::Absent,
                value: Some(b"journal".to_vec()),
            }],
        )
        .expect("open journal");
    let error = fixture
        .store
        .publish(prepared.objects, &prepared.facts)
        .expect_err("the guard must fence the journal");
    assert!(matches!(error, StoreError::StaleFact { table: "ws_apply", .. }));
}

#[derive(Debug)]
struct Recovering;

impl JournalState for Recovering {
    fn observe(
        &self,
        store: &Store,
        workspace: WorkspaceId,
    ) -> Result<ApplyObservation, crate::CoreError> {
        Ok(ApplyObservation {
            phase: ApplyPhase::Recovery,
            guard: guard_for(workspace, store.fact(FactTable::WsApply, &ws_apply_key(workspace))?),
        })
    }
}

#[test]
fn a_recovery_journal_blocks_snapshot_with_recovery() {
    let fixture = Fixture::new(Scope::Full);
    fixture.put("f", b"one\n");
    let recovering = Recovering;
    let input = SnapshotInput {
        journal: &recovering,
        ..fixture.input(fixture.empty_tree, None)
    };
    let error = snapshot(&fixture.store, &input).expect_err("recovery must refuse");
    assert_eq!(error.code, ErrorCode::EWorkspaceRecovery);
    assert_eq!(
        status(&fixture.store, &input).expect("status"),
        StatusReport::Materializing(ApplyPhase::Recovery)
    );
}

#[test]
fn explicit_write_hashes_bytes_the_stat_cache_would_trust() {
    let fixture = Fixture::new(Scope::Full);
    fixture.put("f", b"before\n");
    let tree = fixture.commit(fixture.empty_tree, Some(&batch(WatchToken::Invalid, at(1), Vec::new())));
    fixture.put("f", b"AFTER!\n");

    // Model the floor: a same-tick edit whose tuple the cache already holds.
    let key = cache_key(fixture.workspace, b"f");
    let bytes = fixture.store.fact(FactTable::WsStatus, &key).expect("lookup").expect("row");
    let mut forged: StatusRow = decode_row(&fixture.store, "row", &bytes).expect("decode");
    let meta = std::fs::symlink_metadata(fixture.root.join("f")).expect("stat");
    forged.stat = FileStat::from_metadata(&meta).expect("tuple");
    forged.racy = false;
    fixture
        .store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::WsStatus,
                key,
                expected: FactExpectation::Value(bytes),
                value: Some(encode_row("row", &forged).expect("encode")),
            }],
        )
        .expect("forge row");
    assert!(
        matches!(fixture.snapshot(tree, None), SnapshotOutcome::NoChange { .. }),
        "a trusted tuple hides a same-tick edit from the crawl"
    );

    let paths = [path("f")];
    let input = WriteInput {
        workspace: fixture.workspace,
        state: &fixture.state,
        expected: WorkspaceStamp::INITIAL,
        root: &fixture.root,
        base_tree: tree,
        paths: &paths,
        clock: Fixture::settled_clock(),
        limits: CrawlLimits::reference(),
        journal: &NoJournal,
    };
    let WriteOutcome::Changed(prepared) = write(&fixture.store, &input).expect("write") else {
        panic!("write must hash the bytes and see the edit");
    };
    assert_eq!(prepared.descriptor.written, vec![path("f")]);
    let next = prepared.descriptor.tree;
    fixture
        .store
        .publish(prepared.objects, &prepared.facts)
        .expect("publish write");
    assert_eq!(fixture.files(next)["f"], fixture.blob(b"AFTER!\n"));

    std::fs::remove_file(fixture.root.join("f")).expect("remove");
    let paths = [path("f")];
    let remove = WriteInput {
        paths: &paths,
        base_tree: next,
        ..input
    };
    let WriteOutcome::Changed(prepared) = write(&fixture.store, &remove).expect("remove") else {
        panic!("write must record the removal");
    };
    assert_eq!(prepared.descriptor.removed, vec![path("f")]);
    assert!(prepared.descriptor.written.is_empty());
}

#[test]
fn explicit_write_rejects_stale_stamps_and_out_of_scope_paths() {
    let fixture = Fixture::new(Scope::cone([path("a")]));
    fixture.put("a/f", b"one\n");
    fn make<'a>(
        fixture: &'a Fixture,
        paths: &'a [RepoPath],
        expected: WorkspaceStamp,
    ) -> WriteInput<'a> {
        WriteInput {
            workspace: fixture.workspace,
            state: &fixture.state,
            expected,
            root: &fixture.root,
            base_tree: fixture.empty_tree,
            paths,
            clock: Fixture::settled_clock(),
            limits: CrawlLimits::reference(),
            journal: &NO_JOURNAL,
        }
    }
    let stale = WorkspaceStamp {
        sequence: 4,
        lease_epoch: 0,
    };
    let inside = [path("a/f")];
    let outside = [path("b/f")];
    let error = write(&fixture.store, &make(&fixture, &inside, stale)).expect_err("stale stamp");
    assert_eq!(error.code, ErrorCode::EStale);
    let error = write(&fixture.store, &make(&fixture, &outside, WorkspaceStamp::INITIAL))
        .expect_err("out of scope");
    assert_eq!(error.code, ErrorCode::EInvalid);
    assert!(matches!(
        write(&fixture.store, &make(&fixture, &inside, WorkspaceStamp::INITIAL)).expect("write"),
        WriteOutcome::Changed(_)
    ));
}

#[derive(Debug)]
struct Ignored(&'static str);

impl super::IgnoreRule for Ignored {
    fn is_ignored(&self, path: &RepoPath) -> bool {
        path.as_bytes().starts_with(self.0.as_bytes())
    }
}

#[test]
fn snapshot_skips_ignored_untracked_files_but_write_includes_them() {
    let fixture = Fixture::new(Scope::Full);
    fixture.put("keep", b"keep\n");
    fixture.put("target/skip", b"skip\n");
    let ignored = Ignored("target/");
    let input = SnapshotInput {
        ignore: &ignored,
        ..fixture.input(fixture.empty_tree, None)
    };
    let SnapshotOutcome::Changed(prepared) = snapshot(&fixture.store, &input).expect("snapshot") else {
        panic!("the unignored file must change the tree");
    };
    assert_eq!(prepared.descriptor.changed, vec![path("keep")]);
    let tree = prepared.descriptor.tree;
    fixture
        .store
        .publish(prepared.objects, &prepared.facts)
        .expect("publish");
    assert_eq!(fixture.files(tree).len(), 1);

    let paths = [path("target/skip")];
    let write_input = WriteInput {
        workspace: fixture.workspace,
        state: &fixture.state,
        expected: WorkspaceStamp::INITIAL,
        root: &fixture.root,
        base_tree: tree,
        paths: &paths,
        clock: Fixture::settled_clock(),
        limits: CrawlLimits::reference(),
        journal: &NO_JOURNAL,
    };
    let WriteOutcome::Changed(prepared) = write(&fixture.store, &write_input).expect("write") else {
        panic!("write never consults the ignore rule");
    };
    assert_eq!(prepared.descriptor.written, vec![path("target/skip")]);
}

#[test]
fn cone_scope_keeps_out_of_scope_trees_by_id() {
    let fixture = Fixture::new(Scope::cone([path("a")]));
    fixture.put("a/in", b"one\n");
    fixture.put("b/out", b"one\n");
    fixture.put("top", b"one\n");
    let tree = fixture.commit(fixture.empty_tree, Some(&batch(WatchToken::Invalid, at(1), Vec::new())));
    // Root files are always in a cone scope; the unlisted directory is not.
    assert_eq!(
        fixture.files(tree).keys().cloned().collect::<Vec<_>>(),
        vec!["a/in".to_owned(), "top".to_owned()]
    );
    let in_row = cache_key(fixture.workspace, b"a/in");
    assert!(fixture.store.fact(FactTable::WsStatus, &in_row).expect("lookup").is_some());
    assert!(
        fixture
            .store
            .fact(FactTable::WsStatus, &cache_key(fixture.workspace, b"b/out"))
            .expect("lookup")
            .is_none(),
        "an out-of-scope file is never crawled and never cached"
    );
    fixture.put("b/out", b"TWO, but out of scope\n");
    let events = batch(
        at(1),
        at(2),
        vec![WatchEvent {
            path: b"b/out".to_vec(),
            kind: WatchEventKind::Changed,
        }],
    );
    // The reducer drops the event before it becomes a candidate.
    let SnapshotOutcome::NoChange { cache } = fixture.snapshot(tree, Some(&events)) else {
        panic!("out-of-scope changes do not change the cone tree");
    };
    assert!(cache.is_empty(), "nothing out of scope needs refreshing");
}
