use std::sync::atomic::{AtomicU64, Ordering};

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefName, RefTarget};
use ruk_core::refs::StoreRefs;
use ruk_core::workspace::HeadRef;

use crate::export::{ExportRequest, export_repository};
use crate::import::fixtures::Fixture;
use crate::import::objects::SourceObjects;
use crate::import::{DirectPublish, ImportProgress, import_repository};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct Scratch {
    dir: std::path::PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ruk-notes-test-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        Self { dir }
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn ref_name(name: &str) -> RefName {
    RefName::new(name.as_bytes().to_vec()).expect("ref name")
}

#[derive(Debug)]
struct NotesSource {
    target: Oid,
    blob: Oid,
    notes: Oid,
}

fn notes_source(fixture: &Fixture) -> NotesSource {
    let blob = fixture.blob(b"reviewed\n");
    let target_tree = fixture.loose("tree", b"");
    let (_, target) = fixture.commit(target_tree, &[], b"", b"annotated\n");
    let hex = target.to_hex();
    let (_, inner) = fixture.tree(&[(false, hex[2..].as_bytes(), blob)]);
    let (_, root) = fixture.tree(&[(true, hex[..2].as_bytes(), inner)]);
    let (_, notes) = fixture.commit(root, &[], b"", b"notes\n");
    fixture.write_ref("refs/notes/commits", notes);
    NotesSource {
        target,
        blob,
        notes,
    }
}

#[test]
fn notes_import_then_export_keeps_identical_oid() {
    let fixture = Fixture::sha1();
    let built = notes_source(&fixture);
    let store = fixture.store();
    let mut sink = DirectPublish(&store);
    let request = fixture.request(7, b"origin");
    import_repository(&store, &request, &ImportProgress::new(), &mut sink).expect("import");
    let stored =
        ruk_core::refdata::resolve(&StoreRefs::new(&store), &ref_name("refs/notes/commits"))
            .expect("resolve notes ref");
    assert_eq!(stored.oid, Some(built.notes));
    let source = SourceObjects::open(&fixture.git_dir, fixture.hash, 1 << 20).expect("source");
    let name = ref_name("refs/notes/commits");
    let imported =
        crate::import::notes::load_notes_namespace(&source, &name, built.notes).expect("imported");
    assert_eq!(imported.find(built.target), Some(built.blob));
    let exported =
        crate::export::notes::load_notes_namespace(&store, &name, built.notes).expect("exported");
    let imported_edges: Vec<_> = imported
        .edges()
        .iter()
        .map(|e| (e.target, e.note))
        .collect();
    let exported_edges: Vec<_> = exported
        .edges()
        .iter()
        .map(|e| (e.target, e.note))
        .collect();
    assert_eq!(imported_edges, exported_edges);
    let scratch = Scratch::new();
    let target = scratch.path("out.git");
    export_repository(
        &store,
        &ExportRequest {
            target: target.clone(),
            head: HeadRef::Detached(built.notes),
            store_root: fixture.dir.join("store"),
        },
    )
    .expect("export");
    let packed = std::fs::read(target.join("packed-refs")).expect("packed-refs");
    let text = String::from_utf8(packed).expect("utf8");
    assert!(text.contains(&format!("{} refs/notes/commits\n", built.notes)));
    assert_eq!(store.hash_kind(), HashKind::Sha1);
}
