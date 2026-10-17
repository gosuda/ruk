use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Bound;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use redb::backends::FileBackend;
use redb::{BackendError, Database, ReadableDatabase, StorageBackend, StorageError, TableDefinition};

const VALUES: TableDefinition<u64, &[u8]> = TableDefinition::new("values");

fn open_file(path: &std::path::Path) -> File {
    OpenOptions::new().read(true).write(true).open(path).unwrap()
}

fn seed(db: &Database) {
    let transaction = db.begin_write().unwrap();
    transaction.open_table(VALUES).unwrap().insert(0, b"old".as_slice()).unwrap();
    transaction.commit().unwrap();
}

fn value(db: &Database) -> Vec<u8> {
    db.begin_read().unwrap().open_table(VALUES).unwrap().get(0).unwrap().unwrap().value().to_vec()
}

#[test]
fn readers_keep_old_root_until_external_durability_finishes() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let db = Database::create(file.path()).unwrap();
    seed(&db);
    let old_view = db.begin_read().unwrap();
    let transaction = db.begin_write().unwrap();
    transaction.open_table(VALUES).unwrap().insert(0, b"new".as_slice()).unwrap();
    let mut calls = 0;
    transaction.commit_with_pre_publish(|| {
        calls += 1;
        assert_eq!(value(&db), b"old");
        Ok(())
    }).unwrap();
    assert_eq!(calls, 1);
    assert_eq!(value(&db), b"new");
    assert_eq!(old_view.open_table(VALUES).unwrap().get(0).unwrap().unwrap().value(), b"old");
    drop(old_view);
    drop(db);
    let reopened = Database::builder().open_with_backend(FileBackend::new(open_file(file.path())).unwrap()).unwrap();
    assert_eq!(value(&reopened), b"new");
}

#[test]
fn callback_error_closes_writer_and_reopen_preserves_durable_root() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let db = Database::create(file.path()).unwrap();
    seed(&db);
    let transaction = db.begin_write().unwrap();
    transaction.open_table(VALUES).unwrap().insert(0, b"unpublished".as_slice()).unwrap();
    assert!(transaction.commit_with_pre_publish(|| {
        Err(StorageError::Io(io::Error::other("external flush failed")))
    }).is_err());
    assert!(db.begin_write().is_err());
    drop(db);
    let reopened = Database::open(file.path()).unwrap();
    assert_eq!(value(&reopened), b"old");
    let transaction = reopened.begin_write().unwrap();
    transaction.open_table(VALUES).unwrap().insert(0, b"recovered".as_slice()).unwrap();
    transaction.commit_with_pre_publish(|| Ok(())).unwrap();
    assert_eq!(value(&reopened), b"recovered");
}

#[test]
fn callback_panic_does_not_abort_adopted_allocator_pages() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let db = Database::create(file.path()).unwrap();
    seed(&db);
    let transaction = db.begin_write().unwrap();
    transaction.open_table(VALUES).unwrap().insert(0, b"unpublished".as_slice()).unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| {
        transaction.commit_with_pre_publish(|| panic!("external producer panicked"))
    }));
    assert!(result.is_err());
    assert!(db.begin_write().is_err());
    drop(db);
    let reopened = Database::open(file.path()).unwrap();
    assert_eq!(value(&reopened), b"old");
    reopened.begin_write().unwrap().commit().unwrap();
}

#[derive(Debug)]
struct GrowthBoundary {
    file: FileBackend,
    sealed: Arc<AtomicBool>,
}

impl StorageBackend for GrowthBoundary {
    fn len(&self) -> io::Result<u64> { self.file.len() }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> { self.file.read(offset, out) }
    fn set_len(&self, len: u64) -> io::Result<()> {
        if self.sealed.load(Ordering::SeqCst) && len > self.file.len()? {
            return Err(io::Error::other("database grew after external durability boundary"));
        }
        self.file.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> { self.file.sync_data() }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> { self.file.write(offset, bytes) }
    fn close(&self) -> io::Result<()> { self.file.close() }
    fn try_lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<bool, BackendError> { self.file.try_lock_range(start, end) }
    fn try_lock_shared_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<bool, BackendError> { self.file.try_lock_shared_range(start, end) }
    fn lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> { self.file.lock_range(start, end) }
    fn lock_shared_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> { self.file.lock_shared_range(start, end) }
    fn unlock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> { self.file.unlock_range(start, end) }
    fn query_lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<bool, BackendError> { self.file.query_lock_range(start, end) }
}

#[test]
fn repeated_reclamation_never_grows_storage_after_callback() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let sealed = Arc::new(AtomicBool::new(false));
    let db = Database::builder().set_cache_size(0).create_with_backend(GrowthBoundary {
        file: FileBackend::new(open_file(file.path())).unwrap(),
        sealed: Arc::clone(&sealed),
    }).unwrap();
    for generation in 0..12u8 {
        sealed.store(false, Ordering::SeqCst);
        let mut transaction = db.begin_write().unwrap();
        transaction.set_quick_repair(true);
        let payload = vec![generation; 128 * 1024];
        {
            let mut table = transaction.open_table(VALUES).unwrap();
            for key in 0..24u64 {
                table.insert(key, payload.as_slice()).unwrap();
            }
        }
        transaction.commit_with_pre_publish(|| {
            sealed.store(true, Ordering::SeqCst);
            Ok(())
        }).unwrap();
        assert_eq!(value(&db), payload);
    }
    drop(db);
    let reopened = Database::open(file.path()).unwrap();
    assert_eq!(value(&reopened), vec![11; 128 * 1024]);
}

#[test]
fn open_backend_does_not_initialize_empty_or_truncated_storage() {
    let empty = tempfile::NamedTempFile::new().unwrap();
    assert!(Database::builder().open_with_backend(FileBackend::new(open_file(empty.path())).unwrap()).is_err());
    assert_eq!(empty.as_file().metadata().unwrap().len(), 0);
    let truncated = tempfile::NamedTempFile::new().unwrap();
    {
        let db = Database::create(truncated.path()).unwrap();
        seed(&db);
    }
    truncated.as_file().set_len(8).unwrap();
    let before = std::fs::read(truncated.path()).unwrap();
    assert!(Database::builder().open_with_backend(FileBackend::new(open_file(truncated.path())).unwrap()).is_err());
    assert_eq!(std::fs::read(truncated.path()).unwrap(), before);
}
