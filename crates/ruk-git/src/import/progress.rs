//! Cooperative cancellation and progress for one import.
//!
//! The import polls [`ImportProgress::is_cancelled`] between objects and
//! batches; a lane or an operator thread may call [`ImportProgress::cancel`]
//! at any time. Every field is an atomic, so no lock is ever held across
//! source or store I/O and a reader never blocks the import.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Shared progress and cancellation state of one import.
#[derive(Debug, Default)]
pub struct ImportProgress {
    cancelled: AtomicBool,
    objects_read: AtomicU64,
    objects_published: AtomicU64,
    bytes_read: AtomicU64,
    batches: AtomicU64,
    refs: AtomicU64,
}

/// A point-in-time copy of the counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProgressSnapshot {
    /// Source objects read and verified.
    pub objects_read: u64,
    /// Objects durably handed to the publish sink.
    pub objects_published: u64,
    /// Decoded payload bytes read from the source.
    pub bytes_read: u64,
    /// Batches durably published.
    pub batches: u64,
    /// Source refs enumerated.
    pub refs: u64,
}

impl ImportProgress {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. The import stops at its next poll; batches
    /// already published stay published, and no ref fact is published.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            objects_read: self.objects_read.load(Ordering::Relaxed),
            objects_published: self.objects_published.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            batches: self.batches.load(Ordering::Relaxed),
            refs: self.refs.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn object_read(&self, bytes: u64) {
        self.objects_read.fetch_add(1, Ordering::Relaxed);
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn batch_published(&self, objects: u64) {
        self.objects_published.fetch_add(objects, Ordering::Relaxed);
        self.batches.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn refs_seen(&self, count: u64) {
        self.refs.fetch_add(count, Ordering::Relaxed);
    }
}
