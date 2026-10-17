//! Byte-bounded reachability checkpoint and query cache.
//!
//! # Sound resident memory bounds
//!
//! - Fixed-capacity slot storage: Cache container memory (slots, hash index, and LRU links)
//!   is fully calculated and pre-reserved from [`ByteBudget`] on construction.
//! - Storage entries hold exact [`Box<[u8]>`] serialized Roaring bytes. Their memory
//!   is pre-reserved before vector allocation, and the reservation lives inside the
//!   [`Arc<CachedReachabilityEntry>`] until the last clone is dropped.
//! - Queries deserialize into a bounded, caller-charged scope ([`ScopedReachability`]),
//!   returning decode scratch memory to the caller's budget on drop.
//! - Doubly-linked LRU with an open-addressing hash table delivers $O(1)$ lookups,
//!   $O(1)$ MRU updates, and $O(1)$ evictions without linear map scans.
//! - Mutex poisoning panics immediately.

use std::sync::{Arc, Mutex};

use roaring::RoaringBitmap;

use crate::budget::{ByteBudget, ByteReservation};
use crate::error::{CoreError, ErrorCode};
use crate::graph::types::GlobalPosition;
use crate::heads::Head;

const EMPTY_INDEX: usize = usize::MAX;
pub(crate) const DEFAULT_MAX_CACHE_ENTRIES: usize = 256;

/// A cached reachability checkpoint holding an immutable, pre-reserved byte slice.
pub(crate) struct CachedReachabilityEntry {
    _reservation: ByteReservation,
    serialized_bytes: Box<[u8]>,
    cardinality: u64,
}

impl CachedReachabilityEntry {
    /// Deserializes the bitmap into a bounded temporary scope charged to `budget`.
    pub(crate) fn decode_scoped(
        &self,
        budget: &Arc<ByteBudget>,
    ) -> Result<ScopedReachability, CoreError> {
        let decode_bound = (self.serialized_bytes.len() as u64)
            .saturating_mul(4)
            .max(1024);
        let reservation = budget.reserve(decode_bound)?;
        let bitmap = RoaringBitmap::deserialize_from(&self.serialized_bytes[..])
            .map_err(|e| CoreError::new(ErrorCode::ECorrupt, format!("failed decoding roaring bitmap: {e}")))?;
        Ok(ScopedReachability {
            _reservation: reservation,
            bitmap,
        })
    }

    /// Number of reachable commits represented in this checkpoint.
    #[must_use]
    pub(crate) fn cardinality(&self) -> u64 {
        self.cardinality
    }

    /// Byte length of the stored serialized bitmap payload.
    #[must_use]
    pub(crate) fn serialized_len(&self) -> usize {
        self.serialized_bytes.len()
    }
}

/// Bounded temporary decoded bitmap holding an active reservation against `budget`.
pub(crate) struct ScopedReachability {
    _reservation: ByteReservation,
    bitmap: RoaringBitmap,
}

impl ScopedReachability {
    /// Checks if `pos` is contained in this reachability checkpoint.
    #[must_use]
    pub(crate) fn contains(&self, pos: GlobalPosition) -> bool {
        self.bitmap.contains(pos.as_u32())
    }

    /// Access the underlying decoded bitmap.
    #[must_use]
    pub(crate) fn bitmap(&self) -> &RoaringBitmap {
        &self.bitmap
    }
}

struct Slot {
    head: Option<Head>,
    entry: Option<Arc<CachedReachabilityEntry>>,
    prev_lru: usize,
    next_lru: usize,
}

struct CacheInner {
    slots: Box<[Slot]>,
    hash_table: Box<[usize]>,
    lru_head: usize,
    lru_tail: usize,
    free_head: usize,
    count: usize,
}

/// Fixed-capacity, byte-bounded reachability cache.
pub(crate) struct ReachabilityCache {
    _container_reservation: ByteReservation,
    inner: Mutex<CacheInner>,
    budget: Arc<ByteBudget>,
}

impl ReachabilityCache {
    /// Creates a new cache with pre-reserved slot and index capacity.
    pub(crate) fn new(budget: Arc<ByteBudget>, max_entries: usize) -> Result<Self, CoreError> {
        let capacity = max_entries.max(16);
        let hash_size = capacity.checked_mul(2).ok_or_else(|| {
            CoreError::new(ErrorCode::ECapacity, "cache capacity overflow")
        })?;

        let slot_bytes = (capacity as u64) * (std::mem::size_of::<Slot>() as u64);
        let hash_bytes = (hash_size as u64) * (std::mem::size_of::<usize>() as u64);
        let container_bytes = slot_bytes.saturating_add(hash_bytes);

        let container_reservation = budget.reserve(container_bytes)?;

        let mut slots_vec = Vec::with_capacity(capacity);
        for i in 0..capacity {
            slots_vec.push(Slot {
                head: None,
                entry: None,
                prev_lru: EMPTY_INDEX,
                next_lru: if i + 1 < capacity { i + 1 } else { EMPTY_INDEX },
            });
        }

        let hash_table = vec![EMPTY_INDEX; hash_size].into_boxed_slice();

        Ok(Self {
            _container_reservation: container_reservation,
            inner: Mutex::new(CacheInner {
                slots: slots_vec.into_boxed_slice(),
                hash_table,
                lru_head: EMPTY_INDEX,
                lru_tail: EMPTY_INDEX,
                free_head: 0,
                count: 0,
            }),
            budget,
        })
    }

    #[inline]
    fn hash_head(head: &Head, mask: usize) -> usize {
        let digest = match head {
            Head::Git { oid } => oid.as_bytes(),
            Head::Conflicted { key } => key.as_bytes(),
        };
        let b0 = digest[0] as usize;
        let b1 = digest[1] as usize;
        let b2 = digest[2] as usize;
        let b3 = digest[3] as usize;
        let combined = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        combined & mask
    }

    /// Looks up a cached reachability checkpoint by commit [`Head`].
    #[must_use]
    pub(crate) fn get(&self, head: &Head) -> Option<Arc<CachedReachabilityEntry>> {
        let mut inner = self.inner.lock().expect("reachability cache mutex poisoned");
        let slot_idx = Self::find_slot(&inner, head)?;
        Self::touch_mru(&mut inner, slot_idx);
        inner.slots[slot_idx].entry.as_ref().map(Arc::clone)
    }

    fn find_slot(inner: &CacheInner, head: &Head) -> Option<usize> {
        let mask = inner.hash_table.len() - 1;
        let mut idx = Self::hash_head(head, mask);

        for _ in 0..inner.hash_table.len() {
            let slot_idx = inner.hash_table[idx];
            if slot_idx == EMPTY_INDEX {
                return None;
            }
            if inner.slots[slot_idx].head.as_ref() == Some(head) {
                return Some(slot_idx);
            }
            idx = (idx + 1) & mask;
        }
        None
    }

    fn touch_mru(inner: &mut CacheInner, slot_idx: usize) {
        if inner.lru_head == slot_idx {
            return;
        }

        // Unlink from current position
        let prev = inner.slots[slot_idx].prev_lru;
        let next = inner.slots[slot_idx].next_lru;

        if prev != EMPTY_INDEX {
            inner.slots[prev].next_lru = next;
        }
        if next != EMPTY_INDEX {
            inner.slots[next].prev_lru = prev;
        }
        if inner.lru_tail == slot_idx {
            inner.lru_tail = prev;
        }

        // Push to head
        inner.slots[slot_idx].prev_lru = EMPTY_INDEX;
        inner.slots[slot_idx].next_lru = inner.lru_head;

        if inner.lru_head != EMPTY_INDEX {
            inner.slots[inner.lru_head].prev_lru = slot_idx;
        }
        inner.lru_head = slot_idx;

        if inner.lru_tail == EMPTY_INDEX {
            inner.lru_tail = slot_idx;
        }
    }

    fn remove_lru_tail(inner: &mut CacheInner) -> Option<Arc<CachedReachabilityEntry>> {
        let tail_idx = inner.lru_tail;
        if tail_idx == EMPTY_INDEX {
            return None;
        }

        let prev = inner.slots[tail_idx].prev_lru;
        if prev != EMPTY_INDEX {
            inner.slots[prev].next_lru = EMPTY_INDEX;
            inner.lru_tail = prev;
        } else {
            inner.lru_head = EMPTY_INDEX;
            inner.lru_tail = EMPTY_INDEX;
        }

        // Unhash
        if let Some(h) = &inner.slots[tail_idx].head {
            let mask = inner.hash_table.len() - 1;
            let mut idx = Self::hash_head(h, mask);
            while inner.hash_table[idx] != EMPTY_INDEX {
                if inner.hash_table[idx] == tail_idx {
                    inner.hash_table[idx] = EMPTY_INDEX;
                    break;
                }
                idx = (idx + 1) & mask;
            }
        }

        inner.slots[tail_idx].head = None;
        let entry = inner.slots[tail_idx].entry.take();

        // Return to free list
        inner.slots[tail_idx].prev_lru = EMPTY_INDEX;
        inner.slots[tail_idx].next_lru = inner.free_head;
        inner.free_head = tail_idx;
        inner.count -= 1;

        entry
    }

    /// Attempts to admit a reachability checkpoint into resident storage.
    pub(crate) fn admit(
        &self,
        head: Head,
        bitmap: &RoaringBitmap,
    ) -> Result<Option<Arc<CachedReachabilityEntry>>, CoreError> {
        let encoded_len = bitmap.serialized_size();
        let resident_memory = (encoded_len as u64)
            .saturating_add(std::mem::size_of::<CachedReachabilityEntry>() as u64);

        let mut reservation = self.budget.reserve(resident_memory);

        let mut inner = self.inner.lock().expect("reachability cache mutex poisoned");

        // If head already exists, replace entry
        if let Some(existing_slot) = Self::find_slot(&inner, &head) {
            Self::touch_mru(&mut inner, existing_slot);
            if let Ok(res) = reservation {
                let mut buf = Vec::with_capacity(encoded_len);
                bitmap.serialize_into(&mut buf).map_err(|e| {
                    CoreError::new(ErrorCode::EIo, format!("failed serializing roaring bitmap: {e}"))
                })?;
                let entry = Arc::new(CachedReachabilityEntry {
                    _reservation: res,
                    serialized_bytes: buf.into_boxed_slice(),
                    cardinality: bitmap.len(),
                });
                inner.slots[existing_slot].entry = Some(Arc::clone(&entry));
                return Ok(Some(entry));
            }
        }

        // Evict LRU entries if needed
        while reservation.is_err() && inner.count > 0 {
            drop(Self::remove_lru_tail(&mut inner));
            reservation = self.budget.reserve(resident_memory);
        }

        // If no free slots, evict one slot
        if inner.free_head == EMPTY_INDEX && inner.count > 0 {
            drop(Self::remove_lru_tail(&mut inner));
            if reservation.is_err() {
                reservation = self.budget.reserve(resident_memory);
            }
        }

        let Ok(res) = reservation else {
            return Ok(None);
        };

        if inner.free_head == EMPTY_INDEX {
            return Ok(None);
        }

        let mut buf = Vec::with_capacity(encoded_len);
        bitmap.serialize_into(&mut buf).map_err(|e| {
            CoreError::new(ErrorCode::EIo, format!("failed serializing roaring bitmap: {e}"))
        })?;

        let entry = Arc::new(CachedReachabilityEntry {
            _reservation: res,
            serialized_bytes: buf.into_boxed_slice(),
            cardinality: bitmap.len(),
        });

        let slot_idx = inner.free_head;
        inner.free_head = inner.slots[slot_idx].next_lru;

        inner.slots[slot_idx].head = Some(head);
        inner.slots[slot_idx].entry = Some(Arc::clone(&entry));
        inner.count += 1;

        // Insert into hash table
        let mask = inner.hash_table.len() - 1;
        let mut h_idx = Self::hash_head(&head, mask);
        while inner.hash_table[h_idx] != EMPTY_INDEX {
            h_idx = (h_idx + 1) & mask;
        }
        inner.hash_table[h_idx] = slot_idx;

        Self::touch_mru(&mut inner, slot_idx);

        Ok(Some(entry))
    }

    /// Number of cached checkpoints currently held.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().expect("reachability cache mutex poisoned").count
    }

    /// True if the cache contains no entries.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
