//! Private-object exclusion for pack emission and negotiation.
//!
//! A private object is present in the local store but must never leave it:
//! it is never a pack walk root, never a have, never a thin base, and never
//! an emitted pack member. A promised object (a [`PromisorRow`] in
//! [`FactTable::Promisor`]) is likewise never emitted: the local store does
//! not hold its bytes, so naming it would corrupt the pack.
//!
//! [`PrivateFilter`] is the explicit caller-supplied set of private OIDs.
//! [`PrivateClosure`] is the same set expanded through the full object
//! closure of its roots, so marking one private tip excludes everything it
//! reaches. Store-aware predicates treat an explicit member or a promised
//! OID as excluded. Callers filter roots and haves before any walk or any
//! wire encoding; the pack walkers skip excluded OIDs without descending
//! from excluded roots, so private history stays private at the cost of a
//! larger pack when public history is reachable only through it.

use std::collections::{HashSet, VecDeque};

use ruk_core::ids::Oid;
use ruk_core::store::Store;

use super::pack::{Links, object_links};
use super::{Interrupt, promisor_row, read_object};
use crate::GitError;

/// Largest object pulled through a private-closure expansion.
const EXPAND_OBJECT_BYTES: u64 = 512 << 20;

/// The explicit set of private object identities.
///
/// Membership is exact: only the listed OIDs are private. Use
/// [`PrivateClosure::expand`] to grow one private tip into the full set of
/// OIDs it reaches before filtering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrivateFilter {
    /// Exact private identities.
    oids: HashSet<Oid>,
}

impl PrivateFilter {
    /// An empty filter: nothing is explicitly private.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            oids: HashSet::new(),
        }
    }

    /// A filter holding exactly `oids`.
    #[must_use]
    pub fn from_oids(oids: impl IntoIterator<Item = Oid>) -> Self {
        Self {
            oids: oids.into_iter().collect(),
        }
    }

    /// A filter holding exactly the closure's OIDs, moved without copying.
    #[must_use]
    pub fn from_closure(closure: PrivateClosure) -> Self {
        Self { oids: closure.oids }
    }

    /// Inserts `oid`, reporting whether it was newly present.
    pub fn insert(&mut self, oid: Oid) -> bool {
        self.oids.insert(oid)
    }

    /// Whether `oid` is explicitly private, ignoring store state.
    #[must_use]
    pub fn contains(&self, oid: Oid) -> bool {
        self.oids.contains(&oid)
    }

    /// How many OIDs are explicitly private.
    #[must_use]
    pub fn len(&self) -> usize {
        self.oids.len()
    }

    /// Whether no OID is explicitly private.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.oids.is_empty()
    }

    /// Every explicitly private OID.
    #[must_use]
    pub fn oids(&self) -> &HashSet<Oid> {
        &self.oids
    }

    /// Whether `oid` is excluded: explicitly private or promised.
    ///
    /// # Errors
    /// Store failures; a malformed promisor row is [`GitError::Corrupt`].
    pub fn is_excluded(&self, store: &Store, oid: Oid) -> Result<bool, GitError> {
        if self.oids.contains(&oid) {
            return Ok(true);
        }
        Ok(promisor_row(store, oid)?.is_some())
    }

    /// Whether `oid` may be emitted: neither private nor promised.
    ///
    /// # Errors
    /// Store failures; a malformed promisor row is [`GitError::Corrupt`].
    pub fn should_emit(&self, store: &Store, oid: Oid) -> Result<bool, GitError> {
        Ok(!self.is_excluded(store, oid)?)
    }

    /// Removes explicitly private OIDs from `roots`, preserving order.
    #[must_use]
    pub fn filter_roots(&self, roots: &[Oid]) -> Vec<Oid> {
        roots
            .iter()
            .copied()
            .filter(|oid| !self.oids.contains(oid))
            .collect()
    }

    /// Removes excluded OIDs (private or promised) from `roots`.
    ///
    /// # Errors
    /// Store failures; a malformed promisor row is [`GitError::Corrupt`].
    pub fn filter_roots_store(&self, store: &Store, roots: &[Oid]) -> Result<Vec<Oid>, GitError> {
        let mut kept = Vec::with_capacity(roots.len());
        for oid in roots.iter().copied() {
            if !self.is_excluded(store, oid)? {
                kept.push(oid);
            }
        }
        Ok(kept)
    }

    /// Removes explicitly private OIDs from `haves`, preserving order.
    #[must_use]
    pub fn filter_haves(&self, haves: &[Oid]) -> Vec<Oid> {
        haves
            .iter()
            .copied()
            .filter(|oid| !self.oids.contains(oid))
            .collect()
    }

    /// Removes excluded OIDs (private or promised) from `haves`.
    ///
    /// # Errors
    /// Store failures; a malformed promisor row is [`GitError::Corrupt`].
    pub fn filter_haves_store(&self, store: &Store, haves: &[Oid]) -> Result<Vec<Oid>, GitError> {
        let mut kept = Vec::with_capacity(haves.len());
        for oid in haves.iter().copied() {
            if !self.is_excluded(store, oid)? {
                kept.push(oid);
            }
        }
        Ok(kept)
    }
}

/// The full object closure of a set of private roots.
///
/// Built once with [`PrivateClosure::expand`], then converted into a
/// [`PrivateFilter`] for pack and negotiation guards.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrivateClosure {
    /// Every OID reachable from the expanded roots, including the roots.
    oids: HashSet<Oid>,
}

impl PrivateClosure {
    /// An empty closure: nothing is private.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            oids: HashSet::new(),
        }
    }

    /// Every OID in the closure.
    #[must_use]
    pub fn oids(&self) -> &HashSet<Oid> {
        &self.oids
    }

    /// How many OIDs the closure holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.oids.len()
    }

    /// Whether the closure holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.oids.is_empty()
    }

    /// Whether `oid` is in the closure.
    #[must_use]
    pub fn contains(&self, oid: Oid) -> bool {
        self.oids.contains(&oid)
    }

    /// Expands `roots` through their full object closures.
    ///
    /// Every reachable commit, tree, blob, and tag joins the set; missing
    /// objects stop the walk without error so a partially present private
    /// history still excludes what is present.
    ///
    /// # Errors
    /// Store failures other than absence, malformed payloads, and
    /// cancellation or deadline trips.
    pub fn expand(store: &Store, roots: &[Oid], interrupt: &Interrupt) -> Result<Self, GitError> {
        let mut oids = HashSet::new();
        let mut queue: VecDeque<Oid> = roots.iter().copied().collect();
        while let Some(oid) = queue.pop_front() {
            interrupt.check("expanding the private closure")?;
            if !oids.insert(oid) {
                continue;
            }
            let found = match read_object(store, oid, EXPAND_OBJECT_BYTES) {
                Ok((kind, bytes)) => Some((kind, bytes)),
                Err(err) if matches!(err, GitError::NotFound { .. }) => None,
                Err(err) => return Err(err),
            };
            let Some((kind, bytes)) = found else {
                continue;
            };
            let links = object_links(kind, &bytes, store.hash_kind())?;
            enqueue_links(&links, &mut queue);
        }
        Ok(Self { oids })
    }

    /// Converts the closure into an emission filter, moved without copying.
    #[must_use]
    pub fn into_filter(self) -> PrivateFilter {
        PrivateFilter { oids: self.oids }
    }
}

/// Enqueues every object one link set names.
fn enqueue_links(links: &Links, queue: &mut VecDeque<Oid>) {
    if let Some(tree) = links.tree {
        queue.push_back(tree);
    }
    queue.extend(links.parents.iter().copied());
    queue.extend(links.entries.iter().map(|(oid, _)| *oid));
    if let Some((target, _)) = links.tag_target {
        queue.push_back(target);
    }
}

/// Whether `oid` is promised by a partial clone and therefore unemittable.
///
/// # Errors
/// Store failures; a malformed row is [`GitError::Corrupt`].
pub fn is_promised(store: &Store, oid: Oid) -> Result<bool, GitError> {
    Ok(promisor_row(store, oid)?.is_some())
}

/// Removes excluded OIDs (private or promised) from `oids`.
///
/// # Errors
/// Store failures; a malformed promisor row is [`GitError::Corrupt`].
pub fn exclude_private_oids(
    store: &Store,
    filter: &PrivateFilter,
    oids: &[Oid],
) -> Result<Vec<Oid>, GitError> {
    filter.filter_roots_store(store, oids)
}
