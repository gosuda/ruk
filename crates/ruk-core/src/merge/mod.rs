// Copyright 2023 The Jujutsu Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is a modified port of jj 0.46.0 `core/src/merge.rs` (changes
// described in the module documentation below).

//! The jj merge algebra: ordered odd-length `+,-,+,...,+` term sequences.
//!
//! Ported from jj 0.46.0 `core/src/merge.rs` (Apache-2.0, The Jujutsu
//! Authors) with semantics preserved exactly: the algebra, simplification,
//! flattening, and trivial-resolution behavior are unchanged. Changes made
//! for Ruk, recorded at the definitions that carry them:
//!
//! * `SameChange` gains `Serialize`/`JsonSchema`, and Ruk's default is
//!   [`SameChange::Keep`] (jj's product default is `accept`);
//! * `Merge` gains a validated `Deserialize` (odd, non-empty term arrays),
//!   `JsonSchema`, [`Merge::try_from_vec`], and
//!   [`Merge::resolve_trivial_default`];
//! * `Diff` is carried over unchanged;
//! * jj's `ContentHash`/blake2/proc-macro machinery and `try_map_async` are
//!   omitted: native canonical object identity owns hashing and this crate
//!   has no async runtime;
//! * `itertools::zip_longest` and `hashbrown` uses are replaced with
//!   equivalent std code (same panic contract for mismatched lengths).
//!
//! The license text is retained in `crates/ruk-core/licenses/`.

pub mod composed;
pub mod syntax;

use core::fmt;
use core::hash::Hash;
use core::ops::Deref;
use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use smallvec::{SmallVec, smallvec, smallvec_inline};

/// A generic diff/transition from one value to another.
///
/// This is not a diff in the `patch(1)` sense.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Diff<T> {
    /// The state before
    pub before: T,
    /// The state after
    pub after: T,
}

impl<T> Diff<T> {
    /// Create a new diff
    pub fn new(before: T, after: T) -> Self {
        Self { before, after }
    }

    /// Apply a function to both values
    pub fn map<U>(self, mut f: impl FnMut(T) -> U) -> Diff<U> {
        Diff {
            before: f(self.before),
            after: f(self.after),
        }
    }

    /// Combine a `Diff<T>` and a `Diff<U>` into a `Diff<(T, U)>`.
    pub fn zip<U>(self, other: Diff<U>) -> Diff<(T, U)> {
        Diff {
            before: (self.before, other.before),
            after: (self.after, other.after),
        }
    }

    /// Inverts a diff, swapping the before and after terms.
    pub fn invert(self) -> Self {
        Self {
            before: self.after,
            after: self.before,
        }
    }

    /// Convert a `&Diff<T>` into a `Diff<&T>`.
    pub fn as_ref(&self) -> Diff<&T> {
        Diff {
            before: &self.before,
            after: &self.after,
        }
    }

    /// Converts a `Diff<T>` or `&Diff<T>` to `Diff<&T::Target>`. (e.g.
    /// `Diff<String>` to `Diff<&str>`)
    pub fn as_deref(&self) -> Diff<&T::Target>
    where
        T: Deref,
    {
        self.as_ref().map(Deref::deref)
    }

    /// Convert a diff into an array `[before, after]`.
    pub fn into_array(self) -> [T; 2] {
        [self.before, self.after]
    }
}

impl<T: Eq> Diff<T> {
    /// Whether the diff represents a change, i.e. if `before` and `after` are
    /// not equal
    pub fn is_changed(&self) -> bool {
        self.before != self.after
    }
}

/// Whether to resolve a conflict that makes the same change at all sides.
///
/// jj derives only `Deserialize`; Ruk requires the wire type in method
/// schemas, so this derives both directions and `JsonSchema`. jj's product
/// default is `accept`; Ruk's model default is [`SameChange::Keep`], reached
/// through `SameChange::default()` and `Merge::resolve_trivial_default`.
/// `Accept` stays reachable only through an explicit resolution argument.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum SameChange {
    /// Leaves same-change conflict unresolved. Ruk's model default.
    #[default]
    Keep,
    /// Resolves same-change conflict as if one side were unchanged.
    /// (i.e. `A+(A-B)=A`)
    ///
    /// This matches what Git and Mercurial do (in the 3-way case at least),
    /// but not what Darcs does. It means that repeated 3-way merging of
    /// multiple trees may give different results depending on the order of
    /// merging.
    Accept,
}

/// Attempt to resolve trivial conflicts between the inputs. There must be
/// an odd number of terms.
#[must_use]
pub fn trivial_merge<T>(values: &[T], same_change: SameChange) -> Option<&T>
where
    T: Eq + Hash,
{
    assert!(
        values.len() % 2 == 1,
        "trivial_merge() requires an odd number of terms"
    );
    // Optimize the common cases of 3-way merge and 1-way (non-)merge
    if let [add] = values {
        return Some(add);
    } else if let [add0, remove, add1] = values {
        return if add0 == add1 && same_change == SameChange::Accept {
            Some(add0)
        } else if add0 == remove {
            Some(add1)
        } else if add1 == remove {
            Some(add0)
        } else {
            None
        };
    }

    // Number of occurrences of each value, with positive indexes counted as +1 and
    // negative as -1, thereby letting positive and negative terms with the same
    // value (i.e. key in the map) cancel each other.
    let mut counts: std::collections::HashMap<&T, i32> = std::collections::HashMap::new();
    for (value, n) in values.iter().zip([1, -1].into_iter().cycle()) {
        counts.entry(value).and_modify(|e| *e += n).or_insert(n);
    }

    // Collect non-zero value. Values with a count of 0 mean that they have
    // canceled out.
    counts.retain(|_, count| *count != 0);
    if counts.len() == 1 {
        // If there is a single value with a count of 1 left, then that is the result.
        let (value, count) = counts.into_iter().next().expect("len checked == 1");
        debug_assert_eq!(count, 1);
        Some(value)
    } else if counts.len() == 2 && same_change == SameChange::Accept {
        // All sides made the same change.
        let mut iter = counts.into_iter();
        let (value1, count1) = iter.next().expect("len checked == 2");
        let (value2, count2) = iter.next().expect("len checked == 2");
        debug_assert_eq!(count1 + count2, 1);
        if count1 > 0 {
            Some(value1)
        } else {
            Some(value2)
        }
    } else {
        None
    }
}

/// A generic representation of merged values.
///
/// There is exactly one more `adds()` than `removes()`. When interpreted as a
/// series of diffs, the merge's (i+1)-st add is matched with the i-th
/// remove. The zeroth add is considered a diff from the non-existent state.
///
/// The wire shape is jj's: a transparent bare term array. Deserialization is
/// validated — an empty or even-length term array is rejected at the
/// boundary rather than admitted as an invalid state.
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct Merge<T> {
    /// Alternates between positive and negative terms, starting with positive.
    values: SmallVec<[T; 1]>,
}

impl<T: fmt::Debug> fmt::Debug for Merge<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format like an enum with two variants to make it less verbose in the common
        // case of a resolved state.
        if let Some(value) = self.as_resolved() {
            f.debug_tuple("Resolved").field(value).finish()
        } else {
            f.debug_tuple("Conflicted").field(&self.values).finish()
        }
    }
}

impl<T> Merge<T> {
    /// Creates a `Merge` from the given values, in which positive and negative
    /// terms alternate.
    ///
    /// # Panics
    /// Panics when `values` has an even number of terms (jj contract).
    pub fn from_vec(values: impl Into<SmallVec<[T; 1]>>) -> Self {
        let values = values.into();
        assert!(values.len() % 2 != 0, "must have an odd number of terms");
        Self { values }
    }

    /// Creates a new merge object from the given removes and adds.
    ///
    /// # Panics
    /// Panics when `adds` is empty.
    pub fn from_removes_adds(
        removes: impl IntoIterator<Item = T>,
        adds: impl IntoIterator<Item = T>,
    ) -> Self {
        let mut removes = removes.into_iter();
        let mut adds = adds.into_iter();
        let mut values = SmallVec::with_capacity(removes.size_hint().0 * 2 + 1);
        values.push(adds.next().expect("must have at least one add"));
        loop {
            match (removes.next(), adds.next()) {
                (Some(remove), Some(add)) => values.extend([remove, add]),
                (None, None) => break,
                _ => panic!("must have one more adds than removes"),
            }
        }
        Self { values }
    }

    /// Creates a `Merge` from a first side and a series of diffs to apply to
    /// that side.
    pub fn from_diffs(first_side: T, diffs: impl IntoIterator<Item = Diff<T>>) -> Self {
        let values = core::iter::once(first_side)
            .chain(diffs.into_iter().flat_map(Diff::into_array))
            .collect();
        Self { values }
    }

    /// Creates a `Merge` with a single resolved value.
    pub const fn resolved(value: T) -> Self {
        Self {
            values: smallvec_inline![value],
        }
    }

    /// Creates a `Merge` by repeating a single value.
    pub fn repeated(value: T, num_sides: usize) -> Self
    where
        T: Clone,
    {
        Self {
            values: smallvec![value; num_sides * 2 - 1],
        }
    }

    /// The removed values, also called negative terms.
    pub fn removes(&self) -> impl ExactSizeIterator<Item = &T> {
        self.values[1..].iter().step_by(2)
    }

    /// The added values, also called positive terms.
    pub fn adds(&self) -> impl ExactSizeIterator<Item = &T> {
        self.values.iter().step_by(2)
    }

    /// Return the removed values and added values and take the ownership.
    pub fn into_removes_adds(
        self,
    ) -> (
        impl ExactSizeIterator<Item = T>,
        impl ExactSizeIterator<Item = T>,
    ) {
        let (removes, adds): (Vec<_>, Vec<_>) = self
            .values
            .into_iter()
            .enumerate()
            .partition(|(n, _)| *n % 2 == 1);
        (
            removes.into_iter().map(|(_, item)| item),
            adds.into_iter().map(|(_, item)| item),
        )
    }

    /// Returns the zeroth added value, which is guaranteed to exist.
    pub fn first(&self) -> &T {
        &self.values[0]
    }

    /// Returns the `index`-th removed value, which is considered belonging to
    /// the `index`-th diff pair.
    pub fn get_remove(&self, index: usize) -> Option<&T> {
        self.values.get(index * 2 + 1)
    }

    /// Returns the `index`-th added value, which is considered belonging to the
    /// `index-1`-th diff pair. The zeroth add is a diff from the non-existent
    /// state.
    pub fn get_add(&self, index: usize) -> Option<&T> {
        self.values.get(index * 2)
    }

    /// Removes the specified "removed"/"added" values. The removed slots are
    /// replaced by the last "removed"/"added" values.
    pub fn swap_remove(&mut self, remove_index: usize, add_index: usize) -> (T, T) {
        // Swap with the last "added" and "removed" values in order.
        let add = self.values.swap_remove(add_index * 2);
        let remove = self.values.swap_remove(remove_index * 2 + 1);
        (remove, add)
    }

    /// The number of positive terms in the conflict.
    pub fn num_sides(&self) -> usize {
        self.values.len() / 2 + 1
    }

    /// Whether this merge is resolved. Does not resolve trivial merges.
    pub fn is_resolved(&self) -> bool {
        self.values.len() == 1
    }

    /// Returns the resolved value, if this merge is resolved. Does not
    /// resolve trivial merges.
    pub fn as_resolved(&self) -> Option<&T> {
        if let [value] = &self.values[..] {
            Some(value)
        } else {
            None
        }
    }

    /// Returns the resolved value, if this merge is resolved. Otherwise returns
    /// the merge itself as an `Err`. Does not resolve trivial merges.
    pub fn into_resolved(mut self) -> Result<T, Self> {
        if self.values.len() == 1 {
            Ok(self.values.pop().expect("len checked == 1"))
        } else {
            Err(self)
        }
    }

    /// Returns a vector mapping of a value's index in the simplified merge to
    /// its original index in the unsimplified merge.
    ///
    /// The merge is simplified by removing identical values in add and remove
    /// values.
    fn get_simplified_mapping(&self) -> Vec<usize>
    where
        T: PartialEq,
    {
        let unsimplified_len = self.values.len();
        let mut simplified_to_original_indices: Vec<usize> = (0..unsimplified_len).collect();

        let mut add_index = 0;
        while add_index < simplified_to_original_indices.len() {
            let add = &self.values[simplified_to_original_indices[add_index]];
            let mut remove_indices = simplified_to_original_indices
                .iter()
                .enumerate()
                .skip(1)
                .step_by(2);
            let paired = remove_indices
                .find(|&(_, original_remove_index)| &self.values[*original_remove_index] == add);
            if let Some((remove_index, _)) = paired {
                // Align the current "add" value to the `remove_index/2`-th diff, then
                // delete the diff pair.
                simplified_to_original_indices.swap(remove_index + 1, add_index);
                simplified_to_original_indices.drain(remove_index..remove_index + 2);
            } else {
                add_index += 2;
            }
        }

        simplified_to_original_indices
    }

    /// Apply the mapping returned by [`Self::get_simplified_mapping`].
    #[must_use]
    fn apply_simplified_mapping(&self, mapping: &[usize]) -> Self
    where
        T: Clone,
    {
        // Reorder values based on their new indices in the simplified merge.
        let values = mapping
            .iter()
            .map(|index| self.values[*index].clone())
            .collect();
        Self { values }
    }

    /// Simplify the merge by joining diffs like A->B and B->C into A->C.
    /// Also drops trivial diffs like A->A.
    #[must_use]
    pub fn simplify(&self) -> Self
    where
        T: PartialEq + Clone,
    {
        let mapping = self.get_simplified_mapping();
        self.apply_simplified_mapping(&mapping)
    }

    /// Simplify the merge, using a function to choose which values to compare.
    #[must_use]
    pub fn simplify_by<'a, U>(&'a self, f: impl FnMut(&'a T) -> U) -> Self
    where
        T: Clone,
        U: PartialEq,
    {
        let mapping = self.map(f).get_simplified_mapping();
        self.apply_simplified_mapping(&mapping)
    }

    /// Updates the merge based on the given simplified merge.
    ///
    /// # Panics
    /// Panics when `simplified` has a different term count than this merge's
    /// simplified form (jj contract).
    pub fn update_from_simplified(mut self, simplified: Self) -> Self
    where
        T: PartialEq,
    {
        let mapping = self.get_simplified_mapping();
        assert_eq!(mapping.len(), simplified.values.len());
        for (index, value) in mapping.into_iter().zip(simplified.values) {
            self.values[index] = value;
        }
        self
    }

    /// If this merge can be trivially resolved, returns the value it resolves
    /// to.
    #[must_use]
    pub fn resolve_trivial(&self, same_change: SameChange) -> Option<&T>
    where
        T: Eq + Hash,
    {
        trivial_merge(&self.values, same_change)
    }

    /// [`Self::resolve_trivial`] under Ruk's model default [`SameChange::Keep`].
    #[must_use]
    pub fn resolve_trivial_default(&self) -> Option<&T>
    where
        T: Eq + Hash,
    {
        self.resolve_trivial(SameChange::default())
    }

    /// Returns a slice containing the terms. The items will alternate between
    /// positive and negative terms, starting with positive (since there's one
    /// more of those).
    pub fn as_slice(&self) -> &[T] {
        &self.values
    }

    /// Returns an iterator over references to the terms. The items will
    /// alternate between positive and negative terms, starting with
    /// positive (since there's one more of those).
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.values.iter()
    }

    /// A version of `Merge::iter()` that iterates over mutable references.
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.values.iter_mut()
    }

    /// Creates a new merge by applying `f` to each remove and add.
    pub fn map<'a, U>(&'a self, f: impl FnMut(&'a T) -> U) -> Merge<U> {
        let values = self.values.iter().map(f).collect();
        Merge { values }
    }

    /// Creates a new merge by applying `f` to each remove and add, consuming
    /// `self`.
    pub fn into_map<U>(self, f: impl FnMut(T) -> U) -> Merge<U> {
        let values = self.values.into_iter().map(f).collect();
        Merge { values }
    }

    /// Creates a new merge by applying `f` to each remove and add, returning
    /// `Err` if `f` returns `Err` for any of them.
    pub fn try_map<'a, U, E>(
        &'a self,
        f: impl FnMut(&'a T) -> Result<U, E>,
    ) -> Result<Merge<U>, E> {
        let values: SmallVec<[U; 1]> = self
            .values
            .iter()
            .map(f)
            .collect::<Result<SmallVec<[U; 1]>, E>>()?;
        Ok(Merge { values })
    }

    /// Converts a `&Merge<T>` into a `Merge<&T>`.
    pub fn as_ref(&self) -> Merge<&T> {
        let values = self.values.iter().collect();
        Merge { values }
    }

    /// Zip two merges which have the same number of terms. Panics if the merges
    /// don't have the same number of terms.
    pub fn zip<U>(self, other: Merge<U>) -> Merge<(T, U)> {
        assert_eq!(self.values.len(), other.values.len());
        let values = self.values.into_iter().zip(other.values).collect();
        Merge { values }
    }
}

impl<T, U> Merge<(T, U)> {
    /// Unzips a merge of pairs into a pair of merges.
    pub fn unzip(self) -> (Merge<T>, Merge<U>) {
        let (left, right): (SmallVec<[T; 1]>, SmallVec<[U; 1]>) = self.values.into_iter().unzip();
        (Merge { values: left }, Merge { values: right })
    }
}

impl<T> Merge<&'_ T> {
    /// Convert a `Merge<&T>` into a `Merge<T>` by cloning each term.
    pub fn cloned(&self) -> Merge<T>
    where
        T: Clone,
    {
        self.map(|&term| term.clone())
    }
}

/// Helper for consuming items from an iterator and then creating a `Merge`.
///
/// By not collecting directly into `Merge`, we can avoid creating invalid
/// instances of it. If we had `Merge::from_iter()` we would need to allow it to
/// accept iterators of any length (including 0). We couldn't make it panic on
/// even lengths because we can get passed such iterators from e.g.
/// `Option::from_iter()`. By collecting into `MergeBuilder` instead, we move
/// the checking until after `from_iter()` (to `MergeBuilder::build()`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeBuilder<T> {
    values: SmallVec<[T; 1]>,
}

impl<T> Default for MergeBuilder<T> {
    fn default() -> Self {
        Self {
            values: Default::default(),
        }
    }
}

impl<T> MergeBuilder<T> {
    /// Requires that exactly one more "adds" than "removes" have been added to
    /// this builder.
    ///
    /// # Panics
    /// Panics on an even (including empty) term count.
    pub fn build(self) -> Merge<T> {
        Merge::from_vec(self.values)
    }
}

impl<T> IntoIterator for Merge<T> {
    type Item = T;
    type IntoIter = smallvec::IntoIter<[T; 1]>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Merge<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Merge<T> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T> FromIterator<T> for MergeBuilder<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut builder = Self::default();
        builder.extend(iter);
        builder
    }
}

impl<T> Extend<T> for MergeBuilder<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.values.extend(iter);
    }
}

impl<T> Merge<Option<T>> {
    /// Creates a resolved merge with a value of `None`.
    pub const fn absent() -> Self {
        Self::resolved(None)
    }

    /// Creates a resolved merge with a value of `Some(value)`.
    pub fn normal(value: T) -> Self {
        Self::resolved(Some(value))
    }

    /// Whether this represents a resolved value of `None`.
    pub fn is_absent(&self) -> bool {
        matches!(self.as_resolved(), Some(None))
    }

    /// The opposite of `is_absent()`.
    pub fn is_present(&self) -> bool {
        !self.is_absent()
    }

    /// Returns the value if this is present and non-conflicting.
    pub fn as_normal(&self) -> Option<&T> {
        self.as_resolved()?.as_ref()
    }

    /// The removed values, excluding `None` terms.
    pub fn present_removes(&self) -> impl Iterator<Item = &T> {
        self.removes().flatten()
    }

    /// The added values, excluding `None` terms.
    pub fn present_adds(&self) -> impl Iterator<Item = &T> {
        self.adds().flatten()
    }
}

impl<T: Clone> Merge<Option<&T>> {
    /// Creates a new merge by cloning inner `Option<&T>`s.
    pub fn cloned(&self) -> Merge<Option<T>> {
        self.map(|value| value.cloned())
    }
}

impl<T> Merge<Merge<T>> {
    /// Flattens a nested merge into a regular merge.
    ///
    /// Let's say we have a 3-way merge of 3-way merges like this:
    ///
    /// ```text
    /// 4 5   7 8
    ///  3     6
    ///    1 2
    ///     0
    /// ```
    ///
    /// Flattening that results in this 9-way merge:
    ///
    /// ```text
    /// 4 5 0 7 8
    ///  3 2 1 6
    /// ```
    pub fn flatten(self) -> Merge<T> {
        let mut outer_values = self.values.into_iter();
        let mut result = outer_values.next().expect("merge has a zeroth term");
        while let Some(mut remove) = outer_values.next() {
            // Add removes reversed, and with the first element moved last, so we preserve
            // the diffs
            remove.values.rotate_left(1);
            for i in 0..remove.values.len() / 2 {
                remove.values.swap(i * 2, i * 2 + 1);
            }
            result.values.extend(remove.values);
            let add = outer_values.next().expect("merge has paired add");
            result.values.extend(add.values);
        }
        result
    }
}

impl<T: Serialize> Serialize for Merge<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.values.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Merge<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let values = SmallVec::<[T; 1]>::deserialize(deserializer)?;
        Self::try_from_vec(values).map_err(serde::de::Error::custom)
    }
}

impl<T: JsonSchema> JsonSchema for Merge<T> {
    fn schema_name() -> Cow<'static, str> {
        format!("Merge_of_{}", T::schema_name()).into()
    }

    fn schema_id() -> Cow<'static, str> {
        format!("{}::Merge<{}>", module_path!(), T::schema_id()).into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let items = generator.subschema_for::<T>();
        json_schema!({
            "description": "Terms alternating +,-,+,...,+; always an odd number (>= 1). A single term is a resolved value.",
            "type": "array",
            "items": items,
            "minItems": 1
        })
    }
}

impl<T> Merge<T> {
    /// Creates a `Merge` from a term vector, validating the odd-length
    /// invariant instead of panicking. This is the validated boundary used by
    /// deserialization and by callers that read terms from outside.
    ///
    /// # Errors
    /// [`crate::error::CoreModelError::Invalid`] for empty or even-length
    /// term vectors.
    pub fn try_from_vec(
        values: impl Into<SmallVec<[T; 1]>>,
    ) -> Result<Self, crate::error::CoreModelError> {
        let values = values.into();
        if values.is_empty() || values.len() % 2 == 0 {
            return Err(crate::error::CoreModelError::Invalid {
                what: "merge terms",
                detail: format!("expected odd length >= 1, got {}", values.len()),
            });
        }
        Ok(Self { values })
    }
}

#[cfg(test)]
mod tests;
