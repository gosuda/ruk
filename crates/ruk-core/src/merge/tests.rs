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
// The enumeration tests below are modified ports of the tests in jj 0.46.0
// `core/src/merge.rs`; Ruk-authored property and wire-format tests follow.

//! Tests for the merge algebra: the ported jj enumeration tables (same
//! expectations as jj, with `test_trivial_merge` split per `SameChange`) and
//! Ruk-authored property tests and wire-format checks.

use super::{Diff, Merge, MergeBuilder, SameChange, trivial_merge};
use crate::error::CoreModelError;

fn c<T: Clone>(terms: &[T]) -> Merge<T> {
    Merge::from_vec(terms.to_vec())
}

#[test]
fn test_diff_map() {
    let diff = Diff::new(1, 2);
    assert_eq!(diff.map(|x| x + 2), Diff::new(3, 4));
}

#[test]
fn test_diff_zip() {
    let diff1 = Diff::new(1, 2);
    let diff2 = Diff::new(3, 4);
    assert_eq!(diff1.zip(diff2), Diff::new((1, 3), (2, 4)));
}

#[test]
fn test_diff_invert() {
    let diff = Diff::new(1, 2);
    assert_eq!(diff.invert(), Diff::new(2, 1));
}

#[test]
fn test_diff_as_ref() {
    let diff = Diff::new(1, 2);
    assert_eq!(diff.as_ref(), Diff::new(&1, &2));
}

#[test]
fn test_diff_into_array() {
    let diff = Diff::new(1, 2);
    assert_eq!(diff.into_array(), [1, 2]);
}

#[test]
fn test_diff_is_changed() {
    assert!(!Diff::new(3, 3).is_changed());
    assert!(Diff::new(3, 4).is_changed());
}

#[test]
fn test_merge_from_diffs() {
    assert_eq!(Merge::from_diffs(1, []), Merge::resolved(1));
    assert_eq!(
        Merge::from_diffs(1, [Diff::new(2, 3)]),
        Merge::from_vec(vec![1, 2, 3])
    );
    assert_eq!(
        Merge::from_diffs(1, [Diff::new(2, 3), Diff::new(4, 5)]),
        Merge::from_vec(vec![1, 2, 3, 4, 5])
    );
}

/// Ported jj `test_trivial_merge` (jj/core/src/merge.rs:765-828): the
/// exhaustive behavior table for every 5-way term vector over {0..4},
/// parameterized by `SameChange` as upstream parameterizes it.
#[test]
fn test_trivial_merge_keep() {
    run_trivial_merge_table(SameChange::Keep);
}

#[test]
fn test_trivial_merge_accept() {
    run_trivial_merge_table(SameChange::Accept);
}

fn run_trivial_merge_table(same_change: SameChange) {
    let accept_same_change = same_change == SameChange::Accept;
    assert_eq!(trivial_merge(&[0], same_change), Some(&0));
    assert_eq!(trivial_merge(&[0, 0, 0], same_change), Some(&0));
    assert_eq!(trivial_merge(&[0, 0, 1], same_change), Some(&1));
    assert_eq!(
        trivial_merge(&[0, 1, 0], same_change),
        accept_same_change.then_some(&0)
    );
    assert_eq!(trivial_merge(&[0, 1, 1], same_change), Some(&0));
    assert_eq!(trivial_merge(&[0, 1, 2], same_change), None);
    assert_eq!(trivial_merge(&[0, 0, 0, 0, 0], same_change), Some(&0));
    assert_eq!(trivial_merge(&[0, 0, 0, 0, 1], same_change), Some(&1));
    assert_eq!(
        trivial_merge(&[0, 0, 0, 1, 0], same_change),
        accept_same_change.then_some(&0)
    );
    assert_eq!(trivial_merge(&[0, 0, 0, 1, 1], same_change), Some(&0));
    assert_eq!(trivial_merge(&[0, 0, 0, 1, 2], same_change), None);
    assert_eq!(trivial_merge(&[0, 0, 1, 0, 0], same_change), Some(&1));
    assert_eq!(
        trivial_merge(&[0, 0, 1, 0, 1], same_change),
        accept_same_change.then_some(&1)
    );
    assert_eq!(trivial_merge(&[0, 0, 1, 0, 2], same_change), None);
    assert_eq!(trivial_merge(&[0, 0, 1, 1, 0], same_change), Some(&0));
    assert_eq!(trivial_merge(&[0, 0, 1, 1, 1], same_change), Some(&1));
    assert_eq!(trivial_merge(&[0, 0, 1, 1, 2], same_change), Some(&2));
    assert_eq!(trivial_merge(&[0, 0, 1, 2, 0], same_change), None);
    assert_eq!(
        trivial_merge(&[0, 0, 1, 2, 1], same_change),
        accept_same_change.then_some(&1)
    );
    assert_eq!(trivial_merge(&[0, 0, 1, 2, 2], same_change), Some(&1));
    assert_eq!(trivial_merge(&[0, 0, 1, 2, 3], same_change), None);
    assert_eq!(
        trivial_merge(&[0, 1, 0, 0, 0], same_change),
        accept_same_change.then_some(&0)
    );
    assert_eq!(trivial_merge(&[0, 1, 0, 0, 1], same_change), Some(&0));
    assert_eq!(trivial_merge(&[0, 1, 0, 0, 2], same_change), None);
    assert_eq!(
        trivial_merge(&[0, 1, 0, 1, 0], same_change),
        accept_same_change.then_some(&0)
    );
    assert_eq!(
        trivial_merge(&[0, 1, 0, 1, 1], same_change),
        accept_same_change.then_some(&0)
    );
    assert_eq!(trivial_merge(&[0, 1, 0, 1, 2], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 0, 2, 0], same_change), None);
    assert_eq!(
        trivial_merge(&[0, 1, 0, 2, 1], same_change),
        accept_same_change.then_some(&0)
    );
    assert_eq!(
        trivial_merge(&[0, 1, 0, 2, 2], same_change),
        accept_same_change.then_some(&0)
    );
    assert_eq!(trivial_merge(&[0, 1, 0, 2, 3], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 1, 0, 0], same_change), Some(&0));
    assert_eq!(trivial_merge(&[0, 1, 1, 0, 1], same_change), Some(&1));
    assert_eq!(trivial_merge(&[0, 1, 1, 0, 2], same_change), Some(&2));
    assert_eq!(
        trivial_merge(&[0, 1, 1, 1, 0], same_change),
        accept_same_change.then_some(&0)
    );
    assert_eq!(trivial_merge(&[0, 1, 1, 1, 1], same_change), Some(&0));
    assert_eq!(trivial_merge(&[0, 1, 1, 1, 2], same_change), None);
    assert_eq!(
        trivial_merge(&[0, 1, 1, 2, 0], same_change),
        accept_same_change.then_some(&0)
    );
    assert_eq!(trivial_merge(&[0, 1, 1, 2, 1], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 1, 2, 2], same_change), Some(&0));
    assert_eq!(trivial_merge(&[0, 1, 1, 2, 3], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 0, 0], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 0, 1], same_change), Some(&2));
    assert_eq!(
        trivial_merge(&[0, 1, 2, 0, 2], same_change),
        accept_same_change.then_some(&2)
    );
    assert_eq!(trivial_merge(&[0, 1, 2, 0, 3], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 1, 0], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 1, 1], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 1, 2], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 1, 3], same_change), None);
    assert_eq!(
        trivial_merge(&[0, 1, 2, 2, 0], same_change),
        accept_same_change.then_some(&0)
    );
    assert_eq!(trivial_merge(&[0, 1, 2, 2, 1], same_change), Some(&0));
    assert_eq!(trivial_merge(&[0, 1, 2, 2, 2], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 2, 3], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 3, 0], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 3, 1], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 3, 2], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 3, 3], same_change), None);
    assert_eq!(trivial_merge(&[0, 1, 2, 3, 4], same_change), None);
}

#[test]
fn test_as_resolved() {
    assert_eq!(
        Merge::from_removes_adds(vec![], vec![0]).as_resolved(),
        Some(&0)
    );
    // Even a trivially resolvable merge is not resolved
    assert_eq!(
        Merge::from_removes_adds(vec![0], vec![0, 1]).as_resolved(),
        None
    );
}

#[test]
fn test_get_simplified_mapping() {
    // 1-way merge
    assert_eq!(c(&[0]).get_simplified_mapping(), vec![0]);
    // 3-way merge
    assert_eq!(c(&[0, 0, 0]).get_simplified_mapping(), vec![2]);
    assert_eq!(c(&[0, 0, 1]).get_simplified_mapping(), vec![2]);
    assert_eq!(c(&[0, 1, 0]).get_simplified_mapping(), vec![0, 1, 2]);
    assert_eq!(c(&[0, 1, 1]).get_simplified_mapping(), vec![0]);
    assert_eq!(c(&[0, 1, 2]).get_simplified_mapping(), vec![0, 1, 2]);
    // 5-way merge
    assert_eq!(c(&[0, 0, 0, 0, 0]).get_simplified_mapping(), vec![4]);
    assert_eq!(c(&[0, 0, 0, 0, 1]).get_simplified_mapping(), vec![4]);
    assert_eq!(c(&[0, 0, 0, 1, 0]).get_simplified_mapping(), vec![2, 3, 4]);
    assert_eq!(c(&[0, 0, 0, 1, 1]).get_simplified_mapping(), vec![2]);
    assert_eq!(c(&[0, 0, 0, 1, 2]).get_simplified_mapping(), vec![2, 3, 4]);
    assert_eq!(c(&[0, 0, 1, 0, 0]).get_simplified_mapping(), vec![2]);
    assert_eq!(c(&[0, 0, 1, 0, 1]).get_simplified_mapping(), vec![2, 3, 4]);
    assert_eq!(c(&[0, 0, 1, 0, 2]).get_simplified_mapping(), vec![2, 3, 4]);
    assert_eq!(c(&[0, 0, 1, 1, 0]).get_simplified_mapping(), vec![4]);
    assert_eq!(c(&[0, 0, 1, 1, 1]).get_simplified_mapping(), vec![4]);
    assert_eq!(c(&[0, 0, 1, 1, 2]).get_simplified_mapping(), vec![4]);
    assert_eq!(c(&[0, 0, 2, 1, 0]).get_simplified_mapping(), vec![2, 3, 4]);
    assert_eq!(c(&[0, 0, 2, 1, 1]).get_simplified_mapping(), vec![2]);
    assert_eq!(c(&[0, 0, 2, 1, 2]).get_simplified_mapping(), vec![2, 3, 4]);
    assert_eq!(c(&[0, 0, 2, 1, 3]).get_simplified_mapping(), vec![2, 3, 4]);
    assert_eq!(c(&[0, 1, 0, 0, 0]).get_simplified_mapping(), vec![4, 1, 2]);
    assert_eq!(c(&[0, 1, 0, 0, 1]).get_simplified_mapping(), vec![2]);
    assert_eq!(c(&[0, 1, 0, 0, 2]).get_simplified_mapping(), vec![4, 1, 2]);
    assert_eq!(
        c(&[0, 1, 0, 1, 0]).get_simplified_mapping(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(c(&[0, 1, 0, 1, 1]).get_simplified_mapping(), vec![0, 3, 2]);
    assert_eq!(
        c(&[0, 1, 0, 1, 2]).get_simplified_mapping(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(
        c(&[0, 1, 0, 2, 0]).get_simplified_mapping(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(c(&[0, 1, 0, 2, 1]).get_simplified_mapping(), vec![0, 3, 2]);
    assert_eq!(c(&[0, 1, 0, 2, 2]).get_simplified_mapping(), vec![0, 1, 2]);
    assert_eq!(
        c(&[0, 1, 0, 2, 3]).get_simplified_mapping(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(c(&[0, 1, 1, 0, 0]).get_simplified_mapping(), vec![4]);
    assert_eq!(c(&[0, 1, 1, 0, 1]).get_simplified_mapping(), vec![2]);
    assert_eq!(c(&[0, 1, 1, 0, 2]).get_simplified_mapping(), vec![4]);
    assert_eq!(c(&[0, 1, 1, 1, 0]).get_simplified_mapping(), vec![0, 3, 4]);
    assert_eq!(c(&[0, 1, 1, 1, 1]).get_simplified_mapping(), vec![0]);
    assert_eq!(c(&[0, 1, 1, 1, 2]).get_simplified_mapping(), vec![0, 3, 4]);
    assert_eq!(c(&[0, 1, 1, 2, 0]).get_simplified_mapping(), vec![0, 3, 4]);
    assert_eq!(c(&[0, 1, 1, 2, 1]).get_simplified_mapping(), vec![0, 3, 4]);
    assert_eq!(c(&[0, 1, 1, 2, 2]).get_simplified_mapping(), vec![0]);
    assert_eq!(c(&[0, 1, 1, 2, 3]).get_simplified_mapping(), vec![0, 3, 4]);
    assert_eq!(c(&[0, 1, 2, 0, 0]).get_simplified_mapping(), vec![4, 1, 2]);
    assert_eq!(c(&[0, 1, 2, 0, 1]).get_simplified_mapping(), vec![2]);
    assert_eq!(c(&[0, 1, 2, 0, 2]).get_simplified_mapping(), vec![4, 1, 2]);
    assert_eq!(c(&[0, 1, 2, 0, 3]).get_simplified_mapping(), vec![4, 1, 2]);
    assert_eq!(
        c(&[0, 1, 2, 1, 0]).get_simplified_mapping(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(c(&[0, 1, 2, 1, 1]).get_simplified_mapping(), vec![0, 3, 2]);
    assert_eq!(
        c(&[0, 1, 2, 1, 2]).get_simplified_mapping(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(
        c(&[0, 1, 2, 1, 3]).get_simplified_mapping(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(c(&[0, 1, 2, 2, 0]).get_simplified_mapping(), vec![0, 1, 4]);
    assert_eq!(c(&[0, 1, 2, 2, 1]).get_simplified_mapping(), vec![0]);
    assert_eq!(c(&[0, 1, 2, 2, 2]).get_simplified_mapping(), vec![0, 1, 4]);
    assert_eq!(c(&[0, 1, 2, 2, 3]).get_simplified_mapping(), vec![0, 1, 4]);
    assert_eq!(
        c(&[0, 1, 2, 3, 0]).get_simplified_mapping(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(c(&[0, 1, 2, 3, 1]).get_simplified_mapping(), vec![0, 3, 2]);
    assert_eq!(
        c(&[0, 1, 2, 3, 2]).get_simplified_mapping(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(
        c(&[0, 1, 2, 3, 4, 5, 1]).get_simplified_mapping(),
        vec![0, 3, 4, 5, 2]
    );
    assert_eq!(
        c(&[0, 1, 2, 3, 4]).get_simplified_mapping(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(c(&[2, 0, 3, 1, 1]).get_simplified_mapping(), vec![0, 1, 2]);
}

#[test]
fn test_simplify() {
    // 1-way merge
    assert_eq!(c(&[0]).simplify(), c(&[0]));
    // 3-way merge
    assert_eq!(c(&[0, 0, 0]).simplify(), c(&[0]));
    assert_eq!(c(&[0, 0, 1]).simplify(), c(&[1]));
    assert_eq!(c(&[1, 0, 0]).simplify(), c(&[1]));
    assert_eq!(c(&[1, 0, 1]).simplify(), c(&[1, 0, 1]));
    assert_eq!(c(&[1, 0, 2]).simplify(), c(&[1, 0, 2]));
    // 5-way merge
    assert_eq!(c(&[0, 0, 0, 0, 0]).simplify(), c(&[0]));
    assert_eq!(c(&[0, 0, 0, 0, 1]).simplify(), c(&[1]));
    assert_eq!(c(&[0, 0, 0, 1, 0]).simplify(), c(&[0, 1, 0]));
    assert_eq!(c(&[0, 0, 0, 1, 1]).simplify(), c(&[0]));
    assert_eq!(c(&[0, 0, 0, 1, 2]).simplify(), c(&[0, 1, 2]));
    assert_eq!(c(&[0, 0, 1, 0, 0]).simplify(), c(&[1]));
    assert_eq!(c(&[0, 0, 1, 0, 1]).simplify(), c(&[1, 0, 1]));
    assert_eq!(c(&[0, 0, 1, 0, 2]).simplify(), c(&[1, 0, 2]));
    assert_eq!(c(&[0, 0, 1, 1, 0]).simplify(), c(&[0]));
    assert_eq!(c(&[0, 0, 1, 1, 1]).simplify(), c(&[1]));
    assert_eq!(c(&[0, 0, 1, 1, 2]).simplify(), c(&[2]));
    assert_eq!(c(&[0, 0, 2, 1, 0]).simplify(), c(&[2, 1, 0]));
    assert_eq!(c(&[0, 0, 2, 1, 1]).simplify(), c(&[2]));
    assert_eq!(c(&[0, 0, 2, 1, 2]).simplify(), c(&[2, 1, 2]));
    assert_eq!(c(&[0, 0, 2, 1, 3]).simplify(), c(&[2, 1, 3]));
    assert_eq!(c(&[0, 1, 0, 0, 0]).simplify(), c(&[0, 1, 0]));
    assert_eq!(c(&[0, 1, 0, 0, 1]).simplify(), c(&[0]));
    assert_eq!(c(&[0, 1, 0, 0, 2]).simplify(), c(&[2, 1, 0]));
    assert_eq!(c(&[0, 1, 0, 1, 0]).simplify(), c(&[0, 1, 0, 1, 0]));
    assert_eq!(c(&[0, 1, 0, 1, 1]).simplify(), c(&[0, 1, 0]));
    assert_eq!(c(&[0, 1, 0, 1, 2]).simplify(), c(&[0, 1, 0, 1, 2]));
    assert_eq!(c(&[0, 1, 0, 2, 0]).simplify(), c(&[0, 1, 0, 2, 0]));
    assert_eq!(c(&[0, 1, 0, 2, 1]).simplify(), c(&[0, 2, 0]));
    assert_eq!(c(&[0, 1, 0, 2, 2]).simplify(), c(&[0, 1, 0]));
    assert_eq!(c(&[0, 1, 0, 2, 3]).simplify(), c(&[0, 1, 0, 2, 3]));
    assert_eq!(c(&[0, 1, 1, 0, 0]).simplify(), c(&[0]));
    assert_eq!(c(&[0, 1, 1, 0, 1]).simplify(), c(&[1]));
    assert_eq!(c(&[0, 1, 1, 0, 2]).simplify(), c(&[2]));
    assert_eq!(c(&[0, 1, 1, 1, 0]).simplify(), c(&[0, 1, 0]));
    assert_eq!(c(&[0, 1, 1, 1, 1]).simplify(), c(&[0]));
    assert_eq!(c(&[0, 1, 1, 1, 2]).simplify(), c(&[0, 1, 2]));
    assert_eq!(c(&[0, 1, 1, 2, 0]).simplify(), c(&[0, 2, 0]));
    assert_eq!(c(&[0, 1, 1, 2, 1]).simplify(), c(&[0, 2, 1]));
    assert_eq!(c(&[0, 1, 1, 2, 2]).simplify(), c(&[0]));
    assert_eq!(c(&[0, 1, 1, 2, 3]).simplify(), c(&[0, 2, 3]));
    assert_eq!(c(&[0, 1, 2, 0, 0]).simplify(), c(&[0, 1, 2]));
    assert_eq!(c(&[0, 1, 2, 0, 1]).simplify(), c(&[2]));
    assert_eq!(c(&[0, 1, 2, 0, 2]).simplify(), c(&[2, 1, 2]));
    assert_eq!(c(&[0, 1, 2, 0, 3]).simplify(), c(&[3, 1, 2]));
    assert_eq!(c(&[0, 1, 2, 1, 0]).simplify(), c(&[0, 1, 2, 1, 0]));
    assert_eq!(c(&[0, 1, 2, 1, 1]).simplify(), c(&[0, 1, 2]));
    assert_eq!(c(&[0, 1, 2, 1, 2]).simplify(), c(&[0, 1, 2, 1, 2]));
    assert_eq!(c(&[0, 1, 2, 1, 3]).simplify(), c(&[0, 1, 2, 1, 3]));
    assert_eq!(c(&[0, 1, 2, 2, 0]).simplify(), c(&[0, 1, 0]));
    assert_eq!(c(&[0, 1, 2, 2, 1]).simplify(), c(&[0]));
    assert_eq!(c(&[0, 1, 2, 2, 2]).simplify(), c(&[0, 1, 2]));
    assert_eq!(c(&[0, 1, 2, 2, 3]).simplify(), c(&[0, 1, 3]));
    assert_eq!(c(&[0, 1, 2, 3, 0]).simplify(), c(&[0, 1, 2, 3, 0]));
    assert_eq!(c(&[0, 1, 2, 3, 1]).simplify(), c(&[0, 3, 2]));
    assert_eq!(c(&[0, 1, 2, 3, 2]).simplify(), c(&[0, 1, 2, 3, 2]));
    assert_eq!(c(&[0, 1, 2, 3, 3]).simplify(), c(&[0, 1, 2]));
    assert_eq!(c(&[0, 1, 2, 3, 4]).simplify(), c(&[0, 1, 2, 3, 4]));
    assert_eq!(c(&[0, 1, 2, 3, 4, 5, 1]).simplify(), c(&[0, 3, 4, 5, 2]));
}

#[test]
fn test_simplify_by() {
    fn enumerate_and_simplify_by(merge: Merge<i32>) -> Merge<(usize, i32)> {
        let enumerated = Merge::from_vec(merge.iter().copied().enumerate().collect::<Vec<_>>());
        enumerated.simplify_by(|&(_index, value)| value)
    }

    // 1-way merge
    assert_eq!(enumerate_and_simplify_by(c(&[0])), c(&[(0, 0)]));
    // 3-way merge
    assert_eq!(enumerate_and_simplify_by(c(&[1, 0, 0])), c(&[(0, 1)]));
    assert_eq!(
        enumerate_and_simplify_by(c(&[1, 0, 2])),
        c(&[(0, 1), (1, 0), (2, 2)])
    );
    // 5-way merge
    assert_eq!(enumerate_and_simplify_by(c(&[0, 0, 0, 0, 0])), c(&[(4, 0)]));
    assert_eq!(enumerate_and_simplify_by(c(&[0, 0, 0, 0, 1])), c(&[(4, 1)]));
    assert_eq!(
        enumerate_and_simplify_by(c(&[0, 0, 0, 1, 2])),
        c(&[(2, 0), (3, 1), (4, 2)])
    );
    assert_eq!(
        enumerate_and_simplify_by(c(&[0, 1, 2, 2, 0])),
        c(&[(0, 0), (1, 1), (4, 0)])
    );
    assert_eq!(
        enumerate_and_simplify_by(c(&[0, 1, 2, 2, 2])),
        c(&[(0, 0), (1, 1), (4, 2)])
    );
    assert_eq!(
        enumerate_and_simplify_by(c(&[0, 1, 2, 2, 3])),
        c(&[(0, 0), (1, 1), (4, 3)])
    );
    assert_eq!(
        enumerate_and_simplify_by(c(&[0, 1, 2, 3, 4])),
        c(&[(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)])
    );
}

#[test]
fn test_update_from_simplified() {
    // 1-way merge
    assert_eq!(c(&[0]).update_from_simplified(c(&[1])), c(&[1]));
    // 3-way merge
    assert_eq!(c(&[0, 0, 0]).update_from_simplified(c(&[1])), c(&[0, 0, 1]));
    assert_eq!(c(&[1, 0, 0]).update_from_simplified(c(&[2])), c(&[2, 0, 0]));
    assert_eq!(
        c(&[1, 0, 2]).update_from_simplified(c(&[2, 1, 3])),
        c(&[2, 1, 3])
    );
    // 5-way merge
    assert_eq!(
        c(&[0, 0, 0, 0, 0]).update_from_simplified(c(&[1])),
        c(&[0, 0, 0, 0, 1])
    );
    assert_eq!(
        c(&[0, 0, 0, 1, 0]).update_from_simplified(c(&[2, 3, 1])),
        c(&[0, 0, 2, 3, 1])
    );
    assert_eq!(
        c(&[0, 1, 0, 0, 0]).update_from_simplified(c(&[2, 3, 1])),
        c(&[0, 3, 1, 0, 2])
    );
    assert_eq!(
        c(&[2, 0, 3, 1, 4]).update_from_simplified(c(&[3, 1, 4, 2, 5])),
        c(&[3, 1, 4, 2, 5])
    );

    assert_eq!(c(&[0, 0, 3, 1, 3, 2, 4]).simplify(), c(&[3, 1, 3, 2, 4]));
    // Check that the `3`s are replaced correctly and that `4` ends up in the
    // correct position.
    assert_eq!(
        c(&[0, 0, 3, 1, 3, 2, 4]).update_from_simplified(c(&[10, 1, 11, 2, 4])),
        c(&[0, 0, 10, 1, 11, 2, 4])
    );
}

#[test]
fn test_merge_invariants() {
    fn check_invariants(terms: &[u32]) {
        let merge = Merge::from_vec(terms.to_vec());
        // `simplify()` is idempotent
        assert_eq!(
            merge.simplify().simplify(),
            merge.simplify(),
            "simplify() not idempotent for {merge:?}"
        );
        // `resolve_trivial()` is unaffected by `simplify()`
        assert_eq!(
            merge.simplify().resolve_trivial(SameChange::Accept),
            merge.resolve_trivial(SameChange::Accept),
            "simplify() changed result of resolve_trivial() for {merge:?}"
        );
    }
    // 1-way merge
    check_invariants(&[0]);
    for i in 0..=1_u32 {
        for j in 0..=i + 1 {
            // 3-way merge
            check_invariants(&[i, 0, j]);
            for k in 0..=j + 1 {
                for l in 0..=k + 1 {
                    // 5-way merge
                    check_invariants(&[0, i, j, k, l]);
                }
            }
        }
    }
}

#[test]
fn test_swap_remove() {
    let mut x = c(&[0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(x.swap_remove(0, 1), (1, 2));
    assert_eq!(x, c(&[0, 5, 6, 3, 4]));
    assert_eq!(x.swap_remove(1, 0), (3, 0));
    assert_eq!(x, c(&[4, 5, 6]));
    assert_eq!(x.swap_remove(0, 1), (5, 6));
    assert_eq!(x, c(&[4]));
}

#[test]
fn test_iter() {
    // 1-way merge
    assert_eq!(c(&[1]).iter().collect::<Vec<_>>(), vec![&1]);
    // 5-way merge
    assert_eq!(
        c(&[1, 2, 3, 4, 5]).iter().collect::<Vec<_>>(),
        vec![&1, &2, &3, &4, &5]
    );
}

#[test]
fn test_from_iter() {
    // 1-way merge
    assert_eq!(MergeBuilder::from_iter([1]).build(), c(&[1]));
    // 5-way merge
    assert_eq!(
        MergeBuilder::from_iter([1, 2, 3, 4, 5]).build(),
        c(&[1, 2, 3, 4, 5])
    );
}

#[test]
#[should_panic]
fn test_from_iter_empty() {
    MergeBuilder::from_iter([1; 0]).build();
}

#[test]
#[should_panic]
fn test_from_iter_even() {
    MergeBuilder::from_iter([1, 2]).build();
}

#[test]
fn test_extend() {
    // 1-way merge
    let mut builder: MergeBuilder<i32> = Default::default();
    builder.extend([1]);
    assert_eq!(builder.build(), c(&[1]));
    // 5-way merge
    let mut builder: MergeBuilder<i32> = Default::default();
    builder.extend([1, 2]);
    builder.extend([3, 4, 5]);
    assert_eq!(builder.build(), c(&[1, 2, 3, 4, 5]));
}

#[test]
fn test_map() {
    fn increment(i: &i32) -> i32 {
        i + 1
    }
    // 1-way merge
    assert_eq!(c(&[1]).map(increment), c(&[2]));
    // 3-way merge
    assert_eq!(c(&[1, 3, 5]).map(increment), c(&[2, 4, 6]));
}

#[test]
fn test_try_map() {
    fn sqrt(i: &i32) -> Result<i32, ()> {
        if *i >= 0 {
            Ok(f64::from(*i).sqrt() as i32)
        } else {
            Err(())
        }
    }
    // 1-way merge
    assert_eq!(c(&[1]).try_map(sqrt), Ok(c(&[1])));
    assert_eq!(c(&[-1]).try_map(sqrt), Err(()));
    // 3-way merge
    assert_eq!(c(&[1, 4, 9]).try_map(sqrt), Ok(c(&[1, 2, 3])));
    assert_eq!(c(&[-1, 4, 9]).try_map(sqrt), Err(()));
    assert_eq!(c(&[1, -4, 9]).try_map(sqrt), Err(()));
}

#[test]
fn test_flatten() {
    // 1-way merge of 1-way merge
    assert_eq!(c(&[c(&[0])]).flatten(), c(&[0]));
    // 1-way merge of 3-way merge
    assert_eq!(c(&[c(&[0, 1, 2])]).flatten(), c(&[0, 1, 2]));
    // 3-way merge of 1-way merges
    assert_eq!(c(&[c(&[0]), c(&[1]), c(&[2])]).flatten(), c(&[0, 1, 2]));
    // 3-way merge of 3-way merges
    assert_eq!(
        c(&[c(&[0, 1, 2]), c(&[3, 4, 5]), c(&[6, 7, 8])]).flatten(),
        c(&[0, 1, 2, 5, 4, 3, 6, 7, 8])
    );
}

#[test]
fn test_zip() {
    // Zip of 1-way merges
    assert_eq!(c(&[1]).zip(c(&[2])), c(&[(1, 2)]));
    // Zip of 3-way merges
    assert_eq!(
        c(&[1, 2, 3]).zip(c(&[4, 5, 6])),
        c(&[(1, 4), (2, 5), (3, 6)])
    );
}

#[test]
fn test_unzip() {
    // 1-way merge
    assert_eq!(c(&[(1, 2)]).unzip(), (c(&[1]), c(&[2])));
    // 3-way merge
    assert_eq!(
        c(&[(1, 4), (2, 5), (3, 6)]).unzip(),
        (c(&[1, 2, 3]), c(&[4, 5, 6]))
    );
}

// ---- Ruk-side validated deserialization tests -----------------------

#[test]
fn same_change_default_is_keep() {
    assert_eq!(SameChange::default(), SameChange::Keep);
}

#[test]
fn same_change_wire_form() {
    assert_eq!(
        sonic_rs::to_string(&SameChange::Keep).expect("json"),
        "\"keep\""
    );
    assert_eq!(
        sonic_rs::to_string(&SameChange::Accept).expect("json"),
        "\"accept\""
    );
    let keep: SameChange = sonic_rs::from_str("\"keep\"").expect("keep");
    let accept: SameChange = sonic_rs::from_str("\"accept\"").expect("accept");
    assert_eq!(keep, SameChange::Keep);
    assert_eq!(accept, SameChange::Accept);
}

#[test]
fn merge_wire_shape_is_bare_array() {
    let merge = Merge::from_vec(vec![1, 2, 3]);
    assert_eq!(sonic_rs::to_string(&merge).expect("json"), "[1,2,3]");
    let resolved = Merge::resolved(42_u32);
    assert_eq!(sonic_rs::to_string(&resolved).expect("json"), "[42]");
}

#[test]
fn merge_deserializes_odd_arrays() {
    let merge: Merge<u32> = sonic_rs::from_str("[7]").expect("resolved");
    assert_eq!(merge, Merge::resolved(7));
    let conflicted: Merge<u32> = sonic_rs::from_str("[1,2,3]").expect("conflict");
    assert_eq!(conflicted, Merge::from_vec(vec![1, 2, 3]));
}

#[test]
fn merge_rejects_empty_and_even_arrays() {
    let empty: Result<Merge<u32>, _> = sonic_rs::from_str("[]");
    assert!(empty.is_err(), "empty term array must be rejected");
    let even: Result<Merge<u32>, _> = sonic_rs::from_str("[1,2]");
    assert!(even.is_err(), "even term array must be rejected");
    let even5: Result<Merge<u32>, _> = sonic_rs::from_str("[1,2,3,4]");
    assert!(even5.is_err());
}

#[test]
fn merge_round_trips_through_wire() {
    let original = Merge::from_vec(vec![10_u64, 20, 30, 40, 50]);
    let json = sonic_rs::to_string(&original).expect("serialize");
    let back: Merge<u64> = sonic_rs::from_str(&json).expect("deserialize");
    assert_eq!(back, original);
}

#[test]
fn try_from_vec_matches_deserializer_semantics() {
    assert!(Merge::<u8>::try_from_vec(Vec::new()).is_err());
    assert!(Merge::<u8>::try_from_vec(vec![1, 2]).is_err());
    assert_eq!(
        Merge::<u8>::try_from_vec(vec![1, 2, 3]).expect("odd"),
        Merge::from_vec(vec![1, 2, 3])
    );
}

#[test]
fn invalid_merge_terms_error_shape() {
    let err = Merge::<u8>::try_from_vec(Vec::new()).expect_err("empty");
    let CoreModelError::Invalid { what, detail } = err else {
        panic!("expected Invalid, got {err:?}");
    };
    assert_eq!(what, "merge terms");
    assert!(detail.contains("odd"));
}

// ---- Ruk-authored property tests (B2: jj has no property tests for the
// algebra; these are derived from the plan's constraints, not ported) --

use proptest::prelude::*;

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(2048))]

    /// Odd-length closure: a validated merge built from arbitrary odd
    /// term vectors keeps the invariant, and every vector produced by
    /// the algebra's own operations is odd again.
    #[test]
    fn prop_odd_length_closure(
        terms in prop::collection::vec(0_u8..8, 1..13)
            .prop_filter("odd length", |t| t.len() % 2 == 1),
    ) {
        let merge = Merge::from_vec(terms.clone());
        prop_assert_eq!(merge.as_slice().len() % 2, 1);
        let simplified = merge.simplify();
        prop_assert_eq!(simplified.as_slice().len() % 2, 1);
        let flattened = Merge::from_vec(vec![
            merge.clone(),
            Merge::from_vec(vec![1_u8, 2, 3]),
            merge.clone(),
        ])
        .flatten();
        prop_assert_eq!(flattened.as_slice().len() % 2, 1);
    }

    /// Cancellation identities: merging [a,b,b] resolves to a and
    /// [b,a,a] resolves to b under both SameChange settings.
    #[test]
    fn prop_cancellation_identities(
        a in 0_u16..1000, b in 0_u16..1000,
    ) {
        let ab: Merge<u16> = Merge::from_vec(vec![a, b, b]);
        let ba: Merge<u16> = Merge::from_vec(vec![b, a, a]);
        for same_change in [SameChange::Keep, SameChange::Accept] {
            prop_assert_eq!(ab.resolve_trivial(same_change), Some(&a));
            prop_assert_eq!(ba.resolve_trivial(same_change), Some(&b));
        }
    }

    /// Simplification idempotence and resolve-preservation hold for
    /// arbitrary odd vectors (jj's `check_invariants`, generalized).
    #[test]
    fn prop_simplify_invariants(
        terms in prop::collection::vec(0_u32..6, 1..11)
            .prop_filter("odd length", |t| t.len() % 2 == 1),
    ) {
        let merge = Merge::from_vec(terms);
        let simplified = merge.simplify();
        prop_assert_eq!(simplified.simplify(), simplified.clone(),
            "simplify() not idempotent for {merge:?}", merge = merge);
        for same_change in [SameChange::Keep, SameChange::Accept] {
            prop_assert_eq!(
                simplified.resolve_trivial(same_change),
                merge.resolve_trivial(same_change),
                "simplify() changed resolve_trivial({same_change:?}) for {merge:?}",
                same_change = same_change,
                merge = merge
            );
        }
    }

    /// Flattening equivalence per jj's documented shape: flatten of
    /// [add0, remove, add1] yields add0 terms + reversed-remove terms +
    /// add1 terms. For a 1-way remove (single term) the rotate makes it
    /// the last term; for a 3-way remove the diffs are reversed in
    /// place. The leaf multiset is preserved for both flavors, which is
    /// the property the plan requires ("flattening equivalence"); the
    /// plan forbids asserting literal term order.
    #[test]
    fn prop_flatten_preserves_leaf_multiset(
        inner in prop::collection::vec(0_u32..4, 1..7)
            .prop_filter("odd length", |t| t.len() % 2 == 1),
        remove_flavor in 0_u8..2,
    ) {
        let remove_terms: Vec<u32> = match remove_flavor {
            0 => vec![9_u32],
            _ => vec![9_u32, 9, 9],
        };
        // Outer shape: add0=inner, remove=remove_terms, add1=inner.
        let outer = Merge::from_vec(vec![
            Merge::from_vec(inner.clone()),
            Merge::from_vec(remove_terms.clone()),
            Merge::from_vec(inner.clone()),
        ]);
        let flat = outer.flatten();
        let mut expected: Vec<u32> = inner.clone();
        expected.extend_from_slice(&remove_terms);
        expected.extend_from_slice(&inner);
        expected.sort_unstable();
        let mut actual: Vec<u32> = flat.iter().copied().collect();
        actual.sort_unstable();
        prop_assert_eq!(actual, expected);
    }

    /// Same-change acceptance is exactly the 3-way rule A+(A-B)=A: a
    /// 3-way merge [x, y, x] resolves under Accept for any y (equal y
    /// resolves either way; different y is the same-change case), while
    /// Keep leaves the x!=y case conflicted.
    #[test]
    fn prop_same_change_three_way_rule(
        x in 0_u8..40, y in 0_u8..40,
    ) {
        let merge = Merge::<u8>::from_vec(vec![x, y, x]);
        prop_assert_eq!(merge.resolve_trivial(SameChange::Accept), Some(&x));
        prop_assert_eq!(
            merge.resolve_trivial(SameChange::Keep),
            (y == x).then_some(&x)
        );
    }

    /// removes/adds partitioning is exact for arbitrary odd vectors.
    #[test]
    fn prop_removes_adds_partition(
        terms in prop::collection::vec(0_u8..9, 1..15)
            .prop_filter("odd length", |t| t.len() % 2 == 1),
    ) {
        let merge = Merge::from_vec(terms.clone());
        let sides = merge.num_sides();
        prop_assert_eq!(merge.adds().count(), sides);
        prop_assert_eq!(merge.removes().count(), sides - 1);
        prop_assert_eq!(merge.iter().len(), terms.len());
        let (removes, adds) = merge.clone().into_removes_adds();
        let removes: Vec<u8> = removes.collect();
        let adds: Vec<u8> = adds.collect();
        prop_assert_eq!(removes.len(), sides - 1);
        prop_assert_eq!(adds.len(), sides);
        let rebuilt = Merge::from_removes_adds(removes, adds);
        prop_assert_eq!(rebuilt, merge);
    }
}
