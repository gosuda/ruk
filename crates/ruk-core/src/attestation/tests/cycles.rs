//! The batch supersession-cycle check, on bare graphs. Real digests cannot form a
//! cycle, because each digest covers its predecessor's digest; the check is the
//! defense that keeps preparation correct if that invariant is ever broken.

use crate::attestation::status::has_cycle;

#[test]
fn an_empty_batch_has_no_cycle() {
    assert!(!has_cycle(&[]));
}

#[test]
fn a_self_reference_is_a_cycle() {
    assert!(has_cycle(&[Some(0)]));
}

#[test]
fn a_two_member_loop_is_a_cycle() {
    assert!(has_cycle(&[Some(1), Some(0)]));
}

#[test]
fn a_loop_reached_from_an_outside_chain_is_a_cycle() {
    // 0 leads into the loop 1 -> 2 -> 1.
    assert!(has_cycle(&[Some(1), Some(2), Some(1)]));
}

#[test]
fn chains_that_end_are_not_cycles() {
    // 2 -> 1 -> 0 -> nothing.
    assert!(!has_cycle(&[None, Some(0), Some(1)]));
    // Two chains share a settled tail.
    assert!(!has_cycle(&[None, Some(0), Some(0)]));
}
