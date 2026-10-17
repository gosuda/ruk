//! Derived statuses and the supersession-cycle check. These are pure functions:
//! nothing here reads the store, and nothing compares timestamps.

use std::collections::HashSet;

use crate::protocol::AttestationStatus;

use super::verify::VerifiedStatement;

/// The status of each member of one `(subject, kind, signer)` group, in member
/// order.
///
/// A member named as superseded by a member of the same group is `Superseded`.
/// Otherwise the group's live members either agree on one result (`Live`) or
/// disagree (`Ambiguous` for every live member). A disagreement persists until a
/// signed supersession removes the conflicting live statement.
pub(super) fn derive(members: &[&VerifiedStatement]) -> Vec<AttestationStatus> {
    let superseded: HashSet<[u8; 32]> = members
        .iter()
        .filter_map(|member| {
            member
                .statement()
                .supersedes
                .map(|digest| *digest.as_bytes())
        })
        .collect();
    let live_results: HashSet<&str> = members
        .iter()
        .filter(|member| !superseded.contains(member.digest().as_bytes()))
        .map(|member| member.statement().result.as_str())
        .collect();
    let conflicted = live_results.len() > 1;
    members
        .iter()
        .map(|member| {
            if superseded.contains(member.digest().as_bytes()) {
                AttestationStatus::Superseded
            } else if conflicted {
                AttestationStatus::Ambiguous
            } else {
                AttestationStatus::Live
            }
        })
        .collect()
}

/// Whether following each member's single batch predecessor ever returns to a
/// member already on the same chain.
///
/// `next[i]` is the batch index that member `i` supersedes, when it is in the
/// batch. Each member names at most one predecessor, so every walk is a chain. A
/// walk that reaches a member already on its own chain has found a cycle.
pub(super) fn has_cycle(next: &[Option<usize>]) -> bool {
    const UNVISITED: u8 = 0;
    const ON_CHAIN: u8 = 1;
    const SETTLED: u8 = 2;

    let mut state = vec![UNVISITED; next.len()];
    for (start, _) in next.iter().enumerate() {
        if state[start] != UNVISITED {
            continue;
        }
        let mut chain = Vec::new();
        let mut cursor = Some(start);
        while let Some(node) = cursor {
            match state[node] {
                UNVISITED => {
                    state[node] = ON_CHAIN;
                    chain.push(node);
                    cursor = next[node];
                }
                ON_CHAIN => return true,
                _ => break,
            }
        }
        for node in chain {
            state[node] = SETTLED;
        }
    }
    false
}
