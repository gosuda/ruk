//! Changed-path Bloom filter implementation matching Git's commit-graph chunk.
//!
//! # Specification and parameters
//!
//! Follows Git's pinned changed-path Bloom filter specification (`git/bloom.c`):
//! - 10 bits per path entry (`DEFAULT_BITS_PER_ENTRY = 10`)
//! - 7 hash functions (`DEFAULT_NUM_HASHES = 7`)
//! - 512 maximum changed paths (`DEFAULT_MAX_CHANGED_PATHS = 512`)
//! - Murmur3 seeded 32-bit hashes with seeds `0x293ae76f` and `0x7e646e2c`.
//!
//! # False-negative safety
//!
//! If a commit changed more than 512 paths, or if the filter is absent, empty,
//! or corrupted, the filter is marked truncated (single byte `0xFF`). Queries
//! against a truncated or missing filter ALWAYS return [`BloomMatch::Candidate`].

use std::collections::BTreeSet;

use crate::graph::types::BloomMatch;

pub(crate) const DEFAULT_NUM_HASHES: u32 = 7;
pub(crate) const DEFAULT_BITS_PER_ENTRY: u32 = 10;
pub(crate) const DEFAULT_MAX_CHANGED_PATHS: usize = 512;
pub(crate) const BLOOM_SEED0: u32 = 0x293ae76f;
pub(crate) const BLOOM_SEED1: u32 = 0x7e646e2c;

#[must_use]
pub(crate) fn murmur3_seeded(seed: u32, data: &[u8]) -> u32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    const R1: u32 = 15;
    const R2: u32 = 13;
    const M: u32 = 5;
    const N: u32 = 0xe6546b64;

    let len = data.len();
    let len4 = len / 4;
    let mut h = seed;

    for i in 0..len4 {
        let b = &data[4 * i..4 * i + 4];
        let k = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let k = k.wrapping_mul(C1).rotate_left(R1).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(R2).wrapping_mul(M).wrapping_add(N);
    }

    let tail = &data[4 * len4..];
    let mut k1 = 0u32;
    match tail.len() {
        3 => {
            k1 ^= u32::from(tail[2]) << 16;
            k1 ^= u32::from(tail[1]) << 8;
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(C1).rotate_left(R1).wrapping_mul(C2);
            h ^= k1;
        }
        2 => {
            k1 ^= u32::from(tail[1]) << 8;
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(C1).rotate_left(R1).wrapping_mul(C2);
            h ^= k1;
        }
        1 => {
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(C1).rotate_left(R1).wrapping_mul(C2);
            h ^= k1;
        }
        _ => {}
    }

    let len_u32 = len as u32;
    h ^= len_u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h
}

#[must_use]
pub(crate) fn bloom_hashes(key: &[u8]) -> [u32; DEFAULT_NUM_HASHES as usize] {
    let h0 = murmur3_seeded(BLOOM_SEED0, key);
    let h1 = murmur3_seeded(BLOOM_SEED1, key);
    let mut out = [0u32; DEFAULT_NUM_HASHES as usize];
    for (i, slot) in out.iter_mut().enumerate() {
        let idx = i as u32;
        *slot = h0.wrapping_add(idx.wrapping_mul(h1));
    }
    out
}

pub(crate) fn expand_path_and_ancestors(path: &[u8], set: &mut BTreeSet<Vec<u8>>) {
    let mut trimmed = path;
    while trimmed.first() == Some(&b'/') {
        trimmed = &trimmed[1..];
    }
    while trimmed.last() == Some(&b'/') {
        trimmed = &trimmed[..trimmed.len() - 1];
    }
    if trimmed.is_empty() {
        return;
    }

    set.insert(trimmed.to_vec());

    for (i, &byte) in trimmed.iter().enumerate() {
        if byte == b'/' {
            let prefix = &trimmed[..i];
            if !prefix.is_empty() {
                set.insert(prefix.to_vec());
            }
        }
    }
}

#[must_use]
pub(crate) fn build_bloom_filter(changed_paths: &[&[u8]]) -> Vec<u8> {
    let mut expanded = BTreeSet::new();
    for path in changed_paths {
        expand_path_and_ancestors(path, &mut expanded);
    }

    if expanded.is_empty() || expanded.len() > DEFAULT_MAX_CHANGED_PATHS {
        return vec![0xFF];
    }

    let num_bits = expanded.len().saturating_mul(DEFAULT_BITS_PER_ENTRY as usize);
    let num_bytes = (num_bits + 7) / 8;
    let num_bytes = if num_bytes == 0 { 1 } else { num_bytes };

    let mut filter = vec![0u8; num_bytes];
    let total_bits = (num_bytes * 8) as u64;

    for path in &expanded {
        let hashes = bloom_hashes(path);
        for hash in hashes {
            let bit_idx = (hash as u64) % total_bits;
            let byte_idx = (bit_idx / 8) as usize;
            let bit_mask = 1u8 << (bit_idx % 8);
            filter[byte_idx] |= bit_mask;
        }
    }

    filter
}

#[must_use]
pub(crate) fn check_bloom_filter(filter_data: &[u8], path: &[u8]) -> BloomMatch {
    if filter_data.is_empty() || (filter_data.len() == 1 && filter_data[0] == 0xFF) {
        return BloomMatch::Candidate;
    }

    let mut path_set = BTreeSet::new();
    expand_path_and_ancestors(path, &mut path_set);

    if path_set.is_empty() {
        return BloomMatch::Candidate;
    }

    let total_bits = (filter_data.len() * 8) as u64;
    if total_bits == 0 {
        return BloomMatch::Candidate;
    }

    for component in &path_set {
        let hashes = bloom_hashes(component);
        for hash in hashes {
            let bit_idx = (hash as u64) % total_bits;
            let byte_idx = (bit_idx / 8) as usize;
            let bit_mask = 1u8 << (bit_idx % 8);
            if (filter_data[byte_idx] & bit_mask) == 0 {
                return BloomMatch::DefinitelyNo;
            }
        }
    }

    BloomMatch::Candidate
}
