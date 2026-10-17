//! Adversarial and invariant test suite for the immutable graph acceleration engine.

use std::sync::Arc;

use roaring::RoaringBitmap;
use smallvec::SmallVec;

use crate::budget::ByteBudget;
use crate::change::ChangeId;
use crate::error::ErrorCode;
use crate::graph::bloom::{
    build_bloom_filter, check_bloom_filter, murmur3_seeded, DEFAULT_MAX_CHANGED_PATHS,
};
use crate::graph::cache::ReachabilityCache;
use crate::graph::composite::{ChangeIdCursor, GraphIndex, GraphIndexBuilder};
use crate::graph::folding::{fold_segments, should_fold};
use crate::graph::segment::{CommitGraphEntry, GraphSegment, GraphSegmentWriter, StagedCommit};
use crate::graph::traversal::{find_heads, find_roots, is_ancestor, AncestorStepper};
use crate::graph::types::{
    BloomMatch, ExactPathVerifier, Generation, GlobalPosition, LocalPosition, PrefixResolution,
    ShallowAncestry, GRAPH_SEGMENT_MAGIC, GRAPH_SEGMENT_V1_FORMAT, MAX_GRAPH_POSITIONS,
};
use crate::heads::Head;
use crate::ids::{CommitKey, HashKind, Oid};

fn make_git_head(byte_val: u8, kind: HashKind) -> Head {
    let mut bytes = vec![0u8; kind.oid_len()];
    bytes[0] = byte_val;
    for (i, b) in bytes.iter_mut().enumerate().skip(1) {
        *b = ((byte_val as usize + i * 37) % 256) as u8;
    }
    let oid = Oid::from_bytes(&bytes).expect("valid oid bytes");
    Head::Git { oid }
}

fn make_conflicted_head(byte_val: u8, kind: HashKind) -> Head {
    // Native CommitKey has 32-byte identity
    let mut bytes = vec![0u8; 32];
    bytes[0] = byte_val;
    bytes[1] = 0xCF;
    for (i, b) in bytes.iter_mut().enumerate().skip(2) {
        *b = ((byte_val as usize + i * 53) % 256) as u8;
    }
    let key = CommitKey::from_bytes(&bytes).expect("valid commit key bytes");
    Head::Conflicted { key }
}

fn make_change_id(val: u8) -> ChangeId {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    for (i, b) in bytes.iter_mut().enumerate().skip(1) {
        *b = ((val as usize + i * 19) % 256) as u8;
    }
    ChangeId::from_bytes(bytes)
}

#[test]
fn test_sha1_native_head_fixed32_regression() {
    let kind = HashKind::Sha1;
    assert_eq!(kind.oid_len(), 20);

    // Create a 32-byte native CommitKey
    let raw_key_bytes = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26,
    ];
    let key = CommitKey::from_bytes(&raw_key_bytes).expect("valid 32-byte key");
    assert_eq!(key.as_bytes().len(), 32);
    let head = Head::Conflicted { key };

    let mut entry = CommitGraphEntry {
        generation: 1,
        parent1_raw: 0xFFFF_FFFF,
        parent2_raw: 0xFFFF_FFFF,
        change_id_pos: 0,
        head_tag: 1,
        head_digest: [0u8; 32],
    };
    entry.head_digest.copy_from_slice(key.as_bytes());

    // In a SHA-1 repository, decoding must NOT truncate to 20 bytes!
    let decoded = entry.to_head(kind).expect("decoded head");
    match decoded {
        Head::Conflicted { key: decoded_key } => {
            assert_eq!(decoded_key.as_bytes().len(), 32);
            assert_eq!(decoded_key.as_bytes(), &raw_key_bytes);
        }
        Head::Git { .. } => panic!("expected conflicted head"),
    }

    // Now test roundtrip through a complete GraphSegment in a SHA-1 repo
    let budget = ByteBudget::new(10 * 1024 * 1024);
    let mut writer = GraphSegmentWriter::new(kind, String::new(), 0);
    writer.add_commit(StagedCommit {
        head,
        change_id: make_change_id(1),
        generation: Generation::ROOT,
        parents: SmallVec::new(),
        changed_paths: Vec::new(),
    });

    let bytes = writer.build().expect("built segment");
    let segment = GraphSegment::open_from_bytes(bytes, kind, None, &budget).expect("opened segment");

    let read_head = segment.head_at(LocalPosition::from_raw_checked(0)).expect("read head");
    assert_eq!(read_head, head);
    match read_head {
        Head::Conflicted { key: k } => {
            assert_eq!(k.as_bytes().len(), 32);
            assert_eq!(k.as_bytes(), &raw_key_bytes);
        }
        Head::Git { .. } => panic!("expected conflicted head"),
    }
}

#[test]
fn test_cache_same_anchor_repeated_admission() {
    let budget = ByteBudget::new(100_000);
    let cache = ReachabilityCache::new(Arc::clone(&budget), 16).expect("created cache");
    let head = make_git_head(1, HashKind::Sha1);

    let mut bm = RoaringBitmap::new();
    for i in 0..50 {
        bm.insert(i);
    }

    // Admit head 10 times repeatedly
    for _ in 0..10 {
        let res = cache.admit(head, &bm).expect("admit succeeded");
        assert!(res.is_some());
    }

    // Length must be exactly 1; no duplicates
    assert_eq!(cache.len(), 1);
    let entry = cache.get(&head).expect("found entry");
    assert_eq!(entry.cardinality(), 50);
}

#[test]
fn test_cache_held_arc_eviction() {
    // Container (~1.1 KiB) + three held entries (~0.4 KiB) + one decode
    // reservation (1 KiB floor) must fit inside the shared budget.
    let budget = ByteBudget::new(4096);
    let cache = ReachabilityCache::new(Arc::clone(&budget), 16).expect("created cache");

    let h1 = make_git_head(1, HashKind::Sha1);
    let h2 = make_git_head(2, HashKind::Sha1);
    let h3 = make_git_head(3, HashKind::Sha1);

    let mut bm = RoaringBitmap::new();
    for i in 0..10 {
        bm.insert(i);
    }

    let held_entry_1 = cache.admit(h1, &bm).expect("admitted h1").expect("not declined");
    assert_eq!(held_entry_1.cardinality(), 10);

    let _held_entry_2 = cache.admit(h2, &bm).expect("admitted h2");
    let _held_entry_3 = cache.admit(h3, &bm).expect("admitted h3");

    let scoped = held_entry_1.decode_scoped(&budget).expect("decoded scoped");
    assert!(scoped.contains(GlobalPosition::from_raw_checked(5)));
    assert!(!scoped.contains(GlobalPosition::from_raw_checked(99)));

    drop(scoped);
    drop(held_entry_1);
}

#[test]
fn test_preallocation_rejection() {
    let budget_tiny = ByteBudget::new(50);
    let cache_err = ReachabilityCache::new(Arc::clone(&budget_tiny), 16);
    assert!(cache_err.is_err());

    // With enough budget for container but not for a 10,000-element bitmap
    let budget = ByteBudget::new(3000);
    let cache = ReachabilityCache::new(Arc::clone(&budget), 16).expect("created cache");
    let head = make_git_head(1, HashKind::Sha1);

    let mut bm = RoaringBitmap::new();
    for i in 0..10000 {
        bm.insert(i * 10);
    }

    let res = cache.admit(head, &bm).expect("handled without error");
    assert!(res.is_none());
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_bounded_high_divergence_paging() {
    let budget = ByteBudget::new(10 * 1024 * 1024);
    let kind = HashKind::Sha1;
    let mut builder = GraphIndexBuilder::new(GraphIndex::empty(kind));

    let cid = make_change_id(42);
    let total_divergent = 100usize;
    let mut expected_heads = Vec::new();

    for i in 0..total_divergent {
        let h = make_git_head((i % 250 + 1) as u8, kind);
        builder.add_commit(h, cid, &[], vec![]).expect("added commit");
        expected_heads.push(h);
    }

    let index = builder.finish(&budget).expect("built index");

    // Page through divergent heads in bounded batches of 15
    let page_size = 15;
    let mut cursor: Option<ChangeIdCursor> = None;
    let mut collected_heads = Vec::new();

    loop {
        let page = index
            .change_id_to_heads_page(&cid, cursor, page_size)
            .expect("read page");
        assert!(page.items.len() <= page_size);
        collected_heads.extend(page.items);

        if page.next_cursor.is_none() {
            break;
        }
        cursor = page.next_cursor;
    }

    assert_eq!(collected_heads.len(), total_divergent);
}

#[test]
fn test_prefix_lookup_work_and_early_ambiguity() {
    let budget = ByteBudget::new(10 * 1024 * 1024);
    let kind = HashKind::Sha1;
    let mut builder = GraphIndexBuilder::new(GraphIndex::empty(kind));

    // Two heads sharing the exact first byte 0xAA
    let mut b1 = vec![0xAA; 20];
    b1[1] = 0x11;
    let h1 = Head::Git { oid: Oid::from_bytes(&b1).unwrap() };

    let mut b2 = vec![0xAA; 20];
    b2[1] = 0x22;
    let h2 = Head::Git { oid: Oid::from_bytes(&b2).unwrap() };

    // Third head with completely different first byte 0xBB
    let mut b3 = vec![0xBB; 20];
    let h3 = Head::Git { oid: Oid::from_bytes(&b3).unwrap() };

    builder.add_commit(h1, make_change_id(1), &[], vec![]).unwrap();
    builder.add_commit(h2, make_change_id(2), &[], vec![]).unwrap();
    builder.add_commit(h3, make_change_id(3), &[], vec![]).unwrap();

    let index = builder.finish(&budget).unwrap();

    // Query prefix "aa" matches both h1 and h2 -> must return AmbiguousMatch
    let res_ambig = index.resolve_head_prefix("aa").unwrap();
    assert_eq!(res_ambig, PrefixResolution::AmbiguousMatch);

    // Query prefix "aa11" matches only h1 -> SingleMatch(h1)
    let res_single = index.resolve_head_prefix("aa11").unwrap();
    assert_eq!(res_single, PrefixResolution::SingleMatch(h1));

    // Query prefix "cc" has zero matches -> NoMatch
    let res_none = index.resolve_head_prefix("cc").unwrap();
    assert_eq!(res_none, PrefixResolution::NoMatch);
}

#[test]
fn test_capacity_boundary_2_pow_31() {
    let pos_max_valid = GlobalPosition::new(0x7FFF_FFFF);
    assert!(pos_max_valid.is_ok());
    assert_eq!(pos_max_valid.unwrap().as_u32(), 0x7FFF_FFFF);

    let pos_overflow = GlobalPosition::new(0x8000_0000);
    assert!(pos_overflow.is_err());
    assert_eq!(pos_overflow.unwrap_err().code, ErrorCode::ECapacity);

    let pos_huge = GlobalPosition::new(0xFFFF_FFFF);
    assert!(pos_huge.is_err());
    assert_eq!(pos_huge.unwrap_err().code, ErrorCode::ECapacity);
}

#[test]
fn test_corrupt_file_ranges_and_checksum() {
    let budget = ByteBudget::new(10 * 1024 * 1024);
    let kind = HashKind::Sha1;

    let mut writer = GraphSegmentWriter::new(kind, String::new(), 0);
    let h1 = make_git_head(1, kind);
    let cid1 = make_change_id(1);
    writer.add_commit(StagedCommit {
        head: h1,
        change_id: cid1,
        generation: Generation::ROOT,
        parents: SmallVec::new(),
        changed_paths: vec![b"src/main.rs".to_vec()],
    });

    let valid_bytes = writer.build().expect("valid segment build");
    let opened = GraphSegment::open_from_bytes(valid_bytes.clone(), kind, None, &budget);
    assert!(opened.is_ok());

    let mut bad_crc_bytes = valid_bytes.clone();
    bad_crc_bytes[20] ^= 0x55;
    let err_crc = GraphSegment::open_from_bytes(bad_crc_bytes, kind, None, &budget);
    assert_eq!(err_crc.err().expect("crc32 must fail").code, ErrorCode::ECorrupt);

    let mut bad_magic_bytes = valid_bytes.clone();
    bad_magic_bytes[0..8].copy_from_slice(b"BADMAGIC");
    let csum_off = bad_magic_bytes.len() - 4;
    let new_crc = crc32c::crc32c(&bad_magic_bytes[..csum_off]);
    bad_magic_bytes[csum_off..].copy_from_slice(&new_crc.to_le_bytes());

    let err_magic = GraphSegment::open_from_bytes(bad_magic_bytes, kind, None, &budget);
    assert_eq!(err_magic.err().expect("magic must fail").code, ErrorCode::ECorrupt);
}

#[test]
fn test_octopus_parent_ordering_preservation() {
    let budget = ByteBudget::new(10 * 1024 * 1024);
    let kind = HashKind::Sha256;
    let mut builder = GraphIndexBuilder::new(GraphIndex::empty(kind));

    let mut parent_heads = Vec::new();
    let mut parent_positions = Vec::new();
    for i in 1..=6 {
        let h = make_git_head(i, kind);
        let pos = builder.add_commit(h, make_change_id(i), &[], vec![]).unwrap();
        parent_heads.push(h);
        parent_positions.push(pos);
    }

    let ordered_parent_heads = vec![
        parent_heads[4],
        parent_heads[1],
        parent_heads[5],
        parent_heads[0],
        parent_heads[2],
        parent_heads[3],
    ];
    let expected_positions = vec![
        parent_positions[4],
        parent_positions[1],
        parent_positions[5],
        parent_positions[0],
        parent_positions[2],
        parent_positions[3],
    ];

    let merge_head = make_conflicted_head(99, kind);
    let merge_pos = builder
        .add_commit(merge_head, make_change_id(99), &ordered_parent_heads, vec![])
        .unwrap();

    let index = builder.finish(&budget).expect("built index with octopus");
    let actual_parents = index.pos_to_parents(merge_pos).unwrap();
    assert_eq!(actual_parents.as_slice(), expected_positions.as_slice());
}

#[test]
fn test_fold_and_reopen_equivalence() {
    let budget = ByteBudget::new(10 * 1024 * 1024);
    let kind = HashKind::Sha1;

    let mut builder1 = GraphIndexBuilder::new(GraphIndex::empty(kind));
    let h1 = make_git_head(1, kind);
    let h2 = make_git_head(2, kind);
    let h3 = make_git_head(3, kind);
    let h4 = make_git_head(4, kind);

    builder1.add_commit(h1, make_change_id(1), &[], vec![]).unwrap();
    builder1.add_commit(h2, make_change_id(2), &[h1], vec![]).unwrap();
    builder1.add_commit(h3, make_change_id(3), &[h2], vec![]).unwrap();
    builder1.add_commit(h4, make_change_id(4), &[h3], vec![]).unwrap();

    let index1 = builder1.finish(&budget).unwrap();
    assert_eq!(index1.num_total_commits(), 4);

    assert!(should_fold(3, 4));
    let mut builder2 = GraphIndexBuilder::new(index1);
    let h5 = make_git_head(5, kind);
    let h6 = make_git_head(6, kind);
    let h7 = make_git_head(7, kind);

    builder2.add_commit(h5, make_change_id(5), &[h4], vec![]).unwrap();
    builder2.add_commit(h6, make_change_id(6), &[h5], vec![]).unwrap();
    builder2.add_commit(h7, make_change_id(7), &[h6], vec![]).unwrap();

    let index_folded = builder2.finish(&budget).unwrap();
    assert_eq!(index_folded.num_total_commits(), 7);
    assert_eq!(index_folded.segments().len(), 1);

    let cancel = || false;
    let all_heads = [h1, h2, h3, h4, h5, h6, h7];
    for (i, &head) in all_heads.iter().enumerate() {
        let pos = index_folded.head_to_pos(&head).expect("head resolved");
        assert_eq!(pos.as_u32(), i as u32);
        assert_eq!(index_folded.pos_to_head(pos).unwrap(), head);
        assert_eq!(index_folded.pos_to_generation(pos).unwrap().as_u32(), (i + 1) as u32);

        if i > 0 {
            let prev_pos = GlobalPosition::new((i - 1) as u32).unwrap();
            assert_eq!(
                is_ancestor(&index_folded, prev_pos, pos, None, &cancel, 1000).unwrap(),
                ShallowAncestry::ProvenYes
            );
        }
    }
}

#[test]
fn test_shallow_ambiguity_tri_state() {
    let budget = ByteBudget::new(10 * 1024 * 1024);
    let kind = HashKind::Sha1;
    let mut builder = GraphIndexBuilder::new(GraphIndex::empty(kind));

    let h1 = make_git_head(1, kind);
    let h2 = make_git_head(2, kind);
    let h3 = make_git_head(3, kind);
    let h4 = make_git_head(4, kind);

    let p1 = builder.add_commit(h1, make_change_id(1), &[], vec![]).unwrap();
    let p2 = builder.add_commit(h2, make_change_id(2), &[h1], vec![]).unwrap();
    let p3 = builder.add_commit(h3, make_change_id(3), &[h2], vec![]).unwrap();
    let p4 = builder.add_commit(h4, make_change_id(4), &[h3], vec![]).unwrap();

    let index = builder.finish(&budget).unwrap();
    let cancel = || false;

    let shallow = [h2];
    assert_eq!(
        is_ancestor(&index, p1, p4, Some(&shallow), &cancel, 1000).unwrap(),
        ShallowAncestry::Indeterminate
    );
    assert_eq!(
        is_ancestor(&index, p2, p4, Some(&shallow), &cancel, 1000).unwrap(),
        ShallowAncestry::ProvenYes
    );
    assert_eq!(
        is_ancestor(&index, p4, p3, Some(&shallow), &cancel, 1000).unwrap(),
        ShallowAncestry::ProvenNo
    );
}

#[test]
fn test_bloom_filter_false_negative_safety_and_verification() {
    let changed_paths = vec![
        b"crates/ruk-core/src/graph.rs".as_slice(),
        b"docs/architecture.md".as_slice(),
    ];

    let filter = build_bloom_filter(&changed_paths);

    assert_eq!(
        check_bloom_filter(&filter, b"crates/ruk-core/src/graph.rs"),
        BloomMatch::Candidate
    );
    assert_eq!(
        check_bloom_filter(&filter, b"docs/architecture.md"),
        BloomMatch::Candidate
    );
    assert_eq!(
        check_bloom_filter(&filter, b"crates"),
        BloomMatch::Candidate
    );
    assert_eq!(
        check_bloom_filter(&filter, b"vendor/unrelated/library.rs"),
        BloomMatch::DefinitelyNo
    );

    let mut many_paths = Vec::new();
    for i in 0..600 {
        many_paths.push(format!("file_{i}.txt").into_bytes());
    }
    let many_refs: Vec<&[u8]> = many_paths.iter().map(|p| p.as_slice()).collect();
    let large_filter = build_bloom_filter(&many_refs);
    assert_eq!(large_filter.len(), 1);
    assert_eq!(large_filter[0], 0xFF);
    assert_eq!(
        check_bloom_filter(&large_filter, b"any/random/path.rs"),
        BloomMatch::Candidate
    );
}

#[test]
fn test_graph_installed_file_reopen() {
    let budget = ByteBudget::new(10 * 1024 * 1024);
    let kind = HashKind::Sha1;
    let temp_dir = std::env::temp_dir().join(format!("ruk-graph-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let file_path = temp_dir.join("segment-01.graph");

    let mut writer = GraphSegmentWriter::new(kind, String::new(), 0);
    let h1 = make_git_head(1, kind);
    let h2 = make_git_head(2, kind);
    let cid1 = make_change_id(1);
    let cid2 = make_change_id(2);

    writer.add_commit(StagedCommit {
        head: h1,
        change_id: cid1,
        generation: Generation::ROOT,
        parents: SmallVec::new(),
        changed_paths: vec![b"src/lib.rs".to_vec()],
    });
    writer.add_commit(StagedCommit {
        head: h2,
        change_id: cid2,
        generation: Generation::new(2).unwrap(),
        parents: smallvec::smallvec![GlobalPosition::from_raw_checked(0)],
        changed_paths: vec![b"src/main.rs".to_vec()],
    });

    writer.install_to_disk(&file_path).expect("installed segment to disk");
    assert!(file_path.exists());

    let opened = GraphSegment::open_file(&file_path, kind, None, &budget).expect("reopened installed file");
    assert_eq!(opened.num_local_commits(), 2);
    assert_eq!(opened.num_parent_commits(), 0);
    assert_eq!(opened.head_at(LocalPosition::from_raw_checked(0)).unwrap(), h1);
    assert_eq!(opened.head_at(LocalPosition::from_raw_checked(1)).unwrap(), h2);

    let parents_1 = opened.parents_at(LocalPosition::from_raw_checked(1)).unwrap();
    assert_eq!(parents_1.as_slice(), &[GlobalPosition::from_raw_checked(0)]);

    let _ = std::fs::remove_file(&file_path);
    let _ = std::fs::remove_dir(&temp_dir);
}

/// Slice-5 acceptance measurement: object and row work on a large synthetic
/// history and a large branch set. Run on demand; excluded from the suite
/// because it builds 100k commits and writes a throwaway store.
///
/// `cargo test -p ruk-core --lib -- --ignored measure_object_and_row_work --nocapture`
#[test]
#[ignore = "measurement; run on demand"]
fn measure_object_and_row_work() {
    use std::time::Instant;

    use crate::store::{FactMutation, FactPageBudget, FactTable, PreparationBudget, Store};

    let kind = HashKind::Sha1;
    let budget = Arc::new(ByteBudget::new(256 * 1024 * 1024));

    fn seq_head(i: u32, kind: HashKind) -> Head {
        let mut bytes = vec![0u8; kind.oid_len()];
        bytes[..4].copy_from_slice(&i.to_be_bytes());
        for (off, b) in bytes.iter_mut().enumerate().skip(4) {
            *b = ((i as usize).wrapping_add(off * 53) % 256) as u8;
        }
        Head::Git { oid: Oid::from_bytes(&bytes).expect("oid") }
    }

    // --- history: 100k linear commits, one changed path each ---
    const N: u32 = 100_000;
    let t = Instant::now();
    let mut builder = GraphIndexBuilder::new(GraphIndex::empty(kind));
    let mut positions = Vec::with_capacity(N as usize);
    let mut prev: Option<Head> = None;
    for i in 0..N {
        let parents: &[Head] = prev.as_slice();
        let pos = builder
            .add_commit(
                seq_head(i, kind),
                make_change_id((i % 251) as u8),
                parents,
                vec![format!("src/mod_{}.rs", i % 4096).into_bytes()],
            )
            .expect("add");
        positions.push(pos);
        prev = Some(seq_head(i, kind));
    }
    let index = builder.finish(&budget).expect("index");
    println!("MEASURE index_build commits={N} ms={}", t.elapsed().as_millis());
    assert_eq!(index.num_total_commits(), N);

    // --- full-depth ancestor walk from the tip ---
    let t = Instant::now();
    let mut stepper = AncestorStepper::new(&index, &[*positions.last().expect("tip")], None).expect("stepper");
    let mut walked = 0usize;
    loop {
        let page = stepper
            .step_batch(&index, 1000, &|| false, usize::MAX)
            .expect("walk");
        if page.positions.is_empty() {
            break;
        }
        walked += page.positions.len();
    }
    println!("MEASURE ancestor_walk depth={N} visited={walked} ms={}", t.elapsed().as_millis());
    assert_eq!(walked, N as usize);

    // --- ancestry probes: 1k distant pairs (generation short-circuit) ---
    let t = Instant::now();
    let mut proven = 0usize;
    for i in 0..1000u32 {
        let a = positions[i as usize];
        let d = positions[(N - 1 - i) as usize];
        if is_ancestor(&index, a, d, None, &|| false, usize::MAX).expect("probe")
            == ShallowAncestry::ProvenYes
        {
            proven += 1;
        }
    }
    println!("MEASURE ancestor_probe pairs=1000 proven={proven} us={}", t.elapsed().as_micros());
    assert_eq!(proven, 1000);

    // --- prefix resolution over 100k heads ---
    let tip = seq_head(N - 1, kind);
    let t = Instant::now();
    let mut misses = 0usize;
    for i in 0..1000u32 {
        let h = seq_head(i * 97, kind);
        let oid_hex = match &h {
            Head::Git { oid } => oid.to_hex(),
            Head::Conflicted { .. } => unreachable!(),
        };
        if index.resolve_head_prefix(&oid_hex[..12]).is_err() {
            misses += 1;
        }
    }
    println!("MEASURE head_prefix hits=1000 misses={misses} us={}", t.elapsed().as_micros());
    assert_eq!(misses, 0);

    // --- changed-path Bloom: 10k checks against one dense filter ---
    let paths: Vec<&[u8]> = (0..4096u32)
        .map(|i| format!("src/mod_{}.rs", i).into_bytes())
        .collect::<Vec<_>>()
        .iter()
        .map(|v| v.as_slice())
        .collect();
    let owned: Vec<Vec<u8>> = (0..4096u32)
        .map(|i| format!("src/mod_{}.rs", i).into_bytes())
        .collect();
    let paths: Vec<&[u8]> = owned.iter().map(|v| v.as_slice()).collect();
    let filter = build_bloom_filter(&paths);
    let t = Instant::now();
    let mut hits = 0usize;
    for i in 0..10_000u32 {
        let probe = format!("src/mod_{}.rs", i % 8192);
        if check_bloom_filter(&filter, probe.as_bytes()) != BloomMatch::DefinitelyNo {
            hits += 1;
        }
    }
    println!(
        "MEASURE bloom_check paths={} probes=10000 hits={hits} us={}",
        paths.len(),
        t.elapsed().as_micros()
    );

    // --- store row work: publish then page a 10k-ref fact set ---
    let dir = std::env::temp_dir().join(format!("ruk-measure-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("measure dir");
    let store = Store::create(
        &dir.join("store"),
        kind,
        Arc::new(PreparationBudget::reference_defaults()),
    )
    .expect("create store");

    let t = Instant::now();
    let mut facts = Vec::with_capacity(10_000);
    for i in 0..10_000u32 {
        facts.push(FactMutation {
            table: FactTable::Refs,
            key: format!("refs/heads/branch-{i:06}").into_bytes(),
            expected: crate::store::FactExpectation::Absent,
            value: Some(b"target".to_vec()),
        });
    }
    store.publish(Vec::new(), &facts).expect("publish refs");
    println!("MEASURE ref_publish rows=10000 ms={}", t.elapsed().as_millis());

    let base = store.io_stats();
    let t = Instant::now();
    let mut cursor: Option<Vec<u8>> = None;
    let mut rows = 0usize;
    let budget_rows = FactPageBudget::new(1000, 1024 * 1024);
    loop {
        let page = store
            .fact_page(FactTable::Refs, cursor.as_deref(), budget_rows)
            .expect("page");
        rows += page.rows.len();
        cursor = page.rows.last().map(|row| row.key.clone());
        if !page.more {
            break;
        }
    }
    let stats = store.io_stats();
    println!(
        "MEASURE ref_scan rows={rows} lookups={} pages={} rows_read={} ms={}",
        stats.fact_lookups - base.fact_lookups,
        stats.fact_page_calls - base.fact_page_calls,
        stats.fact_rows - base.fact_rows,
        t.elapsed().as_millis()
    );
    assert_eq!(rows, 10_000);
    assert_eq!(stats.fact_rows - base.fact_rows, 10_000);

    // --- object work: 1000 blobs prepare+publish, read back ---
    let t = Instant::now();
    let mut prepared = Vec::with_capacity(1000);
    for i in 0..1000u32 {
        let body = format!("blob-body-{i}").into_bytes();
        prepared.push(
            store
                .prepare(
                    crate::store::ObjectKind::Blob,
                    body.len() as u64,
                    body.as_slice(),
                    None,
                )
                .expect("prepare"),
        );
    }
    store.publish(prepared, &[]).expect("publish blobs");
    println!("MEASURE blob_publish objects=1000 ms={}", t.elapsed().as_millis());

    let base = store.io_stats();
    let t = Instant::now();
    for i in 0..1000u32 {
        let expected = format!("blob-body-{i}").into_bytes();
        let oid = kind
            .hash_git_object("blob", &expected)
            .expect("hash");
        let mut got = Vec::new();
        std::io::Read::read_to_end(&mut store.read(oid).expect("read").bytes, &mut got)
            .expect("drain");
        assert_eq!(got, expected);
    }
    let stats = store.io_stats();
    println!(
        "MEASURE blob_read objects=1000 decoded_bytes={} reads={} ms={}",
        stats.object_decoded_bytes - base.object_decoded_bytes,
        stats.object_reads - base.object_reads,
        t.elapsed().as_millis()
    );
    assert_eq!(stats.object_reads - base.object_reads, 1000);

    let _ = std::fs::remove_dir_all(&dir);
}
