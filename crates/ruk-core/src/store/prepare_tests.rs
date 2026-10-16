//! Adversarial tests for preparation, spools, budgets and canonical deltas.
//!
//! Object identities come from the parent byte oracles
//! (`local://ruk-store-byte-oracles.json`) and delta bytes from the Git
//! delta format, not from this implementation's own encoder.

use std::cell::Cell;
use std::fs;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::ids::{HashKind, Oid};
use crate::store::delta::{apply_delta, clamp_copy_spans, encode_delta};
use crate::store::error::StoreError;
use crate::store::prepare::{EncodedSink, Failure, classify_sink, decode_record, prepare_object};
use crate::store::segment::SegmentError;
use crate::store::spool::{BudgetLimits, PreparationBudget, Spool, SpoolWriter};
use crate::store::types::{Encoding, ObjectKind, PreparedObject, ReadObject};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("ruk-prep-{tag}-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&path).expect("temp root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn scratch_entries(&self) -> Vec<String> {
        match fs::read_dir(self.0.join("scratch")) {
            Ok(entries) => entries
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limits(threshold: usize) -> BudgetLimits {
    BudgetLimits {
        memory_spool_threshold: threshold,
        ..BudgetLimits::default()
    }
}

fn budget_with(limits: BudgetLimits) -> Arc<PreparationBudget> {
    Arc::new(PreparationBudget::new(limits))
}

fn default_budget() -> Arc<PreparationBudget> {
    Arc::new(PreparationBudget::reference_defaults())
}

/// Deterministic incompressible bytes.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let bytes = state.to_le_bytes();
            bytes[0] ^ bytes[3]
        })
        .collect()
}

fn len64(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).expect("length fits")
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let low = u8::try_from(value & 0x7f).expect("seven bits");
        value >>= 7;
        if value == 0 {
            out.push(low);
            return out;
        }
        out.push(low | 0x80);
    }
}

fn prepare(
    budget: &Arc<PreparationBudget>,
    root: &Path,
    hash_kind: HashKind,
    kind: ObjectKind,
    data: &[u8],
    predecessor: Option<(Oid, &ReadObject)>,
) -> Result<PreparedObject, StoreError> {
    prepare_object(
        hash_kind,
        kind,
        len64(data),
        Cursor::new(data.to_vec()),
        predecessor,
        budget,
        root,
    )
}

fn read_all(spool: &Spool) -> Vec<u8> {
    let mut out = Vec::new();
    spool.view().read_to_end(&mut out).expect("read spool");
    out
}

fn spool_of(budget: &Arc<PreparationBudget>, root: &Path, bytes: &[u8]) -> Spool {
    let mut writer = SpoolWriter::new(budget, root);
    writer.append(bytes).expect("append");
    writer.finish().expect("finish")
}

/// What a stored record claims to be.
struct Rec<'a> {
    hash_kind: HashKind,
    kind: ObjectKind,
    oid: &'a Oid,
    encoding: Encoding,
    decoded_len: u64,
}

impl<'a> Rec<'a> {
    fn blob(oid: &'a Oid, encoding: Encoding, decoded_len: u64) -> Self {
        Self {
            hash_kind: HashKind::Sha1,
            kind: ObjectKind::Blob,
            oid,
            encoding,
            decoded_len,
        }
    }
}

fn decode_bytes(
    budget: &Arc<PreparationBudget>,
    root: &Path,
    rec: &Rec<'_>,
    encoded: Vec<u8>,
    base: Option<(Oid, &Spool)>,
) -> Result<Spool, StoreError> {
    let encoded_len = len64(&encoded);
    decode_record(
        rec.hash_kind,
        rec.kind,
        rec.oid,
        rec.encoding,
        Cursor::new(encoded),
        encoded_len,
        rec.decoded_len,
        base.map(|(oid, spool)| (oid, spool.view())),
        budget,
        root,
    )
}

fn decode_prepared(
    budget: &Arc<PreparationBudget>,
    root: &Path,
    hash_kind: HashKind,
    prepared: &PreparedObject,
    base: Option<&ReadObject>,
) -> Result<Spool, StoreError> {
    let rec = Rec {
        hash_kind,
        kind: prepared.kind,
        oid: &prepared.oid,
        encoding: prepared.encoding,
        decoded_len: prepared.decoded_len,
    };
    decode_bytes(
        budget,
        root,
        &rec,
        read_all(&prepared.payload),
        base.and_then(|read| prepared.base.map(|oid| (oid, &read.bytes))),
    )
}

fn assert_corrupt(result: Result<Spool, StoreError>) {
    match result {
        Err(StoreError::Corrupt(_)) => {}
        other => panic!("expected E_CORRUPT, got {other:?}"),
    }
}

fn hex_oid(hex: &str) -> Oid {
    Oid::from_hex(hex).expect("oid")
}

/// The five parent oracle objects for sha1, rebuilt from their documented
/// text. The expected ids are the parent's, not computed here.
fn sha1_oracle() -> Vec<(ObjectKind, Vec<u8>, &'static str)> {
    let blob = b"Ruk exact bytes\0\xff\r\n\n".to_vec();
    let blob_oid = hex_oid("a09917acf1a590bfae6975b474255428a9de4c08");
    let mut tree = b"100644 payload.bin\0".to_vec();
    tree.extend_from_slice(blob_oid.as_bytes());
    let tree_hex = "d89b0e8d19f8889aa02e44e0d502c991c2104b16";
    let commit_hex = "9a9418ce1dcf349028993df108bf5f294fd0a887";

    let mut commit = format!(
        "tree {tree_hex}\nauthor A <a@example.test> 1 -0000\ncommitter B <b@example.test> 2 +0530\n\
         x-z preserved-first\nx-a preserved-second\n\nbyte message"
    )
    .into_bytes();
    commit.extend_from_slice(b"\xff\x00\n");

    let mut tag = format!(
        "object {commit_hex}\ntype commit\ntag exact-v1\ntagger C <c@example.test> 3 +0000\n\nannotated"
    )
    .into_bytes();
    tag.extend_from_slice(b"\xff\n");

    let mut conflict_payload = format!(
        "trees {tree_hex} {} {}\nparent {commit_hex}\nauthor A <a@example.test> 1 -0000\n\
         committer B <b@example.test> 2 +0530\n\nnative",
        "1".repeat(40),
        "2".repeat(40)
    )
    .into_bytes();
    conflict_payload.extend_from_slice(b"\xff\x00\n");
    let mut conflict = format!("conflict-v1 {}\0", conflict_payload.len()).into_bytes();
    conflict.extend_from_slice(&conflict_payload);

    vec![
        (
            ObjectKind::Blob,
            blob,
            "a09917acf1a590bfae6975b474255428a9de4c08",
        ),
        (ObjectKind::Tree, tree, tree_hex),
        (ObjectKind::Commit, commit, commit_hex),
        (
            ObjectKind::Tag,
            tag,
            "4b4091ab8c18150e79d2da777f87fa672b98e481",
        ),
        (
            ObjectKind::Conflict,
            conflict,
            "fb4084cae077aa7dfcdb8731b57f0072c2be2f45",
        ),
    ]
}

#[test]
fn oracle_objects_hash_and_round_trip_for_both_kinds() {
    let root = TempRoot::new("oracle");
    let budget = default_budget();
    let sha1 = sha1_oracle();
    assert_eq!(
        [
            sha1[1].1.len(),
            sha1[2].1.len(),
            sha1[3].1.len(),
            sha1[4].1.len()
        ],
        [39, 174, 119, 274],
        "documented oracle lengths"
    );
    for (kind, bytes, expected) in &sha1 {
        let prepared =
            prepare(&budget, root.path(), HashKind::Sha1, *kind, bytes, None).expect("prepare");
        assert_eq!(prepared.oid.to_hex(), *expected, "{kind:?}");
        assert_eq!(prepared.encoding, Encoding::Zstd);
        assert_eq!((prepared.base, prepared.depth), (None, 0));
        let decoded =
            decode_prepared(&budget, root.path(), HashKind::Sha1, &prepared, None).expect("decode");
        assert_eq!(read_all(&decoded), *bytes, "{kind:?}");
    }
    let blob = &sha1[0].1;
    let sha256 = prepare(
        &budget,
        root.path(),
        HashKind::Sha256,
        ObjectKind::Blob,
        blob,
        None,
    )
    .expect("sha256");
    assert_eq!(
        sha256.oid.to_hex(),
        "947cfda6040d3bf793cacfbd8703874640300650dafd43db5656b4ae9a38260c"
    );
    let decoded = decode_prepared(&budget, root.path(), HashKind::Sha256, &sha256, None).unwrap();
    assert_eq!(read_all(&decoded), *blob);
    // A sha256 id is refused by a sha1 repository, never compared.
    let err = decode_prepared(&budget, root.path(), HashKind::Sha1, &sha256, None).unwrap_err();
    assert!(matches!(err, StoreError::ObjectFormat(_)), "{err:?}");
}

#[test]
fn native_conflict_bytes_are_hashed_without_a_git_header() {
    let root = TempRoot::new("conflict");
    let budget = default_budget();
    let sha1 = sha1_oracle();
    let (_, framed, expected) = &sha1[4];
    let as_blob = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        framed,
        None,
    )
    .unwrap();
    assert_ne!(
        as_blob.oid.to_hex(),
        *expected,
        "a blob header must change the identity"
    );
    let as_conflict = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Conflict,
        framed,
        None,
    )
    .unwrap();
    assert_eq!(as_conflict.oid.to_hex(), *expected);
}

#[test]
fn empty_objects_hash_to_the_known_empty_blob_ids() {
    let root = TempRoot::new("empty");
    let budget = default_budget();
    for (kind, expected) in [
        (HashKind::Sha1, "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
        (
            HashKind::Sha256,
            "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813",
        ),
    ] {
        let prepared = prepare(&budget, root.path(), kind, ObjectKind::Blob, b"", None).unwrap();
        assert_eq!(prepared.oid.to_hex(), expected);
        let decoded = decode_prepared(&budget, root.path(), kind, &prepared, None).unwrap();
        assert!(decoded.is_empty());
    }
}

#[test]
fn spilled_payload_round_trips_and_every_byte_is_released() {
    let root = TempRoot::new("spill");
    let budget = budget_with(limits(1024));
    let data = noise(1, 300_000);
    let prepared = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        &data,
        None,
    )
    .unwrap();
    assert!(
        prepared.payload.len() > 1024,
        "incompressible payload must spill"
    );
    assert_eq!(root.scratch_entries().len(), 1);
    let (memory, scratch) = budget.in_use();
    assert!(scratch >= prepared.payload.len());
    assert!(
        memory < 1 << 20,
        "only the encoded spool remains charged: {memory}"
    );

    let decoded = decode_prepared(&budget, root.path(), HashKind::Sha1, &prepared, None).unwrap();
    assert_eq!(root.scratch_entries().len(), 2);
    assert_eq!(read_all(&decoded), data);
    drop(decoded);
    drop(prepared);
    assert!(
        root.scratch_entries().is_empty(),
        "own files only, all removed"
    );
    assert_eq!(budget.in_use(), (0, 0));
}

#[test]
fn declared_length_mismatch_is_invalid_and_leaves_nothing() {
    let root = TempRoot::new("length");
    for (threshold, len) in [(256 * 1024, 1000_usize), (1024, 5000)] {
        let budget = budget_with(limits(threshold));
        let data = noise(2, len);
        for declared in [len64(&data) - 1, len64(&data) + 1] {
            let err = prepare_object(
                HashKind::Sha1,
                ObjectKind::Blob,
                declared,
                Cursor::new(data.clone()),
                None,
                &budget,
                root.path(),
            )
            .unwrap_err();
            assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
            assert_eq!(budget.in_use(), (0, 0));
            assert!(root.scratch_entries().is_empty());
        }
    }
}

#[test]
fn declared_length_mismatch_with_a_predecessor_is_invalid_too() {
    let root = TempRoot::new("length-delta");
    let budget = default_budget();
    let base = noise(3, 50_000);
    let base_oid = HashKind::Sha1.hash_git_object("blob", &base).unwrap();
    let read = ReadObject {
        kind: ObjectKind::Blob,
        bytes: spool_of(&budget, root.path(), &base),
        depth: 0,
    };
    let err = prepare_object(
        HashKind::Sha1,
        ObjectKind::Blob,
        50_001,
        Cursor::new(base.clone()),
        Some((base_oid, &read)),
        &budget,
        root.path(),
    )
    .unwrap_err();
    assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
    drop(read);
    assert_eq!(budget.in_use(), (0, 0));
}

struct Tripwire<'a>(&'a Cell<bool>);

impl Read for Tripwire<'_> {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        self.0.set(true);
        Ok(0)
    }
}

#[test]
fn admission_refuses_before_reading_a_single_byte() {
    let root = TempRoot::new("admission");
    let budget = budget_with(BudgetLimits {
        max_object_bytes: Some(100),
        ..BudgetLimits::default()
    });
    let touched = Cell::new(false);
    let err = prepare_object(
        HashKind::Sha1,
        ObjectKind::Blob,
        101,
        Tripwire(&touched),
        None,
        &budget,
        root.path(),
    )
    .unwrap_err();
    assert!(matches!(err, StoreError::Limit(_)), "{err:?}");
    assert!(!touched.get(), "input was read before admission");
    let at_limit = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        &noise(4, 100),
        None,
    );
    assert!(at_limit.is_ok());
}

#[test]
fn memory_exhaustion_is_typed_and_releases_everything() {
    let root = TempRoot::new("memory");
    let budget = budget_with(BudgetLimits {
        max_prepared_memory: 1 << 20,
        ..BudgetLimits::default()
    });
    let err = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        &noise(5, 10_000),
        None,
    )
    .unwrap_err();
    assert!(matches!(err, StoreError::Limit(_)), "{err:?}");
    assert_eq!(budget.in_use(), (0, 0));
    assert!(root.scratch_entries().is_empty());
}

#[test]
fn released_memory_admits_the_next_preparation() {
    let root = TempRoot::new("memory-reuse");
    // Room for exactly one small preparation at a time (1 MiB I/O + 2 MiB codec).
    let budget = budget_with(BudgetLimits {
        max_prepared_memory: 4 << 20,
        ..BudgetLimits::default()
    });
    for seed in 0..3 {
        let prepared = prepare(
            &budget,
            root.path(),
            HashKind::Sha1,
            ObjectKind::Blob,
            &noise(seed, 5_000),
            None,
        )
        .unwrap();
        // The live payload keeps its own bytes charged until dropped.
        assert!(budget.in_use().0 >= prepared.payload.len());
        drop(prepared);
        assert_eq!(budget.in_use(), (0, 0));
    }
}

#[test]
fn per_store_and_global_scratch_exhaustion_release_the_disk_charge() {
    for (per_store, total) in [(50_000, u64::MAX / 2), (u64::MAX / 2, 50_000)] {
        let root = TempRoot::new("scratch");
        let budget = budget_with(BudgetLimits {
            max_scratch_per_store: per_store,
            max_scratch_total: total,
            memory_spool_threshold: 1024,
            ..BudgetLimits::default()
        });
        let err = prepare(
            &budget,
            root.path(),
            HashKind::Sha1,
            ObjectKind::Blob,
            &noise(6, 200_000),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, StoreError::Limit(_)), "{err:?}");
        assert_eq!(
            budget.in_use(),
            (0, 0),
            "disk charge must be released with the file"
        );
        assert!(
            root.scratch_entries().is_empty(),
            "the failed spool's own file is removed"
        );
    }
}

#[test]
fn crash_left_scratch_counts_against_admission_and_survives() {
    let root = TempRoot::new("leftover");
    fs::create_dir_all(root.path().join("scratch")).unwrap();
    let leftover = root.path().join("scratch").join("crashed-spool.tmp");
    fs::write(&leftover, vec![0_u8; 100_000]).unwrap();
    let budget = budget_with(BudgetLimits {
        max_scratch_per_store: 120_000,
        memory_spool_threshold: 1024,
        ..BudgetLimits::default()
    });
    let err = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        &noise(7, 50_000),
        None,
    )
    .unwrap_err();
    assert!(matches!(err, StoreError::Limit(_)), "{err:?}");
    assert_eq!(
        fs::metadata(&leftover).unwrap().len(),
        100_000,
        "foreign file untouched"
    );
    assert_eq!(
        budget.scratch_in_use(root.path()),
        Some(100_000),
        "baseline stays charged"
    );

    let small = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        &noise(8, 10_000),
        None,
    )
    .expect("a small object still fits next to the leftover");
    drop(small);
    assert!(leftover.exists());
    assert_eq!(budget.scratch_in_use(root.path()), Some(100_000));
}

#[test]
fn scratch_registration_is_idempotent_and_never_double_charges() {
    let root = TempRoot::new("register");
    fs::create_dir_all(root.path().join("scratch")).unwrap();
    fs::write(
        root.path().join("scratch").join("old.tmp"),
        vec![1_u8; 5000],
    )
    .unwrap();
    let budget = default_budget();
    budget.register_scratch(root.path()).unwrap();
    budget.register_scratch(root.path()).unwrap();
    assert_eq!(budget.scratch_in_use(root.path()), Some(5000));
    assert_eq!(budget.in_use(), (0, 5000));
}

fn base_and_target() -> (Vec<u8>, Vec<u8>) {
    let base = noise(10, 200_000);
    let mut target = base.clone();
    for byte in &mut target[100_000..100_050] {
        *byte ^= 0xff;
    }
    (base, target)
}

fn base_read(budget: &Arc<PreparationBudget>, root: &Path, base: &[u8], depth: u8) -> ReadObject {
    ReadObject {
        kind: ObjectKind::Blob,
        bytes: spool_of(budget, root, base),
        depth,
    }
}

#[test]
fn small_edit_becomes_a_git_delta_with_exact_instruction_bytes() {
    let root = TempRoot::new("delta");
    let budget = default_budget();
    let (base, target) = base_and_target();
    let base_oid = HashKind::Sha1.hash_git_object("blob", &base).unwrap();
    let read = base_read(&budget, root.path(), &base, 0);
    let prepared = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        &target,
        Some((base_oid, &read)),
    )
    .unwrap();
    assert_eq!(prepared.encoding, Encoding::Delta);
    assert_eq!((prepared.base, prepared.depth), (Some(base_oid), 1));
    assert_eq!(
        prepared.oid,
        HashKind::Sha1.hash_git_object("blob", &target).unwrap()
    );
    assert!(
        prepared.payload.len() * 2 < len64(&target),
        "kept only below half"
    );

    let payload = read_all(&prepared.payload);
    assert_eq!(&payload[..20], base_oid.as_bytes());
    let stream = zstd::stream::decode_all(&payload[20..]).unwrap();
    // varint(200000) twice, copy 0x10000 at 0 (no size bytes), copy 34464 at
    // 0x10000, then the 50-byte literal middle (the xor-ed bytes). The
    // suffix copy of the last 99950 bytes (base offset 100050 = 0x0186d2)
    // follows as two pieces: 0x10000 bytes, then 34414 = 0x866e bytes at
    // 0x0286d2.
    assert_eq!(
        &stream[..11],
        &[
            0xc0, 0x9a, 0x0c, 0xc0, 0x9a, 0x0c, 0x80, 0xb4, 0x01, 0xa0, 0x86
        ]
    );
    assert_eq!(stream[11], 50);
    assert_eq!(&stream[12..62], &target[100_000..100_050]);
    assert_eq!(
        &stream[62..],
        &[0x87, 0xd2, 0x86, 0x01, 0xb7, 0xd2, 0x86, 0x02, 0x6e, 0x86]
    );

    let decoded =
        decode_prepared(&budget, root.path(), HashKind::Sha1, &prepared, Some(&read)).unwrap();
    assert_eq!(read_all(&decoded), target);
}

#[test]
fn unrelated_predecessor_and_depth_cap_fall_back_to_zstd() {
    let root = TempRoot::new("fallback");
    let budget = default_budget();
    let (base, target) = base_and_target();
    let base_oid = HashKind::Sha1.hash_git_object("blob", &base).unwrap();

    let unrelated = noise(11, 200_000);
    let read = base_read(&budget, root.path(), &base, 0);
    let prepared = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        &unrelated,
        Some((base_oid, &read)),
    )
    .unwrap();
    assert_eq!(
        (prepared.encoding, prepared.base, prepared.depth),
        (Encoding::Zstd, None, 0)
    );
    let decoded = decode_prepared(&budget, root.path(), HashKind::Sha1, &prepared, None).unwrap();
    assert_eq!(read_all(&decoded), unrelated);

    let at_cap = base_read(&budget, root.path(), &base, 50);
    let capped = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        &target,
        Some((base_oid, &at_cap)),
    )
    .unwrap();
    assert_eq!(
        capped.encoding,
        Encoding::Zstd,
        "a depth 50 base never gains a link"
    );

    let below_cap = base_read(&budget, root.path(), &base, 49);
    let last = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        &target,
        Some((base_oid, &below_cap)),
    )
    .unwrap();
    assert_eq!((last.encoding, last.depth), (Encoding::Delta, 50));
}

#[test]
fn malformed_predecessors_are_errors_not_silent_fallbacks() {
    let root = TempRoot::new("predecessor");
    let budget = default_budget();
    let (base, target) = base_and_target();
    let read = base_read(&budget, root.path(), &base, 0);
    let sha1_oid = HashKind::Sha1.hash_git_object("blob", &base).unwrap();
    let err = prepare(
        &budget,
        root.path(),
        HashKind::Sha256,
        ObjectKind::Blob,
        &target,
        Some((sha1_oid, &read)),
    )
    .unwrap_err();
    assert!(matches!(err, StoreError::ObjectFormat(_)), "{err:?}");
    let err = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Tree,
        &target,
        Some((sha1_oid, &read)),
    )
    .unwrap_err();
    assert!(matches!(err, StoreError::Invalid(_)), "{err:?}");
}

#[test]
fn delta_decode_rejects_wrong_base_missing_base_and_framing_damage() {
    let root = TempRoot::new("delta-damage");
    let budget = default_budget();
    let (base, target) = base_and_target();
    let base_oid = HashKind::Sha1.hash_git_object("blob", &base).unwrap();
    let read = base_read(&budget, root.path(), &base, 0);
    let prepared = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        &target,
        Some((base_oid, &read)),
    )
    .unwrap();
    let payload = read_all(&prepared.payload);
    let decode = |encoded: Vec<u8>, base: Option<(Oid, &Spool)>| {
        let rec = Rec::blob(&prepared.oid, Encoding::Delta, prepared.decoded_len);
        decode_bytes(&budget, root.path(), &rec, encoded, base)
    };
    assert!(decode(payload.clone(), Some((base_oid, &read.bytes))).is_ok());

    let other = hex_oid("0123456789012345678901234567890123456789");
    assert_corrupt(decode(payload.clone(), Some((other, &read.bytes))));
    assert_corrupt(decode(payload.clone(), None));
    let mut trailing = payload.clone();
    trailing.push(0);
    assert_corrupt(decode(trailing, Some((base_oid, &read.bytes))));
    let truncated = payload[..payload.len() - 1].to_vec();
    assert_corrupt(decode(truncated, Some((base_oid, &read.bytes))));
    assert_corrupt(decode(
        payload[..10].to_vec(),
        Some((base_oid, &read.bytes)),
    ));
    // The right base id over different base bytes cannot reproduce the identity.
    let wrong_bytes = spool_of(&budget, root.path(), &noise(12, 200_000));
    assert_corrupt(decode(payload, Some((base_oid, &wrong_bytes))));
    assert_eq!(
        budget.in_use().1,
        0,
        "no scratch left charged after failed decodes"
    );
}

#[test]
fn raw_records_decode_and_every_mismatch_is_corrupt() {
    let root = TempRoot::new("raw");
    let budget = default_budget();
    let data = noise(13, 1000);
    let oid = HashKind::Sha1.hash_git_object("blob", &data).unwrap();
    let decode = |encoded: Vec<u8>, decoded_len: u64, oid: &Oid| {
        let rec = Rec::blob(oid, Encoding::Raw, decoded_len);
        decode_bytes(&budget, root.path(), &rec, encoded, None)
    };
    assert_eq!(read_all(&decode(data.clone(), 1000, &oid).unwrap()), data);
    assert_corrupt(decode(data.clone(), 999, &oid));
    assert_corrupt(decode(data[..999].to_vec(), 1000, &oid));
    let mut flipped = data.clone();
    flipped[500] ^= 1;
    assert_corrupt(decode(flipped, 1000, &oid));
    let tree_oid = HashKind::Sha1.hash_git_object("tree", &data).unwrap();
    assert_corrupt(decode(data, 1000, &tree_oid));
}

fn frame(data: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(data, 3).unwrap()
}

#[test]
fn zstd_framing_attacks_are_rejected() {
    let root = TempRoot::new("framing");
    let budget = default_budget();
    let data = noise(14, 5000);
    let oid = HashKind::Sha1.hash_git_object("blob", &data).unwrap();
    let decode = |encoded: Vec<u8>| {
        let rec = Rec::blob(&oid, Encoding::Zstd, 5000);
        decode_bytes(&budget, root.path(), &rec, encoded, None)
    };
    let good = frame(&data);
    assert_eq!(read_all(&decode(good.clone()).unwrap()), data);

    let mut trailing = good.clone();
    trailing.push(0);
    assert_corrupt(decode(trailing));
    let mut concatenated = good.clone();
    concatenated.extend_from_slice(&frame(b""));
    assert_corrupt(decode(concatenated));
    let mut skippable = good.clone();
    skippable.extend_from_slice(&[0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0]);
    assert_corrupt(decode(skippable));
    assert_corrupt(decode(good[..good.len() - 1].to_vec()));
    assert_corrupt(decode(good[..good.len() / 2].to_vec()));
    assert_corrupt(decode(vec![0xff; 64]));
    assert_corrupt(decode(Vec::new()));
    assert_eq!(budget.in_use(), (0, 0));
}

#[test]
fn decompression_bombs_stop_at_the_declared_length() {
    let root = TempRoot::new("bomb");
    let budget = budget_with(BudgetLimits {
        max_prepared_memory: 16 << 20,
        max_scratch_total: 1 << 20,
        max_scratch_per_store: 1 << 20,
        ..BudgetLimits::default()
    });
    // 64 MiB of zeros compress to a few KiB; the record declares 1 KiB.
    let bomb = zstd::stream::encode_all(io::repeat(0).take(64 << 20), 3).unwrap();
    assert!(bomb.len() < 16 * 1024);
    let zeros = vec![0_u8; 1024];
    let oid = HashKind::Sha1.hash_git_object("blob", &zeros).unwrap();
    let rec = Rec::blob(&oid, Encoding::Zstd, 1024);
    assert_corrupt(decode_bytes(&budget, root.path(), &rec, bomb, None));
    assert_eq!(budget.in_use(), (0, 0));
    assert!(root.scratch_entries().is_empty());
}

#[test]
fn frames_needing_a_window_above_level_three_are_rejected() {
    let root = TempRoot::new("window");
    let budget = default_budget();
    let data = noise(15, 1 << 20);
    let oid = HashKind::Sha1.hash_git_object("blob", &data).unwrap();
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
    encoder.window_log(27).unwrap();
    encoder.write_all(&data).unwrap();
    let hostile = encoder.finish().unwrap();
    let rec = Rec::blob(&oid, Encoding::Zstd, len64(&data));
    assert_corrupt(decode_bytes(&budget, root.path(), &rec, hostile, None));
    assert_eq!(budget.in_use(), (0, 0));
}

#[test]
fn large_level_three_objects_fit_the_window_cap() {
    let root = TempRoot::new("large");
    let budget = default_budget();
    let block = noise(16, 300_000);
    let mut data = Vec::new();
    for round in 0..16_u8 {
        data.extend_from_slice(&block);
        data.extend_from_slice(&[round; 4096]);
    }
    let prepared = prepare(
        &budget,
        root.path(),
        HashKind::Sha1,
        ObjectKind::Blob,
        &data,
        None,
    )
    .unwrap();
    assert!(
        prepared.payload.len() < len64(&data) / 4,
        "repeats inside the window compress"
    );
    let decoded = decode_prepared(&budget, root.path(), HashKind::Sha1, &prepared, None).unwrap();
    assert_eq!(read_all(&decoded), data);
}

struct FailingReader {
    data: Cursor<Vec<u8>>,
    after: usize,
    error: fn() -> io::Error,
}

impl Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let position = usize::try_from(self.data.position()).unwrap();
        if position >= self.after {
            return Err((self.error)());
        }
        let room = (self.after - position).min(buf.len());
        self.data.read(&mut buf[..room])
    }
}

#[test]
fn read_failures_keep_their_class() {
    let root = TempRoot::new("io");
    let budget = default_budget();
    let data = noise(17, 4000);
    let oid = HashKind::Sha1.hash_git_object("blob", &data).unwrap();
    let good = frame(&data);
    let decode = |error: fn() -> io::Error, after: usize| {
        let source = FailingReader {
            data: Cursor::new(good.clone()),
            after,
            error,
        };
        decode_record(
            HashKind::Sha1,
            ObjectKind::Blob,
            &oid,
            Encoding::Zstd,
            source,
            len64(&good),
            4000,
            None,
            &budget,
            root.path(),
        )
    };
    let io_error = decode(|| io::Error::other("disk fell over"), 3).unwrap_err();
    assert!(matches!(io_error, StoreError::Io(_)), "{io_error:?}");
    let embedded = decode(
        || {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                SegmentError::Corrupt("record truncated".into()),
            )
        },
        3,
    )
    .unwrap_err();
    assert!(matches!(embedded, StoreError::Corrupt(_)), "{embedded:?}");
    assert_eq!(budget.in_use(), (0, 0));
}

#[test]
fn input_read_failure_is_io_and_releases_the_spool() {
    let root = TempRoot::new("input-io");
    let budget = budget_with(limits(1024));
    let source = FailingReader {
        data: Cursor::new(noise(18, 100_000)),
        after: 50_000,
        error: || io::Error::other("source vanished"),
    };
    let err = prepare_object(
        HashKind::Sha1,
        ObjectKind::Blob,
        100_000,
        source,
        None,
        &budget,
        root.path(),
    )
    .unwrap_err();
    assert!(matches!(err, StoreError::Io(_)), "{err:?}");
    assert_eq!(budget.in_use(), (0, 0));
    assert!(root.scratch_entries().is_empty());
}

fn apply(base: &[u8], delta: &[u8], expected: u64) -> (Result<(), StoreError>, Vec<u8>) {
    let mut out = Vec::new();
    let result = apply_delta(
        &mut Cursor::new(base.to_vec()),
        len64(base),
        delta,
        expected,
        &mut out,
    );
    (result, out)
}

/// Asserts `E_CORRUPT` and returns whatever the applier had written.
fn assert_delta_corrupt(base: &[u8], delta: &[u8], expected: u64) -> Vec<u8> {
    let (result, out) = apply(base, delta, expected);
    match result {
        Err(StoreError::Corrupt(_)) => out,
        other => panic!("expected E_CORRUPT, got {other:?}"),
    }
}

#[test]
fn delta_applier_checks_every_instruction_before_writing() {
    let base = b"0123456789";
    let (result, out) = apply(base, &[10, 5, 0x91, 2, 3, 2, b'x', b'y'], 5);
    result.unwrap();
    assert_eq!(out, b"234xy");

    // Copy past the end of the base: nothing written.
    assert!(assert_delta_corrupt(base, &[10, 4, 0x91, 8, 4], 4).is_empty());
    // Copy larger than the room left in the result: refused before copying.
    assert!(assert_delta_corrupt(base, &[10, 3, 0x90, 5], 3).is_empty());
    // Insert larger than the room left: refused before writing.
    assert!(assert_delta_corrupt(base, &[10, 2, 3, b'a', b'b', b'c'], 2).is_empty());
    // A zero size field means 0x10000, which outruns a 10-byte base.
    assert!(assert_delta_corrupt(base, &[10, 10, 0x80], 10).is_empty());
    // Reserved opcode, truncated insert, truncated copy operand.
    assert_delta_corrupt(base, &[10, 1, 0], 1);
    assert_delta_corrupt(base, &[10, 5, 5, b'a', b'b'], 5);
    assert_delta_corrupt(base, &[10, 5, 0x91, 2], 5);
    // The stream ends before the declared result, or continues after it.
    assert_delta_corrupt(base, &[10, 5], 5);
    assert_delta_corrupt(base, &[10, 1, 1, b'a', 1, b'b'], 1);
    // Wrong base size, wrong result size, truncated header, 64-bit overflow.
    assert_delta_corrupt(base, &[9, 1, 1, b'a'], 1);
    assert_delta_corrupt(base, &[10, 6, 1, b'a'], 1);
    assert_delta_corrupt(base, &[10], 1);
    assert_delta_corrupt(base, &[0xff; 11], 1);
    // A result size of 2^40 against a declared length of 1 is refused up front.
    assert_delta_corrupt(base, &[10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x20], 1);
}

#[test]
fn zero_size_copy_means_sixty_four_kib_and_wide_operands_decode() {
    let base = noise(19, 70_000);

    // Size field absent: 0x10000 bytes from offset 0.
    let mut stream = varint(70_000);
    stream.extend(varint(65_536));
    stream.push(0x80);
    let (result, out) = apply(&base, &stream, 65_536);
    result.unwrap();
    assert_eq!(out, base[..65_536]);

    // Offset 0x10000 (byte 2 only), size 4464 = 0x1170 (two size bytes).
    let mut stream = varint(70_000);
    stream.extend(varint(4464));
    stream.extend([0xb4, 0x01, 0x70, 0x11]);
    let (result, out) = apply(&base, &stream, 4464);
    result.unwrap();
    assert_eq!(out, base[65_536..70_000]);

    // Offset 0x01000000 uses the fourth offset byte.
    let wide = noise(23, 0x0100_000a);
    let mut stream = varint(len64(&wide));
    stream.extend(varint(10));
    stream.extend([0x98, 0x01, 0x0a]);
    let (result, out) = apply(&wide, &stream, 10);
    result.unwrap();
    assert_eq!(out, wide[0x0100_0000..]);
}

fn encode(base: &[u8], target: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_delta(
        &mut Cursor::new(base.to_vec()),
        len64(base),
        &mut Cursor::new(target.to_vec()),
        len64(target),
        &mut out,
    )
    .unwrap();
    out
}

#[test]
fn encoder_emits_the_canonical_git_instruction_bytes() {
    // Prefix copy, literal middle, suffix copy.
    assert_eq!(
        encode(b"head-OLD-tail", b"head-NEW!-tail"),
        [13, 14, 0x90, 5, 4, b'N', b'E', b'W', b'!', 0x91, 8, 5]
    );
    // No common suffix: prefix copy, then the literal tail.
    assert_eq!(
        encode(b"0123456789ABCDEF", b"0123456789XYZ"),
        [16, 13, 0x90, 10, 3, b'X', b'Y', b'Z']
    );
    // Identical 200000-byte objects: copies split at 0x10000 as Git does.
    let data = noise(20, 200_000);
    assert_eq!(
        encode(&data, &data),
        [
            0xc0, 0x9a, 0x0c, 0xc0, 0x9a, 0x0c, // both sizes
            0x80, // 0x10000 at 0 (zero size field)
            0x84, 0x01, // 0x10000 at 0x10000
            0x84, 0x02, // 0x10000 at 0x20000
            0xb4, 0x03, 0x40, 0x0d, // 3392 at 0x30000
        ]
    );
    // Literals are cut at 127 bytes per insert: 127 + 127 + 46.
    let stream = encode(b"", &[7_u8; 300]);
    assert_eq!(stream.len(), 3 + 3 + 300);
    assert_eq!(&stream[..3], &[0x00, 0xac, 0x02]);
    assert_eq!(stream[3], 127);
    assert_eq!(stream[3 + 128], 127);
    assert_eq!(stream[3 + 256], 46);
}

#[test]
fn encoder_round_trips_through_the_applier_for_edge_shapes() {
    let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (Vec::new(), Vec::new()),
        (Vec::new(), b"only literal".to_vec()),
        (b"only base".to_vec(), Vec::new()),
        (b"same".to_vec(), b"same".to_vec()),
        (b"abcabc".to_vec(), b"abcXabc".to_vec()),
        (noise(21, 70_000), noise(22, 70_000)),
        (
            b"x".repeat(200_000),
            [b"x".repeat(100_000), b"y".to_vec(), b"x".repeat(100_000)].concat(),
        ),
    ];
    for (base, target) in cases {
        let delta = encode(&base, &target);
        let (result, out) = apply(&base, &delta, len64(&target));
        result.unwrap();
        assert_eq!(out, target);
    }
}

#[test]
fn copy_spans_shrink_to_encodable_offsets_instead_of_failing() {
    let limit = u64::from(u32::MAX);
    assert_eq!(clamp_copy_spans(100, 10, 20), (10, 20));
    // Prefix pieces all start below 2^32 when the span is capped there.
    assert_eq!(clamp_copy_spans(5 << 32, 1 << 40, 0), (1 << 32, 0));
    // A suffix whose last piece would start above u32::MAX is dropped...
    assert_eq!(clamp_copy_spans(5 << 32, 10, 10), (10, 0));
    // ...but one whose last piece starts exactly at u32::MAX stays.
    assert_eq!(clamp_copy_spans(limit + 1, 7, 1), (7, 1));
    // One byte more of suffix pushes the last piece to 2^32 + 65535.
    assert_eq!(clamp_copy_spans((1 << 32) + 65_536, 7, 65_537), (7, 0));
}

#[test]
fn encoded_sink_refuses_u32_overflow_and_the_keep_threshold_before_writing() {
    let root = TempRoot::new("sink");
    let budget = default_budget();
    let mut sink = EncodedSink::new(SpoolWriter::new(&budget, root.path()), None);
    sink.preset_written(u64::from(u32::MAX) - 1);
    let err = sink.write(&[1, 2]).unwrap_err();
    match classify_sink(err) {
        Failure::Store(StoreError::Capacity(_)) => {}
        Failure::Store(other) => panic!("expected capacity, got {other:?}"),
        Failure::OverThreshold => panic!("expected capacity"),
    }

    let mut bounded = EncodedSink::new(SpoolWriter::new(&budget, root.path()), Some(4));
    bounded.write_all(&[1, 2, 3, 4]).unwrap();
    let err = bounded.write(&[5]).unwrap_err();
    assert!(matches!(classify_sink(err), Failure::OverThreshold));
}

#[test]
fn spools_read_seek_and_view_independently_in_memory_and_on_disk() {
    let root = TempRoot::new("cursor");
    for threshold in [1 << 20, 16] {
        let budget = budget_with(limits(threshold));
        let data: Vec<u8> = (0..=255).collect();
        let mut spool = spool_of(&budget, root.path(), &data);
        assert_eq!(spool.len(), 256);
        assert!(!spool.is_empty());
        let mut first = [0_u8; 4];
        spool.read_exact(&mut first).unwrap();
        assert_eq!(first, [0, 1, 2, 3]);
        assert_eq!(spool.seek(SeekFrom::End(-2)).unwrap(), 254);
        let mut tail = Vec::new();
        spool.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, [254, 255]);
        assert_eq!(spool.seek(SeekFrom::Current(-6)).unwrap(), 250);
        assert!(spool.seek(SeekFrom::Current(-1000)).is_err());
        spool.seek(SeekFrom::Start(300)).unwrap();
        assert_eq!(
            spool.read(&mut first).unwrap(),
            0,
            "reads past the end are empty"
        );

        let mut left = spool.view();
        let mut right = spool.view();
        left.seek(SeekFrom::Start(10)).unwrap();
        let mut a = [0_u8; 3];
        let mut b = [0_u8; 3];
        left.read_exact(&mut a).unwrap();
        right.read_exact(&mut b).unwrap();
        assert_eq!((a, b), ([10, 11, 12], [0, 1, 2]));
        assert_eq!(left.len(), 256);
    }
}

#[test]
fn failed_spool_writer_stays_failed_and_releases() {
    let root = TempRoot::new("failed");
    let budget = budget_with(BudgetLimits {
        max_scratch_per_store: 100,
        memory_spool_threshold: 8,
        ..BudgetLimits::default()
    });
    let mut writer = SpoolWriter::new(&budget, root.path());
    writer.append(&[0; 4]).unwrap();
    let err = writer.append(&[0; 200]).unwrap_err();
    assert!(matches!(err, StoreError::Limit(_)), "{err:?}");
    assert!(matches!(
        writer.append(&[1]).unwrap_err(),
        StoreError::Invalid(_)
    ));
    assert!(matches!(
        writer.finish().unwrap_err(),
        StoreError::Invalid(_)
    ));
    assert_eq!(budget.in_use(), (0, 0));
    assert!(root.scratch_entries().is_empty());
}
