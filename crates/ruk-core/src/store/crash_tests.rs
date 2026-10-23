//! Real-process crash proofs for the durable store publication boundaries.
//!
//! Every fault point is exercised by killing an actual child process at the
//! requested boundary and then proving what the files and metadata hold
//! afterwards: an acknowledged publication is present after reopen, an
//! uncommitted publication is all-or-nothing, and committed corruption
//! refuses service. No fake backend, no mocked store, and the parent process
//! environment is never modified.
//!
//! # What a process kill proves
//!
//! The child leaves through `std::process::exit`: no destructors, no
//! buffered flushes, no cleanup, but the kernel keeps every completed
//! `write` in its page cache and the parent reads that cache. These tests
//! therefore prove *hook ordering and the resulting state*: which bytes and
//! metadata rows exist once the named step has returned, and that recovery
//! and later publications behave correctly from that state. They do not
//! prove power-loss persistence. Whether an `fsync` ran, succeeded, or was
//! ordered before the commit is invisible here; `after_append` and
//! `after_segment_sync`, for example, leave identical observable state.
//! Fsync ordering is a code-inspection claim, and power-loss persistence
//! stays unproven until it is exercised on storage that drops unsynced
//! writes.
//!
//! # Hook contract (frozen with StoreIntegration)
//!
//! Integration calls [`crash_at`] from `#[cfg(test)]` blocks in
//! `publish` and recovery, immediately after the named step completes and
//! before the next durability step begins:
//!
//! | Label | Fires |
//! |---|---|
//! | `after_append` | after the last record byte, and any seal footer the batch wrote, is written, before any fsync |
//! | `after_segment_sync` | after fsync of every touched segment (sealed ones included), before directory sync |
//! | `after_directory_sync` | after fsync of the segments directory, before metadata commit |
//! | `after_metadata_commit` | first statement after the redb Immediate commit returns |
//! | `capacity_pending_persisted` | after the capacity-ledger pending commit, before the publication transaction opens |
//! | `before_ack` | last statement inside `publish`, after in-memory bookkeeping, immediately before `Ok` returns |
//! | `recovery_after_tail_truncate` | after truncating an uncommitted active tail, before the next segment is examined |
//! | `recovery_after_detect_corrupt` | after the quarantine latch is set on committed corruption |
//!
//! `after_ack` is deliberately NOT a hook inside `publish`: a point inside
//! the library would only show the post-commit state, not that the caller
//! observed the acknowledgement. The acknowledgement boundary is child-side
//! and owned by this module: after `publish` returns `Ok`, the child routine
//! writes an ack marker file (file fsync plus directory fsync through the
//! store's own durability helpers) and *then* calls
//! [`crash_at`]`("after_ack")`. A kill at `after_ack` therefore shows the
//! acknowledged outcome is present after reopen; the presence or absence of
//! the marker distinguishes acknowledged success from pre-acknowledgement
//! termination at every other point.
//!
//! [`crash_at`] is a no-op unless the process was spawned with
//! [`CRASH_ENV`] set, so hooks are inert in the parent and in normal runs.
//!
//! # Process model
//!
//! The non-ignored tests in this file are the parents. Each spawns a child
//! by re-executing the *current test executable* with the ignored
//! [`CHILD_ENTRY`] dispatcher selected (`store::crash_tests::store_crash_child
//! --exact --ignored --nocapture`; libtest's `--exact` compares the full
//! module path, so the bare function name would match zero tests) and the
//! full request carried in child-only
//! environment variables set through `std::process::Command::env`: the
//! parent environment is never read back, written, or mutated. The child
//! runs the requested routine against the real store and real filesystem,
//! and the fault schedule kills it with [`crash_exit_code`] at the requested
//! boundary. Exit statuses fully disambiguate the outcome:
//!
//! | Status | Meaning |
//! |---|---|
//! | [`EXIT_CRASH`] (70) | child terminated at the requested fault point |
//! | [`EXIT_COMPLETE`] (0) | routine completed without a pending fault |
//! | [`EXIT_ARGS`] (1) | bad child request |
//! | [`EXIT_STORE`] (2) | unexpected store or marker error |
//! | [`EXIT_ASSERT`] (3) | post-condition mismatch |
//! | [`EXIT_EXPECTED_CORRUPT`] (71) | fresh process observed the required `E_CORRUPT` refusal |
//! | [`EXIT_UNEXPECTED_OPEN`] (72) | fresh process opened a store that must refuse service |
//!
//! A crash at [`EXIT_CRASH`] proves nothing after that line ran; a child
//! panic (bug) exits 101 instead and fails the parent assertion.
//!
//! # Seal-boundary scenario
//!
//! `publish_seal_boundary` crosses the real [`SEGMENT_TARGET_BYTES`]
//! (256 MiB) with real files; there is no lowered target and no
//! configuration knob. It publishes a small acknowledged object, then one
//! incompressible blob larger than the target, streamed from a
//! position-deterministic generator so no payload is held in memory. That
//! one publication seals twice: the roll seals the committed first segment
//! (footer past its committed extent) and the oversized record seals its own
//! dedicated segment. A kill at `after_directory_sync@2` leaves an
//! uncommitted footer tail plus a sealed orphan segment no manifest names; a
//! kill at `after_metadata_commit@2` leaves both manifests sealed. Each run
//! writes about 512 MiB of scratch and segment files, plus a 256 MiB read
//! spool in the verifying parent.
//!
//! # Fault schedule grammar
//!
//! One comma-separated list in [`CRASH_ENV`], evaluated at every hook call:
//!
//! ```text
//! point          act on the first occurrence of `point`
//! point@N        act on the Nth (1-based) occurrence of `point`
//! ```
//!
//! Occurrences are counted per process across every publication, so
//! `after_metadata_commit@2` kills the second publication's commit inside
//! one child. Unknown labels never match: hook drift surfaces as a clean
//! [`EXIT_COMPLETE`] child and a failing parent assertion, never as a crash
//! at the wrong place.

use std::fs::File;
use std::io::{self, Read, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::conflict::{ConflictRecord, ConflictRecordInput, Signature, TzOffset};
use crate::ids::{HashKind, Oid};
use crate::store::capacity::{PendingReservation, ReservationState};
use crate::store::metadata::Metadata;
use crate::store::segment::{FOOTER_LEN, SEAL_MAGIC, SEGMENT_TARGET_BYTES, segment_file_name};
use crate::store::types::{
    FactExpectation, FactMutation, FactTable, ObjectKind, ObjectLocation, PreparedObject,
    SegmentManifest,
};
use crate::store::{
    EventContext, EventSource, META_FILE, PreparationBudget, SEGMENTS_DIR, Store, StoreError,
};

// ---------------------------------------------------------------------------
// Child process contract
// ---------------------------------------------------------------------------

/// Environment variable carrying the child fault schedule. Set only on
/// spawned children, never on the parent.
pub(crate) const CRASH_ENV: &str = "RUK_CRASH_AT";

/// Environment variable naming the child routine.
const CHILD_REQUEST_ENV: &str = "RUK_STORE_CRASH_REQUEST";

/// Environment variable carrying [`UNIT_SEPARATOR_STR`]-joined routine
/// arguments: `<store root> <hash kind> [routine-specific...]`.
const CHILD_ARGS_ENV: &str = "RUK_STORE_CRASH_ARGS";

/// The exact ignored child entrypoint invoked by the parent tests: the full
/// libtest path of [`store_crash_child`] (crate name excluded), which is what
/// `--exact` compares against.
const CHILD_ENTRY: &str = "store::crash_tests::store_crash_child";

/// Field separator inside [`CHILD_ARGS_ENV`].
const UNIT_SEPARATOR_STR: &str = "\u{1f}";
const UNIT_SEPARATOR: char = '\u{1f}';

/// Exit status of a child that reached its requested fault point.
const EXIT_CRASH: i32 = 70;
/// Child routine completed normally.
const EXIT_COMPLETE: i32 = 0;
/// Bad child request (unknown routine, missing or malformed arguments).
const EXIT_ARGS: i32 = 1;
/// Unexpected store or marker error inside a child routine.
const EXIT_STORE: i32 = 2;
/// Child post-condition mismatch.
const EXIT_ASSERT: i32 = 3;
/// Fresh process observed the required `E_CORRUPT` refusal.
const EXIT_EXPECTED_CORRUPT: i32 = 71;
/// Fresh process opened a store that must refuse service.
const EXIT_UNEXPECTED_OPEN: i32 = 72;

/// The parent-asserted exit status of a child killed at a fault point.
pub(crate) fn crash_exit_code() -> i32 {
    EXIT_CRASH
}

/// One schedule entry: a point label, which occurrence acts, and how many
/// occurrences have been observed.
struct Arm {
    point: String,
    occurrence: u32,
    hits: AtomicU32,
}

/// The parsed schedule. Empty in the parent (no [`CRASH_ENV`]), so hooks are
/// inert there; the initializer is the single parse of the child env.
static SCHEDULE: LazyLock<Vec<Arm>> =
    LazyLock::new(|| parse_schedule(&std::env::var(CRASH_ENV).unwrap_or_default()));

/// Parses the schedule grammar (see module docs).
fn parse_schedule(spec: &str) -> Vec<Arm> {
    let mut arms = Vec::new();
    for item in spec.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (point, occurrence) = match item.split_once('@') {
            Some((point, count)) => match count.parse::<u32>() {
                Ok(count) if count >= 1 => (point, count),
                _ => continue,
            },
            None => (item, 1),
        };
        arms.push(Arm {
            point: point.to_owned(),
            occurrence,
            hits: AtomicU32::new(0),
        });
    }
    arms
}

/// Applies the fault schedule to one observed boundary occurrence.
///
/// Called by Integration from `#[cfg(test)]` publication and recovery code,
/// and by the child routines below at the child-side `after_ack` boundary.
/// Without [`CRASH_ENV`] this returns immediately. In a child, the matching
/// arm terminates the whole process with [`crash_exit_code`]: no unwinding,
/// no buffer flushes, no cleanup, so the on-disk state is exactly the
/// durability frontier of the named boundary.
pub(crate) fn crash_at(point: &str) {
    let arms = &*SCHEDULE;
    if arms.is_empty() {
        return;
    }
    for arm in arms {
        if arm.point != point {
            continue;
        }
        let hits = arm.hits.fetch_add(1, Ordering::Relaxed) + 1;
        if hits == arm.occurrence {
            std::process::exit(crash_exit_code());
        }
    }
}

/// The ignored child dispatcher. The crash-test parent tests are its only
/// legitimate callers; invoked any other way (including `cargo test
/// -- --ignored`) it fails loudly because the required child environment is
/// absent.
#[test]
#[ignore = "crash-test child dispatcher; the parent tests spawn it as a subprocess"]
fn store_crash_child() {
    let Ok(routine) = std::env::var(CHILD_REQUEST_ENV) else {
        panic!(
            "{CHILD_ENTRY} requires {CHILD_REQUEST_ENV} and {CHILD_ARGS_ENV}; \
             the crash-test parent tests are its only callers"
        );
    };
    let args: Vec<String> = std::env::var(CHILD_ARGS_ENV)
        .unwrap_or_default()
        .split(UNIT_SEPARATOR)
        .map(str::to_owned)
        .collect();
    let code = dispatch_child(&routine, &args);
    if code != EXIT_COMPLETE {
        std::process::exit(code);
    }
}

/// Routes a child request to its routine and returns its exit status.
fn dispatch_child(routine: &str, args: &[String]) -> i32 {
    match routine {
        "publish_blob_fact" => child_publish_blob_fact(args),
        "publish_capacity_probe" => child_publish_capacity_probe(args),
        "publish_two_serial" => child_publish_two_serial(args),
        "publish_two_racing" => child_publish_two_racing(args),
        "publish_mixed_conflict" => child_publish_mixed_conflict(args),
        "publish_seal_boundary" => child_publish_seal_boundary(args),
        "open_expect_corrupt" => child_open_expect_corrupt(args),
        "open_assert_state" => child_open_assert_state(args),
        "open_recovering" => child_open_recovering(args),
        _ => EXIT_ARGS,
    }
}

// ---------------------------------------------------------------------------
// Shared scenario data: parent and child derive identical expectations
// from these constants, so no expected digest is ever hardcoded.
// ---------------------------------------------------------------------------

/// Publication A's payload: the acknowledged-survival probe.
const BLOB_A: &[u8] = b"ruk crash proof: acknowledged bytes must survive process death\n";
/// Publication B's payload: the uncommitted-tail probe.
const BLOB_B: &[u8] = b"ruk crash proof: uncommitted tail bytes must truncate cleanly\n";
/// Concurrent preparation payloads (published as one atomic set).
const C1_PAYLOADS: [&[u8]; 4] = [
    b"ruk concurrent preparation payload zero\n",
    b"ruk concurrent preparation payload one\n",
    b"ruk concurrent preparation payload two\n",
    b"ruk concurrent preparation payload three\n",
];
/// Fact keys for publications A, B, the conflict record, claims, and the
/// one-batch duplicate probe.
const FACT_KEY_A: &[u8] = b"refs/heads/ruk-crash-a";
const FACT_KEY_B: &[u8] = b"refs/heads/ruk-crash-b";
const FACT_KEY_CONFLICT: &[u8] = b"refs/heads/ruk-crash-conflict";
const FACT_KEY_SEALED: &[u8] = b"refs/heads/ruk-crash-sealed";
const FACT_KEY_DUP: &[u8] = b"refs/heads/ruk-crash-dup";
const CLAIM_KEY: &[u8] = b"claim/ruk-crash-proof";
/// Unknown paths a hostile or crashed prior process may have left behind.
const UNKNOWN_SCRATCH_BYTES: &[u8] = b"unknown journal bytes that must survive recovery";
const UNKNOWN_SEGMENT_BYTES: &[u8] = b"unknown segment bytes that must survive recovery";

/// Seed of the oversized seal-boundary payload.
const SEAL_SEED: u64 = 0x5EA1_B0DA_C0DE_D00D;
/// Decoded length of the oversized seal-boundary payload: strictly above the
/// real segment target, so the record needs a dedicated segment whatever the
/// encoding adds or saves. The payload is incompressible, so the encoded
/// record is at least this long; the parent asserts the sealed record
/// extent really exceeds [`SEGMENT_TARGET_BYTES`].
const SEAL_BLOB_LEN: u64 = SEGMENT_TARGET_BYTES + 64 * 1024;
/// Chunk for every streaming pass over the oversized payload or a segment.
const STREAM_CHUNK: usize = 64 * 1024;
/// Object locator rows read per metadata page by [`committed_rows`]; the
/// scenario stores hold far fewer.
const OBJECT_PAGE: usize = 16;

/// A byte length as the store's declared `u64` length. Lossless on every
/// supported target; fails loudly instead of truncating if that ever changes.
fn len_u64(bytes: &[u8]) -> u64 {
    usize_u64(bytes.len())
}

/// A `usize` as `u64`, failing loudly instead of truncating.
fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).expect("usize fits in u64")
}

/// Deterministic incompressible byte stream of an exact length, generated on
/// the fly. Byte `p` depends only on `(seed, p)`, so the stream is identical
/// whatever read sizes consume it, and a verifier can regenerate it
/// independently without holding the payload.
struct NoiseStream {
    seed: u64,
    pos: u64,
    len: u64,
}

impl NoiseStream {
    fn new(seed: u64, len: u64) -> Self {
        Self { seed, pos: 0, len }
    }

    /// The SplitMix64 output for 8-byte lane `index`.
    fn word(&self, index: u64) -> u64 {
        let step = index.wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut z = self.seed.wrapping_add(step);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl Read for NoiseStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.len - self.pos;
        let want = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let mut done = 0;
        while done < want {
            let lane = usize::try_from(self.pos & 7).unwrap_or_default();
            let word = self.word(self.pos >> 3).to_le_bytes();
            let take = (8 - lane).min(want - done);
            buf[done..done + take].copy_from_slice(&word[lane..lane + take]);
            done += take;
            self.pos += usize_u64(take);
        }
        Ok(done)
    }
}

/// Streams `source` against the first `len` bytes of the seeded noise
/// stream in bounded chunks and reports whether they are identical and the
/// source ends exactly there.
fn stream_matches_noise(source: &mut impl Read, seed: u64, len: u64) -> io::Result<bool> {
    let mut expected = NoiseStream::new(seed, len);
    let mut got = vec![0_u8; STREAM_CHUNK];
    let mut want = vec![0_u8; STREAM_CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let take = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(STREAM_CHUNK);
        source.read_exact(&mut got[..take])?;
        expected.read_exact(&mut want[..take])?;
        if got[..take] != want[..take] {
            return Ok(false);
        }
        remaining -= usize_u64(take);
    }
    let mut probe = [0_u8; 1];
    Ok(source.read(&mut probe)? == 0)
}

/// The canonical Git blob identity of the oversized seal-boundary payload,
/// computed here from the generator alone, independent of the store.
fn noise_blob_oid(kind: HashKind) -> Oid {
    let mut hasher = gix_hash::hasher(kind.gix());
    hasher.update(format!("blob {SEAL_BLOB_LEN}\0").as_bytes());
    let mut source = NoiseStream::new(SEAL_SEED, SEAL_BLOB_LEN);
    let mut chunk = vec![0_u8; STREAM_CHUNK];
    loop {
        let read = source.read(&mut chunk).expect("generate noise");
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    Oid::from(hasher.try_finalize().expect("oversized blob hash"))
}

/// The canonical Git identity of a blob payload under `kind`.
fn blob_oid(kind: HashKind, payload: &[u8]) -> Oid {
    kind.hash_git_object("blob", payload)
        .expect("canonical blob hash")
}

/// The deterministic framed conflict-v1 record used by the mixed-kind probe.
fn conflict_frame(kind: HashKind) -> Vec<u8> {
    let empty_tree = kind.hash_git_object("tree", b"").expect("empty tree");
    let signature = Signature {
        name: "Ruk Crash Proof".into(),
        email: "crash@ruk.test".into(),
        timestamp: 1_700_000_000,
        offset: TzOffset::UTC,
    };
    let input = ConflictRecordInput {
        trees: vec![empty_tree],
        parents: Vec::new(),
        author: signature.clone(),
        committer: signature,
        extra_headers: Vec::new(),
        message: "ruk crash proof conflict".into(),
    };
    ConflictRecord::from_input(&input, kind)
        .expect("valid conflict record")
        .encode()
}

/// Builds one fact mutation over an object identity or raw value.
fn fact_mutation(
    table: FactTable,
    key: &[u8],
    expected: FactExpectation,
    value: Option<&[u8]>,
) -> FactMutation {
    FactMutation {
        table,
        key: key.to_vec(),
        expected,
        value: value.map(<[u8]>::to_vec),
    }
}

/// The shared budget for every store opened by these tests.
fn test_budget() -> Arc<PreparationBudget> {
    Arc::new(PreparationBudget::reference_defaults())
}

// ---------------------------------------------------------------------------
// Acknowledgement markers
//
// The child-side acknowledgement boundary: after `publish` returns Ok, the
// child writes a marker file (file fsync plus directory fsync via the
// store's own durability helpers) before calling the child-side
// `after_ack` hook. Marker presence in the parent distinguishes an
// acknowledged publication from a kill before the acknowledgement; it says
// nothing about whether those fsyncs reached stable storage.
// ---------------------------------------------------------------------------

/// The acknowledgement directory for a store root: a sibling of the root,
/// never inside the store, so recovery and unknown-path semantics stay clean.
fn ack_dir(root: &Path) -> PathBuf {
    PathBuf::from(format!("{}-ack", root.display()))
}

/// The marker path for one acknowledged publication name.
fn ack_marker(root: &Path, name: &str) -> PathBuf {
    ack_dir(root).join(format!("{name}.marker"))
}

/// Records one acknowledgement marker. Uses the store's own durability
/// primitives so the acknowledgement rides the exact machinery under test:
/// `create_file_published` publishes the namespace entry on every platform
/// (POSIX create-new, Windows MoveFileExW publication), `sync_file` flushes
/// the marker bytes, and on POSIX `sync_dir` then flushes the directory
/// entry. Observers in this module only see the marker's presence, never
/// whether the flushes held.
fn write_ack_marker(dir: &Path, name: &str) -> Result<(), StoreError> {
    let path = dir.join(format!("{name}.marker"));
    let mut file = crate::store::durability::create_file_published(&path)?;
    file.write_all(b"1").map_err(StoreError::Io)?;
    crate::store::durability::sync_file(&file)?;
    #[cfg(unix)]
    crate::store::durability::sync_dir(dir)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Child routines
// ---------------------------------------------------------------------------

/// Parses `<root> <kind>` from the joined child arguments.
fn store_args(args: &[String]) -> Result<(PathBuf, HashKind), i32> {
    let Some(root) = args.first() else {
        return Err(EXIT_ARGS);
    };
    let Some(kind_text) = args.get(1) else {
        return Err(EXIT_ARGS);
    };
    let kind = HashKind::from_str(kind_text).map_err(|_| EXIT_ARGS)?;
    Ok((PathBuf::from(root), kind))
}

/// The child-side acknowledgement sequence: record the marker, then apply
/// the child-side `after_ack` fault point. Every publishing routine ends
/// with this.
fn acknowledge(root: &Path, name: &str) -> i32 {
    if write_ack_marker(&ack_dir(root), name).is_err() {
        return EXIT_STORE;
    }
    crash_at("after_ack");
    EXIT_COMPLETE
}

/// Creates a fresh store, prepares [`BLOB_A`], and publishes it with one
/// `refs` fact row. The fault schedule selects the kill boundary.
fn child_publish_blob_fact(args: &[String]) -> i32 {
    let Ok((root, kind)) = store_args(args) else {
        return EXIT_ARGS;
    };
    let Ok(store) = Store::create(&root, kind, test_budget()) else {
        return EXIT_STORE;
    };
    let Ok(prepared) = store.prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None) else {
        return EXIT_STORE;
    };
    if prepared.oid() != blob_oid(kind, BLOB_A) {
        return EXIT_ASSERT;
    }
    let oid = prepared.oid();
    let facts = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_A,
        FactExpectation::Absent,
        Some(oid.as_bytes()),
    )];
    match store.publish(
        vec![prepared],
        &facts,
        EventSource::LocalPush,
        &EventContext::default(),
    ) {
        Ok(_) => acknowledge(&root, "a"),
        Err(_) => EXIT_STORE,
    }
}

/// Publishes [`BLOB_A`] with one `refs` fact row for the capacity-ledger
/// probe. The `capacity_pending_persisted` schedule kills the child after
/// the pending commit but before any append, leaving a durable `Pending`
/// row and no committed bytes.
fn child_publish_capacity_probe(args: &[String]) -> i32 {
    let Ok((root, kind)) = store_args(args) else {
        return EXIT_ARGS;
    };
    let Ok(store) = Store::create(&root, kind, test_budget()) else {
        return EXIT_STORE;
    };
    let Ok(prepared) = store.prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None) else {
        return EXIT_STORE;
    };
    if prepared.oid() != blob_oid(kind, BLOB_A) {
        return EXIT_ASSERT;
    }
    let oid = prepared.oid();
    let facts = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_A,
        FactExpectation::Absent,
        Some(oid.as_bytes()),
    )];
    match store.publish(
        vec![prepared],
        &facts,
        EventSource::LocalPush,
        &EventContext::default(),
    ) {
        Ok(_) => acknowledge(&root, "a"),
        Err(_) => EXIT_STORE,
    }
}

/// Publishes A (acknowledged) and then B in one child; the schedule kills
/// the second publication while A stays acknowledged. A kill at a
/// pre-commit boundary (`after_directory_sync@2`) leaves B's records on
/// disk beyond A's committed extent; a kill at `after_metadata_commit@2`
/// would instead leave B committed and no tail at all.
fn child_publish_two_serial(args: &[String]) -> i32 {
    let Ok((root, kind)) = store_args(args) else {
        return EXIT_ARGS;
    };
    let Ok(store) = Store::create(&root, kind, test_budget()) else {
        return EXIT_STORE;
    };
    let Ok(prepared_a) = store.prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None) else {
        return EXIT_STORE;
    };
    let oid_a = prepared_a.oid();
    let facts_a = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_A,
        FactExpectation::Absent,
        Some(oid_a.as_bytes()),
    )];
    match store.publish(
        vec![prepared_a],
        &facts_a,
        EventSource::LocalPush,
        &EventContext::default(),
    ) {
        Ok(_) => {}
        Err(_) => return EXIT_STORE,
    }
    if write_ack_marker(&ack_dir(&root), "a").is_err() {
        return EXIT_STORE;
    }
    crash_at("after_ack");
    let Ok(prepared_b) = store.prepare(ObjectKind::Blob, len_u64(BLOB_B), BLOB_B, None) else {
        return EXIT_STORE;
    };
    let oid_b = prepared_b.oid();
    let facts_b = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_B,
        FactExpectation::Absent,
        Some(oid_b.as_bytes()),
    )];
    match store.publish(
        vec![prepared_b],
        &facts_b,
        EventSource::LocalPush,
        &EventContext::default(),
    ) {
        Ok(_) => acknowledge(&root, "b"),
        Err(_) => EXIT_STORE,
    }
}

/// Two threads race one publication each through the serialized writer.
/// Each thread records its own ack marker after its publish returns and
/// only then applies the child-side `after_ack` fault point, so the
/// per-process occurrence counter orders the two acknowledgements.
fn child_publish_two_racing(args: &[String]) -> i32 {
    let Ok((root, kind)) = store_args(args) else {
        return EXIT_ARGS;
    };
    let Ok(store) = Store::create(&root, kind, test_budget()) else {
        return EXIT_STORE;
    };
    let oid_a = blob_oid(kind, BLOB_A);
    let oid_b = blob_oid(kind, BLOB_B);
    let prepared_a = match store.prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None) {
        Ok(prepared) if prepared.oid() == oid_a => prepared,
        _ => return EXIT_ASSERT,
    };
    let prepared_b = match store.prepare(ObjectKind::Blob, len_u64(BLOB_B), BLOB_B, None) {
        Ok(prepared) if prepared.oid() == oid_b => prepared,
        _ => return EXIT_ASSERT,
    };
    let ack_dir: &Path = &ack_dir(&root);
    let outcomes: Vec<i32> = std::thread::scope(|scope| {
        let store = &store;
        let first = scope.spawn(move || {
            let facts = [fact_mutation(
                FactTable::Refs,
                FACT_KEY_A,
                FactExpectation::Absent,
                Some(oid_a.as_bytes()),
            )];
            match store.publish(
                vec![prepared_a],
                &facts,
                EventSource::LocalPush,
                &EventContext::default(),
            ) {
                Ok(_) => {
                    if write_ack_marker(ack_dir, "a").is_err() {
                        EXIT_STORE
                    } else {
                        crash_at("after_ack");
                        EXIT_COMPLETE
                    }
                }
                Err(_) => EXIT_STORE,
            }
        });
        let second = scope.spawn(move || {
            let facts = [fact_mutation(
                FactTable::Refs,
                FACT_KEY_B,
                FactExpectation::Absent,
                Some(oid_b.as_bytes()),
            )];
            match store.publish(
                vec![prepared_b],
                &facts,
                EventSource::LocalPush,
                &EventContext::default(),
            ) {
                Ok(_) => {
                    if write_ack_marker(ack_dir, "b").is_err() {
                        EXIT_STORE
                    } else {
                        crash_at("after_ack");
                        EXIT_COMPLETE
                    }
                }
                Err(_) => EXIT_STORE,
            }
        });
        vec![
            first.join().expect("publish thread A"),
            second.join().expect("publish thread B"),
        ]
    });
    if outcomes.into_iter().eq([EXIT_COMPLETE, EXIT_COMPLETE]) {
        EXIT_COMPLETE
    } else {
        EXIT_STORE
    }
}

/// Publishes a Git blob and a native conflict record in one atomic set.
fn child_publish_mixed_conflict(args: &[String]) -> i32 {
    let Ok((root, kind)) = store_args(args) else {
        return EXIT_ARGS;
    };
    let Ok(store) = Store::create(&root, kind, test_budget()) else {
        return EXIT_STORE;
    };
    let framed = conflict_frame(kind);
    let Ok(conflict_oid) = kind.hash_parts(&[framed.as_slice()]) else {
        return EXIT_ASSERT;
    };
    let prepared_blob = match store.prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None) {
        Ok(prepared) if prepared.oid() == blob_oid(kind, BLOB_A) => prepared,
        _ => return EXIT_ASSERT,
    };
    let prepared_conflict = match store.prepare(
        ObjectKind::Conflict,
        len_u64(&framed),
        framed.as_slice(),
        None,
    ) {
        Ok(prepared) if prepared.oid() == conflict_oid => prepared,
        _ => return EXIT_ASSERT,
    };
    let facts = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_CONFLICT,
        FactExpectation::Absent,
        Some(conflict_oid.as_bytes()),
    )];
    match store.publish(
        vec![prepared_blob, prepared_conflict],
        &facts,
        EventSource::LocalPush,
        &EventContext::default(),
    ) {
        Ok(_) => acknowledge(&root, "mixed"),
        Err(_) => EXIT_STORE,
    }
}

/// Publishes a small acknowledged blob, then one incompressible blob larger
/// than the real segment target, streamed from [`NoiseStream`]. The second
/// publication seals the committed first segment (roll) and its own
/// dedicated segment (oversized record) before one metadata commit; the
/// schedule selects the kill boundary (`@2` addresses that publication).
fn child_publish_seal_boundary(args: &[String]) -> i32 {
    let Ok((root, kind)) = store_args(args) else {
        return EXIT_ARGS;
    };
    let Ok(store) = Store::create(&root, kind, test_budget()) else {
        return EXIT_STORE;
    };
    let Ok(prepared_a) = store.prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None) else {
        return EXIT_STORE;
    };
    let oid_a = prepared_a.oid();
    let facts_a = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_A,
        FactExpectation::Absent,
        Some(oid_a.as_bytes()),
    )];
    if store
        .publish(
            vec![prepared_a],
            &facts_a,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .is_err()
    {
        return EXIT_STORE;
    }
    let code = acknowledge(&root, "a");
    if code != EXIT_COMPLETE {
        return code;
    }
    let noise = NoiseStream::new(SEAL_SEED, SEAL_BLOB_LEN);
    let Ok(prepared) = store.prepare(ObjectKind::Blob, SEAL_BLOB_LEN, noise, None) else {
        return EXIT_STORE;
    };
    let oid = prepared.oid();
    let facts = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_SEALED,
        FactExpectation::Absent,
        Some(oid.as_bytes()),
    )];
    match store.publish(
        vec![prepared],
        &facts,
        EventSource::LocalPush,
        &EventContext::default(),
    ) {
        Ok(_) => acknowledge(&root, "sealed"),
        Err(_) => EXIT_STORE,
    }
}

/// Opens a store that must refuse service with `E_CORRUPT`.
fn child_open_expect_corrupt(args: &[String]) -> i32 {
    let Ok((root, _kind)) = store_args(args) else {
        return EXIT_ARGS;
    };
    match Store::open(&root, test_budget()) {
        Ok(_) => EXIT_UNEXPECTED_OPEN,
        Err(StoreError::Corrupt(_)) => EXIT_EXPECTED_CORRUPT,
        Err(_) => EXIT_STORE,
    }
}

/// Opens a store and lets the recovery hooks act; used to kill a fresh
/// process exactly at a recovery boundary.
fn child_open_recovering(args: &[String]) -> i32 {
    let Ok((root, _kind)) = store_args(args) else {
        return EXIT_ARGS;
    };
    match Store::open(&root, test_budget()) {
        Ok(_) => EXIT_COMPLETE,
        Err(_) => EXIT_STORE,
    }
}

/// Opens a store and asserts one named post-crash state (see
/// [`open_assert_spec`]).
fn child_open_assert_state(args: &[String]) -> i32 {
    let Ok((root, kind)) = store_args(args) else {
        return EXIT_ARGS;
    };
    let Some(spec) = args.get(2).map(String::as_str) else {
        return EXIT_ARGS;
    };
    let Ok(store) = Store::open(&root, test_budget()) else {
        return EXIT_STORE;
    };
    match open_assert_spec(&store, kind, spec) {
        Ok(true) => EXIT_COMPLETE,
        Ok(false) => EXIT_ASSERT,
        Err(code) => code,
    }
}

/// Asserts the named surviving state and returns whether it held.
/// `Err(EXIT_ARGS)` marks an unknown spec; other errors are store failures.
fn open_assert_spec(store: &Store, kind: HashKind, spec: &str) -> Result<bool, i32> {
    let oid_a = blob_oid(kind, BLOB_A);
    let oid_b = blob_oid(kind, BLOB_B);
    match spec {
        "a" => {
            assert_bytes(store, oid_a, ObjectKind::Blob, BLOB_A)?;
            fact_is(store, FactTable::Refs, FACT_KEY_A, Some(oid_a.as_bytes()))
        }
        "ab" => {
            assert_bytes(store, oid_a, ObjectKind::Blob, BLOB_A)?;
            assert_bytes(store, oid_b, ObjectKind::Blob, BLOB_B)?;
            let fact_a = fact_is(store, FactTable::Refs, FACT_KEY_A, Some(oid_a.as_bytes()))?;
            let fact_b = fact_is(store, FactTable::Refs, FACT_KEY_B, Some(oid_b.as_bytes()))?;
            Ok(fact_a && fact_b)
        }
        "a_not_b" => {
            assert_bytes(store, oid_a, ObjectKind::Blob, BLOB_A)?;
            if present(store, oid_b)? {
                return Ok(false);
            }
            if !fact_is(store, FactTable::Refs, FACT_KEY_A, Some(oid_a.as_bytes()))? {
                return Ok(false);
            }
            fact_is(store, FactTable::Refs, FACT_KEY_B, None)
        }
        "xor_ab" => {
            let has_a = present(store, oid_a)?;
            let has_b = present(store, oid_b)?;
            if has_a == has_b {
                return Ok(false);
            }
            if !fact_is(
                store,
                FactTable::Refs,
                FACT_KEY_A,
                has_a.then_some(oid_a.as_bytes()),
            )? {
                return Ok(false);
            }
            fact_is(
                store,
                FactTable::Refs,
                FACT_KEY_B,
                has_b.then_some(oid_b.as_bytes()),
            )
        }
        "xor_ab_or_ab" => match open_assert_spec(store, kind, "ab") {
            Ok(true) => Ok(true),
            // `ab` reports a missing object as EXIT_ASSERT: that is the
            // separate-commit outcome, checked by `xor_ab`. Any other code is
            // a store failure and stays fatal.
            Ok(false) | Err(EXIT_ASSERT) => open_assert_spec(store, kind, "xor_ab"),
            Err(code) => Err(code),
        },
        "none" => {
            if present(store, oid_a)? || present(store, oid_b)? {
                return Ok(false);
            }
            if !fact_is(store, FactTable::Refs, FACT_KEY_A, None)? {
                return Ok(false);
            }
            fact_is(store, FactTable::Refs, FACT_KEY_B, None)
        }
        "c1_all" => {
            assert_bytes(store, oid_a, ObjectKind::Blob, BLOB_A)?;
            assert_bytes(store, oid_b, ObjectKind::Blob, BLOB_B)?;
            if !fact_is(store, FactTable::Refs, FACT_KEY_A, Some(oid_a.as_bytes()))? {
                return Ok(false);
            }
            if !fact_is(store, FactTable::Refs, FACT_KEY_B, Some(oid_b.as_bytes()))? {
                return Ok(false);
            }
            for (index, payload) in C1_PAYLOADS.iter().enumerate() {
                let oid = blob_oid(kind, payload);
                assert_bytes(store, oid, ObjectKind::Blob, payload)?;
                let key = format!("refs/heads/c1-{index}");
                if !fact_is(store, FactTable::Refs, key.as_bytes(), Some(oid.as_bytes()))? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Err(EXIT_ARGS),
    }
}

// ---------------------------------------------------------------------------
// Read-side assertion helpers shared by parent and child
// ---------------------------------------------------------------------------

/// Reads `oid` and asserts kind, zero delta depth, and exact bytes.
fn assert_bytes(store: &Store, oid: Oid, kind: ObjectKind, expected: &[u8]) -> Result<(), i32> {
    match store.read(oid) {
        Ok(mut record) => {
            if record.kind != kind || record.depth != 0 {
                return Err(EXIT_ASSERT);
            }
            let mut got = Vec::new();
            if record.bytes.read_to_end(&mut got).is_err() {
                return Err(EXIT_STORE);
            }
            if got == expected {
                Ok(())
            } else {
                Err(EXIT_ASSERT)
            }
        }
        Err(_) => Err(EXIT_ASSERT),
    }
}

/// Reports whether `oid` is readable, treating only not-found as absence.
fn present(store: &Store, oid: Oid) -> Result<bool, i32> {
    match store.read(oid) {
        Ok(_) => Ok(true),
        Err(StoreError::NotFound(_)) => Ok(false),
        Err(_) => Err(EXIT_STORE),
    }
}

/// Reports whether `key` holds exactly `want`.
fn fact_is(store: &Store, table: FactTable, key: &[u8], want: Option<&[u8]>) -> Result<bool, i32> {
    match store.fact(table, key) {
        Ok(value) => Ok(value.as_deref() == want),
        Err(_) => Err(EXIT_STORE),
    }
}

// ---------------------------------------------------------------------------
// Parent-side harness
// ---------------------------------------------------------------------------

/// Uniqueness counter for scratch roots within one parent process.
static ROOT_SEQ: AtomicU32 = AtomicU32::new(0);

/// A unique, non-existent store root under the system temp directory. The
/// child's `Store::create` brings the whole layout into existence with
/// synced directory entries; the parent never pre-creates it.
fn fresh_root(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let seq = ROOT_SEQ.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "ruk-crash-{0}-{tag}-{nanos}-{seq}",
        std::process::id()
    ));
    crate::store::durability::create_dir_published(&ack_dir(&root))
        .expect("publish acknowledgement directory before starting children");
    root
}

/// Best-effort scratch cleanup; test failures must not mask the assertion.
fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(ack_dir(root));
}

/// Spawns the ignored child dispatcher of the current test executable with
/// the request carried entirely in child-only environment variables.
///
/// Asserts that libtest actually ran exactly one test. A filter that matches
/// nothing exits 0 without running anything, which would pass every
/// clean-exit child check vacuously; this makes that failure mode loud.
fn spawn_child(routine: &str, schedule: &str, args: &[&str]) -> ExitStatus {
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .arg(CHILD_ENTRY)
        .arg("--exact")
        .arg("--ignored")
        .arg("--nocapture")
        .env(CRASH_ENV, schedule)
        .env(CHILD_REQUEST_ENV, routine)
        .env(CHILD_ARGS_ENV, args.join(UNIT_SEPARATOR_STR))
        .output()
        .expect("spawn crash-test child from the current test executable");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
        "child filter {CHILD_ENTRY:?} matched no test; routine {routine:?}, \
         stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output.status
}

/// Asserts the child terminated exactly at the requested fault point.
fn assert_crashed(status: &ExitStatus, context: &str) {
    assert_eq!(
        status.code(),
        Some(crash_exit_code()),
        "{context}: child must terminate at the requested fault point \
         (exit {}), got {status:?}",
        crash_exit_code()
    );
}

/// Asserts a fresh-process state verification succeeded.
fn assert_child_state(root: &Path, kind: &str, spec: &str, context: &str) {
    let root_arg = root.to_string_lossy().into_owned();
    let status = spawn_child("open_assert_state", "", &[&root_arg, kind, spec]);
    assert_eq!(
        status.code(),
        Some(EXIT_COMPLETE),
        "{context}: fresh-process state check {spec:?} failed for {}",
        root.display()
    );
}

/// Asserts the acknowledgement marker exists: the publication was
/// acknowledged before the kill.
fn assert_acknowledged(root: &Path, name: &str, context: &str) {
    assert!(
        ack_marker(root, name).exists(),
        "{context}: acknowledgement marker for {name} must exist"
    );
}

/// Asserts the acknowledgement marker is absent: the kill preceded the
/// acknowledgement.
fn assert_unacknowledged(root: &Path, name: &str, context: &str) {
    assert!(
        !ack_marker(root, name).exists(),
        "{context}: acknowledgement marker for {name} must not exist"
    );
}

/// Every committed segment manifest and object locator of a store root,
/// read straight from the metadata tables.
///
/// This never constructs a [`Store`]: opening one runs recovery and would
/// truncate the very tail being observed. The metadata handle is dropped
/// before returning, so the next child or `Store::open` can take the
/// database lock.
fn committed_rows(root: &Path) -> (Vec<SegmentManifest>, Vec<(Oid, ObjectLocation)>) {
    let meta = Metadata::open(&root.join(META_FILE))
        .expect("read committed metadata without running recovery");
    let manifests = meta.all_manifests().expect("manifest rows");
    let objects = meta
        .object_page(None, OBJECT_PAGE)
        .expect("object locator rows");
    assert!(
        objects.len() < OBJECT_PAGE,
        "scenario stores hold fewer than {OBJECT_PAGE} objects"
    );
    (manifests, objects)
}

/// The path of segment file `id` under a store root.
fn segment_path(root: &Path, id: u64) -> PathBuf {
    root.join(SEGMENTS_DIR).join(segment_file_name(id))
}

/// The on-disk length of segment file `id`.
fn segment_len(root: &Path, id: u64) -> u64 {
    std::fs::metadata(segment_path(root, id))
        .expect("segment file")
        .len()
}

/// The committed extent and the on-disk length of the store's single open
/// segment, read from the manifest rows and the segment file alone.
fn open_segment_extent(root: &Path) -> (u64, u64) {
    let (manifests, _) = committed_rows(root);
    let mut open = manifests.iter().filter(|row| !row.sealed && !row.retired);
    let manifest = open.next().expect("the store has an open segment");
    assert!(open.next().is_none(), "the store has one open segment");
    (manifest.committed_end, segment_len(root, manifest.id))
}

/// `len` bytes of `path` starting at `start`.
fn read_range(path: &Path, start: u64, len: usize) -> Vec<u8> {
    let mut file = File::open(path).expect("open segment file");
    file.seek(SeekFrom::Start(start)).expect("seek range");
    let mut bytes = vec![0_u8; len];
    file.read_exact(&mut bytes).expect("read segment range");
    bytes
}

/// The length and CRC32C of a file, streamed in bounded chunks.
fn file_fingerprint(path: &Path) -> (u64, u32) {
    let mut file = File::open(path).expect("open segment file");
    let mut chunk = vec![0_u8; STREAM_CHUNK];
    let (mut len, mut crc) = (0_u64, 0_u32);
    loop {
        let read = file.read(&mut chunk).expect("read segment file");
        if read == 0 {
            return (len, crc);
        }
        crc = crc32c::crc32c_append(crc, &chunk[..read]);
        len += usize_u64(read);
    }
}

/// Prepares and publishes one small blob under one `refs` fact row, checking
/// its identity against the canonical Git blob hash.
fn publish_small_blob(store: &Store, kind: HashKind, payload: &[u8], key: &[u8]) -> Oid {
    let prepared = store
        .prepare(ObjectKind::Blob, len_u64(payload), payload, None)
        .expect("prepare a small blob");
    let oid = prepared.oid();
    assert_eq!(oid, blob_oid(kind, payload), "canonical blob identity");
    let facts = [fact_mutation(
        FactTable::Refs,
        key,
        FactExpectation::Absent,
        Some(oid.as_bytes()),
    )];
    store
        .publish(
            vec![prepared],
            &facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish a small blob");
    oid
}

/// Asserts `key` in the `refs` table holds exactly `want`.
fn assert_refs_fact(store: &Store, key: &[u8], want: Option<&[u8]>, context: &str) {
    assert_eq!(
        store
            .fact(FactTable::Refs, key)
            .expect("fact read")
            .as_deref(),
        want,
        "{context}: refs fact row"
    );
}

// ---------------------------------------------------------------------------
// Parent tests: acknowledged permanence
// ---------------------------------------------------------------------------

/// Kills a child after the metadata commit (or after the child-side
/// acknowledgement) and proves from a fresh reopen that the publication is
/// fully present and the store healthy, for both hash kinds. The marker
/// distinguishes the acknowledged outcome from the pre-return termination.
fn assert_acknowledged_publication_survives(point: &str) {
    let acknowledged = point == "after_ack";
    for kind in [HashKind::Sha1, HashKind::Sha256] {
        let root = fresh_root(&format!("ack-{}", kind.format_name()));
        let root_arg = root.to_string_lossy().into_owned();
        let status = spawn_child("publish_blob_fact", point, &[&root_arg, kind.format_name()]);
        assert_crashed(&status, &format!("{point} kill with {kind}"));
        if acknowledged {
            assert_acknowledged(&root, "a", &format!("{point} kill with {kind}"));
        } else {
            assert_unacknowledged(&root, "a", &format!("{point} kill with {kind}"));
        }
        let store = Store::open(&root, test_budget()).expect("reopen after acknowledged kill");
        assert!(
            !store.quarantine(),
            "an acknowledged publication must not latch quarantine"
        );
        assert_eq!(store.hash_kind(), kind, "repository hash kind is fixed");
        let oid = blob_oid(kind, BLOB_A);
        assert_bytes(&store, oid, ObjectKind::Blob, BLOB_A)
            .expect("acknowledged object bytes after reopen");
        assert_eq!(
            store.fact(FactTable::Refs, FACT_KEY_A).expect("fact read"),
            Some(oid.as_bytes().to_vec()),
            "acknowledged fact row after reopen"
        );
        drop(store);
        cleanup(&root);
    }
}

/// Death after the metadata commit returns leaves the publication present
/// after reopen: commit-and-die is never rolled back. No acknowledgement was
/// recorded yet, and the marker proves it.
#[test]
fn crash_after_metadata_commit_keeps_acknowledged_publication() {
    assert_acknowledged_publication_survives("after_metadata_commit");
}

/// Death at the last statement before `publish` returns `Ok` shows the
/// in-memory bookkeeping between the commit and the caller-visible return
/// carries no separate on-disk state: the committed frontier is identical,
/// and the acknowledgement marker is still absent.
#[test]
fn crash_before_ack_keeps_committed_publication() {
    assert_acknowledged_publication_survives("before_ack");
}

/// Death at the child-side acknowledgement boundary — after `publish`
/// returned and the child recorded its observable acknowledgement — shows
/// the acknowledged outcome is present after reopen.
#[test]
fn crash_after_ack_keeps_acknowledged_publication() {
    assert_acknowledged_publication_survives("after_ack");
}

// ---------------------------------------------------------------------------
// Parent tests: uncommitted all-or-nothing
// ---------------------------------------------------------------------------

/// Kills a child at each pre-commit boundary (append written, segments
/// synced, directory synced) for both hash kinds, then proves the store
/// reopens cleanly with the publication entirely absent, and that the
/// recovered store publishes the identical object and fact again while
/// refusing a duplicate same-path fact row.
///
/// This is an absence-and-recovery test, not a truncation test. The first
/// publication of a fresh store creates a segment file that no manifest row
/// names, so recovery treats it as an unknown orphan: it is neither
/// truncated nor deleted, and the reopened store allocates past it. The
/// crash-left bytes must therefore survive unchanged. Truncation of a
/// manifest-owned tail is proved by
/// `recovery_tail_truncation_completes_before_the_recovery_crash`.
#[test]
fn crash_before_metadata_commit_leaves_publication_absent() {
    for kind in [HashKind::Sha1, HashKind::Sha256] {
        for point in ["after_append", "after_segment_sync", "after_directory_sync"] {
            assert_precommit_kill_leaves_absence(kind, point);
        }
    }
}

/// One pre-commit kill of `publish_blob_fact` and its recovery proof; see
/// [`crash_before_metadata_commit_leaves_publication_absent`].
fn assert_precommit_kill_leaves_absence(kind: HashKind, point: &str) {
    let context = format!("{point} kill with {kind}");
    let root = fresh_root(&format!("precommit-{}-{point}", kind.format_name()));
    let root_arg = root.to_string_lossy().into_owned();
    let status = spawn_child("publish_blob_fact", point, &[&root_arg, kind.format_name()]);
    assert_crashed(&status, &context);
    assert_unacknowledged(&root, "a", &context);
    let (manifests, objects) = committed_rows(&root);
    assert!(
        manifests.is_empty() && objects.is_empty(),
        "{context}: nothing may be committed, got {manifests:?}"
    );
    let orphan_path = segment_path(&root, 0);
    let orphan = std::fs::read(&orphan_path).expect("crash-left segment file");
    assert!(
        !orphan.is_empty(),
        "{context}: the killed append left bytes in the orphan segment"
    );
    let store =
        Store::open(&root, test_budget()).expect("reopen after pre-commit kill must recover");
    assert!(
        !store.quarantine(),
        "an uncommitted tail must not latch quarantine"
    );
    let oid = blob_oid(kind, BLOB_A);
    match store.read(oid) {
        Err(StoreError::NotFound(_)) => {}
        other => panic!(
            "{context}: uncommitted object must be absent after recovery, got readable={}",
            other.is_ok()
        ),
    }
    assert_refs_fact(&store, FACT_KEY_A, None, &context);
    let republished = publish_small_blob(&store, kind, BLOB_A, FACT_KEY_A);
    assert_eq!(republished, oid, "identity is stable across recovery");
    assert_bytes(&store, oid, ObjectKind::Blob, BLOB_A).expect("republished object bytes");
    assert_refs_fact(&store, FACT_KEY_A, Some(oid.as_bytes()), &context);
    let prepared = store
        .prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None)
        .expect("prepare for the duplicate row probe");
    let facts = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_A,
        FactExpectation::Absent,
        Some(oid.as_bytes()),
    )];
    match store.publish(
        vec![prepared],
        &facts,
        EventSource::LocalPush,
        &EventContext::default(),
    ) {
        Err(StoreError::StaleFact { .. }) => {}
        other => panic!(
            "{context}: duplicate same-path fact row must be refused with a stale \
             expectation, got ok={}",
            other.is_ok()
        ),
    }
    assert_refs_fact(&store, FACT_KEY_A, Some(oid.as_bytes()), &context);
    assert_eq!(
        std::fs::read(&orphan_path).expect("crash-left segment file"),
        orphan,
        "{context}: the unknown orphan segment must survive unchanged"
    );
    drop(store);
    cleanup(&root);
}

/// Death after the capacity-ledger pending commit but before any append
/// leaves a durable `Pending` row and no committed bytes: the commit that
/// precedes the first reservation call is already on disk when the process
/// dies. Reopening reconciles the row to `Released` (re-checked against the
/// file extents) without latching quarantine, and the next publication
/// takes the next per-generation sequence and commits normally.
#[test]
fn capacity_pending_kill_reconciles_to_released() {
    for kind in [HashKind::Sha1, HashKind::Sha256] {
        assert_capacity_pending_reconciles(kind);
    }
}

/// One `capacity_pending_persisted` kill and its recovery proof; see
/// [`capacity_pending_kill_reconciles_to_released`].
fn assert_capacity_pending_reconciles(kind: HashKind) {
    let context = format!("capacity_pending_persisted kill with {kind}");
    let root = fresh_root(&format!("capacity-pending-{}", kind.format_name()));
    let root_arg = root.to_string_lossy().into_owned();
    let status = spawn_child(
        "publish_capacity_probe",
        "capacity_pending_persisted",
        &[&root_arg, kind.format_name()],
    );
    assert_crashed(&status, &context);
    assert_unacknowledged(&root, "a", &context);
    // The pending row committed before the kill: exactly one `Pending` row
    // for generation 1, with no charges yet, read without running recovery.
    let meta =
        Metadata::open(&root.join(META_FILE)).expect("read ledger rows without running recovery");
    let rows = meta.pending_rows().expect("pending rows");
    assert_eq!(
        rows.len(),
        1,
        "{context}: one pending row must be durable, got {rows:?}"
    );
    assert_eq!(
        rows[0].0,
        PendingReservation::key(1, 0),
        "{context}: pending row key"
    );
    assert_eq!(rows[0].1.generation, 1, "{context}: pending generation");
    assert_eq!(rows[0].1.seq, 0, "{context}: pending sequence");
    assert_eq!(
        rows[0].1.state,
        ReservationState::Pending,
        "{context}: pending state"
    );
    assert!(
        rows[0].1.charges.is_empty(),
        "{context}: killed before any append, so no charges"
    );
    drop(meta);
    let (manifests, objects) = committed_rows(&root);
    assert!(
        manifests.is_empty() && objects.is_empty(),
        "{context}: nothing may be committed, got {manifests:?}"
    );
    // Reopen reconciles the dead row and keeps serving.
    let store = Store::open(&root, test_budget()).expect("reopen must recover and reconcile");
    assert!(
        !store.quarantine(),
        "{context}: a dead pending row must not latch quarantine"
    );
    let rows = store
        .capacity_pending_rows_for_tests()
        .expect("ledger rows");
    assert_eq!(
        rows.len(),
        1,
        "{context}: the dead row survives as a tombstone, got {rows:?}"
    );
    assert_eq!(
        rows[0].1.state,
        ReservationState::Released,
        "{context}: reconciled state"
    );
    let oid = blob_oid(kind, BLOB_A);
    match store.read(oid) {
        Err(StoreError::NotFound(_)) => {}
        other => panic!(
            "{context}: uncommitted object must be absent after recovery, got readable={}",
            other.is_ok()
        ),
    }
    // The retry takes the next sequence and commits with its observed charge.
    let republished = publish_small_blob(&store, kind, BLOB_A, FACT_KEY_A);
    assert_eq!(republished, oid, "identity is stable across recovery");
    assert_bytes(&store, oid, ObjectKind::Blob, BLOB_A).expect("republished object bytes");
    let rows = store
        .capacity_pending_rows_for_tests()
        .expect("ledger rows");
    assert_eq!(
        rows.len(),
        2,
        "{context}: retry adds a second row, got {rows:?}"
    );
    assert_eq!(
        rows[1].0,
        PendingReservation::key(1, 1),
        "{context}: retry sequence"
    );
    assert_eq!(
        rows[1].1.state,
        ReservationState::Committed,
        "{context}: retry state"
    );
    assert_eq!(
        rows[1].1.charges.len(),
        1,
        "{context}: one record reserved exactly once, got {:?}",
        rows[1].1.charges
    );
    drop(store);
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Parent tests: recovery truncation under a second crash
// ---------------------------------------------------------------------------

/// Builds committed-then-uncommitted state, lets a fresh process truncate
/// the uncommitted tail and die at the recovery hook, then proves the
/// committed publication survived the truncation crash intact.
///
/// The first child is killed after B's records are written and flushed in
/// the open segment but before the metadata commit
/// (`after_directory_sync@2`), so B is a real uncommitted tail behind A's
/// committed extent. Killing after the commit would make B committed and
/// leave recovery nothing to truncate. The marker for A shows only A was
/// acknowledged; the missing marker for B shows B never was; the segment's
/// on-disk length versus its manifest `committed_end` shows the tail exists
/// before recovery and is already gone when the recovery child dies at the
/// hook, which fires after the truncation call returned. A process kill
/// shows that ordering, not that the truncation reached stable storage. No
/// `Store` is opened in the parent until then, so nothing but the
/// crash-scheduled child can consume the tail.
#[test]
fn recovery_tail_truncation_completes_before_the_recovery_crash() {
    let root = fresh_root("sha1-tail-reclaim");
    let root_arg = root.to_string_lossy().into_owned();
    let status = spawn_child(
        "publish_two_serial",
        "after_directory_sync@2",
        &[&root_arg, "sha1"],
    );
    assert_crashed(&status, "kill before the second publication commits");
    assert_acknowledged(&root, "a", "first publication acknowledged");
    assert_unacknowledged(&root, "b", "second publication never acknowledged");
    let (committed_end, on_disk) = open_segment_extent(&root);
    assert!(
        on_disk > committed_end,
        "the killed second publication must leave an uncommitted tail: segment \
         holds {on_disk} bytes against a committed extent of {committed_end}"
    );
    let status = spawn_child(
        "open_recovering",
        "recovery_after_tail_truncate",
        &[&root_arg, "sha1"],
    );
    assert_crashed(&status, "kill after the recovery tail truncation");
    assert_eq!(
        open_segment_extent(&root),
        (committed_end, committed_end),
        "the tail must already be truncated to the committed extent, and the \
         committed prefix kept whole, when the recovery child dies"
    );
    let store = Store::open(&root, test_budget())
        .expect("reopen after the recovery kill must see the truncated state");
    assert!(
        !store.quarantine(),
        "tail truncation must not latch quarantine"
    );
    let oid_a = blob_oid(HashKind::Sha1, BLOB_A);
    let oid_b = blob_oid(HashKind::Sha1, BLOB_B);
    assert_bytes(&store, oid_a, ObjectKind::Blob, BLOB_A)
        .expect("committed object survives the truncation crash");
    assert_eq!(
        store.fact(FactTable::Refs, FACT_KEY_A).expect("fact read"),
        Some(oid_a.as_bytes().to_vec()),
        "committed fact row survives the truncation crash"
    );
    match store.read(oid_b) {
        Err(StoreError::NotFound(_)) => {}
        other => panic!(
            "uncommitted object must be gone after the truncation crash, got \
             readable={}",
            other.is_ok()
        ),
    }
    assert_eq!(
        store.fact(FactTable::Refs, FACT_KEY_B).expect("fact read"),
        None,
        "uncommitted fact row must be gone after the truncation crash"
    );
    drop(store);
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Parent tests: committed corruption refuses service
// ---------------------------------------------------------------------------

/// Corrupts one byte inside the committed extent of a published segment and
/// proves three refusal layers: the live handle's reads latch quarantine and
/// refuse further reads and writes, a fresh process's recovery detects the
/// corruption (killed at the detection hook), and another fresh process
/// refuses to open at all.
#[test]
fn corrupt_committed_bytes_refuse_service() {
    let root = fresh_root("sha1-corrupt-flip");
    let root_arg = root.to_string_lossy().into_owned();
    let status = spawn_child("publish_blob_fact", "", &[&root_arg, "sha1"]);
    assert_eq!(
        status.code(),
        Some(EXIT_COMPLETE),
        "clean publication child must exit successfully"
    );
    assert_acknowledged(&root, "a", "clean publication acknowledged");
    let store = Store::open(&root, test_budget()).expect("clean reopen before corruption");
    let oid = blob_oid(HashKind::Sha1, BLOB_A);
    assert_bytes(&store, oid, ObjectKind::Blob, BLOB_A).expect("read before corruption");
    flip_committed_byte(&root);
    match store.read(oid) {
        Err(StoreError::Corrupt(_)) => {}
        other => panic!(
            "corrupt committed bytes must refuse reads with E_CORRUPT, got \
             readable={}",
            other.is_ok()
        ),
    }
    assert!(
        store.quarantine(),
        "committed corruption must latch quarantine"
    );
    assert!(
        store.quarantine_reason().is_some(),
        "quarantine must carry a reason"
    );
    match store.fact(FactTable::Refs, FACT_KEY_A) {
        Err(StoreError::Corrupt(_)) => {}
        other => panic!(
            "fact reads must refuse under quarantine, got ok={}",
            other.is_ok()
        ),
    }
    match store.prepare(ObjectKind::Blob, len_u64(BLOB_B), BLOB_B, None) {
        Ok(prepared) => match store.publish(
            vec![prepared],
            &[],
            EventSource::LocalPush,
            &EventContext::default(),
        ) {
            Err(StoreError::Corrupt(_)) => {}
            other => panic!(
                "publication must refuse under quarantine, got ok={}",
                other.is_ok()
            ),
        },
        Err(StoreError::Corrupt(_)) => {}
        Err(err) => panic!("unexpected prepare error under quarantine: {err:?}"),
    }
    drop(store);
    let status = spawn_child(
        "open_recovering",
        "recovery_after_detect_corrupt",
        &[&root_arg, "sha1"],
    );
    assert_crashed(&status, "kill at corruption detection during recovery");
    let status = spawn_child("open_expect_corrupt", "", &[&root_arg, "sha1"]);
    assert_eq!(
        status.code(),
        Some(EXIT_EXPECTED_CORRUPT),
        "a fresh process must refuse to open the corrupted store"
    );
    cleanup(&root);
}

/// Removes five bytes from the committed extent of a published segment and
/// proves the missing committed bytes refuse service identically.
#[test]
fn missing_committed_bytes_refuse_service() {
    let root = fresh_root("sha1-missing-bytes");
    let root_arg = root.to_string_lossy().into_owned();
    let status = spawn_child("publish_blob_fact", "", &[&root_arg, "sha1"]);
    assert_eq!(
        status.code(),
        Some(EXIT_COMPLETE),
        "clean publication child must exit successfully"
    );
    assert_acknowledged(&root, "a", "clean publication acknowledged");
    let store = Store::open(&root, test_budget()).expect("clean reopen before truncation");
    let oid = blob_oid(HashKind::Sha1, BLOB_A);
    assert_bytes(&store, oid, ObjectKind::Blob, BLOB_A).expect("read before truncation");
    truncate_committed_file(&root);
    match store.read(oid) {
        Err(StoreError::Corrupt(_)) => {}
        other => panic!(
            "missing committed bytes must refuse reads with E_CORRUPT, got \
             readable={}",
            other.is_ok()
        ),
    }
    assert!(
        store.quarantine(),
        "missing committed bytes must latch quarantine"
    );
    drop(store);
    let status = spawn_child("open_expect_corrupt", "", &[&root_arg, "sha1"]);
    assert_eq!(
        status.code(),
        Some(EXIT_EXPECTED_CORRUPT),
        "a fresh process must refuse the store with missing committed bytes"
    );
    cleanup(&root);
}

/// Flips one byte in the middle of the committed extent of the first
/// segment file. Test-harness surgery on committed bytes, never a store API.
fn flip_committed_byte(root: &Path) {
    let path = first_segment_file(root);
    let mut bytes = std::fs::read(&path).expect("read committed segment");
    let at = bytes.len() / 2;
    bytes[at] ^= 0xff;
    std::fs::write(&path, bytes).expect("write corrupted segment");
}

/// Removes five trailing bytes from the committed extent.
fn truncate_committed_file(root: &Path) {
    let path = first_segment_file(root);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open committed segment for truncation");
    let len = file.metadata().expect("segment metadata").len();
    file.set_len(len - 5).expect("truncate committed segment");
    file.sync_all().expect("sync truncation");
}

/// The first `seg_` file of the store's segments directory.
fn first_segment_file(root: &Path) -> PathBuf {
    let mut files: Vec<PathBuf> = std::fs::read_dir(root.join("segments"))
        .expect("segments directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("seg_"))
        })
        .collect();
    files.sort();
    files.into_iter().next().expect("at least one segment file")
}

// ---------------------------------------------------------------------------
// Parent tests: unknown paths survive recovery
// ---------------------------------------------------------------------------

/// Leaves unknown files in the scratch and segments directories, reopens,
/// publishes again, and proves the unknown paths survive byte-identical:
/// filename shape is never deletion authority.
#[test]
fn unknown_scratch_and_segment_files_survive_recovery() {
    let root = fresh_root("sha1-unknown-paths");
    let root_arg = root.to_string_lossy().into_owned();
    let status = spawn_child("publish_blob_fact", "", &[&root_arg, "sha1"]);
    assert_eq!(
        status.code(),
        Some(EXIT_COMPLETE),
        "clean publication child must exit successfully"
    );
    std::fs::create_dir_all(root.join("scratch")).expect("scratch directory");
    let unknown_scratch = root.join("scratch").join("unknown-journal-ruk-crash.bin");
    std::fs::write(&unknown_scratch, UNKNOWN_SCRATCH_BYTES).expect("write unknown scratch file");
    let unknown_segment = root.join("segments").join("seg_00000000deadbeef");
    std::fs::write(&unknown_segment, UNKNOWN_SEGMENT_BYTES).expect("write unknown segment file");
    let store = Store::open(&root, test_budget()).expect("reopen with unknown files present");
    assert_bytes(
        &store,
        blob_oid(HashKind::Sha1, BLOB_A),
        ObjectKind::Blob,
        BLOB_A,
    )
    .expect("committed object readable with unknown files present");
    assert_eq!(
        std::fs::read(&unknown_scratch).expect("unknown scratch file"),
        UNKNOWN_SCRATCH_BYTES,
        "unknown scratch file must survive recovery"
    );
    assert_eq!(
        std::fs::read(&unknown_segment).expect("unknown segment file"),
        UNKNOWN_SEGMENT_BYTES,
        "unknown segment file must survive recovery"
    );
    let prepared = store
        .prepare(ObjectKind::Blob, len_u64(BLOB_B), BLOB_B, None)
        .expect("prepare alongside unknown files");
    let oid = prepared.oid();
    let facts = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_B,
        FactExpectation::Absent,
        Some(oid.as_bytes()),
    )];
    store
        .publish(
            vec![prepared],
            &facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish alongside unknown files");
    assert_bytes(&store, oid, ObjectKind::Blob, BLOB_B).expect("new publication readable");
    assert_eq!(
        std::fs::read(&unknown_scratch).expect("unknown scratch file"),
        UNKNOWN_SCRATCH_BYTES,
        "publication must not touch unknown scratch paths"
    );
    assert_eq!(
        std::fs::read(&unknown_segment).expect("unknown segment file"),
        UNKNOWN_SEGMENT_BYTES,
        "publication must not touch unknown segment paths"
    );
    drop(store);
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Parent tests: concurrency
// ---------------------------------------------------------------------------

/// Prepares four objects on parallel threads, publishes them as one atomic
/// set with four fact rows, then runs two publications concurrently through
/// the serialized writer, and finally proves the complete state from a
/// fresh process: concurrent preparation and serialized concurrent
/// publication are all present after reopen, exactly as published.
#[test]
fn concurrent_preparation_and_serial_publications_roundtrip() {
    let root = fresh_root("sha1-concurrent-roundtrip");
    let store = Store::create(&root, HashKind::Sha1, test_budget()).expect("create store");
    let prepared: Vec<PreparedObject> = std::thread::scope(|scope| {
        let handles: Vec<_> = C1_PAYLOADS
            .iter()
            .map(|payload| {
                let store = &store;
                let payload: &[u8] = payload;
                scope
                    .spawn(move || store.prepare(ObjectKind::Blob, len_u64(payload), payload, None))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("prepare thread").expect("prepare"))
            .collect()
    });
    let facts: Vec<FactMutation> = prepared
        .iter()
        .enumerate()
        .map(|(index, object)| FactMutation {
            table: FactTable::Refs,
            key: format!("refs/heads/c1-{index}").into_bytes(),
            expected: FactExpectation::Absent,
            value: Some(object.oid().as_bytes().to_vec()),
        })
        .collect();
    let publication = store
        .publish(
            prepared,
            &facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("one atomic four-object publication");
    assert!(publication.generation >= 1, "publication bumps generation");
    for (index, payload) in C1_PAYLOADS.iter().enumerate() {
        assert_bytes(
            &store,
            blob_oid(HashKind::Sha1, payload),
            ObjectKind::Blob,
            payload,
        )
        .unwrap_or_else(|_| panic!("concurrently prepared object {index} readable"));
    }
    let outcomes: Vec<Result<(), StoreError>> = std::thread::scope(|scope| {
        let store = &store;
        let first = scope.spawn(move || -> Result<(), StoreError> {
            let prepared = store.prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None)?;
            let oid = prepared.oid();
            let facts = [fact_mutation(
                FactTable::Refs,
                FACT_KEY_A,
                FactExpectation::Absent,
                Some(oid.as_bytes()),
            )];
            store
                .publish(
                    vec![prepared],
                    &facts,
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .map(|_| ())
        });
        let second = scope.spawn(move || -> Result<(), StoreError> {
            let prepared = store.prepare(ObjectKind::Blob, len_u64(BLOB_B), BLOB_B, None)?;
            let oid = prepared.oid();
            let facts = [fact_mutation(
                FactTable::Refs,
                FACT_KEY_B,
                FactExpectation::Absent,
                Some(oid.as_bytes()),
            )];
            store
                .publish(
                    vec![prepared],
                    &facts,
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .map(|_| ())
        });
        vec![
            first.join().expect("concurrent publish thread A"),
            second.join().expect("concurrent publish thread B"),
        ]
    });
    for outcome in outcomes {
        outcome.expect("serialized concurrent publication");
    }
    drop(store);
    assert_child_state(&root, "sha1", "c1_all", "concurrent roundtrip state");
    cleanup(&root);
}

/// Two publications race through the serialized writer while the process is
/// killed: at the first metadata commit either one publication survives
/// whole, or both do when the writer grouped them into one commit, and
/// neither was acknowledged; during the first append neither survives.
/// Every publication is all-or-nothing under concurrent crash, and the
/// recovered store keeps serving and publishing.
#[test]
fn concurrent_publications_are_atomic_under_crash() {
    let first_commit_root = fresh_root("sha1-racing-first-commit");
    let first_commit_arg = first_commit_root.to_string_lossy().into_owned();
    let status = spawn_child(
        "publish_two_racing",
        "after_metadata_commit@1",
        &[&first_commit_arg, "sha1"],
    );
    assert_crashed(&status, "racing kill at the first metadata commit");
    assert_unacknowledged(&first_commit_root, "a", "racing kill at first commit");
    assert_unacknowledged(&first_commit_root, "b", "racing kill at first commit");
    assert_child_state(
        &first_commit_root,
        "sha1",
        "xor_ab_or_ab",
        "one racing publication, or both grouped into one commit, survives a first-commit kill",
    );
    let first_append_root = fresh_root("sha1-racing-first-append");
    let first_append_arg = first_append_root.to_string_lossy().into_owned();
    let status = spawn_child(
        "publish_two_racing",
        "after_append@1",
        &[&first_append_arg, "sha1"],
    );
    assert_crashed(&status, "racing kill during the first append");
    assert_child_state(
        &first_append_root,
        "sha1",
        "none",
        "neither racing publication survives an append kill",
    );
    let store = Store::open(&first_append_root, test_budget())
        .expect("reopen after the racing append kill");
    assert!(
        !store.quarantine(),
        "a racing pre-commit kill must not latch quarantine"
    );
    let prepared = store
        .prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None)
        .expect("prepare on the recovered racing store");
    let oid = prepared.oid();
    let facts = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_A,
        FactExpectation::Absent,
        Some(oid.as_bytes()),
    )];
    store
        .publish(
            vec![prepared],
            &facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish on the recovered racing store");
    assert_bytes(&store, oid, ObjectKind::Blob, BLOB_A).expect("recovered store publishes");
    drop(store);
    cleanup(&first_commit_root);
    cleanup(&first_append_root);
}

// ---------------------------------------------------------------------------
// Parent tests: mixed native conflict publication at every boundary
// ---------------------------------------------------------------------------

/// Reopens a store root in this process; recovery runs inside `Store::open`.
fn reopen(root: &Path) -> Store {
    Store::open(root, test_budget()).expect("reopen must recover")
}

/// The blob identity, the native conflict identity, and the framed conflict
/// bytes of the mixed publication. The conflict identity hashes the framed
/// bytes directly, with no Git object header.
fn mixed_identities(kind: HashKind) -> (Oid, Oid, Vec<u8>) {
    let framed = conflict_frame(kind);
    let conflict = kind
        .hash_parts(&[framed.as_slice()])
        .expect("deterministic conflict identity");
    (blob_oid(kind, BLOB_A), conflict, framed)
}

/// Whether the blob, the conflict record and the conflict fact row are each
/// visible: the three members of the mixed publication.
fn mixed_presence(store: &Store, blob: Oid, conflict: Oid) -> (bool, bool, bool) {
    let blob_present = present(store, blob).expect("blob read");
    let conflict_present = present(store, conflict).expect("conflict read");
    let fact = store
        .fact(FactTable::Refs, FACT_KEY_CONFLICT)
        .expect("fact read");
    (blob_present, conflict_present, fact.is_some())
}

/// Reads the conflict record back and asserts its storage kind, zero delta
/// depth, and exact framed bytes, complete length header included.
fn assert_conflict_record(store: &Store, oid: Oid, framed: &[u8]) {
    let mut record = store.read(oid).expect("conflict record readable");
    assert_eq!(
        record.kind,
        ObjectKind::Conflict,
        "native conflict records keep their storage kind"
    );
    assert_eq!(record.depth, 0, "conflict records are never deltas");
    let mut got = Vec::new();
    record
        .bytes
        .read_to_end(&mut got)
        .expect("read conflict payload");
    assert_eq!(
        got, framed,
        "conflict framed bytes must be preserved exactly"
    );
}

/// Publishes a Git blob and a framed native conflict record in one atomic
/// set with one fact row and kills the child at each boundary around the
/// commit, for both hash kinds. Before the commit the two objects and the
/// fact are absent together; from the commit on they are present together
/// and byte-exact, the conflict record keeping its direct framed-byte hash
/// identity and complete length header. The acknowledgement marker exists
/// only for the `after_ack` kill.
#[test]
fn mixed_publication_is_atomic_across_crash_boundaries() {
    for kind in [HashKind::Sha1, HashKind::Sha256] {
        for point in [
            "after_append",
            "after_directory_sync",
            "after_metadata_commit",
            "after_ack",
        ] {
            assert_mixed_boundary(kind, point);
        }
    }
}

/// One mixed-publication kill at `point` and its reopen proof.
fn assert_mixed_boundary(kind: HashKind, point: &str) {
    let context = format!("{point} kill with {kind}");
    let root = fresh_root(&format!("mixed-{}-{point}", kind.format_name()));
    let root_arg = root.to_string_lossy().into_owned();
    let status = spawn_child(
        "publish_mixed_conflict",
        point,
        &[&root_arg, kind.format_name()],
    );
    assert_crashed(&status, &context);
    if point == "after_ack" {
        assert_acknowledged(&root, "mixed", &context);
    } else {
        assert_unacknowledged(&root, "mixed", &context);
    }
    let committed = matches!(point, "after_metadata_commit" | "after_ack");
    let (manifests, objects) = committed_rows(&root);
    assert_eq!(
        (manifests.len(), objects.len()),
        (usize::from(committed), 2 * usize::from(committed)),
        "{context}: committed metadata must hold the whole set or nothing, got {manifests:?}"
    );
    if committed {
        assert_mixed_present(&root, kind, &context);
    } else {
        assert_mixed_absent(&root, kind, &context);
    }
    cleanup(&root);
}

/// A kill at or after the commit: the blob, the conflict record and the
/// fact are all present and byte-exact after reopen.
fn assert_mixed_present(root: &Path, kind: HashKind, context: &str) {
    let store = reopen(root);
    assert!(
        !store.quarantine(),
        "{context}: a committed publication must not latch quarantine"
    );
    let (blob, conflict, framed) = mixed_identities(kind);
    assert_eq!(
        mixed_presence(&store, blob, conflict),
        (true, true, true),
        "{context}: blob, conflict record and fact must be present together"
    );
    assert_bytes(&store, blob, ObjectKind::Blob, BLOB_A).expect("blob bytes after reopen");
    assert_conflict_record(&store, conflict, &framed);
    let row = conflict.as_bytes();
    assert_refs_fact(&store, FACT_KEY_CONFLICT, Some(row), context);
}

/// A kill before the commit: nothing is visible, the crash-left segment is
/// an untouched orphan, and the identical set republishes on the recovered
/// store.
fn assert_mixed_absent(root: &Path, kind: HashKind, context: &str) {
    let orphan_path = segment_path(root, 0);
    let orphan = std::fs::read(&orphan_path).expect("segment file left by the child");
    assert!(
        !orphan.is_empty(),
        "{context}: the killed append left bytes in the orphan segment"
    );
    let store = reopen(root);
    assert!(
        !store.quarantine(),
        "{context}: an uncommitted set must not latch quarantine"
    );
    let (blob, conflict, framed) = mixed_identities(kind);
    assert_eq!(
        mixed_presence(&store, blob, conflict),
        (false, false, false),
        "{context}: blob, conflict record and fact must be absent together"
    );
    let framed_len = len_u64(&framed);
    let frame = framed.as_slice();
    let prepared_blob = store
        .prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None)
        .expect("prepare the blob on the recovered store");
    let prepared_conflict = store
        .prepare(ObjectKind::Conflict, framed_len, frame, None)
        .expect("prepare the conflict record on the recovered store");
    assert_eq!(prepared_blob.oid(), blob, "blob identity across recovery");
    assert_eq!(
        prepared_conflict.oid(),
        conflict,
        "conflict identity across recovery"
    );
    let facts = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_CONFLICT,
        FactExpectation::Absent,
        Some(conflict.as_bytes()),
    )];
    store
        .publish(
            vec![prepared_blob, prepared_conflict],
            &facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("republish the mixed set on the recovered store");
    assert_eq!(
        mixed_presence(&store, blob, conflict),
        (true, true, true),
        "{context}: the republished set must be present together"
    );
    assert_bytes(&store, blob, ObjectKind::Blob, BLOB_A).expect("republished blob bytes");
    assert_conflict_record(&store, conflict, &framed);
    assert_eq!(
        std::fs::read(&orphan_path).expect("segment file left by the child"),
        orphan,
        "{context}: the unknown orphan segment must survive unchanged"
    );
}

// ---------------------------------------------------------------------------
// Parent tests: real seal boundary
// ---------------------------------------------------------------------------

/// Reads `oid` back and streams its bytes against the seeded noise stream in
/// bounded chunks; the store has already verified the identity by
/// recomputing it from the decoded bytes.
fn assert_noise_object(store: &Store, oid: Oid) {
    let mut record = store
        .read(oid)
        .expect("the sealed oversized object reads back");
    assert_eq!(
        record.kind,
        ObjectKind::Blob,
        "the oversized object keeps its storage kind"
    );
    assert_eq!(record.depth, 0, "the oversized object is never a delta");
    assert_eq!(
        record.bytes.len(),
        SEAL_BLOB_LEN,
        "the decoded length is exact"
    );
    let identical = stream_matches_noise(&mut record.bytes, SEAL_SEED, SEAL_BLOB_LEN)
        .expect("stream the oversized object");
    assert!(
        identical,
        "the oversized object bytes must equal the generated stream"
    );
}

/// Kills the oversized publication after its directory sync, with the first
/// segment's seal footer and a second sealed segment already on disk but no
/// manifest naming either, for SHA-1.
#[test]
fn seal_boundary_precommit_kill_leaves_footer_tail_and_orphan_sha1() {
    assert_seal_boundary_precommit(HashKind::Sha1);
}

/// As the SHA-1 precommit seal-boundary kill, for SHA-256.
#[test]
fn seal_boundary_precommit_kill_leaves_footer_tail_and_orphan_sha256() {
    assert_seal_boundary_precommit(HashKind::Sha256);
}

/// Kills the oversized publication right after its metadata commit, with
/// both segments sealed in the committed manifests, for SHA-1.
#[test]
fn seal_boundary_postcommit_kill_keeps_sealed_segments_sha1() {
    assert_seal_boundary_postcommit(HashKind::Sha1);
}

/// As the SHA-1 postcommit seal-boundary kill, for SHA-256.
#[test]
fn seal_boundary_postcommit_kill_keeps_sealed_segments_sha256() {
    assert_seal_boundary_postcommit(HashKind::Sha256);
}

/// Seal-boundary kill at `after_directory_sync@2`.
///
/// On disk, before any recovery: the manifests still describe only A's open
/// segment, whose file now ends in an uncommitted seal footer, and a second
/// sealed segment holding the oversized record exists that no manifest
/// names. Recovery must truncate exactly the footer tail, leave the orphan
/// byte-identical, drop nothing committed, and let a later publication
/// resume the open segment without touching the orphan.
fn assert_seal_boundary_precommit(kind: HashKind) {
    let context = format!("seal-boundary precommit kill with {kind}");
    let root = fresh_root(&format!("seal-pre-{}", kind.format_name()));
    let root_arg = root.to_string_lossy().into_owned();
    let status = spawn_child(
        "publish_seal_boundary",
        "after_directory_sync@2",
        &[&root_arg, kind.format_name()],
    );
    assert_crashed(&status, &context);
    assert_acknowledged(&root, "a", &context);
    assert_unacknowledged(&root, "sealed", &context);

    let oid_a = blob_oid(kind, BLOB_A);
    let footer = usize_u64(FOOTER_LEN);
    let (manifests, objects) = committed_rows(&root);
    assert_eq!(
        manifests.len(),
        1,
        "{context}: only A's segment may be committed, got {manifests:?}"
    );
    let first = &manifests[0];
    assert!(
        first.id == 0 && !first.sealed && first.committed_end == first.records_end,
        "{context}: the committed manifest must still describe an open segment, got {first:?}"
    );
    let committed: Vec<Oid> = objects.iter().map(|(oid, _)| *oid).collect();
    assert_eq!(committed, [oid_a], "{context}: only A may be committed");
    let first_path = segment_path(&root, 0);
    assert_eq!(
        segment_len(&root, 0),
        first.committed_end + footer,
        "{context}: the roll must have written A's seal footer past its committed extent"
    );
    let footer_magic = read_range(&first_path, first.committed_end, SEAL_MAGIC.len());
    assert_eq!(
        footer_magic, SEAL_MAGIC,
        "{context}: the bytes past the committed extent must be a seal footer"
    );
    let orphan_path = segment_path(&root, 1);
    let orphan = file_fingerprint(&orphan_path);
    assert!(
        orphan.0 > SEGMENT_TARGET_BYTES,
        "{context}: the orphan must hold the oversized record, found {} bytes",
        orphan.0
    );
    let orphan_tail = read_range(&orphan_path, orphan.0 - footer, SEAL_MAGIC.len());
    assert_eq!(
        orphan_tail, SEAL_MAGIC,
        "{context}: the orphan segment must end in a seal footer"
    );

    let store = reopen(&root);
    assert!(
        !store.quarantine(),
        "{context}: a seal-boundary kill must not latch quarantine"
    );
    assert_eq!(
        segment_len(&root, 0),
        first.committed_end,
        "{context}: recovery must truncate the uncommitted footer tail"
    );
    assert_bytes(&store, oid_a, ObjectKind::Blob, BLOB_A).expect("A survives recovery");
    assert_refs_fact(&store, FACT_KEY_A, Some(oid_a.as_bytes()), &context);
    assert_refs_fact(&store, FACT_KEY_SEALED, None, &context);
    let oid_c = publish_small_blob(&store, kind, BLOB_B, FACT_KEY_B);
    assert_bytes(&store, oid_c, ObjectKind::Blob, BLOB_B).expect("C after recovery");
    drop(store);

    let (after, after_objects) = committed_rows(&root);
    assert_eq!(
        after.len(),
        1,
        "{context}: the open segment is resumed, got {after:?}"
    );
    let resumed = &after[0];
    let extended = !resumed.sealed && resumed.committed_end > first.committed_end;
    assert!(
        extended,
        "{context}: C must extend the open segment, got {resumed:?}"
    );
    assert_eq!(
        (segment_len(&root, 0), after_objects.len()),
        (resumed.committed_end, 2),
        "{context}: no footer bytes may survive and A and C are the only objects"
    );
    assert_eq!(
        file_fingerprint(&orphan_path),
        orphan,
        "{context}: the unknown orphan segment must survive recovery and publication"
    );
    let store = reopen(&root);
    assert_bytes(&store, oid_a, ObjectKind::Blob, BLOB_A).expect("A after the second reopen");
    assert_bytes(&store, oid_c, ObjectKind::Blob, BLOB_B).expect("C after the second reopen");
    assert_refs_fact(&store, FACT_KEY_SEALED, None, &context);
    drop(store);
    cleanup(&root);
}

/// Seal-boundary kill at `after_metadata_commit@2`.
///
/// The committed manifests seal both segments, each ending exactly at its
/// footer and never grown afterwards; the oversized record's extent exceeds
/// the real 256 MiB target. Reopen must verify both segments, return the
/// oversized blob byte-exact under the canonical identity computed here from
/// the generator alone, and let a later publication open a fresh segment
/// rather than append past a seal.
fn assert_seal_boundary_postcommit(kind: HashKind) {
    let context = format!("seal-boundary postcommit kill with {kind}");
    let root = fresh_root(&format!("seal-post-{}", kind.format_name()));
    let root_arg = root.to_string_lossy().into_owned();
    let status = spawn_child(
        "publish_seal_boundary",
        "after_metadata_commit@2",
        &[&root_arg, kind.format_name()],
    );
    assert_crashed(&status, &context);
    assert_acknowledged(&root, "a", &context);
    assert_unacknowledged(&root, "sealed", &context);

    let oid_a = blob_oid(kind, BLOB_A);
    let footer = usize_u64(FOOTER_LEN);
    let (manifests, objects) = committed_rows(&root);
    assert_eq!(
        manifests.len(),
        2,
        "{context}: both segments must be committed, got {manifests:?}"
    );
    for (id, manifest) in (0_u64..).zip(&manifests) {
        assert!(
            manifest.id == id && manifest.sealed && !manifest.retired,
            "{context}: segment {id} must be committed sealed, got {manifest:?}"
        );
        assert_eq!(
            (manifest.committed_end, segment_len(&root, id)),
            (manifest.records_end + footer, manifest.committed_end),
            "{context}: segment {id} must end exactly at its footer"
        );
    }
    let big = &manifests[1];
    assert!(
        big.records_end > SEGMENT_TARGET_BYTES,
        "{context}: the sealed record extent must exceed the real target, found {}",
        big.records_end
    );
    assert_eq!(
        objects.len(),
        2,
        "{context}: exactly A and the oversized object are committed"
    );
    let located = objects.iter().find(|(oid, _)| *oid != oid_a);
    let Some((oid_big, location)) = located else {
        panic!("{context}: the oversized locator must be committed");
    };
    let oid_big = *oid_big;
    assert_eq!(
        oid_big,
        noise_blob_oid(kind),
        "{context}: committed identity must be the canonical hash of the payload"
    );
    let placement = (location.segment, location.offset);
    assert_eq!(
        placement,
        (1, 0),
        "{context}: the oversized locator must name segment 1 at offset 0"
    );
    assert_eq!(
        (location.decoded_len, location.depth),
        (SEAL_BLOB_LEN, 0),
        "{context}: the oversized locator must carry the exact decoded length"
    );
    assert_eq!(
        location.offset + location.record_len,
        big.records_end,
        "{context}: the oversized record must fill its segment's record extent"
    );

    let sealed_rows = manifests.clone();
    let store = reopen(&root);
    assert!(
        !store.quarantine(),
        "{context}: a committed seal must not latch quarantine"
    );
    assert_bytes(&store, oid_a, ObjectKind::Blob, BLOB_A).expect("A survives reopen");
    assert_refs_fact(&store, FACT_KEY_A, Some(oid_a.as_bytes()), &context);
    let big_row = oid_big.as_bytes();
    assert_refs_fact(&store, FACT_KEY_SEALED, Some(big_row), &context);
    assert_noise_object(&store, oid_big);
    let oid_c = publish_small_blob(&store, kind, BLOB_B, FACT_KEY_B);
    assert_bytes(&store, oid_c, ObjectKind::Blob, BLOB_B).expect("C after reopen");
    drop(store);

    let (after, after_objects) = committed_rows(&root);
    assert_eq!(
        after.len(),
        3,
        "{context}: C must open a new segment, got {after:?}"
    );
    assert_eq!(
        &after[..2],
        sealed_rows.as_slice(),
        "{context}: sealed manifests must not change"
    );
    let third = &after[2];
    assert!(
        third.id == 2 && !third.sealed && third.committed_end == third.records_end,
        "{context}: C must land in a fresh open segment, got {third:?}"
    );
    assert_eq!(
        (segment_len(&root, 2), after_objects.len()),
        (third.committed_end, 3),
        "{context}: the new segment holds exactly C and the set has three objects"
    );
    for manifest in &after[..2] {
        assert_eq!(
            segment_len(&root, manifest.id),
            manifest.committed_end,
            "{context}: nothing may be appended after a seal"
        );
    }
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Parent tests: expectation machinery
// ---------------------------------------------------------------------------

/// Proves atomic fact semantics on a live store: a stale `Absent`
/// expectation refuses a duplicate same-path row, a wrong `Value`
/// expectation refuses without visible mutation, a duplicate
/// `(table, key)` pair inside one publish batch is rejected as invalid with
/// no partial rows, and satisfied expectations insert and remove exactly as
/// supplied.
#[test]
fn stale_expectations_reject_atomically_without_duplicate_rows() {
    let root = fresh_root("sha1-stale-expectations");
    let store = Store::create(&root, HashKind::Sha1, test_budget()).expect("create store");
    let oid = blob_oid(HashKind::Sha1, BLOB_A);
    let prepared = store
        .prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None)
        .expect("prepare");
    let refs_facts = [fact_mutation(
        FactTable::Refs,
        FACT_KEY_A,
        FactExpectation::Absent,
        Some(oid.as_bytes()),
    )];
    store
        .publish(
            vec![prepared],
            &refs_facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("initial publication");
    let duplicate = store
        .prepare(ObjectKind::Blob, len_u64(BLOB_A), BLOB_A, None)
        .expect("prepare for duplicate probe");
    match store.publish(
        vec![duplicate],
        &refs_facts,
        EventSource::LocalPush,
        &EventContext::default(),
    ) {
        Err(StoreError::StaleFact { .. }) => {}
        other => panic!(
            "duplicate same-path fact row must be refused with a stale \
             expectation, got ok={}",
            other.is_ok()
        ),
    }
    assert_bytes(&store, oid, ObjectKind::Blob, BLOB_A).expect("object untouched by refusal");
    assert_eq!(
        store.fact(FactTable::Refs, FACT_KEY_A).expect("fact read"),
        Some(oid.as_bytes().to_vec()),
        "refused duplicate must not touch the row"
    );
    let wrong_value = [fact_mutation(
        FactTable::Claims,
        CLAIM_KEY,
        FactExpectation::Value(b"wrong".to_vec()),
        Some(b"right"),
    )];
    match store.publish(
        Vec::new(),
        &wrong_value,
        EventSource::LocalPush,
        &EventContext::default(),
    ) {
        Err(StoreError::StaleFact { .. }) => {}
        other => panic!(
            "wrong value expectation must be refused, got ok={}",
            other.is_ok()
        ),
    }
    assert_eq!(
        store.fact(FactTable::Claims, CLAIM_KEY).expect("fact read"),
        None,
        "refused wrong-value expectation must not mutate"
    );
    let duplicate_batch = [
        fact_mutation(
            FactTable::Refs,
            FACT_KEY_DUP,
            FactExpectation::Absent,
            Some(b"first"),
        ),
        fact_mutation(
            FactTable::Refs,
            FACT_KEY_DUP,
            FactExpectation::Absent,
            Some(b"second"),
        ),
    ];
    match store.publish(
        Vec::new(),
        &duplicate_batch,
        EventSource::LocalPush,
        &EventContext::default(),
    ) {
        Err(StoreError::Invalid(_)) => {}
        other => panic!(
            "duplicate (table, key) inside one publish batch must be rejected \
             as invalid, got ok={}",
            other.is_ok()
        ),
    }
    assert_eq!(
        store
            .fact(FactTable::Refs, FACT_KEY_DUP)
            .expect("fact read"),
        None,
        "rejected duplicate batch must leave no partial row"
    );
    let insert = [fact_mutation(
        FactTable::Claims,
        CLAIM_KEY,
        FactExpectation::Absent,
        Some(b"right"),
    )];
    store
        .publish(
            Vec::new(),
            &insert,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("satisfied insert");
    assert_eq!(
        store.fact(FactTable::Claims, CLAIM_KEY).expect("fact read"),
        Some(b"right".to_vec()),
        "satisfied expectation inserts"
    );
    let remove = [fact_mutation(
        FactTable::Claims,
        CLAIM_KEY,
        FactExpectation::Value(b"right".to_vec()),
        None,
    )];
    store
        .publish(
            Vec::new(),
            &remove,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("satisfied remove");
    assert_eq!(
        store.fact(FactTable::Claims, CLAIM_KEY).expect("fact read"),
        None,
        "satisfied expectation removes"
    );
    drop(store);
    cleanup(&root);
}
