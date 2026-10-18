//! Adversarial tests for segment framing, seal footers and extent checks.
//!
//! Expected bytes never come from the code under test. A bit-by-bit CRC32C
//! (anchored to published vectors) and a hand-rolled frame builder produce
//! reference bytes, and one fixture is frozen as hex literals computed
//! outside this crate. Corruption cases flip, cut and splice those bytes and
//! demand `Corrupt`, never success and never a plain I/O error.

use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::segment::{
    FOOTER_LEN, HEADER_LEN, MAX_RECORD_PAYLOAD, RecordAppended, RecordHeader, RecordPayload,
    SEAL_MAGIC, SEGMENT_TARGET_BYTES, SegmentError, SegmentWriter, read_record_header,
    record_len_for, scan_records, segment_file_name, validate_segment_file,
    validate_segment_layout, verify_seal,
};
use super::types::{Encoding, ObjectKind};

// ---------------------------------------------------------------------------
// Independent reference implementation and frozen fixture
// ---------------------------------------------------------------------------

/// Bit-by-bit CRC32C (reflected Castagnoli polynomial). Deliberately not the
/// table/hardware implementation the module under test uses.
fn crc_ref(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn plen(payload: &[u8]) -> u64 {
    u64::try_from(payload.len()).expect("length fits u64")
}

/// A record built straight from the wire description, with a valid checksum,
/// from raw kind/flag bytes (so unknown values can be framed too).
fn frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("test payload fits u32");
    let mut out = len.to_le_bytes().to_vec();
    out.push(kind);
    out.push(flags);
    let mut covered = out.clone();
    covered.extend_from_slice(payload);
    out.extend_from_slice(&crc_ref(&covered).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// A footer with a valid self-checksum over the given fields.
fn seal_footer(magic: [u8; 8], extent: u64, region_crc: u32) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend_from_slice(&extent.to_le_bytes());
    out.extend_from_slice(&region_crc.to_le_bytes());
    let crc = crc_ref(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("ascii hex");
            u8::from_str_radix(digits, 16).expect("hex digit pair")
        })
        .collect()
}

type Rec = (u8, u8, Vec<u8>);

/// Four records covering every flag spelling and an empty payload:
/// (Blob, Raw, "123456789"), (Commit, Delta, 5 bytes), (Conflict, Zstd, empty),
/// (Tag, Zstd, "abc").
fn fixture() -> Vec<Rec> {
    vec![
        (1, 0, b"123456789".to_vec()),
        (3, 3, vec![0x00, 0xff, 0x10, 0x80, 0x7f]),
        (5, 1, Vec::new()),
        (4, 1, b"abc".to_vec()),
    ]
}

/// The fixture's four records as frozen bytes (record 1 is 19 bytes, 2 is 15,
/// 3 is 10, 4 is 13); CRCs computed outside this crate by an independent
/// bitwise implementation.
const FIXTURE_RECORDS_HEX: [&str; 4] = [
    "090000000100eb5751c9313233343536373839",
    "05000000030345caef6b00ff10807f",
    "000000000501220669f8",
    "0300000004014fec65c9616263",
];
const FIXTURE_OFFSETS: [u64; 4] = [0, 19, 34, 44];
const FIXTURE_RECORD_LENS: [u64; 4] = [19, 15, 10, 13];
const FIXTURE_RECORDS_END: u64 = 57;
const FIXTURE_REGION_CRC: u32 = 0x4a3d_d08a;
const FIXTURE_FOOTER_HEX: &str = "52554b5345414c3139000000000000008ad03d4a4405406e";
const FIXTURE_SEALED_END: u64 = 81;

fn fixture_records() -> Vec<u8> {
    FIXTURE_RECORDS_HEX
        .iter()
        .flat_map(|record| unhex(record))
        .collect()
}

fn fixture_sealed() -> Vec<u8> {
    let mut bytes = fixture_records();
    bytes.extend(unhex(FIXTURE_FOOTER_HEX));
    bytes
}

fn kind_of(byte: u8) -> ObjectKind {
    ObjectKind::from_repr(byte).expect("known kind byte")
}

fn encoding_of(byte: u8) -> Encoding {
    Encoding::from_repr(byte).expect("known flag byte")
}

/// Deterministic, non-constant filler with no relation to the CRC.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            u8::try_from(i % 251)
                .expect("below 251")
                .wrapping_mul(31)
                .wrapping_add(seed)
        })
        .collect()
}

fn open_cursor() -> SegmentWriter<Cursor<Vec<u8>>> {
    SegmentWriter::fresh(Cursor::new(Vec::new())).expect("fresh writer")
}

fn written(writer: &SegmentWriter<Cursor<Vec<u8>>>) -> &Vec<u8> {
    writer.get_ref().get_ref()
}

fn append_all<W: Write + Seek>(
    writer: &mut SegmentWriter<W>,
    records: &[Rec],
) -> Vec<RecordAppended> {
    records
        .iter()
        .map(|(kind, flags, payload)| {
            writer
                .append(
                    kind_of(*kind),
                    encoding_of(*flags),
                    plen(payload),
                    crc_ref(payload),
                    payload.as_slice(),
                )
                .expect("append")
        })
        .collect()
}

fn corrupt_detail<T: Debug>(result: Result<T, SegmentError>) -> String {
    match result {
        Err(SegmentError::Corrupt(detail)) => detail,
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

fn capacity_detail<T: Debug>(result: Result<T, SegmentError>) -> String {
    match result {
        Err(SegmentError::Capacity(detail)) => detail,
        other => panic!("expected Capacity, got {other:?}"),
    }
}

fn invalid_what<T: Debug>(result: Result<T, SegmentError>) -> &'static str {
    match result {
        Err(SegmentError::Invalid { what, .. }) => what,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

fn scan_vec(bytes: &[u8], records_end: u64) -> Result<u32, SegmentError> {
    scan_records(&mut Cursor::new(bytes.to_vec()), records_end, |_, _| ())
}

// ---------------------------------------------------------------------------
// Sinks and sources that misbehave
// ---------------------------------------------------------------------------

/// A sparse stream that only tracks length and position, so u64-edge extent
/// arithmetic is testable without a petabyte of memory.
#[derive(Debug)]
struct Hole {
    len: u64,
    pos: u64,
    written: u64,
}

impl Hole {
    fn at(len: u64) -> Self {
        Self {
            len,
            pos: len,
            written: 0,
        }
    }
}

impl Write for Hole {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = plen(buf);
        self.pos = self
            .pos
            .checked_add(n)
            .ok_or_else(|| io::Error::other("hole position overflow"))?;
        self.len = self.len.max(self.pos);
        self.written += n;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for Hole {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::End(delta) => self.len.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
        };
        self.pos = target.ok_or_else(|| io::Error::other("hole seek out of range"))?;
        Ok(self.pos)
    }
}

/// Accepts `budget` bytes, then fails like a full disk.
#[derive(Debug)]
struct FailAfter {
    inner: Cursor<Vec<u8>>,
    budget: usize,
}

impl Write for FailAfter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.budget == 0 {
            return Err(io::Error::new(io::ErrorKind::StorageFull, "disk full"));
        }
        let n = buf.len().min(self.budget);
        let n = self.inner.write(&buf[..n])?;
        self.budget -= n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for FailAfter {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.inner.seek(to)
    }
}

/// Counts `write` calls, so tests can pin that staged appends batch into
/// one flush instead of one syscall per record.
#[derive(Debug, Default)]
struct CountWrites {
    inner: Cursor<Vec<u8>>,
    writes: usize,
}

impl Write for CountWrites {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for CountWrites {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.inner.seek(to)
    }
}

/// Serves filler bytes, then fails with a non-EOF I/O error.
#[derive(Debug)]
struct BrokenReader {
    served: usize,
    fail_at: usize,
}

impl Read for BrokenReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.served >= self.fail_at {
            return Err(io::Error::other("device gone"));
        }
        let n = buf.len().min(self.fail_at - self.served);
        buf[..n].fill(7);
        self.served += n;
        Ok(n)
    }
}

/// A payload source that must never be touched: any read is an I/O failure,
/// so a test expecting a typed rejection sees `Io` instead and fails.
#[derive(Debug)]
struct Tripwire;

impl Read for Tripwire {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other(
            "the payload must not be read when the declaration is rejected",
        ))
    }
}

// ---------------------------------------------------------------------------
// Wire literals and the CRC anchor
// ---------------------------------------------------------------------------

#[test]
fn discriminants_and_sizes_are_the_wire_contract() {
    use Encoding::{Delta, Raw, Zstd};
    use ObjectKind::{Blob, Commit, Conflict, Tag, Tree};
    assert_eq!(
        [Blob, Tree, Commit, Tag, Conflict].map(ObjectKind::to_repr),
        [1, 2, 3, 4, 5]
    );
    assert_eq!([Raw, Zstd, Delta].map(Encoding::to_repr), [0, 1, 3]);
    assert_eq!(HEADER_LEN, 10);
    assert_eq!(FOOTER_LEN, 24);
    assert_eq!(SEAL_MAGIC, *b"RUKSEAL1");
    assert_eq!(MAX_RECORD_PAYLOAD, 4_294_967_295);
    assert_eq!(SEGMENT_TARGET_BYTES, 256 * 1024 * 1024);
}

#[test]
fn reference_crc_matches_published_castagnoli_vectors() {
    // RFC 3720 appendix B.4 and the standard "123456789" check value.
    assert_eq!(crc_ref(b"123456789"), 0xE306_9283);
    assert_eq!(crc_ref(&[0_u8; 32]), 0x8A91_36AA);
    assert_eq!(crc_ref(&[0xFF_u8; 32]), 0x62A8_AB43);
    let ascending: Vec<u8> = (0..32).collect();
    assert_eq!(crc_ref(&ascending), 0x46DD_794E);
    let descending: Vec<u8> = (0..32).rev().collect();
    assert_eq!(crc_ref(&descending), 0x113F_DB5C);
    assert_eq!(crc_ref(&[]), 0);
}

#[test]
fn frame_builder_reproduces_the_frozen_fixture() {
    let built: Vec<u8> = fixture()
        .iter()
        .flat_map(|(kind, flags, payload)| frame(*kind, *flags, payload))
        .collect();
    assert_eq!(built, fixture_records());
    assert_eq!(plen(&built), FIXTURE_RECORDS_END);
    assert_eq!(crc_ref(&built), FIXTURE_REGION_CRC);
    assert_eq!(
        seal_footer(*b"RUKSEAL1", FIXTURE_RECORDS_END, FIXTURE_REGION_CRC),
        unhex(FIXTURE_FOOTER_HEX)
    );
}

// ---------------------------------------------------------------------------
// Writer: golden bytes, density, chunk boundaries, resumption
// ---------------------------------------------------------------------------

#[test]
fn writer_emits_the_golden_segment_bytes() {
    let mut writer = open_cursor();
    let appended = append_all(&mut writer, &fixture());
    assert_eq!(
        appended.iter().map(|a| a.offset).collect::<Vec<_>>(),
        FIXTURE_OFFSETS
    );
    assert_eq!(
        appended.iter().map(|a| a.record_len).collect::<Vec<_>>(),
        FIXTURE_RECORD_LENS
    );
    writer
        .flush_staged()
        .expect("staged bytes reach the stream");
    assert_eq!(written(&writer), &fixture_records());
    assert_eq!(writer.records_end(), FIXTURE_RECORDS_END);
    assert_eq!(writer.records_crc(), FIXTURE_REGION_CRC);
    assert_eq!(writer.committed_end(), FIXTURE_RECORDS_END);
    assert!(!writer.is_sealed());

    assert_eq!(writer.seal().expect("seal"), FIXTURE_SEALED_END);
    assert_eq!(written(&writer), &fixture_sealed());
    assert!(writer.is_sealed());
    assert_eq!(writer.records_end(), FIXTURE_RECORDS_END);
    assert_eq!(writer.committed_end(), FIXTURE_SEALED_END);
}

#[test]
fn frozen_fixture_verifies_scans_and_reads_back() {
    let sealed = fixture_sealed();
    let verified = validate_segment_file(
        &mut Cursor::new(sealed.clone()),
        FIXTURE_SEALED_END,
        FIXTURE_RECORDS_END,
        true,
    )
    .expect("sealed fixture validates");
    assert_eq!(verified.records_crc, FIXTURE_REGION_CRC);
    assert_eq!(verified.file_len, FIXTURE_SEALED_END);

    let mut seen: Vec<(u64, ObjectKind, Encoding, u32, u64)> = Vec::new();
    let crc = scan_records(
        &mut Cursor::new(sealed.clone()),
        FIXTURE_RECORDS_END,
        |offset, header| {
            seen.push((
                offset,
                header.kind,
                header.encoding,
                header.payload_len,
                header.record_len(),
            ));
        },
    )
    .expect("scan");
    assert_eq!(crc, FIXTURE_REGION_CRC);
    assert_eq!(
        seen,
        vec![
            (0, ObjectKind::Blob, Encoding::Raw, 9, 19),
            (19, ObjectKind::Commit, Encoding::Delta, 5, 15),
            (34, ObjectKind::Conflict, Encoding::Zstd, 0, 10),
            (44, ObjectKind::Tag, Encoding::Zstd, 3, 13),
        ]
    );

    for (index, (_, _, payload)) in fixture().iter().enumerate() {
        let mut reader = RecordPayload::open(
            Cursor::new(sealed.clone()),
            FIXTURE_OFFSETS[index],
            FIXTURE_RECORDS_END,
        )
        .expect("open record");
        assert_eq!(reader.header().record_len(), FIXTURE_RECORD_LENS[index]);
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("read payload");
        assert_eq!(&got, payload);
        reader.finish().expect("record verifies");
    }
}

#[test]
fn record_offsets_are_dense_across_chunk_boundaries() {
    // Sizes straddle the writer's 64 KiB record buffer: a record of exactly
    // one buffer (payload 65_526), one byte over, two buffers, and more.
    let sizes = [
        0_usize, 1, 9, 10, 11, 65_525, 65_526, 65_527, 65_535, 65_536, 65_537, 131_062, 131_072,
        200_003,
    ];
    let records: Vec<Rec> = sizes
        .iter()
        .enumerate()
        .map(|(i, &len)| {
            let kind = u8::try_from(i % 5).expect("small") + 1;
            let flags = [0, 1, 3][i % 3];
            (kind, flags, pattern(len, u8::try_from(i).expect("small")))
        })
        .collect();

    let mut writer = open_cursor();
    let appended = append_all(&mut writer, &records);
    let expected: Vec<u8> = records
        .iter()
        .flat_map(|(kind, flags, payload)| frame(*kind, *flags, payload))
        .collect();
    writer
        .flush_staged()
        .expect("staged bytes reach the stream");
    assert_eq!(written(&writer), &expected);

    let mut next = 0_u64;
    for (record, placed) in records.iter().zip(&appended) {
        assert_eq!(placed.offset, next, "no hole before a record");
        assert_eq!(placed.record_len, 10 + plen(&record.2));
        next += placed.record_len;
    }
    assert_eq!(writer.records_end(), next);
    assert_eq!(writer.records_end(), plen(&expected));
    assert_eq!(writer.records_crc(), crc_ref(&expected));

    let mut cursor = Cursor::new(expected.clone());
    let mut offsets = Vec::new();
    let crc = scan_records(&mut cursor, next, |offset, _| offsets.push(offset)).expect("scan");
    assert_eq!(crc, crc_ref(&expected));
    assert_eq!(
        offsets,
        appended.iter().map(|a| a.offset).collect::<Vec<_>>()
    );

    for (record, placed) in records.iter().zip(&appended) {
        let mut reader = RecordPayload::open(&mut cursor, placed.offset, next).expect("open");
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("read");
        assert_eq!(got, record.2);
        reader.finish().expect("finish");
    }
}

#[test]
fn resumed_writer_continues_the_records_checksum_chain() {
    let all = fixture();
    let mut first = open_cursor();
    append_all(&mut first, &all[..2]);
    first.flush_staged().expect("staged bytes reach the stream");
    let (end, crc, bytes) = (
        first.records_end(),
        first.records_crc(),
        written(&first).clone(),
    );
    drop(first);

    let mut second = SegmentWriter::resumed(Cursor::new(bytes), end, crc).expect("resume");
    append_all(&mut second, &all[2..]);
    second
        .flush_staged()
        .expect("staged bytes reach the stream");
    assert_eq!(written(&second), &fixture_records());
    assert_eq!(second.records_crc(), FIXTURE_REGION_CRC);
    assert_eq!(second.seal().expect("seal"), FIXTURE_SEALED_END);
    assert_eq!(written(&second), &fixture_sealed());
}

#[test]
fn writers_refuse_streams_that_do_not_match_the_committed_extent() {
    let non_empty = Cursor::new(vec![0_u8; 3]);
    assert_eq!(
        invalid_what(SegmentWriter::fresh(non_empty)),
        "segment stream"
    );

    // A sealed file is longer than its records extent: never reopened.
    let sealed = Cursor::new(fixture_sealed());
    assert_eq!(
        invalid_what(SegmentWriter::resumed(
            sealed,
            FIXTURE_RECORDS_END,
            FIXTURE_REGION_CRC
        )),
        "segment stream"
    );
    // An uncommitted tail must be truncated first; a short file is refused too.
    let mut tail = fixture_records();
    tail.push(0);
    assert_eq!(
        invalid_what(SegmentWriter::resumed(
            Cursor::new(tail),
            FIXTURE_RECORDS_END,
            FIXTURE_REGION_CRC
        )),
        "segment stream"
    );
    let short = fixture_records()[..56].to_vec();
    assert_eq!(
        invalid_what(SegmentWriter::resumed(
            Cursor::new(short),
            FIXTURE_RECORDS_END,
            FIXTURE_REGION_CRC
        )),
        "segment stream"
    );
}

#[test]
fn seal_is_final() {
    let mut writer = open_cursor();
    append_all(&mut writer, &fixture());
    writer.seal().expect("seal");
    let sealed_bytes = written(&writer).clone();

    assert_eq!(
        invalid_what(writer.append(ObjectKind::Blob, Encoding::Raw, 0, 0, io::empty())),
        "sealed segment"
    );
    assert_eq!(invalid_what(writer.seal()), "sealed segment");
    assert_eq!(written(&writer), &sealed_bytes, "refusals write nothing");
}

#[test]
fn empty_segments_seal_and_verify() {
    let mut writer = open_cursor();
    assert_eq!(writer.seal().expect("seal empty"), 24);
    assert_eq!(written(&writer), &seal_footer(*b"RUKSEAL1", 0, 0));
    let verified = validate_segment_file(&mut Cursor::new(written(&writer).clone()), 24, 0, true)
        .expect("empty sealed segment validates");
    assert_eq!(verified.records_crc, 0);
    assert_eq!(verified.file_len, 24);

    let open = validate_segment_file(&mut Cursor::new(Vec::new()), 0, 0, false)
        .expect("empty open segment validates");
    assert_eq!(open.file_len, 0);
}

// ---------------------------------------------------------------------------
// Writer: arithmetic, declaration checks, failure poisoning
// ---------------------------------------------------------------------------

#[test]
fn payload_length_is_checked_against_the_u32_framing_limit() {
    assert_eq!(record_len_for(0).expect("empty"), 10);
    assert_eq!(record_len_for(1).expect("one"), 11);
    assert_eq!(
        record_len_for(4_294_967_295).expect("largest"),
        4_294_967_305
    );
    for too_big in [4_294_967_296, u64::MAX] {
        assert!(capacity_detail(record_len_for(too_big)).contains("record limit"));
    }

    let mut writer = open_cursor();
    for too_big in [4_294_967_296, u64::MAX] {
        let result = writer.append(ObjectKind::Blob, Encoding::Zstd, too_big, 0, Tripwire);
        assert!(capacity_detail(result).contains("record limit"));
    }
    // Nothing was written and the writer is not poisoned: no hole, no closure.
    assert_eq!(writer.records_end(), 0);
    assert!(written(&writer).is_empty());
    let placed = append_all(&mut writer, &fixture()[..1]);
    assert_eq!(placed[0].offset, 0);
}

#[test]
fn segment_extents_use_checked_u64_arithmetic() {
    // The record itself would overflow u64.
    let mut writer = SegmentWriter::resumed(Hole::at(u64::MAX - 5), u64::MAX - 5, 0).expect("hole");
    let result = writer.append(ObjectKind::Blob, Encoding::Raw, 0, 0, io::empty());
    assert!(capacity_detail(result).contains("overflows u64"));
    assert_eq!(writer.get_ref().written, 0);
    // Still usable (not poisoned): the same refusal, not "poisoned".
    let again = writer.append(ObjectKind::Blob, Encoding::Raw, 0, 0, io::empty());
    assert!(capacity_detail(again).contains("overflows u64"));

    // The record fits but its footer could not: refuse now, not at seal time.
    let mut writer =
        SegmentWriter::resumed(Hole::at(u64::MAX - 30), u64::MAX - 30, 0).expect("hole");
    let result = writer.append(ObjectKind::Blob, Encoding::Raw, 0, 0, io::empty());
    assert!(capacity_detail(result).contains("overflows u64"));
    assert_eq!(writer.get_ref().written, 0);

    // Exactly representable with footer: appends, then seals to u64::MAX.
    let start = u64::MAX - 34;
    let mut writer = SegmentWriter::resumed(Hole::at(start), start, 0).expect("hole");
    let placed = writer
        .append(ObjectKind::Blob, Encoding::Raw, 0, 0, io::empty())
        .expect("last record that leaves footer room");
    assert_eq!(placed.offset, start);
    assert_eq!(writer.records_end(), u64::MAX - 24);
    assert_eq!(writer.seal().expect("seal at the edge"), u64::MAX);
    assert_eq!(writer.committed_end(), u64::MAX);

    // Sealing without footer room is a capacity error and does not poison.
    let mut writer =
        SegmentWriter::resumed(Hole::at(u64::MAX - 10), u64::MAX - 10, 0).expect("hole");
    assert!(capacity_detail(writer.seal()).contains("overflows u64"));
    assert!(!writer.is_sealed());
    assert!(capacity_detail(writer.seal()).contains("overflows u64"));
}

#[test]
fn target_size_is_a_checked_placement_hint() {
    let writer = SegmentWriter::resumed(
        Hole::at(SEGMENT_TARGET_BYTES - 5),
        SEGMENT_TARGET_BYTES - 5,
        0,
    )
    .expect("hole");
    assert!(writer.fits_target(5));
    assert!(!writer.fits_target(6));
    assert!(
        !writer.fits_target(u64::MAX),
        "overflow is a refusal, not a panic"
    );
    let fresh = open_cursor();
    assert!(fresh.fits_target(SEGMENT_TARGET_BYTES));
    assert!(!fresh.fits_target(SEGMENT_TARGET_BYTES + 1));
}

#[test]
fn short_payload_source_poisons_the_writer_and_leaves_the_extent_alone() {
    let mut writer = open_cursor();
    let short = &[7_u8; 4][..];
    let result = writer.append(
        ObjectKind::Blob,
        Encoding::Zstd,
        10,
        crc_ref(&[7; 10]),
        short,
    );
    assert!(matches!(result, Err(SegmentError::Invalid { .. })));
    assert_eq!(writer.records_end(), 0);
    assert_eq!(writer.records_crc(), 0);

    let retry = writer.append(ObjectKind::Blob, Encoding::Raw, 0, 0, io::empty());
    assert!(matches!(retry, Err(SegmentError::Poisoned)));
    assert!(matches!(writer.seal(), Err(SegmentError::Poisoned)));
    assert_eq!(writer.records_end(), 0);
    assert!(!writer.is_sealed());
}

#[test]
fn payload_checksum_mismatch_is_corruption_and_poisons() {
    let mut writer = open_cursor();
    let result = writer.append(
        ObjectKind::Blob,
        Encoding::Zstd,
        3,
        0xdead_beef,
        &b"abc"[..],
    );
    assert!(matches!(result, Err(SegmentError::Corrupt(_))));
    assert_eq!(
        writer.records_end(),
        0,
        "the bad record is not part of the extent"
    );
    let retry = writer.append(ObjectKind::Blob, Encoding::Raw, 0, 0, io::empty());
    assert!(matches!(retry, Err(SegmentError::Poisoned)));
}

#[test]
fn payload_source_io_failure_and_sink_failure_poison() {
    let mut writer = open_cursor();
    let result = writer.append(
        ObjectKind::Blob,
        Encoding::Zstd,
        10,
        0,
        BrokenReader {
            served: 0,
            fail_at: 5,
        },
    );
    match result {
        Err(SegmentError::Io(err)) => assert_eq!(err.kind(), io::ErrorKind::Other),
        other => panic!("expected Io, got {other:?}"),
    }
    assert_eq!(writer.records_end(), 0);
    assert!(matches!(
        writer.append(ObjectKind::Blob, Encoding::Raw, 0, 0, io::empty()),
        Err(SegmentError::Poisoned)
    ));

    // Small records stage in memory without touching the sink: the append
    // succeeds and the full disk surfaces at the flush, which poisons the
    // writer just as a direct write failure would.
    let sink = FailAfter {
        inner: Cursor::new(Vec::new()),
        budget: 3,
    };
    let mut writer = SegmentWriter::fresh(sink).expect("fresh");
    let placed = writer
        .append(
            ObjectKind::Blob,
            Encoding::Raw,
            9,
            crc_ref(b"123456789"),
            &b"123456789"[..],
        )
        .expect("a small record stages without touching the sink");
    assert_eq!(placed.record_len, 19);
    match writer.flush_staged() {
        Err(SegmentError::Io(err)) => assert_eq!(err.kind(), io::ErrorKind::StorageFull),
        other => panic!("expected Io, got {other:?}"),
    }
    assert!(matches!(
        writer.append(ObjectKind::Blob, Encoding::Raw, 0, 0, io::empty()),
        Err(SegmentError::Poisoned)
    ));
    assert!(matches!(writer.seal(), Err(SegmentError::Poisoned)));
}

#[test]
fn staged_appends_batch_into_one_write_per_flush() {
    let mut writer = SegmentWriter::fresh(CountWrites::default()).expect("fresh");
    let records = fixture();
    let appended = append_all(&mut writer, &records);
    assert_eq!(
        writer.get_ref().writes,
        0,
        "appends stage in memory without touching the stream"
    );
    writer.flush_staged().expect("flush");
    assert_eq!(
        writer.get_ref().writes,
        1,
        "one flush writes the whole staging in one call"
    );
    assert_eq!(
        writer.get_ref().inner.get_ref(),
        &fixture_records(),
        "batched bytes match the unbuffered framing"
    );
    writer.flush_staged().expect("empty flush is a no-op");
    assert_eq!(writer.get_ref().writes, 1);
    assert_eq!(appended.len(), records.len());
}

#[test]
fn large_record_flushes_mid_record_and_stays_byte_identical() {
    // A record larger than the staging bound flushes mid-record: memory
    // stays bounded and the streamed bytes still match the framing.
    let payload = pattern(9_000_000, 7);
    let mut writer = SegmentWriter::fresh(CountWrites::default()).expect("fresh");
    let placed = writer
        .append(
            ObjectKind::Blob,
            Encoding::Raw,
            plen(&payload),
            crc_ref(&payload),
            payload.as_slice(),
        )
        .expect("large record stages");
    assert_eq!(placed.record_len, 10 + plen(&payload));
    assert_eq!(
        writer.get_ref().writes,
        1,
        "staging past the bound flushes mid-record"
    );
    writer.flush_staged().expect("flush the tail");
    assert_eq!(writer.get_ref().writes, 2);
    assert_eq!(
        writer.get_ref().inner.get_ref(),
        &frame(1, 0, &payload),
        "flushed pieces concatenate to the exact framing"
    );
    assert_eq!(writer.records_end(), 10 + plen(&payload));
    assert_eq!(
        writer.records_crc(),
        crc_ref(writer.get_ref().inner.get_ref())
    );
}

#[test]
fn checksum_mismatch_after_a_mid_record_flush_still_poisons() {
    // The bad record's flushed prefix sits beyond the extent (the poisoned
    // state recovery truncates); the writer still reports an empty extent
    // and refuses everything after.
    let payload = pattern(9_000_000, 9);
    let mut writer = SegmentWriter::fresh(CountWrites::default()).expect("fresh");
    let result = writer.append(
        ObjectKind::Blob,
        Encoding::Raw,
        plen(&payload),
        0xdead_beef,
        payload.as_slice(),
    );
    assert!(matches!(result, Err(SegmentError::Corrupt(_))));
    assert_eq!(writer.records_end(), 0);
    assert_eq!(writer.committed_end(), 0);
    assert!(matches!(
        writer.append(ObjectKind::Blob, Encoding::Raw, 0, 0, io::empty()),
        Err(SegmentError::Poisoned)
    ));
    assert!(matches!(writer.seal(), Err(SegmentError::Poisoned)));
}

#[test]
fn failed_footer_write_poisons_and_does_not_seal() {
    // Enough room for the first record (19 bytes) but only 5 footer bytes.
    let sink = FailAfter {
        inner: Cursor::new(Vec::new()),
        budget: 19 + 5,
    };
    let mut writer = SegmentWriter::fresh(sink).expect("fresh");
    append_all(&mut writer, &fixture()[..1]);
    match writer.seal() {
        Err(SegmentError::Io(err)) => assert_eq!(err.kind(), io::ErrorKind::StorageFull),
        other => panic!("expected Io, got {other:?}"),
    }
    assert!(!writer.is_sealed());
    assert_eq!(writer.committed_end(), 19);
    assert!(matches!(writer.seal(), Err(SegmentError::Poisoned)));
}

#[test]
fn source_longer_than_declared_is_not_over_read() {
    let mut source = Cursor::new(vec![9_u8; 100]);
    let mut writer = open_cursor();
    writer
        .append(
            ObjectKind::Blob,
            Encoding::Raw,
            10,
            crc_ref(&[9; 10]),
            &mut source,
        )
        .expect("append");
    assert_eq!(source.position(), 10);
    writer
        .flush_staged()
        .expect("staged bytes reach the stream");
    assert_eq!(written(&writer), &frame(1, 0, &[9; 10]));
}

#[test]
fn copying_from_a_truncated_record_keeps_the_corrupt_diagnosis() {
    // Compaction-style copy: the source record is short on disk. The writer
    // must report corruption, not blame its own caller's declaration.
    let truncated = fixture_records()[..12].to_vec();
    let source = RecordPayload::open(Cursor::new(truncated), 0, 19).expect("header present");
    let mut writer = open_cursor();
    let result = writer.append(
        ObjectKind::Blob,
        Encoding::Raw,
        9,
        crc_ref(b"123456789"),
        source,
    );
    assert!(matches!(result, Err(SegmentError::Corrupt(_))));
    assert!(matches!(
        writer.append(ObjectKind::Blob, Encoding::Raw, 0, 0, io::empty()),
        Err(SegmentError::Poisoned)
    ));
}

// ---------------------------------------------------------------------------
// Header validation
// ---------------------------------------------------------------------------

#[test]
fn every_unknown_kind_or_flag_byte_is_rejected_even_with_a_valid_checksum() {
    for kind in 0..=u8::MAX {
        let bytes = frame(kind, 0, b"x");
        let end = plen(&bytes);
        let header = read_record_header(&mut Cursor::new(bytes.clone()), 0, end);
        let scanned = scan_vec(&bytes, end);
        if (1..=5).contains(&kind) {
            assert_eq!(header.expect("known kind").kind, kind_of(kind));
            scanned.expect("known kind scans");
        } else {
            assert!(
                corrupt_detail(header).contains("unknown object kind"),
                "kind {kind}"
            );
            assert!(
                corrupt_detail(scanned).contains("unknown object kind"),
                "kind {kind}"
            );
        }
    }
    for flags in 0..=u8::MAX {
        let bytes = frame(1, flags, b"x");
        let end = plen(&bytes);
        let header = read_record_header(&mut Cursor::new(bytes.clone()), 0, end);
        let scanned = scan_vec(&bytes, end);
        if [0, 1, 3].contains(&flags) {
            assert_eq!(header.expect("known flags").encoding, encoding_of(flags));
            scanned.expect("known flags scan");
        } else {
            assert!(
                corrupt_detail(header).contains("unknown flags"),
                "flags {flags}"
            );
            assert!(
                corrupt_detail(scanned).contains("unknown flags"),
                "flags {flags}"
            );
        }
    }
    for kind in 1..=5_u8 {
        for flags in [0_u8, 1, 3] {
            let bytes = frame(kind, flags, b"payload");
            let end = plen(&bytes);
            let header: RecordHeader =
                read_record_header(&mut Cursor::new(bytes), 0, end).expect("valid pair");
            assert_eq!(
                (header.kind, header.encoding),
                (kind_of(kind), encoding_of(flags))
            );
            assert_eq!(header.payload_len, 7);
        }
    }
}

#[test]
fn records_cannot_cross_the_committed_extent_or_reach_into_the_footer() {
    let sealed = fixture_sealed();
    let at =
        |offset: u64, end: u64| read_record_header(&mut Cursor::new(sealed.clone()), offset, end);

    assert_eq!(
        at(44, FIXTURE_RECORDS_END)
            .expect("last record")
            .payload_len,
        3
    );
    // One byte short of the record's payload: the record would cross.
    assert!(corrupt_detail(at(44, 56)).contains("remain inside"));
    // The footer is not a record, whatever bytes it holds.
    assert!(corrupt_detail(at(FIXTURE_RECORDS_END, FIXTURE_RECORDS_END)).contains("does not fit"));
    assert!(corrupt_detail(at(FIXTURE_RECORDS_END, FIXTURE_SEALED_END - 14)).contains("unknown"));
    // Header itself would cross, or the offset is absurd.
    assert!(corrupt_detail(at(48, FIXTURE_RECORDS_END)).contains("does not fit"));
    assert!(corrupt_detail(at(u64::MAX, u64::MAX)).contains("does not fit"));
    assert!(corrupt_detail(at(u64::MAX - 9, u64::MAX)).contains("does not fit"));
    assert!(corrupt_detail(at(0, 0)).contains("does not fit"));
    assert!(corrupt_detail(at(0, 9)).contains("does not fit"));
}

#[test]
fn a_record_claiming_four_gigabytes_is_refused_before_any_allocation() {
    // len = u32::MAX with a valid checksum over its three real bytes' prefix.
    let mut bytes = u32::MAX.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(b"abc");
    let end = plen(&bytes);
    assert!(
        corrupt_detail(read_record_header(&mut Cursor::new(bytes.clone()), 0, end))
            .contains("remain inside")
    );
    assert!(corrupt_detail(scan_vec(&bytes, end)).contains("spans"));

    // With a (wrong) huge extent the claim is plausible; reading hits real EOF.
    let mut reader = RecordPayload::open(Cursor::new(bytes), 0, u64::MAX).expect("claim fits u64");
    assert_eq!(reader.header().payload_len, u32::MAX);
    let mut got = Vec::new();
    let err = reader.read_to_end(&mut got).expect_err("truncated");
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(got, b"abc");
    assert!(corrupt_detail(Err::<(), _>(SegmentError::from(err))).contains("truncated"));
    assert!(corrupt_detail(reader.finish()).contains("truncated"));
}

#[test]
fn a_lying_length_field_never_verifies() {
    let genuine = frame(1, 0, b"abcd");
    for claimed in [0_u32, 1, 3, 5, 6, 1000] {
        let mut lying = genuine.clone();
        lying[..4].copy_from_slice(&claimed.to_le_bytes());
        let end = plen(&lying);
        assert!(
            matches!(scan_vec(&lying, end), Err(SegmentError::Corrupt(_))),
            "claimed {claimed}"
        );
    }
}

// ---------------------------------------------------------------------------
// Scanning: boundaries, truncation, bit flips
// ---------------------------------------------------------------------------

#[test]
fn scan_accepts_exactly_the_record_boundaries() {
    let records = fixture_records();
    for end in 0..=FIXTURE_RECORDS_END {
        let result = scan_vec(&records, end);
        if end == 0 || FIXTURE_OFFSETS.contains(&end) || end == FIXTURE_RECORDS_END {
            let crc = result.expect("a record boundary is a valid extent end");
            let cut = usize::try_from(end).expect("small");
            assert_eq!(crc, crc_ref(&records[..cut]));
        } else {
            assert!(
                matches!(result, Err(SegmentError::Corrupt(_))),
                "end {end}: {result:?}"
            );
        }
    }
}

#[test]
fn stray_bytes_and_gaps_between_records_are_corrupt() {
    let mut stray = fixture_records();
    stray.extend_from_slice(&[0; 5]);
    assert!(corrupt_detail(scan_vec(&stray, 62)).contains("stray"));

    // A three-byte hole between records 1 and 2: dense framing is the format.
    let records = fixture_records();
    let mut gapped = records[..19].to_vec();
    gapped.extend_from_slice(&[0, 0, 0]);
    gapped.extend_from_slice(&records[19..]);
    let end = plen(&gapped);
    assert!(matches!(
        scan_vec(&gapped, end),
        Err(SegmentError::Corrupt(_))
    ));
}

#[test]
fn every_truncation_of_committed_bytes_is_corrupt_not_io() {
    let records = fixture_records();
    for keep in 0..records.len() {
        let result = scan_vec(&records[..keep], FIXTURE_RECORDS_END);
        assert!(
            matches!(result, Err(SegmentError::Corrupt(_))),
            "kept {keep}: {result:?}"
        );
    }
}

#[test]
fn every_single_byte_flip_in_a_segment_is_detected() {
    let sealed = fixture_sealed();
    for mask in [0x01_u8, 0x10, 0x80, 0xff] {
        for index in 0..sealed.len() {
            let mut damaged = sealed.clone();
            damaged[index] ^= mask;
            let context = format!("byte {index} ^ {mask:#04x}");
            if index < 57 {
                let scan = scan_vec(&damaged, FIXTURE_RECORDS_END);
                assert!(
                    matches!(scan, Err(SegmentError::Corrupt(_))),
                    "scan {context}: {scan:?}"
                );
            }
            let seal = verify_seal(&mut Cursor::new(damaged.clone()), FIXTURE_RECORDS_END);
            assert!(
                matches!(seal, Err(SegmentError::Corrupt(_))),
                "seal {context}: {seal:?}"
            );
            let file = validate_segment_file(
                &mut Cursor::new(damaged),
                FIXTURE_SEALED_END,
                FIXTURE_RECORDS_END,
                true,
            );
            assert!(
                matches!(file, Err(SegmentError::Corrupt(_))),
                "file {context}: {file:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Payload reader
// ---------------------------------------------------------------------------

#[test]
fn payload_reader_never_leaves_its_record() {
    let bytes = fixture_records();
    let mut reader =
        RecordPayload::open(Cursor::new(bytes.clone()), 0, FIXTURE_RECORDS_END).expect("open");
    // A buffer far larger than the record, then one-byte reads: same bytes.
    let mut big = [0xAA_u8; 4096];
    let n = reader.read(&mut big).expect("read");
    assert_eq!(&big[..n], b"123456789");
    assert_eq!(reader.read(&mut big).expect("eof"), 0);
    assert_eq!(reader.read(&mut big).expect("still eof"), 0);
    reader.finish().expect("finish");

    let mut reader =
        RecordPayload::open(Cursor::new(bytes), 19, FIXTURE_RECORDS_END).expect("open");
    let mut one = [0_u8; 1];
    let mut got = Vec::new();
    while reader.read(&mut one).expect("byte") == 1 {
        got.push(one[0]);
    }
    assert_eq!(got, [0x00, 0xff, 0x10, 0x80, 0x7f]);
    reader.finish().expect("finish");

    // Records stay readable when the extent ends at their own boundary.
    let mut empty =
        RecordPayload::open(Cursor::new(fixture_records()), 34, 44).expect("empty record");
    assert_eq!(empty.read(&mut big).expect("empty"), 0);
    empty.finish().expect("empty record verifies");
}

#[test]
fn finish_verifies_what_the_reader_did_not_consume() {
    fn open(bytes: &[u8]) -> RecordPayload<Cursor<Vec<u8>>> {
        RecordPayload::open(Cursor::new(bytes.to_vec()), 0, FIXTURE_RECORDS_END).expect("open")
    }
    let intact = fixture_records();
    open(&intact).finish().expect("unread but intact");

    let mut payload_flip = intact.clone();
    payload_flip[10] ^= 0x40;
    assert!(corrupt_detail(open(&payload_flip).finish()).contains("checksum mismatch"));

    let mut crc_flip = intact.clone();
    crc_flip[6] ^= 0x01;
    assert!(corrupt_detail(open(&crc_flip).finish()).contains("checksum mismatch"));

    // The bytes a decoder saw are untrusted: reading succeeds, finish rejects.
    let mut reader = open(&payload_flip);
    let mut got = Vec::new();
    reader
        .read_to_end(&mut got)
        .expect("reads do not judge the checksum");
    assert_eq!(got.len(), 9);
    assert!(corrupt_detail(reader.finish()).contains("checksum mismatch"));

    // Reading only part of the payload still leaves the whole record checked.
    let mut tail_flip = intact;
    tail_flip[18] ^= 0x01;
    let mut reader = open(&tail_flip);
    let mut head = [0_u8; 3];
    reader.read_exact(&mut head).expect("prefix reads");
    assert!(corrupt_detail(reader.finish()).contains("checksum mismatch"));
}

#[test]
fn truncated_payload_reads_are_corrupt_and_sticky() {
    let truncated = fixture_records()[..14].to_vec();
    let mut reader =
        RecordPayload::open(Cursor::new(truncated), 0, FIXTURE_RECORDS_END).expect("header intact");
    let mut got = Vec::new();
    let first = reader
        .read_to_end(&mut got)
        .expect_err("only 4 of 9 bytes exist");
    assert_eq!(first.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(got, b"1234");
    assert!(corrupt_detail(Err::<(), _>(SegmentError::from(first))).contains("5 of 9"));

    let again = reader.read(&mut [0_u8; 8]).expect_err("failure is sticky");
    assert_eq!(again.kind(), io::ErrorKind::UnexpectedEof);
    assert!(corrupt_detail(reader.finish()).contains("truncated"));
}

#[test]
fn only_embedded_segment_errors_are_recovered_from_io_errors() {
    assert!(matches!(
        SegmentError::from(io::Error::other("disk on fire")),
        SegmentError::Io(_)
    ));
    // A bare EOF from somewhere else is not silently reclassified.
    assert!(matches!(
        SegmentError::from(io::Error::from(io::ErrorKind::UnexpectedEof)),
        SegmentError::Io(_)
    ));
    let wrapped = io::Error::new(
        io::ErrorKind::InvalidData,
        SegmentError::Corrupt("x".into()),
    );
    assert!(matches!(SegmentError::from(wrapped), SegmentError::Corrupt(detail) if detail == "x"));
}

// ---------------------------------------------------------------------------
// Seal verification and segment validation
// ---------------------------------------------------------------------------

fn sealed_with_footer(footer: &[u8]) -> Vec<u8> {
    let mut bytes = fixture_records();
    bytes.extend_from_slice(footer);
    bytes
}

fn verify_with_footer(footer: &[u8]) -> Result<u32, SegmentError> {
    verify_seal(
        &mut Cursor::new(sealed_with_footer(footer)),
        FIXTURE_RECORDS_END,
    )
}

#[test]
fn seal_verification_rejects_every_footer_defect() {
    assert_eq!(
        verify_with_footer(&unhex(FIXTURE_FOOTER_HEX)).expect("golden footer"),
        FIXTURE_REGION_CRC
    );
    // Each defect keeps a valid footer self-checksum except where stated.
    let wrong_extent = seal_footer(*b"RUKSEAL1", FIXTURE_RECORDS_END - 1, FIXTURE_REGION_CRC);
    assert!(
        corrupt_detail(verify_with_footer(&wrong_extent)).contains("inconsistent sealed extent")
    );
    let huge_extent = seal_footer(*b"RUKSEAL1", u64::MAX, FIXTURE_REGION_CRC);
    assert!(
        corrupt_detail(verify_with_footer(&huge_extent)).contains("inconsistent sealed extent")
    );
    let wrong_region = seal_footer(*b"RUKSEAL1", FIXTURE_RECORDS_END, FIXTURE_REGION_CRC ^ 1);
    assert!(corrupt_detail(verify_with_footer(&wrong_region)).contains("records checksum"));
    let wrong_magic = seal_footer(*b"RUKSEAL2", FIXTURE_RECORDS_END, FIXTURE_REGION_CRC);
    assert!(corrupt_detail(verify_with_footer(&wrong_magic)).contains("magic"));
    let mut wrong_self_crc = unhex(FIXTURE_FOOTER_HEX);
    wrong_self_crc[23] ^= 0x80;
    assert!(corrupt_detail(verify_with_footer(&wrong_self_crc)).contains("footer checksum"));

    // Every proper prefix of the footer is a truncated footer.
    let golden_footer = unhex(FIXTURE_FOOTER_HEX);
    for keep in 0..FOOTER_LEN {
        let result = verify_with_footer(&golden_footer[..keep]);
        assert!(
            corrupt_detail(result).contains("truncated seal footer"),
            "kept {keep}"
        );
    }
}

#[test]
fn seal_verification_checks_records_independently_of_the_region_checksum() {
    // A footer whose region checksum honestly covers a record with an unknown
    // kind: the records walk must still refuse it.
    let mut records = frame(1, 0, b"fine");
    records.extend(frame(9, 0, b"bad kind"));
    let mut sealed = records.clone();
    sealed.extend(seal_footer(*b"RUKSEAL1", plen(&records), crc_ref(&records)));
    let result = verify_seal(&mut Cursor::new(sealed), plen(&records));
    assert!(corrupt_detail(result).contains("unknown object kind"));
}

#[test]
fn manifest_extent_that_disagrees_with_the_footer_is_corrupt() {
    // records_end at an interior record boundary: the footer is not there.
    let sealed = fixture_sealed();
    let result = verify_seal(&mut Cursor::new(sealed.clone()), 44);
    assert!(corrupt_detail(result).contains("magic"));
    let file = validate_segment_file(&mut Cursor::new(sealed), 44 + 24, 44, true);
    assert!(corrupt_detail(file).contains("after its footer"));
}

#[test]
fn layout_rules_reject_self_contradicting_manifests() {
    let max = u64::MAX;
    let bad: [(u64, u64, bool); 11] = [
        (56, 57, false),
        (58, 57, false),
        (81, 57, false),
        (57, 57, true),
        (80, 57, true),
        (82, 57, true),
        (0, 57, true),
        (max, max, true),
        (max, max - 23, true),
        (max - 1, max - 24, true),
        (23, 0, true),
    ];
    for (committed, records, sealed) in bad {
        let result = validate_segment_layout(committed, records, sealed);
        assert!(
            matches!(result, Err(SegmentError::Corrupt(_))),
            "({committed}, {records}, {sealed}): {result:?}"
        );
    }
    let good: [(u64, u64, bool); 5] = [
        (0, 0, false),
        (57, 57, false),
        (24, 0, true),
        (81, 57, true),
        (max, max - 24, true),
    ];
    for (committed, records, sealed) in good {
        validate_segment_layout(committed, records, sealed)
            .unwrap_or_else(|err| panic!("({committed}, {records}, {sealed}): {err:?}"));
    }
}

#[test]
fn open_segment_validation_reports_the_uncommitted_tail_without_judging_it() {
    let records = fixture_records();
    let check = |bytes: Vec<u8>| {
        validate_segment_file(
            &mut Cursor::new(bytes),
            FIXTURE_RECORDS_END,
            FIXTURE_RECORDS_END,
            false,
        )
    };

    let exact = check(records.clone()).expect("exact");
    assert_eq!(
        (exact.records_crc, exact.file_len),
        (FIXTURE_REGION_CRC, 57)
    );

    let mut garbage_tail = records.clone();
    garbage_tail.extend_from_slice(&[0xEE; 17]);
    let tailed = check(garbage_tail).expect("garbage beyond the committed extent is not read");
    assert_eq!(tailed.file_len, 74);
    assert_eq!(tailed.file_len - FIXTURE_RECORDS_END, 17);

    // Crash between "footer written" and "manifest committed": the manifest
    // is still open, the file already carries a footer past the extent.
    let crashed_seal = check(fixture_sealed()).expect("uncommitted footer is just a tail");
    assert_eq!(crashed_seal.file_len, FIXTURE_SEALED_END);
    assert_eq!(crashed_seal.records_crc, FIXTURE_REGION_CRC);

    for keep in 0..records.len() {
        let result = check(records[..keep].to_vec());
        assert!(corrupt_detail(result).contains("missing"), "kept {keep}");
    }
}

#[test]
fn sealed_segment_validation_is_exact_about_length() {
    let sealed = fixture_sealed();
    let check = |bytes: Vec<u8>| {
        validate_segment_file(
            &mut Cursor::new(bytes),
            FIXTURE_SEALED_END,
            FIXTURE_RECORDS_END,
            true,
        )
    };
    check(sealed.clone()).expect("exact");

    let mut longer = sealed.clone();
    longer.push(0);
    assert!(corrupt_detail(check(longer)).contains("after its footer"));

    for keep in 0..sealed.len() {
        let result = check(sealed[..keep].to_vec());
        assert!(
            corrupt_detail(result).contains("missing"),
            "kept {keep}: a short file is never extended"
        );
    }
}

// ---------------------------------------------------------------------------
// File names
// ---------------------------------------------------------------------------

#[test]
fn segment_file_names_are_sixteen_lowercase_hex_digits() {
    assert_eq!(segment_file_name(0), "seg_0000000000000000");
    assert_eq!(segment_file_name(1), "seg_0000000000000001");
    assert_eq!(segment_file_name(0xabc), "seg_0000000000000abc");
    assert_eq!(segment_file_name(0xdead_beef), "seg_00000000deadbeef");
    assert_eq!(segment_file_name(u64::MAX), "seg_ffffffffffffffff");
}

// ---------------------------------------------------------------------------
// Real files: the instantiation the store uses
// ---------------------------------------------------------------------------

struct TempFile(PathBuf);

impl TempFile {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "ruk-segment-test-{}-{unique}-{tag}",
            std::process::id()
        )))
    }

    fn create_new(&self) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&self.0)
            .expect("create_new scratch file")
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn real_file_seal_then_verify_then_read() {
    let scratch = TempFile::new("sealed");
    let mut writer = SegmentWriter::fresh(scratch.create_new()).expect("fresh file writer");
    append_all(&mut writer, &fixture());
    assert_eq!(writer.seal().expect("seal"), FIXTURE_SEALED_END);
    writer.get_ref().sync_all().expect("sync");
    assert_eq!(
        std::fs::read(&scratch.0).expect("read back"),
        fixture_sealed()
    );

    let mut file = File::open(&scratch.0).expect("open read-only");
    let verified = validate_segment_file(&mut file, FIXTURE_SEALED_END, FIXTURE_RECORDS_END, true)
        .expect("validates");
    assert_eq!(verified.records_crc, FIXTURE_REGION_CRC);

    // Both `&mut File` and `&File` are valid sources for a payload reader.
    let mut by_mut = RecordPayload::open(&mut file, 19, FIXTURE_RECORDS_END).expect("open");
    let mut got = Vec::new();
    by_mut.read_to_end(&mut got).expect("read");
    by_mut.finish().expect("finish");
    assert_eq!(got, [0x00, 0xff, 0x10, 0x80, 0x7f]);

    let shared = File::open(&scratch.0).expect("open shared");
    let mut by_ref = RecordPayload::open(&shared, 44, FIXTURE_RECORDS_END).expect("open");
    let mut got = Vec::new();
    by_ref.read_to_end(&mut got).expect("read");
    by_ref.finish().expect("finish");
    assert_eq!(got, b"abc");
}

#[test]
fn real_file_crash_recovery_shape_truncate_tail_then_resume() {
    let scratch = TempFile::new("resume");
    let all = fixture();
    let mut writer = SegmentWriter::fresh(scratch.create_new()).expect("fresh file writer");
    append_all(&mut writer, &all[..3]);
    let committed = writer.records_end();
    // Model the production crash shape: the append loop always flushes
    // staged bytes before any crash hook or sync, so a killed process
    // leaves the committed prefix on the file.
    writer
        .flush_staged()
        .expect("committed prefix reaches the file");
    drop(writer);

    // An append that was never committed: a whole record plus a torn one.
    let mut torn = frame(4, 1, b"abc");
    torn.extend_from_slice(&frame(2, 1, &pattern(1000, 3))[..400]);
    OpenOptions::new()
        .append(true)
        .open(&scratch.0)
        .expect("reopen for append")
        .write_all(&torn)
        .expect("write tail");

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&scratch.0)
        .expect("reopen");
    let verified = validate_segment_file(&mut file, committed, committed, false)
        .expect("committed prefix is intact");
    assert_eq!(verified.file_len, committed + plen(&torn));
    file.set_len(committed)
        .expect("owner truncates the uncommitted tail");

    let mut writer = SegmentWriter::resumed(file, committed, verified.records_crc).expect("resume");
    append_all(&mut writer, &all[3..]);
    assert_eq!(writer.records_crc(), FIXTURE_REGION_CRC);
    writer
        .flush_staged()
        .expect("resumed tail reaches the file");
    assert_eq!(
        std::fs::read(&scratch.0).expect("read back"),
        fixture_records()
    );
}
