//! Canonical Git delta instruction streams over seekable spools.
//!
//! Format (Git `gitformat-pack`): two LEB128-style sizes (base, result)
//! followed by instructions. `0x80 | flags` copies from the base with up to
//! four little-endian offset bytes (flags `0x01..=0x08`) and up to three
//! size bytes (flags `0x10..=0x40`, size 0 means 0x10000); `1..=127` inserts
//! that many literal bytes; `0` is reserved.
//!
//! The writer-side search is deliberately tiny: a known predecessor, a
//! bounded common prefix and suffix copied from it, and a literal middle.
//! Copies are emitted in pieces of at most 0x10000 bytes, as Git itself
//! does (a 0x10000 piece carries no size bytes), so every Git reader
//! accepts the stream. Spans whose copy offsets Git cannot encode (above
//! `u32::MAX`) are left to the literal middle instead of failing; the
//! caller's half-size rule then decides whether the delta is worth keeping.
//!
//! The reader checks every instruction against the base and result bounds
//! before it copies anything, so a hostile stream can neither read outside
//! the base nor produce output beyond the declared result size.

use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};

use crate::store::error::StoreError;
use crate::store::segment::SegmentError;

/// Chunk size for every bounded stream copy and comparison.
pub(crate) const IO_CHUNK: usize = 64 * 1024;
/// Largest copy piece the writer emits (Git's own limit).
const COPY_PIECE: u64 = 0x1_0000;
/// Largest copy size the encoding can carry (three size bytes).
const MAX_COPY_SIZE: u64 = 0x00ff_ffff;
/// Largest offset the encoding can carry (four offset bytes).
const MAX_COPY_OFFSET: u64 = 0xffff_ffff;
/// Longest literal run one insert instruction carries.
const MAX_INSERT: usize = 127;
/// Prefix span whose copy pieces all start at an encodable offset.
const MAX_PREFIX_SPAN: u64 = 1 << 32;

fn corrupt(detail: impl Into<String>) -> StoreError {
    StoreError::Corrupt(detail.into())
}

/// Classifies a failed read of stored bytes: an embedded segment diagnosis
/// wins, end-of-stream and invalid-data are format failures (`E_CORRUPT`),
/// everything else is a real I/O failure.
pub(crate) fn classify_read(err: io::Error, what: &str) -> StoreError {
    match SegmentError::from(err) {
        SegmentError::Io(inner)
            if matches!(
                inner.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            ) =>
        {
            corrupt(format!("{what}: {inner}"))
        }
        SegmentError::Io(inner) => StoreError::Io(inner),
        other => StoreError::from(other),
    }
}

/// Reduces the copied prefix and suffix to spans whose every copy piece has
/// an encodable offset: the prefix is capped so its last piece starts below
/// `2^32`, and a suffix whose last piece would start above `u32::MAX` is
/// dropped entirely (its bytes become literals). `prefix + suffix <=
/// min(base_len, target_len)` holds on entry and is preserved.
pub(crate) fn clamp_copy_spans(base_len: u64, prefix: u64, suffix: u64) -> (u64, u64) {
    let prefix = prefix.min(MAX_PREFIX_SPAN);
    if suffix == 0 {
        return (prefix, 0);
    }
    let first = base_len - suffix;
    let last_piece_start = first.saturating_add((suffix - 1) / COPY_PIECE * COPY_PIECE);
    if last_piece_start > MAX_COPY_OFFSET {
        (prefix, 0)
    } else {
        (prefix, suffix)
    }
}

fn common_prefix<B: Read + Seek, T: Read + Seek>(
    base: &mut B,
    target: &mut T,
    limit: u64,
    left: &mut [u8],
    right: &mut [u8],
) -> io::Result<u64> {
    base.seek(SeekFrom::Start(0))?;
    target.seek(SeekFrom::Start(0))?;
    let mut matched = 0_u64;
    while matched < limit {
        let want = usize::try_from(limit - matched)
            .unwrap_or(usize::MAX)
            .min(left.len());
        base.read_exact(&mut left[..want])?;
        target.read_exact(&mut right[..want])?;
        if left[..want] == right[..want] {
            matched += crate::store::spool::to_u64(want);
            continue;
        }
        let same = left[..want]
            .iter()
            .zip(&right[..want])
            .take_while(|(a, b)| a == b)
            .count();
        return Ok(matched + crate::store::spool::to_u64(same));
    }
    Ok(matched)
}

fn common_suffix<B: Read + Seek, T: Read + Seek>(
    base: &mut B,
    base_len: u64,
    target: &mut T,
    target_len: u64,
    limit: u64,
    left: &mut [u8],
    right: &mut [u8],
) -> io::Result<u64> {
    let mut matched = 0_u64;
    while matched < limit {
        let want = usize::try_from(limit - matched)
            .unwrap_or(usize::MAX)
            .min(left.len());
        let width = crate::store::spool::to_u64(want);
        base.seek(SeekFrom::Start(base_len - matched - width))?;
        base.read_exact(&mut left[..want])?;
        target.seek(SeekFrom::Start(target_len - matched - width))?;
        target.read_exact(&mut right[..want])?;
        if left[..want] == right[..want] {
            matched += width;
            continue;
        }
        let same = left[..want]
            .iter()
            .rev()
            .zip(right[..want].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        return Ok(matched + crate::store::spool::to_u64(same));
    }
    Ok(matched)
}

fn write_varint<W: Write>(out: &mut W, mut value: u64) -> io::Result<()> {
    let mut bytes = [0_u8; 10];
    let mut used = 0;
    loop {
        let low = u8::try_from(value & 0x7f).unwrap_or(0x7f);
        value >>= 7;
        if value == 0 {
            bytes[used] = low;
            used += 1;
            break;
        }
        bytes[used] = low | 0x80;
        used += 1;
    }
    out.write_all(&bytes[..used])
}

/// One copy instruction. Callers guarantee `offset <= u32::MAX` and
/// `1 <= size <= 0xffffff`; anything else is refused rather than encoded.
fn write_copy<W: Write>(out: &mut W, offset: u64, size: u64) -> io::Result<()> {
    if offset > MAX_COPY_OFFSET || size == 0 || size > MAX_COPY_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "copy instruction outside the Git delta encoding",
        ));
    }
    let mut frame = [0_u8; 8];
    let mut used = 1;
    let mut command = 0x80_u8;
    for (index, flag) in [0x01_u8, 0x02, 0x04, 0x08].into_iter().enumerate() {
        let byte = u8::try_from((offset >> (8 * index)) & 0xff).unwrap_or(0);
        if byte != 0 {
            command |= flag;
            frame[used] = byte;
            used += 1;
        }
    }
    // Git writes a 0x10000 copy with no size bytes (zero means 0x10000).
    let size_field = if size == COPY_PIECE { 0 } else { size };
    for (index, flag) in [0x10_u8, 0x20, 0x40].into_iter().enumerate() {
        let byte = u8::try_from((size_field >> (8 * index)) & 0xff).unwrap_or(0);
        if byte != 0 {
            command |= flag;
            frame[used] = byte;
            used += 1;
        }
    }
    frame[0] = command;
    out.write_all(&frame[..used])
}

fn write_copies<W: Write>(out: &mut W, mut offset: u64, mut len: u64) -> io::Result<()> {
    while len > 0 {
        let piece = len.min(COPY_PIECE);
        write_copy(out, offset, piece)?;
        offset += piece;
        len -= piece;
    }
    Ok(())
}

fn write_inserts<T: Read + Seek, W: Write>(
    out: &mut W,
    target: &mut T,
    start: u64,
    mut len: u64,
    chunk: &mut [u8],
    frame: &mut Vec<u8>,
) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    target.seek(SeekFrom::Start(start))?;
    while len > 0 {
        let want = usize::try_from(len).unwrap_or(usize::MAX).min(chunk.len());
        target.read_exact(&mut chunk[..want])?;
        frame.clear();
        for piece in chunk[..want].chunks(MAX_INSERT) {
            frame.push(u8::try_from(piece.len()).unwrap_or(0));
            frame.extend_from_slice(piece);
        }
        out.write_all(frame)?;
        len -= crate::store::spool::to_u64(want);
    }
    Ok(())
}

/// Writes the canonical delta turning `base` into `target` to `out`.
///
/// Memory: three `IO_CHUNK` buffers plus one instruction frame. Errors from
/// `out` pass through unchanged so the caller can recognise its own limit
/// markers.
pub(crate) fn encode_delta<B: Read + Seek, T: Read + Seek, W: Write>(
    base: &mut B,
    base_len: u64,
    target: &mut T,
    target_len: u64,
    out: &mut W,
) -> io::Result<()> {
    let common = base_len.min(target_len);
    let mut left = vec![0_u8; IO_CHUNK];
    let mut right = vec![0_u8; IO_CHUNK];
    let prefix_limit = common.min(MAX_PREFIX_SPAN);
    let prefix = common_prefix(base, target, prefix_limit, &mut left, &mut right)?;
    let suffix = common_suffix(
        base,
        base_len,
        target,
        target_len,
        common - prefix,
        &mut left,
        &mut right,
    )?;
    let (prefix, suffix) = clamp_copy_spans(base_len, prefix, suffix);

    write_varint(out, base_len)?;
    write_varint(out, target_len)?;
    write_copies(out, 0, prefix)?;
    let mut frame = Vec::with_capacity(IO_CHUNK + IO_CHUNK / MAX_INSERT + 2);
    write_inserts(
        out,
        target,
        prefix,
        target_len - prefix - suffix,
        &mut left,
        &mut frame,
    )?;
    write_copies(out, base_len - suffix, suffix)
}

fn read_byte<D: Read>(source: &mut D) -> Result<Option<u8>, StoreError> {
    let mut byte = [0_u8; 1];
    loop {
        match source.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => return Ok(Some(byte[0])),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(classify_read(err, "delta stream")),
        }
    }
}

fn read_varint<D: Read>(source: &mut D) -> Result<u64, StoreError> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    loop {
        let byte = read_byte(source)?.ok_or_else(|| corrupt("delta header is truncated"))?;
        let bits = u64::from(byte & 0x7f);
        if shift > 63 || (shift == 63 && bits > 1) {
            return Err(corrupt("delta size overflows 64 bits"));
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn read_operand<D: Read>(
    source: &mut D,
    command: u8,
    flags: &[(u8, u32)],
) -> Result<u64, StoreError> {
    let mut value = 0_u64;
    for &(flag, shift) in flags {
        if command & flag == 0 {
            continue;
        }
        let byte = read_byte(source)?.ok_or_else(|| corrupt("copy instruction is truncated"))?;
        value |= u64::from(byte) << shift;
    }
    Ok(value)
}

fn read_exact_stored<R: Read>(
    source: &mut R,
    buf: &mut [u8],
    what: &str,
) -> Result<(), StoreError> {
    source
        .read_exact(buf)
        .map_err(|err| classify_read(err, what))
}

/// Applies the delta stream `delta` to `base`, writing exactly
/// `expected_len` bytes to `out`.
///
/// Every instruction is validated against the base length and the remaining
/// result size before any byte is copied or written. Truncated streams,
/// opcode 0, size mismatches and trailing instructions are `E_CORRUPT`; a
/// failing `out` surfaces as its own typed error.
///
/// # Errors
/// See above; resource refusals from `out` stay typed.
pub(crate) fn apply_delta<B: Read + Seek, D: Read, W: Write>(
    base: &mut B,
    base_len: u64,
    delta: D,
    expected_len: u64,
    out: &mut W,
) -> Result<(), StoreError> {
    let mut delta = BufReader::with_capacity(IO_CHUNK, delta);
    let declared_base = read_varint(&mut delta)?;
    if declared_base != base_len {
        return Err(corrupt(format!(
            "delta expects a base of {declared_base} bytes, the stored base has {base_len}"
        )));
    }
    let result_size = read_varint(&mut delta)?;
    if result_size != expected_len {
        return Err(corrupt(format!(
            "delta produces {result_size} bytes, the record declares {expected_len}"
        )));
    }
    let mut buf = vec![0_u8; IO_CHUNK];
    let mut produced = 0_u64;
    while produced < result_size {
        let command = read_byte(&mut delta)?
            .ok_or_else(|| corrupt("delta ends before its declared result size"))?;
        let step = if command & 0x80 != 0 {
            copy_from_base(
                base,
                base_len,
                &mut delta,
                command,
                result_size - produced,
                &mut buf,
                out,
            )?
        } else if command != 0 {
            insert_literal(&mut delta, command, result_size - produced, &mut buf, out)?
        } else {
            return Err(corrupt("delta uses the reserved opcode 0"));
        };
        produced += step;
    }
    if !delta
        .fill_buf()
        .map_err(|err| classify_read(err, "delta stream"))?
        .is_empty()
    {
        return Err(corrupt("delta has instructions after its declared result"));
    }
    Ok(())
}

fn copy_from_base<B: Read + Seek, D: Read, W: Write>(
    base: &mut B,
    base_len: u64,
    delta: &mut D,
    command: u8,
    room: u64,
    buf: &mut [u8],
    out: &mut W,
) -> Result<u64, StoreError> {
    let offset = read_operand(
        delta,
        command,
        &[(0x01, 0), (0x02, 8), (0x04, 16), (0x08, 24)],
    )?;
    let mut size = read_operand(delta, command, &[(0x10, 0), (0x20, 8), (0x40, 16)])?;
    if size == 0 {
        size = COPY_PIECE;
    }
    // Both checks precede the first byte copied.
    match offset.checked_add(size) {
        Some(end) if end <= base_len => {}
        _ => {
            return Err(corrupt(format!(
                "delta copies {size} bytes at {offset} outside its {base_len}-byte base"
            )));
        }
    }
    if size > room {
        return Err(corrupt(format!(
            "delta copy of {size} bytes exceeds the {room} bytes left in the result"
        )));
    }
    base.seek(SeekFrom::Start(offset))
        .map_err(|err| classify_read(err, "delta base"))?;
    let mut left = size;
    while left > 0 {
        let want = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
        read_exact_stored(base, &mut buf[..want], "delta base")?;
        out.write_all(&buf[..want])
            .map_err(crate::store::spool::io_to_store)?;
        left -= crate::store::spool::to_u64(want);
    }
    Ok(size)
}

fn insert_literal<D: Read, W: Write>(
    delta: &mut D,
    command: u8,
    room: u64,
    buf: &mut [u8],
    out: &mut W,
) -> Result<u64, StoreError> {
    let size = u64::from(command);
    if size > room {
        return Err(corrupt(format!(
            "delta insert of {size} bytes exceeds the {room} bytes left in the result"
        )));
    }
    let len = usize::from(command);
    read_exact_stored(delta, &mut buf[..len], "delta insert")?;
    out.write_all(&buf[..len])
        .map_err(crate::store::spool::io_to_store)?;
    Ok(size)
}
