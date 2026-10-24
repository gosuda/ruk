//! Tar-to-zip transcoding shared by the CLI archive verb and the daemon's
//! streamed archive reads.
//!
//! [`ZipTranscoder`] is a streaming [`TarSink`]: tar bytes arrive in any
//! chunking and zip bytes leave through the inner writer as entries
//! complete, so neither side ever holds a whole archive. The state machine
//! follows the serve half's ustar layout.
//!
//! `g` globals and `x` pax records carry no entry of their own:
//! - `g` records carry global comments or metadata and do not alter or
//!   retarget subsequent members.
//! - `x` pax records carry entry-specific overrides (`path=`, `linkpath=`,
//!   `size=`, `mtime=`) describing the following named member.
//!
//! Pending overrides are consumed and drained exactly once by the next named
//! member (`5` directory, `2` symlink, or `0` file), ensuring no override
//! leaks into subsequent members:
//! - `5` members become directories using their effective name and mtime.
//! - `2` members become symlinks using their effective name, symlink target
//!   (from `linkpath` if overridden), and mtime. Symlink targets must be UTF-8.
//! - `0` members become files whose bodies stream into their zip entry. The
//!   effective size from a pax `size=` record overrides a zero or truncated
//!   ustar header size (used when blobs exceed ustar's inline octal capacity).
//!   When the effective size exceeds `u32::MAX`, the entry is marked with
//!   ZIP64 large file support. If the effective size is zero, the entry is
//!   stored uncompressed; otherwise it is deflated.
//!
//! Names and symlink targets must be UTF-8: the zip writer stores them as
//! text, so a non-UTF-8 name or target refuses with [`GitError::Corrupt`]
//! instead of landing mojibake. Extended headers are parsed strictly:
//! malformed framing, invalid or out-of-bounds lengths, missing newlines,
//! and non-decimal numeric fields refuse rather than silently falling back.

use std::io::{self, Write};

use ruk_git::GitError;
use ruk_git::transport::archive::TarSink;
use zip::CompressionMethod;
use zip::ZipWriter;
use zip::write::{SimpleFileOptions, StreamWriter};

/// Bytes per ustar record.
const RECORD: usize = 512;

/// Largest `x` or `g` record body the transcoder buffers. The serve half
/// emits records of a few hundred bytes, so anything past this bound is
/// refused instead of buffered.
const MAX_PAX_BYTES: u64 = 1 << 20;

/// Where the transcoder is within the tar stream.
enum Phase {
    /// Collecting the next 512-byte header record.
    Header,
    /// Buffering an `x` (`global == false`) or `g` record body.
    Pax {
        buf: Vec<u8>,
        remaining: u64,
        pad: u64,
        global: bool,
    },
    /// Streaming a file body into its open zip entry.
    File { remaining: u64, pad: u64 },
    /// Skipping bytes up to the next record boundary.
    Padding { remaining: u64 },
    /// The closing zero record was seen; later bytes are ignored.
    Trailer,
}

/// Overrides parsed from an `x` pax extended-header record body.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(crate) struct PaxOverrides {
    pub(crate) path: Option<Vec<u8>>,
    pub(crate) linkpath: Option<Vec<u8>>,
    pub(crate) size: Option<u64>,
    pub(crate) mtime: Option<u64>,
}

impl PaxOverrides {
    /// Consecutive `x` headers accumulate: a later record overrides only
    /// the keys it carries, leaving earlier keys intact.
    fn merge(&mut self, other: PaxOverrides) {
        if other.path.is_some() {
            self.path = other.path;
        }
        if other.linkpath.is_some() {
            self.linkpath = other.linkpath;
        }
        if other.size.is_some() {
            self.size = other.size;
        }
        if other.mtime.is_some() {
            self.mtime = other.mtime;
        }
    }
}

/// A streaming tar-to-zip transcoder. Zip output goes to the inner writer
/// as each entry completes; [`Self::close`] writes the central directory.
pub(crate) struct ZipTranscoder<W: Write> {
    zip: Option<ZipWriter<StreamWriter<W>>>,
    phase: Phase,
    header: Vec<u8>,
    pending: PaxOverrides,
    output: Option<W>,
}

impl<W: Write> ZipTranscoder<W> {
    /// A transcoder writing the zip to `inner`. The writer never seeks, so
    /// `inner` may be a socket or channel adapter.
    pub(crate) fn new(inner: W) -> Self {
        Self {
            zip: Some(ZipWriter::new_stream(inner)),
            phase: Phase::Header,
            header: Vec::with_capacity(RECORD),
            pending: PaxOverrides::default(),
            output: None,
        }
    }

    /// The inner writer once [`TarSink::finish`] has closed the zip.
    pub(crate) fn into_output(self) -> Option<W> {
        self.output
    }

    /// The open zip writer.
    ///
    /// # Errors
    /// `Corrupt` when the archive continues after the zip was closed.
    fn zip_mut(&mut self) -> Result<&mut ZipWriter<StreamWriter<W>>, GitError> {
        self.zip
            .as_mut()
            .ok_or_else(|| corrupt("archive continues after its zip was closed"))
    }

    /// Handles one complete 512-byte record: the zero record closes the
    /// archive, a ustar record starts a member.
    fn begin_member(&mut self, header: &[u8; RECORD]) -> Result<(), GitError> {
        if header.iter().all(|byte| *byte == 0) {
            self.phase = Phase::Trailer;
            return Ok(());
        }
        if header[257..263] != *b"ustar\0" {
            return Err(corrupt("archive member is not a ustar header"));
        }
        let ustar_size = parse_octal(&header[124..136], "size")?;
        let mode = u32::try_from(parse_octal(&header[100..108], "mode")?)
            .map_err(|_| corrupt("archive member mode overflows"))?;
        let ustar_mtime = parse_octal(&header[136..148], "mtime")?;
        match header[156] {
            typeflag @ (b'x' | b'g') => {
                if ustar_size > MAX_PAX_BYTES {
                    return Err(corrupt("pax record exceeds the transcoder bound"));
                }
                self.phase = if ustar_size == 0 {
                    if typeflag == b'x' {
                        self.pending = PaxOverrides::default();
                    }
                    Phase::Header
                } else {
                    Phase::Pax {
                        buf: Vec::new(),
                        remaining: ustar_size,
                        pad: pad_for(ustar_size),
                        global: typeflag == b'g',
                    }
                };
            }
            b'5' => {
                let pending = std::mem::take(&mut self.pending);
                let name = resolve_name(pending.path, header)?;
                let mtime = pending.mtime.unwrap_or(ustar_mtime);
                let options = SimpleFileOptions::default()
                    .unix_permissions(mode)
                    .last_modified_time(zip_mtime(mtime));
                self.zip_mut()?
                    .add_directory(name, options)
                    .map_err(zip_failed)?;
                self.phase = skip_body(ustar_size);
            }
            b'2' => {
                let pending = std::mem::take(&mut self.pending);
                let name = resolve_name(pending.path, header)?;
                let mtime = pending.mtime.unwrap_or(ustar_mtime);
                let options = SimpleFileOptions::default()
                    .unix_permissions(mode)
                    .last_modified_time(zip_mtime(mtime));
                let raw_target = pending.linkpath.unwrap_or_else(|| header_linkname(header));
                let target = String::from_utf8(raw_target)
                    .map_err(|_| corrupt("symlink target is not UTF-8; zip stores it as text"))?;
                self.zip_mut()?
                    .add_symlink(name, target, options)
                    .map_err(zip_failed)?;
                self.phase = skip_body(ustar_size);
            }
            b'0' => {
                let pending = std::mem::take(&mut self.pending);
                let name = resolve_name(pending.path, header)?;
                let effective_size = pending.size.unwrap_or(ustar_size);
                let mtime = pending.mtime.unwrap_or(ustar_mtime);
                let method = if effective_size == 0 {
                    CompressionMethod::Stored
                } else {
                    CompressionMethod::Deflated
                };
                let options = SimpleFileOptions::default()
                    .unix_permissions(mode)
                    .last_modified_time(zip_mtime(mtime))
                    .large_file(effective_size >= u64::from(u32::MAX))
                    .compression_method(method);
                self.zip_mut()?
                    .start_file(name, options)
                    .map_err(zip_failed)?;
                self.phase = if effective_size == 0 {
                    Phase::Header
                } else {
                    Phase::File {
                        remaining: effective_size,
                        pad: pad_for(effective_size),
                    }
                };
            }
            other => {
                return Err(corrupt(format!("archive member has unknown type {other}")));
            }
        }
        Ok(())
    }
}

impl<W: Write> TarSink for ZipTranscoder<W> {
    fn write_tar(&mut self, mut bytes: &[u8]) -> Result<(), GitError> {
        while !bytes.is_empty() {
            match std::mem::replace(&mut self.phase, Phase::Header) {
                Phase::Trailer => {
                    self.phase = Phase::Trailer;
                    return Ok(());
                }
                Phase::Header => {
                    let take = (RECORD - self.header.len()).min(bytes.len());
                    self.header.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if self.header.len() == RECORD {
                        let block: [u8; RECORD] = std::mem::take(&mut self.header)
                            .try_into()
                            .map_err(|_| corrupt("archive record is not 512 bytes"))?;
                        self.begin_member(&block)?;
                    }
                }
                Phase::Pax {
                    mut buf,
                    remaining,
                    pad,
                    global,
                } => {
                    let take = bytes.len().min(narrow(remaining));
                    buf.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    let remaining = remaining - wide(take);
                    if remaining > 0 {
                        self.phase = Phase::Pax {
                            buf,
                            remaining,
                            pad,
                            global,
                        };
                    } else {
                        let overrides = parse_pax(&buf)?;
                        if !global {
                            self.pending.merge(overrides);
                        }
                        self.phase = after_body(pad);
                    }
                }
                Phase::File { remaining, pad } => {
                    let take = bytes.len().min(narrow(remaining));
                    self.zip_mut()?
                        .write_all(&bytes[..take])
                        .map_err(write_failed)?;
                    bytes = &bytes[take..];
                    let remaining = remaining - wide(take);
                    self.phase = if remaining > 0 {
                        Phase::File { remaining, pad }
                    } else {
                        after_body(pad)
                    };
                }
                Phase::Padding { remaining } => {
                    let take = bytes.len().min(narrow(remaining));
                    bytes = &bytes[take..];
                    let remaining = remaining - wide(take);
                    self.phase = if remaining > 0 {
                        Phase::Padding { remaining }
                    } else {
                        Phase::Header
                    };
                }
            }
        }
        Ok(())
    }

    fn fail(&mut self, _message: &str) -> Result<(), GitError> {
        Ok(())
    }

    /// Closes the zip. The archive must end on a record boundary, after the
    /// zero record or with no partial record pending.
    fn finish(&mut self) -> Result<(), GitError> {
        match &self.phase {
            Phase::Trailer => {}
            Phase::Header if self.header.is_empty() => {}
            Phase::Header => return Err(corrupt("archive ends inside a header record")),
            Phase::Pax { .. } | Phase::File { .. } | Phase::Padding { .. } => {
                return Err(corrupt("archive ends inside a member"));
            }
        }
        let zip = self
            .zip
            .take()
            .ok_or_else(|| corrupt("archive was already closed"))?;
        let stream = zip.finish().map_err(zip_failed)?;
        let mut inner = stream.into_inner();
        inner.flush().map_err(write_failed)?;
        self.output = Some(inner);
        Ok(())
    }
}

/// Transcodes a complete tar archive into a zip archive in memory. The CLI
/// verb uses this; the daemon streams through [`ZipTranscoder`] directly.
pub(crate) fn tar_to_zip(tar: &[u8]) -> Result<Vec<u8>, GitError> {
    let mut transcoder = ZipTranscoder::new(Vec::new());
    transcoder.write_tar(tar)?;
    transcoder.finish()?;
    transcoder
        .into_output()
        .ok_or_else(|| corrupt("zip archive was not closed"))
}

/// Bytes after a body that pad it to the next record boundary.
fn pad_for(size: u64) -> u64 {
    (RECORD_WIDE - size % RECORD_WIDE) % RECORD_WIDE
}

/// The phase after a body of `size` bytes whose padding is `pad`.
fn after_body(pad: u64) -> Phase {
    if pad == 0 {
        Phase::Header
    } else {
        Phase::Padding { remaining: pad }
    }
}

/// The phase skipping a member's body and padding, for members whose body
/// carries nothing the zip needs.
fn skip_body(size: u64) -> Phase {
    let total = size + pad_for(size);
    if total == 0 {
        Phase::Header
    } else {
        Phase::Padding { remaining: total }
    }
}

/// [`RECORD`] as `u64`, for padding arithmetic.
const RECORD_WIDE: u64 = 512;

/// `n` widened to `u64`. Every `usize` fits, so the conversion cannot fail.
fn wide(n: usize) -> u64 {
    u64::try_from(n).expect("usize fits in u64")
}

/// `n` narrowed to `usize`, saturating. A count past `usize` only ever caps a
/// slice of input that is already in memory, so saturation is safe.
fn narrow(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

fn corrupt(detail: impl Into<String>) -> GitError {
    GitError::Corrupt {
        detail: detail.into(),
    }
}

fn write_failed(err: io::Error) -> GitError {
    GitError::Io {
        detail: format!("cannot write the zip archive: {err}"),
    }
}

/// Maps a zip writer failure onto the interpreter: I/O stays I/O, every
/// other refusal (bad names, duplicate entries, a finished stream) is a
/// corrupt archive, never a silent truncation.
fn zip_failed(err: zip::result::ZipError) -> GitError {
    match err {
        zip::result::ZipError::Io(io) => GitError::Io {
            detail: format!("cannot write the zip archive: {io}"),
        },
        other => GitError::Corrupt {
            detail: format!("cannot write the zip archive: {other}"),
        },
    }
}

/// Parses a NUL/space-terminated octal header field.
pub(crate) fn parse_octal(field: &[u8], what: &str) -> Result<u64, GitError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0 || *byte == b' ')
        .unwrap_or(field.len());
    let text = std::str::from_utf8(&field[..end]).map_err(|_| GitError::Corrupt {
        detail: format!("archive header {what} is not ASCII"),
    })?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(0);
    }
    if !text.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(GitError::Corrupt {
            detail: format!("archive header {what} is not octal: {text:?}"),
        });
    }
    u64::from_str_radix(text, 8).map_err(|_| GitError::Corrupt {
        detail: format!("archive header {what} overflows: {text:?}"),
    })
}

/// The ustar prefix/name fields joined with `/`, without consulting any
/// `x` record beside the member.
pub(crate) fn header_name(header: &[u8; RECORD]) -> Vec<u8> {
    let prefix_end = header[345..500]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(155);
    let name_end = header[..100]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(100);
    let (prefix, name) = (&header[345..345 + prefix_end], &header[..name_end]);
    if prefix.is_empty() {
        name.to_vec()
    } else {
        let mut out = prefix.to_vec();
        out.push(b'/');
        out.extend_from_slice(name);
        out
    }
}

/// Reads the link target out of a symlink member's ustar linkname field.
fn header_linkname(header: &[u8; RECORD]) -> Vec<u8> {
    let end = header[157..257]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(100);
    header[157..157 + end].to_vec()
}

/// Resolves a member name from the pending override or the ustar header.
fn resolve_name(override_path: Option<Vec<u8>>, header: &[u8; RECORD]) -> Result<String, GitError> {
    let raw = override_path.unwrap_or_else(|| header_name(header));
    String::from_utf8(raw)
        .map_err(|_| corrupt("archive member name is not UTF-8; zip stores names as text"))
}

/// Reads the `path` record out of pax extended-header data, if present.
///
/// Returns `Ok(None)` if no `path` override is present in valid pax data.
/// Returns `Err` if the pax data is malformed.
pub(crate) fn pax_path_record(data: &[u8]) -> Result<Option<Vec<u8>>, GitError> {
    parse_pax(data).map(|overrides| overrides.path)
}

/// Parses pax extended-header data into [`PaxOverrides`].
///
/// Each record has the POSIX format:
/// `"%d %s=%s\n", <length>, <keyword>, <value>`
/// where `<length>` is the decimal byte count of the entire record including
/// the length field itself, space, keyword, '=', value, and trailing newline.
///
/// A single strict traversal processes all four keys (`path`, `linkpath`,
/// `size`, `mtime`), with later records in the same body overwriting earlier
/// ones. Malformed framing, non-numeric, zero, or oversized record lengths,
/// records without trailing `\n`, records without '=', or non-decimal
/// `size`/`mtime` fail with [`GitError::Corrupt`].
pub(crate) fn parse_pax(mut data: &[u8]) -> Result<PaxOverrides, GitError> {
    let mut overrides = PaxOverrides::default();
    while !data.is_empty() {
        let space = data
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| corrupt("malformed pax record: missing length separator"))?;
        let length_slice = &data[..space];
        if length_slice.is_empty() || !length_slice.iter().all(|byte| byte.is_ascii_digit()) {
            return Err(corrupt("malformed pax record: non-numeric length"));
        }
        let len_text = std::str::from_utf8(length_slice)
            .map_err(|_| corrupt("malformed pax record: length is not ASCII"))?;
        let len: usize = len_text
            .parse()
            .map_err(|_| corrupt("malformed pax record: length overflows usize"))?;
        if len == 0 {
            return Err(corrupt("malformed pax record: zero length"));
        }
        if len <= space + 1 {
            return Err(corrupt("malformed pax record: length too small for body"));
        }
        if len > data.len() {
            return Err(corrupt(
                "malformed pax record: length exceeds remaining data",
            ));
        }
        let record = &data[..len];
        data = &data[len..];
        if !record.ends_with(b"\n") {
            return Err(corrupt("malformed pax record: missing trailing newline"));
        }
        let body = &record[space + 1..record.len() - 1];
        let eq = body
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| corrupt("malformed pax record: missing '=' delimiter"))?;
        let keyword = &body[..eq];
        if keyword.is_empty() {
            return Err(corrupt("malformed pax record: empty keyword"));
        }
        let value = &body[eq + 1..];

        match keyword {
            b"path" => {
                overrides.path = Some(value.to_vec());
            }
            b"linkpath" => {
                overrides.linkpath = Some(value.to_vec());
            }
            b"size" => {
                overrides.size = Some(parse_decimal(value, "size")?);
            }
            b"mtime" => {
                overrides.mtime = Some(parse_decimal(value, "mtime")?);
            }
            _ => {
                // Unknown/unsupported keys are ignored.
            }
        }
    }
    Ok(overrides)
}

fn parse_decimal(value: &[u8], what: &str) -> Result<u64, GitError> {
    let text = std::str::from_utf8(value).map_err(|_| GitError::Corrupt {
        detail: format!("pax {what} is not ASCII"),
    })?;
    // pax `mtime` permits `seconds.fraction`; the integer part alone is
    // what the ustar field carries and what zip timestamps express.
    let seconds = text.split_once('.').map_or(text, |(head, _)| head);
    if seconds.is_empty() || !seconds.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(GitError::Corrupt {
            detail: format!("pax {what} is not decimal: {text:?}"),
        });
    }
    seconds.parse::<u64>().map_err(|_| GitError::Corrupt {
        detail: format!("pax {what} overflows: {text:?}"),
    })
}

/// Converts a tar mtime into zip's DOS timestamp: out-of-range stamps
/// (before 1980 or past 2107) fall back to the zip epoch instead of
/// failing the archive.
fn zip_mtime(stamp: u64) -> zip::DateTime {
    const DAY: u64 = 86400;
    let (days, clock) = (stamp / DAY, stamp % DAY);
    // Days to civil date on the proleptic Gregorian calendar; the shifted
    // era keeps every division exact for all representable stamps.
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    // Saturating conversions: any component outside the DOS range fails
    // `from_date_and_time` below and lands on the zip epoch, exactly like
    // a pre-1980 stamp.
    let year = u16::try_from(year).unwrap_or(u16::MAX);
    let month = u8::try_from(month).unwrap_or(u8::MAX);
    let day = u8::try_from(day).unwrap_or(u8::MAX);
    let hour = u8::try_from(clock / 3600).unwrap_or(u8::MAX);
    let minute = u8::try_from((clock % 3600) / 60).unwrap_or(u8::MAX);
    let second = u8::try_from(clock % 60).unwrap_or(u8::MAX);
    zip::DateTime::from_date_and_time(year, month, day, hour, minute, second).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;

    /// One ustar record with the fields the transcoder reads, checksummed.
    fn record(name: &[u8], typeflag: u8, size: u64, mode: u32) -> [u8; RECORD] {
        let mut header = [0u8; RECORD];
        header[..name.len()].copy_from_slice(name);
        let octal = |field: &mut [u8], value: u64| {
            let digits = field.len() - 1;
            let text = format!("{value:0digits$o}");
            field[..text.len()].copy_from_slice(text.as_bytes());
        };
        octal(&mut header[100..108], u64::from(mode));
        octal(&mut header[124..136], size);
        octal(&mut header[136..148], 1_700_000_000);
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: u32 = header
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if (148..156).contains(&index) {
                    u32::from(b' ')
                } else {
                    u32::from(*byte)
                }
            })
            .sum();
        let text = format!("{sum:07o}");
        header[148..155].copy_from_slice(text.as_bytes());
        header[155] = b' ';
        header
    }

    fn link_record(name: &[u8], target: &[u8]) -> [u8; RECORD] {
        let mut header = record(name, b'2', 0, 0o777);
        header[157..157 + target.len()].copy_from_slice(target);
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        let text = format!("{sum:07o}");
        header[148..155].copy_from_slice(text.as_bytes());
        header[155] = b' ';
        header
    }

    fn ext_record(keyword: &str, value: &[u8]) -> Vec<u8> {
        let mut len = 1 + 1 + keyword.len() + 1 + value.len() + 1;
        loop {
            let grown = len.to_string().len() + 1 + keyword.len() + 1 + value.len() + 1;
            if grown == len {
                break;
            }
            len = grown;
        }
        let mut out = format!("{len} {keyword}=").into_bytes();
        out.extend_from_slice(value);
        out.push(b'\n');
        assert_eq!(out.len(), len);
        out
    }

    fn pax_member(typeflag: u8, records: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (k, v) in records {
            body.extend_from_slice(&ext_record(k, v));
        }
        let len = wide(body.len());
        body.resize(body.len().div_ceil(RECORD) * RECORD, 0);
        let mut tar = record(b"pax", typeflag, len, 0o644).to_vec();
        tar.extend_from_slice(&body);
        tar
    }

    fn padded_pax_linkpath(target: &[u8]) -> Vec<u8> {
        pax_member(b'x', &[("linkpath", target)])
    }

    /// A tar holding one file, one directory, and one symlink, closed by
    /// two zero records.
    fn sample_tar() -> Vec<u8> {
        let body = b"hello\n";
        let mut tar = Vec::new();
        tar.extend_from_slice(&record(b"a.txt", b'0', 6, 0o644));
        tar.extend_from_slice(body);
        tar.extend_from_slice(&[0u8; RECORD - 6]);
        tar.extend_from_slice(&record(b"dir/", b'5', 0, 0o755));
        tar.extend_from_slice(&record(b"link", b'2', 0, 0o777));
        tar.extend_from_slice(&[0u8; 2 * RECORD]);
        tar
    }

    /// Every entry of a zip as `(name, contents)`, in archive order.
    fn read_back(zip_bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut archive = zip::ZipArchive::new(io::Cursor::new(zip_bytes)).expect("zip parses");
        let mut out = Vec::new();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).expect("entry");
            let name = entry.name().expect("entry name is UTF-8").into_owned();
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents).expect("entry reads");
            out.push((name, contents));
        }
        out
    }

    #[test]
    fn streamed_chunking_matches_whole_buffer() {
        let tar = sample_tar();
        let whole = tar_to_zip(&tar).expect("whole transcode");
        let mut byte_by_byte = ZipTranscoder::new(Vec::new());
        for byte in &tar {
            byte_by_byte
                .write_tar(std::slice::from_ref(byte))
                .expect("one byte at a time");
        }
        byte_by_byte.finish().expect("finish");
        let streamed = byte_by_byte.into_output().expect("closed output");
        assert_eq!(read_back(&streamed), read_back(&whole));
        let entries = read_back(&whole);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], ("a.txt".to_owned(), b"hello\n".to_vec()));
        assert_eq!(entries[1].0, "dir/");
        assert_eq!(entries[2].0, "link");
    }

    #[test]
    fn pax_linkpath_targets_only_the_following_symlink() {
        let long_target = b"target/".repeat(20);
        let mut tar = Vec::new();
        // 1. Pax linkpath followed by a file -> file drains the linkpath override
        tar.extend_from_slice(&padded_pax_linkpath(b"wrong/target1"));
        tar.extend_from_slice(&record(b"file.txt", b'0', 1, 0o644));
        tar.push(b'x');
        tar.extend_from_slice(&[0u8; RECORD - 1]);
        // Symlink following the file must not inherit wrong/target1
        tar.extend_from_slice(&link_record(b"link-after-file", b"target-after-file"));

        // 2. Pax linkpath followed by a directory -> dir drains the linkpath override
        tar.extend_from_slice(&padded_pax_linkpath(b"wrong/target2"));
        tar.extend_from_slice(&record(b"dir/", b'5', 0, 0o755));
        // Symlink following the directory must not inherit wrong/target2
        tar.extend_from_slice(&link_record(b"link-after-dir", b"target-after-dir"));

        // 3. Pax linkpath followed by symlink -> symlink gets the long_target
        tar.extend_from_slice(&padded_pax_linkpath(&long_target));
        tar.extend_from_slice(&link_record(b"long-link", b"see paxheader"));

        // 4. One-time draining: next symlink must not inherit long_target
        tar.extend_from_slice(&link_record(b"link-after-drain", b"target-clean"));
        tar.extend_from_slice(&[0u8; 2 * RECORD]);

        let expected = vec![
            ("file.txt".to_owned(), b"x".to_vec()),
            ("link-after-file".to_owned(), b"target-after-file".to_vec()),
            ("dir/".to_owned(), Vec::new()),
            ("link-after-dir".to_owned(), b"target-after-dir".to_vec()),
            ("long-link".to_owned(), long_target),
            ("link-after-drain".to_owned(), b"target-clean".to_vec()),
        ];

        let whole = tar_to_zip(&tar).expect("transcode");
        assert_eq!(read_back(&whole), expected);

        // Byte-at-a-time streaming through ZipTranscoder
        let mut byte_by_byte = ZipTranscoder::new(Vec::new());
        for byte in &tar {
            byte_by_byte
                .write_tar(std::slice::from_ref(byte))
                .expect("one byte at a time");
        }
        byte_by_byte.finish().expect("finish");
        let streamed = byte_by_byte.into_output().expect("closed output");
        assert_eq!(read_back(&streamed), expected);
    }

    #[test]
    fn pax_header_with_path_and_linkpath() {
        let mut path =
            b"very/nested/directory/structure/that/cannot/fit/in/inline/ustar/header/fields/"
                .repeat(2);
        path.extend_from_slice(b"target-symlink");
        let long_target =
            b"relative/path/to/target/directory/that/also/exceeds/the/ustar/field/limit/".repeat(2);

        let mut tar = Vec::new();
        tar.extend_from_slice(&pax_member(
            b'x',
            &[("path", &path), ("linkpath", &long_target)],
        ));
        tar.extend_from_slice(&link_record(b"placeholder-name", b"placeholder-target"));
        tar.extend_from_slice(&[0u8; 2 * RECORD]);

        let zip = tar_to_zip(&tar).expect("transcode");
        let entries = read_back(&zip);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, String::from_utf8(path).unwrap());
        assert_eq!(entries[0].1, long_target);
    }

    #[test]
    fn global_pax_cannot_rename_or_retarget() {
        let mut tar = Vec::new();
        tar.extend_from_slice(&pax_member(
            b'g',
            &[("path", b"injected-name"), ("linkpath", b"injected-target")],
        ));
        tar.extend_from_slice(&link_record(b"real-link", b"real-target"));
        tar.extend_from_slice(&[0u8; 2 * RECORD]);

        let zip = tar_to_zip(&tar).expect("transcode");
        let entries = read_back(&zip);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "real-link");
        assert_eq!(entries[0].1, b"real-target");
    }

    #[test]
    fn malformed_pax_records_refuse() {
        let malformed_bodies: Vec<&[u8]> = vec![
            b"20 path=foo",          // missing trailing newline
            b"0 \n",                 // zero length
            b"2 \n",                 // length too small for body
            b"4 =x\n",               // empty keyword
            b"999 path=foo\n",       // length exceeds body
            b"abc path=foo\n",       // non-numeric length
            b"12345678",             // no space separator
            b"20 size=notanumber\n", // non-decimal size
            b"15 mtime=bad\n",       // non-decimal mtime
            b"10 noequals\n",        // missing '=' delimiter
        ];
        for malformed in malformed_bodies {
            let mut tar = Vec::new();
            let mut body = malformed.to_vec();
            let len = body.len() as u64;
            body.resize(body.len().div_ceil(RECORD) * RECORD, 0);
            tar.extend_from_slice(&record(b"pax", b'x', len, 0o644));
            tar.extend_from_slice(&body);
            tar.extend_from_slice(&record(b"file.txt", b'0', 0, 0o644));
            tar.extend_from_slice(&[0u8; 2 * RECORD]);

            let err = tar_to_zip(&tar).expect_err("malformed pax must fail");
            assert!(
                matches!(err, GitError::Corrupt { .. }),
                "expected Corrupt for {malformed:?}, got {err:?}"
            );

            // Global headers must also validate framing strictly.
            let mut gtar = Vec::new();
            gtar.extend_from_slice(&record(b"pax", b'g', len, 0o644));
            gtar.extend_from_slice(&body);
            gtar.extend_from_slice(&record(b"file.txt", b'0', 0, 0o644));
            gtar.extend_from_slice(&[0u8; 2 * RECORD]);

            let gerr = tar_to_zip(&gtar).expect_err("malformed global pax must fail");
            assert!(
                matches!(gerr, GitError::Corrupt { .. }),
                "expected Corrupt for global {malformed:?}, got {gerr:?}"
            );
        }
    }

    #[test]
    fn consecutive_x_headers_merge_overrides() {
        let mut tar = Vec::new();
        tar.extend_from_slice(&pax_member(b'x', &[("linkpath", b"kept-target")]));
        tar.extend_from_slice(&pax_member(b'x', &[("mtime", b"1700000000")]));
        tar.extend_from_slice(&link_record(b"merged-link", b"see paxheader"));
        tar.extend_from_slice(&[0u8; 2 * RECORD]);
        let zip = tar_to_zip(&tar).expect("transcode");
        let entries = read_back(&zip);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "merged-link");
        assert_eq!(entries[0].1, b"kept-target");
    }

    #[test]
    fn fractional_pax_mtime_truncates_to_seconds() {
        let mut tar = Vec::new();
        tar.extend_from_slice(&pax_member(b'x', &[("mtime", b"1700000000.5")]));
        tar.extend_from_slice(&record(b"file.txt", b'0', 1, 0o644));
        tar.push(b'x');
        tar.extend_from_slice(&[0u8; RECORD - 1]);
        tar.extend_from_slice(&[0u8; 2 * RECORD]);
        tar_to_zip(&tar).expect("fractional mtime is standard pax");
    }

    #[test]
    fn non_utf8_linkpath_refuses() {
        let mut tar = Vec::new();
        tar.extend_from_slice(&pax_member(b'x', &[("linkpath", &[0xff, 0xfe, 0xfd])]));
        tar.extend_from_slice(&link_record(b"symlink", b"placeholder"));
        tar.extend_from_slice(&[0u8; 2 * RECORD]);

        let err = tar_to_zip(&tar).expect_err("non-UTF-8 linkpath must refuse");
        assert!(matches!(err, GitError::Corrupt { .. }), "{err:?}");
    }

    #[test]
    fn pax_size_overrides_zero_header_size_for_file() {
        let payload = b"hello from a blob whose size was recorded in a pax header\n";
        let mut tar = Vec::new();
        let size_str = payload.len().to_string();
        tar.extend_from_slice(&pax_member(b'x', &[("size", size_str.as_bytes())]));
        // Ustar header has size 0 (as archive.rs does when size overflows USTAR_MAX)
        tar.extend_from_slice(&record(b"large_file.txt", b'0', 0, 0o644));
        tar.extend_from_slice(payload);
        tar.extend_from_slice(&vec![0u8; narrow(pad_for(wide(payload.len())))]);
        tar.extend_from_slice(&[0u8; 2 * RECORD]);

        let zip = tar_to_zip(&tar).expect("transcode");
        let entries = read_back(&zip);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, "large_file.txt");
        assert_eq!(entries[0].1, payload.to_vec());
    }

    #[test]
    fn pax_path_record_parses_valid_and_refuses_corrupt() {
        let valid = ext_record("path", b"hello/world.txt");
        assert_eq!(
            pax_path_record(&valid).expect("parse"),
            Some(b"hello/world.txt".to_vec())
        );

        let empty = b"";
        assert_eq!(pax_path_record(empty).expect("parse"), None);

        let corrupt = b"abc path=invalid\n";
        assert!(matches!(
            pax_path_record(corrupt).expect_err("must fail"),
            GitError::Corrupt { .. }
        ));
    }

    #[test]
    fn truncated_member_refuses_at_finish() {
        let tar = sample_tar();
        let mut transcoder = ZipTranscoder::new(Vec::new());
        transcoder.write_tar(&tar[..RECORD + 3]).expect("prefix");
        let err = transcoder.finish().expect_err("member is cut short");
        assert!(matches!(err, GitError::Corrupt { .. }), "{err:?}");
    }
}
