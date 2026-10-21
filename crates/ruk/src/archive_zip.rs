//! Tar-to-zip transcoding shared by the CLI archive verb and the daemon's
//! streamed archive reads.
//!
//! [`ZipTranscoder`] is a streaming [`TarSink`]: tar bytes arrive in any
//! chunking and zip bytes leave through the inner writer as entries
//! complete, so neither side ever holds a whole archive. The state machine
//! follows the serve half's ustar layout. `g` globals and `x` pax records
//! carry no entry of their own (an `x` `path` record only renames the entry
//! after it). `5` members become directories, `2` members symlinks, and `0`
//! members files whose bodies stream into their zip entry.
//!
//! Names and symlink targets must be UTF-8: the zip writer stores them as
//! text, so a non-UTF-8 name refuses instead of landing mojibake.

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

/// A streaming tar-to-zip transcoder. Zip output goes to the inner writer
/// as each entry completes; [`Self::close`] writes the central directory.
pub(crate) struct ZipTranscoder<W: Write> {
    zip: Option<ZipWriter<StreamWriter<W>>>,
    phase: Phase,
    header: Vec<u8>,
    held_path: Option<Vec<u8>>,
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
            held_path: None,
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
        let size = parse_octal(&header[124..136], "size")?;
        let mode = u32::try_from(parse_octal(&header[100..108], "mode")?)
            .map_err(|_| corrupt("archive member mode overflows"))?;
        let mtime = parse_octal(&header[136..148], "mtime")?;
        let options = SimpleFileOptions::default()
            .unix_permissions(mode)
            .last_modified_time(zip_mtime(mtime));
        match header[156] {
            typeflag @ (b'x' | b'g') => {
                if size > MAX_PAX_BYTES {
                    return Err(corrupt("pax record exceeds the transcoder bound"));
                }
                self.phase = if size == 0 {
                    Phase::Header
                } else {
                    Phase::Pax {
                        buf: Vec::new(),
                        remaining: size,
                        pad: pad_for(size),
                        global: typeflag == b'g',
                    }
                };
            }
            b'5' => {
                let name = self.take_name(header)?;
                self.zip_mut()?
                    .add_directory(name, options)
                    .map_err(zip_failed)?;
                self.phase = skip_body(size);
            }
            b'2' => {
                let name = self.take_name(header)?;
                let target = String::from_utf8(header_linkname(header))
                    .map_err(|_| corrupt("symlink target is not UTF-8; zip stores it as text"))?;
                self.zip_mut()?
                    .add_symlink(name, target, options)
                    .map_err(zip_failed)?;
                self.phase = skip_body(size);
            }
            b'0' => {
                let name = self.take_name(header)?;
                let method = if size == 0 {
                    CompressionMethod::Stored
                } else {
                    CompressionMethod::Deflated
                };
                self.zip_mut()?
                    .start_file(name, options.compression_method(method))
                    .map_err(zip_failed)?;
                self.phase = if size == 0 {
                    Phase::Header
                } else {
                    Phase::File {
                        remaining: size,
                        pad: pad_for(size),
                    }
                };
            }
            other => {
                return Err(corrupt(format!("archive member has unknown type {other}")));
            }
        }
        Ok(())
    }

    /// The name of the member a record describes: the `x` path record held
    /// from before it, else the ustar fields. Names must be UTF-8.
    fn take_name(&mut self, header: &[u8; RECORD]) -> Result<String, GitError> {
        let raw = self.held_path.take().unwrap_or_else(|| header_name(header));
        String::from_utf8(raw)
            .map_err(|_| corrupt("archive member name is not UTF-8; zip stores names as text"))
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
                    if wide(buf.len()) + wide(take) > MAX_PAX_BYTES {
                        return Err(corrupt("pax record exceeds the transcoder bound"));
                    }
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
                        if !global && let Some(path) = pax_path_record(&buf) {
                            self.held_path = Some(path);
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

/// Reads the `path` record out of pax extended-header data, if present.
pub(crate) fn pax_path_record(data: &[u8]) -> Option<Vec<u8>> {
    let mut rest = data;
    while !rest.is_empty() {
        let space = rest.iter().position(|byte| *byte == b' ')?;
        let len: usize = std::str::from_utf8(&rest[..space]).ok()?.parse().ok()?;
        if len == 0 || len > rest.len() {
            return None;
        }
        let record = &rest[..len];
        rest = &rest[len..];
        if !record.ends_with(b"\n") {
            continue;
        }
        let body = &record[space + 1..record.len() - 1];
        if let Some(value) = body.strip_prefix(b"path=") {
            return Some(value.to_vec());
        }
    }
    None
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
    fn truncated_member_refuses_at_finish() {
        let tar = sample_tar();
        let mut transcoder = ZipTranscoder::new(Vec::new());
        transcoder.write_tar(&tar[..RECORD + 3]).expect("prefix");
        let err = transcoder.finish().expect_err("member is cut short");
        assert!(matches!(err, GitError::Corrupt { .. }), "{err:?}");
    }
}
