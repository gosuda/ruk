//! pkt-line framing (gitprotocol-common) and side-band demultiplexing.
//!
//! A frame is a four-digit lowercase-or-uppercase hex length that counts
//! itself, then the payload. `0000` is flush, `0001` delimiter and `0002`
//! response-end (protocol v2); `0003` and any other length below four are
//! corrupt. A frame never exceeds [`LARGE_PACKET_MAX`] bytes, Git's own
//! bound. The slice decoder [`decode_frame`] is total: truncated input asks
//! for more bytes and malformed input is [`GitError::Corrupt`]; it never
//! panics on any input.
//!
//! Side-band multiplexing carries pack data on band 1, progress on band 2
//! and a fatal remote error on band 3. Accumulated progress and error text
//! is bounded by [`ruk_core::MAX_CONTROL_FRAME_BYTES`], the one control
//! bound, so a peer cannot grow it without limit.

use std::io::{self, Read, Write};

use ruk_core::MAX_CONTROL_FRAME_BYTES;

use super::Interrupt;
use crate::GitError;

/// Largest frame including its four length bytes (Git `LARGE_PACKET_MAX`).
pub const LARGE_PACKET_MAX: usize = 65520;
/// Largest payload of one frame.
pub const LARGE_PACKET_DATA_MAX: usize = LARGE_PACKET_MAX - 4;
/// Largest frame of the original `side-band` capability (Git: 1000 bytes).
pub const SMALL_SIDEBAND_MAX: usize = 1000;

/// One decoded frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    /// `0000`.
    Flush,
    /// `0001`, protocol v2 section delimiter.
    Delimiter,
    /// `0002`, protocol v2 stateless response end.
    ResponseEnd,
    /// A data frame payload, possibly empty (`0004`).
    Data(&'a [u8]),
}

impl Packet<'_> {
    /// The payload of a data frame with one trailing LF removed, or `None`
    /// for a special frame.
    #[must_use]
    pub fn line(&self) -> Option<&[u8]> {
        match self {
            Packet::Data(payload) => Some(payload.strip_suffix(b"\n").unwrap_or(payload)),
            _ => None,
        }
    }
}

fn hex_digit(byte: u8) -> Option<usize> {
    match byte {
        b'0'..=b'9' => Some(usize::from(byte - b'0')),
        b'a'..=b'f' => Some(usize::from(byte - b'a') + 10),
        b'A'..=b'F' => Some(usize::from(byte - b'A') + 10),
        _ => None,
    }
}

/// Parses a four-byte length prefix.
///
/// # Errors
/// [`GitError::Corrupt`] for non-hex bytes, the reserved lengths 3 and
/// below-4 values other than the special frames, and frames above
/// [`LARGE_PACKET_MAX`].
pub fn parse_length(prefix: [u8; 4]) -> Result<usize, GitError> {
    let mut len = 0usize;
    for byte in prefix {
        let digit = hex_digit(byte).ok_or_else(|| GitError::Corrupt {
            detail: format!(
                "pkt-line length {:?} is not hex",
                prefix.escape_ascii().to_string()
            ),
        })?;
        len = len * 16 + digit;
    }
    if len == 3 {
        return Err(GitError::Corrupt {
            detail: "pkt-line length 0003 is invalid".to_owned(),
        });
    }
    if len > LARGE_PACKET_MAX {
        return Err(GitError::Corrupt {
            detail: format!("pkt-line length {len} exceeds {LARGE_PACKET_MAX}"),
        });
    }
    Ok(len)
}

/// Decodes one frame from the start of `input`.
///
/// Returns `Ok(None)` when `input` holds only part of a frame, and the frame
/// with the number of bytes it consumed otherwise.
///
/// # Errors
/// [`GitError::Corrupt`] for a malformed length.
pub fn decode_frame(input: &[u8]) -> Result<Option<(Packet<'_>, usize)>, GitError> {
    let Some(prefix) = input.first_chunk::<4>() else {
        return Ok(None);
    };
    let len = parse_length(*prefix)?;
    let packet = match len {
        0 => Packet::Flush,
        1 => Packet::Delimiter,
        2 => Packet::ResponseEnd,
        _ => match input.get(4..len) {
            Some(payload) => Packet::Data(payload),
            None => return Ok(None),
        },
    };
    Ok(Some((packet, len.max(4))))
}

/// Appends one data frame to `out`.
///
/// # Errors
/// [`GitError::Limit`] when `payload` exceeds [`LARGE_PACKET_DATA_MAX`].
pub fn encode_data(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), GitError> {
    if payload.len() > LARGE_PACKET_DATA_MAX {
        return Err(GitError::Limit {
            detail: format!(
                "pkt-line payload of {} bytes exceeds {LARGE_PACKET_DATA_MAX}",
                payload.len()
            ),
        });
    }
    let len = payload.len() + 4;
    out.extend_from_slice(format!("{len:04x}").as_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Appends a flush frame.
pub fn encode_flush(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0000");
}

/// Appends a delimiter frame.
pub fn encode_delimiter(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0001");
}

/// Appends a response-end frame.
pub fn encode_response_end(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0002");
}

/// Writes an assembled request and flushes the writer.
///
/// # Errors
/// [`GitError::Io`] when the peer cannot accept the bytes.
pub fn send<W: Write + ?Sized>(writer: &mut W, bytes: &[u8]) -> Result<(), GitError> {
    writer
        .write_all(bytes)
        .and_then(|()| writer.flush())
        .map_err(|err| io_error("sending to the remote", &err))
}

/// Maps an I/O failure, unwrapping a [`GitError`] carried inside it.
pub(crate) fn io_error(what: &str, err: &io::Error) -> GitError {
    if let Some(inner) = err.get_ref().and_then(|e| e.downcast_ref::<GitError>()) {
        return inner.clone();
    }
    GitError::Io {
        detail: format!("{what}: {err}"),
    }
}

/// Reads frames from a byte stream into one reusable buffer.
#[derive(Debug)]
pub struct PktReader<R> {
    inner: R,
    buf: Vec<u8>,
    last_data: bool,
    interrupt: Interrupt,
}

impl<R: Read> PktReader<R> {
    /// Wraps `inner`, checking `interrupt` before every frame.
    pub fn new(inner: R, interrupt: Interrupt) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(LARGE_PACKET_MAX),
            last_data: false,
            interrupt,
        }
    }

    /// The wrapped stream, for writing requests on a duplex connection.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// The interrupt checked before each frame.
    pub fn interrupt(&self) -> &Interrupt {
        &self.interrupt
    }

    /// The line payload of the last frame read, or `None` when the last
    /// frame was not data.
    pub fn last_line(&self) -> Option<&[u8]> {
        self.last_data
            .then(|| self.buf.strip_suffix(b"\n").unwrap_or(&self.buf[..]))
    }

    /// Reads one frame.
    ///
    /// # Errors
    /// [`GitError::Io`] when the remote hangs up before a frame begins,
    /// [`GitError::Corrupt`] for a malformed or truncated frame, and
    /// [`GitError::Cancelled`] from the interrupt.
    pub fn read_packet(&mut self) -> Result<Packet<'_>, GitError> {
        self.interrupt.check("reading from the remote")?;
        let mut prefix = [0u8; 4];
        let mut filled = 0;
        while filled < 4 {
            let got = read_some(&mut self.inner, &mut prefix[filled..])?;
            if got == 0 {
                return Err(if filled == 0 {
                    GitError::Io {
                        detail: "the remote end hung up unexpectedly".to_owned(),
                    }
                } else {
                    GitError::Corrupt {
                        detail: "truncated pkt-line length".to_owned(),
                    }
                });
            }
            filled += got;
        }
        let len = parse_length(prefix)?;
        match len {
            0 => {
                self.last_data = false;
                return Ok(Packet::Flush);
            }
            1 => {
                self.last_data = false;
                return Ok(Packet::Delimiter);
            }
            2 => {
                self.last_data = false;
                return Ok(Packet::ResponseEnd);
            }
            _ => {}
        }
        let payload = len - 4;
        self.buf.resize(payload, 0);
        let mut filled = 0;
        while filled < payload {
            let got = read_some(&mut self.inner, &mut self.buf[filled..])?;
            if got == 0 {
                return Err(GitError::Corrupt {
                    detail: format!("truncated pkt-line: {filled} of {payload} payload bytes"),
                });
            }
            filled += got;
        }
        self.last_data = true;
        Ok(Packet::Data(&self.buf[..payload]))
    }

    /// Reads one frame that must be a data line, returning it without its
    /// trailing LF.
    ///
    /// # Errors
    /// As [`Self::read_packet`], and [`GitError::Corrupt`] for a special
    /// frame where `what` was expected.
    pub fn read_line(&mut self, what: &str) -> Result<&[u8], GitError> {
        match self.read_packet()? {
            Packet::Data(payload) => Ok(payload.strip_suffix(b"\n").unwrap_or(payload)),
            other => Err(GitError::Corrupt {
                detail: format!("expected {what}, got {other:?}"),
            }),
        }
    }
}

fn read_some<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, GitError> {
    loop {
        match reader.read(buf) {
            Ok(n) => return Ok(n),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(io_error("reading from the remote", &err)),
        }
    }
}

/// One side-band frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band<'a> {
    /// Band 1: payload data.
    Data(&'a [u8]),
    /// Band 2: progress text.
    Progress(&'a [u8]),
    /// Band 3: a fatal remote error message.
    Error(&'a [u8]),
}

/// Splits a side-band frame payload into its band.
///
/// # Errors
/// [`GitError::Corrupt`] for an empty payload or an unknown band.
pub fn demux(payload: &[u8]) -> Result<Band<'_>, GitError> {
    match payload.split_first() {
        Some((1, rest)) => Ok(Band::Data(rest)),
        Some((2, rest)) => Ok(Band::Progress(rest)),
        Some((3, rest)) => Ok(Band::Error(rest)),
        Some((band, _)) => Err(GitError::Corrupt {
            detail: format!("unknown side-band {band}"),
        }),
        None => Err(GitError::Corrupt {
            detail: "empty side-band frame".to_owned(),
        }),
    }
}

/// Bounded text accumulated from bands 2 and 3.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemoteMessages {
    /// Progress text in arrival order, up to the control bound.
    pub progress: Vec<u8>,
    /// Whether progress past the bound was discarded.
    pub truncated: bool,
}

impl RemoteMessages {
    fn push_progress(&mut self, text: &[u8]) {
        let room = MAX_CONTROL_FRAME_BYTES.saturating_sub(self.progress.len());
        if text.len() > room {
            self.truncated = true;
        }
        self.progress
            .extend_from_slice(&text[..text.len().min(room)]);
    }
}

/// Reads band-1 bytes of a side-band stream as a plain [`Read`] until the
/// terminating flush. Band 2 is collected into [`RemoteMessages`]; band 3
/// fails the read with the remote's message. Without side-band the frames
/// themselves are not used and the caller reads the stream directly.
#[derive(Debug)]
pub struct SidebandReader<'p, R> {
    pkt: &'p mut PktReader<R>,
    max_frame: usize,
    pending: Vec<u8>,
    pos: usize,
    done: bool,
    messages: RemoteMessages,
}

impl<'p, R: Read> SidebandReader<'p, R> {
    /// Demultiplexes frames from `pkt`; `max_frame` is
    /// [`LARGE_PACKET_MAX`] for `side-band-64k` and [`SMALL_SIDEBAND_MAX`]
    /// for `side-band`.
    pub fn new(pkt: &'p mut PktReader<R>, max_frame: usize) -> Self {
        Self {
            pkt,
            max_frame,
            pending: Vec::new(),
            pos: 0,
            done: false,
            messages: RemoteMessages::default(),
        }
    }

    /// Whether the terminating flush was read.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.done
    }

    /// Progress text gathered so far.
    #[must_use]
    pub fn messages(&self) -> &RemoteMessages {
        &self.messages
    }

    /// Consumes band-1 bytes until the terminating flush, discarding them.
    /// Used after a pack trailer to reach the end of the section.
    ///
    /// # Errors
    /// As [`Self::fill`]; band-1 bytes after the pack are
    /// [`GitError::Corrupt`].
    pub fn drain_to_end(&mut self) -> Result<RemoteMessages, GitError> {
        if self.pos < self.pending.len() {
            return Err(GitError::Corrupt {
                detail: "unexpected bytes after the pack trailer".to_owned(),
            });
        }
        if self.fill()? {
            return Err(GitError::Corrupt {
                detail: "unexpected bytes after the pack trailer".to_owned(),
            });
        }
        Ok(std::mem::take(&mut self.messages))
    }

    /// Loads the next band-1 payload; `false` at the terminating flush.
    fn fill(&mut self) -> Result<bool, GitError> {
        while !self.done {
            let max_frame = self.max_frame;
            let packet = self.pkt.read_packet()?;
            let payload = match packet {
                Packet::Flush | Packet::ResponseEnd => {
                    self.done = true;
                    break;
                }
                Packet::Delimiter => {
                    return Err(GitError::Corrupt {
                        detail: "delimiter inside a side-band stream".to_owned(),
                    });
                }
                Packet::Data(payload) => payload,
            };
            if payload.len() + 4 > max_frame {
                return Err(GitError::Corrupt {
                    detail: format!(
                        "side-band frame of {} bytes exceeds {max_frame}",
                        payload.len() + 4
                    ),
                });
            }
            match demux(payload)? {
                Band::Data(data) if data.is_empty() => {}
                Band::Data(data) => {
                    self.pending.clear();
                    self.pending.extend_from_slice(data);
                    self.pos = 0;
                    return Ok(true);
                }
                Band::Progress(text) => self.messages.push_progress(text),
                Band::Error(text) => {
                    let shown = &text[..text.len().min(MAX_CONTROL_FRAME_BYTES)];
                    return Err(GitError::Io {
                        detail: format!("remote error: {}", shown.escape_ascii()),
                    });
                }
            }
        }
        Ok(false)
    }
}

impl<R: Read> Read for SidebandReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos == self.pending.len() && !self.fill().map_err(io::Error::other)? {
            return Ok(0);
        }
        let available = &self.pending[self.pos..];
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(bytes: &[u8]) -> Result<Vec<Packet<'_>>, GitError> {
        let mut out = Vec::new();
        let mut rest = bytes;
        while let Some((packet, used)) = decode_frame(rest)? {
            out.push(packet);
            rest = &rest[used..];
        }
        Ok(out)
    }

    #[test]
    fn decodes_specials_data_and_empty() {
        let got = frames(b"0000000100020004000ahello\n").expect("valid frames");
        assert_eq!(
            got,
            vec![
                Packet::Flush,
                Packet::Delimiter,
                Packet::ResponseEnd,
                Packet::Data(b""),
                Packet::Data(b"hello\n"),
            ]
        );
        assert_eq!(got[4].line(), Some(&b"hello"[..]));
    }

    #[test]
    fn malformed_input_table() {
        let corrupt: &[&[u8]] = &[
            b"0003",
            b"zzzz",
            b"00g4",
            b"fff1xxxx",
            b"ffffxxxx",
            b"-001",
            b" 004",
        ];
        for input in corrupt {
            let err = decode_frame(input).expect_err("must reject");
            assert!(
                matches!(err, GitError::Corrupt { .. }),
                "{:?} gave {err:?}",
                input.escape_ascii().to_string()
            );
        }
        let incomplete: &[&[u8]] = &[b"", b"0", b"00", b"000", b"0009abc", b"fff0"];
        for input in incomplete {
            assert_eq!(decode_frame(input).expect("prefix is fine"), None);
        }
    }

    #[test]
    fn decoder_is_total_over_short_inputs() {
        // Every two-byte suffix after every interesting prefix: no panic.
        let prefixes: &[&[u8]] = &[b"", b"0", b"00", b"000", b"0005", b"fff0"];
        for prefix in prefixes {
            for a in 0..=255u8 {
                let mut input = prefix.to_vec();
                input.push(a);
                let _ = decode_frame(&input);
                input.push(b'0');
                let _ = decode_frame(&input);
            }
        }
    }

    #[test]
    fn uppercase_hex_lengths_are_accepted() {
        let mut input = b"000A".to_vec();
        input.extend_from_slice(b"abcdef");
        assert_eq!(
            decode_frame(&input).expect("valid"),
            Some((Packet::Data(b"abcdef"), 10))
        );
    }

    #[test]
    fn encode_round_trips_and_bounds_payload() {
        let mut out = Vec::new();
        encode_data(&mut out, b"want x\n").expect("small");
        encode_delimiter(&mut out);
        encode_flush(&mut out);
        encode_response_end(&mut out);
        assert_eq!(out, b"000bwant x\n000100000002");
        let big = vec![0u8; LARGE_PACKET_DATA_MAX + 1];
        assert!(matches!(
            encode_data(&mut Vec::new(), &big),
            Err(GitError::Limit { .. })
        ));
        let max = vec![7u8; LARGE_PACKET_DATA_MAX];
        let mut out = Vec::new();
        encode_data(&mut out, &max).expect("exactly the bound");
        assert_eq!(&out[..4], b"fff0");
    }

    #[test]
    fn reader_reports_truncation_and_hangup() {
        let mut reader = PktReader::new(&b"0009ab"[..], Interrupt::none());
        assert!(matches!(
            reader.read_packet(),
            Err(GitError::Corrupt { .. })
        ));
        let mut reader = PktReader::new(&b"00"[..], Interrupt::none());
        assert!(matches!(
            reader.read_packet(),
            Err(GitError::Corrupt { .. })
        ));
        let mut reader = PktReader::new(&b""[..], Interrupt::none());
        assert!(matches!(reader.read_packet(), Err(GitError::Io { .. })));
    }

    #[test]
    fn sideband_demuxes_bands() {
        let mut wire = Vec::new();
        encode_data(&mut wire, b"\x02counting\r").expect("frame");
        encode_data(&mut wire, b"\x01PACK").expect("frame");
        encode_data(&mut wire, b"\x01data").expect("frame");
        encode_flush(&mut wire);
        let mut pkt = PktReader::new(&wire[..], Interrupt::none());
        let mut band = SidebandReader::new(&mut pkt, LARGE_PACKET_MAX);
        let mut data = Vec::new();
        band.read_to_end(&mut data).expect("bands");
        assert_eq!(data, b"PACKdata");
        assert!(band.finished());
        assert_eq!(band.messages().progress, b"counting\r");
    }

    #[test]
    fn sideband_error_band_fails_and_unknown_band_is_corrupt() {
        let mut wire = Vec::new();
        encode_data(&mut wire, b"\x03access denied\n").expect("frame");
        let mut pkt = PktReader::new(&wire[..], Interrupt::none());
        let mut band = SidebandReader::new(&mut pkt, LARGE_PACKET_MAX);
        let err = band.read_to_end(&mut Vec::new()).expect_err("band 3");
        assert!(
            matches!(io_error("x", &err), GitError::Io { detail } if detail.contains("access denied"))
        );

        assert!(matches!(demux(b"\x04x"), Err(GitError::Corrupt { .. })));
        assert!(matches!(demux(b""), Err(GitError::Corrupt { .. })));
    }

    #[test]
    fn small_sideband_rejects_oversized_frames() {
        let mut wire = Vec::new();
        let mut payload = vec![1u8];
        payload.extend(std::iter::repeat_n(0u8, SMALL_SIDEBAND_MAX));
        encode_data(&mut wire, &payload).expect("frame");
        let mut pkt = PktReader::new(&wire[..], Interrupt::none());
        let mut band = SidebandReader::new(&mut pkt, SMALL_SIDEBAND_MAX);
        let err = band.read_to_end(&mut Vec::new()).expect_err("too large");
        assert!(matches!(io_error("x", &err), GitError::Corrupt { .. }));
    }
}
