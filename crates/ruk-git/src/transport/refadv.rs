//! Ref advertisements: protocol v0/v1 (capabilities after a NUL on the first
//! line) and protocol v2 (capability advertisement, then `ls-refs`).
//!
//! Every form normalizes to [`AdvertisedRef`] rows: name, OID (absent only
//! for a v2 `unborn` row), peeled OID, and symref target. A missing
//! `object-format` capability means SHA-1; a genuine mismatch with the local
//! store is [`GitError::ObjectFormat`] before any OID is interpreted.

use std::io::Read;

use ruk_core::ids::{HashKind, Oid};

use super::AGENT;
use super::pktline::{self, Packet, PktReader};
use crate::{GitError, parse_oid_for};

/// The negotiated Git wire protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// Original protocol, no version line.
    V0,
    /// `version 1` line followed by the v0 grammar.
    V1,
    /// Command-based protocol v2.
    V2,
}

/// An ordered capability list: `name` or `name=value` entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    entries: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl Capabilities {
    /// Parses a space-separated v0 capability list.
    #[must_use]
    pub fn parse_list(list: &[u8]) -> Self {
        let mut caps = Self::default();
        for word in list.split(|b| *b == b' ').filter(|w| !w.is_empty()) {
            caps.push_entry(word);
        }
        caps
    }

    /// Adds one `name` or `name=value` entry (one v2 capability line).
    pub fn push_entry(&mut self, entry: &[u8]) {
        match entry.iter().position(|b| *b == b'=') {
            Some(eq) => self
                .entries
                .push((entry[..eq].to_vec(), Some(entry[eq + 1..].to_vec()))),
            None => self.entries.push((entry.to_vec(), None)),
        }
    }

    /// Whether `name` is present, with or without a value.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.entries.iter().any(|(n, _)| n == name.as_bytes())
    }

    /// The first value of `name`.
    #[must_use]
    pub fn value(&self, name: &str) -> Option<&[u8]> {
        self.values(name).next()
    }

    /// Every value of `name` in order (`symref` may repeat).
    pub fn values<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a [u8]> + 'a {
        let name = name.as_bytes().to_vec();
        self.entries
            .iter()
            .filter(move |(n, _)| n.as_slice() == name.as_slice())
            .filter_map(|(_, v)| v.as_deref())
    }

    /// Whether the v2 capability `name` lists `feature` in its
    /// space-separated value (`fetch=shallow filter`).
    #[must_use]
    pub fn feature(&self, name: &str, feature: &str) -> bool {
        self.value(name).is_some_and(|value| {
            value
                .split(|b| *b == b' ')
                .any(|word| word == feature.as_bytes())
        })
    }

    /// The object format the peer speaks, required to equal `local`.
    ///
    /// # Errors
    /// [`GitError::ObjectFormat`] for an unknown or different format.
    pub fn object_format(&self, local: HashKind) -> Result<HashKind, GitError> {
        let remote = match self.value("object-format") {
            None => HashKind::Sha1,
            Some(b"sha1") => HashKind::Sha1,
            Some(b"sha256") => HashKind::Sha256,
            Some(other) => {
                return Err(GitError::ObjectFormat {
                    detail: format!("remote uses unknown object format {}", other.escape_ascii()),
                });
            }
        };
        if remote != local {
            return Err(GitError::ObjectFormat {
                detail: format!("remote uses {remote} but the local store is {local}"),
            });
        }
        Ok(remote)
    }
}

/// One normalized advertised ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertisedRef {
    /// Full ref name bytes as sent (`HEAD`, `refs/heads/main`).
    pub name: Vec<u8>,
    /// Target OID; `None` only for a v2 `unborn` symref.
    pub oid: Option<Oid>,
    /// The fully peeled OID of an annotated tag.
    pub peeled: Option<Oid>,
    /// The ref a symbolic ref points at.
    pub symref_target: Option<Vec<u8>>,
}

/// A v0/v1 advertisement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advertisement {
    /// [`ProtocolVersion::V0`] or [`ProtocolVersion::V1`].
    pub version: ProtocolVersion,
    /// Capabilities from the first line.
    pub capabilities: Capabilities,
    /// Advertised refs in wire order.
    pub refs: Vec<AdvertisedRef>,
    /// `shallow` lines of a shallow server repository.
    pub shallow: Vec<Oid>,
}

/// What a server sends first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Initial {
    /// A v0/v1 ref advertisement.
    Refs(Advertisement),
    /// A v2 capability advertisement; refs come from `ls-refs`.
    V2(Capabilities),
}

fn corrupt(detail: impl Into<String>) -> GitError {
    GitError::Corrupt {
        detail: detail.into(),
    }
}

fn split_once(line: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let at = line.iter().position(|b| *b == sep)?;
    Some((&line[..at], &line[at + 1..]))
}

fn oid_field(field: &[u8], kind: HashKind) -> Result<Oid, GitError> {
    let text = std::str::from_utf8(field)
        .map_err(|_| corrupt(format!("non-ASCII object id {}", field.escape_ascii())))?;
    parse_oid_for(text, kind).map_err(|err| match err {
        GitError::ObjectFormat { detail } => GitError::ObjectFormat { detail },
        other => corrupt(other.to_string()),
    })
}

fn ref_name(field: &[u8]) -> Result<Vec<u8>, GitError> {
    if field.is_empty() || field.iter().any(|b| matches!(b, 0 | b'\n' | b' ')) {
        return Err(corrupt(format!("malformed ref name {}", field.escape_ascii())));
    }
    Ok(field.to_vec())
}

/// Reads the first server response and dispatches on its version.
///
/// A smart-HTTP `# service=` preamble is skipped. `local` is the store hash
/// kind; the v0 capability list is checked against it before OIDs parse.
///
/// # Errors
/// [`GitError::Corrupt`] for grammar violations, [`GitError::Version`] for
/// an unknown protocol version, and [`GitError::ObjectFormat`].
pub fn read_initial<R: Read>(pkt: &mut PktReader<R>, local: HashKind) -> Result<Initial, GitError> {
    let mut first = owned_packet(pkt.read_packet()?);
    if let Some(line) = first.as_deref()
        && line.starts_with(b"# service=")
    {
        if pkt.read_packet()? != Packet::Flush {
            return Err(corrupt("service preamble is not followed by a flush"));
        }
        first = owned_packet(pkt.read_packet()?);
    }
    let Some(line) = first else {
        return Ok(Initial::Refs(Advertisement {
            version: ProtocolVersion::V0,
            capabilities: Capabilities::default(),
            refs: Vec::new(),
            shallow: Vec::new(),
        }));
    };
    match line.as_slice() {
        b"version 2" => {
            let mut caps = Capabilities::default();
            loop {
                match pkt.read_packet()? {
                    Packet::Flush => break,
                    Packet::Data(_) => {
                        let line = pkt_line_again(pkt)?;
                        caps.push_entry(&line);
                    }
                    other => return Err(corrupt(format!("unexpected {other:?} in capabilities"))),
                }
            }
            caps.object_format(local)?;
            Ok(Initial::V2(caps))
        }
        b"version 1" => {
            let first = owned_packet(pkt.read_packet()?);
            read_v0_rest(pkt, first, ProtocolVersion::V1, local).map(Initial::Refs)
        }
        version if version.starts_with(b"version ") => Err(GitError::Version {
            detail: format!("unsupported protocol {}", version.escape_ascii()),
        }),
        _ => read_v0_rest(pkt, Some(line), ProtocolVersion::V0, local).map(Initial::Refs),
    }
}

/// The last packet's line, re-borrowed after a match released the borrow.
fn pkt_line_again<R: Read>(pkt: &mut PktReader<R>) -> Result<Vec<u8>, GitError> {
    pkt.last_line()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| corrupt("missing capability line"))
}

fn owned_packet(packet: Packet<'_>) -> Option<Vec<u8>> {
    packet.line().map(<[u8]>::to_vec)
}

fn read_v0_rest<R: Read>(
    pkt: &mut PktReader<R>,
    first: Option<Vec<u8>>,
    version: ProtocolVersion,
    local: HashKind,
) -> Result<Advertisement, GitError> {
    let mut adv = Advertisement {
        version,
        capabilities: Capabilities::default(),
        refs: Vec::new(),
        shallow: Vec::new(),
    };
    let Some(first) = first else {
        return Ok(adv);
    };
    let (head, caps) = split_once(&first, 0).ok_or_else(|| corrupt("first ref line has no capability list"))?;
    adv.capabilities = Capabilities::parse_list(caps);
    let kind = adv.capabilities.object_format(local)?;
    let (oid, name) = split_once(head, b' ').ok_or_else(|| corrupt("malformed first ref line"))?;
    let oid = oid_field(oid, kind)?;
    if name == b"capabilities^{}" {
        if oid != kind.zero_oid() {
            return Err(corrupt("capabilities^{} line carries a non-zero id"));
        }
    } else {
        push_v0_ref(&mut adv.refs, oid, name)?;
    }
    loop {
        let packet = pkt.read_packet()?;
        let line = match packet {
            Packet::Flush => break,
            Packet::Data(_) => packet.line().unwrap_or_default().to_vec(),
            other => return Err(corrupt(format!("unexpected {other:?} in ref advertisement"))),
        };
        if let Some(rest) = line.strip_prefix(b"shallow ") {
            adv.shallow.push(oid_field(rest, kind)?);
            continue;
        }
        let (oid, name) = split_once(&line, b' ').ok_or_else(|| corrupt("malformed ref line"))?;
        let oid = oid_field(oid, kind)?;
        push_v0_ref(&mut adv.refs, oid, name)?;
    }
    for value in adv.capabilities.values("symref") {
        let (from, to) = split_once(value, b':').ok_or_else(|| corrupt("malformed symref capability"))?;
        if let Some(row) = adv.refs.iter_mut().find(|r| r.name == from) {
            row.symref_target = Some(ref_name(to)?);
        }
    }
    Ok(adv)
}

fn push_v0_ref(refs: &mut Vec<AdvertisedRef>, oid: Oid, name: &[u8]) -> Result<(), GitError> {
    if let Some(base) = name.strip_suffix(b"^{}") {
        let last = refs
            .last_mut()
            .filter(|r| r.name == base)
            .ok_or_else(|| corrupt(format!("peeled line for {} without its ref", base.escape_ascii())))?;
        last.peeled = Some(oid);
        return Ok(());
    }
    refs.push(AdvertisedRef {
        name: ref_name(name)?,
        oid: Some(oid),
        peeled: None,
        symref_target: None,
    });
    Ok(())
}

/// Builds a v2 `ls-refs` request asking for peeled and symref attributes,
/// `unborn` when the server offers it, limited to `prefixes` when given.
///
/// # Errors
/// [`GitError::Limit`] for a prefix longer than one frame.
pub fn ls_refs_request(
    caps: &Capabilities,
    kind: HashKind,
    prefixes: &[&[u8]],
) -> Result<Vec<u8>, GitError> {
    let mut out = Vec::new();
    write_command_header(&mut out, "ls-refs", caps, kind)?;
    pktline::encode_data(&mut out, b"peel\n")?;
    pktline::encode_data(&mut out, b"symrefs\n")?;
    if caps.feature("ls-refs", "unborn") {
        pktline::encode_data(&mut out, b"unborn\n")?;
    }
    for prefix in prefixes {
        let mut line = b"ref-prefix ".to_vec();
        line.extend_from_slice(prefix);
        line.push(b'\n');
        pktline::encode_data(&mut out, &line)?;
    }
    pktline::encode_flush(&mut out);
    Ok(out)
}

/// Writes `command=<name>`, `agent`, `object-format` (when advertised) and
/// the delimiter that opens the argument section of a v2 command.
pub(crate) fn write_command_header(
    out: &mut Vec<u8>,
    command: &str,
    caps: &Capabilities,
    kind: HashKind,
) -> Result<(), GitError> {
    pktline::encode_data(out, format!("command={command}\n").as_bytes())?;
    if caps.has("agent") {
        pktline::encode_data(out, format!("agent={AGENT}\n").as_bytes())?;
    }
    if caps.has("object-format") {
        pktline::encode_data(out, format!("object-format={}\n", kind.format_name()).as_bytes())?;
    }
    pktline::encode_delimiter(out);
    Ok(())
}

/// Parses a v2 `ls-refs` response up to its flush.
///
/// # Errors
/// [`GitError::Corrupt`] for grammar violations.
pub fn read_ls_refs<R: Read>(
    pkt: &mut PktReader<R>,
    kind: HashKind,
) -> Result<Vec<AdvertisedRef>, GitError> {
    let mut refs = Vec::new();
    loop {
        let packet = pkt.read_packet()?;
        let line = match packet {
            Packet::Flush => return Ok(refs),
            Packet::Data(_) => packet.line().unwrap_or_default(),
            other => return Err(corrupt(format!("unexpected {other:?} in ls-refs"))),
        };
        refs.push(parse_ls_refs_line(line, kind)?);
    }
}

/// Parses one `ls-refs` row: `(<oid> | unborn) SP <name> (SP <attr>)*`.
///
/// # Errors
/// [`GitError::Corrupt`] for a malformed row.
pub fn parse_ls_refs_line(line: &[u8], kind: HashKind) -> Result<AdvertisedRef, GitError> {
    let mut fields = line.split(|b| *b == b' ');
    let oid = fields.next().ok_or_else(|| corrupt("empty ls-refs line"))?;
    let name = fields.next().ok_or_else(|| corrupt("ls-refs line without a name"))?;
    let mut row = AdvertisedRef {
        name: ref_name(name)?,
        oid: if oid == b"unborn" {
            None
        } else {
            Some(oid_field(oid, kind)?)
        },
        peeled: None,
        symref_target: None,
    };
    for attr in fields {
        if let Some(target) = attr.strip_prefix(b"symref-target:") {
            row.symref_target = Some(ref_name(target)?);
        } else if let Some(peeled) = attr.strip_prefix(b"peeled:") {
            row.peeled = Some(oid_field(peeled, kind)?);
        }
    }
    if row.oid.is_none() && row.symref_target.is_none() {
        return Err(corrupt("unborn ls-refs row without a symref target"));
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Interrupt;

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";
    const Z: &str = "0000000000000000000000000000000000000000";

    fn wire(lines: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for line in lines {
            if line.is_empty() {
                pktline::encode_flush(&mut out);
            } else {
                pktline::encode_data(&mut out, line).expect("frame");
            }
        }
        out
    }

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).expect("hex")
    }

    #[test]
    fn parses_v0_with_caps_peeled_symref_shallow() {
        let first = format!("{A} HEAD\0multi_ack side-band-64k symref=HEAD:refs/heads/main agent=git/2\n");
        let main = format!("{A} refs/heads/main\n");
        let tag = format!("{B} refs/tags/v1\n");
        let peeled = format!("{A} refs/tags/v1^{{}}\n");
        let shallow = format!("shallow {B}\n");
        let bytes = wire(&[
            first.as_bytes(),
            main.as_bytes(),
            tag.as_bytes(),
            peeled.as_bytes(),
            shallow.as_bytes(),
            b"",
        ]);
        let mut pkt = PktReader::new(&bytes[..], Interrupt::none());
        let Initial::Refs(adv) = read_initial(&mut pkt, HashKind::Sha1).expect("v0") else {
            panic!("expected v0");
        };
        assert_eq!(adv.version, ProtocolVersion::V0);
        assert!(adv.capabilities.has("side-band-64k"));
        assert_eq!(adv.refs.len(), 3);
        assert_eq!(adv.refs[0].symref_target.as_deref(), Some(&b"refs/heads/main"[..]));
        assert_eq!(adv.refs[2].peeled, Some(oid(A)));
        assert_eq!(adv.shallow, vec![oid(B)]);
    }

    #[test]
    fn empty_repository_and_v1_and_service_preamble() {
        let first = format!("{Z} capabilities^{{}}\0report-status delete-refs\n");
        let bytes = wire(&[b"# service=git-receive-pack\n", b"", b"version 1\n", first.as_bytes(), b""]);
        let mut pkt = PktReader::new(&bytes[..], Interrupt::none());
        let Initial::Refs(adv) = read_initial(&mut pkt, HashKind::Sha1).expect("v1") else {
            panic!("expected v1");
        };
        assert_eq!(adv.version, ProtocolVersion::V1);
        assert!(adv.refs.is_empty());
        assert!(adv.capabilities.has("delete-refs"));
    }

    #[test]
    fn object_format_mismatch_and_missing_default() {
        let first = format!("{A} HEAD\0object-format=sha256\n");
        let bytes = wire(&[first.as_bytes(), b""]);
        let mut pkt = PktReader::new(&bytes[..], Interrupt::none());
        assert!(matches!(
            read_initial(&mut pkt, HashKind::Sha1),
            Err(GitError::ObjectFormat { .. })
        ));
        let caps = Capabilities::parse_list(b"ofs-delta");
        assert_eq!(caps.object_format(HashKind::Sha1).expect("default"), HashKind::Sha1);
        assert!(caps.object_format(HashKind::Sha256).is_err());
    }

    #[test]
    fn orphan_peeled_line_and_bad_oid_are_corrupt() {
        let first = format!("{A} refs/heads/a\0\n");
        let orphan = format!("{A} refs/tags/x^{{}}\n");
        let bytes = wire(&[first.as_bytes(), orphan.as_bytes(), b""]);
        let mut pkt = PktReader::new(&bytes[..], Interrupt::none());
        assert!(matches!(read_initial(&mut pkt, HashKind::Sha1), Err(GitError::Corrupt { .. })));
        let bytes = wire(&[b"xyz HEAD\0\n", b""]);
        let mut pkt = PktReader::new(&bytes[..], Interrupt::none());
        assert!(matches!(read_initial(&mut pkt, HashKind::Sha1), Err(GitError::Corrupt { .. })));
    }

    #[test]
    fn v2_capabilities_and_ls_refs() {
        let bytes = wire(&[
            b"version 2\n",
            b"agent=git/2.50\n",
            b"ls-refs=unborn\n",
            b"fetch=shallow filter\n",
            b"",
        ]);
        let mut pkt = PktReader::new(&bytes[..], Interrupt::none());
        let Initial::V2(caps) = read_initial(&mut pkt, HashKind::Sha1).expect("v2") else {
            panic!("expected v2");
        };
        assert!(caps.feature("fetch", "filter"));
        assert!(caps.feature("ls-refs", "unborn"));
        let request = ls_refs_request(&caps, HashKind::Sha1, &[b"refs/heads/"]).expect("request");
        let expected = {
            let mut out = Vec::new();
            pktline::encode_data(&mut out, b"command=ls-refs\n").expect("f");
            pktline::encode_data(&mut out, format!("agent={AGENT}\n").as_bytes()).expect("f");
            pktline::encode_delimiter(&mut out);
            for line in [&b"peel\n"[..], b"symrefs\n", b"unborn\n", b"ref-prefix refs/heads/\n"] {
                pktline::encode_data(&mut out, line).expect("f");
            }
            pktline::encode_flush(&mut out);
            out
        };
        assert_eq!(request, expected);

        let head = format!("{A} HEAD symref-target:refs/heads/main\n");
        let tag = format!("{B} refs/tags/v1 peeled:{A}\n");
        let bytes = wire(&[head.as_bytes(), tag.as_bytes(), b"unborn refs/x symref-target:refs/heads/y\n", b""]);
        let mut pkt = PktReader::new(&bytes[..], Interrupt::none());
        let refs = read_ls_refs(&mut pkt, HashKind::Sha1).expect("ls-refs");
        assert_eq!(refs[0].symref_target.as_deref(), Some(&b"refs/heads/main"[..]));
        assert_eq!(refs[1].peeled, Some(oid(A)));
        assert_eq!(refs[2].oid, None);
        assert!(parse_ls_refs_line(b"unborn HEAD", HashKind::Sha1).is_err());
    }
}
