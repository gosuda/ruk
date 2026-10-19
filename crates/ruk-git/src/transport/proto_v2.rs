//! Protocol v2 session primitives: `ls-refs`, `fetch` and `object-info`
//! command framing plus the capability advertisement and the fetch
//! response sections shared by the stateful and smart-http transports.
//!
//! The wire grammar follows `git/Documentation/gitprotocol-v2.adoc`:
//! one `command=<name>` line, the negotiated capability lines (`agent`,
//! `object-format`), a delimiter, the command arguments, and a flush.
//! Capability *negotiation* (which args a server honors) stays with the
//! caller, the way [`super::fetch::receive`] gates `filter` and `shallow`
//! on the advertised `fetch` features: this module frames what it is
//! told, and refuses only malformed requests (empty wants/oids, detached
//! prefixes). Servers ignore no unknown argument, so callers MUST gate
//! feature arguments (`unborn`, `filter`, `deepen`, `thin-pack`,
//! `ofs-delta`, `sideband-all`, `object-info` attrs) on the capability
//! advertisement first.
//!
//! The git-daemon handshake already asks for v2 first (`version=2` in the
//! initial request; see [`super::net`]), and smart-http probes with the
//! [`GIT_PROTOCOL_HEADER`]; both fall back to v0 when the server answers
//! a v0 advertisement, so the v0 paths stay untouched.

use std::io::Read;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::Store;

use super::fetch::Filter;
use super::pack::{IngestLimits, StagedPack, ingest_pack};
use super::pktline::{self, Packet, PktReader, RemoteMessages, SidebandReader};
use super::refadv::{self, Capabilities};
use super::Interrupt;
use crate::GitError;

/// The HTTP header that asks a smart-http server to speak protocol v2
/// (`git/Documentation/gitprotocol-v2.adoc`, "HTTP Transport").
pub const GIT_PROTOCOL_HEADER: &str = "Git-Protocol";
/// The header value selecting protocol v2.
pub const GIT_PROTOCOL_V2_VALUE: &str = "version=2";

/// What one `ls-refs` command asks for (`gitprotocol-v2.adoc` "ls-refs").
///
/// `unborn` is sent only when the server advertises the `unborn`
/// `ls-refs` feature; a server without it would refuse the argument.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LsRefsCommand {
    /// `ref-prefix` lines limiting the advertisement (pure optimization;
    /// the caller still filters the result itself).
    pub prefixes: Vec<Vec<u8>>,
    /// Ask for peeled tags (`peel`).
    pub peel: bool,
    /// Ask for symref targets (`symrefs`).
    pub symrefs: bool,
    /// Ask for unborn `HEAD` (`unborn`, feature-gated).
    pub unborn: bool,
}

impl LsRefsCommand {
    /// The advertisement read every fetch and ls-remote performs: peeled
    /// tags, symref targets, unborn `HEAD` when offered.
    #[must_use]
    pub fn advertisement(prefixes: Vec<Vec<u8>>) -> Self {
        Self {
            prefixes,
            peel: true,
            symrefs: true,
            unborn: true,
        }
    }
}

/// Builds one `command=ls-refs` request: the command header, the requested
/// argument lines, and the closing flush.
///
/// # Errors
/// [`GitError::Limit`] for a prefix longer than one frame.
pub fn ls_refs_request(
    caps: &Capabilities,
    kind: HashKind,
    cmd: &LsRefsCommand,
) -> Result<Vec<u8>, GitError> {
    let mut out = Vec::new();
    refadv::write_command_header(&mut out, "ls-refs", caps, kind)?;
    if cmd.peel {
        pktline::encode_data(&mut out, b"peel\n")?;
    }
    if cmd.symrefs {
        pktline::encode_data(&mut out, b"symrefs\n")?;
    }
    if cmd.unborn && caps.feature("ls-refs", "unborn") {
        pktline::encode_data(&mut out, b"unborn\n")?;
    }
    for prefix in &cmd.prefixes {
        let mut line = b"ref-prefix ".to_vec();
        line.extend_from_slice(prefix);
        line.push(b'\n');
        pktline::encode_data(&mut out, &line)?;
    }
    pktline::encode_flush(&mut out);
    Ok(out)
}

/// What one `fetch` command asks for (`gitprotocol-v2.adoc` "fetch").
///
/// The caller resolves `filter`/`depth`/`sideband_all` against the
/// advertised `fetch` features first (unadvertised arguments are server
/// errors, not warnings); `thin_pack`/`ofs_delta` likewise gate on the
/// `thin-pack`/`ofs-delta` features, and stay unset against servers that
/// do not list them, which then send whole packs.
#[derive(Clone, Debug, Default)]
pub struct FetchCommand<'a> {
    /// OIDs to retrieve (`want` lines, at least one).
    pub wants: &'a [Oid],
    /// Local OIDs offered as common history (`have` lines).
    pub haves: &'a [Oid],
    /// Local shallow boundaries (`shallow` lines).
    pub shallows: &'a [Oid],
    /// Shallow depth (`deepen`, feature-gated).
    pub depth: Option<u32>,
    /// Partial-clone filter (`filter`, feature-gated).
    pub filter: Option<Filter>,
    /// Ask for a thin pack (`thin-pack`, feature-gated).
    pub thin_pack: bool,
    /// Accept `OBJ_OFS_DELTA` pack entries (`ofs-delta`, feature-gated).
    pub ofs_delta: bool,
    /// Multiplex the whole response (`sideband-all`, feature-gated).
    pub sideband_all: bool,
}

/// Builds one `command=fetch` request: the command header, wants, haves,
/// negotiated pack lines, `done`, and the closing flush.
///
/// # Errors
/// [`GitError::Invalid`] with no wants; [`GitError::Limit`] for an
/// argument longer than one frame.
pub fn fetch_request(
    caps: &Capabilities,
    kind: HashKind,
    cmd: &FetchCommand<'_>,
) -> Result<Vec<u8>, GitError> {
    if cmd.wants.is_empty() {
        return Err(GitError::Invalid {
            detail: "fetch needs at least one want".to_owned(),
        });
    }
    let mut out = Vec::new();
    refadv::write_command_header(&mut out, "fetch", caps, kind)?;
    for want in cmd.wants {
        pktline::encode_data(&mut out, format!("want {want}\n").as_bytes())?;
    }
    for oid in cmd.shallows {
        pktline::encode_data(&mut out, format!("shallow {oid}\n").as_bytes())?;
    }
    for have in cmd.haves {
        pktline::encode_data(&mut out, format!("have {have}\n").as_bytes())?;
    }
    if cmd.thin_pack {
        pktline::encode_data(&mut out, b"thin-pack\n")?;
    }
    if cmd.ofs_delta {
        pktline::encode_data(&mut out, b"ofs-delta\n")?;
    }
    if let Some(filter) = cmd.filter {
        pktline::encode_data(&mut out, format!("filter {}\n", filter.spec()).as_bytes())?;
    }
    if let Some(depth) = cmd.depth {
        pktline::encode_data(&mut out, format!("deepen {depth}\n").as_bytes())?;
    }
    if cmd.sideband_all {
        pktline::encode_data(&mut out, b"sideband-all\n")?;
    }
    pktline::encode_data(&mut out, b"done\n")?;
    pktline::encode_flush(&mut out);
    Ok(out)
}

/// What one `object-info` command asks for (`gitprotocol-v2.adoc`
/// "object-info"): full OIDs plus which attributes to report, in order.
#[derive(Clone, Debug, Default)]
pub struct ObjectInfoCommand<'a> {
    /// Full OIDs to describe (`oid` lines, at least one).
    pub oids: &'a [Oid],
    /// Report each object's size (`size`).
    pub size: bool,
    /// Report each object's type (`type`).
    pub object_type: bool,
}

/// Builds one `command=object-info` request: the command header, the
/// attribute lines, one `oid` line per object, and the closing flush.
///
/// # Errors
/// [`GitError::Invalid`] with no OIDs.
pub fn object_info_request(
    caps: &Capabilities,
    kind: HashKind,
    cmd: &ObjectInfoCommand<'_>,
) -> Result<Vec<u8>, GitError> {
    if cmd.oids.is_empty() {
        return Err(GitError::Invalid {
            detail: "object-info needs at least one oid".to_owned(),
        });
    }
    let mut out = Vec::new();
    refadv::write_command_header(&mut out, "object-info", caps, kind)?;
    if cmd.size {
        pktline::encode_data(&mut out, b"size\n")?;
    }
    if cmd.object_type {
        pktline::encode_data(&mut out, b"type\n")?;
    }
    for oid in cmd.oids {
        pktline::encode_data(&mut out, format!("oid {oid}\n").as_bytes())?;
    }
    pktline::encode_flush(&mut out);
    Ok(out)
}

/// One `object-info` answer row: the OID plus one value per requested
/// attribute, in request order. An unrecognized OID carries no values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectInfoEntry {
    /// The object described.
    pub oid: Oid,
    /// One value per requested attribute (sizes, types).
    pub values: Vec<String>,
}

/// Reads one `object-info` response up to its flush: the echoed attribute
/// lines (`size`, `type`) first, then one row per object.
///
/// # Errors
/// [`GitError::Corrupt`] for grammar violations or an unknown attribute.
pub fn read_object_info<R: Read>(
    pkt: &mut PktReader<R>,
    kind: HashKind,
) -> Result<(Vec<String>, Vec<ObjectInfoEntry>), GitError> {
    let mut attrs = Vec::new();
    let mut entries = Vec::new();
    let mut in_attrs = true;
    loop {
        let packet = pkt.read_packet()?;
        let line = match packet {
            Packet::Flush | Packet::ResponseEnd => break,
            Packet::Delimiter => continue,
            Packet::Data(_) => pkt.last_line().unwrap_or_default().to_vec(),
        };
        if in_attrs && (line == b"size" || line == b"type") {
            attrs.push(String::from_utf8_lossy(&line).into_owned());
            continue;
        }
        in_attrs = false;
        let (oid, rest) = match line.iter().position(|b| *b == b' ') {
            Some(at) => (&line[..at], Some(&line[at + 1..])),
            None => (line.as_slice(), None),
        };
        let text =
            std::str::from_utf8(oid).map_err(|_| corrupt(format!("non-ASCII object id {}", oid.escape_ascii())))?;
        let oid = crate::parse_oid_for(text, kind).map_err(|err| match err {
            GitError::ObjectFormat { detail } => GitError::ObjectFormat { detail },
            other => corrupt(other.to_string()),
        })?;
        let values = match rest {
            None | Some(b"") => Vec::new(),
            Some(rest) => rest
                .split(|b| *b == b' ')
                .filter(|word| !word.is_empty())
                .map(|word| String::from_utf8_lossy(word).into_owned())
                .collect(),
        };
        if values.len() > attrs.len() {
            return Err(corrupt(format!(
                "object-info row carries {} values for {} attributes",
                values.len(),
                attrs.len()
            )));
        }
        entries.push(ObjectInfoEntry { oid, values });
    }
    Ok((attrs, entries))
}

/// Encodes the server half of the opening exchange: `version 2`, one line
/// per capability, and the closing flush. Fake servers in tests serve
/// exactly these bytes.
///
/// # Errors
/// [`GitError::Limit`] for a capability longer than one frame.
pub fn encode_capability_advertisement(caps: &Capabilities) -> Result<Vec<u8>, GitError> {
    let mut out = Vec::new();
    pktline::encode_data(&mut out, b"version 2\n")?;
    for line in caps.to_lines() {
        let mut framed = line;
        framed.push(b'\n');
        pktline::encode_data(&mut out, &framed)?;
    }
    pktline::encode_flush(&mut out);
    Ok(out)
}

/// One `fetch` response: the pack staging plus the shallow boundaries and
/// progress the sections around it carried.
#[derive(Debug)]
pub struct FetchSections {
    /// Staged objects, invisible until published.
    pub staged: StagedPack,
    /// Server-declared shallow boundaries (`shallow` lines).
    pub shallow: Vec<Oid>,
    /// Boundaries the server lifted (`unshallow` lines).
    pub unshallow: Vec<Oid>,
    /// Progress text gathered from side-band 2.
    pub progress: RemoteMessages,
}

/// Reads one `fetch` response after the request flush: the `shallow-info`
/// boundaries plus the sideband-multiplexed `packfile` section. The
/// packfile section always demultiplexes: live servers multiplex it
/// whether or not `sideband-all` was negotiated (verified against git
/// 2.53.0), so a raw pack here is corrupt. The packfile section closes
/// the response; negotiation sections always precede it.
///
/// # Errors
/// Grammar failures are [`GitError::Corrupt`]; see [`ingest_pack`] for
/// pack errors.
pub fn read_fetch_response<R: Read>(
    pkt: &mut PktReader<R>,
    kind: HashKind,
    store: &Store,
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<FetchSections, GitError> {
    let mut shallow = Vec::new();
    let mut unshallow = Vec::new();
    let mut staged = None;
    let mut progress = RemoteMessages::default();
    loop {
        interrupt.check("reading the fetch response")?;
        match pkt.read_packet()? {
            Packet::Flush => break,
            Packet::ResponseEnd => break,
            Packet::Delimiter => {}
            Packet::Data(_) => {
                let section = pkt.last_line().unwrap_or_default().to_vec();
                match section.as_slice() {
                    b"acknowledgment" | b"acknowledgments" => {
                        read_section_lines(pkt, &mut Vec::new())?;
                    }
                    b"shallow-info" => {
                        let mut lines = Vec::new();
                        read_section_lines(pkt, &mut lines)?;
                        for line in lines {
                            if let Some(rest) = line.strip_prefix(b"shallow ") {
                                shallow.push(parse_server_oid(rest, kind)?);
                            } else if let Some(rest) = line.strip_prefix(b"unshallow ") {
                                unshallow.push(parse_server_oid(rest, kind)?);
                            }
                        }
                    }
                    b"wanted-refs" => read_section_lines(pkt, &mut Vec::new())?,
                    b"packfile" => {
                        let mut band =
                            SidebandReader::new(pkt, super::pktline::LARGE_PACKET_MAX);
                        let pack = ingest_pack(&mut band, kind, store, limits, interrupt)?;
                        progress = band.drain_to_end()?;
                        staged = Some(pack);
                        // The packfile section closes the response: live
                        // servers send one flush for section and response,
                        // then hold the connection open in silence. Reading
                        // on would block forever, so the loop ends here.
                        break;
                    }
                    _ => read_section_lines(pkt, &mut Vec::new())?,
                }
            }
        }
    }
    let Some(staged) = staged else {
        return Err(GitError::Corrupt {
            detail: "fetch response carries no packfile section".to_owned(),
        });
    };
    Ok(FetchSections {
        staged,
        shallow,
        unshallow,
        progress,
    })
}

/// Reads one response section up to its terminator (flush, response-end,
/// or delimiter).
fn read_section_lines<R: Read>(
    pkt: &mut PktReader<R>,
    lines: &mut Vec<Vec<u8>>,
) -> Result<(), GitError> {
    loop {
        match pkt.read_packet()? {
            Packet::Flush | Packet::ResponseEnd => return Ok(()),
            Packet::Delimiter => return Ok(()),
            Packet::Data(_) => lines.push(pkt.last_line().unwrap_or_default().to_vec()),
        }
    }
}

/// Reads a server OID the way the fetch clients do.
pub(crate) fn parse_server_oid(field: &[u8], kind: HashKind) -> Result<Oid, GitError> {
    let text = std::str::from_utf8(field).map_err(|_| GitError::Corrupt {
        detail: "server sent a non-ASCII object id".to_owned(),
    })?;
    crate::parse_oid_for(text, kind).map_err(|err| match err {
        GitError::ObjectFormat { detail } => GitError::ObjectFormat { detail },
        other => GitError::Corrupt {
            detail: other.to_string(),
        },
    })
}

fn corrupt(detail: impl Into<String>) -> GitError {
    GitError::Corrupt {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::session::test_support::test_store;

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";
    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).expect("hex")
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        pktline::encode_data(&mut out, payload).expect("frame");
        out
    }

    fn caps_with(lines: &[&[u8]]) -> Capabilities {
        let mut caps = Capabilities::default();
        for line in lines {
            caps.push_entry(line);
        }
        caps
    }

    #[test]
    fn ls_refs_frames_command_args_and_prefixes() {
        let caps = caps_with(&[b"agent=git/2.50", b"ls-refs=unborn"]);
        let cmd = LsRefsCommand::advertisement(vec![b"refs/heads/".to_vec()]);
        let request = ls_refs_request(&caps, HashKind::Sha1, &cmd).expect("request");
        let mut expected = Vec::new();
        pktline::encode_data(&mut expected, b"command=ls-refs\n").expect("f");
        pktline::encode_data(
            &mut expected,
            format!("agent={}\n", super::super::AGENT).as_bytes(),
        )
        .expect("f");
        pktline::encode_delimiter(&mut expected);
        for line in [
            &b"peel\n"[..],
            b"symrefs\n",
            b"unborn\n",
            b"ref-prefix refs/heads/\n",
        ] {
            pktline::encode_data(&mut expected, line).expect("f");
        }
        pktline::encode_flush(&mut expected);
        assert_eq!(request, expected);
    }

    #[test]
    fn ls_refs_omits_unborn_without_the_feature() {
        let caps = caps_with(&[b"fetch=shallow"]);
        let cmd = LsRefsCommand::advertisement(Vec::new());
        let request = ls_refs_request(&caps, HashKind::Sha1, &cmd).expect("request");
        let text = String::from_utf8_lossy(&request);
        assert!(text.contains("peel\n"), "asks to peel");
        assert!(!text.contains("unborn"), "unborn needs the feature: {text}");
    }

    #[test]
    fn fetch_frames_want_have_done_with_negotiated_lines() {
        let caps = caps_with(&[b"fetch=shallow filter sideband-all"]);
        let cmd = FetchCommand {
            wants: &[oid(A)],
            haves: &[oid(B)],
            shallows: &[],
            depth: Some(1),
            filter: Some(Filter::BlobNone),
            thin_pack: false,
            ofs_delta: false,
            sideband_all: true,
        };
        let request = fetch_request(&caps, HashKind::Sha1, &cmd).expect("request");
        let text = String::from_utf8_lossy(&request);
        for line in [
            "command=fetch\n",
            &format!("want {A}\n"),
            &format!("have {B}\n"),
            "filter blob:none\n",
            "deepen 1\n",
            "sideband-all\n",
            "done\n",
        ] {
            assert!(text.contains(line), "missing {line:?} in {text}");
        }
        assert!(text.ends_with("0000"), "closing flush");
        assert!(
            text.find(&format!("want {A}")).unwrap() < text.find(&format!("have {B}")).unwrap(),
            "wants precede haves"
        );
        assert!(
            text.find("done\n").unwrap() > text.find("sideband-all\n").unwrap(),
            "done terminates the arguments"
        );
    }

    #[test]
    fn fetch_frames_thin_pack_and_ofs_delta_when_asked() {
        let caps = caps_with(&[b"fetch=thin-pack"]);
        let cmd = FetchCommand {
            wants: &[oid(A)],
            haves: &[],
            shallows: &[],
            depth: None,
            filter: None,
            thin_pack: true,
            ofs_delta: true,
            sideband_all: false,
        };
        let bytes = fetch_request(&caps, HashKind::Sha1, &cmd).expect("r");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("thin-pack\n"), "{text}");
        assert!(text.contains("ofs-delta\n"), "{text}");
    }

    #[test]
    fn fetch_refuses_empty_wants_and_object_info_empty_oids() {
        let caps = Capabilities::default();
        let cmd = FetchCommand::default();
        assert!(matches!(
            fetch_request(&caps, HashKind::Sha1, &cmd),
            Err(GitError::Invalid { .. })
        ));
        let info = ObjectInfoCommand::default();
        assert!(matches!(
            object_info_request(&caps, HashKind::Sha1, &info),
            Err(GitError::Invalid { .. })
        ));
    }

    #[test]
    fn object_info_frames_attrs_and_oids() {
        let caps = Capabilities::default();
        let cmd = ObjectInfoCommand {
            oids: &[oid(A), oid(B)],
            size: true,
            object_type: true,
        };
        let request = object_info_request(&caps, HashKind::Sha1, &cmd).expect("request");
        let text = String::from_utf8_lossy(&request);
        assert!(text.contains("command=object-info\n"), "{text}");
        assert!(text.contains("size\n"), "{text}");
        assert!(text.contains("type\n"), "{text}");
        assert!(text.contains(&format!("oid {A}\n")), "{text}");
        assert!(text.contains(&format!("oid {B}\n")), "{text}");
        assert!(text.ends_with("0000"), "closing flush");
    }

    #[test]
    fn object_info_reads_attrs_then_rows() {
        let mut body = Vec::new();
        for line in [b"size\n".as_slice(), b"type\n"] {
            body.extend(frame(line));
        }
        body.extend(frame(format!("{A} 123 commit\n").as_bytes()));
        // An unrecognized OID answers with the oid plus a blank.
        body.extend(frame(format!("{B} \n").as_bytes()));
        body.extend(b"0000");
        let mut pkt = PktReader::new(&body[..], Interrupt::none());
        let (attrs, entries) = read_object_info(&mut pkt, HashKind::Sha1).expect("parse");
        assert_eq!(attrs, vec!["size".to_owned(), "type".to_owned()]);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].oid, oid(A));
        assert_eq!(entries[0].values, vec!["123".to_owned(), "commit".to_owned()]);
        assert_eq!(entries[1].oid, oid(B));
        assert!(entries[1].values.is_empty());
    }

    #[test]
    fn capability_advertisement_round_trips() {
        let caps = caps_with(&[
            b"agent=git/2.50",
            b"ls-refs=unborn",
            b"fetch=shallow filter",
            b"object-format=sha1",
        ]);
        let bytes = encode_capability_advertisement(&caps).expect("encode");
        let mut pkt = PktReader::new(&bytes[..], Interrupt::none());
        match refadv::read_initial(&mut pkt, HashKind::Sha1).expect("parse") {
            refadv::Initial::V2(back) => assert_eq!(back, caps),
            refadv::Initial::Refs(_) => panic!("expected v2"),
        }
    }

    #[test]
    fn v0_advertisement_dispatches_away_from_v2() {
        // The fallback probe: a server that ignores `Git-Protocol` answers
        // v0, and the client must take the v0 path, not the v2 one.
        let first = format!("{A} HEAD\0multi_ack\n");
        let mut bytes = frame(first.as_bytes());
        bytes.extend(b"0000");
        let mut pkt = PktReader::new(&bytes[..], Interrupt::none());
        assert!(matches!(
            refadv::read_initial(&mut pkt, HashKind::Sha1).expect("parse"),
            refadv::Initial::Refs(_)
        ));
    }

    #[test]
    fn fetch_sections_ingest_a_sideband_packfile() {
        let store = test_store(HashKind::Sha1);
        let pack = include_bytes!("fixtures/basic.pack");
        let mut script = Vec::new();
        script.extend(frame(b"packfile\n"));
        let mut banded = vec![0x01];
        banded.extend_from_slice(&pack[..pack.len() / 2]);
        script.extend(frame(&banded));
        script.extend(frame(b"\x02progress\n"));
        let mut banded = vec![0x01];
        banded.extend_from_slice(&pack[pack.len() / 2..]);
        script.extend(frame(&banded));
        script.extend(b"0000");
        let mut pkt = PktReader::new(&script[..], Interrupt::none());
        let sections = read_fetch_response(
            &mut pkt,
            HashKind::Sha1,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("sections");
        assert_eq!(sections.staged.oids().len(), 16);
        assert!(sections.shallow.is_empty());
        assert!(sections.progress.progress.starts_with(b"progress\n"));
        super::super::fetch::verify_closure(
            &store,
            &sections.staged,
            &[oid(FOUR)],
            None,
            &[],
            &Interrupt::none(),
        )
        .expect("complete pack verifies");
    }

    #[test]
    fn fetch_sections_without_packfile_is_corrupt() {
        let mut script = frame(b"shallow-info\n");
        script.extend(frame(format!("shallow {A}\n").as_bytes()));
        // One flush ends the section, a second ends the response with no
        // packfile section: that is corrupt, not a hangup.
        script.extend(b"0000");
        script.extend(b"0000");
        let store = test_store(HashKind::Sha1);
        let mut pkt = PktReader::new(&script[..], Interrupt::none());
        assert!(matches!(
            read_fetch_response(
                &mut pkt,
                HashKind::Sha1,
                &store,
                IngestLimits::default(),
                &Interrupt::none(),
            ),
            Err(GitError::Corrupt { .. })
        ));
    }
}
