//! Behavioral tests for the conflict record: exact layout, identity,
//! canonical decoding, byte fidelity, and validation at the input boundary.

use std::collections::HashSet;

use proptest::prelude::*;

use super::{ConflictRecord, ConflictRecordInput, ExtraHeader, FORMAT_TAG, Signature, TzOffset};
use crate::bytes::ByteString;
use crate::error::CoreModelError;
use crate::heads::Head;
use crate::ids::{CommitKey, HashKind, Oid};

const KINDS: [HashKind; 2] = [HashKind::Sha1, HashKind::Sha256];

type Mutation = Box<dyn Fn(&mut ConflictRecordInput)>;

/// Boxes a mutation; the `Fn` bound gives the closure its higher-ranked
/// `&mut` signature, which a bare `Box::new(|input| ..)` in a `vec!` would not.
fn mutation(change: impl Fn(&mut ConflictRecordInput) + 'static) -> Mutation {
    Box::new(change)
}

fn oid(kind: HashKind, fill: u8) -> Oid {
    Oid::from_bytes(&[fill; 32][..kind.oid_len()]).expect("oid")
}

fn key(kind: HashKind, fill: u8) -> CommitKey {
    CommitKey::from_bytes(&[fill; 32][..kind.oid_len()]).expect("key")
}

fn sig(name: &str, email: &str, timestamp: i64, offset: &str) -> Signature {
    Signature {
        name: name.into(),
        email: email.into(),
        timestamp,
        offset: TzOffset::parse(offset.as_bytes()).expect("offset"),
    }
}

fn header(name: &str, value: &str) -> ExtraHeader {
    ExtraHeader {
        name: name.into(),
        value: value.into(),
    }
}

fn sample_input(kind: HashKind) -> ConflictRecordInput {
    ConflictRecordInput {
        trees: vec![oid(kind, 0x11), oid(kind, 0x22), oid(kind, 0x33)],
        parents: vec![
            Head::Git {
                oid: oid(kind, 0x44),
            },
            Head::Conflicted {
                key: key(kind, 0x55),
            },
        ],
        author: sig("A U Thor", "a@example.com", 1_700_000_000, "+0100"),
        committer: sig("C O Mitter", "c@example.com", 1_700_000_100, "-0000"),
        extra_headers: vec![
            header("z-extra", "line one\nline two"),
            header("change-id", "lkonztmnvsxytrwkxpvuutrmompwylqq"),
        ],
        message: "resolve later\n".into(),
    }
}

fn record(kind: HashKind) -> ConflictRecord {
    ConflictRecord::from_input(&sample_input(kind), kind).expect("valid sample")
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{FORMAT_TAG} {}\0", payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

fn sample_payload(kind: HashKind) -> String {
    String::from_utf8(record(kind).encode_payload()).expect("sample payload is UTF-8")
}

fn hex(fill: &str, kind: HashKind) -> String {
    fill.repeat(kind.oid_len())
}

#[test]
fn encodes_the_documented_layout_byte_for_byte() {
    let kind = HashKind::Sha1;
    let expected = format!(
        "trees {} {} {}\n\
         parent {}\n\
         parent conflict {}\n\
         author A U Thor <a@example.com> 1700000000 +0100\n\
         committer C O Mitter <c@example.com> 1700000100 -0000\n\
         change-id lkonztmnvsxytrwkxpvuutrmompwylqq\n\
         z-extra line one\n line two\n\
         \n\
         resolve later\n",
        hex("11", kind),
        hex("22", kind),
        hex("33", kind),
        hex("44", kind),
        hex("55", kind),
    );
    assert_eq!(record(kind).encode(), frame(expected.as_bytes()));
}

#[test]
fn key_is_the_repository_kind_hash_of_the_framed_record() {
    for kind in KINDS {
        let rec = record(kind);
        // Independent route: Git object hashing with object type `conflict-v1`
        // frames exactly as `conflict-v1 <len>\0<payload>`.
        let expected = kind
            .hash_git_object(FORMAT_TAG, &rec.encode_payload())
            .expect("hash");
        let key = rec.key().expect("key");
        assert_eq!(key.to_hex(), expected.to_hex());
        assert_eq!(key.kind(), kind);
        assert_eq!(key.as_bytes().len(), kind.oid_len());
    }
}

#[test]
fn key_depends_on_every_field_and_on_the_hash_kind() {
    let mutations: Vec<Mutation> = vec![
        mutation(|input| input.trees[0] = oid(HashKind::Sha1, 0x12)),
        mutation(|input| input.trees.reverse()),
        mutation(|input| input.parents.reverse()),
        mutation(|input| {
            let _ = input.parents.pop();
        }),
        mutation(|input| input.author.timestamp += 1),
        mutation(|input| input.committer.offset = TzOffset::UTC),
        mutation(|input| input.author.name = "A U Thoq".into()),
        mutation(|input| input.extra_headers[0].value = "line one\nline twO".into()),
        mutation(|input| input.extra_headers.push(header("extra", ""))),
        mutation(|input| input.message = "resolve later".into()),
    ];
    let base = ConflictRecord::from_input(&sample_input(HashKind::Sha1), HashKind::Sha1)
        .expect("base")
        .key()
        .expect("key");
    let mut seen = HashSet::from([base.to_hex()]);
    for mutate in &mutations {
        let mut input = sample_input(HashKind::Sha1);
        mutate(&mut input);
        let rec = ConflictRecord::from_input(&input, HashKind::Sha1).expect("mutated");
        assert!(
            seen.insert(rec.key().expect("key").to_hex()),
            "two records share a key"
        );
    }
    // Identical input, identical key; the other hash kind is a different key.
    let again =
        ConflictRecord::from_input(&sample_input(HashKind::Sha1), HashKind::Sha1).expect("again");
    assert_eq!(again.key().expect("key"), base);
    assert_ne!(
        record(HashKind::Sha256).key().expect("key").to_hex(),
        base.to_hex()
    );
}

#[test]
fn header_input_order_does_not_change_identity() {
    let mut reordered = sample_input(HashKind::Sha1);
    reordered.extra_headers.reverse();
    let a = ConflictRecord::from_input(&reordered, HashKind::Sha1).expect("a");
    assert_eq!(a, record(HashKind::Sha1));
    assert_eq!(
        a.key().expect("key"),
        record(HashKind::Sha1).key().expect("key")
    );
}

#[test]
fn round_trips_for_both_hash_kinds() {
    for kind in KINDS {
        let rec = record(kind);
        let bytes = rec.encode();
        let decoded = ConflictRecord::decode(&bytes, kind).expect("decode");
        assert_eq!(decoded, rec);
        assert_eq!(decoded.encode(), bytes);
        assert_eq!(decoded.key().expect("key"), rec.key().expect("key"));
        let rebuilt = ConflictRecord::from_input(&rec.to_input(), kind).expect("from_input");
        assert_eq!(rebuilt, rec);
        assert_eq!(decoded.trees().as_slice().len(), 3);
        assert_eq!(decoded.parents().len(), 2);
        assert_eq!(decoded.message().as_bytes(), b"resolve later\n");
        assert_eq!(decoded.kind(), kind);
    }
}

#[test]
fn decoding_with_the_wrong_hash_kind_is_an_object_format_error() {
    for kind in KINDS {
        let other = if kind == HashKind::Sha1 {
            HashKind::Sha256
        } else {
            HashKind::Sha1
        };
        let bytes = record(kind).encode();
        let err = ConflictRecord::decode(&bytes, other).expect_err("wrong width");
        // The width of a hex field differs, so it is rejected either as a
        // malformed digest or as a format mismatch; never accepted.
        assert!(
            matches!(
                err,
                CoreModelError::ObjectFormat(_) | CoreModelError::Invalid { .. }
            ),
            "{err:?}"
        );
    }
}

#[test]
fn decode_rejects_every_non_canonical_or_malformed_record() {
    let kind = HashKind::Sha1;
    let valid = sample_payload(kind);
    let swap = |a: &str, b: &str| {
        let mut lines: Vec<&str> = valid.split('\n').collect();
        let (i, j) = (
            lines.iter().position(|l| l.starts_with(a)).expect("a"),
            lines.iter().position(|l| l.starts_with(b)).expect("b"),
        );
        lines.swap(i, j);
        lines.join("\n")
    };
    let payloads: Vec<(&str, String)> = vec![
        (
            "uppercase hex",
            valid.replacen(&hex("11", kind), &hex("AA", kind), 1),
        ),
        (
            "double space in trees",
            valid.replacen("trees ", "trees  ", 1),
        ),
        (
            "trailing space in trees",
            valid.replacen("\nparent ", " \nparent ", 1),
        ),
        (
            "leading-zero timestamp",
            valid.replacen("1700000000 +0100", "01700000000 +0100", 1),
        ),
        (
            "plus-signed timestamp",
            valid.replacen("1700000000 +0100", "+1700000000 +0100", 1),
        ),
        ("colon offset", valid.replacen("+0100", "+01:00", 1)),
        ("short offset", valid.replacen("+0100", "+100", 1)),
        (
            "no space before email",
            valid.replacen("A U Thor <", "A U Thor<", 1),
        ),
        ("committer before author", swap("author ", "committer ")),
        (
            "missing blank line",
            valid.replacen("\n\nresolve", "\nresolve", 1),
        ),
        (
            "header without value separator",
            valid.replacen("\n\nresolve", "\nbogus\n\nresolve", 1),
        ),
        (
            "continuation without header",
            valid.replacen("\nchange-id", "\n cont\nchange-id", 1),
        ),
        (
            "structural header among extras",
            valid.replacen(
                "\nchange-id",
                &format!("\nparent {}\nchange-id", hex("44", kind)),
                1,
            ),
        ),
        (
            "NUL in header value",
            valid.replacen("line two", "line\0two", 1),
        ),
        (
            "no tree terms",
            valid.replacen(
                &format!(
                    "trees {} {} {}",
                    hex("11", kind),
                    hex("22", kind),
                    hex("33", kind)
                ),
                "trees",
                1,
            ),
        ),
        (
            "even tree count",
            valid.replacen(&format!(" {}\nparent", hex("33", kind)), "\nparent", 1),
        ),
        (
            "truncated mid-header",
            valid[..valid.find("committer").expect("committer")].to_owned(),
        ),
        (
            "missing author",
            valid.replacen("author A U Thor <a@example.com> 1700000000 +0100\n", "", 1),
        ),
        (
            "duplicate change-id",
            valid.replacen(
                "\nz-extra",
                "\nchange-id lkonztmnvsxytrwkxpvuutrmompwylqq\nz-extra",
                1,
            ),
        ),
        (
            "unsorted extra headers",
            valid.replacen(
                "change-id lkonztmnvsxytrwkxpvuutrmompwylqq\nz-extra line one\n line two\n",
                "z-extra line one\n line two\nchange-id lkonztmnvsxytrwkxpvuutrmompwylqq\n",
                1,
            ),
        ),
    ];
    for (why, payload) in &payloads {
        let result = ConflictRecord::decode(&frame(payload.as_bytes()), kind);
        assert!(result.is_err(), "accepted {why}");
    }
    // The unmodified record still decodes (the table rejects the edits, not the base).
    assert!(ConflictRecord::decode(&frame(valid.as_bytes()), kind).is_ok());
}

#[test]
fn decode_rejects_bad_framing() {
    let kind = HashKind::Sha1;
    let payload = sample_payload(kind).into_bytes();
    let good = frame(&payload);
    let plus_one = format!("{FORMAT_TAG} {}\0", payload.len() + 1).into_bytes();
    let minus_one = format!("{FORMAT_TAG} {}\0", payload.len() - 1).into_bytes();
    let padded = format!("{FORMAT_TAG} 0{}\0", payload.len()).into_bytes();
    let framings: Vec<(&str, Vec<u8>)> = vec![
        ("length too large", [plus_one, payload.clone()].concat()),
        ("length too small", [minus_one, payload.clone()].concat()),
        ("leading-zero length", [padded, payload.clone()].concat()),
        (
            "future format tag",
            [b"conflict-v2 1\0".to_vec(), payload.clone()].concat(),
        ),
        (
            "no space after tag",
            [b"conflict-v1\0".to_vec(), payload.clone()].concat(),
        ),
        (
            "negative length",
            [b"conflict-v1 -5\0".to_vec(), payload.clone()].concat(),
        ),
        (
            "no NUL",
            format!("{FORMAT_TAG} {}", payload.len()).into_bytes(),
        ),
        (
            "trailing byte after payload",
            [good.clone(), b"x".to_vec()].concat(),
        ),
        ("empty", Vec::new()),
        ("git commit instead", b"commit 0\0".to_vec()),
    ];
    for (why, bytes) in &framings {
        assert!(
            ConflictRecord::decode(bytes, kind).is_err(),
            "accepted {why}"
        );
    }
    for cut in 0..good.len() {
        assert!(
            ConflictRecord::decode(&good[..cut], kind).is_err(),
            "accepted a {cut}-byte truncation"
        );
    }
}

#[test]
fn from_input_rejects_invalid_state_at_the_boundary() {
    let kind = HashKind::Sha1;
    let wrong = HashKind::Sha256;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "wrong-width tree",
            mutation(move |i| i.trees[1] = oid(wrong, 1)),
        ),
        (
            "wrong-width git parent",
            mutation(move |i| i.parents[0] = Head::Git { oid: oid(wrong, 1) }),
        ),
        (
            "wrong-width conflict parent",
            mutation(move |i| i.parents[1] = Head::Conflicted { key: key(wrong, 1) }),
        ),
        ("no trees", mutation(|i| i.trees.clear())),
        ("two trees", mutation(|i| i.trees.truncate(2))),
        ("angle in name", mutation(|i| i.author.name = "A <B".into())),
        (
            "newline in email",
            mutation(|i| i.committer.email = "a\n@b".into()),
        ),
        (
            "NUL in name",
            mutation(|i| i.author.name = ByteString::new(vec![b'a', 0])),
        ),
        ("'>' in email", mutation(|i| i.author.email = "a>b".into())),
        (
            "empty header name",
            mutation(|i| i.extra_headers.push(header("", "v"))),
        ),
        (
            "space in header name",
            mutation(|i| i.extra_headers.push(header("a b", "v"))),
        ),
        (
            "newline in header name",
            mutation(|i| i.extra_headers.push(header("a\nb", "v"))),
        ),
        (
            "NUL in header value",
            mutation(|i| i.extra_headers.push(header("x", "a\0b"))),
        ),
        (
            "tree header",
            mutation(|i| i.extra_headers.push(header("tree", "x"))),
        ),
        (
            "trees header",
            mutation(|i| i.extra_headers.push(header("trees", "x"))),
        ),
        (
            "parent header",
            mutation(|i| i.extra_headers.push(header("parent", "x"))),
        ),
        (
            "author header",
            mutation(|i| i.extra_headers.push(header("author", "x"))),
        ),
        (
            "committer header",
            mutation(|i| i.extra_headers.push(header("committer", "x"))),
        ),
        (
            "duplicate change-id",
            mutation(|i| i.extra_headers.push(header("change-id", "other"))),
        ),
    ];
    for (why, mutate) in &cases {
        let mut input = sample_input(kind);
        mutate(&mut input);
        assert!(
            ConflictRecord::from_input(&input, kind).is_err(),
            "accepted {why}"
        );
    }
    let mut width = sample_input(kind);
    width.trees[0] = oid(wrong, 9);
    assert!(matches!(
        ConflictRecord::from_input(&width, kind),
        Err(CoreModelError::ObjectFormat(_))
    ));
}

#[test]
fn repeated_non_unique_headers_are_kept_and_sorted_bytewise() {
    let kind = HashKind::Sha1;
    let mut input = sample_input(kind);
    input.extra_headers = vec![
        header("mergetag", "object b"),
        header("mergetag", "object a"),
        header("encoding", "ISO-8859-1"),
        header("Zeta", "capital sorts before lowercase"),
    ];
    let rec = ConflictRecord::from_input(&input, kind).expect("record");
    let got: Vec<(Vec<u8>, Vec<u8>)> = rec
        .extra_headers()
        .iter()
        .map(|h| (h.name.as_bytes().to_vec(), h.value.as_bytes().to_vec()))
        .collect();
    let want: Vec<(Vec<u8>, Vec<u8>)> = [
        ("Zeta", "capital sorts before lowercase"),
        ("encoding", "ISO-8859-1"),
        ("mergetag", "object a"),
        ("mergetag", "object b"),
    ]
    .iter()
    .map(|(name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec()))
    .collect();
    assert_eq!(got, want);
    assert_eq!(
        ConflictRecord::decode(&rec.encode(), kind).expect("decode"),
        rec
    );
}

#[test]
fn arbitrary_bytes_survive_exactly() {
    let kind = HashKind::Sha1;
    let mut input = sample_input(kind);
    input.author.name = ByteString::new(vec![0xe9, b' ', 0xff]);
    input.author.email = ByteString::new(vec![0x80]);
    input.message = ByteString::new(vec![0xff, 0x00, b'\n', 0xfe, b'\n', b'\n']);
    input.extra_headers = vec![ExtraHeader {
        name: ByteString::new(vec![0xff, b'h']),
        value: ByteString::new(b"first\n\n second\n".to_vec()),
    }];
    let rec = ConflictRecord::from_input(&input, kind).expect("record");
    let decoded = ConflictRecord::decode(&rec.encode(), kind).expect("decode");
    assert_eq!(
        decoded.message().as_bytes(),
        [0xff, 0x00, b'\n', 0xfe, b'\n', b'\n']
    );
    assert_eq!(
        decoded.extra_headers()[0].value.as_bytes(),
        b"first\n\n second\n"
    );
    assert_eq!(decoded.author().name.as_bytes(), [0xe9, b' ', 0xff]);
    assert_eq!(decoded.key().expect("key"), rec.key().expect("key"));
    // The JSON form carries the same bytes (hex objects for non-UTF-8).
    let json = sonic_rs::to_string(&rec.to_input()).expect("json");
    let back: ConflictRecordInput = sonic_rs::from_str(&json).expect("parse");
    assert_eq!(
        ConflictRecord::from_input(&back, kind).expect("record"),
        rec
    );
}

#[test]
fn empty_message_and_empty_header_value_round_trip() {
    let kind = HashKind::Sha256;
    let mut input = sample_input(kind);
    input.message = ByteString::default();
    input.extra_headers = vec![header("empty", "")];
    let rec = ConflictRecord::from_input(&input, kind).expect("record");
    let bytes = rec.encode();
    assert!(bytes.ends_with(b"\n\n"));
    assert_eq!(ConflictRecord::decode(&bytes, kind).expect("decode"), rec);
}

#[test]
fn empty_extra_headers_survive_postcard_round_trip() {
    // `extra_headers` is positional in postcard: omitting it when empty
    // shifts `message` into its slot on decode. The fixture keeps every
    // other field realistic; only the headers/message vary here.
    for kind in KINDS {
        for message in [
            ByteString::default(),
            ByteString::from("resolve later\n"),
            ByteString::new(vec![0xff, 0x00, b'\n', 0xfe]),
        ] {
            let mut input = sample_input(kind);
            input.extra_headers.clear();
            input.message = message;
            let bytes = postcard::to_allocvec(&input).expect("serialize");
            let back: ConflictRecordInput = postcard::from_bytes(&bytes).expect("decode");
            assert_eq!(back, input);
        }
    }
}

#[test]
fn input_json_shape_and_strictness() {
    use sonic_rs::JsonValueMutTrait;

    let json = sonic_rs::to_value(&sample_input(HashKind::Sha1)).expect("value");
    assert_eq!(json["author"]["offset"], "+0100");
    assert_eq!(json["committer"]["offset"], "-0000");
    assert_eq!(json["parents"][0]["type"], "git");
    assert_eq!(json["parents"][1]["type"], "conflicted");
    assert_eq!(json["message"], "resolve later\n");
    assert_eq!(json["extra_headers"][1]["name"], "change-id");
    let back: ConflictRecordInput = sonic_rs::from_value(&json).expect("round trip");
    assert_eq!(back, sample_input(HashKind::Sha1));
    // Unlisted optional extra_headers default to empty.
    let mut without = json;
    without
        .as_object_mut()
        .expect("object")
        .remove(&"extra_headers");
    let parsed: ConflictRecordInput = sonic_rs::from_value(&without).expect("optional");
    assert!(parsed.extra_headers.is_empty());
}

#[test]
fn tz_offset_preserves_sign_and_digits() {
    for text in ["+0000", "-0000", "+0100", "-0930", "+1259", "+9999"] {
        let tz = TzOffset::parse(text.as_bytes()).expect("parse");
        assert_eq!(tz.to_string(), text);
        assert_eq!(
            sonic_rs::to_string(&tz).expect("json"),
            format!("\"{text}\"")
        );
        assert_eq!(
            sonic_rs::from_str::<TzOffset>(&format!("\"{text}\"")).expect("parse"),
            tz
        );
    }
    assert_ne!(
        TzOffset::parse(b"-0000").expect("neg"),
        TzOffset::parse(b"+0000").expect("pos")
    );
    assert!(TzOffset::parse(b"-0000").expect("neg").is_negative());
    assert_eq!(TzOffset::parse(b"+0130").expect("tz").hhmm(), 130);
    for bad in [
        "", "+", "0100", "+100", "+01000", "+01a0", "+ 100", "++100", "+0100 ",
    ] {
        assert!(TzOffset::parse(bad.as_bytes()).is_err(), "accepted {bad:?}");
    }
    assert!(TzOffset::new(false, 10_000).is_err());
}

fn ident_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        any::<u8>().prop_filter("no <, >, newline, NUL", |b| {
            !matches!(b, b'<' | b'>' | b'\n' | 0)
        }),
        0..10,
    )
}

fn arb_signature() -> impl Strategy<Value = Signature> {
    (
        ident_bytes(),
        ident_bytes(),
        any::<i64>(),
        any::<bool>(),
        0_u16..10_000,
    )
        .prop_map(|(name, email, timestamp, negative, hhmm)| Signature {
            name: name.into(),
            email: email.into(),
            timestamp,
            offset: TzOffset::new(negative, hhmm).expect("range"),
        })
}

fn arb_header() -> impl Strategy<Value = ExtraHeader> {
    (
        prop::collection::vec(prop::sample::select(b"abcdz-".to_vec()), 1..6),
        prop::collection::vec(any::<u8>().prop_filter("no NUL", |b| *b != 0), 0..24),
    )
        .prop_map(|(name, value)| ExtraHeader {
            name: name.into(),
            value: value.into(),
        })
}

fn arb_record() -> impl Strategy<Value = ConflictRecord> {
    let fills = prop::collection::vec(any::<u8>(), 5);
    let parents = prop::collection::vec((any::<bool>(), any::<u8>()), 0..4);
    (
        prop::sample::select(KINDS.to_vec()),
        fills,
        0_usize..3,
        parents,
        arb_signature(),
        arb_signature(),
        prop::collection::vec(arb_header(), 0..4),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(
            |(kind, fills, extra, parents, author, committer, headers, message)| {
                let trees = fills[..extra * 2 + 1]
                    .iter()
                    .map(|f| oid(kind, *f))
                    .collect();
                let parents = parents
                    .into_iter()
                    .map(|(native, fill)| {
                        if native {
                            Head::Conflicted {
                                key: key(kind, fill),
                            }
                        } else {
                            Head::Git {
                                oid: oid(kind, fill),
                            }
                        }
                    })
                    .collect();
                let input = ConflictRecordInput {
                    trees,
                    parents,
                    author,
                    committer,
                    extra_headers: headers,
                    message: message.into(),
                };
                ConflictRecord::from_input(&input, kind).expect("generated input is valid")
            },
        )
}

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(512))]

    /// decode is the exact inverse of encode, and the key is a function of the bytes.
    #[test]
    fn prop_encode_decode_identity(rec in arb_record()) {
        let bytes = rec.encode();
        let decoded = ConflictRecord::decode(&bytes, rec.kind()).expect("decode");
        prop_assert_eq!(&decoded, &rec);
        prop_assert_eq!(decoded.encode(), bytes);
        prop_assert_eq!(decoded.key().expect("key"), rec.key().expect("key"));
        let rebuilt = ConflictRecord::from_input(&rec.to_input(), rec.kind()).expect("rebuild");
        prop_assert_eq!(rebuilt, rec);
    }

    /// Decoding never panics on a corrupted record, and whatever it accepts has
    /// exactly one meaning: it re-encodes to those bytes, and its key is the hash of
    /// those very bytes.
    #[test]
    fn prop_accepted_mutations_are_canonical(
        rec in arb_record(),
        at in any::<prop::sample::Index>(),
        replacement in any::<u8>(),
    ) {
        let mut bytes = rec.encode();
        let index = at.index(bytes.len());
        bytes[index] = replacement;
        if let Ok(decoded) = ConflictRecord::decode(&bytes, rec.kind()) {
            prop_assert_eq!(decoded.encode(), bytes.clone());
            let expected = CommitKey::of_framed_record(rec.kind(), &bytes).expect("hash");
            prop_assert_eq!(decoded.key().expect("key"), expected);
        }
    }

    /// No strict prefix of a framed record is ever accepted.
    #[test]
    fn prop_truncations_are_rejected(rec in arb_record(), cut in any::<prop::sample::Index>()) {
        let bytes = rec.encode();
        let end = cut.index(bytes.len());
        prop_assert!(ConflictRecord::decode(&bytes[..end], rec.kind()).is_err());
    }
}
