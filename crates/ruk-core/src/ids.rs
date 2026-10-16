//! Exact object identity: hash kind and OIDs, plus the native commit key.
//!
//! A repository fixes one hash kind at creation and every object identity in
//! it uses that kind alone. [`Oid`] wraps the gix `ObjectId` (20 bytes for
//! SHA-1, 32 for SHA-256) so there is no second internal hash identity.
//!
//! Wire forms are explicit rather than inherited from gix: JSON uses a
//! lowercase hex string; binary formats use the raw digest bytes.

use core::fmt;
use core::str::FromStr;
use std::borrow::Cow;

use gix_hash::{Kind as GixKind, ObjectId};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::CoreModelError;

/// Repository object format. Fixed per repository; never mixed in one store.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum HashKind {
    Sha1,
    Sha256,
}

impl HashKind {
    /// The default hash kind for newly created repositories.
    pub const DEFAULT: Self = Self::Sha1;

    /// Byte width of an object id in this format.
    #[must_use]
    pub const fn oid_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    /// Hex character width of an object id in this format.
    #[must_use]
    pub const fn hex_len(self) -> usize {
        self.oid_len() * 2
    }

    /// The gix hash kind for this object format.
    #[must_use]
    pub const fn gix(self) -> GixKind {
        match self {
            Self::Sha1 => GixKind::Sha1,
            Self::Sha256 => GixKind::Sha256,
        }
    }

    /// Name used in the on-disk format file (`object-format sha1`).
    #[must_use]
    pub const fn format_name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// The all-zero OID of this format (the new-ref expected-old value).
    #[must_use]
    pub fn zero_oid(self) -> Oid {
        Oid(self.gix().null())
    }

    /// Hashes the concatenation of `parts` under this format.
    ///
    /// # Errors
    /// SHA-1 collision detection (as Git does) refuses attack inputs.
    pub fn hash_parts(self, parts: &[&[u8]]) -> Result<Oid, CoreModelError> {
        let mut hasher = gix_hash::hasher(self.gix());
        for part in parts {
            hasher.update(part);
        }
        hasher
            .try_finalize()
            .map(Oid)
            .map_err(|err| CoreModelError::Invalid {
                what: "object hash",
                detail: err.to_string(),
            })
    }

    /// Hashes `payload` with its canonical Git object header
    /// `<object_type> <decimal length>\0`.
    ///
    /// # Errors
    /// See [`Self::hash_parts`].
    pub fn hash_git_object(self, object_type: &str, payload: &[u8]) -> Result<Oid, CoreModelError> {
        let header = format!("{object_type} {}\0", payload.len());
        self.hash_parts(&[header.as_bytes(), payload])
    }
}

impl fmt::Display for HashKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.format_name())
    }
}

impl FromStr for HashKind {
    type Err = CoreModelError;

    /// Parses the format-file spelling only (`sha1` or `sha256`).
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            other => Err(CoreModelError::Invalid {
                what: "object format",
                detail: other.to_owned(),
            }),
        }
    }
}

/// An exact Git object identity: SHA-1 (20 bytes) or SHA-256 (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(ObjectId);

impl Oid {
    /// Parses canonical lowercase hex of either known width.
    ///
    /// # Errors
    /// Rejects any other width and any non-lowercase-hex character.
    pub fn from_hex(hex: &str) -> Result<Self, CoreModelError> {
        Self::from_bytes_hex(hex.as_bytes())
    }

    /// Parses canonical lowercase hex given as raw bytes.
    ///
    /// # Errors
    /// Rejects any other width and any non-lowercase-hex character.
    pub fn from_bytes_hex(hex: &[u8]) -> Result<Self, CoreModelError> {
        let invalid = || CoreModelError::Invalid {
            what: "oid",
            detail: String::from_utf8_lossy(hex).into_owned(),
        };
        if hex.len() != 40 && hex.len() != 64 {
            return Err(invalid());
        }
        let mut digest = [0_u8; 32];
        let (chunks, _) = hex.as_chunks::<2>();
        for (slot, pair) in digest.iter_mut().zip(chunks) {
            let high = hex_val(pair[0]).ok_or_else(invalid)?;
            let low = hex_val(pair[1]).ok_or_else(invalid)?;
            *slot = (high << 4) | low;
        }
        Self::from_bytes(&digest[..hex.len() / 2])
    }

    /// Builds an OID from a raw digest.
    ///
    /// # Errors
    /// Rejects byte lengths other than 20 and 32.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreModelError> {
        ObjectId::try_from(bytes)
            .map(Self)
            .map_err(|_| CoreModelError::Invalid {
                what: "oid bytes",
                detail: format!("{} bytes", bytes.len()),
            })
    }

    /// Raw digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Lowercase hex rendering.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(self.as_bytes())
    }

    /// The object format implied by this digest's width.
    #[must_use]
    pub fn kind(&self) -> HashKind {
        // `ObjectId` holds exactly 20 or 32 bytes; width alone decides.
        if self.as_bytes().len() == HashKind::Sha1.oid_len() {
            HashKind::Sha1
        } else {
            HashKind::Sha256
        }
    }

    /// The underlying gix identity, for gix object/pack interfaces.
    #[must_use]
    pub const fn to_gix(self) -> ObjectId {
        self.0
    }

    /// Checks this OID belongs to `kind`.
    ///
    /// # Errors
    /// [`CoreModelError::ObjectFormat`] naming `what` on a width mismatch.
    pub fn expect_kind(&self, kind: HashKind, what: &str) -> Result<(), CoreModelError> {
        if self.kind() == kind {
            return Ok(());
        }
        Err(CoreModelError::ObjectFormat(format!(
            "{what} {self} is {} but the repository is {kind}",
            self.kind()
        )))
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self.to_hex())
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Oid {
    type Err = CoreModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::from_hex(text)
    }
}

impl From<ObjectId> for Oid {
    fn from(id: ObjectId) -> Self {
        Self(id)
    }
}

impl From<Oid> for ObjectId {
    fn from(oid: Oid) -> Self {
        oid.0
    }
}

impl Serialize for Oid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

struct OidVisitor;

impl Visitor<'_> for OidVisitor {
    type Value = Oid;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a 40- or 64-character lowercase hex object id, or a 20/32-byte digest")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Oid, E> {
        Oid::from_hex(text).map_err(E::custom)
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Oid, E> {
        Oid::from_bytes(bytes).map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for Oid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(OidVisitor)
        } else {
            deserializer.deserialize_bytes(OidVisitor)
        }
    }
}

impl JsonSchema for Oid {
    fn schema_name() -> Cow<'static, str> {
        "Oid".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::Oid").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Exact Git object id: lowercase hex, 40 characters (sha1) or 64 (sha256).",
            "type": "string",
            "pattern": "^([0-9a-f]{40}|[0-9a-f]{64})$"
        })
    }
}

/// Native identity of a conflicted commit record.
///
/// The key is the repository-kind hash of the exact framed record bytes
/// `conflict-v1 <decimal payload length>\0<payload>` (see
/// `conflict::ConflictRecord::key`). It therefore has the same width as the
/// repository's [`Oid`]s, and the `conflict-v1` framing keeps it in a
/// separate domain from every Git object id: a Git object header begins
/// `blob `, `tree `, `commit ` or `tag `, never `conflict-v1 `.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct CommitKey(Oid);

impl CommitKey {
    /// Hashes already-framed conflict record bytes under `kind`.
    ///
    /// # Errors
    /// See [`HashKind::hash_parts`].
    pub fn of_framed_record(kind: HashKind, framed: &[u8]) -> Result<Self, CoreModelError> {
        kind.hash_parts(&[framed]).map(Self)
    }

    /// Wraps a stored digest.
    ///
    /// # Errors
    /// Rejects byte lengths other than 20 and 32.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreModelError> {
        Oid::from_bytes(bytes).map(Self)
    }

    /// Parses the `keyhex` form of a conflict parent line.
    ///
    /// # Errors
    /// Rejects non-canonical hex or an unsupported width.
    pub fn from_hex(hex: &str) -> Result<Self, CoreModelError> {
        Oid::from_hex(hex).map(Self)
    }

    /// Parses `keyhex` given as raw bytes.
    ///
    /// # Errors
    /// Rejects non-canonical hex or an unsupported width.
    pub fn from_hex_bytes(hex: &[u8]) -> Result<Self, CoreModelError> {
        Oid::from_bytes_hex(hex).map(Self)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }

    #[must_use]
    pub fn kind(&self) -> HashKind {
        self.0.kind()
    }

    /// Checks this key belongs to `kind`.
    ///
    /// # Errors
    /// [`CoreModelError::ObjectFormat`] on a width mismatch.
    pub fn expect_kind(&self, kind: HashKind) -> Result<(), CoreModelError> {
        self.0.expect_kind(kind, "commit key")
    }
}

impl fmt::Debug for CommitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommitKey({})", self.to_hex())
    }
}

impl fmt::Display for CommitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Value of a lowercase hex digit.
pub(crate) const fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Two lowercase hex characters for one byte.
pub(crate) fn hex_byte(byte: u8) -> &'static str {
    const DIGITS: &str = concat!(
        "000102030405060708090a0b0c0d0e0f",
        "101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f",
        "303132333435363738393a3b3c3d3e3f",
        "404142434445464748494a4b4c4d4e4f",
        "505152535455565758595a5b5c5d5e5f",
        "606162636465666768696a6b6c6d6e6f",
        "707172737475767778797a7b7c7d7e7f",
        "808182838485868788898a8b8c8d8e8f",
        "909192939495969798999a9b9c9d9e9f",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    );
    let start = usize::from(byte) * 2;
    &DIGITS[start..start + 2]
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(hex_byte(*byte));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1_HEX: &str = "0123456789abcdef0123456789abcdef01234567";
    const SHA256_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn hex_byte_matches_format_for_every_byte() {
        for byte in 0..=255_u8 {
            assert_eq!(hex_byte(byte), format!("{byte:02x}"));
        }
    }

    #[test]
    fn oid_parses_both_widths_and_infers_kind() {
        let sha1 = Oid::from_hex(SHA1_HEX).expect("sha1");
        assert_eq!(sha1.kind(), HashKind::Sha1);
        assert_eq!(sha1.to_hex(), SHA1_HEX);
        let sha256 = Oid::from_hex(SHA256_HEX).expect("sha256");
        assert_eq!(sha256.kind(), HashKind::Sha256);
        assert_eq!(sha256.to_hex(), SHA256_HEX);
        assert_eq!(sha256.as_bytes().len(), 32);
    }

    #[test]
    fn oid_rejects_every_malformed_shape() {
        let too_long = format!("{SHA1_HEX}0");
        let upper = SHA1_HEX.to_ascii_uppercase();
        let non_hex = format!("{}G", &SHA1_HEX[..39]);
        let padded = format!(" {}", &SHA1_HEX[..39]);
        let too_long_256 = format!("{SHA256_HEX}00");
        for bad in [
            "",
            "abc",
            "zz",
            &SHA1_HEX[..39],
            too_long.as_str(),
            upper.as_str(),
            non_hex.as_str(),
            padded.as_str(),
            &SHA256_HEX[..63],
            too_long_256.as_str(),
        ] {
            assert!(Oid::from_hex(bad).is_err(), "accepted {bad:?}");
        }
        assert!(Oid::from_bytes(&[0_u8; 19]).is_err());
        assert!(Oid::from_bytes(&[0_u8; 21]).is_err());
        assert!(Oid::from_bytes(&[0_u8; 33]).is_err());
        assert!(Oid::from_bytes(&[]).is_err());
    }

    #[test]
    fn oid_json_is_a_hex_string_and_round_trips() {
        let oid = Oid::from_hex(SHA1_HEX).expect("sha1");
        let json = serde_json::to_string(&oid).expect("json");
        assert_eq!(json, format!("\"{SHA1_HEX}\""));
        assert_eq!(serde_json::from_str::<Oid>(&json).expect("parse"), oid);
        assert!(serde_json::from_str::<Oid>("\"ABCDEF\"").is_err());
        assert!(serde_json::from_str::<Oid>("[1,2,3]").is_err());
        assert!(serde_json::from_str::<Oid>("{\"Sha1\":[0]}").is_err());
    }

    #[test]
    fn oid_postcard_is_raw_digest_bytes_for_both_widths() {
        for hex in [SHA1_HEX, SHA256_HEX] {
            let oid = Oid::from_hex(hex).expect("oid");
            let encoded = postcard::to_allocvec(&oid).expect("encode");
            // postcard byte strings are a varint length then the raw bytes.
            assert_eq!(encoded.len(), 1 + oid.as_bytes().len());
            assert_eq!(&encoded[1..], oid.as_bytes());
            assert_eq!(postcard::from_bytes::<Oid>(&encoded).expect("decode"), oid);
        }
        let bad = postcard::to_allocvec(&ByteLen(vec![7_u8; 21])).expect("encode");
        assert!(postcard::from_bytes::<Oid>(&bad).is_err());
    }

    #[derive(Serialize)]
    struct ByteLen(#[serde(serialize_with = "as_bytes")] Vec<u8>);

    fn as_bytes<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    #[test]
    fn zero_oid_matches_width() {
        assert_eq!(HashKind::Sha1.zero_oid().to_hex(), "0".repeat(40));
        assert_eq!(HashKind::Sha256.zero_oid().to_hex(), "0".repeat(64));
        assert_eq!(HashKind::Sha256.zero_oid().kind(), HashKind::Sha256);
    }

    #[test]
    fn git_object_hashing_matches_known_vectors() {
        // Known empty-blob and empty-tree object ids for both formats.
        let cases = [
            (
                HashKind::Sha1,
                "blob",
                "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
            ),
            (
                HashKind::Sha1,
                "tree",
                "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            ),
            (
                HashKind::Sha256,
                "blob",
                "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813",
            ),
            (
                HashKind::Sha256,
                "tree",
                "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321",
            ),
        ];
        for (kind, object_type, expected) in cases {
            let oid = kind.hash_git_object(object_type, b"").expect("hash");
            assert_eq!(oid.to_hex(), expected, "{kind} {object_type}");
        }
        let hello = HashKind::Sha1
            .hash_git_object("blob", b"hello\n")
            .expect("hash");
        assert_eq!(hello.to_hex(), "ce013625030ba8dba906f756967f9e9ca394464a");
    }

    #[test]
    fn expect_kind_reports_mismatch_as_object_format() {
        let sha256 = Oid::from_hex(SHA256_HEX).expect("sha256");
        assert!(sha256.expect_kind(HashKind::Sha256, "tree").is_ok());
        assert!(matches!(
            sha256.expect_kind(HashKind::Sha1, "tree"),
            Err(CoreModelError::ObjectFormat(_))
        ));
    }

    #[test]
    fn hash_kind_wire_and_text_forms() {
        assert_eq!(
            serde_json::to_string(&HashKind::Sha256).expect("json"),
            "\"sha256\""
        );
        assert_eq!(
            serde_json::from_str::<HashKind>("\"sha1\"").expect("parse"),
            HashKind::Sha1
        );
        assert!(serde_json::from_str::<HashKind>("\"SHA1\"").is_err());
        assert_eq!(
            "sha256".parse::<HashKind>().expect("parse"),
            HashKind::Sha256
        );
        assert!("sha-1".parse::<HashKind>().is_err());
        assert_eq!(HashKind::DEFAULT, HashKind::Sha1);
    }

    #[test]
    fn commit_key_is_kind_hash_of_framed_bytes() {
        let framed = b"conflict-v1 3\0abc";
        let sha1 = CommitKey::of_framed_record(HashKind::Sha1, framed).expect("sha1 key");
        let sha256 = CommitKey::of_framed_record(HashKind::Sha256, framed).expect("sha256 key");
        assert_eq!(sha1.kind(), HashKind::Sha1);
        assert_eq!(sha256.kind(), HashKind::Sha256);
        assert_eq!(sha1.as_bytes().len(), 20);
        assert_eq!(sha256.as_bytes().len(), 32);
        // The conflict framing keeps keys apart from a Git blob of the same bytes.
        let blob = HashKind::Sha1
            .hash_git_object("blob", b"abc")
            .expect("blob");
        assert_ne!(sha1.to_hex(), blob.to_hex());
        assert_eq!(CommitKey::from_hex(&sha1.to_hex()).expect("hex"), sha1);
        assert!(sha1.expect_kind(HashKind::Sha1).is_ok());
        assert!(sha1.expect_kind(HashKind::Sha256).is_err());
        let json = serde_json::to_string(&sha256).expect("json");
        assert_eq!(json, format!("\"{}\"", sha256.to_hex()));
        assert_eq!(
            serde_json::from_str::<CommitKey>(&json).expect("parse"),
            sha256
        );
    }

    #[test]
    fn commit_key_rejects_malformed_input() {
        assert!(CommitKey::from_bytes(&[1_u8; 31]).is_err());
        assert!(CommitKey::from_bytes(&[1_u8; 64]).is_err());
        assert!(CommitKey::from_hex("zz").is_err());
        assert!(CommitKey::from_hex(&"0".repeat(63)).is_err());
        assert!(CommitKey::from_hex(&"g".repeat(64)).is_err());
        assert!(CommitKey::from_hex(&"A".repeat(40)).is_err());
    }
}
