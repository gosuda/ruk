//! The non-hash identities: change IDs, operation IDs with a checked
//! counter, and the UUID-backed workspace/session/request/plan/lease IDs.
//!
//! Wire forms are explicit: human-readable formats carry the canonical text
//! form, binary formats carry the raw bytes.

use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;
use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::error::CoreModelError;
use crate::ids::{Oid, hex_byte, hex_val};

/// Serde visitor shared by the fixed-width identities: text for
/// human-readable formats, raw bytes for binary ones.
struct IdVisitor<T> {
    expecting: &'static str,
    from_text: fn(&str) -> Result<T, CoreModelError>,
    from_bytes: fn(&[u8]) -> Result<T, CoreModelError>,
    marker: PhantomData<T>,
}

impl<T> Visitor<'_> for IdVisitor<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.expecting)
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<T, E> {
        (self.from_text)(text).map_err(E::custom)
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<T, E> {
        (self.from_bytes)(bytes).map_err(E::custom)
    }
}

fn deserialize_id<'de, D: Deserializer<'de>, T>(
    deserializer: D,
    expecting: &'static str,
    from_text: fn(&str) -> Result<T, CoreModelError>,
    from_bytes: fn(&[u8]) -> Result<T, CoreModelError>,
) -> Result<T, D::Error> {
    let visitor = IdVisitor {
        expecting,
        from_text,
        from_bytes,
        marker: PhantomData,
    };
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

/// jj's "reverse hex" digit alphabet: nibble 0 is `z`, nibble 15 is `k`.
const REVERSE_HEX_DIGITS: &[u8; 16] = b"zyxwvutsrqponmlk";

/// A change identity: 16 random bytes. Native-created commit headers carry it
/// as 32 characters of jj's reverse hex (`z`..`k` for nibbles 0..=15), e.g.
/// `change-id lkonztmnvsxytrwkxpvuutrmompwylqq`. Only that exact lowercase
/// form parses, so one identity has one spelling.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChangeId([u8; 16]);

impl ChangeId {
    /// Byte length of the raw identity.
    pub const LEN: usize = 16;

    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// A fresh random identity (UUID v4 entropy, version bits included).
    #[must_use]
    pub fn generate() -> Self {
        Self(*Uuid::new_v4().as_bytes())
    }

    /// Derives a change identity deterministically from a commit object ID.
    ///
    /// Mirrors jj's synthetic fallback (`synthetic_change_id_from_git_commit_id`
    /// in `jj/lib/src/git_backend.rs`): the trailing 16 bytes of the OID,
    /// in reverse order with each byte's bits reversed. Leading OID bytes
    /// are avoided so a hash prefix is unambiguous between commit and change
    /// IDs, and the bit reversal keeps users from depending on any
    /// relationship between the two. Predictability from the OID is an
    /// accepted trade, as it is in jj.
    #[must_use]
    pub fn from_oid(oid: &Oid) -> Self {
        let bytes = oid.as_bytes();
        let start = bytes.len() - Self::LEN;
        let mut out = [0_u8; Self::LEN];
        for (slot, byte) in out.iter_mut().zip(bytes[start..].iter().rev()) {
            *slot = byte.reverse_bits();
        }
        Self(out)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The 32-character reverse-hex header form.
    #[must_use]
    pub fn to_reverse_hex(&self) -> String {
        let mut out = String::with_capacity(Self::LEN * 2);
        for byte in self.0 {
            out.push(char::from(REVERSE_HEX_DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(REVERSE_HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        out
    }

    /// Parses the 32-character reverse-hex header form.
    ///
    /// # Errors
    /// Rejects any other width, any character outside `k`..`z`, and
    /// uppercase spellings.
    pub fn from_reverse_hex(text: &str) -> Result<Self, CoreModelError> {
        let invalid = || CoreModelError::Invalid {
            what: "change id",
            detail: text.to_owned(),
        };
        if text.len() != Self::LEN * 2 {
            return Err(invalid());
        }
        let mut bytes = [0_u8; Self::LEN];
        let (chunks, _) = text.as_bytes().as_chunks::<2>();
        for (slot, pair) in bytes.iter_mut().zip(chunks) {
            let high = reverse_nibble(pair[0]).ok_or_else(invalid)?;
            let low = reverse_nibble(pair[1]).ok_or_else(invalid)?;
            *slot = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    fn from_raw(bytes: &[u8]) -> Result<Self, CoreModelError> {
        <[u8; Self::LEN]>::try_from(bytes)
            .map(Self)
            .map_err(|_| CoreModelError::Invalid {
                what: "change id bytes",
                detail: format!("{} bytes", bytes.len()),
            })
    }
}

const fn reverse_nibble(digit: u8) -> Option<u8> {
    match digit {
        b'k'..=b'z' => Some(b'z' - digit),
        _ => None,
    }
}

impl fmt::Debug for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChangeId({})", self.to_reverse_hex())
    }
}

impl fmt::Display for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_reverse_hex())
    }
}

impl FromStr for ChangeId {
    type Err = CoreModelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::from_reverse_hex(text)
    }
}

impl Serialize for ChangeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_reverse_hex())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for ChangeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize_id(
            deserializer,
            "32 reverse-hex characters (k-z) or 16 bytes",
            Self::from_reverse_hex,
            Self::from_raw,
        )
    }
}

impl JsonSchema for ChangeId {
    fn schema_name() -> Cow<'static, str> {
        "ChangeId".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::ChangeId").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Change identity: 16 bytes as 32 reverse-hex characters (nibble 0 = z ... nibble 15 = k).",
            "type": "string",
            "pattern": "^[k-z]{32}$"
        })
    }
}

/// A monotonic operation identity. The wire form is the bare integer.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct OperationId(pub u64);

/// Strictly increasing operation counter. Exhaustion is an explicit
/// `E_CAPACITY`; the counter never wraps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedOperationId {
    last: u64,
    max: u64,
}

impl CheckedOperationId {
    /// A counter whose last allocated id is `last` (0 = none yet) and whose
    /// largest allocatable id is `max`.
    #[must_use]
    pub const fn new(last: u64, max: u64) -> Self {
        Self { last, max }
    }

    /// The most recently allocated id, if any.
    #[must_use]
    pub const fn last(&self) -> Option<OperationId> {
        if self.last == 0 {
            None
        } else {
            Some(OperationId(self.last))
        }
    }

    /// Allocates the next id.
    ///
    /// # Errors
    /// [`CoreModelError::Capacity`] when `max` is exhausted. The counter is
    /// left unchanged, so a failed allocation is never observable as a skip.
    pub fn allocate(&mut self) -> Result<OperationId, CoreModelError> {
        let next = match self.last.checked_add(1) {
            Some(next) if next <= self.max => next,
            _ => {
                return Err(CoreModelError::Capacity(format!(
                    "operation id space exhausted at {}",
                    self.last
                )));
            }
        };
        self.last = next;
        Ok(OperationId(next))
    }
}

fn parse_uuid(text: &str) -> Result<Uuid, CoreModelError> {
    let invalid = || CoreModelError::Invalid {
        what: "uuid",
        detail: text.to_owned(),
    };
    let raw = text.as_bytes();
    if raw.len() != 36 {
        return Err(invalid());
    }
    let mut digits = [0_u8; 16];
    let mut count = 0_usize;
    let mut pending: Option<u8> = None;
    for (index, byte) in raw.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return Err(invalid());
            }
            continue;
        }
        let nibble = hex_val(*byte).ok_or_else(invalid)?;
        match pending.take() {
            None => pending = Some(nibble),
            Some(high) => {
                digits[count] = (high << 4) | nibble;
                count += 1;
            }
        }
    }
    Ok(Uuid::from_bytes(digits))
}

fn format_uuid(uuid: &Uuid) -> String {
    let bytes = uuid.as_bytes();
    let mut out = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(hex_byte(*byte));
    }
    out
}

/// Generates a UUID-backed identity with one canonical spelling: lowercase
/// hyphenated text for human-readable formats, 16 raw bytes for binary ones.
macro_rules! uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            /// A fresh random identity (UUID v4).
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// The nil identity, for explicit sentinels in fixtures.
            #[must_use]
            pub const fn nil() -> Self {
                Self(Uuid::nil())
            }

            /// Wraps raw bytes (for deterministic fixtures and decoding).
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(Uuid::from_bytes(bytes))
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            fn from_raw(bytes: &[u8]) -> Result<Self, CoreModelError> {
                <[u8; 16]>::try_from(bytes)
                    .map(Self::from_bytes)
                    .map_err(|_| CoreModelError::Invalid {
                        what: concat!(stringify!($name), " bytes"),
                        detail: format!("{} bytes", bytes.len()),
                    })
            }
        }

        impl FromStr for $name {
            type Err = CoreModelError;

            /// Parses the canonical lowercase hyphenated form only.
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                parse_uuid(text).map(Self).map_err(|_| CoreModelError::Invalid {
                    what: stringify!($name),
                    detail: text.to_owned(),
                })
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&format_uuid(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), format_uuid(&self.0))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&format_uuid(&self.0))
                } else {
                    serializer.serialize_bytes(self.0.as_bytes())
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserialize_id(
                    deserializer,
                    "a lowercase hyphenated UUID or 16 bytes",
                    <Self as FromStr>::from_str,
                    Self::from_raw,
                )
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> Cow<'static, str> {
                concat!(module_path!(), "::", stringify!($name)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "description": "UUID, lowercase hyphenated.",
                    "type": "string",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
                })
            }
        }
    };
}

uuid_id!(
    /// A workspace identity.
    WorkspaceId
);
uuid_id!(
    /// An authenticated session identity.
    SessionId
);
uuid_id!(
    /// A client request identity for idempotent mutations.
    RequestId
);
uuid_id!(
    /// A durable prepared-publication plan identity.
    PlanId
);
uuid_id!(
    /// A bounded object/view lease identity.
    LeaseId
);
uuid_id!(
    /// A path-scope claim handle returned when a claim is taken.
    ClaimId
);
uuid_id!(
    /// A store identity, bound into page cursors and the coordinator
    /// endpoint path.
    StoreId
);

#[cfg(test)]
mod tests {
    use super::*;

    /// A change id taken from jj's own git_backend test fixtures.
    const JJ_CHANGE_ID: &str = "lkonztmnvsxytrwkxpvuutrmompwylqq";
    const JJ_CHANGE_BYTES: [u8; 16] = [
        0xef, 0xbc, 0x06, 0xdc, 0x47, 0x21, 0x68, 0x3f, 0x2a, 0x45, 0x56, 0x8d, 0xbd, 0xa3, 0x1e,
        0x99,
    ];

    #[test]
    fn change_id_matches_jj_reverse_hex_alphabet() {
        let id = ChangeId::from_bytes(JJ_CHANGE_BYTES);
        assert_eq!(id.to_reverse_hex(), JJ_CHANGE_ID);
        assert_eq!(ChangeId::from_reverse_hex(JJ_CHANGE_ID).expect("parse"), id);
        assert_eq!(
            ChangeId::from_bytes([0; 16]).to_reverse_hex(),
            "z".repeat(32)
        );
        assert_eq!(
            ChangeId::from_bytes([0xff; 16]).to_reverse_hex(),
            "k".repeat(32)
        );
    }

    #[test]
    fn change_id_round_trips_every_byte_value() {
        for byte in 0..=255_u8 {
            let id = ChangeId::from_bytes([byte; 16]);
            assert_eq!(
                ChangeId::from_reverse_hex(&id.to_reverse_hex()).expect("parse"),
                id
            );
        }
    }

    #[test]
    fn change_id_rejects_non_canonical_spellings() {
        let upper = JJ_CHANGE_ID.to_ascii_uppercase();
        let forward_hex = "0123456789abcdef0123456789abcdef";
        let short = &JJ_CHANGE_ID[..31];
        let long = format!("{JJ_CHANGE_ID}z");
        let digit = format!("{}0", &JJ_CHANGE_ID[..31]);
        for bad in [
            "",
            "z",
            short,
            long.as_str(),
            upper.as_str(),
            forward_hex,
            digit.as_str(),
        ] {
            assert!(ChangeId::from_reverse_hex(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn change_id_serde_forms() {
        let id = ChangeId::from_bytes(JJ_CHANGE_BYTES);
        let json = sonic_rs::to_string(&id).expect("json");
        assert_eq!(json, format!("\"{JJ_CHANGE_ID}\""));
        assert_eq!(sonic_rs::from_str::<ChangeId>(&json).expect("parse"), id);
        assert!(sonic_rs::from_str::<ChangeId>("[1,2,3]").is_err());
        let binary = postcard::to_allocvec(&id).expect("postcard");
        assert_eq!(binary.len(), 1 + ChangeId::LEN);
        assert_eq!(
            postcard::from_bytes::<ChangeId>(&binary).expect("decode"),
            id
        );
    }

    #[test]
    fn oid_derived_change_ids_follow_jj_synthetic_rule() {
        use crate::ids::HashKind;

        // The trailing 16 OID bytes, reversed, with each byte bit-reversed.
        // 0x01 is 0b00000001, so every derived byte is 0b10000000.
        let sha1 = Oid::from_bytes(&[0x01; 20]).expect("sha1");
        assert_eq!(sha1.kind(), HashKind::Sha1);
        assert_eq!(ChangeId::from_oid(&sha1), ChangeId::from_bytes([0x80; 16]));

        // Only the trailing bytes participate: a leading marker is ignored,
        // and the last OID byte becomes the first change byte. 0x02 is
        // 0b00000010, bit-reversed to 0b01000000.
        let mut raw = [0x00; 20];
        raw[0] = 0xAB;
        raw[19] = 0x02;
        let marked = Oid::from_bytes(&raw).expect("marked");
        let mut expected = [0x00; 16];
        expected[0] = 0x40;
        assert_eq!(ChangeId::from_oid(&marked), ChangeId::from_bytes(expected));

        // Same trailing bytes under sha256 derive the same change ID.
        let mut wide = [0x00; 32];
        wide[16..].copy_from_slice(&raw[4..]);
        let sha256 = Oid::from_bytes(&wide).expect("sha256");
        assert_eq!(sha256.kind(), HashKind::Sha256);
        assert_eq!(ChangeId::from_oid(&sha256), ChangeId::from_oid(&marked));

        // Derivation is deterministic and distinct per OID.
        assert_eq!(ChangeId::from_oid(&sha1), ChangeId::from_oid(&sha1));
        assert_ne!(ChangeId::from_oid(&sha1), ChangeId::from_oid(&marked));
    }

    #[test]
    fn generated_change_ids_are_distinct_and_parse() {
        let first = ChangeId::generate();
        let second = ChangeId::generate();
        assert_ne!(first, second);
        assert_eq!(first.to_string().parse::<ChangeId>().expect("parse"), first);
    }

    #[test]
    fn operation_counter_never_wraps_and_failure_leaves_state() {
        let mut counter = CheckedOperationId::new(0, 2);
        assert_eq!(counter.last(), None);
        assert_eq!(counter.allocate().expect("first"), OperationId(1));
        assert_eq!(counter.allocate().expect("second"), OperationId(2));
        let before = counter;
        assert!(matches!(
            counter.allocate(),
            Err(CoreModelError::Capacity(_))
        ));
        assert_eq!(counter, before);
        assert_eq!(counter.last(), Some(OperationId(2)));
    }

    #[test]
    fn operation_counter_overflow_at_u64_max_is_capacity_not_wrap() {
        let mut counter = CheckedOperationId::new(u64::MAX - 1, u64::MAX);
        assert_eq!(counter.allocate().expect("last id"), OperationId(u64::MAX));
        assert!(matches!(
            counter.allocate(),
            Err(CoreModelError::Capacity(_))
        ));
        assert_eq!(counter.last(), Some(OperationId(u64::MAX)));
        // A caller-supplied max below `last` can never allocate either.
        let mut exhausted = CheckedOperationId::new(10, 5);
        assert!(exhausted.allocate().is_err());
    }

    #[test]
    fn operation_ids_are_bare_integers_and_ordered() {
        assert_eq!(sonic_rs::to_string(&OperationId(7)).expect("json"), "7");
        assert!(sonic_rs::from_str::<OperationId>("-1").is_err());
        assert!(OperationId(1) < OperationId(2));
        let mut counter = CheckedOperationId::new(0, u64::MAX);
        let first = counter.allocate().expect("first");
        let second = counter.allocate().expect("second");
        assert!(first < second);
    }

    #[test]
    fn uuid_ids_have_one_canonical_spelling() {
        let id = SessionId::from_bytes([
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x42, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17,
            0x40, 0x00,
        ]);
        let text = "123e4567-e89b-42d3-a456-426614174000";
        assert_eq!(id.to_string(), text);
        assert_eq!(text.parse::<SessionId>().expect("parse"), id);
        let json = sonic_rs::to_string(&id).expect("json");
        assert_eq!(json, format!("\"{text}\""));
        assert_eq!(sonic_rs::from_str::<SessionId>(&json).expect("parse"), id);
        for bad in [
            "123E4567-E89B-42D3-A456-426614174000",
            "123e4567e89b42d3a456426614174000",
            "{123e4567-e89b-42d3-a456-426614174000}",
            "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
            "123e4567-e89b-42d3-a456-42661417400",
            "123e4567-e89b-42d3-a456-4266141740000",
            "123e4567_e89b-42d3-a456-426614174000",
            "123e4567-e89b-42d3-a456-42661417400g",
            "",
        ] {
            assert!(bad.parse::<SessionId>().is_err(), "accepted {bad:?}");
            let quoted = sonic_rs::to_string(bad).expect("json");
            assert!(
                sonic_rs::from_str::<SessionId>(&quoted).is_err(),
                "accepted {quoted}"
            );
        }
    }

    #[test]
    fn uuid_ids_binary_form_is_sixteen_raw_bytes() {
        let id = RequestId::generate();
        let encoded = postcard::to_allocvec(&id).expect("postcard");
        assert_eq!(encoded.len(), 1 + 16);
        assert_eq!(
            postcard::from_bytes::<RequestId>(&encoded).expect("decode"),
            id
        );
        assert_ne!(WorkspaceId::generate(), WorkspaceId::nil());
        assert_ne!(PlanId::generate(), PlanId::generate());
        assert_ne!(LeaseId::generate().to_string(), LeaseId::nil().to_string());
    }

    #[test]
    fn distinct_id_types_do_not_interconvert_through_text_by_accident() {
        let plan = PlanId::generate();
        // The same canonical text parses into any UUID id, but the types stay
        // distinct at compile time: this is the explicit, intentional bridge.
        let lease: LeaseId = plan.to_string().parse().expect("parse");
        assert_eq!(lease.as_bytes(), plan.as_bytes());
    }
}
