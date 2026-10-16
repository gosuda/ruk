//! Tagged heads: `Git(Oid)` or `Conflicted(CommitKey)`.
//!
//! One type serves as the `commits` table key form, the graph's tagged Head,
//! and the value stored in refs and workspace state, so the tag cannot
//! diverge between them.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::CoreModelError;
use crate::ids::{CommitKey, HashKind, Oid};

/// A head: an exact Git commit object, or a native commit that cannot be a
/// Git commit (conflicted tree terms or a native parent chain).
///
/// Human-readable formats use the internally tagged object
/// `{"type":"git","oid":..}` / `{"type":"conflicted","key":..}`. Binary
/// formats (postcard) cannot decode internally tagged enums, so they use the
/// externally tagged form: a variant index followed by the digest bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Head {
    Git { oid: Oid },
    Conflicted { key: CommitKey },
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
enum HeadText {
    Git { oid: Oid },
    Conflicted { key: CommitKey },
}

#[derive(Serialize, Deserialize)]
enum HeadBinary {
    Git(Oid),
    Conflicted(CommitKey),
}

impl Serialize for Head {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            let wire = match *self {
                Self::Git { oid } => HeadText::Git { oid },
                Self::Conflicted { key } => HeadText::Conflicted { key },
            };
            wire.serialize(serializer)
        } else {
            let wire = match *self {
                Self::Git { oid } => HeadBinary::Git(oid),
                Self::Conflicted { key } => HeadBinary::Conflicted(key),
            };
            wire.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Head {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            Ok(match HeadText::deserialize(deserializer)? {
                HeadText::Git { oid } => Self::Git { oid },
                HeadText::Conflicted { key } => Self::Conflicted { key },
            })
        } else {
            Ok(match HeadBinary::deserialize(deserializer)? {
                HeadBinary::Git(oid) => Self::Git { oid },
                HeadBinary::Conflicted(key) => Self::Conflicted { key },
            })
        }
    }
}

impl JsonSchema for Head {
    fn schema_name() -> Cow<'static, str> {
        "Head".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::Head").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        HeadText::json_schema(generator)
    }
}

impl Head {
    /// Checks this head's digest width against the repository hash kind.
    ///
    /// # Errors
    /// [`CoreModelError::ObjectFormat`] on a width mismatch.
    pub fn validate(&self, kind: HashKind) -> Result<(), CoreModelError> {
        match self {
            Self::Git { oid } => oid.expect_kind(kind, "head"),
            Self::Conflicted { key } => key.expect_kind(kind),
        }
    }

    #[must_use]
    pub const fn as_git(&self) -> Option<&Oid> {
        match self {
            Self::Git { oid } => Some(oid),
            Self::Conflicted { .. } => None,
        }
    }

    #[must_use]
    pub const fn as_conflicted(&self) -> Option<&CommitKey> {
        match self {
            Self::Git { .. } => None,
            Self::Conflicted { key } => Some(key),
        }
    }

    #[must_use]
    pub const fn is_git(&self) -> bool {
        matches!(self, Self::Git { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1: &str = "0123456789abcdef0123456789abcdef01234567";

    fn git_head() -> Head {
        Head::Git {
            oid: Oid::from_hex(SHA1).expect("oid"),
        }
    }

    fn conflicted(kind: HashKind) -> Head {
        Head::Conflicted {
            key: CommitKey::of_framed_record(kind, b"conflict-v1 0\0").expect("key"),
        }
    }

    #[test]
    fn validate_enforces_the_repository_hash_kind_for_both_variants() {
        assert!(git_head().validate(HashKind::Sha1).is_ok());
        assert!(matches!(
            git_head().validate(HashKind::Sha256),
            Err(CoreModelError::ObjectFormat(_))
        ));
        for kind in [HashKind::Sha1, HashKind::Sha256] {
            let other = if kind == HashKind::Sha1 {
                HashKind::Sha256
            } else {
                HashKind::Sha1
            };
            assert!(conflicted(kind).validate(kind).is_ok());
            assert!(matches!(
                conflicted(kind).validate(other),
                Err(CoreModelError::ObjectFormat(_))
            ));
        }
    }

    #[test]
    fn variants_are_distinct_even_for_identical_digest_bytes() {
        let oid = Oid::from_hex(SHA1).expect("oid");
        let key = CommitKey::from_hex(SHA1).expect("key");
        let git = Head::Git { oid };
        let native = Head::Conflicted { key };
        assert_ne!(git, native);
        assert_eq!(git.as_git(), Some(&oid));
        assert!(git.as_conflicted().is_none() && git.is_git());
        assert_eq!(native.as_conflicted(), Some(&key));
        assert!(native.as_git().is_none() && !native.is_git());
    }

    #[test]
    fn wire_form_is_tagged_with_hex_digests() {
        let json = serde_json::to_string(&git_head()).expect("json");
        assert_eq!(json, format!("{{\"type\":\"git\",\"oid\":\"{SHA1}\"}}"));
        assert_eq!(
            serde_json::from_str::<Head>(&json).expect("parse"),
            git_head()
        );
        let native = conflicted(HashKind::Sha256);
        let json = serde_json::to_string(&native).expect("json");
        assert!(
            json.starts_with("{\"type\":\"conflicted\",\"key\":\""),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<Head>(&json).expect("parse"), native);
    }

    #[test]
    fn untagged_unknown_or_malformed_heads_are_rejected() {
        for bad in [
            format!("{{\"oid\":\"{SHA1}\"}}"),
            format!("{{\"type\":\"tree\",\"oid\":\"{SHA1}\"}}"),
            "{\"type\":\"git\",\"oid\":\"xyz\"}".to_owned(),
            "{\"type\":\"git\"}".to_owned(),
            "{\"type\":\"conflicted\",\"key\":\"00\"}".to_owned(),
        ] {
            assert!(
                serde_json::from_str::<Head>(&bad).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn postcard_round_trips_both_variants() {
        for head in [
            git_head(),
            conflicted(HashKind::Sha1),
            conflicted(HashKind::Sha256),
        ] {
            let bytes = postcard::to_allocvec(&head).expect("encode");
            assert_eq!(postcard::from_bytes::<Head>(&bytes).expect("decode"), head);
        }
    }
}
