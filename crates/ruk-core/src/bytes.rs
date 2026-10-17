//! Lossless byte strings for paths, messages, and header values.
//!
//! Git paths and commit messages are byte strings. A public schema that
//! forced them through `String` would erase non-UTF-8 content, so this type
//! carries exact bytes and picks a representation per serializer:
//!
//! * human-readable formats (JSON): a JSON string when the bytes are valid
//!   UTF-8, otherwise the object `{"hex":"<lowercase hex>"}`; both forms are
//!   accepted on input, the string form is always emitted when possible;
//! * binary formats (postcard): raw bytes.

use core::fmt;
use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ids::{hex_byte, hex_val};

/// An exact byte string. Equality, ordering, and hashing are bytewise.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct ByteString(Vec<u8>);

impl ByteString {
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The UTF-8 view when the bytes are valid UTF-8.
    #[must_use]
    pub fn to_utf8(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }
}

impl From<Vec<u8>> for ByteString {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<&[u8]> for ByteString {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl From<&str> for ByteString {
    fn from(text: &str) -> Self {
        Self(text.as_bytes().to_vec())
    }
}

impl From<String> for ByteString {
    fn from(text: String) -> Self {
        Self(text.into_bytes())
    }
}

impl AsRef<[u8]> for ByteString {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ByteString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b\"{}\"", self.0.escape_ascii())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(hex_byte(*byte));
    }
    out
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let raw = hex.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return None;
    }
    let (chunks, _) = raw.as_chunks::<2>();
    chunks
        .iter()
        .map(|pair| Some((hex_val(pair[0])? << 4) | hex_val(pair[1])?))
        .collect()
}

impl Serialize for ByteString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !serializer.is_human_readable() {
            return serializer.serialize_bytes(&self.0);
        }
        match core::str::from_utf8(&self.0) {
            Ok(text) => serializer.serialize_str(text),
            Err(_) => {
                #[derive(Serialize)]
                struct HexForm<'a> {
                    hex: &'a str,
                }
                HexForm {
                    hex: &encode_hex(&self.0),
                }
                .serialize(serializer)
            }
        }
    }
}

struct HumanVisitor;

impl<'de> Visitor<'de> for HumanVisitor {
    type Value = ByteString;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string or an object {\"hex\": \"<lowercase hex>\"}")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
        Ok(ByteString(text.as_bytes().to_vec()))
    }

    fn visit_string<E: de::Error>(self, text: String) -> Result<Self::Value, E> {
        Ok(ByteString(text.into_bytes()))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut hex: Option<String> = None;
        while let Some(key) = map.next_key::<String>()? {
            if key != "hex" || hex.is_some() {
                return Err(de::Error::custom(format!(
                    "unexpected or duplicate field `{key}` in byte string"
                )));
            }
            hex = Some(map.next_value()?);
        }
        let hex = hex.ok_or_else(|| de::Error::missing_field("hex"))?;
        let bytes = decode_hex(&hex)
            .ok_or_else(|| de::Error::custom("hex must be even-length lowercase hex"))?;
        Ok(ByteString(bytes))
    }
}

struct BinaryVisitor;

impl<'de> Visitor<'de> for BinaryVisitor {
    type Value = ByteString;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a byte string")
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        Ok(ByteString(bytes.to_vec()))
    }

    fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
        Ok(ByteString(bytes))
    }
}

impl<'de> Deserialize<'de> for ByteString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(HumanVisitor)
        } else {
            deserializer.deserialize_byte_buf(BinaryVisitor)
        }
    }
}

impl JsonSchema for ByteString {
    fn schema_name() -> Cow<'static, str> {
        "ByteString".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::ByteString").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Exact bytes: a JSON string when valid UTF-8, else {\"hex\": lowercase hex}.",
            "oneOf": [
                { "type": "string" },
                {
                    "type": "object",
                    "properties": { "hex": { "type": "string", "pattern": "^([0-9a-f]{2})*$" } },
                    "required": ["hex"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_bytes_serialize_as_plain_json_string() {
        let value = ByteString::from("src/lib.rs");
        assert_eq!(sonic_rs::to_string(&value).expect("json"), "\"src/lib.rs\"");
    }

    #[test]
    fn non_utf8_bytes_survive_json_round_trip_via_hex_form() {
        let raw = vec![b'a', 0xff, 0xfe, b'/', 0x80, 0x00];
        let value = ByteString::new(raw.clone());
        let json = sonic_rs::to_string(&value).expect("json");
        assert_eq!(json, "{\"hex\":\"61fffe2f8000\"}");
        let back: ByteString = sonic_rs::from_str(&json).expect("parse");
        assert_eq!(back.as_bytes(), raw.as_slice());
    }

    #[test]
    fn embedded_nul_and_newline_are_exact() {
        let value = ByteString::from("a\0b\nc");
        let back: ByteString =
            sonic_rs::from_str(&sonic_rs::to_string(&value).expect("json")).expect("parse");
        assert_eq!(back, value);
    }

    #[test]
    fn hex_form_accepts_valid_utf8_but_string_form_is_emitted() {
        let from_hex: ByteString = sonic_rs::from_str("{\"hex\":\"6162\"}").expect("hex");
        assert_eq!(from_hex.as_bytes(), b"ab");
        assert_eq!(sonic_rs::to_string(&from_hex).expect("json"), "\"ab\"");
    }

    #[test]
    fn rejects_malformed_hex_form() {
        for bad in [
            "{\"hex\":\"6\"}",
            "{\"hex\":\"zz\"}",
            "{\"hex\":\"AB\"}",
            "{}",
            "{\"hex\":\"61\",\"extra\":1}",
            "{\"hex\":\"61\",\"hex\":\"62\"}",
            "12",
            "[1,2]",
        ] {
            assert!(
                sonic_rs::from_str::<ByteString>(bad).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn postcard_round_trip_is_raw_bytes_for_every_byte_value() {
        let all: Vec<u8> = (0..=255_u8).collect();
        let value = ByteString::new(all.clone());
        let encoded = postcard::to_allocvec(&value).expect("postcard");
        let back: ByteString = postcard::from_bytes(&encoded).expect("decode");
        assert_eq!(back.as_bytes(), all.as_slice());
    }

    #[test]
    fn debug_escapes_without_losing_information() {
        let rendered = format!("{:?}", ByteString::new(vec![b'a', 0xff, b'"']));
        assert_eq!(rendered, "b\"a\\xff\\\"\"");
    }
}
