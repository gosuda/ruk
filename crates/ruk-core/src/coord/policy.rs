//! Coordinator principals and the authoritative version-1 policy file.
//!
//! # Principals
//!
//! A [`Principal`] is a validated operating-system identity: a Unix uid or a
//! Windows SID. Its one spelling is `unix:<decimal uid>` or
//! `windows:<SID>`, at most 256 bytes. The only constructors are the
//! endpoint's own credential reads ([`Principal::from_peer_uid`],
//! [`Principal::from_verified_sid`]) and the trusted decoders for the policy
//! file and stored rows ([`Principal::parse`], `TryFrom<String>`, serde). No
//! request field can name a principal.
//!
//! The SID grammar is the string form of `[MS-DTYP]` section 2.4.2.1:
//! `S-1-` authority `1*("-" sub-authority)`. The authority is decimal below
//! 2^32 and `0x` plus twelve hex digits from 2^32 up. Every sub-authority is
//! a 32-bit decimal. No decimal component has a leading zero. A SID has at
//! most 15 sub-authorities (`[MS-DTYP]` section 2.4.2.2). The canonical
//! spelling writes hex digits in lowercase; [`Principal::from_verified_sid`]
//! lowercases the digits of a hex authority because the operating system, not
//! this module, spells that value. Trusted decoding accepts only the
//! canonical spelling, so equal principals are equal strings.
//!
//! # Policy file
//!
//! `policy.toml` inside the store directory is TOML, format version 1:
//!
//! ```toml
//! version = 1
//! session_idle = "24h"        # optional; fixed units up to hours; > 0
//! lfs = "deny"                # optional; "deny" (the default) refuses Git
//!                             # LFS pointer blobs with E_UNSUPPORTED_LFS,
//!                             # "pointers" records the bytes plainly
//!
//! [[principal]]
//! name = "owner"              # the coordinator's own principal, or an
//!                             # exact `unix:<uid>` / `windows:<SID>`
//! capabilities = { write_changes = "all", push_refs = ["refs/**"] }
//! allow_any_identity = false  # default false
//! identities = [{ name = "Ada", email = "ada@example.test" }]
//! allow_any_claim_keys = false # default false
//! claim_keys = ["tool"]
//! ```
//!
//! `capabilities` uses the [`Capabilities`] serde form; an absent or empty
//! table is a valid read-only ceiling. Unknown fields anywhere, duplicate
//! principals (including an `owner` alias that names a principal the file also
//! spells), invalid identities or claim keys, an unsupported version, and
//! malformed TOML are [`ErrorCode::EPolicy`]. An existing file is
//! authoritative and never implicitly adds the owner.
//!
//! # Loading
//!
//! [`PolicySource::load`] reads the whole file every time, bounded by
//! [`crate::MAX_CONTROL_FRAME_BYTES`] with a one-byte overflow probe, hashes
//! the bytes, and reuses a parsed result only when the hash matches. No
//! length or modification-time shortcut exists, so a same-length edit with a
//! preserved timestamp still changes authority. A missing file selects the
//! owner-only default; every other failure to read the file is an error, never
//! the default.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use jiff::SignedDuration;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::MAX_CONTROL_FRAME_BYTES;
use crate::capability::{
    Capabilities, PathPattern, ReadIntents, RefPattern, UndoScope, WriteScope,
};
use crate::commit::ProvenanceClaims;
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{IdentityClaim, Validate};
use crate::store::CapacityLimits;
use crate::workcopy::lfs::LfsMode;

/// File name of the policy inside the store directory.
const POLICY_FILE_NAME: &str = "policy.toml";

/// The one policy format version this build reads.
const POLICY_VERSION: i64 = 1;

/// Literal `name` that stands for the coordinator's own principal.
const OWNER_ALIAS: &str = "owner";

/// Longest principal spelling, in bytes.
const MAX_PRINCIPAL_BYTES: usize = 256;

const UNIX_PREFIX: &str = "unix:";
const WINDOWS_PREFIX: &str = "windows:";
const SID_PREFIX: &str = "S-1-";

/// A SID carries at most this many sub-authorities (`[MS-DTYP]` 2.4.2.2).
const MAX_SUB_AUTHORITIES: usize = 15;

/// Decimal digits of the largest 32-bit value.
const MAX_DECIMAL_DIGITS: usize = 10;

/// Hex digits of a hex identifier authority.
const AUTHORITY_HEX_DIGITS: usize = 12;

/// Read limit: one byte past the cap, so an overlong file is observable.
/// Widening cast: `usize` fits in `u64` on every platform this build targets.
const READ_LIMIT: u64 = (MAX_CONTROL_FRAME_BYTES as u64) + 1;

/// Session idle lifetime when the policy does not set one.
const DEFAULT_SESSION_IDLE: SignedDuration = SignedDuration::from_hours(24);

/// Top-level fields of a `capabilities` table. A test pins this list to the
/// fields [`Capabilities`] serializes.
const CAPABILITY_KEYS: [&str; 7] = [
    "write_changes",
    "push_refs",
    "land",
    "claim_paths",
    "undo",
    "attest",
    "read_intents",
];

/// Fields of a `read_intents` table; pinned like [`CAPABILITY_KEYS`].
const READ_INTENT_KEYS: [&str; 2] = ["provenance", "claims"];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn invalid(detail: impl Into<String>) -> CoreError {
    CoreError::new(ErrorCode::EInvalid, detail)
}

fn policy_error(detail: impl Into<String>) -> CoreError {
    CoreError::new(ErrorCode::EPolicy, detail)
        .with_hint("correct or remove policy.toml in the store directory")
}

fn forbidden(detail: impl Into<String>) -> CoreError {
    CoreError::new(ErrorCode::EForbidden, detail)
}

fn io_error(path: &Path, op: &str, error: &std::io::Error) -> CoreError {
    CoreError::new(
        ErrorCode::EIo,
        format!("policy file {op} failed for {}: {error}", path.display()),
    )
}

/// First `max` characters of `text`, marked when cut.
fn clip(text: &str, max: usize) -> String {
    let mut clipped: String = text.chars().take(max).collect();
    if text.chars().nth(max).is_some() {
        clipped.push_str("...");
    }
    clipped
}

/// Debug-escaped, clipped rendering of untrusted text for messages.
fn shown(text: &str) -> String {
    let clipped: String = text.chars().take(64).collect();
    let mut shown = format!("{clipped:?}");
    if text.chars().nth(64).is_some() {
        shown.push_str("...");
    }
    shown
}

// ---------------------------------------------------------------------------
// Principal
// ---------------------------------------------------------------------------

/// Canonical decimal `u32`: nonempty ASCII digits, no leading zero except the
/// single digit `0`, at most `u32::MAX`.
fn canonical_u32(text: &str) -> Option<u32> {
    let bytes = text.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_DECIMAL_DIGITS
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes.first() == Some(&b'0'))
    {
        return None;
    }
    text.parse().ok()
}

/// A canonical hex identifier authority: `0x`, twelve lowercase hex digits,
/// and a value of at least 2^32 (smaller values are spelled in decimal).
fn canonical_hex_authority(text: &str) -> bool {
    let Some(digits) = text.strip_prefix("0x") else {
        return false;
    };
    digits.len() == AUTHORITY_HEX_DIGITS
        && digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && u64::from_str_radix(digits, 16).is_ok_and(|value| value > u64::from(u32::MAX))
}

/// Lowercases the digits of a hex authority so an operating-system spelling
/// reaches the canonical form. Everything else is left untouched.
fn lowercase_hex_authority(text: &str) -> std::borrow::Cow<'_, str> {
    let Some(rest) = text.strip_prefix("S-1-0x") else {
        return std::borrow::Cow::Borrowed(text);
    };
    let (digits, tail) = rest.split_at(rest.find('-').unwrap_or(rest.len()));
    std::borrow::Cow::Owned(format!("S-1-0x{}{tail}", digits.to_ascii_lowercase()))
}

/// A Windows security identifier in canonical string form. Constructed only
/// through [`Principal`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sid(String);

impl Sid {
    /// The canonical `S-1-...` spelling.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses exactly the canonical spelling.
    fn parse_canonical(text: &str) -> Result<Self, CoreError> {
        let malformed = || invalid(format!("malformed SID {}", shown(text)));
        if text.len() > MAX_PRINCIPAL_BYTES - WINDOWS_PREFIX.len() {
            return Err(malformed());
        }
        let rest = text.strip_prefix(SID_PREFIX).ok_or_else(malformed)?;
        let mut parts = rest.split('-');
        let authority = parts.next().ok_or_else(malformed)?;
        if canonical_u32(authority).is_none() && !canonical_hex_authority(authority) {
            return Err(malformed());
        }
        let mut sub_authorities = 0_usize;
        for part in parts {
            if canonical_u32(part).is_none() {
                return Err(malformed());
            }
            sub_authorities += 1;
            if sub_authorities > MAX_SUB_AUTHORITIES {
                return Err(malformed());
            }
        }
        if sub_authorities == 0 {
            return Err(malformed());
        }
        Ok(Self(text.to_owned()))
    }
}

/// A validated operating-system identity.
///
/// Serialized (every codec) and displayed as `unix:<decimal uid>` or
/// `windows:<SID>`. Deserialization re-validates, so a stored or configured
/// alias such as `unix:007` is rejected rather than compared as a different
/// principal.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Principal {
    /// A Unix user, by numeric uid.
    Unix(u32),
    /// A Windows user, by SID.
    Windows(Sid),
}

impl Principal {
    /// The peer uid read from kernel credentials by the Unix endpoint (and
    /// the process's own uid for the owner).
    #[must_use]
    pub const fn from_peer_uid(uid: u32) -> Self {
        Self::Unix(uid)
    }

    /// The SID string the Windows endpoint obtained from the verified token
    /// of the peer (or of the coordinator process for the owner).
    ///
    /// # Errors
    /// `E_INVALID` for text outside the SID grammar in the module docs.
    pub fn from_verified_sid(sid: &str) -> Result<Self, CoreError> {
        if sid.len() > MAX_PRINCIPAL_BYTES - WINDOWS_PREFIX.len() {
            return Err(invalid(format!("malformed SID {}", shown(sid))));
        }
        Sid::parse_canonical(&lowercase_hex_authority(sid)).map(Self::Windows)
    }

    /// Parses the canonical spelling for trusted sources: the policy file and
    /// stored rows. Never call this on request-supplied text.
    ///
    /// # Errors
    /// `E_INVALID` for anything but the exact canonical spelling.
    pub fn parse(text: &str) -> Result<Self, CoreError> {
        let malformed = || {
            invalid(format!(
                "a principal is `unix:<uid>` or `windows:<SID>` in canonical form, got {}",
                shown(text)
            ))
        };
        if text.len() > MAX_PRINCIPAL_BYTES {
            return Err(malformed());
        }
        if let Some(uid) = text.strip_prefix(UNIX_PREFIX) {
            return canonical_u32(uid).map(Self::Unix).ok_or_else(malformed);
        }
        if let Some(sid) = text.strip_prefix(WINDOWS_PREFIX) {
            return Sid::parse_canonical(sid)
                .map(Self::Windows)
                .map_err(|_| malformed());
        }
        Err(malformed())
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unix(uid) => write!(f, "{UNIX_PREFIX}{uid}"),
            Self::Windows(sid) => write!(f, "{WINDOWS_PREFIX}{}", sid.as_str()),
        }
    }
}

impl From<Principal> for String {
    fn from(principal: Principal) -> Self {
        principal.to_string()
    }
}

impl TryFrom<String> for Principal {
    type Error = CoreError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// What one listed principal may do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrincipalPolicy {
    /// The capability ceiling. Empty is valid read-only access.
    pub(crate) ceiling: Capabilities,
    allow_any_identity: bool,
    identities: Vec<IdentityClaim>,
    allow_any_claim_keys: bool,
    claim_keys: BTreeSet<String>,
}

impl PrincipalPolicy {
    /// Checks a session's declared identity and claim keys against this
    /// principal's exact allowlists. Request validity (grammar, limits) is the
    /// protocol validators' job and is not repeated here; claim values are not
    /// restricted.
    ///
    /// # Errors
    /// `E_FORBIDDEN` naming the first identity or claim key the policy does
    /// not allow.
    pub(crate) fn admit_claims(
        &self,
        identity: Option<&IdentityClaim>,
        claims: &ProvenanceClaims,
    ) -> Result<(), CoreError> {
        if let Some(identity) = identity
            && !self.allow_any_identity
            && !self.identities.contains(identity)
        {
            return Err(forbidden(format!(
                "identity {} <{}> is not allowed for this principal",
                shown(&identity.name),
                shown(&identity.email)
            ))
            .with_hint("declare an identity listed in the principal's policy, or none"));
        }
        if !self.allow_any_claim_keys
            && let Some(key) = claims
                .as_map()
                .keys()
                .find(|key| !self.claim_keys.contains(key.as_str()))
        {
            return Err(forbidden(format!(
                "claim key {} is not allowed for this principal",
                shown(key)
            ))
            .with_hint("declare only claim keys listed in the principal's policy"));
        }
        Ok(())
    }

    /// The owner-only default ceiling: every supported change, ref, land,
    /// claim, undo, and read-intent authority, and no attestation kinds
    /// (which have no wildcard grammar).
    fn owner_default() -> Result<Self, CoreError> {
        let any_ref = RefPattern::parse("refs/**")?;
        Ok(Self {
            ceiling: Capabilities {
                write_changes: Some(WriteScope::All),
                push_refs: vec![any_ref.clone()],
                land: vec![any_ref],
                claim_paths: vec![PathPattern::parse("**")?],
                undo: Some(UndoScope::All),
                attest: Vec::new(),
                read_intents: ReadIntents {
                    provenance: true,
                    claims: true,
                },
            },
            allow_any_identity: true,
            identities: Vec::new(),
            allow_any_claim_keys: true,
            claim_keys: BTreeSet::new(),
        })
    }
}

/// A parsed, validated policy: the principals the coordinator admits, the
/// session idle bound, and the LFS pointer mode the store enforces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Policy {
    session_idle: SignedDuration,
    lfs: LfsMode,
    capacity: CapacityLimits,
    entries: HashMap<Principal, PrincipalPolicy>,
}

impl Policy {
    /// The policy of a store with no policy file: only `owner`, with the
    /// full ceiling, and pointer blobs refused.
    ///
    /// # Errors
    /// Never in practice; the fixed patterns are valid.
    pub(crate) fn default_for_owner(owner: &Principal) -> Result<Self, CoreError> {
        Ok(Self {
            session_idle: DEFAULT_SESSION_IDLE,
            lfs: LfsMode::default(),
            capacity: CapacityLimits::unbounded(),
            entries: HashMap::from([(owner.clone(), PrincipalPolicy::owner_default()?)]),
        })
    }

    /// Parses a complete policy file. `owner` resolves the `owner` alias.
    ///
    /// # Errors
    /// `E_POLICY` for malformed TOML, an unsupported version, unknown fields,
    /// invalid values, or duplicate principals.
    pub(crate) fn parse(bytes: &[u8], owner: &Principal) -> Result<Self, CoreError> {
        // The TOML parser accepts a UTF-8 byte-order mark, but a Ruk policy
        // file is canonical bytes: a BOM is not valid TOML for this file.
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return Err(policy_error(format!(
                "{POLICY_FILE_NAME} starts with a UTF-8 byte-order mark"
            )));
        }
        let raw = parse_raw(bytes)?;
        let session_idle = match raw.session_idle {
            None => DEFAULT_SESSION_IDLE,
            Some(text) => parse_session_idle(&text)?,
        };
        let mut entries = HashMap::with_capacity(raw.principals.len());
        for entry in raw.principals {
            let (principal, policy) = entry.build(owner)?;
            if entries.contains_key(&principal) {
                return Err(policy_error(format!(
                    "principal {principal} is listed more than once (the `{OWNER_ALIAS}` alias \
                     names {owner})"
                )));
            }
            entries.insert(principal, policy);
        }
        let capacity = raw.capacity.unwrap_or(RawCapacity {
            max_pending: None,
            max_total: None,
        });
        Ok(Self {
            session_idle,
            lfs: raw.lfs.unwrap_or_default(),
            capacity: CapacityLimits {
                max_pending_bytes: capacity.max_pending,
                max_store_bytes: capacity.max_total,
            },
            entries,
        })
    }

    /// The one lookup for endpoint admission and session authorization.
    ///
    /// # Errors
    /// `E_FORBIDDEN` when the principal is not listed.
    pub(crate) fn lookup(&self, principal: &Principal) -> Result<&PrincipalPolicy, CoreError> {
        self.entries.get(principal).ok_or_else(|| {
            forbidden(format!(
                "principal {principal} is not listed in the coordinator policy"
            ))
            .with_hint("ask the coordinator owner to list this principal in policy.toml")
        })
    }

    /// How long a session may stay idle before its write authority expires:
    /// a positive fixed duration, 24 hours by default.
    #[must_use]
    pub(crate) const fn session_idle(&self) -> SignedDuration {
        self.session_idle
    }

    /// How this store treats Git LFS pointer blobs: refused by default,
    /// recorded plainly only under `lfs = "pointers"`.
    #[must_use]
    pub(crate) const fn lfs(&self) -> LfsMode {
        self.lfs
    }

    /// The durable-store quota knobs from `policy.toml [capacity]`
    /// (`max_pending` / `max_total`), unbounded when absent. The
    /// coordinator applies them to the store with
    /// [`crate::store::Store::set_capacity_limits`].
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    #[must_use]
    pub(crate) const fn capacity_limits(&self) -> CapacityLimits {
        self.capacity
    }
}

// ---------------------------------------------------------------------------
// TOML decoding
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    version: i64,
    session_idle: Option<String>,
    lfs: Option<LfsMode>,
    #[serde(default)]
    capacity: Option<RawCapacity>,
    #[serde(default, rename = "principal")]
    principals: Vec<RawPrincipal>,
}

/// The `policy.toml [capacity]` table: durable-store quota knobs for the
/// capacity ledger. Both bounds are byte counts; absent means unbounded.
/// A zero bound admits nothing and is taken literally.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapacity {
    #[serde(default)]
    max_pending: Option<u64>,
    #[serde(default)]
    max_total: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrincipal {
    name: String,
    #[serde(default)]
    capabilities: toml::Table,
    #[serde(default)]
    allow_any_identity: bool,
    #[serde(default)]
    identities: Vec<RawIdentity>,
    #[serde(default)]
    allow_any_claim_keys: bool,
    #[serde(default)]
    claim_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    name: String,
    email: String,
}

/// Reads only the version, so a future-format file reports its version
/// instead of the first field this build does not know.
#[derive(Deserialize)]
struct VersionProbe {
    version: Option<i64>,
}

fn unsupported_version(found: i64) -> CoreError {
    policy_error(format!(
        "policy version {found} is not supported; this build reads version {POLICY_VERSION}"
    ))
}

/// The error for a document the TOML layer refused, with the line when the
/// layer knows it. Only the library's short message is quoted, never the
/// source line, and it is clipped.
fn toml_error(bytes: &[u8], error: &toml::de::Error) -> CoreError {
    let at = error.span().map_or_else(String::new, |span| {
        let upto = span.start.min(bytes.len());
        let line = 1 + bytes[..upto].iter().filter(|byte| **byte == b'\n').count();
        format!(" at line {line}")
    });
    policy_error(format!(
        "{POLICY_FILE_NAME} is not a valid version-{POLICY_VERSION} policy{at}: {}",
        clip(error.message(), 200)
    ))
}

fn parse_raw(bytes: &[u8]) -> Result<RawPolicy, CoreError> {
    match toml::from_slice::<RawPolicy>(bytes) {
        Ok(raw) if raw.version == POLICY_VERSION => Ok(raw),
        Ok(raw) => Err(unsupported_version(raw.version)),
        Err(error) => match toml::from_slice::<VersionProbe>(bytes) {
            Ok(VersionProbe {
                version: Some(found),
            }) if found != POLICY_VERSION => Err(unsupported_version(found)),
            _ => Err(toml_error(bytes, &error)),
        },
    }
}

/// Parses `session_idle`: a jiff duration over fixed units (hours and below,
/// or ISO `PT...`). Calendar units need a relative date and are refused by
/// the parser, as is arithmetic overflow; the result must be positive.
fn parse_session_idle(text: &str) -> Result<SignedDuration, CoreError> {
    let duration = text.parse::<SignedDuration>().map_err(|error| {
        policy_error(format!(
            "session_idle {} is not a fixed positive duration: {}",
            shown(text),
            clip(&error.to_string(), 200)
        ))
    })?;
    if !duration.is_positive() {
        return Err(policy_error(format!(
            "session_idle {} must be greater than zero",
            shown(text)
        )));
    }
    Ok(duration)
}

/// Checks a `capabilities` table for unknown fields at its two table levels
/// (the [`Capabilities`] serde form ignores them), then decodes it.
fn parse_capabilities(table: toml::Table, who: &Principal) -> Result<Capabilities, CoreError> {
    if let Some(key) = table
        .keys()
        .find(|key| !CAPABILITY_KEYS.contains(&key.as_str()))
    {
        return Err(policy_error(format!(
            "principal {who}: unknown capability field {}",
            shown(key)
        )));
    }
    if let Some(toml::Value::Table(intents)) = table.get("read_intents")
        && let Some(key) = intents
            .keys()
            .find(|key| !READ_INTENT_KEYS.contains(&key.as_str()))
    {
        return Err(policy_error(format!(
            "principal {who}: unknown read_intents field {}",
            shown(key)
        )));
    }
    table.try_into::<Capabilities>().map_err(|error| {
        policy_error(format!(
            "principal {who}: invalid capabilities: {}",
            clip(error.message(), 200)
        ))
    })
}

impl RawPrincipal {
    /// Resolves the name and validates every value.
    fn build(self, owner: &Principal) -> Result<(Principal, PrincipalPolicy), CoreError> {
        let principal = if self.name == OWNER_ALIAS {
            owner.clone()
        } else {
            Principal::parse(&self.name).map_err(|error| {
                policy_error(format!(
                    "principal name must be `{OWNER_ALIAS}` or a canonical principal: {}",
                    error.message
                ))
            })?
        };
        let ceiling = parse_capabilities(self.capabilities, &principal)?;
        let identities = self
            .identities
            .into_iter()
            .map(|raw| {
                let identity = IdentityClaim {
                    name: raw.name,
                    email: raw.email,
                };
                identity.validate().map_err(|error| {
                    policy_error(format!(
                        "principal {principal}: invalid identity: {}",
                        error.message
                    ))
                })?;
                Ok(identity)
            })
            .collect::<Result<Vec<_>, CoreError>>()?;
        let mut claim_keys = BTreeSet::new();
        for key in self.claim_keys {
            ProvenanceClaims::new(BTreeMap::from([(key.clone(), String::new())])).map_err(
                |error| {
                    policy_error(format!(
                        "principal {principal}: invalid claim key {}: {error}",
                        shown(&key)
                    ))
                },
            )?;
            claim_keys.insert(key);
        }
        Ok((
            principal,
            PrincipalPolicy {
                ceiling,
                allow_any_identity: self.allow_any_identity,
                identities,
                allow_any_claim_keys: self.allow_any_claim_keys,
                claim_keys,
            },
        ))
    }
}

// ---------------------------------------------------------------------------
// Policy source
// ---------------------------------------------------------------------------

/// One parse outcome and the digest of the bytes that produced it.
#[derive(Debug)]
struct Parsed {
    digest: [u8; 32],
    outcome: Result<Arc<Policy>, CoreError>,
}

/// Where the coordinator's policy comes from: `policy.toml` in the store
/// directory, with the owner resolved by the same credential path as peers.
///
/// The cache holds a parse result keyed by the SHA-256 of the exact bytes
/// read. It saves reparsing an unchanged file and decides nothing: every load
/// reads the file again.
#[derive(Debug)]
pub(crate) struct PolicySource {
    path: PathBuf,
    owner: Principal,
    cache: Mutex<Option<Parsed>>,
}

/// Reads the LFS pointer mode the store at `store_root` declares, parsed
/// through the real coordinator policy loader: any document
/// [`PolicySource::load`] would reject — unknown fields, a bad
/// `[[principal]]`, an unsupported version, malformed TOML, an oversized or
/// non-regular file — fails closed to [`LfsMode::Deny`], never `Pointers`.
/// A missing file selects the owner-only default, whose mode is the store
/// default. The `owner` alias resolves against the on-disk owner of the
/// store directory on Unix, the same choice the daemon registry makes when
/// it binds a coordinator; elsewhere it resolves against the process
/// identity (the daemon refuses hosting there, so no coordinator policy
/// exists to diverge from).
pub(crate) fn lfs_mode_for_store(store_root: &Path) -> LfsMode {
    let Some(owner) = store_owner(store_root) else {
        return LfsMode::Deny;
    };
    PolicySource::open(store_root, owner)
        .load()
        .map(|policy| policy.lfs())
        .unwrap_or_default()
}

/// The principal the coordinator policy source resolves the `owner` alias
/// against for `store_root`: the on-disk owner of the store directory on
/// Unix, the process identity elsewhere. `None` where no owner identity is
/// readable; callers fail closed.
fn store_owner(store_root: &Path) -> Option<Principal> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(store_root)
            .ok()
            .map(|metadata| Principal::from_peer_uid(metadata.uid()))
    }
    #[cfg(not(unix))]
    {
        let _ = store_root;
        super::endpoint::owner().ok()
    }
}

impl PolicySource {
    /// Binds the source to `store_root/policy.toml`. Nothing is read.
    #[must_use]
    pub(crate) fn open(store_root: &Path, owner: Principal) -> Self {
        Self {
            path: store_root.join(POLICY_FILE_NAME),
            owner,
            cache: Mutex::new(None),
        }
    }

    /// The policy the file currently states.
    ///
    /// Blocking: reads and hashes the file. Run it in admitted blocking work,
    /// before authenticating a connection or opening a session and before
    /// authorizing a publication.
    ///
    /// # Errors
    /// `E_POLICY` for an invalid, oversized, or non-regular policy file;
    /// `E_IO` when the file exists but cannot be read. A missing file is not
    /// an error: it selects the owner-only default.
    pub(crate) fn load(&self) -> Result<Arc<Policy>, CoreError> {
        let Some(bytes) = read_policy_file(&self.path)? else {
            return Policy::default_for_owner(&self.owner).map(Arc::new);
        };
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if let Some(outcome) = self.cached(&digest) {
            return outcome;
        }
        let outcome = Policy::parse(&bytes, &self.owner).map(Arc::new);
        *self.cache.lock().unwrap_or_else(PoisonError::into_inner) = Some(Parsed {
            digest,
            outcome: outcome.clone(),
        });
        outcome
    }

    /// The stored outcome for exactly these bytes, if any.
    fn cached(&self, digest: &[u8; 32]) -> Option<Result<Arc<Policy>, CoreError>> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache
            .as_ref()
            .filter(|parsed| parsed.digest == *digest)
            .map(|parsed| parsed.outcome.clone())
    }
}

/// Opens without following a blocking special file: a FIFO at the policy path
/// must fail the regular-file check, not hang the worker.
fn open_policy_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // OFlags::NONBLOCK is a small positive bitmask that fits in a signed 32-bit integer.
        if let Ok(flags) = i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()) {
            options.custom_flags(flags);
        }
    }
    options.open(path)
}

/// Reads the complete policy, `None` when the file does not exist. The read
/// stops one byte past the cap, so the buffer never outgrows the cap by more
/// than that byte and an overlong file is detected instead of truncated.
fn read_policy_file(path: &Path) -> Result<Option<Vec<u8>>, CoreError> {
    let file = match open_policy_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(path, "open", &error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| io_error(path, "stat", &error))?;
    if !metadata.is_file() {
        return Err(policy_error(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let hint = usize::try_from(metadata.len().min(READ_LIMIT)).unwrap_or_default();
    let mut bytes = Vec::with_capacity(hint);
    file.take(READ_LIMIT)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(path, "read", &error))?;
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(policy_error(format!(
            "{} exceeds the {MAX_CONTROL_FRAME_BYTES}-byte limit",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::capability::AttestKind;

    static SEQ: AtomicU32 = AtomicU32::new(0);

    /// A unique temporary directory removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ruk-policy-{tag}-{}-{}-{nanos}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).expect("create the test directory");
            Self(dir)
        }

        fn policy(&self) -> PathBuf {
            self.0.join(POLICY_FILE_NAME)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn owner() -> Principal {
        Principal::from_peer_uid(1000)
    }

    fn other() -> Principal {
        Principal::from_peer_uid(2000)
    }

    fn parsed(text: &str) -> Policy {
        Policy::parse(text.as_bytes(), &owner()).unwrap_or_else(|error| panic!("{text}: {error}"))
    }

    fn code_of(text: &str) -> ErrorCode {
        Policy::parse(text.as_bytes(), &owner())
            .expect_err(text)
            .code
    }

    fn claims(pairs: &[(&str, &str)]) -> ProvenanceClaims {
        ProvenanceClaims::new(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        )
        .expect("claims")
    }

    fn identity(name: &str, email: &str) -> IdentityClaim {
        IdentityClaim {
            name: name.to_owned(),
            email: email.to_owned(),
        }
    }

    fn ref_pattern(text: &str) -> RefPattern {
        RefPattern::parse(text).expect("ref pattern")
    }

    fn write_scope_of(policy: &Policy, who: &Principal) -> Option<WriteScope> {
        policy.lookup(who).expect("listed").ceiling.write_changes
    }

    /// A policy of equal length for every `scope` of equal length.
    fn owner_grant(scope: &str) -> String {
        format!(
            "version = 1\n[[principal]]\nname = \"owner\"\ncapabilities = {{ write_changes = \
             \"{scope}\" }}\n"
        )
    }

    // ----- principals -----------------------------------------------------

    #[test]
    fn canonical_principals_round_trip_through_every_codec() {
        for text in [
            "unix:0",
            "unix:1000",
            "unix:4294967295",
            "windows:S-1-5-18",
            "windows:S-1-5-21-1004336348-1177238915-682003330-512",
            "windows:S-1-1-0",
            "windows:S-1-0-0",
            "windows:S-1-5-4294967295",
            "windows:S-1-4294967295-1",
            "windows:S-1-0x000100000000-1",
            "windows:S-1-0xffffffffffff-1-2",
        ] {
            let principal = Principal::parse(text).expect(text);
            assert_eq!(principal.to_string(), text);
            assert_eq!(String::from(principal.clone()), text);
            let json = sonic_rs::to_string(&principal).expect("json");
            assert_eq!(json, format!("\"{text}\""));
            assert_eq!(
                sonic_rs::from_str::<Principal>(&json).expect("json"),
                principal
            );
            let bytes = postcard::to_allocvec(&principal).expect("postcard");
            assert_eq!(
                postcard::from_bytes::<Principal>(&bytes).expect("postcard"),
                principal
            );
        }
        assert_eq!(
            Principal::from_peer_uid(1000),
            Principal::parse("unix:1000").expect("uid")
        );
    }

    #[test]
    fn uid_aliases_and_junk_are_not_principals() {
        for bad in [
            "",
            "unix",
            "unix:",
            "unix:00",
            "unix:01",
            "unix:01000",
            "unix:+1",
            "unix:-1",
            "unix: 1",
            "unix:1 ",
            " unix:1",
            "unix:1\n",
            "unix:1\0",
            "unix:\u{1}",
            "unix:4294967296",
            "unix:99999999999999999999",
            "unix:0x10",
            "unix:1e3",
            "unix:1000:1",
            "unix:\u{FF11}\u{FF12}",
            "unix:\u{661}\u{662}",
            "UNIX:1",
            "Unix:1",
            "unix1",
            "root",
            "owner",
            "windows:",
            "windows:S-1-5",
            "WINDOWS:S-1-5-18",
            "windows: S-1-5-18",
        ] {
            let error = Principal::parse(bad).expect_err(bad);
            assert_eq!(error.code, ErrorCode::EInvalid, "{bad:?}");
            assert!(
                Principal::try_from(bad.to_owned()).is_err(),
                "TryFrom accepted {bad:?}"
            );
        }
        let long = format!("unix:{}", "1".repeat(300));
        assert_eq!(
            Principal::parse(&long).expect_err("overlong").code,
            ErrorCode::EInvalid
        );
        assert!(
            Principal::parse(&long).expect_err("overlong").message.len() < 512,
            "an overlong principal is not echoed whole"
        );
    }

    #[test]
    fn sids_follow_the_ms_dtyp_grammar() {
        let sixteen = format!("S-1-5{}", "-1".repeat(16));
        let fifteen = format!("S-1-5{}", "-1".repeat(15));
        assert!(Principal::from_verified_sid(&fifteen).is_ok());
        for bad in [
            "",
            "S",
            "S-1",
            "S-1-",
            "S-1-5",
            "S-1-5-",
            "S-1--5",
            "S-1-5--18",
            "S-1-5-18-",
            "S-2-5-18",
            "S-0-5-18",
            "s-1-5-18",
            "S-01-5-18",
            "S-1-05-18",
            "S-1-5-018",
            "S-1-5-+18",
            "S-1-5--1",
            "S-1-5-18 ",
            " S-1-5-18",
            "S-1-5-18\n",
            "S-1-5-1\u{0}8",
            "S-1-5-\u{1}",
            "S-1-5-\u{FF11}\u{FF18}",
            "S-1-5-4294967296",
            "S-1-5-18-99999999999",
            "S-1-4294967296-5",
            "S-1-0x1-5",
            "S-1-0x0000000000ff-5",
            "S-1-0xffffffff-5",
            "S-1-0x00010000000-5",
            "S-1-0x0001000000000-5",
            "S-1-0x00010000000g-5",
            "S-1-0X000100000000-5",
            "S-1-0x-5",
            "unix:1000",
            "windows:S-1-5-18",
            "S-1-5-18/..",
        ] {
            let error = Principal::from_verified_sid(bad).expect_err(bad);
            assert_eq!(error.code, ErrorCode::EInvalid, "{bad:?}");
            assert!(
                Principal::parse(&format!("windows:{bad}")).is_err(),
                "trusted parse accepted {bad:?}"
            );
        }
        assert!(
            Principal::from_verified_sid(&sixteen).is_err(),
            "16 sub-authorities"
        );
        let huge = format!("S-1-5{}", "-1".repeat(400));
        assert!(Principal::from_verified_sid(&huge).is_err());
        assert!(Principal::parse(&format!("windows:{huge}")).is_err());
    }

    #[test]
    fn the_os_hex_authority_is_canonicalized_but_stored_spellings_are_strict() {
        let from_os = Principal::from_verified_sid("S-1-0x0001000000AB-5").expect("os spelling");
        assert_eq!(from_os.to_string(), "windows:S-1-0x0001000000ab-5");
        assert_eq!(
            from_os,
            Principal::parse("windows:S-1-0x0001000000ab-5").expect("canonical")
        );
        assert!(Principal::parse("windows:S-1-0x0001000000AB-5").is_err());
        assert!(sonic_rs::from_str::<Principal>("\"windows:S-1-0x0001000000AB-5\"").is_err());
    }

    #[test]
    fn serde_revalidates_every_decoded_principal() {
        for bad in [
            "\"unix:007\"",
            "\"unix:+7\"",
            "\"windows:S-1-05-18\"",
            "\"windows:S-1-5\"",
            "\"owner\"",
            "\"\"",
            "7",
            "null",
            "[\"unix:1\"]",
            "{\"Unix\":1}",
        ] {
            assert!(sonic_rs::from_str::<Principal>(bad).is_err(), "json {bad}");
        }
        for bad in ["unix:007", "windows:S-1-05-18", "owner"] {
            let bytes = postcard::to_allocvec(&bad.to_owned()).expect("encode text");
            assert!(
                postcard::from_bytes::<Principal>(&bytes).is_err(),
                "postcard {bad}"
            );
        }
    }

    // ----- policy parsing -------------------------------------------------

    #[test]
    fn a_policy_without_principals_admits_nobody_and_never_adds_the_owner() {
        let policy = parsed("version = 1\n");
        assert_eq!(policy.session_idle(), SignedDuration::from_hours(24));
        assert_eq!(policy.lfs(), LfsMode::Deny);
        for who in [owner(), other()] {
            assert_eq!(
                policy.lookup(&who).expect_err("unlisted").code,
                ErrorCode::EForbidden
            );
        }
    }

    #[test]
    fn lfs_mode_defaults_to_deny_and_only_known_modes_are_accepted() {
        assert_eq!(parsed("version = 1\n").lfs(), LfsMode::Deny);
        assert_eq!(parsed("version = 1\nlfs = \"deny\"\n").lfs(), LfsMode::Deny);
        assert_eq!(
            parsed("version = 1\nlfs = \"pointers\"\n").lfs(),
            LfsMode::Pointers
        );
        assert_eq!(parsed("version = 1\nlfs = \"full\"\n").lfs(), LfsMode::Full);
        for text in [
            "version = 1\nlfs = \"fetch\"\n",
            "version = 1\nlfs = true\n",
        ] {
            assert_eq!(code_of(text), ErrorCode::EPolicy, "{text:?}");
        }
    }

    #[test]
    fn an_unlisted_principal_is_forbidden_even_beside_listed_ones() {
        let policy = parsed(
            "version = 1\n[[principal]]\nname = \"unix:2000\"\n\n[[principal]]\nname = \
             \"windows:S-1-5-18\"\n",
        );
        assert!(policy.lookup(&other()).is_ok());
        assert!(
            policy
                .lookup(&Principal::from_verified_sid("S-1-5-18").expect("sid"))
                .is_ok()
        );
        for unlisted in [
            owner(),
            Principal::from_peer_uid(0),
            Principal::from_verified_sid("S-1-5-19").expect("sid"),
        ] {
            let error = policy.lookup(&unlisted).expect_err("unlisted");
            assert_eq!(error.code, ErrorCode::EForbidden);
            assert!(error.message.contains(&unlisted.to_string()));
        }
    }

    #[test]
    fn a_listed_principal_with_no_capabilities_has_a_valid_read_only_ceiling() {
        let policy = parsed(
            "version = 1\n[[principal]]\nname = \"unix:2000\"\n\n[[principal]]\nname = \
             \"unix:3000\"\ncapabilities = {}\n",
        );
        for who in [other(), Principal::from_peer_uid(3000)] {
            let entry = policy.lookup(&who).expect("listed");
            assert_eq!(entry.ceiling, Capabilities::default());
            assert!(entry.ceiling.write_changes.is_none());
            let read_only = Capabilities::negotiate(&entry.ceiling, None).expect("read-only");
            assert_eq!(read_only, Capabilities::default());
            assert!(read_only.require_write(WriteScope::Own).is_err());
        }
    }

    #[test]
    fn requests_beyond_the_ceiling_are_forbidden_not_truncated() {
        let policy = parsed(
            "version = 1\n[[principal]]\nname = \"unix:2000\"\ncapabilities = { write_changes = \
             \"own\", push_refs = [\"refs/heads/agent/**\"], land = [\"refs/heads/main\"], \
             claim_paths = [\"src/**\"], undo = \"session\", attest = [\"review\"], \
             read_intents = { provenance = true } }\n",
        );
        let ceiling = &policy.lookup(&other()).expect("listed").ceiling;
        let narrower = Capabilities {
            write_changes: Some(WriteScope::Own),
            push_refs: vec![ref_pattern("refs/heads/agent/x")],
            land: vec![ref_pattern("refs/heads/main")],
            claim_paths: vec![PathPattern::parse("src/lib").expect("path")],
            undo: Some(UndoScope::Session),
            attest: vec![AttestKind::new("review").expect("kind")],
            read_intents: ReadIntents {
                provenance: true,
                claims: false,
            },
        };
        assert_eq!(
            Capabilities::negotiate(ceiling, Some(&narrower)).expect("subset"),
            narrower
        );
        let excess: [(&str, Capabilities); 8] = [
            (
                "write scope",
                Capabilities {
                    write_changes: Some(WriteScope::Session),
                    ..narrower.clone()
                },
            ),
            (
                "push ref",
                Capabilities {
                    push_refs: vec![ref_pattern("refs/heads/other")],
                    ..narrower.clone()
                },
            ),
            (
                "push wider",
                Capabilities {
                    push_refs: vec![ref_pattern("refs/heads/**")],
                    ..narrower.clone()
                },
            ),
            (
                "land",
                Capabilities {
                    land: vec![ref_pattern("refs/heads/release")],
                    ..narrower.clone()
                },
            ),
            (
                "claim path",
                Capabilities {
                    claim_paths: vec![PathPattern::parse("docs/**").expect("path")],
                    ..narrower.clone()
                },
            ),
            (
                "undo",
                Capabilities {
                    undo: Some(UndoScope::All),
                    ..narrower.clone()
                },
            ),
            (
                "attest",
                Capabilities {
                    attest: vec![AttestKind::new("ci").expect("kind")],
                    ..narrower.clone()
                },
            ),
            (
                "private claims",
                Capabilities {
                    read_intents: ReadIntents {
                        provenance: true,
                        claims: true,
                    },
                    ..narrower.clone()
                },
            ),
        ];
        for (what, request) in excess {
            let error = Capabilities::negotiate(ceiling, Some(&request)).expect_err(what);
            assert_eq!(error.code, ErrorCode::EForbidden, "{what}");
        }
    }

    #[test]
    fn the_owner_alias_resolves_to_the_coordinators_principal_only() {
        let policy = parsed(&owner_grant("all"));
        assert_eq!(write_scope_of(&policy, &owner()), Some(WriteScope::All));
        assert!(
            policy.lookup(&other()).is_err(),
            "the alias is not a wildcard"
        );

        let windows_owner = Principal::from_verified_sid("S-1-5-21-1-2-3-1001").expect("sid");
        let policy =
            Policy::parse(owner_grant("own").as_bytes(), &windows_owner).expect("windows owner");
        assert_eq!(
            write_scope_of(&policy, &windows_owner),
            Some(WriteScope::Own)
        );
        assert!(policy.lookup(&owner()).is_err());
    }

    #[test]
    fn duplicate_principals_including_owner_alias_collisions_are_refused() {
        let entry = |name: &str| format!("[[principal]]\nname = \"{name}\"\n");
        for names in [
            vec!["unix:2000", "unix:2000"],
            vec!["owner", "owner"],
            vec!["owner", "unix:1000"],
            vec!["unix:1000", "owner"],
            vec!["windows:S-1-5-18", "unix:2000", "windows:S-1-5-18"],
        ] {
            let text = format!(
                "version = 1\n{}",
                names.iter().map(|name| entry(name)).collect::<String>()
            );
            assert_eq!(code_of(&text), ErrorCode::EPolicy, "{names:?}");
        }
        let windows_owner = Principal::from_verified_sid("S-1-5-18").expect("sid");
        let text = format!(
            "version = 1\n{}{}",
            entry("owner"),
            entry("windows:S-1-5-18")
        );
        assert_eq!(
            Policy::parse(text.as_bytes(), &windows_owner)
                .expect_err("alias collision")
                .code,
            ErrorCode::EPolicy
        );
        assert!(
            Policy::parse(
                format!("version = 1\n{}{}", entry("owner"), entry("unix:2000")).as_bytes(),
                &owner()
            )
            .is_ok()
        );
    }

    #[test]
    fn principal_names_must_be_canonical() {
        for name in [
            "Owner",
            "OWNER",
            " owner",
            "owner ",
            "",
            "unix:01000",
            "unix:+1000",
            "unix:-1",
            "unix:4294967296",
            "UNIX:1000",
            "windows:S-1-05-18",
            "windows:S-1-5",
            "windows:s-1-5-18",
            "root",
            "*",
        ] {
            let text = format!("version = 1\n[[principal]]\nname = {name:?}\n");
            assert_eq!(code_of(&text), ErrorCode::EPolicy, "{name:?}");
        }
        assert_eq!(
            code_of("version = 1\n[[principal]]\n"),
            ErrorCode::EPolicy,
            "name is required"
        );
        assert_eq!(
            code_of("version = 1\n[[principal]]\nname = 1000\n"),
            ErrorCode::EPolicy
        );
    }

    #[test]
    fn unknown_fields_are_refused_at_every_level() {
        for text in [
            "version = 1\nbogus = 1\n",
            "version = 1\n[bogus]\n",
            "version = 1\n[[principal]]\nname = \"owner\"\nallow_any = true\n",
            "version = 1\n[[principal]]\nname = \"owner\"\nattest = [\"review\"]\n",
            "version = 1\n[[principal]]\nname = \"owner\"\ncapabilities = { write_change = \"all\" }\n",
            "version = 1\n[[principal]]\nname = \"owner\"\ncapabilities = { extra = 1 }\n",
            "version = 1\n[[principal]]\nname = \"owner\"\ncapabilities = { read_intents = { provenence = true } }\n",
            "version = 1\n[[principal]]\nname = \"owner\"\nidentities = [{ name = \"A\", email = \"a@x\", role = \"r\" }]\n",
            "version = 1\n[[principal]]\nname = \"owner\"\nidentities = [{ name = \"A\" }]\n",
            "version = 1\n[[principal]]\nname = \"owner\"\nclaim_key = [\"a\"]\n",
        ] {
            assert_eq!(code_of(text), ErrorCode::EPolicy, "{text}");
        }
    }

    #[test]
    fn capability_key_lists_match_the_capability_types() {
        let capabilities = sonic_rs::to_string(&Capabilities::default()).expect("json");
        let fields: BTreeMap<String, sonic_rs::Value> =
            sonic_rs::from_str(&capabilities).expect("object");
        let mut have: Vec<&str> = fields.keys().map(String::as_str).collect();
        let mut want = CAPABILITY_KEYS.to_vec();
        have.sort_unstable();
        want.sort_unstable();
        assert_eq!(have, want, "update CAPABILITY_KEYS with Capabilities");

        let intents = sonic_rs::to_string(&ReadIntents::default()).expect("json");
        let fields: BTreeMap<String, sonic_rs::Value> =
            sonic_rs::from_str(&intents).expect("object");
        let mut have: Vec<&str> = fields.keys().map(String::as_str).collect();
        let mut want = READ_INTENT_KEYS.to_vec();
        have.sort_unstable();
        want.sort_unstable();
        assert_eq!(have, want, "update READ_INTENT_KEYS with ReadIntents");
    }

    #[test]
    fn every_capability_field_decodes_from_the_policy_form() {
        let policy = parsed(
            "version = 1\n[[principal]]\nname = \"owner\"\n[principal.capabilities]\nwrite_changes \
             = \"session\"\npush_refs = [\"refs/heads/**\", \"refs/tags/*\"]\nland = \
             [\"refs/heads/main\"]\nclaim_paths = [\"src/**\", \"docs\"]\nundo = \"all\"\nattest = \
             [\"review\", \"ci\"]\n[principal.capabilities.read_intents]\nprovenance = \
             true\nclaims = true\n",
        );
        let ceiling = &policy.lookup(&owner()).expect("owner").ceiling;
        assert_eq!(ceiling.write_changes, Some(WriteScope::Session));
        assert_eq!(ceiling.push_refs.len(), 2);
        assert_eq!(ceiling.land, vec![ref_pattern("refs/heads/main")]);
        assert_eq!(ceiling.claim_paths.len(), 2);
        assert_eq!(ceiling.undo, Some(UndoScope::All));
        assert_eq!(ceiling.attest.len(), 2);
        assert!(ceiling.read_intents.provenance && ceiling.read_intents.claims);
    }

    #[test]
    fn invalid_capability_values_are_policy_errors() {
        for body in [
            "write_changes = \"everything\"",
            "write_changes = 3",
            "push_refs = [\"heads/main\"]",
            "push_refs = [\"**\"]",
            "push_refs = \"refs/**\"",
            "land = [\"refs/he*ads/x\"]",
            "claim_paths = [\"a//b\"]",
            "undo = \"none\"",
            "attest = [\"\"]",
            "read_intents = true",
            "read_intents = { provenance = \"yes\" }",
        ] {
            let text = format!(
                "version = 1\n[[principal]]\nname = \"owner\"\ncapabilities = {{ {body} }}\n"
            );
            assert_eq!(code_of(&text), ErrorCode::EPolicy, "{body}");
        }
    }

    #[test]
    fn versions_other_than_one_are_policy_errors() {
        for text in [
            "",
            "# only a comment\n",
            "[[principal]]\nname = \"owner\"\n",
            "version = 0\n",
            "version = 2\n",
            "version = -1\n",
            "version = 1.0\n",
            "version = \"1\"\n",
            "version = true\n",
            "version = [1]\n",
            "version = 1\nversion = 1\n",
        ] {
            assert_eq!(code_of(text), ErrorCode::EPolicy, "{text:?}");
        }
        let error = Policy::parse(
            b"version = 2\nfuture_field = 1\n[[principal]]\nname = 3\n",
            &owner(),
        )
        .expect_err("future format");
        assert_eq!(error.code, ErrorCode::EPolicy);
        assert!(
            error.message.contains("version 2"),
            "a future file reports its version: {}",
            error.message
        );
    }

    #[test]
    fn malformed_toml_and_encodings_are_policy_errors() {
        for bytes in [
            &b"version = "[..],
            b"version = 1\n[[principal]\nname = \"owner\"\n",
            b"version = 1\n[[principal]]\nname = \"owner\n",
            b"version = 1\nname == 2\n",
            b"\xEF\xBB\xBFversion = 1\n",
            b"version = 1\n\xFF\n",
            b"\xFF\xFE",
            b"version = 1\n[[principal]]\nname = \"owner\"\nname = \"owner\"\n",
            b"version = 1\n[a]\n[a]\n",
        ] {
            let error = Policy::parse(bytes, &owner()).expect_err("malformed");
            assert_eq!(error.code, ErrorCode::EPolicy, "{bytes:?}");
        }
    }

    #[test]
    fn policy_errors_do_not_quote_the_source_or_grow_with_it() {
        let hostile = "x".repeat(10_000);
        let text = format!("version = 1\n[[principal]]\nname = \"{hostile}\"\n");
        let error = Policy::parse(text.as_bytes(), &owner()).expect_err("hostile name");
        assert_eq!(error.code, ErrorCode::EPolicy);
        assert!(error.message.len() < 1024, "{}", error.message.len());

        let text = format!("version = 1\n[[principal]]\nname = \"owner\"\n{hostile} = 1\n");
        let error = Policy::parse(text.as_bytes(), &owner()).expect_err("hostile key");
        assert!(error.message.len() < 1024, "{}", error.message.len());
        assert!(error.message.contains("line"), "{}", error.message);
    }

    // ----- session idle ---------------------------------------------------

    #[test]
    fn session_idle_is_a_positive_fixed_duration() {
        for (text, seconds) in [
            ("24h", 86_400),
            ("90m", 5_400),
            ("1h 30m", 5_400),
            ("45s", 45),
            ("PT2H", 7_200),
            ("PT90M", 5_400),
            ("1.5h", 5_400),
            ("1 hour 1 second", 3_601),
        ] {
            let policy = parsed(&format!("version = 1\nsession_idle = \"{text}\"\n"));
            assert_eq!(
                policy.session_idle(),
                SignedDuration::from_secs(seconds),
                "{text}"
            );
        }
        let sub_second = parsed("version = 1\nsession_idle = \"1500ms\"\n");
        assert_eq!(sub_second.session_idle(), SignedDuration::from_millis(1500));
        assert_eq!(
            parsed("version = 1\n").session_idle(),
            SignedDuration::from_hours(24)
        );
    }

    #[test]
    fn session_idle_refuses_calendar_units_overflow_and_non_positive_values() {
        for text in [
            "0s",
            "0h",
            "PT0S",
            "-1h",
            "-90m",
            "1d",
            "1 day",
            "24h 1d",
            "1w",
            "1 week",
            "1mo",
            "1 month",
            "1y",
            "1 year",
            "P1D",
            "P1W",
            "P1M",
            "P1Y",
            "PT1H1D",
            "9223372036854775807h",
            "9223372036854775807s 1h",
            "",
            " ",
            "24",
            "abc",
            "24 parsecs",
            "forever",
        ] {
            let policy = format!("version = 1\nsession_idle = {text:?}\n");
            assert_eq!(code_of(&policy), ErrorCode::EPolicy, "{text:?}");
        }
        for value in ["3600", "86400.0", "true", "[\"24h\"]", "{ hours = 24 }"] {
            let policy = format!("version = 1\nsession_idle = {value}\n");
            assert_eq!(code_of(&policy), ErrorCode::EPolicy, "{value}");
        }
    }

    // ----- identity and claim allowlists ----------------------------------

    #[test]
    fn identities_and_claim_keys_are_exact_allowlists() {
        let policy = parsed(
            "version = 1\n[[principal]]\nname = \"unix:2000\"\nidentities = [{ name = \"Ada\", \
             email = \"ada@example.test\" }, { name = \"Bot\", email = \"bot@example.test\" \
             }]\nclaim_keys = [\"tool\", \"model.name\"]\n",
        );
        let entry = policy.lookup(&other()).expect("listed");
        let ada = identity("Ada", "ada@example.test");
        let tool = claims(&[("tool", "anything at all")]);

        assert!(
            entry
                .admit_claims(None, &ProvenanceClaims::default())
                .is_ok()
        );
        assert!(entry.admit_claims(Some(&ada), &tool).is_ok());
        assert!(
            entry
                .admit_claims(
                    Some(&identity("Bot", "bot@example.test")),
                    &claims(&[("model.name", "")])
                )
                .is_ok()
        );

        for refused in [
            identity("Ada", "other@example.test"),
            identity("ada", "ada@example.test"),
            identity("Ada ", "ada@example.test"),
            identity("Ada", "ADA@example.test"),
            identity("Mallory", "ada@example.test"),
            identity("", ""),
        ] {
            let error = entry
                .admit_claims(Some(&refused), &ProvenanceClaims::default())
                .expect_err("identity");
            assert_eq!(error.code, ErrorCode::EForbidden, "{refused:?}");
        }
        // Grammar-invalid keys never reach the policy: construction rejects
        // them as E_INVALID before admit_claims can check the allowlist.
        let invalid = ProvenanceClaims::new(
            [("Tool".to_owned(), "x".to_owned())]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
        )
        .expect_err("uppercase key is not a claim");
        assert_eq!(invalid.code(), ErrorCode::EInvalid);
        for key in ["tools", "tool.x", "model", "extra"] {
            let error = entry
                .admit_claims(Some(&ada), &claims(&[("tool", "x"), (key, "x")]))
                .expect_err(key);
            assert_eq!(error.code, ErrorCode::EForbidden, "{key}");
            assert!(error.message.contains(key), "{}", error.message);
        }
    }

    #[test]
    fn by_default_no_identity_and_no_claim_key_is_allowed() {
        let policy = parsed("version = 1\n[[principal]]\nname = \"unix:2000\"\n");
        let entry = policy.lookup(&other()).expect("listed");
        assert!(
            entry
                .admit_claims(None, &ProvenanceClaims::default())
                .is_ok()
        );
        assert_eq!(
            entry
                .admit_claims(Some(&identity("A", "a@x")), &ProvenanceClaims::default())
                .expect_err("identity")
                .code,
            ErrorCode::EForbidden
        );
        assert_eq!(
            entry
                .admit_claims(None, &claims(&[("tool", "x")]))
                .expect_err("claim key")
                .code,
            ErrorCode::EForbidden
        );
    }

    #[test]
    fn the_allow_any_flags_are_independent() {
        let policy = parsed(
            "version = 1\n[[principal]]\nname = \"unix:2000\"\nallow_any_identity = \
             true\n\n[[principal]]\nname = \"unix:3000\"\nallow_any_claim_keys = true\n",
        );
        let any_identity = policy.lookup(&other()).expect("identity-open");
        let any_claims = policy
            .lookup(&Principal::from_peer_uid(3000))
            .expect("claims-open");
        let someone = identity("Someone", "s@example.test");
        let tagged = claims(&[("anything", "x"), ("goes", "y")]);

        assert!(
            any_identity
                .admit_claims(Some(&someone), &ProvenanceClaims::default())
                .is_ok()
        );
        assert!(any_identity.admit_claims(None, &tagged).is_err());
        assert!(any_claims.admit_claims(None, &tagged).is_ok());
        assert!(
            any_claims
                .admit_claims(Some(&someone), &ProvenanceClaims::default())
                .is_err()
        );
    }

    #[test]
    fn an_allowlist_never_widens_through_another_principal() {
        let policy = parsed(
            "version = 1\n[[principal]]\nname = \"unix:2000\"\nidentities = [{ name = \"Ada\", \
             email = \"a@x\" }]\nclaim_keys = [\"tool\"]\n\n[[principal]]\nname = \
             \"unix:3000\"\n",
        );
        let ada = identity("Ada", "a@x");
        let tool = claims(&[("tool", "x")]);
        let granted = policy.lookup(&other()).expect("granted");
        assert!(granted.admit_claims(Some(&ada), &tool).is_ok());
        let bare = policy
            .lookup(&Principal::from_peer_uid(3000))
            .expect("bare");
        assert!(
            bare.admit_claims(Some(&ada), &ProvenanceClaims::default())
                .is_err()
        );
        assert!(bare.admit_claims(None, &tool).is_err());
    }

    #[test]
    fn unusable_identities_and_claim_keys_in_the_file_are_policy_errors() {
        for body in [
            "identities = [{ name = \"\", email = \"a@x\" }]",
            "identities = [{ name = \"a\", email = \"\" }]",
            "identities = [{ name = \"a\\nb\", email = \"a@x\" }]",
            "identities = [{ name = \"a<b\", email = \"a@x\" }]",
            "identities = [{ name = \"a\", email = \"a@x>\" }]",
            "identities = [{ name = \"a\", email = \"a\\u0000@x\" }]",
            "identities = [\"Ada <a@x>\"]",
            "identities = \"Ada\"",
            "claim_keys = [\"\"]",
            "claim_keys = [\"Tool\"]",
            "claim_keys = [\"has space\"]",
            "claim_keys = [\"tool\\n\"]",
            "claim_keys = [1]",
            "claim_keys = \"tool\"",
            "allow_any_identity = \"yes\"",
            "allow_any_claim_keys = 1",
        ] {
            let text = format!("version = 1\n[[principal]]\nname = \"owner\"\n{body}\n");
            assert_eq!(code_of(&text), ErrorCode::EPolicy, "{body}");
        }
        let too_long = "k".repeat(65);
        let text = format!(
            "version = 1\n[[principal]]\nname = \"owner\"\nclaim_keys = [\"{too_long}\"]\n"
        );
        assert_eq!(code_of(&text), ErrorCode::EPolicy);
    }

    // ----- policy source --------------------------------------------------

    #[test]
    fn a_missing_file_selects_the_owner_only_default() {
        let dir = TempDir::new("missing");
        let source = PolicySource::open(&dir.0, owner());
        let policy = source.load().expect("default");
        assert_eq!(policy.session_idle(), SignedDuration::from_hours(24));
        assert_eq!(
            policy.lookup(&other()).expect_err("not the owner").code,
            ErrorCode::EForbidden
        );
        assert!(
            policy
                .lookup(&Principal::from_verified_sid("S-1-5-18").expect("sid"))
                .is_err()
        );

        let entry = policy.lookup(&owner()).expect("owner");
        let everything = Capabilities {
            write_changes: Some(WriteScope::All),
            push_refs: vec![ref_pattern("refs/heads/*"), ref_pattern("refs/tags/**")],
            land: vec![ref_pattern("refs/heads/main")],
            claim_paths: vec![PathPattern::parse("src/**").expect("path")],
            undo: Some(UndoScope::All),
            attest: Vec::new(),
            read_intents: ReadIntents {
                provenance: true,
                claims: true,
            },
        };
        assert_eq!(
            Capabilities::negotiate(&entry.ceiling, Some(&everything)).expect("full ceiling"),
            everything
        );
        assert_eq!(
            Capabilities::negotiate(&entry.ceiling, None).expect("whole ceiling"),
            entry.ceiling
        );
        let attested = Capabilities {
            attest: vec![AttestKind::new("review").expect("kind")],
            ..Capabilities::default()
        };
        assert_eq!(
            Capabilities::negotiate(&entry.ceiling, Some(&attested))
                .expect_err("no attestation kinds by default")
                .code,
            ErrorCode::EForbidden
        );
        assert!(
            entry
                .admit_claims(Some(&identity("Anyone", "a@x")), &claims(&[("any", "key")]))
                .is_ok()
        );
    }

    #[test]
    fn an_existing_file_is_authoritative_and_may_be_read_only() {
        let dir = TempDir::new("authoritative");
        let source = PolicySource::open(&dir.0, owner());
        std::fs::write(
            dir.policy(),
            "version = 1\n[[principal]]\nname = \"unix:2000\"\n",
        )
        .expect("write");
        let policy = source.load().expect("valid");
        assert_eq!(
            policy.lookup(&owner()).expect_err("owner not added").code,
            ErrorCode::EForbidden
        );
        assert_eq!(
            policy.lookup(&other()).expect("listed").ceiling,
            Capabilities::default()
        );

        std::fs::write(
            dir.policy(),
            "version = 1\n[[principal]]\nname = \"owner\"\ncapabilities = {}\n",
        )
        .expect("write");
        let read_only = source.load().expect("a read-only owner is valid");
        assert_eq!(
            read_only.lookup(&owner()).expect("listed").ceiling,
            Capabilities::default()
        );
    }

    #[test]
    fn malformed_files_fail_closed_and_recover_when_fixed() {
        let dir = TempDir::new("malformed");
        let source = PolicySource::open(&dir.0, owner());
        for bad in [
            &b"not toml ["[..],
            b"",
            b"version = 2\n",
            b"version = 1\nunknown = 1\n",
            b"\xFF\xFE\x00",
        ] {
            std::fs::write(dir.policy(), bad).expect("write");
            let error = source
                .load()
                .expect_err("must not fall back to the default");
            assert_eq!(error.code, ErrorCode::EPolicy, "{bad:?}");
            let again = source.load().expect_err("stays failed");
            assert_eq!(again, error, "a cached failure is the same failure");
        }
        std::fs::write(dir.policy(), owner_grant("own")).expect("write");
        let fixed = source.load().expect("fixed");
        assert_eq!(write_scope_of(&fixed, &owner()), Some(WriteScope::Own));
    }

    #[test]
    fn a_broken_file_replaces_a_cached_good_policy() {
        let dir = TempDir::new("broken-after-good");
        let source = PolicySource::open(&dir.0, owner());
        std::fs::write(dir.policy(), owner_grant("all")).expect("write");
        source.load().expect("good");
        std::fs::write(dir.policy(), "version = 1\n[[principal]\n").expect("write");
        assert_eq!(source.load().expect_err("revoked").code, ErrorCode::EPolicy);
    }

    #[test]
    fn same_length_same_mtime_edits_take_effect() {
        let dir = TempDir::new("same-mtime");
        let source = PolicySource::open(&dir.0, owner());
        let narrow = owner_grant("own");
        let wide = owner_grant("all");
        assert_eq!(narrow.len(), wide.len(), "the edit must keep the length");

        std::fs::write(dir.policy(), &narrow).expect("write");
        let stamped = std::fs::metadata(dir.policy())
            .expect("metadata")
            .modified()
            .expect("mtime");
        let first = source.load().expect("narrow");
        assert_eq!(write_scope_of(&first, &owner()), Some(WriteScope::Own));

        std::fs::write(dir.policy(), &wide).expect("write");
        let file = OpenOptions::new()
            .write(true)
            .open(dir.policy())
            .expect("reopen to restore the timestamp");
        file.set_modified(stamped).expect("restore mtime");
        drop(file);
        let after = std::fs::metadata(dir.policy()).expect("metadata");
        assert_eq!(after.len(), u64::try_from(narrow.len()).expect("len"));
        assert_eq!(
            after.modified().expect("mtime"),
            stamped,
            "test precondition"
        );

        let second = source.load().expect("wide");
        assert_eq!(write_scope_of(&second, &owner()), Some(WriteScope::All));

        std::fs::write(dir.policy(), &narrow).expect("write");
        let file = OpenOptions::new()
            .write(true)
            .open(dir.policy())
            .expect("reopen");
        file.set_modified(stamped).expect("restore mtime");
        drop(file);
        let third = source.load().expect("narrow again");
        assert_eq!(
            write_scope_of(&third, &owner()),
            Some(WriteScope::Own),
            "revocation must not depend on metadata"
        );
    }

    #[test]
    fn unchanged_bytes_reuse_the_parse_and_changed_bytes_do_not() {
        let dir = TempDir::new("cache");
        let source = PolicySource::open(&dir.0, owner());
        std::fs::write(dir.policy(), owner_grant("own")).expect("write");
        let first = source.load().expect("first");
        let second = source.load().expect("second");
        assert!(
            Arc::ptr_eq(&first, &second),
            "an unchanged file reparses nothing"
        );

        std::fs::write(dir.policy(), owner_grant("all")).expect("write");
        let third = source.load().expect("third");
        assert!(!Arc::ptr_eq(&first, &third));
        assert_eq!(write_scope_of(&first, &owner()), Some(WriteScope::Own));
        assert_eq!(write_scope_of(&third, &owner()), Some(WriteScope::All));
    }

    #[test]
    fn a_narrowed_policy_revokes_the_next_authorization() {
        let dir = TempDir::new("revocation");
        let source = PolicySource::open(&dir.0, owner());
        std::fs::write(
            dir.policy(),
            "version = 1\n[[principal]]\nname = \"owner\"\ncapabilities = { write_changes = \
             \"all\", push_refs = [\"refs/heads/**\"] }\n",
        )
        .expect("write");
        let before = source.load().expect("granted");
        let session =
            Capabilities::negotiate(&before.lookup(&owner()).expect("listed").ceiling, None)
                .expect("session capabilities");
        assert!(session.require_write(WriteScope::All).is_ok());

        std::fs::write(
            dir.policy(),
            "version = 1\n[[principal]]\nname = \"owner\"\ncapabilities = { write_changes = \
             \"own\" }\n",
        )
        .expect("write");
        let after = source.load().expect("narrowed");
        let error = session
            .check_within(&after.lookup(&owner()).expect("listed").ceiling)
            .expect_err("the session now exceeds the policy");
        assert_eq!(error.code, ErrorCode::EForbidden);

        std::fs::write(
            dir.policy(),
            "version = 1\n[[principal]]\nname = \"unix:2000\"\n",
        )
        .expect("write");
        let removed = source.load().expect("owner removed");
        assert_eq!(
            removed.lookup(&owner()).expect_err("removed").code,
            ErrorCode::EForbidden
        );
    }

    #[test]
    fn deleting_the_file_returns_to_the_default() {
        let dir = TempDir::new("deleted");
        let source = PolicySource::open(&dir.0, owner());
        std::fs::write(dir.policy(), "version = 1\n").expect("write");
        assert!(source.load().expect("empty").lookup(&owner()).is_err());
        std::fs::remove_file(dir.policy()).expect("remove");
        assert!(source.load().expect("default").lookup(&owner()).is_ok());
    }

    #[test]
    fn the_size_cap_is_exact() {
        let dir = TempDir::new("cap");
        let source = PolicySource::open(&dir.0, owner());

        let at_cap = padded_policy(MAX_CONTROL_FRAME_BYTES);
        std::fs::write(dir.policy(), &at_cap).expect("write");
        let policy = source.load().expect("a file of exactly the cap is read");
        assert!(policy.lookup(&owner()).is_err());

        let over = padded_policy(MAX_CONTROL_FRAME_BYTES + 1);
        std::fs::write(dir.policy(), &over).expect("write");
        let error = source.load().expect_err("one byte over the cap");
        assert_eq!(error.code, ErrorCode::EPolicy);
        assert!(error.message.contains("limit"), "{}", error.message);

        let far_over = padded_policy(MAX_CONTROL_FRAME_BYTES * 2);
        std::fs::write(dir.policy(), &far_over).expect("write");
        assert_eq!(
            source.load().expect_err("far over").code,
            ErrorCode::EPolicy
        );
    }

    /// A policy of exactly `total` bytes: the version line, then comment
    /// lines of at most 1024 bytes.
    fn padded_policy(total: usize) -> Vec<u8> {
        let header = b"version = 1\n";
        let mut bytes = vec![b'#'; total];
        bytes[..header.len()].copy_from_slice(header);
        for index in (header.len()..total).filter(|index| index % 1024 == 1023) {
            bytes[index] = b'\n';
        }
        bytes
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_file_is_an_io_error_never_the_default() {
        let dir = TempDir::new("unreadable");
        let source = PolicySource::open(&dir.0, owner());
        std::os::unix::fs::symlink(POLICY_FILE_NAME, dir.policy()).expect("self link");
        let error = source.load().expect_err("a symlink loop cannot be read");
        assert_eq!(error.code, ErrorCode::EIo, "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_file_revokes_a_cached_good_policy() {
        let dir = TempDir::new("unreadable-after-good");
        let source = PolicySource::open(&dir.0, owner());
        std::fs::write(dir.policy(), owner_grant("all")).expect("write");
        source.load().expect("good");
        std::fs::remove_file(dir.policy()).expect("remove");
        std::os::unix::fs::symlink(POLICY_FILE_NAME, dir.policy()).expect("self link");
        assert_eq!(source.load().expect_err("unreadable").code, ErrorCode::EIo);
    }

    #[cfg(unix)]
    #[test]
    fn a_non_regular_file_is_a_policy_error_and_never_blocks() {
        let dir = TempDir::new("special");
        let source = PolicySource::open(&dir.0, owner());
        std::fs::create_dir(dir.policy()).expect("directory");
        assert_eq!(
            source.load().expect_err("directory").code,
            ErrorCode::EPolicy
        );
        std::fs::remove_dir(dir.policy()).expect("remove");

        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.policy(),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .expect("fifo");
        assert_eq!(source.load().expect_err("fifo").code, ErrorCode::EPolicy);
    }

    #[cfg(unix)]
    #[test]
    fn a_permission_failure_is_an_io_error_when_the_user_cannot_bypass_it() {
        use std::os::unix::fs::PermissionsExt as _;

        if rustix::process::geteuid().is_root() {
            return;
        }
        let dir = TempDir::new("denied");
        let source = PolicySource::open(&dir.0, owner());
        std::fs::write(dir.policy(), owner_grant("all")).expect("write");
        std::fs::set_permissions(dir.policy(), std::fs::Permissions::from_mode(0o000))
            .expect("chmod");
        let error = source.load().expect_err("denied");
        assert_eq!(error.code, ErrorCode::EIo, "{error}");
    }

    #[test]
    fn the_default_and_parsed_owner_follow_the_credential_spelling() {
        let dir = TempDir::new("windows-owner");
        let windows_owner = Principal::from_verified_sid("S-1-5-21-10-20-30-1001").expect("sid");
        let source = PolicySource::open(&dir.0, windows_owner.clone());
        assert!(
            source
                .load()
                .expect("default")
                .lookup(&windows_owner)
                .is_ok()
        );
        assert!(source.load().expect("default").lookup(&owner()).is_err());

        std::fs::write(
            dir.policy(),
            "version = 1\n[[principal]]\nname = \"windows:S-1-5-21-10-20-30-1001\"\ncapabilities = \
             { write_changes = \"own\" }\n",
        )
        .expect("write");
        let policy = source.load().expect("spelled");
        assert_eq!(
            write_scope_of(&policy, &windows_owner),
            Some(WriteScope::Own)
        );
    }
}
