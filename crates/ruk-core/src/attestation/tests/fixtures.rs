//! Shared fixtures for the attestation tests.
//!
//! Provenance. Test keys come from fixed 32-byte seeds expanded by
//! `ssh_key::private::Ed25519Keypair::from_seed` (RFC 8032 key expansion). Every
//! statement is signed by `ssh_key::PrivateKey::sign` over the exact canonical
//! payload, so each signature is a real Ed25519 signature made by a library, not a
//! canned byte string. The hand-assembled SSHSIG blobs follow the field order of
//! OpenSSH's PROTOCOL.sshsig. A blob is used only where one field must differ from
//! what the library emits, and the verifier under test must accept the control blob
//! before any variant counts. Expected signer fingerprints are recomputed here as
//! base64 of SHA-256 over the wire public-key blob, independently of ssh-key's own
//! fingerprint code.

use std::path::PathBuf;
use std::sync::Arc;

use ssh_key::private::Ed25519Keypair;
use ssh_key::{HashAlg, LineEnding, PrivateKey};

use crate::attestation::{ATTEST_NAMESPACE, PreparedAttestations, Progress, verify_statement};
use crate::capability::{AttestKind, AttestResult};
use crate::error::CoreError;
use crate::ids::{HashKind, Oid};
use crate::protocol::{
    AttestAddArgs, AttestSignature, AttestStatement, StatementDigest, Timestamp,
};
use crate::store::{ObjectKind, PreparationBudget, Store};

/// A store under a unique temporary root, removed when dropped.
pub(super) struct TempStore {
    dir: PathBuf,
    pub(super) store: Store,
}

impl TempStore {
    pub(super) fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ruk-attest-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let store = Store::create(
            &dir.join("store"),
            HashKind::Sha1,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("create store");
        Self { dir, store }
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Publishes a commit-kind object with `body` and returns its identity.
pub(super) fn publish_commit(store: &Store, body: &[u8]) -> Oid {
    publish_object(store, ObjectKind::Commit, body)
}

/// Publishes a blob-kind object with `body` and returns its identity.
pub(super) fn publish_blob(store: &Store, body: &[u8]) -> Oid {
    publish_object(store, ObjectKind::Blob, body)
}

fn publish_object(store: &Store, kind: ObjectKind, body: &[u8]) -> Oid {
    let length = u64::try_from(body.len()).expect("object length");
    let prepared = store
        .prepare(kind, length, body, None)
        .expect("prepare object");
    let oid = prepared.oid();
    store.publish(vec![prepared], &[]).expect("publish object");
    oid
}

/// Publishes a prepared attestation batch. An empty batch publishes nothing.
pub(super) fn apply(store: &Store, prepared: &PreparedAttestations) {
    if !prepared.mutations.is_empty() {
        store
            .publish(Vec::new(), &prepared.mutations)
            .expect("publish attestation rows");
    }
}

/// A checkpoint that never refuses.
pub(super) fn open(_progress: Progress) -> Result<(), CoreError> {
    Ok(())
}

/// The deterministic Ed25519 key for `seed`.
pub(super) fn key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

/// The raw Ed25519 public key bytes of `key`.
pub(super) fn public_bytes(key: &PrivateKey) -> [u8; 32] {
    key.public_key()
        .key_data()
        .ed25519()
        .expect("ed25519 key")
        .0
}

pub(super) fn kind(text: &str) -> AttestKind {
    AttestKind::new(text).expect("kind")
}

pub(super) fn result(text: &str) -> AttestResult {
    AttestResult::new(text).expect("result")
}

/// An object id of the test repository's width, 20 bytes filled with `byte`.
pub(super) fn oid(byte: u8) -> Oid {
    Oid::from_bytes(&[byte; 20]).expect("oid")
}

pub(super) fn statement(
    subject: Oid,
    kind_text: &str,
    result_text: &str,
    signed_at: &str,
    supersedes: Option<StatementDigest>,
) -> AttestStatement {
    AttestStatement {
        subject,
        kind: kind(kind_text),
        result: result(result_text),
        signed_at: Timestamp::parse(signed_at).expect("timestamp"),
        supersedes,
    }
}

/// Signs `statement` with the SHA-1 repository format and `ssh-keygen`-style
/// defaults: namespace `ruk-attest`, SHA-256 hash.
pub(super) fn sign(key: &PrivateKey, statement: AttestStatement) -> AttestAddArgs {
    sign_for(
        HashKind::Sha1,
        key,
        statement,
        ATTEST_NAMESPACE,
        HashAlg::Sha256,
    )
}

/// Signs the canonical payload of `statement` for `format`, in `namespace`,
/// with `hash`.
pub(super) fn sign_for(
    format: HashKind,
    key: &PrivateKey,
    statement: AttestStatement,
    namespace: &str,
    hash: HashAlg,
) -> AttestAddArgs {
    let payload = statement
        .canonical_payload_v1(format)
        .expect("canonical payload");
    let signature = key.sign(namespace, hash, &payload).expect("sign");
    let armor = signature.to_pem(LineEnding::LF).expect("armor");
    AttestAddArgs {
        statement,
        signature: AttestSignature::new(armor).expect("armored signature"),
    }
}

/// The digest a verified statement is stored under.
pub(super) fn digest_of(args: &AttestAddArgs) -> StatementDigest {
    verify_statement(HashKind::Sha1, args)
        .expect("genuine statement verifies")
        .digest()
}

/// The `SHA256:` fingerprint of `public`, computed independently of ssh-key.
pub(super) fn independent_fingerprint(public: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&Sha256::digest(ed25519_key_blob(public)));
    format!("SHA256:{}", base64(&digest).trim_end_matches('='))
}

/// Appends an SSH `string` (u32 big-endian length, then the bytes).
pub(super) fn ssh_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).expect("ssh string length");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The wire public-key blob of an Ed25519 key.
pub(super) fn ed25519_key_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ssh-ed25519");
    ssh_string(&mut blob, public);
    blob
}

/// The wire signature blob with an algorithm name and raw signature bytes.
pub(super) fn named_signature_blob(algorithm: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    ssh_string(&mut blob, algorithm);
    ssh_string(&mut blob, signature);
    blob
}

/// The wire blob of an RSA public key with a syntactically valid exponent and
/// modulus. Only the key type matters: the policy must refuse it.
pub(super) fn rsa_key_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ssh-rsa");
    ssh_string(&mut blob, &[0x01, 0x00, 0x01]);
    ssh_string(&mut blob, &[0x7f; 256]);
    blob
}

/// The wire blob of an ECDSA P-256 public key whose point is all zeros. Only the
/// key type matters here: the policy must refuse the key before any point check.
pub(super) fn ecdsa_key_blob() -> Vec<u8> {
    let mut point = vec![0x04];
    point.extend_from_slice(&[0_u8; 64]);
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ecdsa-sha2-nistp256");
    ssh_string(&mut blob, b"nistp256");
    ssh_string(&mut blob, &point);
    blob
}

/// The wire blob of a FIDO/U2F Ed25519 public key for the `ssh:` application.
pub(super) fn sk_ed25519_key_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"sk-ssh-ed25519@openssh.com");
    ssh_string(&mut blob, public);
    ssh_string(&mut blob, b"ssh:");
    blob
}

/// The fields of one hand-assembled SSHSIG.
pub(super) struct SshSigParts<'a> {
    pub(super) version: u32,
    pub(super) public_key: &'a [u8],
    pub(super) namespace: &'a [u8],
    pub(super) reserved: &'a [u8],
    pub(super) hash: &'a [u8],
    pub(super) signature: &'a [u8],
}

/// The binary SSHSIG layout: magic, version, public key, namespace, reserved,
/// hash algorithm, and signature.
pub(super) fn sshsig_binary(parts: &SshSigParts<'_>) -> Vec<u8> {
    let mut out = b"SSHSIG".to_vec();
    out.extend_from_slice(&parts.version.to_be_bytes());
    ssh_string(&mut out, parts.public_key);
    ssh_string(&mut out, parts.namespace);
    ssh_string(&mut out, parts.reserved);
    ssh_string(&mut out, parts.hash);
    ssh_string(&mut out, parts.signature);
    out
}

/// PEM armor of a binary SSHSIG, with 70-column lines as ssh-key emits them.
pub(super) fn armor(binary: &[u8]) -> AttestSignature {
    let encoded = base64(binary);
    let mut text = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for line in encoded.as_bytes().chunks(70) {
        text.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        text.push('\n');
    }
    text.push_str("-----END SSH SIGNATURE-----\n");
    AttestSignature::new(text).expect("armored signature")
}

/// Standard base64 with padding.
pub(super) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = usize::from(chunk[0]);
        let b1 = usize::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = usize::from(chunk.get(2).copied().unwrap_or(0));
        out.push(char::from(ALPHABET[b0 >> 2]));
        out.push(char::from(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)]));
        if chunk.len() > 1 {
            out.push(char::from(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)]));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[b2 & 0x3f]));
        } else {
            out.push('=');
        }
    }
    out
}
