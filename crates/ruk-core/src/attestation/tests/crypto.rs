//! Adversarial signature tests against the real verifier. Signatures are produced by
//! ssh-key's Ed25519 signing, or assembled as SSHSIG bytes and checked by ssh-key's
//! parser. No verification path is mocked.

use sha2::{Digest, Sha256};
use ssh_key::{HashAlg, LineEnding, PrivateKey, SshSig};

use crate::attestation::{ATTEST_NAMESPACE, verify_statement};
use crate::error::ErrorCode;
use crate::ids::{HashKind, Oid};
use crate::protocol::{
    AttestAddArgs, AttestSignature, AttestStatement, StatementDigest, Timestamp,
};

use super::fixtures::{
    SshSigParts, armor, ecdsa_key_blob, ed25519_key_blob, evidenced, independent_fingerprint, key,
    kind, named_signature_blob, oid, public_bytes, result, rsa_key_blob, sign, sign_for, sign_v1,
    sk_ed25519_key_blob, sshsig_binary, statement,
};

const SIGNED_AT: &str = "2026-10-17T12:00:00Z";

fn subject() -> Oid {
    oid(7)
}

fn review_pass() -> AttestStatement {
    statement(subject(), "review", "pass", SIGNED_AT, None)
}

/// The canonical payload the verifier reconstructs for `statement`: the v2
/// payload new signatures cover.
fn payload_of(statement: &AttestStatement) -> Vec<u8> {
    statement
        .canonical_payload_v2(HashKind::Sha1)
        .expect("canonical payload")
}

fn refusal(args: &AttestAddArgs) -> ErrorCode {
    verify_statement(HashKind::Sha1, args)
        .expect_err("the verifier must refuse this input")
        .code
}

/// The embedded key blob and the signature blob of a genuine library signature over
/// `statement`'s payload, so a variant changes exactly one field.
fn genuine_blobs(signer: &PrivateKey, statement: &AttestStatement) -> (Vec<u8>, Vec<u8>) {
    let signature = signer
        .sign(ATTEST_NAMESPACE, HashAlg::Sha256, &payload_of(statement))
        .expect("sign");
    let key_blob = ed25519_key_blob(&public_bytes(signer));
    let signature_blob = named_signature_blob(b"ssh-ed25519", signature.signature_bytes());
    (key_blob, signature_blob)
}

/// Assembles an SSHSIG with every field explicit and armors it.
fn assemble(
    statement: &AttestStatement,
    key_blob: &[u8],
    signature_blob: &[u8],
    version: u32,
    namespace: &[u8],
    reserved: &[u8],
    hash: &[u8],
) -> AttestAddArgs {
    let binary = sshsig_binary(&SshSigParts {
        version,
        public_key: key_blob,
        namespace,
        reserved,
        hash,
        signature: signature_blob,
    });
    AttestAddArgs {
        statement: statement.clone(),
        signature: armor(&binary),
    }
}

/// The control assembly: every field genuine, so only the variant under test differs.
fn assemble_control(
    signer: &PrivateKey,
    statement: &AttestStatement,
    version: u32,
    namespace: &[u8],
    reserved: &[u8],
    hash: &[u8],
) -> AttestAddArgs {
    let (key_blob, signature_blob) = genuine_blobs(signer, statement);
    assemble(
        statement,
        &key_blob,
        &signature_blob,
        version,
        namespace,
        reserved,
        hash,
    )
}

#[test]
fn library_signature_verifies_and_signer_is_the_independent_sha256_of_the_embedded_key() {
    let signer = key(0x11);
    let args = sign(&signer, review_pass());
    let verified = verify_statement(HashKind::Sha1, &args).expect("genuine signature verifies");

    let expected = independent_fingerprint(&public_bytes(&signer));
    assert_eq!(verified.signer().as_str(), expected.as_str());

    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&Sha256::digest(payload_of(&args.statement)));
    assert_eq!(verified.digest().as_bytes(), &digest);
    assert_eq!(verified.signature(), &args.signature);
    assert_eq!(verified.to_args(), args);
}

#[test]
fn a_sha512_signature_is_accepted_under_the_same_policy() {
    let signer = key(0x11);
    let sha256 = sign(&signer, review_pass());
    let sha512 = sign_for(
        HashKind::Sha1,
        &signer,
        review_pass(),
        ATTEST_NAMESPACE,
        HashAlg::Sha512,
    );
    let first = verify_statement(HashKind::Sha1, &sha256).expect("sha256 verifies");
    let second = verify_statement(HashKind::Sha1, &sha512).expect("sha512 verifies");
    assert_eq!(first.signer(), second.signer());
    assert_eq!(first.digest(), second.digest());
}

#[test]
fn a_hand_assembled_control_blob_verifies_so_the_fixture_encoder_is_trustworthy() {
    let signer = key(0x11);
    let control = assemble_control(
        &signer,
        &review_pass(),
        1,
        ATTEST_NAMESPACE.as_bytes(),
        b"",
        b"sha256",
    );
    verify_statement(HashKind::Sha1, &control).expect("control blob verifies");
}

#[test]
fn any_tampered_payload_field_invalidates_the_signature() {
    let signer = key(0x11);
    let original = review_pass();
    let signed = sign(&signer, original.clone());
    let variants = [
        AttestStatement {
            result: result("fail"),
            ..original.clone()
        },
        AttestStatement {
            kind: kind("ci"),
            ..original.clone()
        },
        AttestStatement {
            subject: oid(8),
            ..original.clone()
        },
        AttestStatement {
            signed_at: Timestamp::parse("2026-10-17T12:00:01Z").expect("timestamp"),
            ..original.clone()
        },
        AttestStatement {
            supersedes: Some(StatementDigest::from_bytes([3; 32])),
            ..original.clone()
        },
        AttestStatement {
            evidence: Some(StatementDigest::from_bytes([5; 32])),
            ..original
        },
    ];
    for statement in variants {
        let tampered = AttestAddArgs {
            statement,
            signature: signed.signature.clone(),
        };
        assert_eq!(refusal(&tampered), ErrorCode::EInvalid);
    }
}

#[test]
fn a_substituted_embedded_key_is_refused_even_though_the_signature_is_genuine() {
    let signer = key(0x11);
    let other = key(0x22);
    let statement = review_pass();
    let genuine = signer
        .sign(ATTEST_NAMESPACE, HashAlg::Sha256, &payload_of(&statement))
        .expect("sign");
    let swapped = SshSig::new(
        other.public_key().key_data().clone(),
        ATTEST_NAMESPACE,
        HashAlg::Sha256,
        genuine.signature().clone(),
    )
    .expect("swapped sshsig");
    let args = AttestAddArgs {
        statement,
        signature: AttestSignature::new(swapped.to_pem(LineEnding::LF).expect("armor"))
            .expect("armored text"),
    };
    assert_eq!(refusal(&args), ErrorCode::EInvalid);
}

#[test]
fn a_namespace_other_than_ruk_attest_is_a_policy_refusal() {
    let signer = key(0x11);
    for namespace in ["git", "file"] {
        let args = sign_for(
            HashKind::Sha1,
            &signer,
            review_pass(),
            namespace,
            HashAlg::Sha256,
        );
        assert_eq!(refusal(&args), ErrorCode::EPolicy, "namespace {namespace}");
    }
}

#[test]
fn non_ed25519_key_types_are_policy_refusals() {
    let signer = key(0x11);
    let statement = review_pass();
    let (_, signature_blob) = genuine_blobs(&signer, &statement);
    let public = public_bytes(&signer);
    for key_blob in [
        rsa_key_blob(),
        ecdsa_key_blob(),
        sk_ed25519_key_blob(&public),
    ] {
        let args = assemble(
            &statement,
            &key_blob,
            &signature_blob,
            1,
            ATTEST_NAMESPACE.as_bytes(),
            b"",
            b"sha256",
        );
        assert_eq!(refusal(&args), ErrorCode::EPolicy);
    }
}

#[test]
fn a_non_ed25519_signature_algorithm_is_a_policy_refusal() {
    let signer = key(0x11);
    let statement = review_pass();
    let (key_blob, signature_blob) = genuine_blobs(&signer, &statement);
    // The raw Ed25519 signature is the final 64 bytes of the blob.
    let raw = &signature_blob[signature_blob.len() - 64..];
    let rsa_named = named_signature_blob(b"rsa-sha2-256", raw);
    let args = assemble(
        &statement,
        &key_blob,
        &rsa_named,
        1,
        ATTEST_NAMESPACE.as_bytes(),
        b"",
        b"sha256",
    );
    assert_eq!(refusal(&args), ErrorCode::EPolicy);
}

#[test]
fn non_empty_reserved_bytes_are_refused_before_the_signature_is_checked() {
    let signer = key(0x11);
    let args = assemble_control(
        &signer,
        &review_pass(),
        1,
        ATTEST_NAMESPACE.as_bytes(),
        b"future-extension",
        b"sha256",
    );
    assert_eq!(refusal(&args), ErrorCode::EPolicy);
}

#[test]
fn an_empty_namespace_is_a_policy_refusal() {
    let signer = key(0x11);
    let args = assemble_control(&signer, &review_pass(), 1, b"", b"", b"sha256");
    assert_eq!(refusal(&args), ErrorCode::EPolicy);
}

#[test]
fn a_hash_algorithm_outside_sha256_and_sha512_is_invalid_encoding() {
    let signer = key(0x11);
    let args = assemble_control(
        &signer,
        &review_pass(),
        1,
        ATTEST_NAMESPACE.as_bytes(),
        b"",
        b"sha1",
    );
    assert_eq!(refusal(&args), ErrorCode::EInvalid);
}

#[test]
fn a_future_sshsig_version_is_a_version_refusal() {
    let signer = key(0x11);
    let args = assemble_control(
        &signer,
        &review_pass(),
        2,
        ATTEST_NAMESPACE.as_bytes(),
        b"",
        b"sha256",
    );
    assert_eq!(refusal(&args), ErrorCode::EVersion);
}

#[test]
fn malformed_armor_is_invalid() {
    let args = AttestAddArgs {
        statement: review_pass(),
        signature: AttestSignature::new(
            "-----BEGIN SSH SIGNATURE-----\n@@@@ not base64 @@@@\n-----END SSH SIGNATURE-----\n",
        )
        .expect("bounded text"),
    };
    assert_eq!(refusal(&args), ErrorCode::EInvalid);
}

#[test]
fn a_subject_of_the_wrong_width_is_an_object_format_refusal() {
    let signer = key(0x11);
    let wide = Oid::from_bytes(&[0x44; 32]).expect("oid");
    let args = sign_for(
        HashKind::Sha256,
        &signer,
        statement(wide, "review", "pass", SIGNED_AT, None),
        ATTEST_NAMESPACE,
        HashAlg::Sha256,
    );
    assert_eq!(refusal(&args), ErrorCode::EObjectFormat);
}

#[test]
fn a_v1_signature_over_an_evidenceless_statement_stays_verifiable() {
    let signer = key(0x11);
    let args = sign_v1(&signer, review_pass());
    let verified = verify_statement(HashKind::Sha1, &args).expect("v1 signature verifies");
    let mut digest = [0_u8; 32];
    let v1 = review_pass()
        .canonical_payload_v1(HashKind::Sha1)
        .expect("v1 payload");
    digest.copy_from_slice(&Sha256::digest(&v1));
    assert_eq!(verified.digest().as_bytes(), &digest);
}

#[test]
fn an_evidence_digest_is_bound_to_the_v2_signature() {
    let signer = key(0x11);
    let evidence = StatementDigest::from_bytes([7; 32]);
    let bound = evidenced(subject(), "ci", "pass", SIGNED_AT, Some(evidence));
    let args = sign(&signer, bound.clone());
    let verified = verify_statement(HashKind::Sha1, &args).expect("v2 signature verifies");
    let mut digest = [0_u8; 32];
    let v2 = bound
        .canonical_payload_v2(HashKind::Sha1)
        .expect("v2 payload");
    digest.copy_from_slice(&Sha256::digest(&v2));
    assert_eq!(verified.digest().as_bytes(), &digest);
}

#[test]
fn stripping_evidence_from_a_v2_signature_is_refused() {
    let signer = key(0x11);
    let evidence = StatementDigest::from_bytes([7; 32]);
    let bound = evidenced(subject(), "ci", "pass", SIGNED_AT, Some(evidence));
    let signed = sign(&signer, bound.clone());
    let stripped = AttestAddArgs {
        statement: AttestStatement {
            evidence: None,
            ..bound
        },
        signature: signed.signature.clone(),
    };
    assert_eq!(refusal(&stripped), ErrorCode::EInvalid);
}

#[test]
fn evidence_cannot_be_added_under_a_v1_signature() {
    let signer = key(0x11);
    let signed = sign_v1(&signer, review_pass());
    let mut upgraded = review_pass();
    upgraded.evidence = Some(StatementDigest::from_bytes([7; 32]));
    let forged = AttestAddArgs {
        statement: upgraded,
        signature: signed.signature.clone(),
    };
    assert_eq!(refusal(&forged), ErrorCode::EInvalid);
}
