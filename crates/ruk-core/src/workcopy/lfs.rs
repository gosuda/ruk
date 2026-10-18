//! Native LFS pointer policy.
//!
//! A Git LFS pointer is a small text file whose first line is
//! `version https://git-lfs.github.com/spec/v1`, followed by optional
//! `ext-*` extension lines, an `oid sha256:<hex>` line, and a final
//! `size <digits>` line. Total file size is strictly below
//! [`MAX_POINTER_BYTES`]; anything at or above it cannot be a pointer.
//!
//! [`LfsMode::Deny`] is the default: a pointer-shaped blob is
//! `E_UNSUPPORTED_LFS` whether it is being recorded into a tree
//! (snapshot, explicit write) or materialized into the worktree.
//! [`LfsMode::Pointers`] (`lfs = "pointers"` in `policy.toml`) treats the
//! bytes as ordinary content and never fetches payloads.

use std::path::Path;

use crate::error::{CoreError, ErrorCode};

/// Upper bound on a Git LFS pointer file: strictly below 1024 bytes.
pub(crate) const MAX_POINTER_BYTES: u64 = 1024;

const VERSION_LINE: &[u8] = b"version https://git-lfs.github.com/spec/v1";
const EXT_PREFIX: &[u8] = b"ext-";
const OID_PREFIX: &[u8] = b"oid sha256:";
const SIZE_PREFIX: &[u8] = b"size ";
const SHA256_HEX_DIGITS: usize = 64;

/// How the store treats a pointer-shaped blob.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LfsMode {
    /// Pointer-shaped blobs are `E_UNSUPPORTED_LFS` in both directions.
    #[default]
    Deny,
    /// `lfs = "pointers"`: pointer bytes are ordinary content; payloads
    /// are never fetched.
    Pointers,
}

/// Whether `bytes` is a Git LFS pointer.
///
/// Strict ordering per the spec: version line, zero or more `ext-` lines,
/// the `oid sha256:` line, the `size` line, and at most one trailing empty
/// line from a final newline. Any other content, ordering, or total size
/// at or above [`MAX_POINTER_BYTES`] is not a pointer.
pub fn is_pointer(bytes: &[u8]) -> bool {
    // usize is at most 64 bits, so widening to u64 is lossless.
    if bytes.len() as u64 >= MAX_POINTER_BYTES {
        return false;
    }
    let mut lines = bytes.split(|byte| *byte == b'\n');
    if lines.next() != Some(VERSION_LINE) {
        return false;
    }
    let oid = loop {
        match lines.next() {
            Some(line) if line.starts_with(EXT_PREFIX) => continue,
            Some(line) => break line,
            None => return false,
        }
    };
    if !parse_oid(oid) {
        return false;
    }
    let Some(size) = lines.next() else {
        return false;
    };
    if !parse_size(size) {
        return false;
    }
    matches!(lines.next(), None | Some(b""))
}

fn parse_oid(line: &[u8]) -> bool {
    line.strip_prefix(OID_PREFIX)
        .is_some_and(|hex| hex.len() == SHA256_HEX_DIGITS && hex.iter().all(u8::is_ascii_hexdigit))
}

fn parse_size(line: &[u8]) -> bool {
    line.strip_prefix(SIZE_PREFIX)
        .is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit))
}

/// Reads the LFS mode the store at `store_root` declares: the `lfs` key of
/// `<store_root>/policy.toml`, parsed through the coordinator policy loader
/// in `coord/policy.rs`, which stays canonical for the full document shape.
/// Transport servers (receive-pack) resolve the `owner` alias the same way
/// the daemon registry does, so both read one policy.
///
/// Fail-closed: a missing file selects the owner-only default, and any
/// document the coordinator would refuse — unknown fields, a bad
/// `[[principal]]`, an unsupported version, malformed TOML, an oversized or
/// non-regular file, an unreadable owner — is [`LfsMode::Deny`], the same
/// default a policy without the key selects. A file the coordinator refuses
/// never enables pointer recording here.
#[must_use]
pub fn mode_for_store(store_root: &Path) -> LfsMode {
    crate::coord::lfs_mode_for_store(store_root)
}

/// The error a pointer-shaped blob raises under [`LfsMode::Deny`].
pub(crate) fn unsupported(path: &[u8]) -> CoreError {
    CoreError::new(
        ErrorCode::EUnsupportedLfs,
        format!(
            "{} is a Git LFS pointer; native workspaces do not transfer LFS payloads",
            String::from_utf8_lossy(path)
        ),
    )
    .with_hint("set `lfs = \"pointers\"` in the store policy.toml to record pointer bytes plainly")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pointer() -> Vec<u8> {
        b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d0b46e9c\nsize 14\n".to_vec()
    }

    #[test]
    fn canonical_pointer_matches() {
        assert!(is_pointer(&pointer()));
    }

    #[test]
    fn mode_for_store_reads_the_lfs_key_and_fails_closed() {
        let dir = std::env::temp_dir().join(format!(
            "ruk-lfs-mode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        // Missing file is the store default.
        assert_eq!(mode_for_store(&dir), LfsMode::Deny);
        std::fs::write(dir.join("policy.toml"), "version = 1\nlfs = \"pointers\"\n")
            .expect("policy");
        assert_eq!(mode_for_store(&dir), LfsMode::Pointers);
        std::fs::write(dir.join("policy.toml"), "version = 1\n").expect("policy");
        assert_eq!(mode_for_store(&dir), LfsMode::Deny);
        std::fs::write(dir.join("policy.toml"), "not toml [[[\n").expect("policy");
        assert_eq!(mode_for_store(&dir), LfsMode::Deny);
        std::fs::write(dir.join("policy.toml"), "version = 2\nlfs = \"pointers\"\n")
            .expect("policy");
        assert_eq!(
            mode_for_store(&dir),
            LfsMode::Deny,
            "a future policy version never enables pointers here"
        );
        // A file the coordinator policy loader rejects never enables
        // pointers here, even with `lfs = "pointers"` set.
        for (name, policy) in [
            (
                "unknown top-level key",
                "version = 1\nlfs = \"pointers\"\nunknown = 1\n",
            ),
            (
                "malformed principal",
                "version = 1\nlfs = \"pointers\"\n[[principal]]\nname = \"bogus\"\n",
            ),
            (
                "bad session_idle",
                "version = 1\nlfs = \"pointers\"\nsession_idle = \"yesterday\"\n",
            ),
        ] {
            std::fs::write(dir.join("policy.toml"), policy).expect("policy");
            assert_eq!(mode_for_store(&dir), LfsMode::Deny, "{name} fails closed");
        }
        // A fully valid policy with principals still honors the key.
        std::fs::write(
            dir.join("policy.toml"),
            "version = 1\nlfs = \"pointers\"\n[[principal]]\nname = \"owner\"\n",
        )
        .expect("policy");
        assert_eq!(mode_for_store(&dir), LfsMode::Pointers);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extension_lines_are_accepted() {
        let mut bytes = b"version https://git-lfs.github.com/spec/v1\n".to_vec();
        bytes.extend_from_slice(b"ext-0-foo sha256:abcdef\n");
        bytes.extend_from_slice(&pointer()[VERSION_LINE.len() + 1..]);
        assert!(is_pointer(&bytes));
    }

    #[test]
    fn non_pointers() {
        for (name, bytes) in [
            ("empty", Vec::new()),
            ("wrong version", b"version https://git-lfs.github.com/spec/v2\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d0b46e9c\nsize 14\n".to_vec()),
            ("missing size", b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d0b46e9c\n".to_vec()),
            ("reordered", b"version https://git-lfs.github.com/spec/v1\nsize 14\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d0b46e9c\n".to_vec()),
            ("trailing text", b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d0b46e9c\nsize 14\nextra\n".to_vec()),
            ("short oid", b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7a\nsize 14\n".to_vec()),
            ("negative size", b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d0b46e9c\nsize -1\n".to_vec()),
            ("pointer at size cutoff", {
                let mut bytes = pointer();
                let pad = 1024usize - bytes.len();
                bytes.extend_from_slice(&vec![b'x'; pad]);
                bytes
            }),
        ] {
            assert!(!is_pointer(&bytes), "{name} must not be a pointer");
        }
    }
}
