//! Coordinator ownership lock: one lifetime owner per store directory.
//!
//! The input is an existing store directory; acquisition never creates it
//! and never opens redb. The lock file (`lock` inside the store directory)
//! is opened without truncation, a nonblocking exclusive platform lock
//! decides owner versus contender, and only the owner publishes its
//! endpoint body (pid, socket/pipe address, nonce) after its endpoint binds
//! and passes readiness. Attach retry timing (50 ms / 5 s) belongs to the
//! attach owner, not this module: this module never sleeps and never starts
//! a second writer on a held lock.
//!
//! Body codec (exactly four LF-terminated lines, at most 512 bytes):
//!
//! ```text
//! ruk-lock 1
//! pid <canonical nonzero decimal u32>
//! address unix:<lowercase hex of absolute native path bytes>
//! nonce <64 lowercase hex digits>
//! ```
//!
//! The address alternative is `address pipe:<ASCII named-pipe path>` with
//! the exact local prefix `\\.\pipe\`. A syntactically valid different
//! header version reports [`ErrorCode::EVersion`]; any other malformed,
//! partial, or overlong body reports [`LockSnapshot::NotReady`] so the
//! attach owner can retry within its deadline.

#[cfg(unix)]
#[path = "lock/unix.rs"]
mod platform;

#[cfg(windows)]
#[path = "lock/windows.rs"]
mod platform;

#[cfg(not(any(unix, windows)))]
compile_error!("ruk-core coordinator lock supports only unix and windows targets");

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{CoreError, ErrorCode};
use crate::ids::{hex_byte, hex_val};

/// Name of the ownership file inside an existing store directory.
const LOCK_FILE_NAME: &str = "lock";

/// Path of the ownership file inside an existing store directory.
#[must_use]
pub(crate) fn lock_path(root: &Path) -> PathBuf {
    root.join(LOCK_FILE_NAME)
}

/// Exact first line of every body this build writes.
const HEADER_V1: &str = "ruk-lock 1";

/// Prefix of a header line carrying a version this build does not speak.
const HEADER_PREFIX: &str = "ruk-lock ";

/// Largest complete body, in bytes. Reads stop one byte past this limit so
/// an overlong file is observable as [`LockSnapshot::NotReady`].
const MAX_BODY_BYTES: usize = 512;

/// Read cap: one byte more than [`MAX_BODY_BYTES`] to detect overlong input.
pub(crate) const MAX_READ_BYTES: usize = MAX_BODY_BYTES + 1;

/// Largest Unix socket path, in native bytes.
const MAX_SOCKET_PATH_BYTES: usize = 103;

/// Exact local named-pipe prefix. Remote names never match it.
const PIPE_PREFIX: &str = r"\\.\pipe\";

/// Opaque 256-bit endpoint nonce. Debug output never carries secret bytes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EndpointNonce([u8; 32]);

impl EndpointNonce {
    /// Draws 32 bytes from the OS generator for one bound endpoint.
    pub(crate) fn generate() -> Result<Self, CoreError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|err| CoreError::new(ErrorCode::EIo, format!("endpoint nonce: {err}")))?;
        Ok(Self(bytes))
    }

    /// Raw bytes for endpoint authentication (HMAC) only.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for EndpointNonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EndpointNonce(..)")
    }
}

/// Bound endpoint address. The Unix variant preserves native path bytes;
/// Debug output carries no nonce (the nonce lives in [`LockBody`], whose
/// Debug form redacts it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EndpointAddress {
    Unix(PathBuf),
    Pipe(String),
}

/// Published ownership body. Only the lock owner writes it, after its
/// endpoint binds and passes its platform readiness check.
#[derive(Clone, PartialEq, Eq)]
pub struct LockBody {
    pub(crate) pid: u32,
    pub(crate) address: EndpointAddress,
    pub(crate) nonce: EndpointNonce,
}

impl core::fmt::Debug for LockBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LockBody")
            .field("pid", &self.pid)
            .field("address", &self.address)
            .field("nonce", &self.nonce)
            .finish()
    }
}

/// What a contender observed under a held lock. `NotReady` covers empty,
/// partial, malformed, and overlong bodies: publication is in-place, so the
/// attach owner retries within its deadline instead of treating them as
/// version or corruption failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LockSnapshot {
    Ready(LockBody),
    NotReady,
}

/// Outcome of [`StoreLock::try_acquire`]: new owner or a contender snapshot.
#[derive(Debug)]
pub(crate) enum Acquisition {
    Owner(StoreLock),
    Held(LockSnapshot),
}

/// The process-wide ownership lock. The lock belongs to the process until
/// explicit [`StoreLock::release`] or owner destruction; `Drop` is only a
/// best-effort cleanup path for unwinding or abandoned owners.
#[derive(Debug)]
pub(crate) struct StoreLock {
    inner: Option<OwnerInner>,
}

#[derive(Debug)]
struct OwnerInner {
    file: platform::HeldFile,
    path: PathBuf,
}

impl StoreLock {
    /// Acquires ownership of the existing store directory `root`, or reports
    /// the body currently published under a held lock. Never creates the
    /// root, never truncates the lock file, never opens redb.
    pub(crate) fn try_acquire(root: &Path) -> Result<Acquisition, CoreError> {
        match root.metadata() {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    format!("store root is not a directory: {}", root.display()),
                ));
            }
            Err(err) => {
                return Err(CoreError::new(
                    ErrorCode::ENotFound,
                    format!("store root is missing: {}: {err}", root.display()),
                ));
            }
        }
        let path = root.join(LOCK_FILE_NAME);
        match platform::try_acquire(&path)? {
            Some(file) => Ok(Acquisition::Owner(StoreLock {
                inner: Some(OwnerInner { file, path }),
            })),
            None => {
                // The lock was held a moment ago. If the file vanished
                // since, report not-ready for the attach owner's bounded
                // retry; the next attempt recreates and owns it. Any other
                // read failure (including security validation) propagates.
                let bytes = match platform::read_body(&path) {
                    Err(err) if err.code == ErrorCode::ENotFound => {
                        return Ok(Acquisition::Held(LockSnapshot::NotReady));
                    }
                    result => result?,
                };
                Ok(Acquisition::Held(decode_body(&bytes)?))
            }
        }
    }

    /// Replaces the body under the held lifetime lock: seek to zero,
    /// truncate, write the complete bounded body, then sync. Only the owner
    /// calls this, after its endpoint binds and passes readiness.
    pub(crate) fn publish(&mut self, body: &LockBody) -> Result<(), CoreError> {
        let bytes = encode_body(body)?;
        let Some(inner) = self.inner.as_mut() else {
            return Err(CoreError::new(
                ErrorCode::EIo,
                "ownership lock is no longer held",
            ));
        };
        let mut file: &std::fs::File = inner.file.file();
        file.seek(SeekFrom::Start(0))
            .map_err(|err| lock_io_error(&inner.path, "publish ownership body", err))?;
        file.set_len(0)
            .map_err(|err| lock_io_error(&inner.path, "publish ownership body", err))?;
        file.write_all(&bytes)
            .map_err(|err| lock_io_error(&inner.path, "publish ownership body", err))?;
        file.sync_all()
            .map_err(|err| lock_io_error(&inner.path, "publish ownership body", err))?;
        Ok(())
    }

    /// Truncates and syncs the body, then drops the platform guard to
    /// unlock. A graceful-close I/O failure is propagated, never reported
    /// as a successful release.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no caller at this commit; retained for later changeset rows"
        )
    )]
    pub(crate) fn release(mut self) -> Result<(), CoreError> {
        let Some(inner) = self.inner.take() else {
            return Err(CoreError::new(
                ErrorCode::EIo,
                "ownership lock is no longer held",
            ));
        };
        let file: &std::fs::File = inner.file.file();
        let result = file
            .set_len(0)
            .and_then(move |()| file.sync_all())
            .map_err(|err| lock_io_error(&inner.path, "release ownership lock", err));
        drop(inner);
        result
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // Best-effort cleanup only: a failed cleanup leaves a stale body,
        // which never authorizes takeover of a held lock and is replaced by
        // the next owner.
        if let Some(inner) = self.inner.take() {
            let mut file: &std::fs::File = inner.file.file();
            let _ = file.seek(SeekFrom::Start(0));
            let _ = file.set_len(0);
            let _ = file.sync_all();
        }
    }
}

/// One I/O failure shape for every publish/release step: the operation, the
/// lock path, and the OS error. No secret bytes ever enter these messages.
fn lock_io_error(path: &Path, op: &'static str, err: std::io::Error) -> CoreError {
    CoreError::new(ErrorCode::EIo, format!("{op} {}: {err}", path.display()))
}

/// First LF-terminated line, if any. A header without its newline is a
/// partial publish, not a version signal.
fn first_line(bytes: &[u8]) -> Option<&[u8]> {
    let end = bytes.iter().position(|&byte| byte == b'\n')?;
    Some(&bytes[..end])
}

/// Canonical nonzero decimal `u32`: nonempty ASCII digits, no leading zero
/// (which also excludes zero itself), at most `u32::MAX`.
fn parse_canonical_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 10 || bytes[0] == b'0' {
        return None;
    }
    let mut value: u32 = 0;
    for &digit in bytes {
        if !digit.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u32::from(digit - b'0'))?;
    }
    Some(value)
}

/// Native bytes of a Unix socket path: absolute on every platform this
/// module supports (byte-level so encode and decode agree exactly).
#[cfg(unix)]
fn unix_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;
    path.as_os_str().as_bytes().to_vec()
}

/// UTF-8 paths encode identically on Windows; anything else is unrepresentable.
#[cfg(windows)]
fn unix_path_bytes(path: &Path) -> Result<Vec<u8>, ()> {
    path.as_os_str()
        .to_str()
        .map(|s| s.as_bytes().to_vec())
        .ok_or(())
}

/// Byte-level socket-path rules shared by the encoder and the decoder.
fn check_socket_bytes(bytes: &[u8]) -> Result<(), ()> {
    if bytes.len() > MAX_SOCKET_PATH_BYTES || bytes.contains(&0) {
        return Err(());
    }
    match bytes.first() {
        Some(b'/') => Ok(()),
        _ => Err(()),
    }
}

/// Byte-level named-pipe rules shared by the encoder and the decoder:
/// exact local prefix, nonempty ASCII name, no CR/LF/NUL, no remote names
/// (which cannot match the local prefix).
fn check_pipe_bytes(bytes: &[u8]) -> Result<(), ()> {
    let Some(name) = bytes.strip_prefix(PIPE_PREFIX.as_bytes()) else {
        return Err(());
    };
    if name.is_empty() || !name.is_ascii() {
        return Err(());
    }
    if name.contains(&b'\r') || name.contains(&b'\n') || name.contains(&0) {
        return Err(());
    }
    Ok(())
}

#[cfg(unix)]
fn socket_path_from_bytes(bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt as _;
    std::ffi::OsString::from_vec(bytes).into()
}

#[cfg(windows)]
fn socket_path_from_bytes(bytes: Vec<u8>) -> Result<PathBuf, ()> {
    String::from_utf8(bytes).map(PathBuf::from).map_err(|_| ())
}

/// Encodes a body into its exact four LF-terminated lines. Invalid internal
/// input reports [`ErrorCode::EInvalid`], overlong input
/// [`ErrorCode::ELimit`]; malformed bytes are never emitted.
pub(crate) fn encode_body(body: &LockBody) -> Result<Vec<u8>, CoreError> {
    if body.pid == 0 {
        return Err(CoreError::new(ErrorCode::EInvalid, "lock pid is zero"));
    }
    let address = match &body.address {
        EndpointAddress::Unix(path) => {
            #[cfg(windows)]
            let raw = unix_path_bytes(path)
                .map_err(|()| CoreError::new(ErrorCode::EInvalid, "lock socket path"))?;
            #[cfg(unix)]
            let raw = unix_path_bytes(path);
            if check_socket_bytes(&raw).is_err() {
                let limit = raw.len() > MAX_SOCKET_PATH_BYTES;
                return Err(CoreError::new(
                    if limit {
                        ErrorCode::ELimit
                    } else {
                        ErrorCode::EInvalid
                    },
                    "lock socket path",
                ));
            }
            let mut hex = String::with_capacity(raw.len() * 2);
            for byte in &raw {
                hex.push_str(hex_byte(*byte));
            }
            format!("address unix:{hex}\n")
        }
        EndpointAddress::Pipe(name) => {
            if check_pipe_bytes(name.as_bytes()).is_err() {
                return Err(CoreError::new(ErrorCode::EInvalid, "lock pipe path"));
            }
            format!("address pipe:{name}\n")
        }
    };
    let mut nonce = String::with_capacity(64);
    for byte in body.nonce.as_bytes() {
        nonce.push_str(hex_byte(*byte));
    }
    let text = format!("ruk-lock 1\npid {}\n{address}nonce {nonce}\n", body.pid);
    if text.len() > MAX_BODY_BYTES {
        return Err(CoreError::new(ErrorCode::ELimit, "lock body"));
    }
    Ok(text.into_bytes())
}

/// Decodes a body observed under a held lock. `Ok(NotReady)` covers empty,
/// partial, malformed, and overlong input for the attach owner's bounded
/// retry. Gate order is fixed: overlong and carriage-return input is
/// `NotReady` first then a complete first line carrying a syntactically
/// valid unknown version is [`ErrorCode::EVersion`] even while the trailing
/// body is still partial and finally anything else malformed is `NotReady`.
pub(crate) fn decode_body(bytes: &[u8]) -> Result<LockSnapshot, CoreError> {
    if bytes.len() > MAX_BODY_BYTES {
        return Ok(LockSnapshot::NotReady);
    }
    if bytes.contains(&b'\r') {
        return Ok(LockSnapshot::NotReady);
    }
    if let Some(header) = first_line(bytes)
        && header != HEADER_V1.as_bytes()
        && let Some(version) = header.strip_prefix(HEADER_PREFIX.as_bytes())
        && parse_canonical_u32(version).is_some_and(|v| v != 1)
    {
        return Err(CoreError::new(
            ErrorCode::EVersion,
            "ownership lock version is not ruk-lock 1",
        ));
    }
    let parts: Vec<&[u8]> = bytes.split(|byte| *byte == b'\n').collect();
    if parts.len() != 5 || !parts[4].is_empty() {
        return Ok(LockSnapshot::NotReady);
    }
    let [header, pid_line, address_line, nonce_line, _] = parts.as_slice() else {
        return Ok(LockSnapshot::NotReady);
    };
    if *header != HEADER_V1.as_bytes() {
        return Ok(LockSnapshot::NotReady);
    }
    let Some(pid) = pid_line.strip_prefix(b"pid ").and_then(parse_canonical_u32) else {
        return Ok(LockSnapshot::NotReady);
    };
    let address = if let Some(hex) = address_line.strip_prefix(b"address unix:") {
        let Some(address) = decode_unix_address(hex) else {
            return Ok(LockSnapshot::NotReady);
        };
        address
    } else if let Some(name) = address_line.strip_prefix(b"address pipe:") {
        let Some(address) = decode_pipe_address(name) else {
            return Ok(LockSnapshot::NotReady);
        };
        address
    } else {
        return Ok(LockSnapshot::NotReady);
    };
    let Some(hex) = nonce_line.strip_prefix(b"nonce ") else {
        return Ok(LockSnapshot::NotReady);
    };
    let Some(nonce) = decode_nonce(hex) else {
        return Ok(LockSnapshot::NotReady);
    };
    Ok(LockSnapshot::Ready(LockBody {
        pid,
        address,
        nonce,
    }))
}

/// Decodes one `address unix:<hex>` payload: even-length canonical
/// lowercase hex within the socket-path byte budget.
fn decode_unix_address(hex: &[u8]) -> Option<EndpointAddress> {
    if !hex.len().is_multiple_of(2) || hex.is_empty() || hex.len() / 2 > MAX_SOCKET_PATH_BYTES {
        return None;
    }
    let mut raw = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_chunks::<2>().0 {
        raw.push((hex_val(pair[0])? << 4) | hex_val(pair[1])?);
    }
    if check_socket_bytes(&raw).is_err() {
        return None;
    }
    #[cfg(unix)]
    let path = socket_path_from_bytes(raw);
    #[cfg(windows)]
    let path = socket_path_from_bytes(raw).ok()?;
    Some(EndpointAddress::Unix(path))
}

/// Decodes one `address pipe:<path>` payload under the named-pipe rules.
fn decode_pipe_address(name: &[u8]) -> Option<EndpointAddress> {
    if check_pipe_bytes(name).is_err() {
        return None;
    }
    let name = core::str::from_utf8(name).ok()?;
    Some(EndpointAddress::Pipe(name.to_owned()))
}

/// Decodes one `nonce <64 hex>` payload into its 32 bytes.
fn decode_nonce(hex: &[u8]) -> Option<EndpointNonce> {
    if hex.len() != 64 {
        return None;
    }
    let mut raw = [0u8; 32];
    for (slot, pair) in raw.iter_mut().zip(hex.as_chunks::<2>().0) {
        *slot = (hex_val(pair[0])? << 4) | hex_val(pair[1])?;
    }
    Some(EndpointNonce(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TestStore {
        dir: PathBuf,
    }

    impl TestStore {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ruk-lock-test-{}-{}-{tag}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create test store root");
            Self { dir }
        }

        fn lock_path(&self) -> PathBuf {
            self.dir.join(LOCK_FILE_NAME)
        }
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn sample_body() -> LockBody {
        LockBody {
            pid: std::process::id(),
            address: EndpointAddress::Unix(PathBuf::from("/tmp/ruk-lock-test-endpoint.sock")),
            nonce: EndpointNonce::generate().expect("generate nonce"),
        }
    }

    fn must_hold(snapshot: LockSnapshot) -> LockBody {
        match snapshot {
            LockSnapshot::Ready(body) => body,
            LockSnapshot::NotReady => panic!("expected a readable published body"),
        }
    }

    #[test]
    fn second_handle_contends_while_owner_holds() {
        let store = TestStore::new("contend");
        let _owner = match StoreLock::try_acquire(&store.dir).expect("first acquire") {
            Acquisition::Owner(lock) => lock,
            Acquisition::Held(_) => panic!("first acquire must own a fresh lock"),
        };
        match StoreLock::try_acquire(&store.dir).expect("second acquire") {
            Acquisition::Owner(_) => panic!("second handle must not own a held lock"),
            Acquisition::Held(LockSnapshot::NotReady) => {}
            Acquisition::Held(LockSnapshot::Ready(_)) => {
                panic!("fresh lock has no published body yet")
            }
        }
    }

    #[test]
    fn held_lock_body_stays_readable() {
        let store = TestStore::new("readable");
        let mut owner = match StoreLock::try_acquire(&store.dir).expect("acquire") {
            Acquisition::Owner(lock) => lock,
            Acquisition::Held(_) => panic!("fresh lock must be acquirable"),
        };
        let body = sample_body();
        owner.publish(&body).expect("publish");
        match StoreLock::try_acquire(&store.dir).expect("contend") {
            Acquisition::Held(snapshot) => assert_eq!(must_hold(snapshot), body),
            Acquisition::Owner(_) => panic!("held lock must stay held"),
        }
    }

    #[test]
    fn partial_body_never_authorizes_an_owner() {
        let store = TestStore::new("partial");
        let _owner = match StoreLock::try_acquire(&store.dir).expect("acquire") {
            Acquisition::Owner(lock) => lock,
            Acquisition::Held(_) => panic!("fresh lock must be acquirable"),
        };
        // A crashed owner mid-publish: truncated file, incomplete lines, no sync.
        std::fs::write(store.lock_path(), b"ruk-lock 1\npid 42\n").expect("write partial body");
        match StoreLock::try_acquire(&store.dir).expect("contend") {
            Acquisition::Held(LockSnapshot::NotReady) => {}
            Acquisition::Held(LockSnapshot::Ready(_)) => {
                panic!("partial body must not read as ready")
            }
            Acquisition::Owner(_) => panic!("held lock must stay held"),
        }
        for partial in [
            &b""[..],
            &b"ruk-lock 1\n"[..],
            &b"ruk-lock 1\npid 42\naddress unix:2f\n"[..],
            &b"ruk-lock 1\npid 42\naddress unix:2f\nnonce abc\n"[..],
        ] {
            assert_eq!(
                decode_body(partial).expect("decode"),
                LockSnapshot::NotReady,
                "partial input must stay not-ready: {partial:?}"
            );
        }
    }

    /// Copies valid encoder output with the single line starting with
    /// `line_prefix` (through its newline) replaced by `new_line`, so each
    /// malformed case carries exactly one defect.
    fn mutate_line(raw: &[u8], line_prefix: &[u8], new_line: &[u8]) -> Vec<u8> {
        let start = raw
            .windows(line_prefix.len())
            .position(|window| window == line_prefix)
            .expect("line present");
        let end = raw[start..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map(|offset| start + offset + 1)
            .expect("line ends");
        let mut out = raw.to_vec();
        out.splice(start..end, new_line.iter().copied());
        out
    }

    #[test]
    fn malformed_bodies_stay_not_ready() {
        let body = sample_body();
        let pid = body.pid;
        let valid = encode_body(&body).expect("encode sample");
        assert_eq!(
            decode_body(&valid).expect("decode"),
            LockSnapshot::Ready(body)
        );
        let upper_nonce = {
            let mut line = b"nonce ".to_vec();
            line.extend([b'A'; 64]);
            line.push(b'\n');
            line
        };
        let cases: Vec<Vec<u8>> = vec![
            mutate_line(&valid, b"pid ", format!("pid 0{pid}\n").as_bytes()),
            mutate_line(&valid, b"pid ", b"pid 0\n"),
            mutate_line(&valid, b"pid ", b"pid 4294967296\n"),
            mutate_line(&valid, b"address ", b"address unix:2F\n"),
            mutate_line(&valid, b"address ", b"address unix:72656c\n"),
            mutate_line(&valid, b"address ", b"address pipe:\n"),
            mutate_line(&valid, b"address ", b"address pipe:\\\\server\\pipe\\x\n"),
            mutate_line(&valid, b"nonce ", &upper_nonce),
            mutate_line(&valid, b"nonce ", b"nonce 00\n"),
            mutate_line(&valid, b"ruk-lock 1", b"ruk-lock\n"),
            mutate_line(&valid, b"ruk-lock 1", b"ruk-lock 1\r\n"),
        ];
        for raw in &cases {
            assert_eq!(
                decode_body(raw).expect("decode"),
                LockSnapshot::NotReady,
                "malformed input must stay not-ready: {raw:?}"
            );
        }
        let mut trailing = valid.clone();
        trailing.push(b'\n');
        assert_eq!(
            decode_body(&trailing).expect("decode"),
            LockSnapshot::NotReady
        );
        let mut unterminated = valid;
        unterminated.pop();
        assert_eq!(
            decode_body(&unterminated).expect("decode"),
            LockSnapshot::NotReady
        );
        let overlong = vec![b'x'; MAX_BODY_BYTES + 1];
        assert_eq!(
            decode_body(&overlong).expect("decode"),
            LockSnapshot::NotReady
        );
    }

    #[test]
    fn valid_unknown_header_is_version_not_not_ready() {
        let body = sample_body();
        let valid = encode_body(&body).expect("encode sample");
        let versioned = mutate_line(&valid, b"ruk-lock 1", b"ruk-lock 2\n");
        let err = decode_body(&versioned).expect_err("unknown version must fail");
        assert_eq!(err.code, ErrorCode::EVersion);
        // A partial v2 publish already fixes the version: fail fast instead
        // of consuming the attach owner's retry budget.
        for partial in [
            b"ruk-lock 2\n".to_vec(),
            b"ruk-lock 2\npid 7\n".to_vec(),
            b"ruk-lock 2\npid 7\naddress unix:2f\n".to_vec(),
        ] {
            assert_eq!(
                decode_body(&partial)
                    .expect_err("partial unknown version must fail")
                    .code,
                ErrorCode::EVersion,
                "partial input must fail fast: {partial:?}"
            );
        }
        // No newline yet: the header may still be arriving.
        assert_eq!(
            decode_body(b"ruk-lock 2").expect("decode"),
            LockSnapshot::NotReady
        );
        // A corrupt header is not a version.
        let mut corrupt = valid;
        corrupt[0] = b'x';
        assert_eq!(
            decode_body(&corrupt).expect("decode"),
            LockSnapshot::NotReady
        );
    }

    #[test]
    fn encoder_rejects_invalid_internal_input() {
        let mut body = sample_body();
        body.pid = 0;
        assert_eq!(
            encode_body(&body).expect_err("zero pid").code,
            ErrorCode::EInvalid
        );
        body.pid = 7;
        body.address = EndpointAddress::Unix(PathBuf::from("relative.sock"));
        assert_eq!(
            encode_body(&body).expect_err("relative path").code,
            ErrorCode::EInvalid
        );
        let long: Vec<u8> = core::iter::once(b'/')
            .chain(core::iter::repeat_n(b'a', MAX_SOCKET_PATH_BYTES))
            .collect();
        body.address = EndpointAddress::Unix(PathBuf::from(String::from_utf8(long).expect("utf8")));
        assert_eq!(
            encode_body(&body).expect_err("overlong path").code,
            ErrorCode::ELimit
        );
        body.address = EndpointAddress::Pipe(r"\\server\pipe\x".to_owned());
        assert_eq!(
            encode_body(&body).expect_err("remote pipe").code,
            ErrorCode::EInvalid
        );
        let huge = format!(r"\\.\pipe\{}", "n".repeat(MAX_BODY_BYTES));
        body.address = EndpointAddress::Pipe(huge);
        assert_eq!(
            encode_body(&body).expect_err("overlong body").code,
            ErrorCode::ELimit
        );
    }

    #[test]
    fn release_permits_a_new_owner() {
        let store = TestStore::new("release");
        let mut owner = match StoreLock::try_acquire(&store.dir).expect("acquire") {
            Acquisition::Owner(lock) => lock,
            Acquisition::Held(_) => panic!("fresh lock must be acquirable"),
        };
        owner.publish(&sample_body()).expect("publish");
        owner.release().expect("release");
        assert_eq!(
            std::fs::read(store.lock_path())
                .expect("read released lock")
                .len(),
            0
        );
        match StoreLock::try_acquire(&store.dir).expect("reacquire") {
            Acquisition::Owner(_) => {}
            Acquisition::Held(_) => panic!("released lock must be acquirable"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_lock_is_forbidden() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let store = TestStore::new("symlink");
        let target = store.dir.join("real-lock");
        std::fs::write(&target, b"ruk-lock 1\n").expect("write target");
        // Mode 0600 on the target isolates the refusal to the symlink
        // itself: only the no-follow rule can fire.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("chmod target");
        symlink(&target, store.lock_path()).expect("symlink lock");
        let err = StoreLock::try_acquire(&store.dir).expect_err("symlink");
        assert_eq!(err.code, ErrorCode::EForbidden);
        assert!(
            err.message.contains("safely openable"),
            "refusal must come from the no-follow rule: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_lock_is_forbidden() {
        use std::os::unix::fs::OpenOptionsExt as _;
        let store = TestStore::new("hardlink");
        // Mode 0600 isolates the refusal to the link count: the mode rule
        // cannot fire.
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(store.lock_path())
            .expect("pre-create lock");
        std::fs::hard_link(store.lock_path(), store.dir.join("alias")).expect("hard link lock");
        let err = StoreLock::try_acquire(&store.dir).expect_err("hardlink");
        assert_eq!(err.code, ErrorCode::EForbidden);
        assert!(
            err.message.contains("hard link"),
            "refusal must come from the link-count rule: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn insecure_mode_lock_is_forbidden() {
        use std::os::unix::fs::PermissionsExt as _;
        let store = TestStore::new("mode");
        std::fs::write(store.lock_path(), b"").expect("pre-create lock");
        std::fs::set_permissions(store.lock_path(), std::fs::Permissions::from_mode(0o644))
            .expect("chmod lock");
        assert_eq!(
            StoreLock::try_acquire(&store.dir)
                .expect_err("insecure mode")
                .code,
            ErrorCode::EForbidden
        );
    }
}
