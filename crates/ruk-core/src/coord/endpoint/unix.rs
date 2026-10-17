//! Unix coordinator endpoint: an exclusive generation directory holding one
//! local Unix domain socket, OS peer authentication, and refusal of
//! positively identified remote filesystems.
//!
//! Each [`UnixEndpoint`] creates `<temp>/r<StoreId hex>-<8 random bytes hex>/s`
//! with mode `0700`, never adopting an existing path. The directory, not the
//! socket's creation mode, protects the socket. Processes under the same
//! effective uid with store access are trusted cooperating peers; this module
//! is not a sandbox against them. The handshake HMAC belongs to the handshake
//! module; this module supplies only the OS-authenticated uid.
//!
//! [`UnixEndpoint::bind`] must run inside a Tokio runtime with I/O enabled.
//! Drop and [`UnixEndpoint::close`] remove only this endpoint's socket and
//! generation directory, never the store lock file. A crashed owner leaves its
//! generation directory behind; nothing in this module sweeps it.

use std::fs::DirBuilder;
use std::io::{self, ErrorKind};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

use crate::coord::lock::EndpointAddress;
use crate::error::{CoreError, ErrorCode};
use crate::ids::hex_byte;
use crate::StoreId;

/// Largest socket pathname, in native bytes, that this endpoint will bind.
const MAX_SOCKET_PATH_BYTES: usize = 103;

/// Socket leaf name inside the generation directory.
const SOCKET_LEAF_NAME: &str = "s";

/// Fresh random bytes per generation directory name. Independent of the lock nonce.
const RANDOM_BYTES: usize = 8;

/// Bounded number of fresh-random retries after `EEXIST` on the generation name.
const MAX_CREATION_ATTEMPTS: usize = 8;

/// One exclusive generation: its directory, its listener, and its published address.
pub(crate) struct UnixEndpoint {
    address: EndpointAddress,
    listener: UnixListener,
    dir: PathBuf,
    socket_path: PathBuf,
    cleaned: bool,
}

impl core::fmt::Debug for UnixEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnixEndpoint")
            .field("address", &self.address)
            .field("dir", &self.dir)
            .finish()
    }
}

impl UnixEndpoint {
    /// Creates a new exclusive generation under [`std::env::temp_dir`] and binds
    /// its socket. Must be called from within a Tokio runtime with I/O enabled.
    ///
    /// # Errors
    /// `E_LIMIT` when the socket path would exceed the portable limit (nothing is
    /// created), `E_INVALID` for a relative temporary directory, `E_IO` for
    /// filesystem or socket failures.
    pub(crate) fn bind(store: StoreId) -> Result<Self, CoreError> {
        Self::bind_in(&std::env::temp_dir(), store)
    }

    /// Binds a new generation under `temp_base`, the only bind path besides
    /// [`Self::bind`]. Tests reach it directly to avoid mutating `TMPDIR`.
    fn bind_in(temp_base: &Path, store: StoreId) -> Result<Self, CoreError> {
        if !temp_base.is_absolute() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "endpoint temporary directory must be absolute: {}",
                    temp_base.display()
                ),
            ));
        }
        let store_hex = hex_string(store.as_bytes());
        for _ in 0..MAX_CREATION_ATTEMPTS {
            if let Some(endpoint) = try_create_and_bind(temp_base, &store_hex)? {
                return Ok(endpoint);
            }
        }
        Err(CoreError::new(
            ErrorCode::EIo,
            format!(
                "no free endpoint generation name after {MAX_CREATION_ATTEMPTS} attempts under {}",
                temp_base.display()
            ),
        ))
    }

    /// The published address, for the store lock body.
    pub(crate) fn address(&self) -> &EndpointAddress {
        &self.address
    }

    /// Waits for the next peer connection.
    pub(crate) async fn accept(&self) -> io::Result<UnixStream> {
        let (stream, _peer) = self.listener.accept().await?;
        Ok(stream)
    }

    /// Removes this generation and reports any failure. Drop repeats the removal
    /// best-effort; a second removal is a no-op.
    pub(crate) fn close(mut self) -> Result<(), CoreError> {
        self.cleanup()
    }

    fn cleanup(&mut self) -> Result<(), CoreError> {
        if self.cleaned {
            return Ok(());
        }
        self.cleaned = true;
        let socket = tolerate_absent(
            &self.socket_path,
            std::fs::remove_file(&self.socket_path),
        );
        let dir = tolerate_absent(&self.dir, std::fs::remove_dir(&self.dir));
        socket.and(dir)
    }
}

impl Drop for UnixEndpoint {
    fn drop(&mut self) {
        // Best effort; failures surface only through explicit `close`.
        let _ = self.cleanup();
    }
}

/// One generation attempt. `Ok(None)` means the random name already existed and
/// the caller should retry with fresh randomness.
fn try_create_and_bind(
    temp_base: &Path,
    store_hex: &str,
) -> Result<Option<UnixEndpoint>, CoreError> {
    let mut random = [0u8; RANDOM_BYTES];
    getrandom::fill(&mut random).map_err(|err| {
        CoreError::new(ErrorCode::EIo, format!("endpoint generation randomness: {err}"))
    })?;
    let dir = temp_base.join(format!("r{store_hex}-{}", hex_string(&random)));
    let socket_path = dir.join(SOCKET_LEAF_NAME);

    let socket_len = byte_len(&socket_path);
    if socket_len > MAX_SOCKET_PATH_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!(
                "endpoint socket path is {socket_len} bytes, above the portable limit of {MAX_SOCKET_PATH_BYTES}: {}",
                socket_path.display()
            ),
        ));
    }

    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    if let Err(err) = builder.create(&dir) {
        return if err.kind() == ErrorKind::AlreadyExists {
            Ok(None)
        } else {
            Err(io_failure(&dir, "create endpoint generation directory", err))
        };
    }

    if let Err(err) = verify_generation_dir(&dir) {
        let _ = std::fs::remove_dir(&dir);
        return Err(err);
    }

    match UnixListener::bind(&socket_path) {
        Ok(listener) => Ok(Some(UnixEndpoint {
            address: EndpointAddress::Unix(socket_path.clone()),
            listener,
            dir,
            socket_path,
            cleaned: false,
        })),
        Err(err) => {
            let _ = std::fs::remove_dir(&dir);
            Err(io_failure(&socket_path, "bind unix listener", err))
        }
    }
}

/// Opens the generation directory without following links and checks what was
/// opened: a directory owned by the effective uid with no group or other bits.
/// Never repairs modes; a violation is `E_FORBIDDEN`.
fn verify_generation_dir(dir: &Path) -> Result<(), CoreError> {
    // No O_DIRECTORY: on Linux a trailing symlink under O_DIRECTORY | O_NOFOLLOW
    // fails with ENOTDIR instead of ELOOP. O_NONBLOCK stops a FIFO planted at this
    // path from blocking the open; the fstat check below refuses anything that
    // is not a directory.
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::NONBLOCK
        | rustix::fs::OFlags::CLOEXEC;
    let fd = rustix::fs::open(dir, flags, rustix::fs::Mode::empty()).map_err(|err| {
        if err.raw_os_error() == rustix::io::Errno::LOOP.raw_os_error() {
            forbidden(dir, "endpoint generation path is a symbolic link")
        } else {
            io_failure(dir, "open endpoint generation directory", err)
        }
    })?;
    let stat = rustix::fs::fstat(&fd)
        .map_err(|err| io_failure(dir, "fstat endpoint generation directory", err))?;
    if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(forbidden(dir, "endpoint generation path is not a directory"));
    }
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(forbidden(
            dir,
            "endpoint generation directory is not owned by the effective user",
        ));
    }
    if stat.st_mode & 0o077 != 0 {
        return Err(forbidden(
            dir,
            "endpoint generation directory grants group or other permissions",
        ));
    }
    Ok(())
}

/// Connects a client stream to a published Unix socket address.
///
/// Every connect failure is `E_IO` with the `io::ErrorKind` in the message. A
/// vanished socket is usually a dead owner whose lock is about to be released,
/// so attach retries it rather than aborting. Named-pipe addresses are
/// `E_INVALID`.
pub(crate) async fn connect(address: &EndpointAddress) -> Result<UnixStream, CoreError> {
    let EndpointAddress::Unix(path) = address else {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "unix endpoint cannot connect to a named-pipe address",
        ));
    };
    UnixStream::connect(path).await.map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!(
                "connect to coordinator socket {} ({:?}): {err}",
                path.display(),
                err.kind()
            ),
        )
    })
}

/// The OS-authenticated effective uid of the peer, via Tokio `peer_cred`.
/// Identity bytes sent by a peer are never consulted.
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, CoreError> {
    stream
        .peer_cred()
        .map(|cred| cred.uid())
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("read peer credentials: {err}")))
}

/// Refuses a positively identified remote filesystem for `root`.
///
/// Parent calls this before `StoreLock` acquisition. It never creates `root`
/// and never opens redb. Filesystems the platform cannot name precisely are
/// accepted; local durable storage is the deployment prerequisite for them.
pub(crate) fn ensure_local_storage(root: &Path) -> Result<(), CoreError> {
    let metadata = root.metadata().map_err(|err| match err.kind() {
        ErrorKind::NotFound => CoreError::new(
            ErrorCode::ENotFound,
            format!("store root is missing: {}", root.display()),
        ),
        _ => io_failure(root, "inspect store root", err),
    })?;
    if !metadata.is_dir() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!("store root is not a directory: {}", root.display()),
        ));
    }
    check_filesystem_type(root)
}

/// Linux: the `statfs` superblock magic is matched against network filesystem
/// magics. FUSE is deliberately not matched because `statfs` cannot report the
/// backing subtype, so a local FUSE mount is never labelled remote.
#[cfg(target_os = "linux")]
fn check_filesystem_type(root: &Path) -> Result<(), CoreError> {
    let statfs = rustix::fs::statfs(root).map_err(|err| statfs_error(root, err))?;
    // Kernel superblock magics are 32-bit values. On ILP32 glibc `f_type` is a
    // signed word, so a CIFS magic arrives negative; the low 32 bits restore it.
    let magic = i128::from(statfs.f_type) & 0xFFFF_FFFF;
    match classify_linux_remote_magic(magic) {
        None => Ok(()),
        Some(name) => Err(forbidden(
            root,
            &format!("store root is on unsupported remote filesystem {name} (magic 0x{magic:x})"),
        )),
    }
}

/// Maps a `statfs` superblock magic to a remote network filesystem name. Values
/// come from Linux `linux/magic.h`; the set is the network filesystems only.
#[cfg(target_os = "linux")]
fn classify_linux_remote_magic(magic: i128) -> Option<&'static str> {
    const NFS_SUPER_MAGIC: i128 = 0x6969;
    const SMB_SUPER_MAGIC: i128 = 0x517B;
    const CIFS_SUPER_MAGIC: i128 = 0xFF53_4D42;
    const SMB2_SUPER_MAGIC: i128 = 0xFE53_4D42;
    const AFS_SUPER_MAGIC: i128 = 0x5346_414F;
    const AFS_FS_MAGIC: i128 = 0x6B41_4653;
    const NCP_SUPER_MAGIC: i128 = 0x564C;
    const CODA_SUPER_MAGIC: i128 = 0x7375_7245;
    const CEPH_SUPER_MAGIC: i128 = 0x00C3_6400;
    const V9FS_MAGIC: i128 = 0x0102_1997;
    match magic {
        NFS_SUPER_MAGIC => Some("NFS"),
        SMB_SUPER_MAGIC => Some("SMB"),
        CIFS_SUPER_MAGIC => Some("CIFS"),
        SMB2_SUPER_MAGIC => Some("SMB2/SMB3"),
        AFS_SUPER_MAGIC | AFS_FS_MAGIC => Some("AFS"),
        NCP_SUPER_MAGIC => Some("NCP"),
        CODA_SUPER_MAGIC => Some("Coda"),
        CEPH_SUPER_MAGIC => Some("CephFS"),
        V9FS_MAGIC => Some("9P"),
        _ => None,
    }
}

/// macOS: `f_fstypename` is matched against the named network filesystems only.
/// `MNT_LOCAL` is not used: it would also refuse a FUSE mount that lacks the
/// flag, which the contract forbids labelling without a reliable subtype.
#[cfg(target_vendor = "apple")]
fn check_filesystem_type(root: &Path) -> Result<(), CoreError> {
    let statfs = rustix::fs::statfs(root).map_err(|err| statfs_error(root, err))?;
    let name: Vec<u8> = statfs
        .f_fstypename
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| byte.to_ne_bytes()[0])
        .collect();
    match classify_apple_remote_name(&name) {
        None => Ok(()),
        Some(label) => Err(forbidden(
            root,
            &format!(
                "store root is on unsupported remote filesystem {label} ({})",
                String::from_utf8_lossy(&name)
            ),
        )),
    }
}

/// Maps a macOS `f_fstypename` to a remote network filesystem label.
#[cfg(target_vendor = "apple")]
fn classify_apple_remote_name(name: &[u8]) -> Option<&'static str> {
    match name {
        b"nfs" => Some("NFS"),
        b"smbfs" => Some("SMB"),
        b"afpfs" => Some("AFP"),
        b"webdav" => Some("WebDAV"),
        _ => None,
    }
}

/// Other Unix targets: no reliable, safe, command-free remote-filesystem
/// identification is wired here. This is the documented local-storage
/// prerequisite, not a positive claim that the filesystem is local.
#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn check_filesystem_type(_root: &Path) -> Result<(), CoreError> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn statfs_error(root: &Path, err: rustix::io::Errno) -> CoreError {
    match err.kind() {
        ErrorKind::NotFound => CoreError::new(
            ErrorCode::ENotFound,
            format!("store root is missing: {}", root.display()),
        ),
        _ => io_failure(root, "statfs store root", err),
    }
}

/// Removal tolerant of an absent entry; any other failure is `E_IO`.
fn tolerate_absent(path: &Path, result: io::Result<()>) -> Result<(), CoreError> {
    match result {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io_failure(path, "remove endpoint entry", err)),
    }
}

fn io_failure(path: &Path, op: &'static str, err: impl core::fmt::Display) -> CoreError {
    CoreError::new(ErrorCode::EIo, format!("{op} {}: {err}", path.display()))
}

fn forbidden(path: &Path, reason: &str) -> CoreError {
    CoreError::new(ErrorCode::EForbidden, format!("{reason}: {}", path.display()))
}

fn byte_len(path: &Path) -> usize {
    path.as_os_str().as_bytes().len()
}

fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(hex_byte(*byte));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{
        DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::oneshot;

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    /// Fresh base directory under `/tmp`. Short on every Unix target, so a long
    /// `TMPDIR` cannot push test socket paths past the portable limit.
    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new() -> Self {
            let path = PathBuf::from("/tmp").join(format!(
                "ruk-ep-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create test base directory");
            Self { path }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
    }

    fn unix_path(address: &EndpointAddress) -> &Path {
        match address {
            EndpointAddress::Unix(path) => path,
            EndpointAddress::Pipe(name) => panic!("unix endpoint published a pipe: {name}"),
        }
    }

    #[test]
    fn live_bind_connect_and_authenticated_uid() {
        let rt = runtime();
        let base = TestDir::new();
        rt.block_on(async {
            let endpoint =
                UnixEndpoint::bind_in(&base.path, StoreId::generate()).expect("bind endpoint");
            let address = endpoint.address().clone();
            let socket_type = std::fs::symlink_metadata(unix_path(&address))
                .expect("socket metadata")
                .file_type();
            assert!(socket_type.is_socket(), "published path must be a unix socket");

            let (uid_tx, uid_rx) = oneshot::channel();
            let server = tokio::spawn(async move {
                let stream = endpoint.accept().await.expect("accept client");
                let uid = peer_uid(&stream).expect("server sees client uid");
                uid_tx.send(uid).expect("report server-side uid");
                endpoint
            });

            let client = connect(&address).await.expect("connect");
            let euid = rustix::process::geteuid().as_raw();
            assert_eq!(peer_uid(&client).expect("client sees server uid"), euid);
            assert_eq!(uid_rx.await.expect("server-side uid"), euid);
            server
                .await
                .expect("join server task")
                .close()
                .expect("close endpoint");
        });
    }

    #[test]
    fn same_store_generations_are_isolated_and_drop_is_scoped() {
        let rt = runtime();
        let base = TestDir::new();
        rt.block_on(async {
            let store = StoreId::generate();
            let first = UnixEndpoint::bind_in(&base.path, store).expect("first generation");
            let second = UnixEndpoint::bind_in(&base.path, store).expect("second generation");
            assert_ne!(first.address(), second.address());

            let first_dir = first.dir.clone();
            let first_socket = first.socket_path.clone();
            let second_dir = second.dir.clone();
            let second_socket = second.socket_path.clone();
            drop(first);
            assert!(!first_socket.exists() && !first_dir.exists());
            assert!(second_socket.exists() && second_dir.exists());

            let address = second.address().clone();
            let server = tokio::spawn(async move {
                let stream = second.accept().await.expect("accept on surviving generation");
                (stream, second)
            });
            let _client = connect(&address).await.expect("connect surviving generation");
            let (_accepted, second) = server.await.expect("join");
            second.close().expect("close surviving generation");
            assert!(!second_socket.exists() && !second_dir.exists());
        });
    }

    #[test]
    fn socket_path_limit_is_checked_before_creation() {
        let rt = runtime();
        let base = TestDir::new();
        rt.block_on(async {
            let store = StoreId::generate();
            let probe = UnixEndpoint::bind_in(&base.path, store).expect("probe generation");
            let overhead = byte_len(unix_path(probe.address())) - byte_len(&base.path);
            probe.close().expect("close probe");

            // A base whose socket path is exactly at the limit must bind.
            let base_len = MAX_SOCKET_PATH_BYTES - overhead;
            let name_len = base_len
                .checked_sub(byte_len(&base.path) + 1)
                .filter(|len| *len > 0)
                .expect("temporary base leaves room for the boundary case");
            let at_limit_base = base.path.join("p".repeat(name_len));
            std::fs::create_dir(&at_limit_base).expect("create boundary base");
            let at_limit =
                UnixEndpoint::bind_in(&at_limit_base, store).expect("path at the limit binds");
            assert_eq!(byte_len(unix_path(at_limit.address())), MAX_SOCKET_PATH_BYTES);
            at_limit.close().expect("close boundary endpoint");

            // One byte longer must be refused, and nothing may be created inside.
            let over_base = at_limit_base.join("p");
            std::fs::create_dir(&over_base).expect("create over-limit base");
            let err = UnixEndpoint::bind_in(&over_base, store)
                .expect_err("path over the limit must be refused");
            assert_eq!(err.code, ErrorCode::ELimit);
            assert_eq!(
                std::fs::read_dir(&over_base).expect("read over-limit base").count(),
                0,
                "refusal must not create a generation directory"
            );
        });
    }

    #[test]
    fn close_removes_only_its_own_generation() {
        let rt = runtime();
        let base = TestDir::new();
        rt.block_on(async {
            let endpoint =
                UnixEndpoint::bind_in(&base.path, StoreId::generate()).expect("bind endpoint");
            let generation = endpoint.dir.clone();
            let socket = endpoint.socket_path.clone();
            endpoint.close().expect("close endpoint");
            assert!(!socket.exists() && !generation.exists());
            assert!(base.path.exists(), "the caller's base directory is never removed");
        });
    }

    #[test]
    fn generation_directory_is_private_and_owned() {
        let rt = runtime();
        let base = TestDir::new();
        rt.block_on(async {
            let endpoint =
                UnixEndpoint::bind_in(&base.path, StoreId::generate()).expect("bind endpoint");
            let meta = std::fs::symlink_metadata(&endpoint.dir).expect("generation metadata");
            assert!(meta.is_dir() && !meta.file_type().is_symlink());
            assert_eq!(meta.uid(), rustix::process::geteuid().as_raw());
            assert_eq!(meta.mode() & 0o077, 0, "no group or other permissions");
            endpoint.close().expect("close endpoint");
        });
    }

    #[test]
    fn verification_refuses_symlinks_and_shared_modes() {
        let base = TestDir::new();
        let private = base.path.join("private");
        DirBuilder::new()
            .mode(0o700)
            .create(&private)
            .expect("create private directory");
        verify_generation_dir(&private).expect("private owned directory verifies");

        let shared = base.path.join("shared");
        std::fs::create_dir(&shared).expect("create shared directory");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o750))
            .expect("set group-readable mode");
        assert_eq!(
            verify_generation_dir(&shared)
                .expect_err("group access must be refused")
                .code,
            ErrorCode::EForbidden
        );

        let link = base.path.join("link");
        std::os::unix::fs::symlink(&private, &link).expect("create symlink");
        assert_eq!(
            verify_generation_dir(&link)
                .expect_err("symlink must be refused")
                .code,
            ErrorCode::EForbidden
        );
    }

    #[test]
    fn connect_refuses_named_pipe_addresses() {
        let rt = runtime();
        rt.block_on(async {
            let pipe = EndpointAddress::Pipe(r"\\.\pipe\ruk-test".to_owned());
            let err = connect(&pipe).await.expect_err("pipe address on unix");
            assert_eq!(err.code, ErrorCode::EInvalid);
        });
    }

    #[test]
    fn connect_failures_are_retryable_io_with_kind_in_message() {
        let rt = runtime();
        let base = TestDir::new();
        let missing = EndpointAddress::Unix(base.path.join("absent-socket"));
        rt.block_on(async {
            let err = connect(&missing).await.expect_err("no listener");
            assert_eq!(err.code, ErrorCode::EIo);
            assert!(err.message.contains("NotFound"), "message: {}", err.message);
        });
    }

    #[test]
    fn local_storage_check_distinguishes_missing_file_and_directory() {
        let base = TestDir::new();
        ensure_local_storage(&base.path).expect("local directory is accepted");
        assert_eq!(
            ensure_local_storage(&base.path.join("absent"))
                .expect_err("missing root")
                .code,
            ErrorCode::ENotFound
        );
        let file = base.path.join("file");
        std::fs::write(&file, b"x").expect("write file");
        assert_eq!(
            ensure_local_storage(&file).expect_err("file root").code,
            ErrorCode::EInvalid
        );
    }

    #[test]
    fn production_bind_uses_temp_dir_or_refuses_overlong_base() {
        let rt = runtime();
        rt.block_on(async {
            match UnixEndpoint::bind(StoreId::generate()) {
                Ok(endpoint) => {
                    let generation = unix_path(endpoint.address())
                        .parent()
                        .expect("generation directory")
                        .to_path_buf();
                    assert_eq!(generation.parent(), Some(std::env::temp_dir().as_path()));
                    endpoint.close().expect("close production endpoint");
                }
                Err(err) => assert!(
                    matches!(err.code, ErrorCode::ELimit | ErrorCode::EInvalid),
                    "unexpected refusal: {err}"
                ),
            }
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_remote_magic_classification() {
        for remote in [
            0x6969_i128,
            0x517B,
            0xFF53_4D42,
            0xFE53_4D42,
            0x5346_414F,
            0x6B41_4653,
            0x564C,
            0x7375_7245,
            0x00C3_6400,
            0x0102_1997,
        ] {
            assert!(classify_linux_remote_magic(remote).is_some(), "0x{remote:x}");
        }
        for local in [
            0xEF53_i128, // ext2/3/4
            0x0102_1994, // tmpfs
            0x9123_683E, // btrfs
            0x5846_5342, // xfs
            0x794C_7630, // overlayfs
            0x6573_5546, // fuse: never labelled remote without a subtype
        ] {
            assert_eq!(classify_linux_remote_magic(local), None, "0x{local:x}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_native_base_path_round_trips() {
        let rt = runtime();
        let base = TestDir::new();
        let non_utf8 = base.path.join(OsString::from_vec(b"u\xff\xfe".to_vec()));
        std::fs::create_dir(&non_utf8).expect("create non-UTF-8 base");
        rt.block_on(async {
            let endpoint =
                UnixEndpoint::bind_in(&non_utf8, StoreId::generate()).expect("bind non-UTF-8");
            let address = endpoint.address().clone();
            assert!(
                unix_path(&address)
                    .as_os_str()
                    .as_bytes()
                    .windows(2)
                    .any(|pair| pair[0] == 0xff && pair[1] == 0xfe),
                "native bytes must survive into the published path"
            );
            let server = tokio::spawn(async move {
                let stream = endpoint.accept().await.expect("accept");
                (peer_uid(&stream), endpoint)
            });
            let client = connect(&address).await.expect("connect non-UTF-8 socket");
            let euid = rustix::process::geteuid().as_raw();
            assert_eq!(peer_uid(&client).expect("client uid"), euid);
            let (server_uid, endpoint) = server.await.expect("join");
            assert_eq!(server_uid.expect("server uid"), euid);
            endpoint.close().expect("close non-UTF-8 endpoint");
        });
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn apple_remote_name_classification() {
        assert_eq!(classify_apple_remote_name(b"nfs"), Some("NFS"));
        assert_eq!(classify_apple_remote_name(b"smbfs"), Some("SMB"));
        assert_eq!(classify_apple_remote_name(b"apfs"), None);
        assert_eq!(classify_apple_remote_name(b"osxfuse"), None);
    }
}
