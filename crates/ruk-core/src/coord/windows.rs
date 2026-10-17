//! Windows native coordinator platform support: atomic owner-only DACL
//! creation, LockFileEx sentinel range locking, local named pipes, peer
//! token inspection, and filesystem storage validation.
//!
//! # Unsafe and Security Boundary
//!
//! This module is the sole location in `coord` where Windows FFI operations
//! occur. All unsafe blocks are confined to private, audited helper functions
//! annotated with narrowly-scoped `#[expect(unsafe_code, reason = "...")]`
//! attributes and detailed `SAFETY:` rationale.
//!
//! Core security invariants:
//! 1. **Atomic owner-only DACL**: New lock files and named pipes are created
//!    with an explicit owner-only protected DACL (`SE_DACL_PROTECTED`) granting
//!    full access only to the process user SID. Inherited permissions are never
//!    assumed to be private.
//! 2. **Handle validation before use**: Opened lock file handles are verified
//!    via `GetFileInformationByHandle` and `GetSecurityInfo` to be regular disk
//!    files with exactly one hardlink, no reparse point / symlink / junction,
//!    owned by the process user, and with a protected DACL granting access to no
//!    other SID.
//! 3. **Fail-closed thread impersonation**: Named pipe peer inspection uses
//!    `ImpersonateNamedPipeClient` with a non-`Send` RAII guard that restores
//!    unimpersonated thread state (`RevertToSelf`) on all returns and unwinds.
//!    If reversion or subsequent thread verification fails, the process aborts
//!    immediately to prevent contaminated workers returning to the threadpool.
//! 4. **Storage locality**: Storage paths are audited to reject remote filesystems
//!    (UNC paths, mapped remote drives) before authoritative operations proceed.

use std::fs::File;
use std::io;
use std::marker::PhantomData;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, HandleOrInvalid, OwnedHandle, RawHandle};
use std::path::{Component, Path, PathBuf, Prefix};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, BOOL, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
    ERROR_CANNOT_IMPERSONATE, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_LOCK_VIOLATION, ERROR_NOT_SUPPORTED,
    ERROR_NO_DATA, ERROR_NO_TOKEN, ERROR_PATH_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    HANDLE, HLOCAL, INVALID_HANDLE_VALUE, WIN32_ERROR,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorControl,
    GetTokenInformation, IsValidAcl, IsValidSid, RevertToSelf, ACCESS_ALLOWED_ACE,
    ACCESS_ALLOWED_ACE_TYPE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE, PSID,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR_CONTROL, SE_DACL_PRESENT,
    SE_DACL_PROTECTED, TOKEN_ACCESS_MASK, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDiskFreeSpaceExW, GetDriveTypeW, GetFileInformationByHandle, GetFileType,
    LockFileEx, UnlockFileEx, BY_HANDLE_FILE_INFORMATION, DRIVE_REMOTE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TYPE_DISK, GENERIC_READ, GENERIC_WRITE, LOCKFILE_EXCLUSIVE_LOCK,
    LOCKFILE_FAIL_IMMEDIATELY, OPEN_ALWAYS, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use crate::error::{CoreError, ErrorCode};
use crate::ids::hex_byte;
use crate::StoreId;

/// Offset in bytes where the exclusive sentinel lock is placed.
///
/// Bytes 0..512 contain the published [`crate::coord::lock::LockBody`] and
/// remain readable to contenders while the sentinel lock is held.
pub(crate) const LOCK_SENTINEL_OFFSET: u64 = 1024 * 1024; // 1 MiB

/// Length in bytes of the sentinel lock range.
pub(crate) const LOCK_SENTINEL_LENGTH: u64 = 1;

/// Exact local named pipe prefix. Remote servers are never addressed.
pub(crate) const LOCAL_PIPE_PREFIX: &str = r"\\.\pipe\";

/// Space available and total capacity for a filesystem path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FilesystemSpace {
    pub(crate) available_bytes: u64,
    pub(crate) total_bytes: u64,
}

/// Nature of positive remote storage evidence detected for a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoteStorageEvidence {
    /// Path uses UNC syntax (`\\server\share` or `\\?\UNC\server\share`).
    UncPath,
    /// Path is located on a mapped network drive.
    RemoteDrive(char),
}

/// Mode for opening a coordinator lock file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockOpenMode {
    /// Atomic create-or-open with owner-only DACL for ownership acquisition.
    CreateOrOpen,
    /// Open existing read-only for contender body inspection.
    OpenExisting,
}

// ---------------------------------------------------------------------------
// Public safe APIs
// ---------------------------------------------------------------------------

/// Queries the security identifier (SID) of the current process user token.
///
/// Formatted as standard string representation (e.g. `S-1-5-21-...`).
pub(crate) fn current_sid() -> Result<String, CoreError> {
    let process_token = open_current_process_token()?;
    let user_sid = query_token_user_sid(process_token.as_raw_handle())?;
    sid_to_string(user_sid.as_psid())
}

/// Inspects the connected client SID of a named pipe server.
///
/// # Preconditions
/// This function must be called **only** after client data (e.g. the HMAC handshake
/// proof) has been successfully read from the connected `NamedPipeServer`. Windows
/// `ImpersonateNamedPipeClient` fails with `ERROR_CANNOT_IMPERSONATE` if called
/// before data has been read on the pipe instance.
///
/// # Fail-closed Guarantee
/// Impersonation is conducted under a strict non-`Send` RAII guard. Before
/// impersonation, the thread must have no impersonation token (`ERROR_NO_TOKEN`).
/// On return or unwind, the guard calls `RevertToSelf` and confirms that
/// `OpenThreadToken` again reports `ERROR_NO_TOKEN`. If reversion or cleanup fails,
/// the process aborts immediately.
pub(crate) fn pipe_peer_sid(
    server: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Result<String, CoreError> {
    // 1. Thread must not already be impersonating.
    if thread_has_impersonation_token()? {
        return Err(CoreError::new(
            ErrorCode::EIo,
            "cannot inspect pipe peer SID: worker thread already holds an impersonation token",
        ));
    }

    // 2. Impersonate and query under fail-closed reversion guard.
    let raw_pipe = server.as_raw_handle() as HANDLE;
    impersonate_and_query_peer_sid(raw_pipe)
}

/// Checks whether storage for `path` is local and durable, refusing positive
/// remote storage evidence.
pub(crate) fn ensure_local_storage(path: &Path) -> Result<(), CoreError> {
    let Some(evidence) = detect_remote_storage(path)? else {
        return Ok(());
    };

    let detail = match evidence {
        RemoteStorageEvidence::UncPath => "UNC path detected".to_string(),
        RemoteStorageEvidence::RemoteDrive(c) => format!("remote mapped drive '{c}:' detected"),
    };
    Err(CoreError::new(
        ErrorCode::EForbidden,
        format!(
            "remote storage is not supported for authoritative store {}: {detail}",
            path.display()
        ),
    ))
}

/// Queries free and total filesystem space for a directory.
pub(crate) fn filesystem_space(path: &Path) -> Result<FilesystemSpace, CoreError> {
    let wide = to_wide_dir_path(path)?;
    let mut free_available: u64 = 0;
    let mut total: u64 = 0;
    let mut total_free: u64 = 0;

    let ok = get_disk_free_space_ex_raw(
        wide.as_ptr(),
        &mut free_available,
        &mut total,
        &mut total_free,
    );
    if ok == 0 {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(code)
                if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32 =>
            {
                Err(CoreError::new(
                    ErrorCode::ENotFound,
                    format!("filesystem path not found: {}", path.display()),
                ))
            }
            _ => Err(CoreError::new(
                ErrorCode::EIo,
                format!("query filesystem space {}: {err}", path.display()),
            )),
        };
    }

    Ok(FilesystemSpace {
        available_bytes: free_available,
        total_bytes: total,
    })
}

/// Detects whether `path` points to remote storage (UNC or mapped remote drive).
///
/// Local verbatim paths (e.g. `\\?\C:\...`) are explicitly recognized as local.
pub(crate) fn detect_remote_storage(
    path: &Path,
) -> Result<Option<RemoteStorageEvidence>, CoreError> {
    // 1. Lexical prefix check on the raw input path.
    if let Some(evidence) = classify_path_prefix(path) {
        return Ok(Some(evidence));
    }

    // 2. Canonicalize path to resolve junctions, symlinks, or mapped drive letters.
    let canonical = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(CoreError::new(
                ErrorCode::ENotFound,
                format!("store path not found: {}", path.display()),
            ));
        }
        Err(err) => {
            return Err(CoreError::new(
                ErrorCode::EIo,
                format!("canonicalize path {}: {err}", path.display()),
            ));
        }
    };

    // 3. Lexical prefix check on canonicalized path.
    if let Some(evidence) = classify_path_prefix(&canonical) {
        return Ok(Some(evidence));
    }

    Ok(None)
}

/// Opens the lock file at `path` with appropriate access, share mode, and security.
///
/// # Security
/// - When creating, an atomic owner-only protected DACL is applied.
/// - Does NOT use `FILE_SHARE_DELETE` (prevents deletion or renaming while open).
/// - Uses `FILE_FLAG_OPEN_REPARSE_POINT` to prevent silently traversing symlinks.
pub(crate) fn open_lock_file(path: &Path, mode: LockOpenMode) -> Result<File, CoreError> {
    let wide_path = to_wide_path(path)?;

    let raw_handle = match mode {
        LockOpenMode::CreateOrOpen => {
            let descriptor = OwnerOnlyDescriptor::create()?;
            open_file_raw(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, // NO FILE_SHARE_DELETE
                Some(&descriptor.security_attributes()),
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            )?
        }
        LockOpenMode::OpenExisting => open_file_raw(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, // NO FILE_SHARE_DELETE
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        )?,
    };

    Ok(adopt_raw_file(raw_handle))
}

#[expect(unsafe_code, reason = "adopt verified exclusively-owned Win32 file handle into std::fs::File")]
fn adopt_raw_file(handle: HANDLE) -> File {
    // SAFETY: handle was returned by CreateFileW, verified != INVALID_HANDLE_VALUE,
    // is exclusively owned by this process, and safely transferred to std::fs::File.
    unsafe { File::from_raw_handle(handle as RawHandle) }
}

#[expect(unsafe_code, reason = "adopt verified Win32 token handle into OwnedHandle")]
fn adopt_raw_handle(handle: HANDLE) -> Result<OwnedHandle, CoreError> {
    // SAFETY: handle is a valid non-null kernel handle.
    let h = unsafe { HandleOrInvalid::from_raw_handle(handle as RawHandle) };
    OwnedHandle::try_from(h).map_err(|_| CoreError::new(ErrorCode::EIo, "invalid kernel handle"))
}

/// Takes an immediate, nonblocking exclusive LockFileEx lock on the sentinel range (offset 1 MiB).
///
/// Returns `Ok(true)` if lock acquired, `Ok(false)` on contention (`ERROR_LOCK_VIOLATION`).
pub(crate) fn lock_exclusive_range(file: &File) -> Result<bool, CoreError> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut overlapped = OVERLAPPED::default();
    overlapped.Anonymous.Anonymous.Offset = LOCK_SENTINEL_OFFSET as u32;
    overlapped.Anonymous.Anonymous.OffsetHigh = (LOCK_SENTINEL_OFFSET >> 32) as u32;

    let ok = lock_file_ex_raw(
        handle,
        LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
        0,
        LOCK_SENTINEL_LENGTH as u32,
        0,
        &mut overlapped,
    );

    if ok != 0 {
        return Ok(true);
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        Ok(false)
    } else {
        Err(CoreError::new(
            ErrorCode::EIo,
            format!("lock sentinel range: {err}"),
        ))
    }
}

/// Releases the sentinel LockFileEx range previously acquired on `file`.
pub(crate) fn unlock_exclusive_range(file: &File) -> Result<(), CoreError> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut overlapped = OVERLAPPED::default();
    overlapped.Anonymous.Anonymous.Offset = LOCK_SENTINEL_OFFSET as u32;
    overlapped.Anonymous.Anonymous.OffsetHigh = (LOCK_SENTINEL_OFFSET >> 32) as u32;

    let ok = unlock_file_ex_raw(
        handle,
        0,
        LOCK_SENTINEL_LENGTH as u32,
        0,
        &mut overlapped,
    );

    if ok != 0 {
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        Err(CoreError::new(
            ErrorCode::EIo,
            format!("unlock sentinel range: {err}"),
        ))
    }
}

/// Audits an opened lock file handle against hostile filesystem and security configurations.
///
/// Refuses:
/// - Non-disk files (e.g. named pipes or character devices).
/// - Directories.
/// - Reparse points (symlinks, junctions, mounts).
/// - Files with more than one hardlink.
/// - Files not owned by the current process user SID.
/// - Absent or null DACLs.
/// - Unprotected DACLs (`SE_DACL_PROTECTED` not set).
/// - DACLs containing ACEs granting access to other SIDs or unsupported ACE types.
pub(crate) fn validate_lock_file(file: &File, path: &Path) -> Result<(), CoreError> {
    let handle = file.as_raw_handle() as HANDLE;

    // 1. Must be a disk file.
    let file_type = get_file_type_raw(handle);
    if file_type != FILE_TYPE_DISK {
        return Err(forbidden(path, "ownership lock is not a disk file"));
    }

    // 2. Query file information by handle.
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let ok = get_file_info_raw(handle, &mut info);
    if ok == 0 {
        return Err(io_error(path, "get file information", io::Error::last_os_error()));
    }

    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(forbidden(path, "ownership lock is a directory"));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(forbidden(path, "ownership lock is a reparse point or symlink"));
    }
    if info.nNumberOfLinks != 1 {
        return Err(forbidden(path, "ownership lock has more than one hard link"));
    }

    // 3. Security descriptor inspection.
    let process_sid = query_current_process_sid()?;
    audit_handle_security(handle, path, &process_sid)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PipeInstanceKind {
    First,
    Subsequent,
}

/// Creates the initial (first) named pipe server instance with owner-only
/// protected DACL, enforcing `FILE_FLAG_FIRST_PIPE_INSTANCE` to prevent
/// server-side namespace squatting.
pub(crate) fn create_first_pipe_server(
    name: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, io::Error> {
    create_pipe_server_inner(name, PipeInstanceKind::First)
}

/// Creates a subsequent named pipe server instance on an already-bound
/// pipe name with owner-only protected DACL and remote clients rejected.
pub(crate) fn create_subsequent_pipe_server(
    name: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, io::Error> {
    create_pipe_server_inner(name, PipeInstanceKind::Subsequent)
}

#[expect(unsafe_code, reason = "create named pipe server with owner-only SECURITY_ATTRIBUTES")]
fn create_pipe_server_inner(
    name: &str,
    kind: PipeInstanceKind,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, io::Error> {
    validate_pipe_address(name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.message))?;

    let descriptor = OwnerOnlyDescriptor::create()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.message))?;
    let mut sa = descriptor.security_attributes();

    let mut opts = tokio::net::windows::named_pipe::ServerOptions::new();
    opts.first_pipe_instance(matches!(kind, PipeInstanceKind::First));
    opts.reject_remote_clients(true);
    opts.access_inbound(true);
    opts.access_outbound(true);
    opts.pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte);

    // SAFETY:
    // - `name` is a validated local pipe address (`\\.\pipe\...`).
    // - `sa` is an aligned local stack variable initialized with a valid
    //   `PSECURITY_DESCRIPTOR` owned by `descriptor` (`LocalMem`).
    // - Memory remains allocated and immutable for the duration of the FFI call.
    unsafe {
        opts.create_with_security_attributes_raw(
            name,
            &mut sa as *mut SECURITY_ATTRIBUTES as *mut core::ffi::c_void,
        )
    }
}

/// Generates an unpredictable, local named pipe path bound to `store_id`.
pub(crate) fn generate_pipe_name(store_id: StoreId) -> Result<String, CoreError> {
    let mut random_bytes = [0u8; 16];
    getrandom::fill(&mut random_bytes)
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("generate pipe randomness: {err}")))?;

    let mut hex_suffix = String::with_capacity(32);
    for b in random_bytes {
        hex_suffix.push_str(hex_byte(b));
    }

    let pipe_path = format!(r"{LOCAL_PIPE_PREFIX}ruk-{store_id}-{hex_suffix}");
    validate_pipe_address(&pipe_path)?;
    Ok(pipe_path)
}

/// Validates that a named pipe path uses the exact local prefix, valid ASCII
/// name characters, and contains no remote server names or traversal elements.
pub(crate) fn validate_pipe_address(addr: &str) -> Result<(), CoreError> {
    if !addr.starts_with(LOCAL_PIPE_PREFIX) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!("named pipe address must start with local prefix '{LOCAL_PIPE_PREFIX}': {addr}"),
        ));
    }

    let name = &addr[LOCAL_PIPE_PREFIX.len()..];
    if name.is_empty() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "named pipe name cannot be empty",
        ));
    }
    if name.len() > 200 {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "named pipe name exceeds 200 characters",
        ));
    }

    if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!("named pipe contains forbidden path separators or traversal elements: {name}"),
        ));
    }

    for b in name.bytes() {
        if !b.is_ascii_alphanumeric() && b != b'-' && b != b'_' && b != b'.' {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("named pipe name contains forbidden character '{}'", b as char),
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private RAII wrappers
// ---------------------------------------------------------------------------

/// RAII wrapper for LocalAlloc allocations freed via `LocalFree`.
struct LocalMem {
    ptr: HLOCAL,
}

impl LocalMem {
    /// Adopts a non-null `HLOCAL` allocation.
    fn adopt(ptr: HLOCAL) -> Self {
        assert!(!ptr.is_null(), "cannot adopt null HLOCAL");
        Self { ptr }
    }

    fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.ptr
    }
}

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: self.ptr was adopted from a valid LocalAlloc call.
            #[expect(unsafe_code, reason = "LocalFree deallocation of Win32 memory")]
            unsafe {
                LocalFree(self.ptr);
            }
        }
    }
}

/// Owned 4-byte (DWORD) aligned storage for a Windows SID.
///
/// Win32 SID structures contain a `SubAuthority: [DWORD; 1]` array and require
/// 4-byte alignment when passed to APIs such as `EqualSid` and
/// `ConvertSidToStringSidW`. Storing as `Vec<u32>` guarantees proper alignment.
#[derive(Clone, PartialEq, Eq)]
struct OwnedSid {
    words: Vec<u32>,
    byte_len: usize,
}

impl OwnedSid {
    #[expect(unsafe_code, reason = "copy verified SID bytes into aligned Vec<u32>")]
    fn from_raw_sid(psid: PSID, byte_len: usize) -> Result<Self, CoreError> {
        if byte_len < 8 {
            return Err(CoreError::new(ErrorCode::EIo, "SID byte buffer is too short"));
        }
        let word_count = (byte_len + 3) / 4;
        let mut words = vec![0u32; word_count];
        // SAFETY: psid is verified valid and points to at least byte_len bytes;
        // words is sized for word_count * 4 >= byte_len bytes and 4-byte aligned.
        unsafe {
            core::ptr::copy_nonoverlapping(
                psid as *const u8,
                words.as_mut_ptr() as *mut u8,
                byte_len,
            );
        }
        let sid = Self { words, byte_len };
        if is_valid_sid_raw(sid.as_psid()) == 0 {
            return Err(CoreError::new(ErrorCode::EIo, "SID validation failed"));
        }
        Ok(sid)
    }

    fn as_psid(&self) -> PSID {
        self.words.as_ptr() as PSID
    }
}

/// Manages an owner-only, protected DACL security descriptor.
struct OwnerOnlyDescriptor {
    _mem: LocalMem,
    psd: PSECURITY_DESCRIPTOR,
}

impl OwnerOnlyDescriptor {
    fn create() -> Result<Self, CoreError> {
        let sid_str = current_sid()?;
        validate_sid_string(&sid_str)?;

        // SDDL: Owner = SID, DACL Protected, Allow FILE_ALL_ACCESS to SID
        let sddl = format!("O:{sid_str}D:P(A;;FA;;;{sid_str})");
        let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(core::iter::once(0)).collect();

        let mut psd: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
        let mut sd_size: u32 = 0;

        let ok = convert_string_sd_to_sd_raw(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            &mut sd_size,
        );
        if ok == 0 || psd.is_null() {
            let err = io::Error::last_os_error();
            return Err(CoreError::new(
                ErrorCode::EIo,
                format!("convert SDDL to security descriptor: {err}"),
            ));
        }

        let mem = LocalMem::adopt(psd as HLOCAL);
        Ok(Self { _mem: mem, psd })
    }

    fn security_attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.psd,
            bInheritHandle: 0, // FALSE: handle is not inherited by child processes
        }
    }
}

/// RAII reversion guard ensuring unimpersonated thread state is restored.
///
/// Marked `!Send` and `!Sync` to prevent moving across threads.
struct ImpersonationGuard {
    active: bool,
    _marker: PhantomData<*mut ()>,
}

impl ImpersonationGuard {
    fn arm() -> Self {
        Self {
            active: true,
            _marker: PhantomData,
        }
    }

    fn disarm(mut self) {
        self.active = false;
        revert_and_verify_clean_thread();
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            revert_and_verify_clean_thread();
        }
    }
}

fn revert_and_verify_clean_thread() {
    let ok = revert_to_self_raw();
    if ok == 0 {
        // Cannot revert to self: fail-closed to prevent dirty impersonation escaping.
        std::process::abort();
    }

    // Verify the thread now has NO token.
    match thread_has_impersonation_token() {
        Ok(false) => {}
        _ => {
            // Either thread still has a token or query failed: abort process.
            std::process::abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Security and Token Inspection Helpers
// ---------------------------------------------------------------------------

fn open_current_process_token() -> Result<OwnedHandle, CoreError> {
    let mut token: HANDLE = core::ptr::null_mut();
    let ok = open_process_token_raw(get_current_process_raw(), TOKEN_QUERY, &mut token);
    if ok == 0 || token.is_null() {
        let err = io::Error::last_os_error();
        return Err(CoreError::new(
            ErrorCode::EIo,
            format!("open current process token: {err}"),
        ));
    }
    adopt_raw_handle(token)
}

fn thread_has_impersonation_token() -> Result<bool, CoreError> {
    let mut token: HANDLE = core::ptr::null_mut();
    let ok = open_thread_token_raw(get_current_thread_raw(), TOKEN_QUERY, 1, &mut token);
    if ok != 0 {
        // SAFETY: token is valid; close it immediately.
        close_handle_raw(token);
        return Ok(true);
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_NO_TOKEN as i32) {
        Ok(false)
    } else {
        Err(CoreError::new(
            ErrorCode::EIo,
            format!("query thread impersonation token: {err}"),
        ))
    }
}

fn query_current_process_sid() -> Result<OwnedSid, CoreError> {
    let token = open_current_process_token()?;
    query_token_user_sid(token.as_raw_handle())
}

#[expect(unsafe_code, reason = "read aligned TOKEN_USER struct and copy validated SID bytes")]
fn query_token_user_sid(token_handle: RawHandle) -> Result<OwnedSid, CoreError> {
    let handle = token_handle as HANDLE;
    let mut required_len: u32 = 0;

    // First call to discover buffer size.
    let _ = get_token_information_raw(
        handle,
        TokenUser,
        core::ptr::null_mut(),
        0,
        &mut required_len,
    );
    let last_err = io::Error::last_os_error();
    if last_err.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(CoreError::new(
            ErrorCode::EIo,
            format!("query token information length: {last_err}"),
        ));
    }

    // Allocate 8-byte aligned memory using Vec<u64>.
    let words = (required_len as usize + 7) / 8;
    let mut buffer: Vec<u64> = vec![0u64; words];
    let mut returned_len: u32 = 0;

    let ok = get_token_information_raw(
        handle,
        TokenUser,
        buffer.as_mut_ptr() as *mut core::ffi::c_void,
        (words * 8) as u32,
        &mut returned_len,
    );
    if ok == 0 {
        let err = io::Error::last_os_error();
        return Err(CoreError::new(
            ErrorCode::EIo,
            format!("query token user: {err}"),
        ));
    }

    // SAFETY: buffer is 8-byte aligned and populated with TOKEN_USER.
    let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let psid = token_user.User.Sid;
    if psid.is_null() {
        return Err(CoreError::new(ErrorCode::EIo, "null SID in token user"));
    }

    // Validate bounds: SID pointer must be within the returned buffer range.
    let buf_start = buffer.as_ptr() as usize;
    let buf_end = buf_start + returned_len as usize;
    let sid_addr = psid as usize;
    if sid_addr < buf_start || sid_addr >= buf_end {
        return Err(CoreError::new(ErrorCode::EIo, "SID pointer outside buffer"));
    }

    if is_valid_sid_raw(psid) == 0 {
        return Err(CoreError::new(ErrorCode::EIo, "invalid SID in token"));
    }

    let sid_len = usize::try_from(get_length_sid_raw(psid))
        .map_err(|_| CoreError::new(ErrorCode::EIo, "SID length overflow"))?;
    if sid_addr.checked_add(sid_len).map_or(true, |end| end > buf_end) {
        return Err(CoreError::new(ErrorCode::EIo, "SID length exceeds buffer"));
    }

    OwnedSid::from_raw_sid(psid, sid_len)
}

fn impersonate_and_query_peer_sid(pipe: HANDLE) -> Result<String, CoreError> {
    let ok = impersonate_named_pipe_client_raw(pipe);
    if ok == 0 {
        let err = io::Error::last_os_error();
        return Err(CoreError::new(
            ErrorCode::EIo,
            format!("impersonate named pipe client: {err}"),
        ));
    }

    // Arm fail-closed guard immediately.
    let guard = ImpersonationGuard::arm();

    // Query thread token under impersonation (OpenAsSelf = 1).
    let mut thread_token: HANDLE = core::ptr::null_mut();
    let ok = open_thread_token_raw(get_current_thread_raw(), TOKEN_QUERY, 1, &mut thread_token);
    if ok == 0 || thread_token.is_null() {
        let err = io::Error::last_os_error();
        // Guard drops on return, reverting impersonation.
        return Err(CoreError::new(
            ErrorCode::EIo,
            format!("open thread token under impersonation: {err}"),
        ));
    }

    let owned_thread_token = adopt_raw_handle(thread_token)?;

    let peer_sid = query_token_user_sid(owned_thread_token.as_raw_handle())?;
    let sid_str = sid_to_string(peer_sid.as_psid())?;

    drop(owned_thread_token);
    guard.disarm();

    Ok(sid_str)
}

fn audit_handle_security(
    handle: HANDLE,
    path: &Path,
    expected_owner: &OwnedSid,
) -> Result<(), CoreError> {
    let mut psid_owner: PSID = core::ptr::null_mut();
    let mut pdacl: *mut ACL = core::ptr::null_mut();
    let mut psd: PSECURITY_DESCRIPTOR = core::ptr::null_mut();

    let ret = get_security_info_raw(
        handle,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &mut psid_owner,
        core::ptr::null_mut(),
        &mut pdacl,
        core::ptr::null_mut(),
        &mut psd,
    );

    if ret != 0 {
        if ret == ERROR_NOT_SUPPORTED || ret == ERROR_INVALID_FUNCTION {
            return Err(forbidden(path, "filesystem does not support security descriptors / DACLs"));
        }
        return Err(io_error(path, "get security info", io::Error::from_raw_os_error(ret as i32)));
    }
    if psd.is_null() {
        return Err(forbidden(path, "null security descriptor"));
    }

    let _sd_guard = LocalMem::adopt(psd as HLOCAL);

    // Verify SE_DACL_PRESENT and SE_DACL_PROTECTED control flags.
    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    let ok = get_security_descriptor_control_raw(psd, &mut control, &mut revision);
    if ok == 0 {
        return Err(io_error(path, "get security descriptor control", io::Error::last_os_error()));
    }

    if control & SE_DACL_PRESENT == 0 || pdacl.is_null() {
        return Err(forbidden(path, "ownership lock has a null DACL (unrestricted access)"));
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err(forbidden(path, "ownership lock DACL is not protected against inheritance"));
    }

    // Verify owner SID matches expected process user SID.
    if psid_owner.is_null() || is_valid_sid_raw(psid_owner) == 0 {
        return Err(forbidden(path, "ownership lock has an invalid owner SID"));
    }
    if equal_sid_raw(psid_owner, expected_owner.as_psid()) == 0 {
        return Err(forbidden(path, "ownership lock is not owned by the current process user"));
    }

    // Verify DACL validity and examine every ACE.
    if is_valid_acl_raw(pdacl) == 0 {
        return Err(forbidden(path, "ownership lock DACL is invalid"));
    }

    let mut size_info = ACL_SIZE_INFORMATION::default();
    let ok = get_acl_size_info_raw(
        pdacl,
        &mut size_info as *mut _ as *mut core::ffi::c_void,
        core::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    );
    if ok == 0 {
        return Err(io_error(path, "get ACL size info", io::Error::last_os_error()));
    }

    // Iterate through all ACEs in the DACL.
    for i in 0..size_info.AceCount {
        let mut pace: *mut core::ffi::c_void = core::ptr::null_mut();
        let ok = get_ace_raw(pdacl, i, &mut pace);
        if ok == 0 || pace.is_null() {
            return Err(forbidden(path, "unable to read ACE in ownership lock DACL"));
        }
        audit_single_ace(pace, path, expected_owner)?;
    }

    Ok(())
}

#[expect(unsafe_code, reason = "dereference verified aligned ACE pointer from GetAce")]
fn audit_single_ace(
    pace: *mut core::ffi::c_void,
    path: &Path,
    expected_owner: &OwnedSid,
) -> Result<(), CoreError> {
    // Alignment check for ACE_HEADER (requires 2-byte alignment).
    if (pace as usize) % core::mem::align_of::<ACE_HEADER>() != 0 {
        return Err(forbidden(path, "misaligned ACE header in DACL"));
    }

    // SAFETY: pace is verified non-null, aligned to align_of::<ACE_HEADER>(),
    // and points to valid ACE memory within the DACL returned by GetAce.
    let header = unsafe { *(pace as *const ACE_HEADER) };

    // Only allow ACCESS_ALLOWED_ACE_TYPE. Fail closed on deny or unsupported types.
    if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
        return Err(forbidden(
            path,
            "ownership lock DACL contains non-allow or unsupported ACE type",
        ));
    }

    // Inheritance flags allowed: OBJECT_INHERIT, CONTAINER_INHERIT, NO_PROPAGATE, INHERIT_ONLY.
    let allowed_flags = (OBJECT_INHERIT_ACE
        | CONTAINER_INHERIT_ACE
        | NO_PROPAGATE_INHERIT_ACE
        | INHERIT_ONLY_ACE) as u8;
    if header.AceFlags & !allowed_flags != 0 {
        return Err(forbidden(
            path,
            "ownership lock DACL ACE contains unsupported flags",
        ));
    }

    // ACCESS_ALLOWED_ACE requires 4-byte alignment (Mask is u32).
    if (pace as usize) % core::mem::align_of::<u32>() != 0 {
        return Err(forbidden(path, "misaligned ACCESS_ALLOWED_ACE in DACL"));
    }
    let ace_size = usize::from(header.AceSize);
    if ace_size < 12 {
        return Err(forbidden(
            path,
            "ACCESS_ALLOWED_ACE size is smaller than header",
        ));
    }

    // SID starts at offset 8 within ACCESS_ALLOWED_ACE.
    // SAFETY: pace is valid for header.AceSize bytes; offset 8 is within the verified ace_size >= 12.
    let ace_sid = unsafe { (pace as *const u8).add(8) as PSID };
    let remaining_in_ace = ace_size - 8;

    if remaining_in_ace < 8 || is_valid_sid_raw(ace_sid) == 0 {
        return Err(forbidden(
            path,
            "invalid SID in ownership lock DACL ACE",
        ));
    }

    let sid_len = usize::try_from(get_length_sid_raw(ace_sid))
        .map_err(|_| forbidden(path, "SID length overflow"))?;
    if sid_len > remaining_in_ace {
        return Err(forbidden(
            path,
            "ACE SID length exceeds ACE boundary",
        ));
    }

    // ACE MUST grant access only to the expected process user SID.
    if equal_sid_raw(ace_sid, expected_owner.as_psid()) == 0 {
        return Err(forbidden(
            path,
            "ownership lock DACL grants access to another SID",
        ));
    }

    Ok(())
}

#[expect(unsafe_code, reason = "read null-terminated wide string returned by ConvertSidToStringSidW")]
fn sid_to_string(psid: PSID) -> Result<String, CoreError> {
    let mut wide_str: *mut u16 = core::ptr::null_mut();
    let ok = convert_sid_to_string_sid_raw(psid, &mut wide_str);
    if ok == 0 || wide_str.is_null() {
        let err = io::Error::last_os_error();
        return Err(CoreError::new(
            ErrorCode::EIo,
            format!("convert SID to string: {err}"),
        ));
    }

    let _mem = LocalMem::adopt(wide_str as HLOCAL);

    // Read null-terminated wide string up to 256 units.
    let mut len = 0;
    // SAFETY:
    // - Provenance & Lifetime: `wide_str` is allocated by `ConvertSidToStringSidW` and
    //   managed by `_mem` (`LocalMem`), which outlives the slice construction.
    // - Bounds & Termination: The loop bounds `len <= 256` before encountering the NUL terminator.
    // - Initialization: Win32 initialized all `len` code units before the terminating NUL.
    // - Alignment: `wide_str` is a `*mut u16` returned by Win32, meeting 2-byte alignment.
    // - Aliasing: `wide_str` is exclusively owned by `_mem` and not modified concurrently.
    unsafe {
        while *wide_str.add(len) != 0 {
            len += 1;
            if len > 256 {
                return Err(CoreError::new(
                    ErrorCode::EIo,
                    "SID string exceeds maximum length",
                ));
            }
        }
        let slice = core::slice::from_raw_parts(wide_str, len);
        String::from_utf16(slice)
            .map_err(|_| CoreError::new(ErrorCode::EIo, "invalid UTF-16 in SID string"))
    }
}

fn validate_sid_string(sid: &str) -> Result<(), CoreError> {
    if !sid.starts_with("S-1-") || sid.len() < 9 || sid.len() > 186 {
        return Err(CoreError::new(ErrorCode::EIo, format!("invalid SID string format: {sid}")));
    }
    for b in sid.bytes() {
        if !b.is_ascii_digit() && b != b'-' {
            return Err(CoreError::new(ErrorCode::EIo, format!("invalid character in SID string: {sid}")));
        }
    }
    Ok(())
}

fn classify_path_prefix(path: &Path) -> Option<RemoteStorageEvidence> {
    let mut components = path.components();
    match components.next()? {
        Component::Prefix(prefix_comp) => match prefix_comp.kind() {
            Prefix::UNC(..) | Prefix::VerbatimUNC(..) => Some(RemoteStorageEvidence::UncPath),
            Prefix::DeviceNS(ns) if ns.to_string_lossy().eq_ignore_ascii_case("UNC") => {
                Some(RemoteStorageEvidence::UncPath)
            }
            Prefix::Disk(c) | Prefix::VerbatimDisk(c) => {
                let drive_root: [u16; 4] = [c as u16, b':' as u16, b'\\' as u16, 0];
                let drive_type = get_drive_type_raw(drive_root.as_ptr());
                if drive_type == DRIVE_REMOTE {
                    Some(RemoteStorageEvidence::RemoteDrive(c as char))
                } else {
                    None
                }
            }
            _ => None,
        },
        _ => None,
    }
}

fn to_wide_path(path: &Path) -> Result<Vec<u16>, CoreError> {
    let s = path.as_os_str();
    let units: Vec<u16> = s.encode_wide().collect();
    if units.contains(&0) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!("path contains interior NUL: {}", path.display()),
        ));
    }
    let mut wide = units;
    wide.push(0);
    Ok(wide)
}

fn to_wide_dir_path(path: &Path) -> Result<Vec<u16>, CoreError> {
    let s = path.as_os_str();
    let mut units: Vec<u16> = s.encode_wide().collect();
    if units.contains(&0) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!("path contains interior NUL: {}", path.display()),
        ));
    }
    if !units.ends_with(&[b'\\' as u16]) && !units.ends_with(&[b'/' as u16]) {
        units.push(b'\\' as u16);
    }
    units.push(0);
    Ok(units)
}

fn io_error(path: &Path, op: &'static str, err: io::Error) -> CoreError {
    CoreError::new(ErrorCode::EIo, format!("{op} {}: {err}", path.display()))
}

fn forbidden(path: &Path, reason: &'static str) -> CoreError {
    CoreError::new(ErrorCode::EForbidden, format!("{reason}: {}", path.display()))
}

// ---------------------------------------------------------------------------
// Narrow, audited FFI helper functions
// ---------------------------------------------------------------------------

#[expect(unsafe_code, reason = "CreateFileW call with explicit Win32 flags and security attributes")]
fn open_file_raw(
    filename: *const u16,
    access: u32,
    share: u32,
    sa: Option<&SECURITY_ATTRIBUTES>,
    disposition: u32,
    flags: u32,
) -> Result<HANDLE, CoreError> {
    let sa_ptr = sa.map_or(core::ptr::null(), |s| s as *const _);
    // SAFETY: filename is a valid null-terminated UTF-16 pointer. sa_ptr is either null
    // or points to a valid live SECURITY_ATTRIBUTES struct.
    let h = unsafe {
        CreateFileW(
            filename,
            access,
            share,
            sa_ptr,
            disposition,
            flags,
            core::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(code)
                if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32 =>
            {
                Err(CoreError::new(ErrorCode::ENotFound, "lock file not found"))
            }
            Some(code) if code == ERROR_ACCESS_DENIED as i32 => {
                Err(CoreError::new(ErrorCode::EForbidden, "access denied opening lock file"))
            }
            _ => Err(CoreError::new(ErrorCode::EIo, format!("open lock file: {err}"))),
        }
    } else {
        Ok(h)
    }
}

#[expect(unsafe_code, reason = "LockFileEx Win32 range lock")]
fn lock_file_ex_raw(
    handle: HANDLE,
    flags: u32,
    reserved: u32,
    bytes_low: u32,
    bytes_high: u32,
    overlapped: &mut OVERLAPPED,
) -> BOOL {
    // SAFETY: handle is valid; overlapped is a valid mutable reference.
    unsafe { LockFileEx(handle, flags, reserved, bytes_low, bytes_high, overlapped) }
}

#[expect(unsafe_code, reason = "UnlockFileEx Win32 range unlock")]
fn unlock_file_ex_raw(
    handle: HANDLE,
    reserved: u32,
    bytes_low: u32,
    bytes_high: u32,
    overlapped: &mut OVERLAPPED,
) -> BOOL {
    // SAFETY: handle is valid; overlapped is a valid mutable reference.
    unsafe { UnlockFileEx(handle, reserved, bytes_low, bytes_high, overlapped) }
}

#[expect(unsafe_code, reason = "GetFileType Win32 query")]
fn get_file_type_raw(handle: HANDLE) -> u32 {
    // SAFETY: handle is a valid opened file handle.
    unsafe { GetFileType(handle) }
}

#[expect(unsafe_code, reason = "GetFileInformationByHandle Win32 query")]
fn get_file_info_raw(handle: HANDLE, info: &mut BY_HANDLE_FILE_INFORMATION) -> BOOL {
    // SAFETY: handle is valid; info is a valid mutable reference.
    unsafe { GetFileInformationByHandle(handle, info) }
}

#[expect(unsafe_code, reason = "GetSecurityInfo Win32 query")]
fn get_security_info_raw(
    handle: HANDLE,
    obj_type: i32,
    sec_info: u32,
    psid_owner: *mut PSID,
    psid_group: *mut PSID,
    pdacl: *mut *mut ACL,
    psacl: *mut *mut ACL,
    psd: *mut PSECURITY_DESCRIPTOR,
) -> WIN32_ERROR {
    // SAFETY: handle is valid; all output pointers are valid references or null.
    unsafe {
        GetSecurityInfo(
            handle,
            obj_type,
            sec_info,
            psid_owner,
            psid_group,
            pdacl,
            psacl,
            psd,
        )
    }
}

#[expect(unsafe_code, reason = "GetSecurityDescriptorControl Win32 query")]
fn get_security_descriptor_control_raw(
    psd: PSECURITY_DESCRIPTOR,
    control: &mut u16,
    revision: &mut u32,
) -> BOOL {
    // SAFETY: psd is non-null and points to a valid security descriptor.
    unsafe { GetSecurityDescriptorControl(psd, control, revision) }
}

#[expect(unsafe_code, reason = "IsValidAcl Win32 query")]
fn is_valid_acl_raw(pacl: *const ACL) -> BOOL {
    // SAFETY: pacl is non-null and points to an ACL structure.
    unsafe { IsValidAcl(pacl) }
}

#[expect(unsafe_code, reason = "GetAclInformation Win32 query")]
fn get_acl_size_info_raw(
    pacl: *const ACL,
    info: *mut core::ffi::c_void,
    len: u32,
    info_class: i32,
) -> BOOL {
    // SAFETY: pacl is valid; info points to an allocation of at least len bytes.
    unsafe { GetAclInformation(pacl, info, len, info_class) }
}

#[expect(unsafe_code, reason = "GetAce Win32 query")]
fn get_ace_raw(pacl: *const ACL, idx: u32, pace: *mut *mut core::ffi::c_void) -> BOOL {
    // SAFETY: pacl is valid; pace is a valid output pointer.
    unsafe { GetAce(pacl, idx, pace) }
}

#[expect(unsafe_code, reason = "IsValidSid Win32 query")]
fn is_valid_sid_raw(psid: PSID) -> BOOL {
    // SAFETY: psid is non-null and points to a candidate SID structure.
    unsafe { IsValidSid(psid) }
}

#[expect(unsafe_code, reason = "GetLengthSid Win32 query")]
fn get_length_sid_raw(psid: PSID) -> u32 {
    // SAFETY: psid was verified valid via IsValidSid.
    unsafe { GetLengthSid(psid) }
}

#[expect(unsafe_code, reason = "EqualSid Win32 comparison")]
fn equal_sid_raw(sid1: PSID, sid2: PSID) -> BOOL {
    // SAFETY: both SIDs were verified valid via IsValidSid.
    unsafe { EqualSid(sid1, sid2) }
}

#[expect(unsafe_code, reason = "OpenProcessToken Win32 query")]
fn open_process_token_raw(
    process: HANDLE,
    access: TOKEN_ACCESS_MASK,
    token: *mut HANDLE,
) -> BOOL {
    // SAFETY: process is a valid process handle; token is a valid output pointer.
    unsafe { OpenProcessToken(process, access, token) }
}

#[expect(unsafe_code, reason = "OpenThreadToken Win32 query")]
fn open_thread_token_raw(
    thread: HANDLE,
    access: TOKEN_ACCESS_MASK,
    open_as_self: BOOL,
    token: *mut HANDLE,
) -> BOOL {
    // SAFETY: thread is a valid thread handle; token is a valid output pointer.
    unsafe { OpenThreadToken(thread, access, open_as_self, token) }
}

#[expect(unsafe_code, reason = "GetTokenInformation Win32 query")]
fn get_token_information_raw(
    token: HANDLE,
    info_class: i32,
    info: *mut core::ffi::c_void,
    len: u32,
    ret_len: *mut u32,
) -> BOOL {
    // SAFETY: token is valid; info points to an allocation of len bytes (or is null when len=0).
    unsafe { GetTokenInformation(token, info_class, info, len, ret_len) }
}

#[expect(unsafe_code, reason = "GetCurrentProcess pseudo-handle query")]
fn get_current_process_raw() -> HANDLE {
    // SAFETY: GetCurrentProcess returns a pseudo-handle that does not need closing.
    unsafe { GetCurrentProcess() }
}

#[expect(unsafe_code, reason = "GetCurrentThread pseudo-handle query")]
fn get_current_thread_raw() -> HANDLE {
    // SAFETY: GetCurrentThread returns a pseudo-handle that does not need closing.
    unsafe { GetCurrentThread() }
}

#[expect(unsafe_code, reason = "CloseHandle Win32 call")]
fn close_handle_raw(handle: HANDLE) -> BOOL {
    // SAFETY: handle is a valid opened kernel handle.
    unsafe { CloseHandle(handle) }
}

#[expect(unsafe_code, reason = "ConvertSidToStringSidW Win32 call")]
fn convert_sid_to_string_sid_raw(sid: PSID, str_sid: *mut *mut u16) -> BOOL {
    // SAFETY: sid is valid; str_sid is a valid output pointer.
    unsafe { ConvertSidToStringSidW(sid, str_sid) }
}

#[expect(unsafe_code, reason = "ConvertStringSecurityDescriptorToSecurityDescriptorW Win32 call")]
fn convert_string_sd_to_sd_raw(
    str_sd: *const u16,
    revision: u32,
    psd: *mut PSECURITY_DESCRIPTOR,
    size: *mut u32,
) -> BOOL {
    // SAFETY: str_sd is a null-terminated UTF-16 string; psd and size are valid output pointers.
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(str_sd, revision, psd, size) }
}

#[expect(unsafe_code, reason = "ImpersonateNamedPipeClient Win32 call")]
fn impersonate_named_pipe_client_raw(pipe: HANDLE) -> BOOL {
    // SAFETY: pipe is a valid connected named pipe server handle.
    unsafe { ImpersonateNamedPipeClient(pipe) }
}

#[expect(unsafe_code, reason = "RevertToSelf Win32 call")]
fn revert_to_self_raw() -> BOOL {
    // SAFETY: RevertToSelf operates on the calling thread's impersonation token.
    unsafe { RevertToSelf() }
}

#[expect(unsafe_code, reason = "GetDiskFreeSpaceExW Win32 call")]
fn get_disk_free_space_ex_raw(
    dir: *const u16,
    free_caller: *mut u64,
    total: *mut u64,
    free_total: *mut u64,
) -> BOOL {
    // SAFETY: dir is a valid null-terminated UTF-16 string; output pointers are valid references.
    unsafe { GetDiskFreeSpaceExW(dir, free_caller, total, free_total) }
}

#[expect(unsafe_code, reason = "GetDriveTypeW Win32 call")]
fn get_drive_type_raw(root: *const u16) -> u32 {
    // SAFETY: root is a valid null-terminated UTF-16 drive root string (e.g. "C:\\\0").
    unsafe { GetDriveTypeW(root) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_sid_format() {
        let sid = current_sid().expect("query current process user SID");
        assert!(sid.starts_with("S-1-"), "SID must start with S-1-: {sid}");
        assert!(sid.len() >= 9, "SID must be at least 9 characters: {sid}");
        validate_sid_string(&sid).expect("SID string format validation");
    }

    #[test]
    fn test_pipe_name_validation() {
        // Valid local names pass
        assert!(validate_pipe_address(r"\\.\pipe\ruk-test-1234").is_ok());
        assert!(validate_pipe_address(r"\\.\pipe\ruk-00000000-0000-0000-0000-000000000000-abcd").is_ok());

        // Remote names fail
        assert!(validate_pipe_address(r"\\server\pipe\ruk-test").is_err());
        assert!(validate_pipe_address(r"\\192.168.1.1\pipe\ruk-test").is_err());

        // Forward slashes or traversal fail
        assert!(validate_pipe_address(r"\\.\pipe\sub/pipe").is_err());
        assert!(validate_pipe_address(r"\\.\pipe\sub\pipe").is_err());
        assert!(validate_pipe_address(r"\\.\pipe\..").is_err());

        // Unix socket paths fail
        assert!(validate_pipe_address("/tmp/ruk.sock").is_err());
    }

    #[test]
    fn test_pipe_name_generation_unpredictable() {
        let store_id = StoreId::generate();
        let name1 = generate_pipe_name(store_id).expect("generate pipe name 1");
        let name2 = generate_pipe_name(store_id).expect("generate pipe name 2");

        assert_ne!(name1, name2, "independent generations must be unpredictable and distinct");
        assert!(name1.contains(&store_id.to_string()), "pipe name must contain store ID");
        assert!(name2.contains(&store_id.to_string()), "pipe name must contain store ID");
        validate_pipe_address(&name1).expect("generated name 1 must be valid");
        validate_pipe_address(&name2).expect("generated name 2 must be valid");
    }

    #[test]
    fn test_filesystem_space_temp_dir() {
        let temp = std::env::temp_dir();
        let space = filesystem_space(&temp).expect("query temp dir space");
        assert!(space.total_bytes > 0, "total bytes must be positive");
        assert!(space.available_bytes <= space.total_bytes, "available <= total");

        // Missing path returns ENotFound
        let missing = temp.join(format!("ruk-nonexistent-{}", uuid::Uuid::new_v4().simple()));
        let err = filesystem_space(&missing).unwrap_err();
        assert_eq!(err.code, ErrorCode::ENotFound);
    }

    #[test]
    fn test_detect_remote_storage_lexical_unc() {
        let unc = Path::new(r"\\server\share\repo");
        assert_eq!(
            classify_path_prefix(unc),
            Some(RemoteStorageEvidence::UncPath),
        );

        let verbatim_unc = Path::new(r"\\?\UNC\server\share\repo");
        assert_eq!(
            classify_path_prefix(verbatim_unc),
            Some(RemoteStorageEvidence::UncPath),
        );

        // Local drive path is NOT classified as UNC
        let local = Path::new(r"C:\store\repo");
        assert_ne!(
            classify_path_prefix(local),
            Some(RemoteStorageEvidence::UncPath),
        );

        // Verbatim local path is NOT classified as UNC
        let verbatim_local = Path::new(r"\\?\C:\store\repo");
        assert_ne!(
            classify_path_prefix(verbatim_local),
            Some(RemoteStorageEvidence::UncPath),
        );
    }

    #[test]
    fn test_ensure_local_storage_rejects_unc() {
        let unc = Path::new(r"\\server\share\store");
        let err = ensure_local_storage(unc).unwrap_err();
        assert_eq!(err.code, ErrorCode::EForbidden);
    }

    #[test]
    fn test_ensure_local_storage_missing_path() {
        let missing = std::env::temp_dir().join(format!("ruk-missing-{}", uuid::Uuid::new_v4().simple()));
        let err = ensure_local_storage(&missing).unwrap_err();
        assert_eq!(err.code, ErrorCode::ENotFound);
    }

    #[test]
    fn test_ensure_local_storage_accepts_temp_dir() {
        let temp = std::env::temp_dir();
        assert!(ensure_local_storage(&temp).is_ok());
    }

    #[test]
    fn test_clean_worker_token_lifecycle() {
        // Path A: Guard drop on unwind (panic resilience).
        let unwind_handle = std::thread::spawn(|| {
            assert!(
                !thread_has_impersonation_token().expect("pre-check token"),
                "fresh worker thread must have no impersonation token",
            );

            let panic_result = std::panic::catch_unwind(|| {
                let _guard = ImpersonationGuard::arm();
                panic!("simulated worker panic under impersonation guard");
            });
            assert!(panic_result.is_err(), "closure must panic");

            assert!(
                !thread_has_impersonation_token().expect("post-unwind token"),
                "worker thread must remain clean after guard unwinding drop",
            );
        });
        unwind_handle.join().expect("unwind thread join");

        // Path B: Error path (invalid handle fails impersonation).
        let error_handle = std::thread::spawn(|| {
            assert!(
                !thread_has_impersonation_token().expect("pre-check token"),
                "fresh worker thread must have no impersonation token",
            );

            let err = impersonate_and_query_peer_sid(INVALID_HANDLE_VALUE).unwrap_err();
            assert_eq!(err.code, ErrorCode::EIo);

            assert!(
                !thread_has_impersonation_token().expect("post-error token"),
                "worker thread must remain clean after impersonation error",
            );
        });
        error_handle.join().expect("error thread join");

        // Path C: Success path (roundtrip under live server/client).
        let success_handle = std::thread::spawn(|| {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            assert!(
                !thread_has_impersonation_token().expect("pre-check token"),
                "fresh worker thread must have no impersonation token",
            );

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");

            rt.block_on(async {
                let store_id = StoreId::generate();
                let pipe_name = generate_pipe_name(store_id).expect("pipe name");
                let server = create_first_pipe_server(&pipe_name).expect("server");

                let client_task = tokio::spawn(async move {
                    let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
                        .open(&pipe_name)
                        .expect("client open");
                    client.write_all(b"z").await.expect("client write");
                    client
                });

                server.connect().await.expect("connect");
                let mut buf = [0u8; 1];
                let _ = (&server).read(&mut buf).await.expect("read");

                let sid = pipe_peer_sid(&server).expect("pipe peer SID");
                assert!(sid.starts_with("S-1-"));

                let _client = client_task.await.expect("client task");
            });

            assert!(
                !thread_has_impersonation_token().expect("post-success token"),
                "worker thread must remain clean after successful peer SID read",
            );
        });
        success_handle.join().expect("success thread join");
    }

    #[test]
    fn test_named_pipe_peer_sid_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        rt.block_on(async {
            let store_id = StoreId::generate();
            let pipe_name = generate_pipe_name(store_id).expect("pipe name");

            let server = create_first_pipe_server(&pipe_name).expect("create first pipe server");

            let client_task = tokio::spawn(async move {
                let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
                    .open(&pipe_name)
                    .expect("client open pipe");
                // Write a byte to ensure server has read data before impersonating.
                client.write_all(b"x").await.expect("client write");
                client
            });

            server.connect().await.expect("server connect");
            let mut buf = [0u8; 1];
            let n = (&server).read(&mut buf).await.expect("server read");
            assert_eq!(n, 1);

            let peer_sid = pipe_peer_sid(&server).expect("inspect pipe peer SID");
            let expected_sid = current_sid().expect("current user SID");
            assert_eq!(peer_sid, expected_sid, "pipe peer SID must match current user SID");

            let _client = client_task.await.expect("client task");
        });
    }
}
