//! Physical pre-publication allocation, one handle-borrowing call per file.
//!
//! Ruk's durability model needs a strict answer to "will this prepared range
//! be writable after the transaction commits?" A free-space sample cannot
//! answer that: another writer may consume the space first, and a COW or
//! sparse layout may need new extents even where bytes already appear
//! allocated. This module performs the strongest platform reservation
//! available and reports what the filesystem then observed.
//!
//! The receipt is an **observation**, not a guarantee beyond the platform
//! contract named below, and it is not a durable charge. The durable pending
//! reservation, quota accounting, and reconciliation live in the store's
//! capacity ledger, which is required to:
//!
//! 1. persist a pending-reservation record before calling
//!    [`reserve_prepublication`],
//! 2. call it under the repository's serialized append allocator,
//! 3. re-query the still-open handle and update the pending record,
//! 4. release charge only through durable truncation, deletion, or
//!    compaction — never through a dropped guard.
//!
//! Platform contract (pinned by `local://ruk-physical-allocation-api.md`):
//!
//! - **Linux**: `fallocate(2)`, split at the current end of file. Ranges
//!   entirely beyond EOF get `FALLOC_FL_KEEP_SIZE` alone — they have no
//!   existing extents to share, so no unshare is needed and the broader
//!   filesystem support applies. Ranges inside the file (overwrites) get
//!   `KEEP_SIZE | UNSHARE_RANGE`, which makes reflink/COW extents private so
//!   a later overwrite cannot hit a late COW allocation. A range crossing
//!   EOF is split into both calls. Linux documents that subsequent writes
//!   into a successfully allocated range do not fail for lack of disk
//!   space. `EOPNOTSUPP`/`ENOSYS`/`EINVAL` from either syscall maps to
//!   [`AllocationError::UnverifiedFilesystem`] — there is no documented
//!   safe fallback, so the caller fails closed.
//! - **Windows**: `SetFileInformationByHandle(FileAllocationInfo)` after
//!   rejecting sparse, compressed, reparse, remote, and block-refcounting
//!   files/volumes, then `FileStandardInfo` for the observation. Microsoft
//!   documents no generic subsequent-overwrite theorem, so a Windows receipt
//!   means "allocation observed", never "subsequent writes guaranteed".
//! - **macOS and other Unix**: `UnverifiedFilesystem`. rustix's Apple
//!   `fallocate` is an `F_PREALLOCATE` plus `ftruncate` shim that accepts
//!   only empty flags and can move EOF; routing it through the strict path
//!   would misstate the guarantee. XNU exposes no unshare primitive.

use std::fs::File;
use std::path::Path;

/// What the filesystem reported after a reservation attempt.
///
/// `allocated_bytes` is a post-operation observation of the whole file, not
/// the delta this call reserved and not necessarily physical-device bytes on
/// every filesystem. `logical_len` is the file-visible length at the same
/// observation point. Callers compare against their own prior receipt rather
/// than reading a delta out of either field.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct AllocationReceipt {
    /// Length of the range the caller asked to reserve.
    pub(crate) requested_bytes: u64,
    /// Filesystem-reported allocated bytes for the whole file.
    pub(crate) allocated_bytes: u64,
    /// Filesystem-reported logical length (`st_size` / `EndOfFile`).
    pub(crate) logical_len: u64,
}

/// Why a reservation could not be completed or could not be verified.
///
/// `Io` covers ordinary failures including `ENOSPC` — the caller asked for
/// space that was not there. `UnverifiedFilesystem` means the platform
/// cannot or will not honour the strict contract on this file (unsupported
/// operation, unsupported mode, sparse/compressed/COW/remote profile, or a
/// platform with no strict primitive). `Unsupported` is reserved for
/// platforms where the primitive class itself is absent.
#[derive(Debug)]
pub(crate) enum AllocationError {
    /// Ordinary I/O failure, including out-of-space.
    Io(std::io::Error),
    /// No strict reservation primitive exists on this platform.
    Unsupported,
    /// The handle does not name a regular file.
    NotRegularFile,
    /// The requested range or a reported field overflowed `u64`.
    Overflow,
    /// The filesystem profile cannot be verified against the strict
    /// contract; the caller must fail closed.
    UnverifiedFilesystem,
}

impl std::fmt::Display for AllocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "allocation I/O failed: {e}"),
            Self::Unsupported => write!(f, "platform has no strict reservation primitive"),
            Self::NotRegularFile => write!(f, "handle is not a regular file"),
            Self::Overflow => write!(f, "range or reported field overflowed u64"),
            Self::UnverifiedFilesystem => {
                write!(
                    f,
                    "filesystem profile fails the strict reservation contract"
                )
            }
        }
    }
}

impl std::error::Error for AllocationError {}

/// Advisory free-space observation for admission diagnostics.
///
/// This is a point-in-time volume sample — useful for error context and
/// coarse admission heuristics, never a reservation. `available` is the
/// caller-visible floor (`f_bavail`-class, so per-user quotas and the
/// privileged reserve are reflected); `total` is the volume size.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct VolumeFloor {
    /// Bytes reported free to the calling user.
    pub(crate) available: u64,
    /// Total bytes on the volume.
    pub(crate) total: u64,
}

/// Reserve `[offset, offset + len)` for a prepared write under the strict
/// platform contract.
///
/// A zero-length reservation is a receipt-only observation: no platform call
/// is made and the returned fields describe the file as found. All other
/// calls perform the platform reservation and then re-query through the
/// still-open handle, so a crash after success leaves the durable pending
/// record reconcilable against a real file state.
pub(crate) fn reserve_prepublication(
    file: &File,
    offset: u64,
    len: u64,
) -> Result<AllocationReceipt, AllocationError> {
    offset.checked_add(len).ok_or(AllocationError::Overflow)?;
    platform::reserve(file, offset, len)
}

/// A platform reservation held by the store's capacity ledger.
///
/// This is a receipt holder, never a guard: dropping it releases nothing.
/// The charge it records lives in the ledger's durable pending-reservation
/// row and is released only through durable truncation, deletion, or
/// compaction. A dropped guard would silently free a charge the ledger
/// still counts as held, so no `Drop` impl exists on purpose.
///
/// The receipt already contains the post-operation re-query of the
/// still-open handle (`stat_receipt`/`FileStandardInfo` run after the
/// reservation call inside [`reserve_prepublication`]), so the ledger can
/// copy the observed fields straight into the pending record without a
/// second query that could observe a different state.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct PhysicalReservation {
    receipt: AllocationReceipt,
}

impl PhysicalReservation {
    /// Reserve `[offset, offset + len)` on the already-open segment file.
    /// See [`reserve_prepublication`] for the platform contract.
    pub(crate) fn reserve(
        file: &File,
        offset: u64,
        len: u64,
    ) -> Result<Self, AllocationError> {
        reserve_prepublication(file, offset, len).map(|receipt| Self { receipt })
    }

    /// The post-operation observation of the still-open handle.
    #[must_use]
    pub(crate) fn receipt(&self) -> AllocationReceipt {
        self.receipt
    }
}

/// Advisory volume sample for admission diagnostics. See [`VolumeFloor`].
pub(crate) fn volume_free_floor(path: &Path) -> Result<VolumeFloor, AllocationError> {
    platform::volume_free_floor(path)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{AllocationError, AllocationReceipt, VolumeFloor};
    use rustix::fs::{FallocateFlags, fallocate, fstat, fstatvfs};
    use rustix::io::Errno;
    use std::fs::File;
    use std::path::Path;

    pub(super) fn reserve(
        file: &File,
        offset: u64,
        len: u64,
    ) -> Result<AllocationReceipt, AllocationError> {
        let meta = file.metadata().map_err(AllocationError::Io)?;
        if !meta.is_file() {
            return Err(AllocationError::NotRegularFile);
        }
        if len > 0 {
            let end = offset + len;
            // The file's current extent layout decides which allocation the
            // strict contract requires. Data already inside the file may be
            // shared on a reflink/COW filesystem and must be unshared; space
            // beyond EOF has nothing to unshare and gets the plain
            // keep-size allocation that wider filesystem support accepts.
            let size = u64::try_from(
                fstat(file)
                    .map_err(|e| AllocationError::Io(e.into()))?
                    .st_size,
            )
            .map_err(|_| AllocationError::Overflow)?;
            if offset < size {
                let inner_len = (size - offset).min(len);
                fallocate(
                    file,
                    FallocateFlags::KEEP_SIZE | FallocateFlags::UNSHARE_RANGE,
                    offset,
                    inner_len,
                )
                .map_err(map_fallocate_error)?;
            }
            if end > size {
                fallocate(
                    file,
                    FallocateFlags::KEEP_SIZE,
                    offset.max(size),
                    end - offset.max(size),
                )
                .map_err(map_fallocate_error)?;
            }
        }
        stat_receipt(file, len)
    }

    fn map_fallocate_error(e: Errno) -> AllocationError {
        match e {
            // EOPNOTSUPP: filesystem or mode unsupported (incl. filesystems
            // that reject UNSHARE_RANGE). ENOSYS: kernel lacks fallocate.
            // EINVAL: cannot distinguish invalid mode from invalid range —
            // fail closed rather than guess a fallback.
            Errno::OPNOTSUPP | Errno::NOSYS | Errno::INVAL => AllocationError::UnverifiedFilesystem,
            other => AllocationError::Io(other.into()),
        }
    }

    fn stat_receipt(file: &File, requested: u64) -> Result<AllocationReceipt, AllocationError> {
        let st = fstat(file).map_err(|e| AllocationError::Io(e.into()))?;
        let allocated = u64::try_from(st.st_blocks)
            .map_err(|_| AllocationError::Overflow)?
            .checked_mul(512)
            .ok_or(AllocationError::Overflow)?;
        let logical = u64::try_from(st.st_size).map_err(|_| AllocationError::Overflow)?;
        Ok(AllocationReceipt {
            requested_bytes: requested,
            allocated_bytes: allocated,
            logical_len: logical,
        })
    }

    pub(super) fn volume_free_floor(path: &Path) -> Result<VolumeFloor, AllocationError> {
        let dir = File::open(path).map_err(AllocationError::Io)?;
        let v = fstatvfs(&dir).map_err(|e| AllocationError::Io(e.into()))?;
        // rustix already substitutes f_bsize when a filesystem reports
        // f_frsize == 0 on the linux-raw backend; keep the fallback anyway.
        let frag = if v.f_frsize == 0 {
            v.f_bsize
        } else {
            v.f_frsize
        };
        let available = v
            .f_bavail
            .checked_mul(frag)
            .ok_or(AllocationError::Overflow)?;
        let total = v
            .f_blocks
            .checked_mul(frag)
            .ok_or(AllocationError::Overflow)?;
        Ok(VolumeFloor { available, total })
    }
}

#[cfg(windows)]
mod platform {
    use super::{AllocationError, AllocationReceipt, VolumeFloor};
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ALLOCATION_INFO, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_TAG_INFO, FILE_INFO_BY_HANDLE_CLASS,
        FILE_REMOTE_DEVICE, FILE_STANDARD_INFO, FILE_SUPPORTS_BLOCK_REFCOUNTING,
        FileAllocationInfo, FileStandardInfo, GetDiskFreeSpaceExW, GetFileInformationByHandleEx,
        GetVolumeInformationByHandleW, SetFileInformationByHandle,
    };

    const REJECTED_ATTRIBUTES: u32 =
        FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_REPARSE_POINT;
    const REJECTED_VOLUME_FLAGS: u32 = FILE_SUPPORTS_BLOCK_REFCOUNTING | FILE_REMOTE_DEVICE;

    pub(super) fn reserve(
        file: &File,
        offset: u64,
        len: u64,
    ) -> Result<AllocationReceipt, AllocationError> {
        let meta = file.metadata().map_err(AllocationError::Io)?;
        if !meta.is_file() {
            return Err(AllocationError::NotRegularFile);
        }
        let handle = file.as_raw_handle();
        reject_unverifiable_file(handle)?;
        reject_unverifiable_volume(handle)?;
        let before = standard_info(handle)?;
        let before_alloc =
            u64::try_from(before.AllocationSize).map_err(|_| AllocationError::Overflow)?;
        if len > 0 {
            let need = offset.checked_add(len).ok_or(AllocationError::Overflow)?;
            // FileAllocationInfo is a whole-file allocation setter, not a
            // range call. Never shrink below what the file already holds.
            let target = need.max(before_alloc);
            if target > before_alloc {
                set_allocation(handle, target)?;
            }
        }
        let after = standard_info(handle)?;
        receipt(after, len)
    }

    fn map_last_error() -> AllocationError {
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(c) if c == 50 || c == 1 || c == 87 => {
                // ERROR_NOT_SUPPORTED / ERROR_INVALID_FUNCTION /
                // ERROR_INVALID_PARAMETER: filesystem profile cannot honour
                // the strict contract. Fail closed.
                AllocationError::UnverifiedFilesystem
            }
            _ => AllocationError::Io(e),
        }
    }

    #[expect(
        unsafe_code,
        reason = "windows-sys FFI bridge: fixed-function calls on a borrowed HANDLE"
    )]
    fn tag_info(
        handle: std::os::windows::raw::HANDLE,
    ) -> Result<FILE_ATTRIBUTE_TAG_INFO, AllocationError> {
        let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
        // SAFETY: handle is borrowed from a live std::fs::File for the
        // duration of the call; info points to an initialized buffer of the
        // exact size passed.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                windows_sys::Win32::Storage::FileSystem::FileAttributeTagInfo,
                &mut info as *mut _ as *mut _,
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        if ok == 0 {
            Err(map_last_error())
        } else {
            Ok(info)
        }
    }

    #[expect(
        unsafe_code,
        reason = "windows-sys FFI bridge: fixed-function calls on a borrowed HANDLE"
    )]
    fn reject_unverifiable_volume(
        handle: std::os::windows::raw::HANDLE,
    ) -> Result<(), AllocationError> {
        let mut flags: u32 = 0;
        // SAFETY: handle is borrowed from a live File; flags is a valid
        // out-pointer; null pointers select "not requested" output fields.
        let ok = unsafe {
            GetVolumeInformationByHandleW(
                handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut flags,
                std::ptr::null_mut(),
                0,
            )
        };
        if ok == 0 {
            return Err(map_last_error());
        }
        if flags & REJECTED_VOLUME_FLAGS != 0 {
            // Block refcounting means a write to a shared cluster may need a
            // fresh extent (COW) — AllocationInfo gives no unshare. Remote
            // volumes sit outside any local allocation theorem.
            return Err(AllocationError::UnverifiedFilesystem);
        }
        Ok(())
    }

    fn reject_unverifiable_file(
        handle: std::os::windows::raw::HANDLE,
    ) -> Result<(), AllocationError> {
        let info = tag_info(handle)?;
        if info.FileAttributes & REJECTED_ATTRIBUTES != 0 {
            return Err(AllocationError::UnverifiedFilesystem);
        }
        Ok(())
    }

    #[expect(
        unsafe_code,
        reason = "windows-sys FFI bridge: fixed-function calls on a borrowed HANDLE"
    )]
    fn standard_info(
        handle: std::os::windows::raw::HANDLE,
    ) -> Result<FILE_STANDARD_INFO, AllocationError> {
        let mut info = FILE_STANDARD_INFO::default();
        // SAFETY: handle is borrowed from a live File; info points to an
        // initialized buffer of the exact size passed.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileStandardInfo,
                &mut info as *mut _ as *mut _,
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        };
        if ok == 0 {
            Err(map_last_error())
        } else {
            Ok(info)
        }
    }

    #[expect(
        unsafe_code,
        reason = "windows-sys FFI bridge: fixed-function calls on a borrowed HANDLE"
    )]
    fn set_allocation(
        handle: std::os::windows::raw::HANDLE,
        target: u64,
    ) -> Result<(), AllocationError> {
        let info = FILE_ALLOCATION_INFO {
            AllocationSize: i64::try_from(target).map_err(|_| AllocationError::Overflow)?,
        };
        // SAFETY: handle is borrowed from a live File opened with write
        // access; info points to an initialized FILE_ALLOCATION_INFO of the
        // exact size passed.
        let ok = unsafe {
            SetFileInformationByHandle(
                handle,
                FileAllocationInfo,
                &info as *const _ as *const _,
                size_of::<FILE_ALLOCATION_INFO>() as u32,
            )
        };
        if ok == 0 {
            Err(map_last_error())
        } else {
            Ok(())
        }
    }

    fn receipt(
        info: FILE_STANDARD_INFO,
        requested: u64,
    ) -> Result<AllocationReceipt, AllocationError> {
        let allocated =
            u64::try_from(info.AllocationSize).map_err(|_| AllocationError::Overflow)?;
        let logical = u64::try_from(info.EndOfFile).map_err(|_| AllocationError::Overflow)?;
        Ok(AllocationReceipt {
            requested_bytes: requested,
            allocated_bytes: allocated,
            logical_len: logical,
        })
    }

    #[expect(
        unsafe_code,
        reason = "windows-sys FFI bridge: fixed-function calls on a borrowed HANDLE"
    )]
    pub(super) fn volume_free_floor(path: &Path) -> Result<VolumeFloor, AllocationError> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        let mut available: u64 = 0;
        let mut total: u64 = 0;
        // SAFETY: wide is a valid NUL-terminated UTF-16 buffer; the out
        // pointers reference live u64 slots for the duration of the call.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut available,
                &mut total,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(map_last_error())
        } else {
            Ok(VolumeFloor { available, total })
        }
    }
}

// Apple and every other Unix: rustix's `fallocate` exists on Apple but is an
// F_PREALLOCATE + ftruncate shim accepting only empty flags — it can move EOF
// and offers no unshare. XNU defines no unshare primitive. Returning
// UnverifiedFilesystem keeps the strict path honest until a reviewed Apple
// FFI implementation passes a real filesystem smoke.
#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::{AllocationError, AllocationReceipt, VolumeFloor};
    use std::fs::File;
    use std::path::Path;

    pub(super) fn reserve(
        _file: &File,
        _offset: u64,
        _len: u64,
    ) -> Result<AllocationReceipt, AllocationError> {
        Err(AllocationError::UnverifiedFilesystem)
    }

    pub(super) fn volume_free_floor(_path: &Path) -> Result<VolumeFloor, AllocationError> {
        Err(AllocationError::UnverifiedFilesystem)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn appended_range_reserves_without_moving_eof() {
        let dir = std::env::temp_dir().join(format!("ruk-phys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seg.bin");
        let mut file = File::create(&path).unwrap();
        file.write_all(&[7u8; 4096]).unwrap();
        file.sync_all().unwrap();

        match reserve_prepublication(&file, 4096, 8192) {
            Ok(receipt) => {
                assert_eq!(receipt.requested_bytes, 8192);
                // KEEP_SIZE must not have moved EOF for the appended range.
                assert_eq!(receipt.logical_len, 4096);
            }
            // tmpfs and some filesystems reject KEEP_SIZE beyond EOF; that
            // is the contract working, not a bug.
            Err(AllocationError::UnverifiedFilesystem) => {}
            Err(other) => panic!("unexpected reservation error: {other}"),
        }
        drop(file);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn overwrite_and_crossing_ranges_take_the_unshare_path() {
        let dir = std::env::temp_dir().join(format!("ruk-phys-ov-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("seg.bin");
        let mut file = File::create(&path).unwrap();
        file.write_all(&[7u8; 4096]).unwrap();
        file.sync_all().unwrap();

        // A pure overwrite and an EOF-crossing range both need UNSHARE_RANGE
        // for their in-file portion. On a filesystem without it the strict
        // contract fails closed; both outcomes are correct.
        for (offset, len) in [(0u64, 4096u64), (2048, 8192)] {
            match reserve_prepublication(&file, offset, len) {
                Ok(receipt) => assert_eq!(receipt.requested_bytes, len),
                Err(AllocationError::UnverifiedFilesystem) => {}
                Err(other) => panic!("unexpected reservation error: {other}"),
            }
        }
        drop(file);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn zero_length_reservation_is_observation_only() {
        let dir = std::env::temp_dir().join(format!("ruk-phys-zero-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = File::create(dir.join("empty.bin")).unwrap();
        let receipt = reserve_prepublication(&file, 0, 0).unwrap();
        assert_eq!(receipt.requested_bytes, 0);
        assert_eq!(receipt.logical_len, 0);
        drop(file);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn directory_handle_is_rejected() {
        let dir = std::env::temp_dir().join(format!("ruk-phys-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let handle = File::open(&dir).unwrap();
        let err = reserve_prepublication(&handle, 0, 1).unwrap_err();
        assert!(matches!(err, AllocationError::NotRegularFile));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn volume_floor_observes_the_mount() {
        let floor = volume_free_floor(Path::new("/tmp")).unwrap();
        assert!(floor.total >= floor.available);
        assert!(floor.total > 0);
    }

    #[test]
    fn overflowing_range_is_rejected() {
        let dir = std::env::temp_dir().join(format!("ruk-phys-of-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = File::create(dir.join("f.bin")).unwrap();
        let err = reserve_prepublication(&file, u64::MAX, 1).unwrap_err();
        assert!(matches!(err, AllocationError::Overflow));
        drop(file);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
