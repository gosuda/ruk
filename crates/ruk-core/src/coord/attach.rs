use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{Instant, sleep_until, timeout_at};

use super::admission::{
    Admission, AdmissionRequest, RepoAdmission, RequestClass, WorkResources, run_blocking,
};
use super::cancel::Cancel;
use super::client::Client;
use super::endpoint;
use super::lock::{Acquisition, LockSnapshot, StoreLock};
use crate::store::{StoreFormat, read_format};
use crate::{CoreError, ErrorCode};

pub(crate) enum Attachment {
    Owner {
        lock: StoreLock,
        format: StoreFormat,
    },
    Client(Client),
}

/// Acquires the sole owner lock or authenticates its current endpoint.
///
/// The caller registers the repository with admission before this call.
/// This path never opens redb. A held lock never permits a second writer.
pub(crate) async fn attach(
    root: &Path,
    admission: &Arc<Admission>,
    repository: &RepoAdmission,
    cancel: &Cancel,
    deadline: Instant,
) -> Result<Attachment, CoreError> {
    let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
    timeout_at(
        deadline,
        attach_until(root, admission, repository, cancel, deadline),
    )
    .await
    .map_err(|_| {
        CoreError::new(
            ErrorCode::ECoordinatorUnresponsive,
            "the store owner did not become reachable before the attach deadline",
        )
    })?
}

async fn attach_until(
    root: &Path,
    admission: &Arc<Admission>,
    repository: &RepoAdmission,
    cancel: &Cancel,
    deadline: Instant,
) -> Result<Attachment, CoreError> {
    let root = Arc::new(root.to_path_buf());
    loop {
        cancel.check()?;
        let admitted = admission
            .admit(
                repository,
                AdmissionRequest {
                    class: RequestClass::Control,
                    resources: WorkResources::Compute,
                    payload_bytes: 0,
                    deadline,
                },
                cancel,
            )
            .await?;
        let probe_root = Arc::clone(&root);
        let (admitted, probe) = run_blocking(admitted, cancel.clone(), move |cancel| {
            cancel.check()?;
            probe_owner(&probe_root)
        })
        .await?;
        drop(admitted);
        let (format, acquisition) = probe?;
        cancel.check()?;
        match acquisition {
            Acquisition::Owner(lock) => return Ok(Attachment::Owner { lock, format }),
            Acquisition::Held(LockSnapshot::Ready(body)) => {
                match Client::connect(format.id, &body, deadline).await {
                    Ok(client) => return Ok(Attachment::Client(client)),
                    Err(error)
                        if matches!(
                            error.code,
                            ErrorCode::EIo | ErrorCode::ECoordinatorUnresponsive
                        ) => {}
                    Err(error) => return Err(error),
                }
            }
            Acquisition::Held(LockSnapshot::NotReady) => {}
        }
        cancel.check()?;
        sleep_until(deadline.min(Instant::now() + Duration::from_millis(50))).await;
    }
}

fn probe_owner(root: &Path) -> Result<(StoreFormat, Acquisition), CoreError> {
    endpoint::ensure_local_storage(root)?;
    let (format, file) = read_format(root)?;
    drop(file);
    Ok((format, StoreLock::try_acquire(root)?))
}
