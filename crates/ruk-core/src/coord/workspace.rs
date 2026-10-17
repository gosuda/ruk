use super::rows::{self, WorkspaceRow};
use crate::store::{FactExpectation, FactMutation, FactTable, Store};
use crate::workspace::WorkspaceStamp;
use crate::{CoreError, ErrorCode, SessionId, WorkspaceId};

pub(crate) struct ObservedWorkspace {
    pub(crate) id: WorkspaceId,
    pub(crate) row: WorkspaceRow,
    bytes: Vec<u8>,
}

pub(crate) fn observe(store: &Store, id: WorkspaceId) -> Result<ObservedWorkspace, CoreError> {
    let key = rows::workspace_key(id);
    let bytes = store
        .fact(FactTable::Workspaces, &key)?
        .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "workspace is not registered"))?;
    let row = rows::decode_workspace(store, &key, &bytes)?;
    Ok(ObservedWorkspace { id, row, bytes })
}

impl ObservedWorkspace {
    pub(crate) fn fence(
        &self,
        session: SessionId,
        expected: WorkspaceStamp,
    ) -> Result<(), CoreError> {
        if self.row.holder != session {
            return Err(CoreError::new(
                ErrorCode::ELeaseLost,
                "session does not hold this workspace",
            ));
        }
        self.row.state.stamp().fence(expected)?;
        Ok(())
    }

    pub(crate) fn replace(self, next: WorkspaceRow) -> Result<FactMutation, CoreError> {
        self.row.check_successor(&next)?;
        let value = rows::encode("workspace", &next)?;
        let key = rows::workspace_key(self.id).to_vec();
        let pair_bytes = key
            .len()
            .checked_add(value.len())
            .ok_or_else(|| CoreError::new(ErrorCode::ECapacity, "workspace row size overflow"))?;
        if u64::try_from(pair_bytes).map_or(true, |bytes| bytes > rows::ROW_MAX_BYTES) {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                "workspace row exceeds the publication row limit",
            ));
        }
        Ok(FactMutation {
            table: FactTable::Workspaces,
            key,
            expected: FactExpectation::Value(self.bytes),
            value: Some(value),
        })
    }

    pub(crate) fn remove(self) -> FactMutation {
        FactMutation {
            table: FactTable::Workspaces,
            key: rows::workspace_key(self.id).to_vec(),
            expected: FactExpectation::Value(self.bytes),
            value: None,
        }
    }
}
