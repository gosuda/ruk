//! `new`: create one native commit and publish it atomically.
//!
//! The request names a tree, the parents, the identities, and the message.
//! Everything else — change identity, predecessor, provenance — is optional
//! and explicit. The operation never guesses a change ID from a message and
//! never derives a parent from the workspace.

use serde::{Deserialize, Serialize};

use crate::bytes::ByteString;
use crate::change::ChangeId;
use crate::commit::{NativeCommitInput, Provenance};
use crate::conflict::Signature;
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::merge::Merge;
use crate::ops::PreparedOp;
use crate::records::Records;
use crate::store::types::ObjectKind;
use crate::store::{Store, StoreError};

/// One commit to create.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewRequest {
    /// The tree this commit records.
    pub tree: Oid,
    /// Ordered parents. Each must be a stored commit.
    pub parents: Vec<Head>,
    /// Author identity written to the record.
    pub author: Signature,
    /// Committer identity written to the record.
    pub committer: Signature,
    /// Raw message bytes. A NUL byte is refused.
    pub message: ByteString,
    /// The change this commit belongs to. When absent, an ID is resolved for
    /// the tree through the stable by-OID mapping (deterministically derived
    /// from the OID when no row exists yet).
    pub change_id: Option<ChangeId>,
    /// The earlier head this commit rewrites, when it is a local rewrite.
    pub predecessor: Option<Head>,
    /// Provenance claims, when the caller has them.
    pub provenance: Option<Provenance>,
}

/// What publication produced.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NewResult {
    /// The stored head, which is the new commit's identity.
    pub head: Head,
    /// The change the commit belongs to.
    pub change_id: ChangeId,
    /// The commit's object ID when it is a Git commit.
    pub oid: Option<Oid>,
}

/// Creates and publishes one native commit.
///
/// # Preconditions
/// - `tree` names a stored tree object of this repository's hash kind.
/// - Every parent is a stored commit, and the parents are distinct.
/// - A `predecessor` is a current head of `change_id`.
///
/// # Errors
/// `E_OBJECT_FORMAT` for a digest of the wrong width, `E_NOT_FOUND` for a
/// tree that is not a stored tree, `E_INVALID` for a parent that is not a
/// stored commit or a message carrying NUL, and `E_STALE` when the
/// predecessor is not a current head of the change. Store failures map by
/// their own code. Nothing is published unless every check passes.
///
/// Publishing runs [`prepare_new`] first, so validation and staging are
/// shared, not duplicated.
///
/// # Errors
/// Same as [`prepare_new`], plus the store's own publication failures.
pub fn new(store: &Store, request: NewRequest) -> Result<NewResult, CoreError> {
    let prepared = prepare_new(store, request)?;
    store
        .publish(prepared.objects, &prepared.facts)
        .map_err(store_error)?;
    Ok(prepared.output)
}

/// Validates one commit creation and stages its publication parts without
/// publishing.
///
/// Runs every check [`new`] runs — tree and parent storage, change
/// resolution, and record preparation — and returns the staged objects,
/// exact-expectation facts, and the output publication will produce.
///
/// # Errors
/// `E_OBJECT_FORMAT` for a digest of the wrong width, `E_NOT_FOUND` for a
/// tree that is not a stored tree, `E_INVALID` for a parent that is not a
/// stored commit or a message carrying NUL, and `E_STALE` when the
/// predecessor is not a current head of the change. Store failures map by
/// their own code.
pub fn prepare_new(store: &Store, request: NewRequest) -> Result<PreparedOp<NewResult>, CoreError> {
    let kind = store.hash_kind();
    request.tree.expect_kind(kind, "tree")?;
    for parent in &request.parents {
        parent.validate(kind)?;
        require_stored_commit(store, parent)?;
    }
    require_tree(store, request.tree)?;

    let records = Records::new(store);
    let mut preparer = records.batch_preparer();
    let change_id = match request.change_id {
        Some(id) => id,
        None => preparer.resolve_or_mint_change_id(&request.tree)?,
    };
    let input = NativeCommitInput {
        change_id,
        tree: Merge::from_vec(vec![request.tree]),
        parents: request.parents,
        predecessor: request.predecessor,
        author: request.author,
        committer: request.committer,
        extra_headers: Vec::new(),
        message: request.message,
        provenance: request.provenance,
    };
    let prepared = records.prepare_native_commit(input)?;
    let head = prepared.head;
    let oid = head.as_git().copied();
    let output = NewResult {
        head,
        change_id: prepared.record.change_id(),
        oid,
    };
    if let Some(existing) = records.get_commit(&head)?
        && existing == prepared.record
    {
        return Ok(PreparedOp {
            objects: Vec::new(),
            facts: Vec::new(),
            output,
        });
    }
    Ok(PreparedOp {
        objects: vec![prepared.prepared_object],
        facts: prepared.mutations,
        output,
    })
}

/// Refuses a parent that is not a stored commit of this repository.
fn require_stored_commit(store: &Store, parent: &Head) -> Result<(), CoreError> {
    let records = Records::new(store);
    if records.get_commit(parent)?.is_some() {
        return Ok(());
    }
    // A Git parent that this repository imported without a record still
    // names a stored commit object; the record table is the authority, so
    // absence is a missing commit, not a missing object.
    Err(CoreError::new(
        ErrorCode::ENotFound,
        format!("parent {} is not a stored commit", describe_head(parent)),
    ))
}

/// Refuses a tree that is not a stored tree of this repository.
fn require_tree(store: &Store, tree: Oid) -> Result<(), CoreError> {
    let Some(len) = store.object_len(tree)? else {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("tree {tree} is not stored"),
        ));
    };
    let read = store.read(tree)?;
    if read.kind != ObjectKind::Tree {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "{tree} is a {:?} object of {len} bytes, not a tree",
                read.kind
            ),
        ));
    }
    Ok(())
}

fn describe_head(head: &Head) -> String {
    match head {
        Head::Git { oid } => oid.to_string(),
        Head::Conflicted { key } => format!("{key:?}"),
    }
}

fn store_error(error: StoreError) -> CoreError {
    CoreError::new(error.code(), error.to_string())
}
