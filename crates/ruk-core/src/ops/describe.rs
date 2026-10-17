//! `describe`: read one change or one commit in its typed form.
//!
//! The operation answers a question, so it never publishes and never
//! mutates. A caller names either a commit identity or a change; a change
//! answer reports every current head, so a divergent change is visible
//! instead of silently resolving to the first head.

use serde::{Deserialize, Serialize};

use crate::change::ChangeId;
use crate::commit::CommitRecord;
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::records::{ChangeEntry, ChangeState, Records};
use crate::store::Store;

/// What to describe: exactly one of a commit head or a change.
///
/// A `Head` carries its own `type` tag, so the request cannot be an
/// internally tagged enum without colliding with it; the two optional fields
/// make the invalid both-and shape unrepresentable at validation instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DescribeRequest {
    /// The commit to describe, when a commit is named.
    pub head: Option<Head>,
    /// The change to describe, when a change is named.
    pub change_id: Option<ChangeId>,
}

impl DescribeRequest {
    /// Describes one commit.
    #[must_use]
    pub const fn commit(head: Head) -> Self {
        Self {
            head: Some(head),
            change_id: None,
        }
    }

    /// Describes one change.
    #[must_use]
    pub const fn change(change_id: ChangeId) -> Self {
        Self {
            head: None,
            change_id: Some(change_id),
        }
    }
}

/// A stored commit in readable form.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CommitDescription {
    /// The commit identity.
    pub head: Head,
    /// The change the commit belongs to.
    pub change_id: ChangeId,
    /// The tree terms; a singleton for every exportable commit.
    pub tree: Vec<String>,
    /// The ordered parents.
    pub parents: Vec<Head>,
    /// The earlier head this commit rewrites, if it is a local rewrite.
    pub predecessor: Option<Head>,
    /// The author line as stored.
    pub author: String,
    /// The committer line as stored.
    pub committer: String,
    /// Whether the record is a Git commit payload rather than a native
    /// conflict-v1 body.
    pub exportable: bool,
    /// The message bytes, rendered as UTF-8 when valid and as hex otherwise.
    pub message: String,
}

/// A stored change in readable form.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ChangeDescription {
    /// The change.
    pub change_id: ChangeId,
    /// Every current head, in stored order.
    pub heads: Vec<Head>,
    /// Whether the change has more than one current head.
    pub divergent: bool,
    /// The stored change state.
    pub state: ChangeState,
}

/// Reads one commit or one change.
///
/// # Errors
/// `E_NOT_FOUND` when the named commit or change is not stored;
/// `E_OBJECT_FORMAT` for a head of the wrong width; store failures map by
/// their own code.
pub fn describe(store: &Store, request: DescribeRequest) -> Result<Description, CoreError> {
    match (request.head, request.change_id) {
        (Some(head), None) => describe_one_commit(store, head).map(Description::Commit),
        (None, Some(change_id)) => describe_one_change(store, change_id).map(Description::Change),
        (Some(_), Some(_)) => Err(CoreError::new(
            ErrorCode::EInvalid,
            "describe names both a commit and a change",
        )),
        (None, None) => Err(CoreError::new(
            ErrorCode::EInvalid,
            "describe names neither a commit nor a change",
        )),
    }
}

fn describe_one_commit(store: &Store, head: Head) -> Result<CommitDescription, CoreError> {
    head.validate(store.hash_kind())?;
    let record = Records::new(store).get_commit(&head)?.ok_or_else(|| {
        CoreError::new(
            ErrorCode::ENotFound,
            format!("commit {head:?} is not stored"),
        )
    })?;
    Ok(describe_commit(head, &record))
}

fn describe_one_change(store: &Store, change_id: ChangeId) -> Result<ChangeDescription, CoreError> {
    let entry = Records::new(store).get_change(&change_id)?.ok_or_else(|| {
        CoreError::new(
            ErrorCode::ENotFound,
            format!("change {change_id} is not stored"),
        )
    })?;
    Ok(describe_change(change_id, entry))
}

/// Either answer.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Description {
    /// One commit.
    Commit(CommitDescription),
    /// One change.
    Change(ChangeDescription),
}

fn describe_commit(head: Head, record: &CommitRecord) -> CommitDescription {
    CommitDescription {
        head,
        change_id: record.change_id(),
        tree: record.tree().iter().map(ToString::to_string).collect(),
        parents: record.parents().to_vec(),
        predecessor: record.predecessor(),
        author: render(&record.author_ident()),
        committer: render(&record.committer_ident()),
        exportable: record.git_payload().is_some(),
        message: render(record.message()),
    }
}

fn describe_change(change_id: ChangeId, entry: ChangeEntry) -> ChangeDescription {
    ChangeDescription {
        change_id,
        divergent: entry.is_divergent(),
        heads: entry.heads,
        state: entry.state,
    }
}

/// Renders bytes as UTF-8 when valid, else as lowercase hex.
fn render(bytes: &[u8]) -> String {
    if let Ok(text) = core::str::from_utf8(bytes) {
        return text.to_owned();
    }
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use core::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}
