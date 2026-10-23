//! Hosted `tree` read: one git-order directory listing with stateless
//! keyset paging.
//!
//! The coordinator resolves the revision and the directory; this module
//! lists it. Paging resumes after an entry name, so no lease state is
//! held. Blob sizes come from the object-length index without loading
//! bodies; anything past the hosted read bound refuses before it loads.

use crate::coord::reads::{DIFF_MAX_ENTRIES, sized_tree_entry, tree_items};
use crate::error::{CoreError, ErrorCode};
use crate::ids::{HashKind, Oid};
use crate::index::RepoPath;
use crate::protocol::{KeysetPage, TreeEntry};
use crate::store::Store;
use crate::workcopy::tree::TreeMode;

/// Lists one directory in git order with keyset paging.
///
/// `root` is the resolved revision tree and `path` the directory inside
/// it (absent is the root). A path naming a blob refuses
/// [`ErrorCode::EInvalid`]; a missing path refuses `E_NOT_FOUND`. Only
/// entries after `after` (exclusive, matched by exact name) return, up to
/// `limit` rows; `next_after` names the last returned entry while rows
/// remain. Blob sizes report stored object lengths; trees report no size.
///
/// # Errors
/// `E_INVALID` for a blob path or an unknown cursor name, `E_NOT_FOUND`
/// for a missing path, `E_CORRUPT` for a malformed tree or a dangling
/// blob link, `E_LIMIT` past the entry or object bounds.
pub(crate) fn list_directory(
    store: &Store,
    kind: HashKind,
    root: Oid,
    path: Option<&RepoPath>,
    limit: usize,
    after: Option<&[u8]>,
) -> Result<KeysetPage<TreeEntry>, CoreError> {
    let dir = match path {
        None => root,
        Some(path) => {
            let node = crate::ops::tree_edit::lookup(store, root, path)?
                .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "no entry at path"))?;
            match node {
                (TreeMode::Tree, oid) => oid,
                _ => {
                    return Err(CoreError::new(
                        ErrorCode::EInvalid,
                        "tree path names a blob",
                    ));
                }
            }
        }
    };
    let items = tree_items(store, kind, dir)?;
    let start = match after {
        None => 0,
        Some(name) => {
            let position = items
                .iter()
                .position(|item| item.name.as_slice() == name)
                .ok_or_else(|| {
                    CoreError::new(ErrorCode::EInvalid, "tree cursor names a missing entry")
                })?;
            position + 1
        }
    };
    if items.len() > DIFF_MAX_ENTRIES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "tree visits more entries than its bound",
        ));
    }
    let end = start.saturating_add(limit).min(items.len());
    let mut entries = Vec::new();
    for item in items.get(start..end).unwrap_or_default() {
        entries.push(sized_tree_entry(
            store,
            item.name.clone(),
            item.mode,
            item.oid,
        )?);
    }
    let next_after = if end >= items.len() {
        None
    } else {
        entries.last().map(|entry| entry.name.clone())
    };
    KeysetPage::new(entries, next_after)
}
