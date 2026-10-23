//! Ref selection and Git ref encoding.
//!
//! [`RefPlan`] is built from the store's ref page and its native conflicts
//! before any object is packed: symbolic refs, sorted direct refs (heads,
//! tags, and every other namespace — including `refs/notes/ruk-attest`,
//! named in the contract), ref-conflict rows, and the requested HEAD.
//!
//! A ref is written when its resolved closure is entirely Git
//! ([`crate::export::objects`]). Any other ref is dropped and named in the
//! report: a ref with a conflict row, a root that is or reaches a native
//! record, or a chain ending at such a ref. A direct ref never renders a
//! native placeholder.

use std::collections::BTreeMap;

use ruk_core::ids::Oid;
use ruk_core::refdata::{RefMap, RefName, RefTarget, RefUpdate, resolve};
use ruk_core::refs::RefEntry;
use ruk_core::refs::{RefConflictEntry, RefConflictPage, page_ref_conflicts, page_refs};
use ruk_core::store::Store;
use ruk_core::workspace::HeadRef;

use super::objects::{NativeReason, RootOutcome};
use super::report::{UnexportedReason, UnexportedRef};
use crate::GitError;

/// Refs per 1000-row page.
const PAGE_LIMIT: usize = 1000;

/// The ref decisions for one export.
#[derive(Debug)]
pub(crate) struct RefPlan {
    /// Direct refs to write, in byte order: target and peeled target.
    pub(crate) direct: BTreeMap<RefName, (Oid, Oid)>,
    /// Symbolic refs to write as loose files, in byte order.
    pub(crate) symbolic: BTreeMap<RefName, RefName>,
    /// Refs that are named in the report instead of written.
    pub(crate) unexported: Vec<UnexportedRef>,
    /// Conflict rows: terms count per name, for the report.
    pub(crate) conflicts: BTreeMap<RefName, usize>,
    /// Whether the symbolic HEAD's target was exported (or is unborn).
    pub(crate) head_exported: bool,
}

impl RefPlan {
    /// Builds the plan: pages every ref and every ref conflict, resolves
    /// every symbolic chain, walks every direct root, drops symbolic refs
    /// whose terminal was not exported, and follows the HEAD.
    ///
    /// # Errors
    /// [`GitError::Invalid`] for a symbolic cycle or a detached HEAD at a
    /// native record; store failures while paging; object failures while
    /// walking.
    pub(crate) fn build(
        store: &Store,
        head: &HeadRef,
        closure: &mut super::objects::Closure<'_>,
    ) -> Result<Self, GitError> {
        let conflicts = load_conflicts(store)?;
        let entries = load_refs(store)?;
        let mut plan = Self {
            direct: BTreeMap::new(),
            symbolic: BTreeMap::new(),
            unexported: Vec::new(),
            conflicts,
            head_exported: false,
        };
        let mut table = RefMap::new();
        table
            .apply(
                store.hash_kind(),
                entries
                    .iter()
                    .map(|row| RefUpdate {
                        name: row.name.clone(),
                        expected: ruk_core::refdata::RefExpect::Any,
                        change: ruk_core::refdata::RefChange::Set(row.target.clone()),
                    })
                    .collect(),
            )
            .map_err(|err| GitError::Invalid {
                detail: format!("stored refs are inconsistent: {err}"),
            })?;
        for entry in &entries {
            plan.add(entry, &table)?;
        }
        for entry in &entries {
            plan.finish(entry, closure)?;
        }
        plan.prune_symbolic(&table)?;
        plan.follow_head(head, &table, closure)?;
        Ok(plan)
    }

    /// Records the ref structurally; conflicted refs drop out here. A
    /// symbolic ref records its immediate link; whether its terminal was
    /// exported is decided in [`Self::prune_symbolic`], after the direct
    /// roots have been walked.
    fn add(&mut self, entry: &RefEntry, table: &RefMap) -> Result<(), GitError> {
        if let Some(&terms) = self.conflicts.get(&entry.name) {
            self.unexported.push(UnexportedRef {
                name: entry.name.clone(),
                reason: UnexportedReason::Conflicted,
                oid: None,
                terms: Some(terms),
            });
            return Ok(());
        }
        if let RefTarget::Symbolic(target) = &entry.target {
            resolve(table, &entry.name).map_err(|err| GitError::Invalid {
                detail: format!("ref {} does not resolve: {err}", entry.name),
            })?;
            self.symbolic.insert(entry.name.clone(), target.clone());
        }
        Ok(())
    }

    /// Drops every symbolic ref whose terminal ref was not exported (and is
    /// not unborn). Chains to a conflicted or native terminal name the ref
    /// in the report instead of writing a link Git would misread.
    fn prune_symbolic(&mut self, table: &RefMap) -> Result<(), GitError> {
        let mut dropped = Vec::new();
        for name in self.symbolic.keys() {
            let terminal = resolve(table, name).map_err(|err| GitError::Invalid {
                detail: format!("ref {name} does not resolve: {err}"),
            })?;
            let terminal_unexported = self.unexported.iter().any(|u| u.name == terminal.terminal);
            if terminal_unexported {
                dropped.push(name.clone());
            }
        }
        for name in dropped {
            self.symbolic.remove(&name);
            self.unexported.push(UnexportedRef {
                name,
                reason: UnexportedReason::SymbolicToUnexported,
                oid: None,
                terms: None,
            });
        }
        Ok(())
    }

    /// Walks every direct root and files it exported or unexported.
    fn finish(
        &mut self,
        entry: &RefEntry,
        closure: &mut super::objects::Closure<'_>,
    ) -> Result<(), GitError> {
        let RefTarget::Direct(oid) = &entry.target else {
            return Ok(());
        };
        let oid = *oid;
        if self.conflicts.contains_key(&entry.name) {
            return Ok(());
        }
        match closure.add_root(oid)? {
            RootOutcome::Exported { peeled } => {
                let peeled = peeled.unwrap_or(oid);
                self.direct.insert(entry.name.clone(), (oid, peeled));
            }
            RootOutcome::Native {
                reason,
                oid: native,
            } => self.unexported.push(UnexportedRef {
                name: entry.name.clone(),
                reason: reason.into(),
                oid: Some(native),
                terms: None,
            }),
        }
        Ok(())
    }

    /// Follows the requested HEAD. A detached HEAD is itself a root and
    /// joins the export; a symbolic HEAD resolves through the ref table and
    /// is exported when its terminal was exported or is unborn. A symbolic
    /// HEAD is always written, even to an unexported ref: Git then sees an
    /// unborn branch, and the report says so.
    fn follow_head(
        &mut self,
        head: &HeadRef,
        table: &RefMap,
        closure: &mut super::objects::Closure<'_>,
    ) -> Result<(), GitError> {
        match head {
            HeadRef::Detached(oid) => match closure.add_root(*oid)? {
                RootOutcome::Exported { .. } => self.head_exported = true,
                RootOutcome::Native { reason, .. } => {
                    return Err(GitError::Invalid {
                        detail: format!(
                            "detached HEAD at {oid} is {} and cannot be exported",
                            native_name(reason)
                        ),
                    });
                }
            },
            HeadRef::Symbolic(name) => {
                let terminal = resolve(table, name).map_err(|err| GitError::Invalid {
                    detail: format!("HEAD does not resolve: {err}"),
                })?;
                if let Some(oid) = terminal.oid {
                    closure.add_root(oid)?;
                }
                let terminal_unexported =
                    self.unexported.iter().any(|u| u.name == terminal.terminal);
                self.head_exported = !terminal_unexported;
            }
        }
        Ok(())
    }
}

/// The conflict terms per ref name.
fn load_conflicts(store: &Store) -> Result<BTreeMap<RefName, usize>, GitError> {
    let mut out = BTreeMap::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let RefConflictPage { entries, more } =
            page_ref_conflicts(store, after.as_deref(), PAGE_LIMIT)?;
        for RefConflictEntry { name, conflict } in entries {
            let terms = conflict
                .adds()
                .len()
                .saturating_add(conflict.removes().len());
            out.insert(name, terms);
        }
        if !more {
            return Ok(out);
        }
        let Some(last) = out.keys().next_back().cloned() else {
            return Ok(out);
        };
        after = Some(last.as_bytes().to_vec());
    }
}

/// Every ref in byte order.
fn load_refs(store: &Store) -> Result<Vec<RefEntry>, GitError> {
    let mut out = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let page = page_refs(store, after.as_deref(), PAGE_LIMIT)?;
        let more = page.more;
        out.extend(page.entries);
        if !more {
            return Ok(out);
        }
        let Some(last) = out.last() else {
            return Ok(out);
        };
        after = Some(last.name.as_bytes().to_vec());
    }
}

/// The `packed-refs` line for one direct ref.
pub(crate) fn packed_line(name: &RefName, target: &Oid) -> Vec<u8> {
    let mut line = Vec::with_capacity(name.as_bytes().len() + target.to_hex().len() + 2);
    line.extend_from_slice(target.to_hex().as_bytes());
    line.push(b' ');
    line.extend_from_slice(name.as_bytes());
    line.push(b'\n');
    line
}

/// The annotated-tag peel line of `packed-refs`.
pub(crate) fn peel_line(peeled: &Oid) -> Vec<u8> {
    let mut line = Vec::with_capacity(peeled.to_hex().len() + 3);
    line.push(b'^');
    line.extend_from_slice(peeled.to_hex().as_bytes());
    line.push(b'\n');
    line
}

/// A loose symbolic ref file (also the shape of `HEAD`).
pub(crate) fn symbolic_bytes(target: &RefName) -> Vec<u8> {
    let mut out = Vec::with_capacity(target.as_bytes().len() + 9);
    out.extend_from_slice(b"ref: ");
    out.extend_from_slice(target.as_bytes());
    out.push(b'\n');
    out
}

fn native_name(reason: NativeReason) -> &'static str {
    match reason {
        NativeReason::NativeRecord => "a native record",
        NativeReason::NativeInClosure => "rooted past a native record",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_and_symbolic_lines_are_exact() {
        let kind = ruk_core::ids::HashKind::Sha1;
        let oid = kind.hash_git_object("blob", b"x").unwrap();
        let name = RefName::new(b"refs/heads/main" as &[u8]).unwrap();
        let line = packed_line(&name, &oid);
        assert_eq!(line, format!("{oid} refs/heads/main\n").into_bytes());
        assert_eq!(peel_line(&oid), format!("^{oid}\n").into_bytes());
        assert_eq!(symbolic_bytes(&name), b"ref: refs/heads/main\n".to_vec());
    }

    #[test]
    fn native_reason_names_refuse_placeholders() {
        assert_eq!(native_name(NativeReason::NativeRecord), "a native record");
        assert_eq!(
            native_name(NativeReason::NativeInClosure),
            "rooted past a native record"
        );
    }
}
