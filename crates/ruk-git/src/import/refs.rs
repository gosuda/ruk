//! Source ref enumeration and three-way ref planning.
//!
//! Refs are read through [`gix_ref`] (loose files plus `packed-refs`) and
//! HEAD is followed one symbolic level. Every imported ref is planned
//! three-way: the previous `remote_observations` value is the base, the
//! stored `refs` value is local, and the source value is new.
//!
//! - Absent local becomes Created with an `Absent` expectation.
//! - A local that equals the source is Unchanged and emits no fact.
//! - A local that still equals the base fast-forwards to Updated with an
//!   exact `Present(local)` expectation.
//! - A source that still equals the base leaves a natively moved ref alone
//!   (KeptLocal, no fact).
//! - Anything else is divergence: direct/direct pairs record their terms
//!   in `ref_conflicts` and keep the local ref (Conflicted); symbolic
//!   targets cannot be merged and are reported without touching the ref
//!   (SymbolicDiverged).
//!
//! Observation rows always advance to the source value with an exact
//! expected-old, and every Created/Updated direct ref appends one reflog
//! entry under the caller's operation id. Ref facts publish only in the
//! final batch, after the object closure is complete. Refs deleted from the
//! source are not removed locally: that scan needs a ranged fact read the
//! store does not expose publicly, so stale observation rows for deleted
//! source refs are a named limitation (see [`plan_refs`]).

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};

use ruk_core::bytes::ByteString;
use ruk_core::change::OperationId;
use ruk_core::conflict::Signature;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{
    RefChange, RefExpect, RefName, RefRead, RefTarget, RefTransaction, RefUpdate,
};
use ruk_core::refs::{
    ReflogKey, ReflogRecord, StoreRefs, prepare_append_reflog, prepare_checked_transaction,
    prepare_set_ref_conflict,
};
use ruk_core::store::{FactExpectation, FactMutation, FactTable, Store};

use crate::GitError;
use crate::import::objects::{SourceObject, oid_from_gix};
use crate::import::walk::object_links;

/// One ref as the source holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceRef {
    pub name: RefName,
    pub target: RefTarget,
}

/// All source refs in name-byte order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceRefs {
    pub refs: Vec<SourceRef>,
}

impl SourceRefs {
    /// Finds a ref by exact name.
    #[must_use]
    pub fn find(&self, name: &RefName) -> Option<&SourceRef> {
        self.refs
            .binary_search_by(|candidate| candidate.name.as_bytes().cmp(name.as_bytes()))
            .ok()
            .map(|index| &self.refs[index])
    }
}

/// The source HEAD: a symbolic name with its one-level target, or a
/// detached object id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceHead {
    Symbolic { name: RefName, target: Option<Oid> },
    Detached(Oid),
}

/// What happened to one imported ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefOutcome {
    pub name: RefName,
    pub imported: RefTarget,
    /// The object an annotated-tag tip peels to, when the tip was a tag.
    pub peeled: Option<Oid>,
    pub decision: RefDecision,
}

/// The three-way decision for one ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefDecision {
    Created,
    Unchanged,
    Updated { previous: RefTarget },
    KeptLocal { local: RefTarget },
    Conflicted { local: RefTarget },
    SymbolicDiverged { local: RefTarget },
}

/// Reads every source ref plus HEAD.
///
/// # Errors
/// [`GitError::Invalid`] for a source ref name the model rejects or a
/// malformed HEAD; [`GitError::ObjectFormat`] for an OID of the wrong
/// width; [`GitError::Io`] when ref files cannot be listed.
pub(crate) fn read_source_refs(
    git_dir: &std::path::Path,
    kind: HashKind,
) -> Result<(SourceRefs, Option<SourceHead>), GitError> {
    let backend = gix_ref::file::Store::at(git_dir.to_path_buf(), kind.gix());
    let platform = backend.iter().map_err(|err| GitError::Corrupt {
        detail: format!("cannot parse refs in {}: {err}", git_dir.display()),
    })?;
    let iter = platform.all().map_err(|err| GitError::Io {
        detail: format!("cannot list refs in {}: {err}", git_dir.display()),
    })?;
    let mut refs = Vec::new();
    for item in iter {
        let reference = item.map_err(|err| GitError::Io {
            detail: format!("cannot read ref in {}: {err}", git_dir.display()),
        })?;
        let raw_name: &[u8] = AsRef::<[u8]>::as_ref(reference.name.as_bstr());
        let name = RefName::new(raw_name.to_vec()).map_err(|err| GitError::Invalid {
            detail: format!("source ref name is invalid: {err}"),
        })?;
        let target = match &reference.target {
            gix_ref::Target::Object(id) => RefTarget::Direct(oid_from_gix(id, kind).map_err(
                |err| GitError::ObjectFormat {
                    detail: err.to_string(),
                },
            )?),
            gix_ref::Target::Symbolic(name) => {
                let raw_target: &[u8] = AsRef::<[u8]>::as_ref(name.as_bstr());
                let target =
                    RefName::new(raw_target.to_vec()).map_err(|err| GitError::Invalid {
                        detail: format!("source symbolic target is invalid: {err}"),
                    })?;
                RefTarget::Symbolic(target)
            }
        };
        refs.push(SourceRef { name, target });
    }
    refs.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let source = SourceRefs { refs };
    let head = read_head(git_dir, kind, &source)?;
    Ok((source, head))
}

fn read_head(
    git_dir: &std::path::Path,
    kind: HashKind,
    source: &SourceRefs,
) -> Result<Option<SourceHead>, GitError> {
    let path = git_dir.join("HEAD");
    let mut text = Vec::new();
    match File::open(&path) {
        Ok(mut file) => file.read_to_end(&mut text).map_err(|err| GitError::Io {
            detail: format!("cannot read {}: {err}", path.display()),
        })?,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(GitError::Io {
                detail: format!("cannot open {}: {err}", path.display()),
            });
        }
    };
    let line: &[u8] = text.strip_suffix(b"\n").unwrap_or(&text);
    if let Some(name) = line.strip_prefix(b"ref: ") {
        let name = RefName::new(name.to_vec()).map_err(|err| GitError::Corrupt {
            detail: format!("source HEAD is invalid: {err}"),
        })?;
        let target = source.find(&name).and_then(|found| match &found.target {
            RefTarget::Direct(oid) => Some(*oid),
            RefTarget::Symbolic(_) => None,
        });
        return Ok(Some(SourceHead::Symbolic { name, target }));
    }
    let text = core::str::from_utf8(line).map_err(|_| GitError::Corrupt {
        detail: "source HEAD is neither a symbolic reference nor hex".to_owned(),
    })?;
    crate::parse_oid_for(text.trim(), kind)
        .map(SourceHead::Detached)
        .map_err(|_| GitError::Corrupt {
            detail: "source HEAD is neither a symbolic reference nor hex".to_owned(),
        })
        .map(Some)
}

/// Observation row key: `source ++ 0x00 ++ full refname`.
#[must_use]
pub fn observation_key(source: &[u8], name: &RefName) -> Vec<u8> {
    let mut key = Vec::with_capacity(source.len() + 1 + name.as_bytes().len());
    key.extend_from_slice(source);
    key.push(0x00);
    key.extend_from_slice(name.as_bytes());
    key
}

/// Observation row value: `0x00 ++ raw oid` for a direct target,
/// `0x01 ++ refname` for a symbolic one.
#[must_use]
pub fn encode_observation(target: &RefTarget) -> Vec<u8> {
    match target {
        RefTarget::Direct(oid) => {
            let mut value = Vec::with_capacity(1 + oid.as_bytes().len());
            value.push(0x00);
            value.extend_from_slice(oid.as_bytes());
            value
        }
        RefTarget::Symbolic(name) => {
            let mut value = Vec::with_capacity(1 + name.as_bytes().len());
            value.push(0x01);
            value.extend_from_slice(name.as_bytes());
            value
        }
    }
}

/// Decodes an observation row value.
///
/// # Errors
/// [`GitError::Corrupt`] for a bad tag, width, or ref name.
pub fn decode_observation(bytes: &[u8], kind: HashKind) -> Result<RefTarget, GitError> {
    let bad = || GitError::Corrupt {
        detail: "remote_observations row is malformed".to_owned(),
    };
    let (tag, rest) = bytes.split_first().ok_or_else(bad)?;
    match tag {
        0x00 => {
            let oid = Oid::from_bytes(rest).map_err(|_| bad())?;
            crate::require_kind(oid, kind)
                .map(RefTarget::Direct)
                .map_err(|err| GitError::Corrupt {
                    detail: err.to_string(),
                })
        }
        0x01 => RefName::new(rest.to_vec())
            .map(RefTarget::Symbolic)
            .map_err(|_| bad()),
        _ => Err(bad()),
    }
}

/// Shallow row key: the raw OID bytes; the value is always empty.
#[must_use]
pub fn shallow_key(oid: Oid) -> Vec<u8> {
    oid.as_bytes().to_vec()
}

fn direct(target: &RefTarget) -> Option<Oid> {
    match target {
        RefTarget::Direct(oid) => Some(*oid),
        RefTarget::Symbolic(_) => None,
    }
}

/// Ref facts plus per-ref outcomes. Observation fact expectations are exact
/// (absent or the previous bytes); ref-table expectations come from
/// [`prepare_checked_transaction`] against the live store.
#[derive(Debug)]
pub(crate) struct RefPlan {
    pub outcomes: Vec<RefOutcome>,
    pub facts: Vec<FactMutation>,
}

/// Plans every source ref three-way. Reads the live `refs` value for the
/// decision and the expectation, then prepares one checked transaction so
/// directory/file collisions and symbolic chains are validated.
///
/// Limitation: refs deleted from the source keep their last observation
/// row and are never removed locally, because that scan needs a ranged
/// fact read the store does not expose publicly.
///
/// # Errors
/// [`GitError::Stale`] when the store moved under the lane; model
/// rejections as their own codes.
pub(crate) fn plan_refs(
    store: &Store,
    request: &crate::import::ImportRequest<'_>,
    source: &SourceRefs,
    peeled: &HashMap<Oid, Oid>,
) -> Result<RefPlan, GitError> {
    let reader = StoreRefs::new(store);
    let observation_source = request.observation_source;
    let operation = request.operation;
    let committer = &request.committer;
    let message = &request.message;
    let mut outcomes = Vec::with_capacity(source.refs.len());
    let mut updates = Vec::new();
    let mut facts = Vec::new();
    let mut reflogs: Vec<(RefName, Option<Oid>, Option<Oid>)> = Vec::new();

    for candidate in &source.refs {
        let local = reader.get(&candidate.name).map_err(GitError::from)?;
        let key = observation_key(observation_source, &candidate.name);
        let base_bytes = store
            .fact(FactTable::RemoteObservations, &key)
            .map_err(GitError::from)?;
        let base = base_bytes
            .as_deref()
            .map(|bytes| decode_observation(bytes, store.hash_kind()))
            .transpose()?;

        let decision = match (&local, &base) {
            (None, _) => RefDecision::Created,
            (Some(local), _) if local == &candidate.target => RefDecision::Unchanged,
            (Some(local), Some(base)) if local == base => RefDecision::Updated {
                previous: local.clone(),
            },
            (Some(local), Some(base)) if base == &candidate.target => RefDecision::KeptLocal {
                local: local.clone(),
            },
            (Some(local), _) => match (&local, &candidate.target) {
                (RefTarget::Direct(_), RefTarget::Direct(_)) => RefDecision::Conflicted {
                    local: local.clone(),
                },
                _ => RefDecision::SymbolicDiverged {
                    local: local.clone(),
                },
            },
        };

        match &decision {
            RefDecision::Created | RefDecision::Updated { .. } => {
                let expected = match &local {
                    Some(target) => RefExpect::Present(target.clone()),
                    None => RefExpect::Absent,
                };
                updates.push(RefUpdate {
                    name: candidate.name.clone(),
                    expected,
                    change: RefChange::Set(candidate.target.clone()),
                });
                if direct(&candidate.target).is_some()
                    || local.as_ref().is_some_and(|t| direct(t).is_some())
                {
                    reflogs.push((
                        candidate.name.clone(),
                        local.as_ref().and_then(direct),
                        direct(&candidate.target),
                    ));
                }
            }
            RefDecision::Conflicted { local } => {
                facts.extend(ruk_core::refs::tag_freeze_guards(
                    store,
                    &[&candidate.name],
                )?);
                let base_oid = base.as_ref().and_then(direct);
                let merge = ruk_core::merge::Merge::from_removes_adds(
                    [base_oid],
                    [direct(local), direct(&candidate.target)],
                );
                facts.push(
                    prepare_set_ref_conflict(store, &candidate.name, &merge)
                        .map_err(GitError::from)?,
                );
            }
            RefDecision::Unchanged
            | RefDecision::KeptLocal { .. }
            | RefDecision::SymbolicDiverged { .. } => {}
        }

        let expected = base_bytes.map_or(FactExpectation::Absent, FactExpectation::Value);
        facts.push(FactMutation {
            table: FactTable::RemoteObservations,
            key,
            expected,
            value: Some(encode_observation(&candidate.target)),
        });

        let peeled = match &candidate.target {
            RefTarget::Direct(oid) => peeled.get(oid).copied(),
            RefTarget::Symbolic(_) => None,
        };
        outcomes.push(RefOutcome {
            name: candidate.name.clone(),
            imported: candidate.target.clone(),
            peeled,
            decision,
        });
    }

    if !updates.is_empty() {
        let transaction = RefTransaction::new(store.hash_kind(), updates).map_err(ref_error)?;
        transaction.check(&reader).map_err(ref_error)?;
        let prepared = prepare_checked_transaction(store, &transaction).map_err(GitError::from)?;
        facts.extend(prepared.into_mutations());
    }

    append_reflogs(store, operation, committer, message, reflogs, &mut facts)?;

    Ok(RefPlan { outcomes, facts })
}

fn ref_error(err: ruk_core::refdata::RefError) -> GitError {
    GitError::from(ruk_core::error::CoreError::from(err))
}

fn append_reflogs(
    store: &Store,
    operation: OperationId,
    committer: &Signature,
    message: &ByteString,
    entries: Vec<(RefName, Option<Oid>, Option<Oid>)>,
    facts: &mut Vec<FactMutation>,
) -> Result<(), GitError> {
    for (index, (name, old_oid, new_oid)) in entries.into_iter().enumerate() {
        let ordinal = u64::try_from(index).map_err(|_| GitError::Limit {
            detail: "too many reflog entries in one import".to_owned(),
        })?;
        let key = ReflogKey::new(name, operation, ordinal);
        let record = ReflogRecord {
            operation,
            old_oid,
            new_oid,
            committer: committer.clone(),
            message: message.clone(),
        };
        facts.push(prepare_append_reflog(store, &key, &record).map_err(GitError::from)?);
    }
    Ok(())
}

/// Follows one tag hop for peel reporting; shared with the walk cache.
pub(crate) fn tag_target(object: &SourceObject, hash: HashKind) -> Result<Option<Oid>, GitError> {
    if object.kind != ruk_core::store::ObjectKind::Tag {
        return Ok(None);
    }
    let links = object_links(object.kind, &object.payload, hash)?;
    links.links.into_iter().next().map(|link| link.oid).map_or(
        Err(GitError::Corrupt {
            detail: "tag has no target".to_owned(),
        }),
        |oid| Ok(Some(oid)),
    )
}
