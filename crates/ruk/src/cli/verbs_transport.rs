//! Transport and maintenance verbs: `fetch`, `pull`, `push`,
//! `receive-pack`, `upload-pack`, `archive`, `bundle`, `gc`, `fsck`,
//! `ls-remote`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `fetch` | local stores via `session::local_fetch`, SSH/git-daemon remotes via `fetch::receive` over `net` streams | `--prune` drops orphaned remote-tracking refs (pull-mirror parity); `http(s)` is a named gap |
//! | `pull` | fetch + fast-forward | local and SSH/git remotes (fast-forward only) |
//! | `push` | local stores via `session::local_push`, SSH/git-daemon remotes via `push::push_over`, both with a persisted plan | `--mirror` sets every ref and deletes stale ones (push-mirror parity); `http(s)` is a named gap |
//! | `receive-pack` | `serve::serve_receive_pack` + `session::apply_refs` | served (protocol v0) |
//! | `upload-pack` | `serve::serve_upload_pack` + `session::local_closure` | served (protocol v0) |
//! | `archive` | no archive writer | unsupported |
//! | `bundle` | no bundle format | unsupported |
//! | `gc` | no repack/prune lane | unsupported |
//! | `fsck` | ref walk + object existence | implemented (reachable only; no dangling census) |
//! | `ls-remote` | local `session::advertise` or one `net::discover` round trip | SSH/git remotes served; `http(s)` is a named gap |
//!
//! Oracle anchors: `git/builtin/fetch.c`, `git/builtin/pull.c`,
//! `git/builtin/push.c`, `git/builtin/receive-pack.c`,
//! `git/builtin/upload-pack.c`, `git/builtin/archive.c`,
//! `git/builtin/bundle.c`, `git/builtin/gc.c`, `git/builtin/fsck.c`,
//! `git/builtin/ls-remote.c`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use ruk_core::change::PlanId;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefRead, RefTarget, RefUpdate};
use ruk_core::refs::StoreRefs;
use ruk_core::store::{FactExpectation, FactMutation, FactTable, ObjectKind, Store};
use ruk_core::{LfsMode, mode_for_store};
use ruk_git::GitError;
use ruk_git::transport::archive::serve_upload_archive;
use ruk_git::transport::fetch::{self, FetchWireRequest};
use ruk_git::transport::mirror::{prune_for_spec, push_mirror_updates};
use ruk_git::transport::net::{self, Endpoint};
use ruk_git::transport::pack::IngestLimits;
use ruk_git::transport::push::{PushUpdate, PushWireRequest};
use ruk_git::transport::serve::{HeadAdvertisement, serve_receive_pack, serve_upload_pack};
use ruk_git::transport::session::{
    AdvertisedLocalRef, LocalFetchRequest, Service, advertise, local_fetch, local_push,
    open_local_store,
};
use ruk_git::transport::{Interrupt, has_object, observation_key};

use super::state::{
    is_ancestor, list_refs, load_or_default, open_store_at, remote_fetch_specs, remote_root,
    resolve_rev, scan_index, walk_history,
};
use super::{Ctx, FlagSpec, collect, line};

/// Downloads objects and refs from a local repository.
///
/// Oracle: `git/builtin/fetch.c`.
pub(crate) fn fetch(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        FlagSpec {
            long: "tags",
            short: Some('t'),
            takes_value: false,
        },
        FlagSpec {
            long: "depth",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "prune",
            short: Some('p'),
            takes_value: false,
        },
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let target = opts.positionals.first().map_or("origin", String::as_str);
    let remote_label = configured_name(ctx, target).unwrap_or_else(|| target.to_owned());
    let spec_texts: Vec<String> = if opts.positionals.len() > 1 {
        opts.positionals[1..].to_vec()
    } else {
        remote_fetch_specs(ctx, &remote_label)
    };
    let depth = opts
        .single("depth")?
        .map(|value| {
            value.parse::<u32>().map_err(|_| GitError::Invalid {
                detail: format!("bad depth {value:?}"),
            })
        })
        .transpose()?;
    let plan = FetchPlan {
        force_all: opts.is_set("force"),
        depth,
        fetch_tags: opts.is_set("tags"),
        prune: opts.is_set("prune"),
    };
    run_fetch(ctx, &remote_label, &spec_texts, plan)
}

/// How a fetch updates refs. Data, not selectors: one plan per invocation.
pub(crate) struct FetchPlan {
    /// Every update behaves as forced.
    pub(crate) force_all: bool,
    /// Shallow depth, when the caller asked for one.
    pub(crate) depth: Option<u32>,
    /// Also take all advertised tags.
    pub(crate) fetch_tags: bool,
    /// Delete remote-tracking refs whose upstream counterpart is gone.
    pub(crate) prune: bool,
}

/// Where a fetch/push/ls-remote target points: a local repository root or
/// a network endpoint SSH and git-daemon transports serve.
enum Target {
    /// A local repository root holding `.ruk`.
    Local(PathBuf),
    /// An SSH or git-daemon endpoint.
    Net(Endpoint),
}

/// Resolves a remote name or URL: configured names read their URL first,
/// then `file://` URLs and bare paths land local, SSH and git-daemon URLs
/// route network, and HTTP URLs refuse with the named gap.
///
/// Oracle: `git/builtin/fetch.c` (remote resolution).
fn resolve_target(ctx: &Ctx, target: &str) -> Result<Target, GitError> {
    let url = ctx
        .config_get(&format!("remote.{target}.url"))
        .unwrap_or_else(|| target.to_owned());
    match net::parse_endpoint(&url)? {
        Endpoint::Local { .. } => Ok(Target::Local(remote_root(ctx, target)?)),
        endpoint @ (Endpoint::Ssh { .. } | Endpoint::Git { .. }) => Ok(Target::Net(endpoint)),
        Endpoint::Http { url, .. } => Err(net::http_gap(&url)),
    }
}

/// The source side of one fetch: a local store or a network endpoint.
enum FetchSource {
    /// A local source store.
    Local(Store),
    /// A network endpoint (refs discover over a separate connection).
    Net(Endpoint),
}

/// Expands refspecs, negotiates the pack, and updates refs atomically.
///
/// `remote update` shares this path: it passes the remote's configured
/// refspecs with its own prune flag.
///
/// Oracle: `git/builtin/fetch.c`, `git/builtin/remote.c` (`update`).
pub(crate) fn run_fetch(
    ctx: &Ctx,
    remote_label: &str,
    spec_texts: &[String],
    plan: FetchPlan,
) -> Result<Vec<u8>, GitError> {
    let dest = ctx.store()?;
    let dest_kind = ctx.kind()?;
    let (source, advertised) = match resolve_target(ctx, remote_label)? {
        Target::Local(src_root) => {
            let src = open_store_at(&src_root)?;
            if src.hash_kind() != dest_kind {
                return Err(GitError::ObjectFormat {
                    detail: "source and destination object formats disagree".to_owned(),
                });
            }
            let advertised = advertise(&src)?;
            (FetchSource::Local(src), advertised)
        }
        Target::Net(endpoint) => {
            let advertised = net::to_local_refs(net::discover_endpoint(
                &endpoint,
                Service::UploadPack,
                dest_kind,
            )?)?;
            (FetchSource::Net(endpoint), advertised)
        }
    };
    let mut pairs: Vec<FetchedRef> = Vec::new();
    for spec_text in spec_texts {
        match &source {
            FetchSource::Local(src) => pairs.extend(expand_spec(src, &advertised, spec_text)?),
            FetchSource::Net(_) => pairs.extend(expand_spec_net(&advertised, dest, spec_text)?),
        }
    }
    if plan.fetch_tags {
        for entry in &advertised {
            if entry.name.starts_with(b"refs/tags/") {
                let name = RefName::new(entry.name.clone()).map_err(|err| GitError::Invalid {
                    detail: format!("source ref refused: {err}"),
                })?;
                if pairs.iter().any(|fetched| fetched.name == name) {
                    continue;
                }
                if let RefTarget::Direct(oid) = &entry.target {
                    pairs.push(FetchedRef {
                        oid: *oid,
                        name,
                        target: entry.target.clone(),
                        force: false,
                    });
                }
            }
        }
    }
    let dest_refs = StoreRefs::new(dest);
    let pruned = if plan.prune {
        collect_prune_deletes(&advertised, dest, spec_texts, &pairs)?
    } else {
        Vec::new()
    };
    if pairs.is_empty() && pruned.is_empty() {
        return write_fetch_head(ctx, &[]);
    }
    let mut updates = Vec::new();
    let mut tracking = Vec::new();
    let mut lines = Vec::new();
    for fetched in &pairs {
        let oid = fetched.oid;
        let name = &fetched.name;
        let target = &fetched.target;
        let current = dest_refs
            .get(name)
            .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
        if !plan.force_all && !fetched.force {
            if let Some(old) = current_as_direct(&current) {
                if !is_ancestor(dest, old, oid)? {
                    lines.push(format!(
                        "! rejected {} (non-fast-forward)\n",
                        name.to_utf8().unwrap_or_default()
                    ));
                    continue;
                }
            }
        }
        let expected = current.map(RefExpect::Present).unwrap_or(RefExpect::Absent);
        updates.push(RefUpdate {
            name: name.clone(),
            expected,
            change: RefChange::Set(target.clone()),
        });
        tracking.push((name.clone(), target.clone()));
        lines.push(format!(
            "  {} -> {}\n",
            oid.to_hex(),
            name.to_utf8().unwrap_or_default()
        ));
    }
    for name in &pruned {
        let current = dest_refs
            .get(name)
            .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
        let Some(RefTarget::Direct(oid)) = current else {
            continue;
        };
        updates.push(RefUpdate {
            name: name.clone(),
            expected: RefExpect::Present(RefTarget::Direct(oid)),
            change: RefChange::Delete,
        });
        lines.push(format!(
            " - [deleted] {}\n",
            name.to_utf8().unwrap_or_default()
        ));
    }
    let wants: Vec<Oid> = pairs.iter().map(|fetched| fetched.oid).collect();
    let haves: Vec<Oid> = list_refs(dest)?
        .into_iter()
        .filter_map(|(_, target)| match target {
            RefTarget::Direct(oid) => Some(oid),
            RefTarget::Symbolic(_) => None,
        })
        .collect();
    let prepared = ruk_core::refs::prepare_checked_transaction(
        dest,
        &ruk_core::refdata::RefTransaction::new(dest_kind, updates)
            .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?,
    )?;
    let mut ref_mutations = prepared.into_mutations();
    for name in &pruned {
        ref_mutations.push(FactMutation {
            table: FactTable::RemoteObservations,
            key: observation_key(remote_label.as_bytes(), name),
            expected: FactExpectation::Any,
            value: None,
        });
    }
    if pairs.is_empty() {
        // Prune-only: no objects move, so the ref deletes (plus their
        // observation cleanup) publish without a pack round-trip.
        dest.publish(Vec::new(), &ref_mutations)?;
        let mut out = lines.concat().into_bytes();
        out.extend_from_slice(&write_fetch_head(ctx, &pairs)?);
        return Ok(out);
    }
    match &source {
        FetchSource::Local(src) => {
            let request = LocalFetchRequest {
                wants,
                haves,
                filter: None,
                depth: plan.depth,
            };
            local_fetch(
                dest,
                src,
                remote_label.as_bytes(),
                &request,
                &tracking,
                &ref_mutations,
                IngestLimits::default(),
                &Interrupt::none(),
            )?;
        }
        FetchSource::Net(endpoint) => {
            fetch_pack_net(
                dest,
                endpoint,
                remote_label,
                &wants,
                &haves,
                plan.depth,
                &tracking,
                &ref_mutations,
            )?;
        }
    }
    let mut out = lines.concat().into_bytes();
    out.extend_from_slice(&write_fetch_head(ctx, &pairs)?);
    Ok(out)
}

/// Runs the pack half of a network fetch over one upload-pack connection:
/// negotiate the wants, verify the closure, and publish staged objects
/// together with the caller's ref deltas, the way `local_fetch` publishes
/// its pack plus ref mutations in one transaction.
///
/// Oracle: `git/builtin/fetch.c`.
fn fetch_pack_net(
    dest: &Store,
    endpoint: &Endpoint,
    remote_label: &str,
    wants: &[Oid],
    haves: &[Oid],
    depth: Option<u32>,
    tracking: &[(RefName, RefTarget)],
    ref_mutations: &[FactMutation],
) -> Result<(), GitError> {
    let request = FetchWireRequest {
        wants: wants.to_vec(),
        haves: haves.to_vec(),
        filter: None,
        depth,
        shallow: Vec::new(),
        list_refs: false,
        ref_prefixes: Vec::new(),
    };
    let stream = net::open_stream(endpoint, Service::UploadPack)?;
    let received = fetch::receive(
        stream,
        dest.hash_kind(),
        dest,
        &request,
        IngestLimits::default(),
        &Interrupt::none(),
    )?;
    let report = fetch::verify_closure(
        dest,
        &received.staged,
        wants,
        None,
        &received.shallow,
        &Interrupt::none(),
    )?;
    if !report.missing_promisor.is_empty() {
        return Err(GitError::Corrupt {
            detail: "fetch without a filter left promisor objects missing".to_owned(),
        });
    }
    let mut facts = ref_mutations.to_vec();
    facts.extend(fetch::shallow_facts(&received.shallow, &received.unshallow));
    facts.extend(fetch::observation_mutations(
        remote_label.as_bytes(),
        tracking,
    ));
    fetch::publish_fetch(dest, received.staged, &facts)?;
    Ok(())
}

/// Remote-tracking refs one fetch refspec orphans: local destinations
/// whose source counterpart is no longer advertised. Names already taking
/// an update are kept, never pruned; symbolic refs never prune.
fn collect_prune_deletes(
    advertised: &[ruk_git::transport::session::AdvertisedLocalRef],
    dest: &Store,
    spec_texts: &[String],
    pairs: &[FetchedRef],
) -> Result<Vec<RefName>, GitError> {
    let advertised_names: HashSet<Vec<u8>> =
        advertised.iter().map(|entry| entry.name.clone()).collect();
    let local_names: Vec<Vec<u8>> = list_refs(dest)?
        .into_iter()
        .filter_map(|(name, target)| {
            matches!(target, RefTarget::Direct(_)).then(|| name.as_bytes().to_vec())
        })
        .collect();
    let mut pruned = Vec::new();
    for spec_text in spec_texts {
        let spec = parse_spec(spec_text)?;
        for orphan in prune_for_spec(
            &local_names,
            &advertised_names,
            &spec.src,
            spec.dst.as_deref(),
        ) {
            if pairs
                .iter()
                .any(|fetched| fetched.name.as_bytes() == orphan.as_slice())
                || pruned
                    .iter()
                    .any(|name: &RefName| name.as_bytes() == orphan.as_slice())
            {
                continue;
            }
            pruned.push(RefName::new(orphan).map_err(|err| GitError::Invalid {
                detail: format!("pruned ref refused: {err}"),
            })?);
        }
    }
    Ok(pruned)
}

/// Reads the direct oid behind an optional current target.
fn current_as_direct(current: &Option<RefTarget>) -> Option<Oid> {
    match current {
        Some(RefTarget::Direct(oid)) => Some(*oid),
        _ => None,
    }
}

/// One fetched ref with the force flag of the spec that named it.
struct FetchedRef {
    /// Source object id.
    oid: Oid,
    /// Destination ref.
    name: RefName,
    /// Destination target.
    target: RefTarget,
    /// The naming spec carried `+`.
    force: bool,
}

/// One parsed refspec: force flag, source pattern, optional destination.
struct RefSpec {
    /// `+` forces non-fast-forward updates.
    force: bool,
    /// Source ref or glob.
    src: String,
    /// Destination ref, glob, or absent (FETCH_HEAD only).
    dst: Option<String>,
}

/// Parses `[+]<src>[:<dst>]` the way `fetch` accepts refspecs.
fn parse_spec(text: &str) -> Result<RefSpec, GitError> {
    let (force, rest) = text
        .strip_prefix('+')
        .map_or((false, text), |tail| (true, tail));
    let (src, dst) = rest
        .split_once(':')
        .map_or((rest, None), |(left, right)| (left, Some(right.to_owned())));
    if src.is_empty() {
        return Err(GitError::Invalid {
            detail: format!("bad refspec {text:?}"),
        });
    }
    Ok(RefSpec {
        force,
        src: src.to_owned(),
        dst,
    })
}

/// Expands one refspec against the advertised refs of a local source.
fn expand_spec(
    src: &Store,
    advertised: &[AdvertisedLocalRef],
    text: &str,
) -> Result<Vec<FetchedRef>, GitError> {
    let spec = parse_spec(text)?;
    if spec.src.contains('*') {
        return expand_glob(advertised, &spec, text);
    }
    let oid = resolve_rev(src, src.hash_kind(), &spec.src)?;
    match spec.dst {
        None => Ok(Vec::new()),
        Some(dst) => {
            let name = dwell_dest(src, &dst)?;
            Ok(vec![FetchedRef {
                oid,
                name: name.clone(),
                target: RefTarget::Direct(oid),
                force: spec.force,
            }])
        }
    }
}

/// Expands one refspec against network-advertised refs: globs behave
/// exactly like [`expand_spec`], while exact sources resolve against the
/// advertisement instead of a source store.
fn expand_spec_net(
    advertised: &[AdvertisedLocalRef],
    dest: &Store,
    text: &str,
) -> Result<Vec<FetchedRef>, GitError> {
    let spec = parse_spec(text)?;
    if spec.src.contains('*') {
        return expand_glob(advertised, &spec, text);
    }
    let (oid, target) = resolve_advertised(advertised, &spec.src)?;
    match spec.dst {
        None => Ok(Vec::new()),
        Some(dst) => {
            let name = dwell_dest(dest, &dst)?;
            Ok(vec![FetchedRef {
                oid,
                name: name.clone(),
                target,
                force: spec.force,
            }])
        }
    }
}

/// Expands one glob refspec against advertised refs, mapping each matched
/// source name through the destination pattern.
fn expand_glob(
    advertised: &[AdvertisedLocalRef],
    spec: &RefSpec,
    text: &str,
) -> Result<Vec<FetchedRef>, GitError> {
    let dst_pattern = spec.dst.clone().ok_or_else(|| GitError::Invalid {
        detail: format!("glob refspec {text:?} needs a destination"),
    })?;
    let mut out = Vec::new();
    for entry in advertised {
        let name_text = String::from_utf8_lossy(&entry.name).into_owned();
        if !glob_pair(&spec.src, &name_text) {
            continue;
        }
        let mapped =
            map_glob(&spec.src, &dst_pattern, &name_text).ok_or_else(|| GitError::Invalid {
                detail: format!("refspec {text:?} does not map {name_text:?}"),
            })?;
        let name = RefName::new(mapped).map_err(|err| GitError::Invalid {
            detail: format!("mapped ref refused: {err}"),
        })?;
        if let RefTarget::Direct(oid) = &entry.target {
            if entry.name.starts_with(b"refs/heads/") || entry.name.starts_with(b"refs/tags/") {
                out.push(FetchedRef {
                    oid: *oid,
                    name,
                    target: entry.target.clone(),
                    force: spec.force,
                });
            }
        }
    }
    Ok(out)
}

/// Resolves an exact fetch source against advertised refs: the full name,
/// then the `heads`/`tags` guesses, then a raw OID the server may serve
/// (`git fetch <sha>`).
fn resolve_advertised(
    advertised: &[AdvertisedLocalRef],
    src: &str,
) -> Result<(Oid, RefTarget), GitError> {
    let guesses = [
        src.to_owned(),
        format!("refs/heads/{src}"),
        format!("refs/tags/{src}"),
    ];
    for guess in &guesses {
        match advertised
            .iter()
            .find(|entry| String::from_utf8_lossy(&entry.name) == *guess)
        {
            Some(entry) => match &entry.target {
                RefTarget::Direct(oid) => return Ok((*oid, entry.target.clone())),
                RefTarget::Symbolic(_) => {
                    return Err(GitError::Invalid {
                        detail: format!("cannot fetch unborn ref {src:?}"),
                    });
                }
            },
            None => {}
        }
    }
    Oid::from_hex(src)
        .map(|oid| (oid, RefTarget::Direct(oid)))
        .map_err(|_| GitError::NotFound {
            detail: format!("no such ref {src:?} on the remote"),
        })
}

/// Expands a short destination the way Git guesses refnames: a full name
/// passes through, otherwise the first existing `heads`/`tags`/`remotes`
/// spelling wins, else `refs/heads/` is the default.
fn dwell_dest(store: &Store, text: &str) -> Result<RefName, GitError> {
    if text.starts_with("refs/") {
        return RefName::new(text.to_owned()).map_err(|err| GitError::Invalid {
            detail: format!("bad destination ref: {err}"),
        });
    }
    let reader = StoreRefs::new(store);
    for candidate in [
        format!("refs/heads/{text}"),
        format!("refs/tags/{text}"),
        format!("refs/remotes/{text}"),
    ] {
        let name = RefName::new(candidate).map_err(|err| GitError::Invalid {
            detail: format!("bad destination ref: {err}"),
        })?;
        if reader
            .get(&name)
            .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?
            .is_some()
        {
            return Ok(name);
        }
    }
    RefName::new(format!("refs/heads/{text}")).map_err(|err| GitError::Invalid {
        detail: format!("bad destination ref: {err}"),
    })
}

/// Matches one glob with a single `*` against a name.
fn glob_pair(pattern: &str, text: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == text,
        Some((head, tail)) => {
            text.starts_with(head) && text.ends_with(tail) && head.len() + tail.len() <= text.len()
        }
    }
}

/// Maps a matched name through a glob destination pattern.
fn glob_map(from: &str, to: &str, text: &str) -> Option<String> {
    let (from_head, from_tail) = from.split_once('*')?;
    let (to_head, to_tail) = to.split_once('*')?;
    let middle = text.strip_prefix(from_head)?.strip_suffix(from_tail)?;
    Some(format!("{to_head}{middle}{to_tail}"))
}

/// Maps a glob source and destination pair, refusing multi-star patterns.
fn map_glob(from: &str, to: &str, text: &str) -> Option<String> {
    if from.matches('*').count() != 1 || to.matches('*').count() != 1 {
        return None;
    }
    glob_map(from, to, text)
}

/// Writes the `FETCH_HEAD` record for fetched tips.
fn write_fetch_head(ctx: &Ctx, pairs: &[FetchedRef]) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let mut text = String::new();
    for fetched in pairs {
        text.push_str(&format!(
            "{}\t{}\n",
            fetched.oid.to_hex(),
            fetched.name.to_utf8().unwrap_or_default()
        ));
    }
    let key = b"cli/pseudo/FETCH_HEAD".to_vec();
    let expected = store
        .fact(FactTable::Pins, &key)?
        .map_or(FactExpectation::Absent, FactExpectation::Value);
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Pins,
                key,
                expected,
                value: Some(text.into_bytes()),
            }],
        )
        .map_err(GitError::from)?;
    Ok(Vec::new())
}

/// Names the configured remote behind a target, if the target is one.
fn configured_name(ctx: &Ctx, target: &str) -> Option<String> {
    let store = ctx.store().ok()?;
    for (key, _) in super::state::config_list(store).ok()? {
        if key == format!("remote.{target}.url") {
            return Some(target.to_owned());
        }
    }
    None
}

/// Fetches and fast-forwards the current branch.
///
/// Oracle: `git/builtin/pull.c`.
pub(crate) fn pull(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "ff-only",
        short: None,
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    ctx.require_worktree()?;
    let (target, branch_arg) = match opts.positionals.as_slice() {
        [] => ("origin", None),
        [target] => (target.as_str(), None),
        [target, branch] => (target.as_str(), Some(branch.as_str())),
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: pull [<remote>] [<branch>]".to_owned(),
            });
        }
    };
    let store = ctx.store()?;
    let (workspace, _) = load_or_default(store)?;
    let current_branch = match workspace.head {
        ruk_core::workspace::HeadRef::Symbolic(name) => name
            .to_utf8()
            .unwrap_or_default()
            .trim_start_matches("refs/heads/")
            .to_owned(),
        ruk_core::workspace::HeadRef::Detached(_) => {
            return Err(GitError::Invalid {
                detail: "pull on a detached HEAD is not implemented".to_owned(),
            });
        }
    };
    let wanted = branch_arg.unwrap_or(current_branch.as_str()).to_owned();
    let remote_label = configured_name(ctx, target).unwrap_or_else(|| target.to_owned());
    let spec = format!("refs/heads/{wanted}:refs/remotes/{remote_label}/{wanted}");
    let plan = FetchPlan {
        force_all: false,
        depth: None,
        fetch_tags: false,
        prune: false,
    };
    run_fetch(ctx, &remote_label, &[spec], plan)?;
    let tip = resolve_rev(
        store,
        ctx.kind()?,
        &format!("refs/remotes/{remote_label}/{wanted}"),
    )?;
    let before = super::state::head_oid(store)?;
    super::verbs_history::merge_fast_forward(ctx, &wanted, before, tip)
}

/// Pushes refs to a local repository through a persisted plan.
///
/// Oracle: `git/builtin/push.c`.
pub(crate) fn push(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        FlagSpec {
            long: "atomic",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "delete",
            short: Some('d'),
            takes_value: false,
        },
        FlagSpec {
            long: "mirror",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let target = opts.positionals.first().map_or("origin", String::as_str);
    // Mirror force: the oracle's `--mirror` forces every ref update, the
    // way a push mirror (`git push --mirror --force`) syncs deletions and
    // rewinds alike.
    let force_all = opts.is_set("force") || opts.is_set("mirror");
    let mirror = opts.is_set("mirror");
    let atomic = opts.is_set("atomic");
    let delete = opts.is_set("delete");
    if mirror && opts.positionals.len() > 1 {
        return Err(GitError::Invalid {
            detail: "usage: push [--mirror] [<remote>]".to_owned(),
        });
    }
    let spec_texts: Vec<String> = if mirror {
        Vec::new()
    } else if opts.positionals.len() > 1 {
        opts.positionals[1..].to_vec()
    } else {
        default_push_specs(store)?
    };
    match resolve_target(ctx, target)? {
        Target::Local(dest_root) => {
            let dest = open_store_at(&dest_root)?;
            if dest.hash_kind() != kind {
                return Err(GitError::ObjectFormat {
                    detail: "source and destination object formats disagree".to_owned(),
                });
            }
            if mirror {
                return push_mirror(ctx, &dest, target, atomic);
            }
            let updates =
                build_push_updates(store, &dest, &spec_texts, delete, force_all, &|name| {
                    peel_dest_oid(&dest, name)
                })?;
            push_local(store, &dest, target, kind, atomic, updates)
        }
        Target::Net(endpoint) => push_net(
            ctx,
            &endpoint,
            target,
            &spec_texts,
            mirror,
            atomic,
            delete,
            force_all,
        ),
    }
}

/// The default push refspecs from the current branch: `HEAD`'s short name
/// pushed to itself, the way the oracle pushes the current branch with no
/// explicit refspec.
fn default_push_specs(store: &Store) -> Result<Vec<String>, GitError> {
    let (workspace, _) = load_or_default(store)?;
    match workspace.head {
        ruk_core::workspace::HeadRef::Symbolic(name) => {
            let short = name.to_utf8().unwrap_or_default().to_owned();
            Ok(vec![format!("{short}:{short}")])
        }
        ruk_core::workspace::HeadRef::Detached(_) => Err(GitError::Invalid {
            detail: "push from a detached HEAD needs an explicit refspec".to_owned(),
        }),
    }
}

/// Builds push updates from refspecs: deletes resolve the destination name
/// and zero the tip, sets resolve the source rev locally and check
/// fast-forward against the destination tip `peel` reports.
fn build_push_updates(
    src: &Store,
    dwell: &Store,
    spec_texts: &[String],
    delete: bool,
    force_all: bool,
    peel: &dyn Fn(&RefName) -> Result<Option<Oid>, GitError>,
) -> Result<Vec<PushUpdate>, GitError> {
    let kind = src.hash_kind();
    let zero = kind.zero_oid();
    let mut updates = Vec::new();
    for spec_text in spec_texts {
        let (force, rest) = spec_text
            .strip_prefix('+')
            .map_or((false, spec_text.as_str()), |tail| (true, tail));
        let (src_text, dst_text) = rest
            .split_once(':')
            .map_or((rest, rest), |(left, right)| (left, right));
        if delete {
            let name = dwell_dest(dwell, dst_text)?;
            let old = peel(&name)?.unwrap_or(zero);
            updates.push(PushUpdate {
                name: name.as_bytes().to_vec(),
                old,
                new: zero,
            });
            continue;
        }
        let new = resolve_rev(src, kind, src_text)?;
        let name = dwell_dest(dwell, dst_text)?;
        let old = peel(&name)?.unwrap_or(zero);
        if old != zero && !force && !force_all && !is_ancestor(src, old, new)? {
            return Err(GitError::PushRejected {
                detail: format!(
                    "non-fast-forward push to {}",
                    name.to_utf8().unwrap_or_default()
                ),
            });
        }
        updates.push(PushUpdate {
            name: name.as_bytes().to_vec(),
            old,
            new,
        });
    }
    Ok(updates)
}

/// Pushes prebuilt updates to a local destination through a persisted plan.
fn push_local(
    src: &Store,
    dest: &Store,
    target: &str,
    kind: HashKind,
    atomic: bool,
    updates: Vec<PushUpdate>,
) -> Result<Vec<u8>, GitError> {
    let request = PushWireRequest {
        updates: updates.clone(),
        atomic,
    };
    let mut plan = ruk_git::transport::push::PushPlanRecord::prepare(
        PlanId::generate(),
        target.as_bytes().to_vec(),
        atomic,
        updates,
    );
    push_outcomes(local_push(
        dest,
        src,
        kind,
        &mut plan,
        &request,
        &Interrupt::none(),
    )?)
}

/// Pushes to a network endpoint: discovers the remote tips for CAS
/// expectations, then drives `push_over` over one receive-pack connection
/// with the same persisted plan local pushes use.
///
/// Oracle: `git/builtin/push.c`.
fn push_net(
    ctx: &Ctx,
    endpoint: &Endpoint,
    target: &str,
    spec_texts: &[String],
    mirror: bool,
    atomic: bool,
    delete: bool,
    force_all: bool,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let advertised = net::to_local_refs(net::discover_endpoint(
        endpoint,
        Service::ReceivePack,
        kind,
    )?)?;
    let remote: Vec<(Vec<u8>, Oid)> = advertised
        .iter()
        .filter_map(|entry| match &entry.target {
            RefTarget::Direct(oid) => Some((entry.name.clone(), *oid)),
            RefTarget::Symbolic(_) => None,
        })
        .collect();
    let updates = if mirror {
        mirror_push_updates(kind, &direct_tips(store)?, &remote)
    } else {
        build_push_updates(store, store, spec_texts, delete, force_all, &|name| {
            peel_advertised(&advertised, name)
        })?
    };
    if mirror && updates.is_empty() {
        return Ok(Vec::new());
    }
    let request = PushWireRequest {
        updates: updates.clone(),
        atomic,
    };
    let mut plan = ruk_git::transport::push::PushPlanRecord::prepare(
        PlanId::generate(),
        target.as_bytes().to_vec(),
        atomic,
        updates,
    );
    let stream = net::open_stream(endpoint, Service::ReceivePack)?;
    push_outcomes(ruk_git::transport::push::push_over(
        stream,
        store,
        kind,
        &mut plan,
        &request,
        &Interrupt::none(),
    )?)
}

/// Reads the advertised tip behind one destination ref, if it exists: the
/// network counterpart of [`peel_dest_oid`].
fn peel_advertised(
    advertised: &[AdvertisedLocalRef],
    name: &RefName,
) -> Result<Option<Oid>, GitError> {
    match advertised
        .iter()
        .find(|entry| entry.name == name.as_bytes())
    {
        None => Ok(None),
        Some(entry) => match &entry.target {
            RefTarget::Direct(oid) => Ok(Some(*oid)),
            RefTarget::Symbolic(_) => Err(GitError::Invalid {
                detail: "destination ref is symbolic".to_owned(),
            }),
        },
    }
}

/// Pushes every local ref to the same name on the destination and deletes
/// destination refs with no local counterpart: `push --mirror`, the verb a
/// push-mirror sync (`git push --mirror --force`) routes through.
///
/// Oracle: `git/builtin/push.c` (`--mirror`).
fn push_mirror(ctx: &Ctx, dest: &Store, target: &str, atomic: bool) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let local = direct_tips(store)?;
    let remote = direct_tips(dest)?;
    let updates = mirror_push_updates(kind, &local, &remote);
    if updates.is_empty() {
        return Ok(Vec::new());
    }
    let request = PushWireRequest {
        updates: updates.clone(),
        atomic,
    };
    let mut plan = ruk_git::transport::push::PushPlanRecord::prepare(
        PlanId::generate(),
        target.as_bytes().to_vec(),
        atomic,
        updates,
    );
    push_outcomes(local_push(
        dest,
        store,
        kind,
        &mut plan,
        &request,
        &Interrupt::none(),
    )?)
}

/// Builds the `push --mirror` update list from local and remote direct
/// tips, forcing every set the way the oracle's `--mirror` does.
fn mirror_push_updates(
    kind: HashKind,
    local: &[(Vec<u8>, Oid)],
    remote: &[(Vec<u8>, Oid)],
) -> Vec<PushUpdate> {
    let zero = kind.zero_oid();
    let mut updates = Vec::new();
    for mirror_update in push_mirror_updates(&local, &remote) {
        updates.push(PushUpdate {
            name: mirror_update.name,
            old: mirror_update.old.unwrap_or(zero),
            new: mirror_update.new.unwrap_or(zero),
        });
    }
    updates
}

/// Direct ref tips of one store as `(name, oid)` pairs; symbolic refs
/// never enter a mirror update.
fn direct_tips(store: &Store) -> Result<Vec<(Vec<u8>, ruk_core::ids::Oid)>, GitError> {
    let mut tips = Vec::new();
    for (name, target) in list_refs(store)? {
        if let RefTarget::Direct(oid) = target {
            tips.push((name.as_bytes().to_vec(), oid));
        }
    }
    Ok(tips)
}

/// Reports push outcomes the way [`push`] does, failing on any rejection.
fn push_outcomes(outcomes: Vec<ruk_git::transport::push::RefOutcome>) -> Result<Vec<u8>, GitError> {
    let mut out = Vec::new();
    for outcome in &outcomes {
        let name = String::from_utf8_lossy(&outcome.name);
        match &outcome.result {
            ruk_git::transport::push::RefResult::Ok => {
                out.extend_from_slice(format!("ok {name}\n").as_bytes());
            }
            ruk_git::transport::push::RefResult::Rejected { reason } => {
                out.extend_from_slice(format!("rejected {name}: {reason}\n").as_bytes());
            }
        }
    }
    if outcomes
        .iter()
        .any(|outcome| !matches!(outcome.result, ruk_git::transport::push::RefResult::Ok))
    {
        return Err(GitError::PushRejected {
            detail: String::from_utf8_lossy(&out).into_owned(),
        });
    }
    Ok(out)
}

/// Reads the direct oid behind one destination ref, if it exists.
fn peel_dest_oid(dest: &Store, name: &RefName) -> Result<Option<Oid>, GitError> {
    let target = StoreRefs::new(dest)
        .get(name)
        .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
    match target {
        None => Ok(None),
        Some(RefTarget::Direct(oid)) => Ok(Some(oid)),
        Some(RefTarget::Symbolic(_)) => Err(GitError::Invalid {
            detail: "destination ref is symbolic".to_owned(),
        }),
    }
}

/// Serves `receive-pack`: advertises refs, ingests the client's pack, and
/// reports per-ref outcomes.
///
/// Oracle: `git/builtin/receive-pack.c`.
pub(crate) fn receive_pack(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let store = serve_store(ctx, args)?;
    let kind = store.hash_kind();
    let head = serve_head(&store)?;
    // The policy lives beside the store the verb actually serves: the
    // resolved root already accounts for `<dir>`, `--git-dir`/`GIT_DIR`
    // (baked into `ctx.store` by `open_ctx`), and the local-store layouts,
    // so no parallel directory walk can land on another repository's file.
    // Missing or coordinator-refused policy fails closed to `Deny`.
    let lfs = mode_for_store(store.root());
    match ctx.env.stdin.as_deref() {
        Some(input) => {
            let mut out = Vec::new();
            serve_receive_pack(
                input,
                &mut out,
                &store,
                kind,
                &head,
                &Interrupt::none(),
                lfs,
            )?;
            Ok(out)
        }
        // Live pipes stream the advertisement and report straight to
        // stdout. Buffering through the return value would withhold the
        // advertisement until the session ends and deadlock a real client,
        // so live runs return no bytes (`run` then writes nothing).
        // `super::read_stdin_bytes` is deliberately unused here: it drains
        // stdin to EOF, but the protocol is frame-delimited.
        None => {
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            serve_receive_pack(
                &mut input,
                &mut output,
                &store,
                kind,
                &head,
                &Interrupt::none(),
                lfs,
            )?;
            Ok(Vec::new())
        }
    }
}

/// Serves `upload-pack`: advertises refs, negotiates wants/haves, and emits
/// a pack.
///
/// Oracle: `git/builtin/upload-pack.c`.
pub(crate) fn upload_pack(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let store = serve_store(ctx, args)?;
    let kind = store.hash_kind();
    let head = serve_head(&store)?;
    match ctx.env.stdin.as_deref() {
        Some(input) => {
            let mut out = Vec::new();
            serve_upload_pack(input, &mut out, &store, kind, &head, &Interrupt::none())?;
            Ok(out)
        }
        // Live pipes stream the advertisement and pack straight to stdout;
        // see `receive_pack` for why the return value stays empty here.
        None => {
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            serve_upload_pack(
                &mut input,
                &mut output,
                &store,
                kind,
                &head,
                &Interrupt::none(),
            )?;
            Ok(Vec::new())
        }
    }
}

/// Serves `upload-archive`: answers `ACK` and streams the tar.
///
/// Oracle: `git/builtin/upload-archive.c`.
pub(crate) fn upload_archive(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let store = serve_store(ctx, args)?;
    let kind = store.hash_kind();
    let head = serve_head(&store)?;
    match ctx.env.stdin.as_deref() {
        Some(input) => {
            let mut out = Vec::new();
            serve_upload_archive(input, &mut out, &store, kind, &head, &Interrupt::none())?;
            Ok(out)
        }
        // Live pipes stream `ACK` and the tar straight to stdout; see
        // `receive_pack` for why the return value stays empty here.
        None => {
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            serve_upload_archive(
                &mut input,
                &mut output,
                &store,
                kind,
                &head,
                &Interrupt::none(),
            )?;
            Ok(Vec::new())
        }
    }
}

/// The store one serve verb runs against: borrowed from the context when it
/// is already open, owned when `<dir>` names another root.
enum ServeStore<'a> {
    /// The context store, borrowed.
    Open(&'a Store),
    /// A store opened from `<dir>` for this invocation.
    Owned(Store),
}

impl std::ops::Deref for ServeStore<'_> {
    type Target = Store;

    fn deref(&self) -> &Store {
        match self {
            Self::Open(store) => store,
            Self::Owned(store) => store,
        }
    }
}

/// Resolves the repository one serve verb runs against: the `<dir>`
/// positional when given (a repository root holding `.ruk`, the way Git's
/// daemons take it), else the context store, else the context root for a
/// daemon invoked with its working directory inside the repository.
fn serve_store<'a>(ctx: &'a Ctx, args: &[String]) -> Result<ServeStore<'a>, GitError> {
    let mut positionals: Vec<&str> = Vec::new();
    let mut dashdash = false;
    for arg in args {
        if dashdash {
            positionals.push(arg);
        } else if arg == "--" {
            dashdash = true;
        } else if arg.starts_with('-') && arg.len() > 1 {
            // Server-side transport flags (e.g. `--strict`) carry no
            // protocol meaning here; ignoring them keeps serving instead of
            // failing on an unfamiliar spelling.
        } else {
            positionals.push(arg);
        }
    }
    if positionals.len() > 1 {
        return Err(GitError::Invalid {
            detail: format!("too many arguments: {}", positionals.join(" ")),
        });
    }
    if let Some(dir) = positionals.first() {
        let path = std::path::Path::new(dir);
        return match open_store_at(path) {
            Ok(store) => Ok(ServeStore::Owned(store)),
            Err(first) => match open_local_store(path) {
                Ok(store) => Ok(ServeStore::Owned(store)),
                Err(_) => Err(first),
            },
        };
    }
    if let Some(store) = ctx.store.as_ref() {
        return Ok(ServeStore::Open(store));
    }
    // No `<dir>` and no `--git-dir`: walk up for a repository the way
    // discovery does for the other verbs.
    let mut dir = ctx.root.as_path();
    loop {
        if let Ok(store) = open_store_at(dir) {
            return Ok(ServeStore::Owned(store));
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }
    Err(GitError::Invalid {
        detail: "not a ruk repository".to_owned(),
    })
}

/// Reads the `HEAD` advertisement for a serve verb: the terminal name of HEAD's
/// chain for the `symref` capability, and its OID for the `HEAD` line (zero
/// when unborn).
///
/// The chain goes through the core `HeadRef::resolve`, which counts HEAD's own
/// link, as every other reader does. A dangling, cyclic, or over-deep chain
/// advertises the zero OID. A store read failure is not unborn: it propagates,
/// so a corrupt store never serves a false HEAD.
fn serve_head(store: &Store) -> Result<HeadAdvertisement, GitError> {
    let (workspace, _) = load_or_default(store)?;
    match workspace.head.resolve(&StoreRefs::new(store)) {
        Ok(ruk_core::workspace::ResolvedHead::Detached(oid)) => {
            Ok(HeadAdvertisement { oid, symref: None })
        }
        Ok(ruk_core::workspace::ResolvedHead::Symbolic(resolved)) => Ok(HeadAdvertisement {
            oid: resolved.oid.unwrap_or_else(|| store.hash_kind().zero_oid()),
            symref: Some(resolved.terminal.as_bytes().to_vec()),
        }),
        Err(ruk_core::refdata::RefError::Read(err)) => Err(GitError::from(err)),
        Err(_) => Ok(HeadAdvertisement {
            oid: store.hash_kind().zero_oid(),
            symref: first_hop(&workspace.head),
        }),
    }
}

/// The immediate target of a symbolic HEAD, for a broken chain that cannot name
/// its terminal.
fn first_hop(head: &ruk_core::workspace::HeadRef) -> Option<Vec<u8>> {
    match head {
        ruk_core::workspace::HeadRef::Symbolic(name) => Some(name.as_bytes().to_vec()),
        ruk_core::workspace::HeadRef::Detached(_) => None,
    }
}

/// Writes an archive. Unsupported: no archive writer exists.
///
/// Oracle: `git/builtin/archive.c`.
pub(crate) fn archive(_ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let _ = args;
    Err(GitError::Unsupported {
        command: "archive: no archive writer in this slice".to_owned(),
    })
}

/// Handles bundles. Unsupported: no bundle format exists.
///
/// Oracle: `git/builtin/bundle.c`.
pub(crate) fn bundle(_ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let _ = args;
    Err(GitError::Unsupported {
        command: "bundle: no bundle format in this slice".to_owned(),
    })
}

/// Collects garbage. Unsupported: no repack or prune lane exists.
///
/// Oracle: `git/builtin/gc.c`.
pub(crate) fn gc(_ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let _ = args;
    Err(GitError::Unsupported {
        command: "gc: no repack or prune lane in this slice".to_owned(),
    })
}

/// Verifies reachable objects: every ref tip, its history, their trees and
/// blobs, and every index row's blob must exist.
///
/// Oracle: `git/builtin/fsck.c`. Unreachable-object reporting needs an
/// object census the store API does not expose, so only reachable
/// corruption fails; the absence of `dangling` lines is documented, not a
/// clean bill for unreachable storage.
pub(crate) fn fsck(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "full",
        short: None,
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "fsck takes no paths".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let _ = opts.is_set("full");
    let mut tips = Vec::new();
    for (_, target) in list_refs(store)? {
        match target {
            RefTarget::Direct(oid) => tips.push(oid),
            RefTarget::Symbolic(name) => {
                let resolved = ruk_core::refdata::resolve(&StoreRefs::new(store), &name)
                    .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
                if let Some(oid) = resolved.oid {
                    tips.push(oid);
                }
            }
        }
    }
    let mut out = Vec::new();
    for (oid, record) in walk_history(store, &tips, None)? {
        let tree = super::tree::commit_tree_oid(&record)?;
        check_tree(store, kind, tree, &mut out)?;
        let _ = oid;
    }
    for (path, _, entry) in scan_index(store, kind)? {
        if !has_object(store, entry.oid())? {
            out.extend_from_slice(
                format!(
                    "missing blob {} for index path {}\n",
                    entry.oid().to_hex(),
                    String::from_utf8_lossy(path.as_bytes())
                )
                .as_bytes(),
            );
        }
    }
    Ok(out)
}

/// Reconciles the LFS sidecar against reachable pointers: every pointer
/// blob reachable from live refs (the same ref-tips plus
/// commit/tree walk [`fsck`] uses) must have a verified payload in
/// `<store>/lfs/objects/` plus a `complete=true` presence row.
///
/// Full mode only: under `Deny` or `Pointers` the verb refuses, so both
/// modes stay byte-identical to a build without this slice. Pointers
/// already verified with a row present are no-ops, so re-runs are
/// idempotent; each fetched payload stages through a temp file with an
/// atomic rename plus one fact-row publication, so a kill leaves at most
/// one temp file and already-synced payloads stay synced. A verified file
/// whose row is absent (rename committed, publication lost) gets its row
/// republished and counts as synced. Payload bytes come from
/// `--from <dir>` (a local directory holding `<oid>` files or
/// `<aa>/<bb>/<oid>` trees, hash-verified before staging); without it,
/// the verb POSTs one git-lfs batch download request to the configured
/// endpoint (`lfs.url`, falling back to `remote.origin.lfsurl`, plus
/// `/objects/batch`) and streams each answered `actions.download.href`
/// into staging, echoing per-action headers and the environment Bearer
/// token only on the endpoint's own authority. Batch error entries and
/// failed downloads land in `missing` with the server's detail.
///
/// Stdout is JSON `{"synced": [...], "missing": [{"oid","error"}]}` with
/// both lists sorted by oid; exit is 0 even when `missing` is non-empty
/// (absence is reported, never fatal, matching push admission under
/// `Full`). Only a refused batch document itself fails the verb.
pub(crate) fn lfs_payload_sync(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    use ruk_core::store::lfs as sidecar;

    let specs = [FlagSpec {
        long: "from",
        short: None,
        takes_value: true,
    }];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: lfs_payload_sync [--from <dir>]".to_owned(),
        });
    }
    let store = ctx.store()?;
    if mode_for_store(store.root()) != LfsMode::Full {
        return Err(GitError::Invalid {
            detail: "lfs_payload_sync needs lfs = \"full\" in the store policy.toml".to_owned(),
        });
    }
    let from = match opts.single("from")? {
        None => None,
        Some(dir) => {
            let path = std::path::Path::new(&dir);
            Some(if path.is_absolute() {
                path.to_path_buf()
            } else {
                ctx.env.cwd.join(path)
            })
        }
    };
    let kind = ctx.kind()?;
    let mut tips = Vec::new();
    for (_, target) in list_refs(store)? {
        match target {
            RefTarget::Direct(oid) => tips.push(oid),
            RefTarget::Symbolic(name) => {
                let resolved = ruk_core::refdata::resolve(&StoreRefs::new(store), &name)
                    .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
                if let Some(oid) = resolved.oid {
                    tips.push(oid);
                }
            }
        }
    }
    // Reachable pointers, keyed by payload hex: small blobs only (a
    // pointer is strictly below 1024 bytes), deduplicated across trees.
    // Unreadable blobs are fsck's domain; the sync skips them.
    let mut pointers: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for (_, record) in super::state::walk_history(store, &tips, None)? {
        let tree = super::tree::commit_tree_oid(&record)?;
        for (_, _, oid) in super::tree::flatten_tree(store, kind, tree)? {
            let len = store.object_len(oid).map_err(GitError::from)?;
            if len.is_some_and(|bytes| bytes >= 1024) {
                continue;
            }
            let Ok((object_kind, bytes)) = super::tree::read_object_bytes(store, oid) else {
                continue;
            };
            if object_kind != ObjectKind::Blob {
                continue;
            }
            if let Some((hex, size)) = ruk_core::parse_pointer(&bytes) {
                pointers.entry(hex).or_insert(size);
            }
        }
    }
    let mut synced: Vec<String> = Vec::new();
    let mut missing: Vec<(String, String)> = Vec::new();
    let mut mutations = Vec::new();
    // Pointers already verified are no-ops (row repair included); the
    // rest need bytes from exactly one source below. `pointers` is a
    // BTreeMap, so both report lists stay sorted by oid.
    let mut pending: Vec<(String, u64)> = Vec::new();
    for (hex, size) in &pointers {
        if sidecar::sidecar_verified(store.root(), hex, *size) {
            // The file survived; the row may not have (rename committed,
            // publication lost). Repair the row so file and fact agree.
            let row = store
                .fact(FactTable::LfsObjects, &sidecar::record_key(hex))
                .map_err(GitError::from)?;
            if row.is_none() {
                synced.push(hex.clone());
                mutations.push(sidecar::upsert_mutation(
                    hex,
                    &sidecar::LfsObjectRecord {
                        size: *size,
                        complete: true,
                    },
                ));
            }
            continue;
        }
        pending.push((hex.clone(), *size));
    }
    match &from {
        Some(dir) => {
            for (hex, size) in &pending {
                let direct = dir.join(hex);
                let nested = dir.join(&hex[0..2]).join(&hex[2..4]).join(hex);
                let src = if direct.is_file() {
                    Some(direct)
                } else if nested.is_file() {
                    Some(nested)
                } else {
                    None
                };
                match src {
                    None => missing.push((
                        hex.clone(),
                        format!("not present in --from {}", dir.display()),
                    )),
                    Some(path) => {
                        match sidecar::stage_verified(store.root(), hex, *size, &path) {
                            Ok(_) => {
                                synced.push(hex.clone());
                                mutations.push(sidecar::upsert_mutation(
                                    hex,
                                    &sidecar::LfsObjectRecord {
                                        size: *size,
                                        complete: true,
                                    },
                                ));
                            }
                            Err(err) => missing.push((hex.clone(), err.to_string())),
                        }
                    }
                }
            }
        }
        None => sync_via_batch(ctx, store, &pending, &mut synced, &mut missing, &mut mutations)?,
    }
    if !mutations.is_empty() {
        store
            .publish(Vec::new(), &mutations)
            .map_err(GitError::from)?;
    }
    let mut out = String::from("{\"synced\": [");
    for (index, hex) in synced.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("\"{hex}\""));
    }
    out.push_str("], \"missing\": [");
    for (index, (hex, error)) in missing.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!(
            "{{\"oid\": \"{hex}\", \"error\": \"{}\"}}",
            json_escape(error)
        ));
    }
    out.push_str("]}\n");
    Ok(out.into_bytes())
}

/// Escapes `text` as one JSON string body: quotes, backslashes, and
/// control characters take their short or `\u00XX` forms, and anything
/// else passes through verbatim. Server error detail is untrusted bytes;
/// `{:?}` would emit Rust's `\u{...}` form, which is not JSON.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for char in text.chars() {
        match char {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            char if (char as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", char as u32));
            }
            char => out.push(char),
        }
    }
    out
}

/// Downloads `pending` payloads through the git-lfs batch API at the
/// configured endpoint (`lfs.url`, falling back to
/// `remote.origin.lfsurl`): one `objects/batch` POST for the download
/// operation, then one payload GET per answered action, streamed to a
/// temp file beside the sidecar and staged hash-verified. Server error
/// entries, omitted objects, and failed downloads land in `missing` with
/// detail; only a refused batch document itself fails the verb.
///
/// # Errors
/// [`GitError::Invalid`] for a malformed endpoint or batch request,
/// [`GitError::Offline`] when the batch endpoint refuses, plus transport
/// failures from the HTTP client.
fn sync_via_batch(
    ctx: &Ctx,
    store: &Store,
    pending: &[(String, u64)],
    synced: &mut Vec<String>,
    missing: &mut Vec<(String, String)>,
    mutations: &mut Vec<FactMutation>,
) -> Result<(), GitError> {
    use ruk_core::store::lfs as sidecar;
    use ruk_git::transport::http::{self, BatchEntry};

    let Some(endpoint) = ctx
        .config_get("lfs.url")
        .or_else(|| ctx.config_get("remote.origin.lfsurl"))
    else {
        for (hex, _) in pending {
            missing.push((
                hex.clone(),
                "no LFS endpoint configured (set lfs.url) and no --from directory".to_owned(),
            ));
        }
        return Ok(());
    };
    if pending.is_empty() {
        return Ok(());
    }
    let batch_url = format!("{}/objects/batch", endpoint.trim_end_matches('/'));
    let request = http::batch_request_body(pending)?;
    let mut headers: Vec<(String, String)> = vec![
        ("Content-Type".to_owned(), http::LFS_JSON.to_owned()),
        ("Accept".to_owned(), http::LFS_JSON.to_owned()),
    ];
    if let Some(auth) = http::auth_header(&ctx.env.vars) {
        headers.push(auth);
    }
    let borrowed: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let reply = http::post_json(&batch_url, &borrowed, &request)?;
    if !http::is_success(reply.status) {
        let preview: String = String::from_utf8_lossy(&reply.body).chars().take(200).collect();
        return Err(GitError::Offline {
            detail: format!(
                "lfs batch {batch_url} refused status {}: {preview:?}",
                reply.status
            ),
        });
    }
    let batch_authority = http::url_authority(&batch_url).ok();
    let mut answers: HashMap<String, BatchEntry> = HashMap::new();
    for entry in http::parse_batch_response(&reply.body)? {
        let oid = match &entry {
            BatchEntry::Ready { oid, .. } | BatchEntry::Failed { oid, .. } => oid.clone(),
        };
        answers.insert(oid, entry);
    }
    // Temp downloads land beside the sidecar (same filesystem) and are
    // removed after every staging attempt, success or failure.
    let tmp_dir = store.root().join("lfs").join("tmp");
    std::fs::create_dir_all(&tmp_dir).map_err(|err| GitError::Io {
        detail: format!("cannot stage lfs downloads: {err}"),
    })?;
    for (hex, size) in pending {
        match answers.get(hex) {
            None => missing.push((
                hex.clone(),
                "batch response omits this object".to_owned(),
            )),
            Some(BatchEntry::Failed { detail, .. }) => {
                missing.push((hex.clone(), detail.clone()));
            }
            Some(BatchEntry::Ready {
                href,
                headers: action_headers,
                ..
            }) => {
                let mut get_headers: Vec<(String, String)> = action_headers.clone();
                if let Some(auth) = http::auth_header(&ctx.env.vars)
                    && batch_authority.as_deref()
                        == http::url_authority(href).ok().as_deref()
                {
                    get_headers.push(auth);
                }
                let tmp = tmp_dir.join(format!("dl-{hex}.{}", std::process::id()));
                let outcome = download_and_stage(store, href, &get_headers, hex, *size, &tmp);
                let _ = std::fs::remove_file(&tmp);
                match outcome {
                    Ok(()) => {
                        synced.push(hex.clone());
                        mutations.push(sidecar::upsert_mutation(
                            hex,
                            &sidecar::LfsObjectRecord {
                                size: *size,
                                complete: true,
                            },
                        ));
                    }
                    Err(detail) => missing.push((hex.clone(), detail)),
                }
            }
        }
    }
    Ok(())
}

/// GETs one payload `href`, streaming the body into `tmp` and staging it
/// hash-verified, returning the human detail for `missing` on any failure
/// so one bad object never fails its siblings.
fn download_and_stage(
    store: &Store,
    href: &str,
    headers: &[(String, String)],
    hex: &str,
    size: u64,
    tmp: &std::path::Path,
) -> Result<(), String> {
    use ruk_core::store::lfs as sidecar;
    use ruk_git::transport::http;

    let borrowed: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut file =
        std::fs::File::create(tmp).map_err(|err| format!("cannot stage download: {err}"))?;
    let (status, _) = http::get_to_writer(href, &borrowed, &mut file)
        .map_err(|err| format!("GET {href} failed: {err}"))?;
    // The staging read opens its own descriptor; flush here so it sees
    // every byte even though the handle drops at return.
    std::io::Write::flush(&mut file)
        .map_err(|err| format!("cannot flush download: {err}"))?;
    if !http::is_success(status) {
        return Err(format!("GET {href} failed with status {status}"));
    }
    sidecar::stage_verified(store.root(), hex, size, tmp)
        .map_err(|err| err.to_string())
        .map(|_| ())
}

/// Checks one tree and its blobs recursively, recording misses.
fn check_tree(
    store: &Store,
    kind: ruk_core::ids::HashKind,
    tree: Oid,
    out: &mut Vec<u8>,
) -> Result<(), GitError> {
    if !has_object(store, tree)? {
        out.extend_from_slice(format!("missing tree {}\n", tree.to_hex()).as_bytes());
        return Ok(());
    }
    for (path, mode, oid) in super::tree::flatten_tree(store, kind, tree)? {
        if mode.octal() == 0o160_000 {
            continue;
        }
        if !has_object(store, oid)? {
            out.extend_from_slice(
                format!(
                    "missing blob {} at {}\n",
                    oid.to_hex(),
                    String::from_utf8_lossy(&path)
                )
                .as_bytes(),
            );
        }
    }
    Ok(())
}

/// Lists refs in a local repository or over one discovery round trip.
///
/// Oracle: `git/builtin/ls-remote.c`.
pub(crate) fn ls_remote(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "heads",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "tags",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let target = opts.positionals.first().map_or("origin", String::as_str);
    if opts.positionals.len() > 2 {
        return Err(GitError::Invalid {
            detail: "usage: ls-remote [<remote>] [<pattern>]".to_owned(),
        });
    }
    let pattern = match opts.positionals.as_slice() {
        [_] | [] => None,
        [_, want] => Some(want.clone()),
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: ls-remote [<remote>] [<pattern>]".to_owned(),
            });
        }
    };
    let advertised = match resolve_target(ctx, target)? {
        Target::Local(root) => {
            let src = open_store_at(&root)?;
            advertise(&src)?
        }
        Target::Net(endpoint) => net::to_local_refs(net::discover_endpoint(
            &endpoint,
            Service::UploadPack,
            ctx.kind()?,
        )?)?,
    };
    Ok(render_ls_remote(
        &advertised,
        opts.is_set("heads"),
        opts.is_set("tags"),
        pattern.as_deref(),
    ))
}

/// Renders advertised refs the `ls-remote` way: one `<oid>\t<name>` line
/// per direct ref, `ref: <target>` lines for symbolic refs, filtered by
/// the `--heads`/`--tags` flags and an optional substring pattern.
fn render_ls_remote(
    advertised: &[AdvertisedLocalRef],
    heads_only: bool,
    tags_only: bool,
    want: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in advertised {
        let name = String::from_utf8_lossy(&entry.name).into_owned();
        if heads_only && !name.starts_with("refs/heads/") {
            continue;
        }
        if tags_only && !name.starts_with("refs/tags/") {
            continue;
        }
        if want.is_some_and(|text| !name.contains(text)) {
            continue;
        }
        match &entry.target {
            RefTarget::Direct(oid) => {
                out.extend_from_slice(format!("{}\t{name}\n", oid.to_hex()).as_bytes());
            }
            RefTarget::Symbolic(pointed) => {
                out.extend_from_slice(
                    format!("ref: {}\t{name}\n", pointed.to_utf8().unwrap_or_default()).as_bytes(),
                );
            }
        }
    }
    line(out)
}
