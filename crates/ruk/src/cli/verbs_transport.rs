//! Transport and maintenance verbs: `fetch`, `pull`, `push`,
//! `receive-pack`, `upload-pack`, `archive`, `bundle`, `gc`, `fsck`,
//! `ls-remote`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `fetch` | `session::local_fetch` + refspec expansion | implemented for local paths; network is `Offline` |
//! | `pull` | fetch + fast-forward | implemented for local paths (fast-forward only) |
//! | `push` | `session::local_push` with a persisted plan | implemented for local paths |
//! | `receive-pack` | `serve::serve_receive_pack` + `session::apply_refs` | served (protocol v0) |
//! | `upload-pack` | `serve::serve_upload_pack` + `session::local_closure` | served (protocol v0) |
//! | `archive` | no archive writer | unsupported |
//! | `bundle` | no bundle format | unsupported |
//! | `gc` | no repack/prune lane | unsupported |
//! | `fsck` | ref walk + object existence | implemented (reachable only; no dangling census) |
//! | `ls-remote` | `session::advertise` | implemented for local paths; network is `Offline` |
//!
//! Oracle anchors: `git/builtin/fetch.c`, `git/builtin/pull.c`,
//! `git/builtin/push.c`, `git/builtin/receive-pack.c`,
//! `git/builtin/upload-pack.c`, `git/builtin/archive.c`,
//! `git/builtin/bundle.c`, `git/builtin/gc.c`, `git/builtin/fsck.c`,
//! `git/builtin/ls-remote.c`.

use ruk_core::change::PlanId;
use ruk_core::ids::Oid;
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefRead, RefTarget, RefUpdate};
use ruk_core::refs::StoreRefs;
use ruk_core::store::{FactExpectation, FactMutation, FactTable, Store};
use ruk_git::GitError;
use ruk_git::transport::archive::serve_upload_archive;
use ruk_git::transport::pack::IngestLimits;
use ruk_git::transport::push::{PushUpdate, PushWireRequest};
use ruk_git::transport::serve::{HeadAdvertisement, serve_receive_pack, serve_upload_pack};
use ruk_git::transport::session::{
    LocalFetchRequest, advertise, local_fetch, local_push, open_local_store,
};
use ruk_git::transport::{Interrupt, has_object};

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
    };
    run_fetch(ctx, &remote_label, &spec_texts, plan)
}

/// How a fetch updates refs. Data, not selectors: one plan per invocation.
struct FetchPlan {
    /// Every update behaves as forced.
    force_all: bool,
    /// Shallow depth, when the caller asked for one.
    depth: Option<u32>,
    /// Also take all advertised tags.
    fetch_tags: bool,
}

/// Expands refspecs, negotiates the pack, and updates refs atomically.
fn run_fetch(
    ctx: &Ctx,
    remote_label: &str,
    spec_texts: &[String],
    plan: FetchPlan,
) -> Result<Vec<u8>, GitError> {
    let dest = ctx.store()?;
    let dest_kind = ctx.kind()?;
    let src_root = remote_root(ctx, remote_label)?;
    let src = open_store_at(&src_root)?;
    if src.hash_kind() != dest_kind {
        return Err(GitError::ObjectFormat {
            detail: "source and destination object formats disagree".to_owned(),
        });
    }
    let advertised = advertise(&src)?;
    let mut pairs: Vec<FetchedRef> = Vec::new();
    for spec_text in spec_texts {
        pairs.extend(expand_spec(&src, &advertised, spec_text)?);
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
    if pairs.is_empty() {
        return write_fetch_head(ctx, &[]);
    }
    let dest_refs = StoreRefs::new(dest);
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
    let ref_mutations = prepared.into_mutations();
    let request = LocalFetchRequest {
        wants,
        haves,
        filter: None,
        depth: plan.depth,
    };
    local_fetch(
        dest,
        &src,
        remote_label.as_bytes(),
        &request,
        &tracking,
        &ref_mutations,
        IngestLimits::default(),
        &Interrupt::none(),
    )?;
    let mut out = lines.concat().into_bytes();
    out.extend_from_slice(&write_fetch_head(ctx, &pairs)?);
    Ok(out)
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

/// Expands one refspec against the advertised source refs.
fn expand_spec(
    src: &Store,
    advertised: &[ruk_git::transport::session::AdvertisedLocalRef],
    text: &str,
) -> Result<Vec<FetchedRef>, GitError> {
    let spec = parse_spec(text)?;
    let mut out = Vec::new();
    if spec.src.contains('*') {
        let dst_pattern = spec.dst.ok_or_else(|| GitError::Invalid {
            detail: format!("glob refspec {text:?} needs a destination"),
        })?;
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
        return Ok(out);
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
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let target = opts.positionals.first().map_or("origin", String::as_str);
    let dest_root = remote_root(ctx, target)?;
    let dest = open_store_at(&dest_root)?;
    if dest.hash_kind() != kind {
        return Err(GitError::ObjectFormat {
            detail: "source and destination object formats disagree".to_owned(),
        });
    }
    let spec_texts: Vec<String> = if opts.positionals.len() > 1 {
        opts.positionals[1..].to_vec()
    } else {
        let (workspace, _) = load_or_default(store)?;
        match workspace.head {
            ruk_core::workspace::HeadRef::Symbolic(name) => {
                let short = name.to_utf8().unwrap_or_default().to_owned();
                vec![format!("{short}:{short}")]
            }
            ruk_core::workspace::HeadRef::Detached(_) => {
                return Err(GitError::Invalid {
                    detail: "push from a detached HEAD needs an explicit refspec".to_owned(),
                });
            }
        }
    };
    let zero = kind.zero_oid();
    let mut updates = Vec::new();
    for spec_text in &spec_texts {
        let (force, rest) = spec_text
            .strip_prefix('+')
            .map_or((false, spec_text.as_str()), |tail| (true, tail));
        let (src_text, dst_text) = rest
            .split_once(':')
            .map_or((rest, rest), |(left, right)| (left, right));
        if opts.is_set("delete") {
            let name = dwell_dest(&dest, dst_text)?;
            let old = peel_dest_oid(&dest, &name)?.unwrap_or(zero);
            updates.push(PushUpdate {
                name: name.as_bytes().to_vec(),
                old,
                new: zero,
            });
            continue;
        }
        let new = resolve_rev(store, kind, src_text)?;
        let name = dwell_dest(&dest, dst_text)?;
        let old = peel_dest_oid(&dest, &name)?.unwrap_or(zero);
        if old != zero && !force && !opts.is_set("force") && !is_ancestor(store, old, new)? {
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
    let request = PushWireRequest {
        updates: updates.clone(),
        atomic: opts.is_set("atomic"),
    };
    let mut plan = ruk_git::transport::push::PushPlanRecord::prepare(
        PlanId::generate(),
        target.as_bytes().to_vec(),
        opts.is_set("atomic"),
        updates,
    );
    let outcomes = local_push(&dest, store, kind, &mut plan, &request, &Interrupt::none())?;
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
    match ctx.env.stdin.as_deref() {
        Some(input) => {
            let mut out = Vec::new();
            serve_receive_pack(input, &mut out, &store, kind, &head, &Interrupt::none())?;
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

/// Reads the `HEAD` advertisement for a serve verb: the symbolic target for
/// the `symref` capability and the OID for the `HEAD` line (zero unborn).
fn serve_head(store: &Store) -> Result<HeadAdvertisement, GitError> {
    let (workspace, _) = load_or_default(store)?;
    match &workspace.head {
        ruk_core::workspace::HeadRef::Symbolic(name) => {
            let oid = StoreRefs::new(store)
                .get(name)?
                .and_then(|target| match target {
                    RefTarget::Direct(oid) => Some(oid),
                    RefTarget::Symbolic(_) => None,
                })
                .unwrap_or_else(|| store.hash_kind().zero_oid());
            Ok(HeadAdvertisement {
                oid,
                symref: Some(name.as_bytes().to_vec()),
            })
        }
        ruk_core::workspace::HeadRef::Detached(oid) => Ok(HeadAdvertisement {
            oid: *oid,
            symref: None,
        }),
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

/// Lists refs in a local repository.
///
/// Oracle: `git/builtin/ls-remote.c`. Network remotes are `Offline`.
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
    let root = remote_root(ctx, target)?;
    let src = open_store_at(&root)?;
    let advertised = advertise(&src)?;
    let pattern = match opts.positionals.as_slice() {
        [_] | [] => None,
        [_, want] => Some(want.clone()),
        _ => {
            return Err(GitError::Invalid {
                detail: "usage: ls-remote [<remote>] [<pattern>]".to_owned(),
            });
        }
    };
    let want = pattern.as_deref();
    let mut out = Vec::new();
    for entry in &advertised {
        let name = String::from_utf8_lossy(&entry.name).into_owned();
        if opts.is_set("heads") && !name.starts_with("refs/heads/") {
            continue;
        }
        if opts.is_set("tags") && !name.starts_with("refs/tags/") {
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
    Ok(line(out))
}
