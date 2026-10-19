//! Transport and maintenance verbs: `fetch`, `pull`, `push`,
//! `receive-pack`, `upload-pack`, `archive`, `gc`, `fsck`,
//! `ls-remote` (`bundle` lives in `verbs_bundle`).
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `fetch` | local stores via `session::local_fetch`, SSH/git-daemon remotes via `fetch::receive` over `net` streams, HTTP remotes via a protocol-v2 probe first (`smart_http::fetch_pack_v2` over `ls-refs` refs) with a v0 `smart_http::fetch_pack` fallback, then `dumb_http` when the smart advertisement is absent | `--prune` drops orphaned remote-tracking refs (pull-mirror parity); `--lfs` pulls LFS payloads for fetched tips (pull-mirror parity) |
//! | `pull` | fetch + fast-forward | local, SSH/git and HTTP remotes (fast-forward only) |
//! | `push` | local stores via `session::local_push`, SSH/git-daemon remotes via `push::push_over`, HTTP remotes via `smart_http::push_pack`, all with a persisted plan | `--mirror` sets every ref and deletes stale ones (push-mirror parity); `--lfs` uploads the outgoing range's verified payloads through the batch API before pushing (push-mirror parity); push over dumb-http stays refused (static files accept no pack) |
//! | `receive-pack` | `serve::serve_receive_pack` + `session::apply_refs` | served (protocol v0; v2 defines no push command) |
//! | `upload-pack` | `serve::serve_upload_pack` + `session::local_closure` | served (protocol v0, plus v2 `ls-refs`/`fetch` via `serve_v2` when `GIT_PROTOCOL` asks for `version=2`) |
//! | `archive` | local trees through the `upload-archive` serve half over a loopback, `--remote` trees through the smart-http `git-upload-archive` RPC or the SSH/git-daemon duplex session | tar and zip (`--format=zip` transcodes the tar client-side; every transport still answers tar); `--prefix`, `-o` and path limits rewrite the stream client-side |
//! | `bundle` | git bundle v2/v3 headers plus pack v2, see `verbs_bundle` | `create`/`verify`/`list-heads`/`unbundle` over the native store |
//! | `gc` | ref closure plus workspace pins through `Store::prune_unreachable`, then `Store::compact` | `--aggressive` repeats compaction; `--auto` exits quietly with no work; `--dry-run` reports; `--prune=now` (default) prunes, `--prune=never` compacts only, other dates are `Unsupported` (no object ages) |
//! | `fsck` | ref walk + object existence, census-minus-reachable sweep | implemented; `--dangling`/`--unreachable` list `dangling <kind> <oid>` rows |
//! | `ls-remote` | local `session::advertise` or one `net::discover` round trip; HTTP remotes probe protocol v2 first (`ls-refs`), then the dumb-http text file | SSH/git and smart/dumb-http remotes served |
//! | `credential` | stdin `key=value` description through the configured helpers with the `get`/`store`/`erase` operation | `fill` echoes the description with the found fields; `approve`/`reject` are silent; needs no repository |
//!
//! Oracle anchors: `git/builtin/fetch.c`, `git/builtin/pull.c`,
//! `git/builtin/push.c`, `git/builtin/receive-pack.c`,
//! `git/builtin/upload-pack.c`, `git/builtin/archive.c`,
//! `git/builtin/gc.c`, `git/builtin/fsck.c`,
//! `git/builtin/ls-remote.c`, `git/builtin/credential.c`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use ruk_core::change::PlanId;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefRead, RefTarget, RefUpdate};
use ruk_core::refs::{StoreRefs, all_reflog_oids};
use ruk_core::store::{FactExpectation, FactMutation, FactTable, ObjectKind, Store};
use ruk_core::{LfsMode, mode_for_store};
use ruk_git::GitError;
use ruk_git::transport::archive::serve_upload_archive;
use ruk_git::transport::fetch::{self, FetchWireRequest};
use ruk_git::transport::mirror::{prune_for_spec, push_mirror_updates};
use ruk_git::transport::net::{self, Endpoint};
use ruk_git::transport::pack::IngestLimits;
use ruk_git::transport::push::{PushUpdate, PushWireRequest};
use ruk_git::transport::refadv::Capabilities;
use ruk_git::transport::serve::{HeadAdvertisement, serve_receive_pack, serve_upload_pack};
use ruk_git::transport::serve_v2::{git_protocol_requests_v2, serve_upload_pack_v2};
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
/// `--lfs` also pulls LFS payloads for the newly-fetched tips through the
/// remote's batch endpoint (pull-mirror parity); without it the fetch stays
/// pointer-only, the way `git fetch` never smudges.
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
        FlagSpec {
            long: "lfs",
            short: None,
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
    let want_lfs = opts.is_set("lfs");
    let plan = FetchPlan {
        force_all: opts.is_set("force"),
        depth,
        fetch_tags: opts.is_set("tags"),
        prune: opts.is_set("prune"),
    };
    let (out, tips) = run_fetch(ctx, &remote_label, &spec_texts, plan)?;
    // Mirror LFS sync, after the refs moved: walks the newly-arrived tips
    // for pointer blobs and pulls their payloads through the remote's
    // batch endpoint. Absence (no endpoint, non-`Full` policy) is silent;
    // per-object misses go to stderr; only a refused batch document fails.
    if want_lfs && !tips.is_empty() {
        mirror_lfs_sync(ctx, &remote_label, &tips)?;
    }
    Ok(out)
}

/// How a push updates refs. Data, not selectors: one flag set per
/// invocation, so the local, network, and mirror lanes share one shape
/// instead of a positional list.
pub(crate) struct PushFlags {
    /// Every update behaves as forced.
    pub(crate) force_all: bool,
    /// All-or-nothing across refs.
    pub(crate) atomic: bool,
    /// Refspecs delete their destination refs.
    pub(crate) delete: bool,
    /// Every local ref mirrors to the same name, deleting stale ones.
    pub(crate) mirror: bool,
    /// Upload outgoing LFS payloads through the batch API before pushing.
    pub(crate) want_lfs: bool,
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
/// a network endpoint the SSH, git-daemon and smart-http transports serve.
enum Target {
    /// A local repository root holding `.ruk`.
    Local(PathBuf),
    /// An SSH, git-daemon or HTTP endpoint.
    Net(Endpoint),
}

/// Resolves a remote name or URL: configured names read their URL first,
/// then `file://` URLs and bare paths land local, and SSH, git-daemon
/// and HTTP URLs route network (HTTP serves smart-http, falling back to
/// dumb-http file fetches when the smart advertisement is absent; push
/// over dumb-http still refuses at discovery).
///
/// Oracle: `git/builtin/fetch.c` (remote resolution).
fn resolve_target(ctx: &Ctx, target: &str) -> Result<Target, GitError> {
    let url = ctx
        .config_get(&format!("remote.{target}.url"))
        .unwrap_or_else(|| target.to_owned());
    match net::parse_endpoint(&url)? {
        Endpoint::Local { .. } => Ok(Target::Local(remote_root(ctx, target)?)),
        endpoint @ (Endpoint::Ssh { .. } | Endpoint::Git { .. } | Endpoint::Http { .. }) => {
            Ok(Target::Net(endpoint))
        }
    }
}

/// The source side of one fetch: a local store or a network endpoint.
enum FetchSource {
    /// A local source store.
    Local(Store),
    /// A network endpoint (refs discover over a separate connection).
    Net(Endpoint),
    /// A smart-http base plus its upload-pack advertisement: discovery
    /// already ran for refspec expansion, and the fetch POST reuses the
    /// same caps (stateless, so no connection is held).
    Http {
        /// Normalized RPC base URL.
        base: String,
        /// The upload-pack advertisement from discovery.
        adv: ruk_git::transport::refadv::Advertisement,
        /// Resolved `http.extraHeader` rows for the base, reused by the
        /// fetch POST (stateless, so no connection is held).
        extra_headers: Vec<(String, String)>,
    },
    /// A smart-http v2 base plus its capability advertisement: refs came
    /// from one `ls-refs` RPC and the fetch POSTs `command=fetch`
    /// (stateless, so no connection is held).
    HttpV2 {
        /// Normalized RPC base URL.
        base: String,
        /// The v2 capability advertisement from the `Git-Protocol` probe.
        caps: Capabilities,
        /// Resolved `http.extraHeader` rows for the base.
        extra_headers: Vec<(String, String)>,
    },
    /// A dumb-http base: the smart advertisement was absent, so discovery
    /// fell back to the text `info/refs` file (the same fallback `git`
    /// makes). The fetch walks loose objects plus listed packs.
    DumbHttp {
        /// Normalized RPC base URL.
        base: String,
        /// Resolved `http.extraHeader` rows for the base.
        extra_headers: Vec<(String, String)>,
    },
}

/// Splits one flat config name into its `http.extraHeader` scope:
/// `Some(None)` for bare `http.extraHeader`, `Some(Some(scope))` for
/// `http.<scope>.extraHeader` with the scope in its original case, `None`
/// for anything else. Section and key match case-insensitively, like git's
/// config; the scope keeps its case for URL matching.
fn extra_header_scope(name: &str) -> Option<Option<String>> {
    let rest = name.to_ascii_lowercase().strip_prefix("http.")?.to_owned();
    if rest == "extraheader" {
        return Some(None);
    }
    rest.strip_suffix(".extraheader").and_then(|scope| {
        if scope.is_empty() {
            None
        } else {
            let raw = &name["http.".len()..name.len() - ".extraheader".len()];
            Some(Some(raw.to_owned()))
        }
    })
}

/// Resolves the `http.extraHeader` request headers for `url` from every
/// config layer, low to high precedence: git-config files, then the repo
/// store, then `-c` / `--config-env` overrides in order given. Store rows
/// stay single-valued (`ruk config` keeps last-wins); multivalued rows
/// come from the files and from repeated `-c` flags. An empty value resets
/// the accumulated list.
fn http_extra_headers(ctx: &Ctx, url: &str) -> Vec<(String, String)> {
    use ruk_git::transport::{credentials, http};
    let mut rows = credentials::http_extra_header_rows();
    if let Ok(store) = ctx.store() {
        if let Ok(pairs) = super::state::config_list(store) {
            let mut scoped = Vec::new();
            let mut unscoped = None;
            for (name, value) in &pairs {
                match extra_header_scope(name) {
                    Some(None) => unscoped = Some(value.clone()),
                    Some(Some(scope)) => scoped.push((scope, value.clone())),
                    None => {}
                }
            }
            if let Some(value) = unscoped {
                rows.push(http::ExtraHeaderRow { scope: None, value });
            }
            scoped.sort();
            for (scope, value) in scoped {
                rows.push(http::ExtraHeaderRow {
                    scope: Some(scope),
                    value,
                });
            }
        }
    }
    for (key, value) in &ctx.cli_config {
        match extra_header_scope(key) {
            Some(scope) => rows.push(http::ExtraHeaderRow {
                scope,
                value: value.clone(),
            }),
            None => {}
        }
    }
    http::extra_headers_for_url(url, &rows)
}

/// Expands refspecs, negotiates the pack, and updates refs.
///
/// `remote update` shares this path: it passes the remote's configured
/// refspecs with its own prune flag. Objects publish first and ref updates
/// second: the fast-forward check walks the new tip's ancestry, which needs
/// the just-fetched objects in the store (checking against the old object
/// set aborts the whole fetch with `NotFound` on every advance through
/// newly-fetched commits).
///
/// Returns the fetch report plus the fetched tip oids (the wants, including
/// tips whose ref update was refused): `fetch --lfs` walks exactly that
/// newly-arrived range for pointer blobs instead of re-scanning every ref.
///
/// Oracle: `git/builtin/fetch.c`, `git/builtin/remote.c` (`update`).
pub(crate) fn run_fetch(
    ctx: &Ctx,
    remote_label: &str,
    spec_texts: &[String],
    plan: FetchPlan,
) -> Result<(Vec<u8>, Vec<Oid>), GitError> {
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
        Target::Net(endpoint) => match endpoint {
            Endpoint::Http { url, .. } => {
                let base = ruk_git::transport::smart_http::normalize_base(&url)?;
                let extra_headers = http_extra_headers(ctx, &base);
                // Highest protocol first: one `Git-Protocol` GET parses
                // v2 caps or the v0 document; only dumb-http falls through.
                match ruk_git::transport::smart_http::discover_versioned(
                    &base,
                    ruk_git::transport::smart_http::SmartService::UploadPack,
                    dest_kind,
                    &extra_headers,
                ) {
                    Ok(ruk_git::transport::smart_http::VersionedDiscovery::V2(caps)) => {
                        let refs = ruk_git::transport::smart_http::ls_refs_v2(
                            &base,
                            &caps,
                            dest_kind,
                            &[],
                            &Interrupt::none(),
                            &extra_headers,
                        )?;
                        let advertised = net::to_local_refs(refs)?;
                        (
                            FetchSource::HttpV2 {
                                base,
                                caps,
                                extra_headers,
                            },
                            advertised,
                        )
                    }
                    Ok(ruk_git::transport::smart_http::VersionedDiscovery::V0(adv)) => {
                        let advertised = net::to_local_refs(adv.refs.clone())?;
                        (
                            FetchSource::Http {
                                base,
                                adv,
                                extra_headers,
                            },
                            advertised,
                        )
                    }
                    Err(err) if ruk_git::transport::dumb_http::is_dumb_gap(&err) => {
                        let adv = ruk_git::transport::dumb_http::discover(
                            &base,
                            dest_kind,
                            &extra_headers,
                        )?;
                        let advertised = net::to_local_refs(adv.refs.clone())?;
                        (
                            FetchSource::DumbHttp {
                                base,
                                extra_headers,
                            },
                            advertised,
                        )
                    }
                    Err(err) => return Err(err),
                }
            }
            _ => {
                let advertised = net::to_local_refs(net::discover_endpoint(
                    &endpoint,
                    Service::UploadPack,
                    dest_kind,
                )?)?;
                (FetchSource::Net(endpoint), advertised)
            }
        },
    };
    let mut pairs: Vec<FetchedRef> = Vec::new();
    for spec_text in spec_texts {
        match &source {
            FetchSource::Local(src) => pairs.extend(expand_spec(src, &advertised, spec_text)?),
            FetchSource::Net(_)
            | FetchSource::Http { .. }
            | FetchSource::HttpV2 { .. }
            | FetchSource::DumbHttp { .. } => {
                pairs.extend(expand_spec_net(&advertised, dest, spec_text)?)
            }
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
        return Ok((write_fetch_head(ctx, &[])?, Vec::new()));
    }
    // Wants cover every advertised tip, including refs this fetch may later
    // refuse to move: like git, refused ref updates keep their objects.
    let wants: Vec<Oid> = pairs.iter().map(|fetched| fetched.oid).collect();
    let haves: Vec<Oid> = list_refs(dest)?
        .into_iter()
        .filter_map(|(_, target)| match target {
            RefTarget::Direct(oid) => Some(oid),
            RefTarget::Symbolic(_) => None,
        })
        .collect();
    if !pairs.is_empty() {
        // Phase one: publish the objects with no ref deltas. The
        // fast-forward check below walks the new tips' ancestry, which only
        // resolves once these objects are in the store.
        fetch_objects_only(dest, &source, remote_label, wants, haves, plan.depth)?;
    }
    // Phase two: the fast-forward check runs against the committed object
    // set, so advances through newly-fetched commits resolve. A refused
    // update keeps the published objects; only the tracking ref stays.
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
                // Runs after phase one publishes, so the new tip's ancestry
                // resolves from committed state. A lookup failure still
                // aborts the fetch: only a proven non-ancestor refuses the
                // ref, and the published objects stay either way.
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
    let mut ref_mutations = if updates.is_empty() {
        Vec::new()
    } else {
        ruk_core::refs::prepare_checked_transaction(
            dest,
            &ruk_core::refdata::RefTransaction::new(dest_kind, updates)
                .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?,
        )?
        .into_mutations()
    };
    ref_mutations.extend(fetch::observation_mutations(
        remote_label.as_bytes(),
        &tracking,
    ));
    for name in &pruned {
        ref_mutations.push(FactMutation {
            table: FactTable::RemoteObservations,
            key: observation_key(remote_label.as_bytes(), name),
            expected: FactExpectation::Any,
            value: None,
        });
    }
    if !ref_mutations.is_empty() {
        // Ref updates only: the objects published in phase one stay even
        // when every update below is a prune delete or a refusal left no
        // updates at all.
        dest.publish(Vec::new(), &ref_mutations)?;
    }
    let mut out = lines.concat().into_bytes();
    out.extend_from_slice(&write_fetch_head(ctx, &pairs)?);
    let tips: Vec<Oid> = pairs.iter().map(|fetched| fetched.oid).collect();
    Ok((out, tips))
}

/// Publishes one fetch's objects with no ref deltas: phase one of
/// [`run_fetch`], shared by every transport. Ref updates (and their
/// fast-forward check) publish separately in phase two, once the new tips'
/// ancestry resolves against the store.
///
/// Oracle: `git/builtin/fetch.c`.
fn fetch_objects_only(
    dest: &Store,
    source: &FetchSource,
    remote_label: &str,
    wants: Vec<Oid>,
    haves: Vec<Oid>,
    depth: Option<u32>,
) -> Result<(), GitError> {
    let request = FetchWireRequest {
        wants,
        haves,
        filter: None,
        depth,
        shallow: Vec::new(),
        list_refs: false,
        ref_prefixes: Vec::new(),
    };
    match source {
        FetchSource::Local(src) => {
            local_fetch(
                dest,
                src,
                remote_label.as_bytes(),
                &LocalFetchRequest {
                    wants: request.wants.clone(),
                    haves: request.haves.clone(),
                    filter: None,
                    depth: request.depth,
                },
                &[],
                &[],
                IngestLimits::default(),
                &Interrupt::none(),
            )?;
        }
        FetchSource::Net(endpoint) => {
            fetch_pack_net(dest, endpoint, remote_label, &request, &[], &[])?;
        }
        FetchSource::Http { .. } => {
            fetch_pack_http(dest, source, remote_label, &request, &[], &[])?;
        }
        FetchSource::HttpV2 { .. } => {
            fetch_pack_http_v2(dest, source, remote_label, &request, &[], &[])?;
        }
        FetchSource::DumbHttp { .. } => {
            fetch_pack_dumb(dest, source, remote_label, &request, &[], &[])?;
        }
    }
    Ok(())
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
    request: &FetchWireRequest,
    tracking: &[(RefName, RefTarget)],
    ref_mutations: &[FactMutation],
) -> Result<(), GitError> {
    let stream = net::open_stream(endpoint, Service::UploadPack)?;
    let received = fetch::receive(
        stream,
        dest.hash_kind(),
        dest,
        request,
        IngestLimits::default(),
        &Interrupt::none(),
    )?;
    publish_received(
        dest,
        received,
        request,
        remote_label,
        tracking,
        ref_mutations,
    )
}

/// Runs the pack half of a smart-http fetch: POSTs the whole v0 request
/// and publishes through the same verify-and-publish tail as
/// [`fetch_pack_net`]. The base and advertisement ride in `source`, which
/// is always the [`FetchSource::Http`] discovery established.
///
/// Oracle: `git/builtin/fetch.c`, `git/remote-curl.c` (`fetch_git`).
fn fetch_pack_http(
    dest: &Store,
    source: &FetchSource,
    remote_label: &str,
    request: &FetchWireRequest,
    tracking: &[(RefName, RefTarget)],
    ref_mutations: &[FactMutation],
) -> Result<(), GitError> {
    let FetchSource::Http {
        base,
        adv,
        extra_headers,
    } = source
    else {
        return Err(GitError::Invalid {
            detail: "smart-http fetch needs an HTTP source".to_owned(),
        });
    };
    let received = ruk_git::transport::smart_http::fetch_pack(
        base,
        adv,
        dest,
        request,
        IngestLimits::default(),
        &Interrupt::none(),
        extra_headers,
    )?;
    publish_received(
        dest,
        received,
        request,
        remote_label,
        tracking,
        ref_mutations,
    )
}

/// Runs the pack half of a smart-http v2 fetch: POSTs `command=fetch` and
/// publishes through the same verify-and-publish tail as
/// [`fetch_pack_http`]. The base and capabilities ride in `source`, which
/// is always the [`FetchSource::HttpV2`] discovery established.
///
/// Oracle: `git/builtin/fetch.c`, `git/remote-curl.c` (`fetch_git`).
fn fetch_pack_http_v2(
    dest: &Store,
    source: &FetchSource,
    remote_label: &str,
    request: &FetchWireRequest,
    tracking: &[(RefName, RefTarget)],
    ref_mutations: &[FactMutation],
) -> Result<(), GitError> {
    let FetchSource::HttpV2 {
        base,
        caps,
        extra_headers,
    } = source
    else {
        return Err(GitError::Invalid {
            detail: "smart-http v2 fetch needs an HTTP v2 source".to_owned(),
        });
    };
    let received = ruk_git::transport::smart_http::fetch_pack_v2(
        base,
        caps,
        dest,
        request,
        IngestLimits::default(),
        &Interrupt::none(),
        extra_headers,
    )?;
    publish_received(
        dest,
        received,
        request,
        remote_label,
        tracking,
        ref_mutations,
    )
}

/// Runs the pack-equivalent half of a dumb-http fetch: walks loose objects
/// plus listed packs and publishes through the same verify-and-publish
/// tail as [`fetch_pack_http`]. Push over dumb-http stays refused: static
/// files accept no pack, so [`push_net`] lets the discovery-time
/// [`net::dumb_http_gap`] refusal propagate.
///
/// Oracle: `git/builtin/fetch.c`, `git/remote-curl.c` (dumb fallback).
fn fetch_pack_dumb(
    dest: &Store,
    source: &FetchSource,
    remote_label: &str,
    request: &FetchWireRequest,
    tracking: &[(RefName, RefTarget)],
    ref_mutations: &[FactMutation],
) -> Result<(), GitError> {
    let FetchSource::DumbHttp {
        base,
        extra_headers,
    } = source
    else {
        return Err(GitError::Invalid {
            detail: "dumb-http fetch needs a dumb-http source".to_owned(),
        });
    };
    let received = ruk_git::transport::dumb_http::fetch_pack(
        base,
        dest,
        request,
        IngestLimits::default(),
        &Interrupt::none(),
        extra_headers,
    )?;
    publish_received(
        dest,
        received,
        request,
        remote_label,
        tracking,
        ref_mutations,
    )
}

/// Verifies one received pack's closure and publishes staged objects
/// together with the caller's ref deltas: the tail every network fetch
/// shares, however the pack arrived.
///
/// Oracle: `git/builtin/fetch.c`.
fn publish_received(
    dest: &Store,
    received: fetch::ReceivedPack,
    request: &FetchWireRequest,
    remote_label: &str,
    tracking: &[(RefName, RefTarget)],
    ref_mutations: &[FactMutation],
) -> Result<(), GitError> {
    let report = fetch::verify_closure(
        dest,
        &received.staged,
        &request.wants,
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
    let (_, _) = run_fetch(ctx, &remote_label, &[spec], plan)?;
    let tip = resolve_rev(
        store,
        ctx.kind()?,
        &format!("refs/remotes/{remote_label}/{wanted}"),
    )?;
    let before = super::state::head_oid(store)?;
    super::verbs_history::merge_fast_forward(ctx, &wanted, before, tip)
}

/// Pushes refs through a persisted plan: local stores, SSH/git-daemon
/// remotes, and HTTP remotes.
///
/// `--lfs` uploads the outgoing pointer blobs' payloads through the
/// remote's LFS batch endpoint before the pack moves (push-mirror parity):
/// the same wants-minus-haves closure the pack carries is scanned for
/// pointer blobs, and every payload already verified in the sidecar is
/// offered with one batch `upload` request. Full mode only; a missing
/// endpoint, no payloads, or a non-`Full` policy skips silently, per-object
/// misses go to stderr, and only a refused batch document fails.
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
        FlagSpec {
            long: "lfs",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let kind = ctx.kind()?;
    let target = opts.positionals.first().map_or("origin", String::as_str);
    // Mirror force: the oracle's `--mirror` forces every ref update, the
    // way a push mirror (`git push --mirror --force`) syncs deletions and
    // rewinds alike.
    let flags = PushFlags {
        force_all: opts.is_set("force") || opts.is_set("mirror"),
        atomic: opts.is_set("atomic"),
        delete: opts.is_set("delete"),
        mirror: opts.is_set("mirror"),
        want_lfs: opts.is_set("lfs"),
    };
    let remote_label = configured_name(ctx, target).unwrap_or_else(|| target.to_owned());
    if flags.mirror && opts.positionals.len() > 1 {
        return Err(GitError::Invalid {
            detail: "usage: push [--mirror] [<remote>]".to_owned(),
        });
    }
    let spec_texts: Vec<String> = if flags.mirror {
        Vec::new()
    } else if opts.positionals.len() > 1 {
        opts.positionals[1..].to_vec()
    } else {
        let store = ctx.store()?;
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
            if flags.mirror {
                return push_mirror(ctx, &dest, target, &flags, &remote_label);
            }
            // Scoped borrows: the store borrow ends before the LFS upload
            // reborrows `ctx` mutably for stderr.
            let updates = {
                let store = ctx.store()?;
                build_push_updates(
                    store,
                    &dest,
                    &spec_texts,
                    flags.delete,
                    flags.force_all,
                    &|name| peel_dest_oid(&dest, name),
                )?
            };
            if flags.want_lfs {
                push_lfs_upload(ctx, &updates, &remote_label)?;
            }
            let store = ctx.store()?;
            push_local(store, &dest, target, kind, flags.atomic, updates)
        }
        Target::Net(endpoint) => {
            push_net(ctx, &endpoint, target, &spec_texts, &flags, &remote_label)
        }
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
/// (or one smart-http POST for HTTP endpoints) with the same persisted
/// plan local pushes use.
///
/// Oracle: `git/builtin/push.c`.
fn push_net(
    ctx: &mut Ctx,
    endpoint: &Endpoint,
    target: &str,
    spec_texts: &[String],
    flags: &PushFlags,
    remote_label: &str,
) -> Result<Vec<u8>, GitError> {
    let kind = ctx.kind()?;
    // Discovery plus the update list under one scoped store borrow, so the
    // LFS upload below can reborrow `ctx` mutably for stderr.
    let (updates, http_adv) = {
        let store = ctx.store()?;
        // HTTP discovery keeps the full advertisement: the POST half reuses
        // its capabilities, while the other transports only need the refs.
        // Stateless, so no connection is held between the two round trips.
        let http_adv = match endpoint {
            Endpoint::Http { url, .. } => {
                let base = ruk_git::transport::smart_http::normalize_base(url)?;
                let extra_headers = http_extra_headers(ctx, &base);
                Some((
                    base.clone(),
                    ruk_git::transport::smart_http::discover(
                        &base,
                        ruk_git::transport::smart_http::SmartService::ReceivePack,
                        kind,
                        &extra_headers,
                    )?,
                    extra_headers,
                ))
            }
            _ => None,
        };
        let advertised = match &http_adv {
            Some((_, adv, _)) => net::to_local_refs(adv.refs.clone())?,
            None => net::to_local_refs(net::discover_endpoint(
                endpoint,
                Service::ReceivePack,
                kind,
            )?)?,
        };
        let remote: Vec<(Vec<u8>, Oid)> = advertised
            .iter()
            .filter_map(|entry| match &entry.target {
                RefTarget::Direct(oid) => Some((entry.name.clone(), *oid)),
                RefTarget::Symbolic(_) => None,
            })
            .collect();
        let updates = if flags.mirror {
            mirror_push_updates(kind, &direct_tips(store)?, &remote)
        } else {
            build_push_updates(
                store,
                store,
                spec_texts,
                flags.delete,
                flags.force_all,
                &|name| peel_advertised(&advertised, name),
            )?
        };
        (updates, http_adv)
    };
    if flags.mirror && updates.is_empty() {
        return Ok(Vec::new());
    }
    // LFS payloads ride the batch API, never the pack: upload the outgoing
    // range's verified payloads before the first pack byte moves.
    if flags.want_lfs {
        push_lfs_upload(ctx, &updates, remote_label)?;
    }
    let store = ctx.store()?;
    let request = PushWireRequest {
        updates: updates.clone(),
        atomic: flags.atomic,
    };
    let mut plan = ruk_git::transport::push::PushPlanRecord::prepare(
        PlanId::generate(),
        target.as_bytes().to_vec(),
        flags.atomic,
        updates,
    );
    match &http_adv {
        Some((base, adv, extra_headers)) => {
            push_outcomes(ruk_git::transport::smart_http::push_pack(
                base,
                adv,
                &store,
                &mut plan,
                &request,
                &Interrupt::none(),
                extra_headers,
            )?)
        }
        None => {
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
    }
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
/// push-mirror sync (`git push --mirror --force`) routes through. With
/// `--lfs` the outgoing range's verified payloads upload through the batch
/// API before the refs move, the same pre-push step [`push_net`] runs.
///
/// Oracle: `git/builtin/push.c` (`--mirror`).
fn push_mirror(
    ctx: &mut Ctx,
    dest: &Store,
    target: &str,
    flags: &PushFlags,
    remote_label: &str,
) -> Result<Vec<u8>, GitError> {
    let kind = ctx.kind()?;
    let local = {
        let store = ctx.store()?;
        direct_tips(store)?
    };
    let remote = direct_tips(dest)?;
    let updates = mirror_push_updates(kind, &local, &remote);
    if updates.is_empty() {
        return Ok(Vec::new());
    }
    if flags.want_lfs {
        push_lfs_upload(ctx, &updates, remote_label)?;
    }
    let store = ctx.store()?;
    let request = PushWireRequest {
        updates: updates.clone(),
        atomic: flags.atomic,
    };
    let mut plan = ruk_git::transport::push::PushPlanRecord::prepare(
        PlanId::generate(),
        target.as_bytes().to_vec(),
        flags.atomic,
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
    // Protocol selection rides on `GIT_PROTOCOL`, the way the oracle's
    // `determine_protocol_version_server` reads it: a v2-speaking client
    // sets `GIT_PROTOCOL=version=2` on the spawned server (ssh `SendEnv`,
    // daemon extra parameter), and anything else keeps the v0 default.
    // The read goes through `CliEnv` (populated from the process by
    // `capture`, per request by the daemon) so verbs never touch the real
    // process environment directly.
    let v2 = git_protocol_requests_v2(ctx.env.get("GIT_PROTOCOL"));
    match ctx.env.stdin.as_deref() {
        Some(input) => {
            let mut out = Vec::new();
            if v2 {
                serve_upload_pack_v2(input, &mut out, &store, kind, &head, &Interrupt::none())?;
            } else {
                serve_upload_pack(input, &mut out, &store, kind, &head, &Interrupt::none())?;
            }
            Ok(out)
        }
        // Live pipes stream the advertisement and pack straight to stdout;
        // see `receive_pack` for why the return value stays empty here.
        None => {
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            let stdout = std::io::stdout();
            let mut output = stdout.lock();
            if v2 {
                serve_upload_pack_v2(
                    &mut input,
                    &mut output,
                    &store,
                    kind,
                    &head,
                    &Interrupt::none(),
                )?;
            } else {
                serve_upload_pack(
                    &mut input,
                    &mut output,
                    &store,
                    kind,
                    &head,
                    &Interrupt::none(),
                )?;
            }
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

/// Streams a tar or zip archive of one revision: local trees through the
/// `upload-archive` serve half over a loopback, `--remote` trees over the
/// smart-http `git-upload-archive` RPC or the SSH/git-daemon duplex
/// `upload-archive` session.
///
/// Oracle: `git/builtin/archive.c` (`run_remote_archiver` client grammar
/// for the `--remote` arm). Every transport answers tar (the server
/// default); `--format=zip` transcodes the narrowed tar client-side
/// through the `zip` writer crate (files deflate, empty files store,
/// directories and symlinks keep their kinds, modes, and mtimes).
/// `--prefix` and path limiting rewrite the streamed tar client-side, so
/// they apply to zip entries exactly as to tar members.
pub(crate) fn archive(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "remote",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "format",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "prefix",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "output",
            short: Some('o'),
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    let format = opts.single("format")?.unwrap_or_else(|| "tar".to_owned());
    let zipped = match format.as_str() {
        "tar" => false,
        "zip" => true,
        other => {
            return Err(GitError::Unsupported {
                command: format!("archive format {other:?}: only tar and zip are spoken"),
            });
        }
    };
    let prefix = match opts.single("prefix")? {
        None => None,
        Some(raw) => {
            if raw.bytes().any(|byte| byte == 0) {
                return Err(GitError::Invalid {
                    detail: "archive --prefix must not contain NUL".to_owned(),
                });
            }
            if raw.starts_with('/') {
                return Err(GitError::Invalid {
                    detail: "archive --prefix must be relative".to_owned(),
                });
            }
            let mut owned = raw.into_bytes();
            if !owned.is_empty() && !owned.ends_with(b"/") {
                owned.push(b'/');
            }
            if owned.is_empty() { None } else { Some(owned) }
        }
    };
    if opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: archive [--remote=<repo>] [--format=tar|zip] [--prefix=<p>/] [-o <file>] <tree-ish> [<path>...]".to_owned(),
        });
    }
    let rev = opts.positionals[0].clone();
    let mut paths: Vec<String> = Vec::new();
    for raw in &opts.positionals[1..] {
        if raw.is_empty() || raw.bytes().any(|byte| byte == 0) {
            return Err(GitError::Invalid {
                detail: "archive paths must be non-empty NUL-free names".to_owned(),
            });
        }
        if raw.starts_with('/') {
            return Err(GitError::Invalid {
                detail: format!("archive path {raw:?} must be relative"),
            });
        }
        let trimmed = raw.strip_suffix('/').unwrap_or(raw);
        if trimmed.is_empty() || trimmed == "." {
            continue;
        }
        paths.push(trimmed.to_owned());
    }
    let tar = match opts.single("remote")? {
        None => {
            let store = ctx.store()?;
            archive_local(store, store.hash_kind(), &rev)?
        }
        Some(raw) => {
            let url = ctx
                .config_get(&format!("remote.{raw}.url"))
                .unwrap_or(raw.clone());
            match net::parse_endpoint(&url)? {
                Endpoint::Local { path } => {
                    let base = if path.is_absolute() {
                        path
                    } else {
                        ctx.env.cwd.join(path)
                    };
                    let store = open_store_at(&base).or_else(|_| open_local_store(&base))?;
                    let kind = store.hash_kind();
                    archive_local(&store, kind, &rev)?
                }
                Endpoint::Http { url, .. } => {
                    let base = ruk_git::transport::smart_http::normalize_base(&url)?;
                    let extra_headers = http_extra_headers(ctx, &base);
                    let out = ruk_git::transport::smart_http::fetch_archive(
                        &base,
                        &ruk_git::transport::smart_http::ArchiveWireRequest { rev },
                        &Interrupt::none(),
                        &extra_headers,
                    )?;
                    out.tar
                }
                endpoint @ (Endpoint::Ssh { .. } | Endpoint::Git { .. }) => {
                    let stream = net::open_archive_stream(&endpoint)?;
                    net::fetch_archive_stream(stream, &rev)?
                }
            }
        }
    };
    let tar = if prefix.is_some() || !paths.is_empty() {
        rewrap_archive_tar(tar, prefix.as_deref(), &paths)?
    } else {
        tar
    };
    // The tar flow above is untouched: zip transcodes the same rewrapped
    // bytes, so the tar path stays byte-identical.
    let stream = if zipped { tar_to_zip(&tar)? } else { tar };
    match opts.single("output")? {
        None => Ok(stream),
        Some(dest) => {
            let path = if PathBuf::from(&dest).is_absolute() {
                PathBuf::from(dest)
            } else {
                ctx.env.cwd.join(dest)
            };
            std::fs::write(&path, &stream).map_err(|err| GitError::Io {
                detail: format!("cannot write archive to {}: {err}", path.display()),
            })?;
            Ok(Vec::new())
        }
    }
}

/// One tar member: its 512-byte header plus the payload without padding.
/// `x` pax headers stay separate members paired with the entry behind
/// them; `g` global headers pass through untouched.
struct TarMember {
    header: [u8; 512],
    data: Vec<u8>,
}

/// Splits a member path across the ustar prefix/name fields at the last
/// slash within the first 155 bytes, mirroring the server half. Returns
/// `None` when no split fits and the caller must carry the name in a pax
/// `path` record instead.
fn split_tar_name(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.len() <= 100 {
        return Some((&[][..], path));
    }
    let mut i = path.len();
    if i > 1 && path[i - 1] == b'/' {
        i -= 1;
    }
    if i > 155 {
        i = 155;
    }
    loop {
        if i == 0 {
            break;
        }
        i -= 1;
        if path[i] == b'/' {
            break;
        }
    }
    if i == 0 {
        return None;
    }
    let (prefix, rest) = (&path[..i], &path[i + 1..]);
    if rest.len() <= 100 {
        Some((prefix, rest))
    } else {
        None
    }
}

/// Parses a NUL/space-terminated octal header field.
fn parse_octal(field: &[u8], what: &str) -> Result<u64, GitError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0 || *byte == b' ')
        .unwrap_or(field.len());
    let text = std::str::from_utf8(&field[..end]).map_err(|_| GitError::Corrupt {
        detail: format!("archive header {what} is not ASCII"),
    })?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(0);
    }
    if !text.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(GitError::Corrupt {
            detail: format!("archive header {what} is not octal: {text:?}"),
        });
    }
    u64::from_str_radix(text, 8).map_err(|_| GitError::Corrupt {
        detail: format!("archive header {what} overflows: {text:?}"),
    })
}

/// Recomputes a member header's checksum over spaces, mirroring the
/// server half's `%07o` shape.
fn checksum_header(header: &mut [u8; 512]) {
    let digits = 7;
    let mut sum: u32 = 0;
    for (index, byte) in header.iter().enumerate() {
        sum += if (148..156).contains(&index) {
            u32::from(b' ')
        } else {
            u32::from(*byte)
        };
    }
    let text = format!("{sum:0digits$o}");
    let bytes = text.as_bytes();
    let n = bytes.len().min(7);
    header[148..148 + n].copy_from_slice(&bytes[..n]);
    header[155] = b' ';
}

/// The ustar prefix/name fields joined with `/`, without consulting any
/// `x` record beside the member.
fn header_name(header: &[u8; 512]) -> Vec<u8> {
    let prefix_end = header[345..500]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(155);
    let name_end = header[..100]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(100);
    let (prefix, name) = (&header[345..345 + prefix_end], &header[..name_end]);
    if prefix.is_empty() {
        name.to_vec()
    } else {
        let mut out = prefix.to_vec();
        out.push(b'/');
        out.extend_from_slice(name);
        out
    }
}

/// Reads the `path` record out of pax extended-header data, if present.
fn pax_path_record(data: &[u8]) -> Option<Vec<u8>> {
    let mut rest = data;
    while !rest.is_empty() {
        let space = rest.iter().position(|byte| *byte == b' ')?;
        let len: usize = std::str::from_utf8(&rest[..space]).ok()?.parse().ok()?;
        if len == 0 || len > rest.len() {
            return None;
        }
        let record = &rest[..len];
        rest = &rest[len..];
        if !record.ends_with(b"\n") {
            continue;
        }
        let body = &record[space + 1..record.len() - 1];
        if let Some(value) = body.strip_prefix(b"path=") {
            return Some(value.to_vec());
        }
    }
    None
}

/// Ensures pax extended-header data carries a `path` record for `path`:
/// an existing record is rewritten, else one is appended. Record lengths
/// count themselves, so every rewrite recomputes the width.
fn set_pax_path(data: &[u8], path: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + path.len() + 16);
    let mut rest = data;
    let mut replaced = false;
    while !rest.is_empty() {
        let Some(space) = rest.iter().position(|byte| *byte == b' ') else {
            out.extend_from_slice(rest);
            break;
        };
        let len: usize = match std::str::from_utf8(&rest[..space])
            .ok()
            .and_then(|text| text.parse().ok())
        {
            Some(len) => len,
            None => {
                out.extend_from_slice(rest);
                break;
            }
        };
        if len == 0 || len > rest.len() {
            out.extend_from_slice(rest);
            break;
        }
        let record = &rest[..len];
        rest = &rest[len..];
        if !record.ends_with(b"\n") {
            out.extend_from_slice(record);
            continue;
        }
        let body = &record[space + 1..record.len() - 1];
        if body.strip_prefix(b"path=").is_none() {
            out.extend_from_slice(record);
            continue;
        }
        out.extend_from_slice(&ext_record_bytes("path", path));
        replaced = true;
    }
    if !replaced {
        out.extend_from_slice(&ext_record_bytes("path", path));
    }
    out
}

/// Whether a member path survives path limiting: an exact hit or anything
/// beneath a named directory (trailing slashes already trimmed).
fn path_kept(name: &[u8], paths: &[String]) -> bool {
    let name = name.strip_suffix(b"/").unwrap_or(name);
    paths.is_empty()
        || paths.iter().any(|wanted| {
            let wanted = wanted.as_bytes();
            name == wanted
                || (name.len() > wanted.len()
                    && name.starts_with(wanted)
                    && name[wanted.len()] == b'/')
        })
}

/// Rewrites a streamed tar client-side: `prefix` (with its trailing slash)
/// is prepended to every member name, and `paths` drops every member
/// outside the named files and directories. The `g` global header is not
/// a member and passes through verbatim; `x` pax headers follow the entry
/// they describe and their `path` records track the rename.
fn rewrap_archive_tar(
    tar: Vec<u8>,
    prefix: Option<&[u8]>,
    paths: &[String],
) -> Result<Vec<u8>, GitError> {
    let corrupt = |detail: String| GitError::Corrupt { detail };
    let mut members: Vec<(TarMember, u8)> = Vec::new();
    let mut pos = 0;
    while pos + 512 <= tar.len() {
        let mut header = [0u8; 512];
        header.copy_from_slice(&tar[pos..pos + 512]);
        pos += 512;
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        if header[257..263] != *b"ustar\0" {
            return Err(corrupt("archive member is not a ustar header".to_owned()));
        }
        let size = usize::try_from(parse_octal(&header[124..136], "size")?)
            .map_err(|_| corrupt("archive member size overflows".to_owned()))?;
        let padded = size.div_ceil(512) * 512;
        if pos + padded > tar.len() {
            return Err(corrupt("archive member runs past the stream".to_owned()));
        }
        let data = tar[pos..pos + size].to_vec();
        pos += padded;
        let typeflag = header[156];
        members.push((TarMember { header, data }, typeflag));
    }
    // `names` holds every described member's logical path (`None` for the
    // `x` headers, which name no member): the `path` record beside a
    // member wins over its (possibly truncated) header fields per POSIX.
    // The keep passes below read only these plus the flags.
    let mut names: Vec<Option<Vec<u8>>> = Vec::with_capacity(members.len());
    let mut held_path: Option<Vec<u8>> = None;
    for (member, typeflag) in &members {
        if *typeflag == b'x' {
            if let Some(path) = pax_path_record(&member.data) {
                held_path = Some(path);
            }
            names.push(None);
            continue;
        }
        if *typeflag == b'g' {
            names.push(Some(header_name(&member.header)));
            continue;
        }
        let path = match held_path.take() {
            Some(path) => path,
            None => header_name(&member.header),
        };
        names.push(Some(path));
    }
    let is_dir = |index: usize| members[index].1 == b'5';
    let under = |dir: &[u8], peer: &[u8]| {
        peer.len() > dir.len() && peer.starts_with(dir) && peer[dir.len()] == b'/'
    };
    // Files (and symlinks, gitlinks-as-dirs aside) pass on a direct hit;
    // directories pass on a hit or when they parent a passing file.
    let mut file_kept = vec![false; members.len()];
    for index in 0..members.len() {
        if members[index].1 == b'g' || members[index].1 == b'x' {
            continue;
        }
        let Some(name) = &names[index] else {
            return Err(corrupt("archive member has no name".to_owned()));
        };
        if !is_dir(index) && path_kept(name, paths) {
            file_kept[index] = true;
        }
    }
    let mut keep = vec![false; members.len()];
    for index in 0..members.len() {
        let typeflag = members[index].1;
        if typeflag == b'g' {
            keep[index] = true;
            continue;
        }
        if typeflag == b'x' {
            continue;
        }
        let Some(name) = &names[index] else {
            return Err(corrupt("archive member has no name".to_owned()));
        };
        if path_kept(name, paths) {
            keep[index] = true;
            continue;
        }
        if !is_dir(index) {
            continue;
        }
        let dir = name.strip_suffix(b"/").unwrap_or(name);
        keep[index] = file_kept
            .iter()
            .enumerate()
            .filter(|(_, kept)| **kept)
            .any(|(other, _)| {
                names[other].as_ref().is_some_and(|peer| {
                    let peer = peer.strip_suffix(b"/").unwrap_or(peer);
                    under(dir, peer)
                })
            });
    }
    // An `x` header passes with the entry it describes (the next non-`x`
    // member); consecutive headers merge onto the same entry.
    for index in 0..members.len() {
        if members[index].1 != b'x' {
            continue;
        }
        keep[index] = members
            .iter()
            .enumerate()
            .skip(index + 1)
            .find(|(_, (_, flag))| *flag != b'x')
            .is_some_and(|(next, _)| keep[next]);
    }
    // Pax headers buffer in memory until their entry arrives, so a
    // synthesized header for an unsplittable rename emits the same way.
    let mut out = Vec::with_capacity(tar.len() + 512);
    let mut pending: Option<TarMember> = None;
    for (index, (mut member, flag)) in members.into_iter().enumerate() {
        match flag {
            // Pax headers buffer in memory until their entry arrives, so
            // a synthesized header for an unsplittable rename emits the
            // same way; consecutive headers merge onto the same entry.
            b'x' => {
                if keep[index] {
                    buffer_pax(&mut pending, member);
                }
            }
            // The global header is not a member: it passes through
            // verbatim, never renamed or filtered.
            b'g' => emit_member(&mut out, &member),
            _ => {
                if !keep[index] {
                    pending = None;
                    continue;
                }
                if let Some(synth) = match prefix {
                    Some(prefix) => rename_member(&mut member, &mut pending, prefix),
                    None => None,
                } {
                    emit_member(&mut out, &synth);
                }
                if let Some(header) = pending.take() {
                    emit_member(&mut out, &header);
                }
                emit_member(&mut out, &member);
            }
        }
    }
    out.extend_from_slice(&[0u8; 1024]);
    Ok(out)
}

/// Buffers one `x` header onto the pending entry: consecutive headers
/// merge, and the size and checksum track the grown data.
fn buffer_pax(pending: &mut Option<TarMember>, member: TarMember) {
    match pending.as_mut() {
        Some(first) => {
            first.data.extend_from_slice(&member.data);
            octal_into(&mut first.header[124..136], first.data.len() as u64);
            checksum_header(&mut first.header);
        }
        None => *pending = Some(member),
    }
}

/// Appends one member with its padding.
fn emit_member(out: &mut Vec<u8>, member: &TarMember) {
    out.extend_from_slice(&member.header);
    out.extend_from_slice(&member.data);
    let pad = member.data.len().div_ceil(512) * 512 - member.data.len();
    out.extend_from_slice(&vec![0u8; pad]);
}

/// Prepends `prefix` to a member's name and returns a synthesized pax
/// header when the longer name no longer splits across the ustar fields.
/// A buffered header describing the member gains (or rewrites) its `path`
/// record and the visible header keeps a truncated placeholder the record
/// overrides per POSIX; without one the header fields move when the name
/// splits, else the synthesized header carries it.
fn rename_member(
    member: &mut TarMember,
    pending: &mut Option<TarMember>,
    prefix: &[u8],
) -> Option<TarMember> {
    let logical = pending
        .as_ref()
        .and_then(|describer| pax_path_record(&describer.data))
        .unwrap_or_else(|| header_name(&member.header));
    let trailing_slash = logical.ends_with(b"/");
    let stem = logical.strip_suffix(b"/").unwrap_or(&logical);
    let mut renamed = prefix.to_vec();
    renamed.extend_from_slice(stem);
    if trailing_slash {
        renamed.push(b'/');
    }
    if let Some(describer) = pending {
        describer.data = set_pax_path(&describer.data, &renamed);
        octal_into(&mut describer.header[124..136], describer.data.len() as u64);
        checksum_header(&mut describer.header);
        truncate_header(&mut member.header, &renamed);
        checksum_header(&mut member.header);
        return None;
    }
    if let Some((name_prefix, name)) = split_tar_name(&renamed) {
        write_split_name(&mut member.header, name_prefix, name);
        checksum_header(&mut member.header);
        return None;
    }
    let record = ext_record_bytes("path", &renamed);
    truncate_header(&mut member.header, &renamed);
    checksum_header(&mut member.header);
    Some(TarMember {
        header: pax_header_bytes(&record),
        data: record,
    })
}

/// Writes ustar name/prefix fields, zeroing the previous contents first.
fn write_split_name(header: &mut [u8; 512], name_prefix: &[u8], name: &[u8]) {
    header[..100].fill(0);
    header[345..500].fill(0);
    header[..name.len()].copy_from_slice(name);
    header[345..345 + name_prefix.len()].copy_from_slice(name_prefix);
}

/// Truncates a header's visible name to what fits; a pax `path` record
/// beside it stays authoritative per POSIX.
fn truncate_header(header: &mut [u8; 512], renamed: &[u8]) {
    header[..100].fill(0);
    header[345..500].fill(0);
    let shown = &renamed[..renamed.len().min(100)];
    header[..shown.len()].copy_from_slice(shown);
}

/// Builds one `%u %s=%s\n` pax record with its self-counting length: the
/// width iterates to its fixed point (at most two rounds, since the width
/// only grows into wider digit counts).
fn ext_record_bytes(keyword: &str, value: &[u8]) -> Vec<u8> {
    // Paths are raw bytes, never coerced through UTF-8: the width counts
    // the digits of the total, iterating to its fixed point (two rounds:
    // the width only grows into wider digit counts).
    let mut width = value.len() + keyword.len() + 4;
    loop {
        let digits = width.ilog10() as usize + 1;
        let total = digits + 1 + keyword.len() + 1 + value.len() + 1;
        if total == width {
            break;
        }
        width = total;
    }
    let mut out = format!("{width} {keyword}=").into_bytes();
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

/// Builds a 512-byte `x` pax header for `record` bytes of data.
fn pax_header_bytes(record: &[u8]) -> [u8; 512] {
    let mut header = [0u8; 512];
    let name = b"paxheader";
    header[..name.len()].copy_from_slice(name);
    octal_into(&mut header[100..108], 0o100666);
    octal_into(&mut header[124..136], record.len() as u64);
    header[156] = b'x';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[265..269].copy_from_slice(b"root");
    header[297..301].copy_from_slice(b"root");
    checksum_header(&mut header);
    header
}

/// Writes a zero-padded octal field with its NUL terminator, mirroring
/// the server half.
fn octal_into(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    let bytes = text.as_bytes();
    let n = bytes.len().min(digits);
    field[..n].copy_from_slice(&bytes[..n]);
}

/// One tar member staged for zip output: the logical path (the pax `path`
/// record when one describes the member, else the ustar fields), its kind,
/// the archived mode and mtime, and the payload (file bytes, or the link
/// target for symlinks).
struct ZipEntry {
    name: Vec<u8>,
    dir: bool,
    symlink: bool,
    mode: u32,
    mtime: u64,
    data: Vec<u8>,
}

/// Reads the link target out of a symlink member's ustar linkname field.
fn header_linkname(header: &[u8; 512]) -> Vec<u8> {
    let end = header[157..257]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(100);
    header[157..157 + end].to_vec()
}

/// Splits a rewrapped tar into zip entries: the `g` global header carries
/// no member, `x` pax headers only rename the entry they describe, `5`
/// members become directories, `2` members symlinks (target from the
/// linkname field), and `0` members files. Anything else is corrupt: the
/// only producer is the `upload-archive` serve half, which emits exactly
/// these kinds.
fn parse_zip_entries(tar: &[u8]) -> Result<Vec<ZipEntry>, GitError> {
    let corrupt = |detail: String| GitError::Corrupt { detail };
    let mut entries = Vec::new();
    let mut held_path: Option<Vec<u8>> = None;
    let mut pos = 0;
    while pos + 512 <= tar.len() {
        let mut header = [0u8; 512];
        header.copy_from_slice(&tar[pos..pos + 512]);
        pos += 512;
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        if header[257..263] != *b"ustar\0" {
            return Err(corrupt("archive member is not a ustar header".to_owned()));
        }
        let size = usize::try_from(parse_octal(&header[124..136], "size")?)
            .map_err(|_| corrupt("archive member size overflows".to_owned()))?;
        let padded = size.div_ceil(512) * 512;
        if pos + padded > tar.len() {
            return Err(corrupt("archive member runs past the stream".to_owned()));
        }
        let data = tar[pos..pos + size].to_vec();
        pos += padded;
        match header[156] {
            b'x' => {
                if let Some(path) = pax_path_record(&data) {
                    held_path = Some(path);
                }
            }
            b'g' => {}
            flag @ (b'0' | b'5' | b'2') => {
                let name = held_path.take().unwrap_or_else(|| header_name(&header));
                let mode = u32::try_from(parse_octal(&header[100..108], "mode")?)
                    .map_err(|_| corrupt("archive member mode overflows".to_owned()))?;
                let mtime = parse_octal(&header[136..148], "mtime")?;
                let (dir, symlink, data) = match flag {
                    b'5' => (true, false, Vec::new()),
                    b'2' => (false, true, header_linkname(&header)),
                    _ => (false, false, data),
                };
                entries.push(ZipEntry {
                    name,
                    dir,
                    symlink,
                    mode,
                    mtime,
                    data,
                });
            }
            other => {
                return Err(corrupt(format!("archive member has unknown type {other}")));
            }
        }
    }
    Ok(entries)
}

/// Maps a zip writer failure onto the interpreter: I/O stays I/O, every
/// other refusal (bad names, duplicate entries, a finished stream) is a
/// corrupt archive, never a silent truncation.
fn zip_failed(err: zip::result::ZipError) -> GitError {
    match err {
        zip::result::ZipError::Io(io) => GitError::Io {
            detail: format!("cannot write the zip archive: {io}"),
        },
        other => GitError::Corrupt {
            detail: format!("cannot write the zip archive: {other}"),
        },
    }
}

/// Converts a tar mtime into zip's DOS timestamp: out-of-range stamps
/// (before 1980 or past 2107) fall back to the zip epoch instead of
/// failing the archive.
fn zip_mtime(stamp: u64) -> zip::DateTime {
    const DAY: u64 = 86400;
    let (days, clock) = (stamp / DAY, stamp % DAY);
    // Days to civil date on the proleptic Gregorian calendar; the shifted
    // era keeps every division exact for all representable stamps.
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    // Saturating conversions: any component outside the DOS range fails
    // `from_date_and_time` below and lands on the zip epoch, exactly like
    // a pre-1980 stamp.
    let year = u16::try_from(year).unwrap_or(u16::MAX);
    let month = u8::try_from(month).unwrap_or(u8::MAX);
    let day = u8::try_from(day).unwrap_or(u8::MAX);
    let hour = u8::try_from(clock / 3600).unwrap_or(u8::MAX);
    let minute = u8::try_from((clock % 3600) / 60).unwrap_or(u8::MAX);
    let second = u8::try_from(clock % 60).unwrap_or(u8::MAX);
    zip::DateTime::from_date_and_time(year, month, day, hour, minute, second).unwrap_or_default()
}

/// Transcodes a rewrapped tar into a zip archive: non-empty files deflate,
/// empty files store, directories and symlinks go through the writer's own
/// constructors, and modes and mtimes carry over. Names must be UTF-8 (the
/// writer stores them as text), so a non-UTF-8 tree name refuses here
/// rather than landing mojibake in the archive.
fn tar_to_zip(tar: &[u8]) -> Result<Vec<u8>, GitError> {
    use std::io::Write as _;

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for entry in parse_zip_entries(tar)? {
        let name = String::from_utf8(entry.name).map_err(|_| GitError::Corrupt {
            detail: "archive member name is not UTF-8; zip stores names as text".to_owned(),
        })?;
        let mtime = zip_mtime(entry.mtime);
        if entry.dir {
            zip.add_directory(
                name,
                zip::write::SimpleFileOptions::default()
                    .unix_permissions(entry.mode)
                    .last_modified_time(mtime),
            )
            .map_err(zip_failed)?;
        } else if entry.symlink {
            let target = String::from_utf8(entry.data).map_err(|_| GitError::Corrupt {
                detail: "symlink target is not UTF-8; zip stores it as text".to_owned(),
            })?;
            zip.add_symlink(
                name,
                target,
                zip::write::SimpleFileOptions::default()
                    .unix_permissions(entry.mode)
                    .last_modified_time(mtime),
            )
            .map_err(zip_failed)?;
        } else {
            let method = if entry.data.is_empty() {
                zip::CompressionMethod::Stored
            } else {
                zip::CompressionMethod::Deflated
            };
            zip.start_file(
                name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(method)
                    .unix_permissions(entry.mode)
                    .last_modified_time(mtime),
            )
            .map_err(zip_failed)?;
            zip.write_all(&entry.data).map_err(|err| GitError::Io {
                detail: format!("cannot write the zip archive: {err}"),
            })?;
        }
    }
    Ok(zip.finish().map_err(zip_failed)?.into_inner())
}

/// Archives one revision of a local store through the `upload-archive`
/// serve half over a loopback: the request framing is the shared
/// `archive_request_body` grammar, and the reply demuxes exactly like the
/// smart-http client tail (ACK, flush, sideband tar).
fn archive_local(store: &Store, kind: HashKind, rev: &str) -> Result<Vec<u8>, GitError> {
    use std::io::Read as _;

    let input = ruk_git::transport::smart_http::archive_request_body(rev)?;
    let head = serve_head(store)?;
    let mut framed = Vec::new();
    serve_upload_archive(
        std::io::Cursor::new(input),
        &mut framed,
        store,
        kind,
        &head,
        &Interrupt::none(),
    )?;
    let mut pkt = ruk_git::transport::pktline::PktReader::new(
        std::io::Cursor::new(framed),
        Interrupt::none(),
    );
    let first = pkt.read_line("the archive acknowledgement")?.to_vec();
    if first != b"ACK" {
        return Err(GitError::Corrupt {
            detail: format!("upload-archive answered {}", first.escape_ascii()),
        });
    }
    match pkt.read_packet()? {
        ruk_git::transport::pktline::Packet::Flush => {}
        other => {
            return Err(GitError::Corrupt {
                detail: format!("upload-archive misses its flush, got {other:?}"),
            });
        }
    }
    let mut sideband = ruk_git::transport::pktline::SidebandReader::new(
        &mut pkt,
        ruk_git::transport::pktline::LARGE_PACKET_MAX,
    );
    let mut tar = Vec::new();
    sideband.read_to_end(&mut tar).map_err(|err| GitError::Io {
        detail: format!("cannot read the archive stream: {err}"),
    })?;
    Ok(tar)
}

/// Collects garbage: prunes objects no live root reaches, then compacts
/// segments to fold the survivors and reclaim the dead bytes.
///
/// Live means the ref closure (every ref tip peeled through tags, walked
/// through history, closed over trees — the same walk [`fsck`] reports
/// from) plus everything the workspace pins beyond refs: a detached
/// `HEAD` oid, index entry blobs, stash commits with their captured index
/// rows, `FETCH_HEAD` tips, in-progress sequencer tips, and every oid
/// named by a reflog record. Census objects outside that set lose their
/// locator rows in one [`Store::prune_unreachable`] transaction (delta
/// bases of kept objects close over inside the store); a
/// [`Store::compact`] pass then merges the sealed survivors and unlinks
/// retired files whose readers drained.
///
/// Flags mirror the oracle (`git/builtin/gc.c`): `--aggressive` repeats
/// compaction until a pass does no work, `--auto` exits quietly when
/// neither unreachable objects nor a compaction backlog exist, `--dry-run`
/// reports without mutating, `--quiet` mutes the report, and `--prune`
/// (bare, like the oracle) or `--prune=now` (the default) prunes while
/// `--prune=never` compacts only. Any other `--prune=<date>` is
/// `Unsupported`: the store keeps no object ages to horizon against, so
/// there is no grace period — an unreachable object prunes immediately.
///
/// Oracle: `git/builtin/gc.c`.
pub(crate) fn gc(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let normalized: Vec<String> = args
        .iter()
        .map(|arg| {
            if arg == "--prune" {
                "--prune=now".to_owned()
            } else {
                arg.clone()
            }
        })
        .collect();
    let specs = [
        FlagSpec {
            long: "aggressive",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "auto",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "dry-run",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "prune",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "quiet",
            short: Some('q'),
            takes_value: false,
        },
    ];
    let opts = collect(&normalized, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: gc [--aggressive] [--auto] [--dry-run] [--prune=now|never] [--quiet]"
                .to_owned(),
        });
    }
    let prune = match opts.single("prune")?.as_deref() {
        None | Some("now") => true,
        Some("never") => false,
        Some(other) => {
            return Err(GitError::Unsupported {
                command: format!(
                    "gc: --prune={other} needs object ages this store does not track (use --prune=now or --prune=never)"
                ),
            });
        }
    };
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let census = store.iter_objects().map_err(GitError::from)?.len();
    let reachable = gc_reachable(store, kind)?;
    let doomed = store.unreachable_oids(&reachable).map_err(GitError::from)?;
    let backlog = store.compaction_backlog().map_err(GitError::from)?;
    if opts.is_set("auto") && doomed.is_empty() && !backlog.has_work() {
        return Ok(Vec::new());
    }
    let quiet = opts.is_set("quiet");
    let mut out = format!("Enumerating objects: {census}, done.\n").into_bytes();
    if opts.is_set("dry-run") {
        if !prune {
            out.extend_from_slice(b"Prune disabled (--prune=never).\n");
        } else if doomed.is_empty() {
            out.extend_from_slice(b"Nothing to prune.\n");
        } else {
            out.extend_from_slice(
                format!("Would prune {} unreachable objects.\n", doomed.len()).as_bytes(),
            );
        }
        if backlog.has_work() {
            out.extend_from_slice(
                format!(
                    "Would compact {} segments ({} retired files pending reclaim).\n",
                    backlog.mergeable, backlog.reclaimable
                )
                .as_bytes(),
            );
        } else {
            out.extend_from_slice(b"Nothing to compact.\n");
        }
        return Ok(if quiet { Vec::new() } else { out });
    }
    if prune {
        let stats = store
            .prune_unreachable(&reachable)
            .map_err(GitError::from)?;
        debug_assert_eq!(stats.objects_pruned, doomed.len());
        if stats.did_work() {
            out.extend_from_slice(
                format!("Unreachable objects: {} pruned.\n", stats.objects_pruned).as_bytes(),
            );
        } else {
            out.extend_from_slice(b"Nothing to prune.\n");
        }
    }
    let mut copied = 0usize;
    let mut bytes_copied = 0u64;
    let mut created = 0usize;
    let mut retired = 0usize;
    let mut unlinked = 0usize;
    let mut bytes_freed = 0u64;
    loop {
        let stats = store.compact().map_err(GitError::from)?;
        let worked = stats.did_work();
        copied += stats.objects_copied;
        bytes_copied += stats.bytes_copied;
        created += stats.segments_created;
        retired += stats.segments_retired;
        unlinked += stats.segments_unlinked;
        bytes_freed += stats.bytes_freed;
        if !opts.is_set("aggressive") || !worked {
            break;
        }
    }
    if retired > 0 || unlinked > 0 {
        out.extend_from_slice(
            format!(
                "Compacted {retired} segments into {created} ({copied} objects, {bytes_copied} bytes copied, {bytes_freed} bytes freed).\n"
            )
            .as_bytes(),
        );
    } else {
        out.extend_from_slice(b"Nothing to compact.\n");
    }
    Ok(if quiet { Vec::new() } else { out })
}

/// Every object id a collection must keep: the ref closure plus workspace
/// pins beyond refs.
///
/// Ref tips (plus a detached `HEAD`) peel through tags and walk history
/// exactly like [`fsck`]; failures there propagate, since a broken ref
/// walk is corruption either verb must report. Pins — index blobs, stash
/// commits and their captured rows, `FETCH_HEAD` tips, sequencer tips, and
/// reflog oids — keep their own oid unconditionally; an absent pin walks
/// nothing further, while any other pin failure propagates, since the
/// reachable set decides deletions and a half walk must not prune blind.
fn gc_reachable(store: &Store, kind: HashKind) -> Result<HashSet<Oid>, GitError> {
    let mut reachable = HashSet::new();
    let mut commits = Vec::new();
    let mut tips = Vec::new();
    for (_, target) in super::state::list_refs(store)? {
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
    let (workspace, _) = super::state::load_or_default(store)?;
    if let ruk_core::workspace::HeadRef::Detached(oid) = workspace.head {
        tips.push(oid);
    }
    for tip in tips {
        let (visited, commit) = peel_tip_chain(store, kind, tip)?;
        reachable.extend(visited.iter().copied());
        match commit {
            Some(commit) => commits.push(commit),
            None => {
                if let Some(&terminal) = visited.last()
                    && super::tree::read_object_bytes(store, terminal)?.0 == ObjectKind::Tree
                {
                    mark_tree(store, kind, terminal, &mut reachable)?;
                }
            }
        }
    }
    for (oid, record) in super::state::walk_history(store, &commits, None)? {
        let tree = super::tree::commit_tree_oid(&record)?;
        reachable.insert(oid);
        mark_tree(store, kind, tree, &mut reachable)?;
    }
    let mut pin_tips = Vec::new();
    for (_, _, entry) in super::state::scan_index(store, kind)? {
        reachable.insert(entry.oid());
    }
    let high_water = super::state::stash_high_water(store)?;
    for slot in 0..high_water {
        if let Some(slot_entry) = super::state::stash_read(store, slot)? {
            if let Ok(oid) = ruk_git::parse_oid_for(&slot_entry.commit_hex, kind) {
                pin_tips.push(oid);
            }
            for (_, _, index_entry) in &slot_entry.rows {
                reachable.insert(index_entry.oid());
            }
        }
    }
    if let Some(raw) = store
        .fact(FactTable::Pins, b"cli/pseudo/FETCH_HEAD")
        .map_err(GitError::from)?
    {
        for line in raw.split(|byte| *byte == b'\n') {
            let field = line
                .split(|byte| *byte == b'\t' || *byte == b' ')
                .next()
                .unwrap_or_default();
            if field.is_empty() {
                continue;
            }
            if let Ok(text) = std::str::from_utf8(field)
                && let Ok(oid) = ruk_git::parse_oid_for(text, kind)
            {
                pin_tips.push(oid);
            }
        }
    }
    for verb in ["merge", "rebase", "cherry-pick", "revert"] {
        if let Some(state) = super::state::sequencer_read(store, verb)? {
            for hex in [&state.head_hex, &state.target_hex] {
                if let Ok(oid) = ruk_git::parse_oid_for(hex, kind) {
                    pin_tips.push(oid);
                }
            }
        }
    }
    pin_tips.extend(all_reflog_oids(store).map_err(GitError::from)?);
    // One absent pin cannot abort the rest; any other failure aborts the
    // collection, since an incomplete reachable set would delete blind.
    for tip in pin_tips {
        reachable.insert(tip);
        gc_walk_pin_tip(store, kind, &mut reachable, tip)?;
    }
    Ok(reachable)
}

/// Walks one pin tip into `reachable`: tags peel, commits walk history,
/// trees walk their subtree. Only an absent tip is tolerated (its own oid
/// is already pinned above; there is no history to walk). Every other
/// failure propagates: the reachable set decides deletions, so a half
/// walk must abort collection rather than prune blind.
fn gc_walk_pin_tip(
    store: &Store,
    kind: HashKind,
    reachable: &mut HashSet<Oid>,
    tip: Oid,
) -> Result<(), GitError> {
    let (visited, commit) = match peel_tip_chain(store, kind, tip) {
        Err(GitError::NotFound { .. }) => return Ok(()),
        other => other?,
    };
    reachable.extend(visited.iter().copied());
    let Some(commit) = commit else {
        if let Some(&terminal) = visited.last()
            && super::tree::read_object_bytes(store, terminal)?.0 == ObjectKind::Tree
        {
            mark_tree(store, kind, terminal, reachable)?;
        }
        return Ok(());
    };
    for (oid, record) in super::state::walk_history(store, &[commit], None)? {
        reachable.insert(oid);
        mark_tree(
            store,
            kind,
            super::tree::commit_tree_oid(&record)?,
            reachable,
        )?;
    }
    Ok(())
}

/// Verifies reachable objects: every commit's tree must exist with every
/// blob it names, and every index row must name a stored object. With
/// `--dangling` or `--unreachable` the verb also lists census objects no
/// ref reaches as `dangling <kind> <oid>` rows, the way the oracle lists
/// unreachable objects. Both spellings report the same set: the store
/// keeps no pack/loose split to tell dangling from unreachable. Index-only
/// blobs count as unreachable (reachability closes over refs alone).
///
/// Oracle: `git/builtin/fsck.c`.
pub(crate) fn fsck(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "full",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "dangling",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "unreachable",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "fsck takes no paths".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let _ = opts.is_set("full");
    let want_dangling = opts.is_set("dangling") || opts.is_set("unreachable");
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
    // Peel tag tips to the commits the history walk accepts; every
    // traversed oid joins the reachable set, so tag objects never report
    // dangling. A ref aimed past commits (a tree, a blob) contributes
    // itself, with trees walking their subtrees.
    let mut reachable = HashSet::new();
    let mut commits = Vec::new();
    for tip in tips {
        let (visited, commit) = peel_tip_chain(store, kind, tip)?;
        reachable.extend(visited.iter().copied());
        match commit {
            Some(commit) => commits.push(commit),
            // A ref aimed past commits resolves to the chain's terminal
            // oid (a tree through a tag, a blob, a tree itself): the
            // terminal is reachable, and a terminal tree walks its subtree.
            None => {
                if let Some(&terminal) = visited.last() {
                    if super::tree::read_object_bytes(store, terminal)?.0 == ObjectKind::Tree {
                        mark_tree(store, kind, terminal, &mut reachable)?;
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    for (oid, record) in walk_history(store, &commits, None)? {
        let tree = super::tree::commit_tree_oid(&record)?;
        check_tree(store, kind, tree, &mut out)?;
        if want_dangling {
            reachable.insert(oid);
            mark_tree(store, kind, tree, &mut reachable)?;
        }
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
    // Unreachable objects: the census minus the ref closure, in census
    // (digest) order, one `dangling <kind> <oid>` row each like the oracle.
    if want_dangling {
        for (oid, object_kind, _) in store.iter_objects().map_err(GitError::from)? {
            if !reachable.contains(&oid) {
                out.extend_from_slice(
                    format!(
                        "dangling {} {}\n",
                        super::verbs_objects::kind_name_of(object_kind),
                        oid.to_hex()
                    )
                    .as_bytes(),
                );
            }
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
/// With `--upload` the direction flips: the verb POSTs one batch upload
/// request listing every reachable payload already verified in the
/// sidecar, then streams each answered `actions.upload.href` straight
/// from the sidecar file (objects the remote already holds answer no
/// actions and need nothing). Pointers
/// with no local payload cannot be offered and land in `missing`.
/// Successful PUTs land in `uploaded`; `--from` is refused alongside
/// `--upload`.
///
/// Stdout is JSON
/// `{"synced": [...], "missing": [{"oid","error"}], "uploaded": [...]}`
/// with all lists sorted by oid (`uploaded` stays empty on the download
/// half; `synced` on the upload half holds only presence-row repairs);
/// exit is 0 even when `missing` is non-empty (absence is reported, never
/// fatal, matching push admission under `Full`). Only a refused batch
/// document itself fails the verb.
pub(crate) fn lfs_payload_sync(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    use ruk_core::store::lfs as sidecar;

    let specs = [
        FlagSpec {
            long: "from",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "upload",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: lfs_payload_sync [--from <dir>] [--upload]".to_owned(),
        });
    }
    let upload = opts.is_set("upload");
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
    if upload && from.is_some() {
        return Err(GitError::Invalid {
            detail: "--upload reads payloads from the sidecar, not --from".to_owned(),
        });
    }
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
    let mut uploaded: Vec<String> = Vec::new();
    let mut mutations = Vec::new();
    // Pointers already verified are no-ops (row repair included); the
    // rest need bytes from exactly one source below. `pointers` is a
    // BTreeMap, so both report lists stay sorted by oid.
    let mut pending: Vec<(String, u64)> = Vec::new();
    // Reachable payloads already verified locally: the download half
    // ignores them; `--upload` offers them to the remote.
    let mut present: Vec<(String, u64)> = Vec::new();
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
            present.push((hex.clone(), *size));
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
                    Some(path) => match sidecar::stage_verified(store.root(), hex, *size, &path) {
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
                    },
                }
            }
        }
        None if !upload => sync_via_batch(
            ctx,
            store,
            &pending,
            &mut synced,
            &mut missing,
            &mut mutations,
        )?,
        // `--upload` reads the sidecar, never `--from` (refused above):
        // offer every locally verified payload to the remote, reporting
        // pointers with no local bytes as missing.
        None => {
            for (hex, _) in &pending {
                missing.push((hex.clone(), "no local payload to upload".to_owned()));
            }
            sync_via_batch_upload(ctx, store, &present, &mut uploaded, &mut missing)?;
        }
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
    out.push_str("], \"uploaded\": [");
    for (index, hex) in uploaded.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("\"{hex}\""));
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
    sync_via_batch_at(ctx, store, &endpoint, pending, synced, missing, mutations)
}

/// Downloads `pending` payloads through the git-lfs batch API at an
/// explicit endpoint: the transfer half of [`sync_via_batch`], shared with
/// the mirror path, which resolves its own remote-specific endpoint.
///
/// # Errors
/// [`GitError::Invalid`] for a malformed endpoint or batch request,
/// [`GitError::Offline`] when the batch endpoint refuses, plus transport
/// failures from the HTTP client.
fn sync_via_batch_at(
    ctx: &Ctx,
    store: &Store,
    endpoint: &str,
    pending: &[(String, u64)],
    synced: &mut Vec<String>,
    missing: &mut Vec<(String, String)>,
    mutations: &mut Vec<FactMutation>,
) -> Result<(), GitError> {
    use ruk_core::store::lfs as sidecar;
    use ruk_git::transport::http::{self, BatchEntry};

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
        let preview: String = String::from_utf8_lossy(&reply.body)
            .chars()
            .take(200)
            .collect();
        return Err(GitError::Offline {
            detail: format!(
                "lfs batch {batch_url} refused status {}: {preview:?}",
                reply.status
            ),
        });
    }
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
            None => missing.push((hex.clone(), "batch response omits this object".to_owned())),
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
                    && http::same_origin(&batch_url, href).unwrap_or(false)
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

/// Pulls LFS payloads for one fetch's newly-arrived tips: the `fetch --lfs`
/// half of pull-mirror sync. Walks the fetched tips (not every ref) for
/// pointer blobs, then batch-downloads the payloads the sidecar still lacks
/// into `<store>/lfs/objects/` with presence rows, the same transfer the
/// download half of [`lfs_payload_sync`] runs.
///
/// Best-effort by design: a non-`Full` policy or no batch endpoint
/// (`lfs.url`, then `remote.<name>.lfsurl`, then `<fetch-url>/info/lfs` for
/// http(s) remotes) skips silently, and per-object misses go to stderr
/// without failing the fetch that already moved its refs. Only a refused
/// batch document itself fails.
///
/// # Errors
/// [`GitError::Invalid`] for a malformed endpoint or batch request,
/// [`GitError::Offline`] when the batch endpoint refuses, plus transport
/// failures from the HTTP client.
fn mirror_lfs_sync(ctx: &mut Ctx, remote_label: &str, tips: &[Oid]) -> Result<(), GitError> {
    use ruk_core::store::lfs as sidecar;

    let store = ctx.store()?;
    if mode_for_store(store.root()) != LfsMode::Full {
        return Ok(());
    }
    let kind = ctx.kind()?;
    // Fetched tips include annotated tag objects under `--tags`, which the
    // commit walk rejects: peel tags to their commit targets first.
    // Non-commit tips (a tag to a tree, etc.) carry no history to scan.
    let mut commits = Vec::with_capacity(tips.len());
    for tip in tips {
        if let Some(commit) = peel_to_commit_tip(store, kind, *tip)? {
            commits.push(commit);
        }
    }
    if commits.is_empty() {
        return Ok(());
    }
    // Pointers in the newly-arrived range, keyed by payload hex: the same
    // small-blob walk the payload-sync verb runs, scoped to the fetched
    // tips. Unreadable blobs are fsck's domain; the sync skips them.
    let mut pointers: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for (_, record) in super::state::walk_history(store, &commits, None)? {
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
    let pending: Vec<(String, u64)> = pointers
        .into_iter()
        .filter(|(hex, size)| !sidecar::sidecar_verified(store.root(), hex, *size))
        .collect();
    if pending.is_empty() {
        return Ok(());
    }
    let Some(endpoint) = lfs_endpoint_for_remote(ctx, remote_label) else {
        return Ok(());
    };
    let mut synced = Vec::new();
    let mut missing: Vec<(String, String)> = Vec::new();
    let mut mutations = Vec::new();
    sync_via_batch_at(
        ctx,
        store,
        &endpoint,
        &pending,
        &mut synced,
        &mut missing,
        &mut mutations,
    )?;
    if !mutations.is_empty() {
        store
            .publish(Vec::new(), &mutations)
            .map_err(GitError::from)?;
    }
    for (hex, error) in &missing {
        ctx.emit_stderr(format!("lfs: {hex} missing ({error})\n").as_bytes());
    }
    Ok(())
}

/// Uploads LFS payloads for one push's outgoing range: the `push --lfs`
/// half of push-mirror sync. Scans the same wants-minus-haves closure the
/// pack carries for pointer blobs, then batch-uploads the payloads the
/// sidecar already verifies to the push remote's batch endpoint (the same
/// transfer the upload half of [`lfs_payload_sync`] runs).
///
/// Best-effort by design: a non-`Full` policy, no batch endpoint
/// (`lfs.url`, then `remote.<name>.lfsurl`, then `<fetch-url>/info/lfs` for
/// http(s) remotes), or no outgoing pointers skip silently, and
/// per-object misses go to stderr without failing the push that follows.
/// Only a refused batch document itself fails.
///
/// # Errors
/// [`GitError::Invalid`] for a malformed batch request,
/// [`GitError::Offline`] when the batch endpoint refuses, plus transport
/// failures from the HTTP client and closure reads.
fn push_lfs_upload(
    ctx: &mut Ctx,
    updates: &[PushUpdate],
    remote_label: &str,
) -> Result<(), GitError> {
    use ruk_core::store::lfs as sidecar;

    // The outgoing range's pointers, keyed by payload hex: the closure
    // entries carry canonical bytes, so pointer parsing needs no second
    // object read. Deletes carry nothing; an all-delete push uploads
    // nothing.
    let (present, pending): (Vec<(String, u64)>, Vec<(String, u64)>) = {
        let store = ctx.store()?;
        if mode_for_store(store.root()) != LfsMode::Full {
            return Ok(());
        }
        let kind = ctx.kind()?;
        let zero = kind.zero_oid();
        let live: Vec<&PushUpdate> = updates.iter().filter(|update| update.new != zero).collect();
        if live.is_empty() {
            return Ok(());
        }
        let closure =
            ruk_git::transport::push::push_closure(store, kind, &live, &Interrupt::none())?;
        let mut pointers: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();
        for entry in &closure {
            if entry.kind != ObjectKind::Blob {
                continue;
            }
            if let Some((hex, size)) = ruk_core::parse_pointer(&entry.bytes) {
                pointers.entry(hex).or_insert(size);
            }
        }
        let mut present = Vec::new();
        let mut pending = Vec::new();
        for (hex, size) in pointers {
            if sidecar::sidecar_verified(store.root(), &hex, size) {
                present.push((hex, size));
            } else {
                pending.push((hex, size));
            }
        }
        (present, pending)
    };
    if present.is_empty() && pending.is_empty() {
        return Ok(());
    }
    // No batch endpoint means LFS is absent: silent, the way a push
    // without `--lfs` behaves.
    let Some(endpoint) = lfs_endpoint_for_remote(ctx, remote_label) else {
        return Ok(());
    };
    // Pointers with no local payload cannot be offered; the push still
    // moves them as pointers, the way `Full` admits pushes with absent
    // payloads.
    let mut missing: Vec<(String, String)> = pending
        .into_iter()
        .map(|(hex, _)| (hex, "no local payload to upload".to_owned()))
        .collect();
    let mut uploaded = Vec::new();
    {
        let store = ctx.store()?;
        sync_via_batch_upload_at(ctx, store, &endpoint, &present, &mut uploaded, &mut missing)?;
    }
    for (hex, error) in &missing {
        ctx.emit_stderr(format!("lfs: {hex} missing ({error})\n").as_bytes());
    }
    Ok(())
}

/// Peels one tip through annotated tags to the commit the history walk
/// accepts, returning every traversed oid plus the commit (at most 32 hops,
/// the same bound the rev-parse peel uses). Anything that never resolves to
/// a commit still contributes its traversed oids with no commit: the tip
/// itself is reachable (a tree tip still walks its subtree), only history
/// has nothing to add.
///
/// # Errors
/// Read failures and malformed tag payloads propagate; absence and damage
/// are caller-level facts, never per-tip silence.
fn peel_tip_chain(
    store: &Store,
    kind: HashKind,
    tip: Oid,
) -> Result<(Vec<Oid>, Option<Oid>), GitError> {
    let mut visited = vec![tip];
    let mut current = tip;
    for _ in 0..32 {
        let (object_kind, bytes) = super::tree::read_object_bytes(store, current)?;
        match object_kind {
            ObjectKind::Commit => return Ok((visited, Some(current))),
            ObjectKind::Tag => {
                // Tag payloads open with `object <hex>`, the line the
                // branch peel reads; anything else is a malformed tag.
                let first = bytes
                    .split(|byte| *byte == b'\n')
                    .next()
                    .unwrap_or_default();
                let hex = first
                    .strip_prefix(b"object ")
                    .ok_or_else(|| GitError::Corrupt {
                        detail: format!("tag {} has no object header", current.to_hex()),
                    })?;
                let text = std::str::from_utf8(hex).map_err(|_| GitError::Corrupt {
                    detail: format!("tag {} has a non-UTF-8 object header", current.to_hex()),
                })?;
                current = ruk_git::parse_oid_for(text, kind)?;
                visited.push(current);
            }
            _ => return Ok((visited, None)),
        }
    }
    Err(GitError::Corrupt {
        detail: format!("tag chain from {} does not end", tip.to_hex()),
    })
}

/// Peels one fetched tip to the commit the history walk accepts: annotated
/// tags dereference through their `object` lines (at most 32 hops, the
/// same bound the rev-parse peel uses). Anything that never resolves to a
/// commit contributes nothing to pointer discovery and yields `None`.
///
/// # Errors
/// Read failures and malformed tag payloads propagate; absence and damage
/// are fetch-level facts, never per-tip silence.
fn peel_to_commit_tip(store: &Store, kind: HashKind, tip: Oid) -> Result<Option<Oid>, GitError> {
    Ok(peel_tip_chain(store, kind, tip)?.1)
}

/// Marks one tree and its subtree reachable: the tree itself plus every
/// entry oid, recursing into subtrees. Missing trees stay silent (the
/// corruption half already reported them); anything else propagates.
///
/// # Errors
/// Malformed tree bodies and damaged reads propagate; absence is the
/// corruption half's report, never this walk's failure.
fn mark_tree(
    store: &Store,
    kind: HashKind,
    tree: Oid,
    reachable: &mut HashSet<Oid>,
) -> Result<(), GitError> {
    if !reachable.insert(tree) {
        return Ok(());
    }
    let body = match super::tree::read_object_bytes(store, tree) {
        Ok((ObjectKind::Tree, body)) => body,
        Ok(_) => {
            return Err(GitError::Invalid {
                detail: format!("object {} is not a tree", tree.to_hex()),
            });
        }
        Err(GitError::NotFound { .. }) => return Ok(()),
        Err(err) => return Err(err),
    };
    for entry in super::tree::parse_tree(kind, &body)? {
        if entry.mode.is_tree() {
            mark_tree(store, kind, entry.oid, reachable)?;
        } else {
            reachable.insert(entry.oid);
        }
    }
    Ok(())
}

/// The LFS batch endpoint for a fetch remote: `lfs.url` first, then
/// `remote.<name>.lfsurl`, then the git-lfs derivation `<fetch-url>/info/lfs`.
/// `None` means LFS is absent and the caller skips silently. A raw-URL fetch
/// target derives from the URL itself when no configured remote matches.
fn lfs_endpoint_for_remote(ctx: &Ctx, remote_label: &str) -> Option<String> {
    if let Some(url) = ctx.config_get("lfs.url") {
        return Some(url);
    }
    if let Some(url) = ctx.config_get(&format!("remote.{remote_label}.lfsurl")) {
        return Some(url);
    }
    match ctx.config_get(&format!("remote.{remote_label}.url")) {
        Some(url) => derive_lfs_endpoint(&url),
        None => derive_lfs_endpoint(remote_label),
    }
}

/// Derives the git-lfs batch endpoint from a remote URL the way git-lfs
/// does: an http(s) remote serves `<url>/info/lfs`. Local paths, SSH, and
/// git-daemon remotes carry no batch endpoint.
fn derive_lfs_endpoint(fetch_url: &str) -> Option<String> {
    let lower = fetch_url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Some(format!("{}/info/lfs", fetch_url.trim_end_matches('/')))
    } else {
        None
    }
}

/// Uploads `present` payloads through the git-lfs batch API at the
/// configured endpoint (`lfs.url`, falling back to
/// `remote.origin.lfsurl`): one `objects/batch` POST for the upload
/// operation, then one payload PUT per answered `actions.upload.href`.
/// Entries without actions are already at the remote and need nothing;
/// server error entries, omitted objects, and failed PUTs land in
/// `missing` with detail; only a refused batch document itself fails the
/// verb. No fact rows change: the sidecar already holds these payloads.
///
/// # Errors
/// [`GitError::Invalid`] for a malformed endpoint or batch request,
/// [`GitError::Offline`] when the batch endpoint refuses, plus transport
/// failures from the HTTP client.
fn sync_via_batch_upload(
    ctx: &Ctx,
    store: &Store,
    present: &[(String, u64)],
    uploaded: &mut Vec<String>,
    missing: &mut Vec<(String, String)>,
) -> Result<(), GitError> {
    if present.is_empty() {
        return Ok(());
    }
    let Some(endpoint) = ctx
        .config_get("lfs.url")
        .or_else(|| ctx.config_get("remote.origin.lfsurl"))
    else {
        for (hex, _) in present {
            missing.push((
                hex.clone(),
                "no LFS endpoint configured (set lfs.url) and nothing to upload to".to_owned(),
            ));
        }
        return Ok(());
    };
    sync_via_batch_upload_at(ctx, store, &endpoint, present, uploaded, missing)
}

/// Uploads `present` payloads through the git-lfs batch API at an explicit
/// endpoint: the transfer half of [`sync_via_batch_upload`], shared with
/// the push path, which resolves its own remote-specific endpoint.
///
/// # Errors
/// [`GitError::Invalid`] for a malformed batch request,
/// [`GitError::Offline`] when the batch endpoint refuses, plus transport
/// failures from the HTTP client.
fn sync_via_batch_upload_at(
    ctx: &Ctx,
    store: &Store,
    endpoint: &str,
    present: &[(String, u64)],
    uploaded: &mut Vec<String>,
    missing: &mut Vec<(String, String)>,
) -> Result<(), GitError> {
    use ruk_git::transport::http::{self, UploadEntry};

    if present.is_empty() {
        return Ok(());
    }
    let batch_url = format!("{}/objects/batch", endpoint.trim_end_matches('/'));
    let request = http::batch_upload_request_body(present)?;
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
        let preview: String = String::from_utf8_lossy(&reply.body)
            .chars()
            .take(200)
            .collect();
        return Err(GitError::Offline {
            detail: format!(
                "lfs batch {batch_url} refused status {}: {preview:?}",
                reply.status
            ),
        });
    }
    let mut answers: HashMap<String, UploadEntry> = HashMap::new();
    for entry in http::parse_batch_upload_response(&reply.body)? {
        let oid = match &entry {
            UploadEntry::NeedsUpload { oid, .. }
            | UploadEntry::Present { oid }
            | UploadEntry::Failed { oid, .. } => oid.clone(),
        };
        answers.insert(oid, entry);
    }
    for (hex, size) in present {
        match answers.get(hex) {
            None => missing.push((hex.clone(), "batch response omits this object".to_owned())),
            Some(UploadEntry::Failed { detail, .. }) => {
                missing.push((hex.clone(), detail.clone()));
            }
            // Already at the remote: nothing to send, nothing to report.
            Some(UploadEntry::Present { .. }) => {}
            Some(UploadEntry::NeedsUpload {
                href,
                headers: action_headers,
                ..
            }) => {
                let mut put_headers: Vec<(String, String)> = action_headers.clone();
                if put_headers
                    .iter()
                    .all(|(name, _)| name.to_ascii_lowercase() != "content-type")
                {
                    put_headers.push((
                        "Content-Type".to_owned(),
                        "application/octet-stream".to_owned(),
                    ));
                }
                if let Some(auth) = http::auth_header(&ctx.env.vars)
                    && http::same_origin(&batch_url, href).unwrap_or(false)
                {
                    put_headers.push(auth);
                }
                let outcome = upload_one(store, href, &put_headers, hex, *size);
                match outcome {
                    Ok(()) => uploaded.push(hex.clone()),
                    Err(detail) => missing.push((hex.clone(), detail)),
                }
            }
        }
    }
    Ok(())
}

/// Streams one sidecar payload to `href`, returning the human detail for
/// `missing` on any failure so one bad object never fails its siblings.
/// The file is never buffered: bytes move straight from the sidecar into
/// the PUT, the way downloads stream into staging.
fn upload_one(
    store: &Store,
    href: &str,
    headers: &[(String, String)],
    hex: &str,
    size: u64,
) -> Result<(), String> {
    use ruk_core::store::lfs as sidecar;
    use ruk_git::transport::http;

    let Some(path) = sidecar::sidecar_path(store.root(), hex) else {
        return Err(format!("no local payload for {hex}"));
    };
    // Open, never buffer. The lane only offers verified payloads, so a
    // size skew means the sidecar changed under us and fails before any
    // byte moves.
    let mut file =
        std::fs::File::open(&path).map_err(|err| format!("cannot read local payload: {err}"))?;
    let actual = file
        .metadata()
        .map_err(|err| format!("cannot read local payload: {err}"))?
        .len();
    if actual != size {
        return Err(format!(
            "local payload size {actual} differs from pointer size {size}"
        ));
    }
    let borrowed: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let reply = http::put_stream(href, &borrowed, size, &mut file)
        .map_err(|err| format!("PUT {href} failed: {err}"))?;
    if !http::is_success(reply.status) {
        return Err(format!("PUT {href} failed with status {}", reply.status));
    }
    Ok(())
}

/// A writer that aborts once more than `limit` bytes arrive, so an
/// over-long response body fails fast with an I/O error instead of
/// filling the sink.
struct SizeCapWriter<W: std::io::Write> {
    inner: W,
    limit: u64,
    written: u64,
}

impl<W: std::io::Write> SizeCapWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            limit,
            written: 0,
        }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: std::io::Write> std::io::Write for SizeCapWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // `usize as u64` widens (never truncates); the sum saturates.
        if self.written.saturating_add(buf.len() as u64) > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::QuotaExceeded,
                format!(
                    "payload exceeds its declared {} bytes after {}",
                    self.limit, self.written
                ),
            ));
        }
        let wrote = self.inner.write(buf)?;
        self.written = self.written.saturating_add(wrote as u64);
        Ok(wrote)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
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
    let file = std::fs::File::create(tmp).map_err(|err| format!("cannot stage download: {err}"))?;
    // Any byte past the pointer's declared size already fails verification,
    // so abort the stream there: a lying or endless body cannot fill the
    // disk while we wait for the hash check to reject it.
    let mut capped = SizeCapWriter::new(file, size);
    let (status, _) = http::get_to_writer(href, &borrowed, &mut capped)
        .map_err(|err| format!("GET {href} failed: {err}"))?;
    let mut file = capped.into_inner();
    // The staging read opens its own descriptor; flush here so it sees
    // every byte even though the handle drops at return.
    std::io::Write::flush(&mut file).map_err(|err| format!("cannot flush download: {err}"))?;
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
        if mode == super::tree::TreeMode::Gitlink {
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
        Target::Net(endpoint) => {
            // Over v2, ls-remote is ls-refs: one `Git-Protocol` GET
            // parses caps or the v0 refs, with no second round trip. A
            // server answering `info/refs` without the smart advertisement
            // falls back to the dumb text file, the same fallback
            // `run_fetch` makes.
            let refs = match &endpoint {
                Endpoint::Http { url, .. } => {
                    let base = ruk_git::transport::smart_http::normalize_base(url)?;
                    let extra_headers = http_extra_headers(ctx, &base);
                    match ruk_git::transport::smart_http::discover_versioned(
                        &base,
                        ruk_git::transport::smart_http::SmartService::UploadPack,
                        ctx.kind()?,
                        &extra_headers,
                    ) {
                        Ok(ruk_git::transport::smart_http::VersionedDiscovery::V2(caps)) => {
                            ruk_git::transport::smart_http::ls_refs_v2(
                                &base,
                                &caps,
                                ctx.kind()?,
                                &[],
                                &Interrupt::none(),
                                &extra_headers,
                            )?
                        }
                        Ok(ruk_git::transport::smart_http::VersionedDiscovery::V0(adv)) => adv.refs,
                        Err(err) if ruk_git::transport::dumb_http::is_dumb_gap(&err) => {
                            ruk_git::transport::dumb_http::discover(
                                &base,
                                ctx.kind()?,
                                &extra_headers,
                            )?
                            .refs
                        }
                        Err(err) => return Err(err),
                    }
                }
                _ => net::discover_endpoint(&endpoint, Service::UploadPack, ctx.kind()?)?,
            };
            net::to_local_refs(refs)?
        }
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

/// Bare `git credential` helper protocol: `fill` looks one description up
/// through the configured helpers and prints the filled description,
/// `approve` stores it, `reject` erases it.
///
/// Oracle: `git/builtin/credential.c`. The description arrives on stdin as
/// `key=value` lines to the first blank line; helpers run with the
/// `get`/`store`/`erase` operation on their command line, the same runner
/// the transport fill uses. A `fill` no helper answers is an error, the
/// way the oracle's interactive prompt fails with no terminal. Needs no
/// repository.
pub(crate) fn credential(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    const USAGE: &str = "usage: credential <fill|approve|reject>";
    let [op] = args else {
        return Err(GitError::Invalid {
            detail: USAGE.to_owned(),
        });
    };
    if op != "fill" && op != "approve" && op != "reject" {
        return Err(GitError::Invalid {
            detail: USAGE.to_owned(),
        });
    }
    let stdin = super::read_stdin_bytes(&ctx.env)?;
    if stdin.len() > ruk_git::transport::credentials::MAX_CREDENTIAL_INPUT {
        return Err(GitError::Limit {
            detail: "credential description exceeds the input bound".to_owned(),
        });
    }
    let desc = ruk_git::transport::credentials::parse_credential_input(&stdin);
    // Helper config files resolve against the captured environment, never
    // the live process one, so the verb stays hermetic under test.
    match op.as_str() {
        "fill" => {
            let Some(filled) =
                ruk_git::transport::credentials::credential_fill_desc(&desc, &ctx.env.vars)
            else {
                return Err(GitError::Invalid {
                    detail: "credential fill found no username".to_owned(),
                });
            };
            let mut out = Vec::new();
            for (key, value) in &filled {
                out.extend_from_slice(format!("{key}={value}\n").as_bytes());
            }
            Ok(line(out))
        }
        "approve" => {
            ruk_git::transport::credentials::credential_approve_desc(&desc, &ctx.env.vars);
            Ok(Vec::new())
        }
        _ => {
            ruk_git::transport::credentials::credential_reject_desc(&desc, &ctx.env.vars);
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod extra_header_scope_tests {
    use super::*;

    #[test]
    fn splits_unscoped_scoped_and_rejects() {
        assert_eq!(extra_header_scope("http.extraHeader"), Some(None));
        assert_eq!(
            extra_header_scope("http.https://host.x/a.extraHeader"),
            Some(Some("https://host.x/a".to_owned()))
        );
        // Section and key match case-insensitively; the scope keeps case.
        assert_eq!(
            extra_header_scope("HTTP.https://Host.X/A.EXTRAHEADER"),
            Some(Some("https://Host.X/A".to_owned()))
        );
        assert_eq!(extra_header_scope("http.extraheaderx"), None);
        assert_eq!(extra_header_scope("http..extraHeader"), None);
        assert_eq!(extra_header_scope("http.extraHeader.more"), None);
        assert_eq!(extra_header_scope("remote.origin.url"), None);
    }
}

#[cfg(test)]
mod archive_rewrap_tests {
    use super::*;

    fn member_bytes(name: &[u8], typeflag: u8, data: &[u8]) -> Vec<u8> {
        let (prefix, short) = split_tar_name(name).expect("test name splits");
        let mut header = [0u8; 512];
        header[..short.len()].copy_from_slice(short);
        header[345..345 + prefix.len()].copy_from_slice(prefix);
        octal_into(&mut header[100..108], 0o644);
        octal_into(&mut header[124..136], data.len() as u64);
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        checksum_header(&mut header);
        let mut out = header.to_vec();
        out.extend_from_slice(data);
        out.extend_from_slice(&vec![0u8; data.len().div_ceil(512) * 512 - data.len()]);
        out
    }

    /// Builds a member with literal header name bytes, the way the server
    /// shapes unsplittable names (truncated visible name, the `x` record
    /// authoritative).
    fn raw_member(name_field: &[u8], typeflag: u8, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name_field.len()].copy_from_slice(name_field);
        octal_into(&mut header[100..108], 0o644);
        octal_into(&mut header[124..136], data.len() as u64);
        header[156] = typeflag;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        checksum_header(&mut header);
        let mut out = header.to_vec();
        out.extend_from_slice(data);
        out.extend_from_slice(&vec![0u8; data.len().div_ceil(512) * 512 - data.len()]);
        out
    }

    fn tar_of(members: &[(&[u8], u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, flag, data) in members {
            out.extend_from_slice(&member_bytes(name, *flag, data));
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    /// Logical (flag, path, payload) triples with `x` records resolved.
    fn logical(tar: &[u8]) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        let mut pos = 0;
        let mut pending: Option<Vec<u8>> = None;
        while pos + 512 <= tar.len() {
            let mut header = [0u8; 512];
            header.copy_from_slice(&tar[pos..pos + 512]);
            pos += 512;
            if header.iter().all(|byte| *byte == 0) {
                break;
            }
            let size = parse_octal(&header[124..136], "size").expect("size") as usize;
            let data = tar[pos..pos + size].to_vec();
            pos += size.div_ceil(512) * 512;
            let flag = header[156];
            if flag == b'x' {
                pending = Some(data);
                continue;
            }
            let path = match pending.take().and_then(|records| pax_path_record(&records)) {
                Some(path) => path,
                None => header_name(&header),
            };
            out.push((flag, path, data));
        }
        out
    }

    #[test]
    fn rewrap_prefixes_members_and_skips_metadata() {
        let tar = tar_of(&[
            (b"pax_global_header", b'g', b"1 comment=abc\n"),
            (b"a.txt", b'0', b"a\n"),
            (b"sub/", b'5', b""),
            (b"sub/b.txt", b'0', b"b\n"),
        ]);
        let out = rewrap_archive_tar(tar, Some(b"lead/"), &[]).expect("rewrap");
        let members = logical(&out);
        assert_eq!(members[0].0, b'g');
        assert_eq!(members[0].1, b"pax_global_header");
        let named: Vec<Vec<u8>> = members[1..]
            .iter()
            .map(|(_, path, _)| path.clone())
            .collect();
        assert_eq!(
            named,
            vec![
                b"lead/a.txt".to_vec(),
                b"lead/sub/".to_vec(),
                b"lead/sub/b.txt".to_vec()
            ]
        );
        assert_eq!(members[1].2, b"a\n");
    }

    #[test]
    fn rewrap_paths_keep_parents_and_drop_others() {
        let tar = tar_of(&[
            (b"a.txt", b'0', b"a\n"),
            (b"sub/", b'5', b""),
            (b"sub/b.txt", b'0', b"b\n"),
        ]);
        let limited = rewrap_archive_tar(tar, None, &["sub".to_owned()]).expect("rewrap");
        let names: Vec<Vec<u8>> = logical(&limited)
            .iter()
            .map(|(_, path, _)| path.clone())
            .collect();
        assert_eq!(names, vec![b"sub/".to_vec(), b"sub/b.txt".to_vec()]);
    }

    #[test]
    fn rewrap_prefix_tracks_pax_records() {
        // No slash: unsplittable, so the `x` path record carries the name.
        let sub_path: Vec<u8> = core::iter::repeat(b'n').take(120).collect();
        let record = ext_record_bytes("path", &sub_path);
        let mut tar = member_bytes(b"h.paxheader", b'x', &record);
        tar.extend_from_slice(&raw_member(&sub_path[..100], b'0', b"data\n"));
        tar.extend_from_slice(&[0u8; 1024]);
        let out = rewrap_archive_tar(tar, Some(b"lead/"), &[]).expect("rewrap");
        let members = logical(&out);
        assert_eq!(members.len(), 1);
        let mut wanted = b"lead/".to_vec();
        wanted.extend_from_slice(&sub_path);
        assert_eq!(members[0].1, wanted);
        assert_eq!(members[0].2, b"data\n");
    }

    #[test]
    fn rewrap_unsplittable_rename_gains_a_pax_header() {
        // Splits (slash at 150) but not after the prefix moves it to 155.
        let mut name = core::iter::repeat(b'a').take(150).collect::<Vec<u8>>();
        name.push(b'/');
        name.extend_from_slice(&core::iter::repeat(b'b').take(40).collect::<Vec<u8>>());
        let tar = tar_of(&[(name.as_slice(), b'0', b"deep\n")]);
        let out = rewrap_archive_tar(tar, Some(b"lead/"), &[]).expect("rewrap");
        let members = logical(&out);
        assert_eq!(members.len(), 1);
        let mut wanted = b"lead/".to_vec();
        wanted.extend_from_slice(&name);
        assert_eq!(members[0].1, wanted);
    }

    /// Builds a member with full control over mode and link target, the
    /// fields `member_bytes` fixes for rewrap-only shapes. The mtime is the
    /// fixed stamp the assertions below decode.
    fn zip_member(name: &[u8], flag: u8, mode: u32, link: &[u8], data: &[u8]) -> Vec<u8> {
        // 1_700_000_000 is Tue 2023-11-14 22:13:20 UTC, inside the DOS range.
        let mtime = 1_700_000_000;
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name);
        octal_into(&mut header[100..108], u64::from(mode));
        let size = u64::try_from(data.len()).expect("test payload fits");
        octal_into(&mut header[124..136], size);
        octal_into(&mut header[136..148], mtime);
        header[156] = flag;
        header[157..157 + link.len()].copy_from_slice(link);
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        checksum_header(&mut header);
        let mut out = header.to_vec();
        out.extend_from_slice(data);
        let pad = data.len().div_ceil(512) * 512 - data.len();
        out.extend_from_slice(&vec![0u8; pad]);
        out
    }

    #[test]
    fn zip_transcode_keeps_kinds_modes_and_mtimes() {
        use std::io::Read as _;

        let mut tar = zip_member(b"f.txt", b'0', 0o100644, b"", b"hello\n");
        tar.extend_from_slice(&zip_member(b"d/", b'5', 0o040775, b"", b""));
        tar.extend_from_slice(&zip_member(b"l", b'2', 0o120777, b"f.txt", b""));
        tar.extend_from_slice(&[0u8; 1024]);
        let zip = tar_to_zip(&tar).expect("transcode");
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&zip)).expect("read back");
        let mut file = archive.by_name("f.txt").expect("file");
        assert_eq!(file.compression(), zip::CompressionMethod::Deflated);
        assert_eq!(file.unix_mode().unwrap_or(0), 0o100644);
        let mtime = file.last_modified().expect("mtime present");
        assert_eq!(
            (
                mtime.year(),
                mtime.month(),
                mtime.day(),
                mtime.hour(),
                mtime.minute(),
                mtime.second()
            ),
            (2023, 11, 14, 22, 13, 20)
        );
        let mut body = Vec::new();
        file.read_to_end(&mut body).expect("payload");
        assert_eq!(body, b"hello\n");
        drop(file);
        let dir = archive.by_name("d/").expect("dir");
        assert!(dir.is_dir());
        assert_eq!(dir.unix_mode().unwrap_or(0), 0o040775);
        drop(dir);
        let mut link = archive.by_name("l").expect("link");
        assert_eq!(link.unix_mode().unwrap_or(0) & 0o170000, 0o120000);
        let mut target = Vec::new();
        link.read_to_end(&mut target).expect("target");
        assert_eq!(target, b"f.txt");
    }
}
