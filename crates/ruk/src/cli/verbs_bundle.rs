//! `bundle`: move objects and refs by archive file.
//!
//! The file layout is the git bundle shape (`git/builtin/bundle.c`):
//! a `# v2/v3 git bundle` signature line, `@object-format=` capability
//! lines (v3), `-<oid> <rev>` prerequisite lines, `<oid> <ref>` head
//! lines, one blank line, then a self-contained pack v2 stream. Readers
//! accept v2 (no capabilities; the object format is inferred from the hex
//! width) and v3. Packs are emitted through
//! `ruk_git::transport::pack::write_pack` and ingested through
//! `ingest_pack`, so a bundle round-trips through real git.
//!
//! Reachability for `create` reuses the same closure the [`fsck`](super::verbs_transport::fsck)
//! walk uses: ref tips peeled through tags, full history via
//! [`walk_history`](super::state::walk_history), trees walked entry by
//! entry. `^<rev>` exclusions become prerequisite lines and are subtracted
//! from the packed closure; the receiver must already hold them.
//!
//! Divergences from the oracle: `create` only bundles named refs (plus
//! `HEAD`); raw object ids are refused. Bundle verbs need an open
//! repository (`verify`/`list-heads`/`unbundle` also need one here, where
//! git works outside a repo). `unbundle` publishes objects but never
//! creates refs, exactly like the oracle; `clone <bundle>` is the path
//! that plants refs.

use std::collections::HashSet;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use ruk_core::store::{EventContext, EventSource, ObjectKind, PreparationBudget, Store};
use ruk_core::workspace::{GitCompatWorkspace, HeadRef, Scope};
use ruk_git::GitError;
use ruk_git::transport::Interrupt;
use ruk_git::transport::pack::{IngestLimits, PackEntry, StagedPack};

use super::state::{
    DEFAULT_BRANCH, apply_refs, config_write, list_refs, resolve_rev, walk_history,
    workspace_mutation,
};
use super::{Collected, Ctx, FlagSpec, collect};

/// Bundle signature lines, git spelling.
const SIG_V2: &str = "# v2 git bundle";
const SIG_V3: &str = "# v3 git bundle";

/// Parsed bundle header plus the pack offset into the file bytes.
pub(crate) struct ParsedBundle {
    /// Declared or inferred object format.
    pub(crate) format: HashKind,
    /// Prerequisite tips (`^` exclusions at create time).
    pub(crate) prereqs: Vec<(Oid, String)>,
    /// Heads in header order.
    pub(crate) heads: Vec<(Oid, Vec<u8>)>,
    /// Byte offset where the pack stream starts.
    pub(crate) pack_offset: usize,
}

/// Whether `path` names a bundle file (signature sniff, no parse).
pub(crate) fn is_bundle_file(path: &std::path::Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    is_bundle_bytes(&bytes)
}

/// Whether `bytes` open with a bundle signature line.
pub(crate) fn is_bundle_bytes(bytes: &[u8]) -> bool {
    first_line(bytes).is_some_and(|line| line == SIG_V2 || line == SIG_V3)
}

/// Dispatches `bundle <create|verify|list-heads|unbundle>`.
///
/// Oracle: `git/builtin/bundle.c`.
pub(crate) fn bundle(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let (sub, rest) = args.split_first().ok_or_else(|| GitError::Usage {
        detail: "usage: bundle <create|verify|list-heads|unbundle>".to_owned(),
    })?;
    match sub.as_str() {
        "create" => bundle_create(ctx, rest),
        "verify" => bundle_verify(ctx, rest),
        "list-heads" => bundle_list_heads(ctx, rest),
        "unbundle" => bundle_unbundle(ctx, rest),
        _ => Err(GitError::Usage {
            detail: format!("unknown bundle subcommand {sub:?}"),
        }),
    }
}

/// Writes `<file>` holding the packed closure of the named refs.
///
/// Usage: `bundle create <file> [--all] [<rev>...]`, where `^<rev>`
/// excludes (and records as prerequisite). At least one head ref is
/// required; an empty closure is refused like the oracle.
fn bundle_create(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "all",
        short: None,
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    let file = opts.positionals.first().ok_or_else(|| GitError::Usage {
        detail: "usage: bundle create <file> [--all] [<rev>...]".to_owned(),
    })?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;

    let mut positives: Vec<String> = Vec::new();
    let mut exclusions: Vec<String> = Vec::new();
    for rev in &opts.positionals[1..] {
        if let Some(excluded) = rev.strip_prefix('^') {
            if excluded.is_empty() {
                return Err(GitError::Invalid {
                    detail: "bundle create: bare ^ excludes nothing".to_owned(),
                });
            }
            exclusions.push(excluded.to_owned());
        } else {
            positives.push(rev.clone());
        }
    }
    if opts.is_set("all") {
        for (name, _) in list_refs(store)? {
            let text = String::from_utf8_lossy(name.as_bytes()).into_owned();
            if !positives.contains(&text) {
                positives.push(text);
            }
        }
    }
    if positives.is_empty() {
        return Err(GitError::Usage {
            detail: "bundle create needs at least one ref".to_owned(),
        });
    }

    // Heads: every positive must name a ref; `HEAD` records the `HEAD`
    // line the way the oracle does when handed `HEAD` explicitly.
    let mut heads: Vec<(Oid, Vec<u8>)> = Vec::new();
    for rev in &positives {
        let (oid, name) = head_ref(store, kind, rev)?;
        if heads.iter().any(|(_, known)| *known == name) {
            continue;
        }
        heads.push((oid, name));
    }

    // Prerequisites: exclusion tips, resolved but never peeled here; the
    // commit peel below decides the subtracted history.
    let mut prereqs: Vec<(Oid, String)> = Vec::new();
    for rev in &exclusions {
        let oid = resolve_rev(store, kind, rev)?;
        if !prereqs.iter().any(|(known, _)| *known == oid) {
            prereqs.push((oid, rev.clone()));
        }
    }

    // Peel heads through tags to commits; non-commit terminals (tree, blob)
    // join the reachable set directly with their subtrees.
    let mut commit_tips: Vec<Oid> = Vec::new();
    let mut reachable: HashSet<Oid> = HashSet::new();
    let mut tags: Vec<Oid> = Vec::new();
    for (oid, _) in &heads {
        let (visited, commit) = peel_to_commit(store, kind, *oid)?;
        tags.extend(visited.iter().skip(1).copied());
        match commit {
            Some(tip) => commit_tips.push(tip),
            None => {
                let terminal = visited.last().copied().unwrap_or(*oid);
                reachable.insert(terminal);
                if super::tree::read_object_bytes(store, terminal)?.0 == ObjectKind::Tree {
                    mark_tree(store, kind, terminal, &mut reachable)?;
                }
            }
        }
    }

    // Excluded history: peel each prerequisite to a commit and subtract its
    // history, the oracle's boundary rule.
    let mut excluded: HashSet<Oid> = HashSet::new();
    for (oid, _) in &prereqs {
        if let (_, Some(tip)) = peel_to_commit(store, kind, *oid)? {
            for (commit, _) in walk_history(store, &[tip], None)? {
                excluded.insert(commit);
            }
        }
    }
    let mut included: Vec<(Oid, ruk_core::commit::CommitRecord)> = Vec::new();
    for (oid, record) in walk_history(store, &commit_tips, None)? {
        if !excluded.contains(&oid) {
            included.push((oid, record));
        }
    }

    // Close over trees: every included commit plus its subtree, every
    // traversed tag object, every non-commit terminal.
    for (oid, record) in &included {
        reachable.insert(*oid);
        let tree = super::tree::commit_tree_oid(record)?;
        mark_tree(store, kind, tree, &mut reachable)?;
    }
    for tag in tags {
        reachable.insert(tag);
    }
    // A head left outside the packed set (fully excluded) would unbundle
    // to a dangling ref: refuse instead of writing it.
    for (oid, name) in &heads {
        if !reachable.contains(oid) {
            return Err(GitError::Invalid {
                detail: format!(
                    "refusing to create an empty bundle for {}",
                    String::from_utf8_lossy(name)
                ),
            });
        }
    }
    if reachable.is_empty() {
        return Err(GitError::Invalid {
            detail: "refusing to create an empty bundle".to_owned(),
        });
    }

    // Pack the closure in oid order so identical stores emit identical
    // bundles; thin bases stay `None` because the stream is
    // self-contained.
    let mut oids: Vec<Oid> = reachable.into_iter().collect();
    oids.sort();
    let mut payloads: Vec<(Oid, ObjectKind, Vec<u8>)> = Vec::with_capacity(oids.len());
    for oid in oids {
        let (object_kind, bytes) = super::tree::read_object_bytes(store, oid)?;
        payloads.push((oid, object_kind, bytes));
    }
    let entries: Vec<PackEntry<'_>> = payloads
        .iter()
        .map(|(oid, object_kind, bytes)| PackEntry {
            oid: *oid,
            kind: *object_kind,
            bytes,
            base: None,
        })
        .collect();
    let mut pack: Vec<u8> = Vec::new();
    ruk_git::transport::pack::write_pack(&mut pack, kind, &entries, &Interrupt::none())?;

    let mut out = format!("{SIG_V3}\n@object-format={}\n", kind.format_name()).into_bytes();
    for (oid, rev) in &prereqs {
        out.extend_from_slice(format!("-{} {rev}\n", oid.to_hex()).as_bytes());
    }
    for (oid, name) in &heads {
        out.extend_from_slice(oid.to_hex().as_bytes());
        out.push(b' ');
        out.extend_from_slice(name);
        out.push(b'\n');
    }
    out.push(b'\n');
    out.extend_from_slice(&pack);
    let dest = join_cwd(ctx, file);
    std::fs::write(&dest, &out).map_err(|err| GitError::Io {
        detail: format!("writing {}: {err}", dest.display()),
    })?;
    Ok(Vec::new())
}

/// Checks `<file>` against the current repository: header parses, the pack
/// stages cleanly, every head is in the pack, every prerequisite is
/// present. Prints the oracle's ref listing, then `<file> is okay`.
fn bundle_verify(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let opts = collect(args, &[])?;
    let [file] = opts.positionals.as_slice() else {
        return Err(GitError::Usage {
            detail: "usage: bundle verify <file>".to_owned(),
        });
    };
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let bytes = read_bundle_file(ctx, file)?;
    let parsed = parse_bundle(&bytes, file)?;
    require_format(parsed.format, kind, file)?;
    let staged = ingest_bundle_pack(store, kind, &parsed, &bytes)?;
    let staged_set: HashSet<Oid> = staged.oids().iter().copied().collect();
    for (oid, name) in &parsed.heads {
        if !staged_set.contains(oid) {
            return Err(GitError::Corrupt {
                detail: format!(
                    "bundle head {} ({}) is not in the pack",
                    oid.to_hex(),
                    String::from_utf8_lossy(name)
                ),
            });
        }
    }
    let mut missing: Vec<String> = Vec::new();
    for (oid, _) in &parsed.prereqs {
        if !ruk_git::transport::has_object(store, *oid)? {
            missing.push(oid.to_hex());
        }
    }
    if !missing.is_empty() {
        return Err(GitError::NotFound {
            detail: format!(
                "repository lacks these prerequisite commits: {}",
                missing.join(" ")
            ),
        });
    }
    let mut out = format!("The bundle contains these {} refs:\n", parsed.heads.len()).into_bytes();
    for (oid, name) in &parsed.heads {
        out.extend_from_slice(oid.to_hex().as_bytes());
        out.push(b' ');
        out.extend_from_slice(name);
        out.push(b'\n');
    }
    if !parsed.prereqs.is_empty() {
        out.extend_from_slice(
            format!(
                "The bundle requires these {} prerequisites:\n",
                parsed.prereqs.len()
            )
            .as_bytes(),
        );
        for (oid, rev) in &parsed.prereqs {
            out.extend_from_slice(format!("{} {rev}\n", oid.to_hex()).as_bytes());
        }
    }
    out.extend_from_slice(format!("{file} is okay\n").as_bytes());
    Ok(out)
}

/// Prints `<oid> <ref>` for every head in `<file>`.
fn bundle_list_heads(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let opts = collect(args, &[])?;
    let [file] = opts.positionals.as_slice() else {
        return Err(GitError::Usage {
            detail: "usage: bundle list-heads <file>".to_owned(),
        });
    };
    let bytes = read_bundle_file(ctx, file)?;
    let parsed = parse_bundle(&bytes, file)?;
    let mut out = Vec::new();
    for (oid, name) in &parsed.heads {
        out.extend_from_slice(oid.to_hex().as_bytes());
        out.push(b' ');
        out.extend_from_slice(name);
        out.push(b'\n');
    }
    Ok(out)
}

/// Ingests `<file>`'s pack into the current store and prints the (optionally
/// pattern-filtered) heads. Refs are never created, matching the oracle:
/// `clone <file>` is the path that plants them.
fn bundle_unbundle(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let opts = collect(args, &[])?;
    let Some((file, patterns)) = opts.positionals.split_first() else {
        return Err(GitError::Usage {
            detail: "usage: bundle unbundle <file> [<ref>...]".to_owned(),
        });
    };
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let bytes = read_bundle_file(ctx, file)?;
    let parsed = parse_bundle(&bytes, file)?;
    require_format(parsed.format, kind, file)?;
    let staged = ingest_bundle_pack(store, kind, &parsed, &bytes)?;
    publish_staged(store, staged)?;
    let mut out = Vec::new();
    for (oid, name) in &parsed.heads {
        if !patterns.is_empty()
            && !patterns
                .iter()
                .any(|pattern| ref_matches(pattern.as_bytes(), name))
        {
            continue;
        }
        out.extend_from_slice(oid.to_hex().as_bytes());
        out.push(b' ');
        out.extend_from_slice(name);
        out.push(b'\n');
    }
    Ok(out)
}

/// Clones a bundle file into a new repository: fresh store in the bundle's
/// object format, pack ingested, branch and tag refs planted, `HEAD` on the
/// bundle's `HEAD` target (or `--branch`, or the first bundled branch).
pub(crate) fn clone_bundle(
    ctx: &mut Ctx,
    bundle_path: std::path::PathBuf,
    opts: &Collected,
) -> Result<Vec<u8>, GitError> {
    if opts.single("depth")?.is_some() {
        return Err(GitError::Invalid {
            detail: "clone --depth from a bundle is not supported".to_owned(),
        });
    }
    let origin = opts
        .single("origin")?
        .unwrap_or_else(|| "origin".to_owned());
    let bytes = std::fs::read(&bundle_path).map_err(|err| GitError::Io {
        detail: format!("reading {}: {err}", bundle_path.display()),
    })?;
    let label = bundle_path.display().to_string();
    let parsed = parse_bundle(&bytes, &label)?;
    let kind = parsed.format;
    let src = opts
        .positionals
        .first()
        .map(String::as_str)
        .unwrap_or(&label);
    let dst_name = opts.positionals.get(1).cloned().unwrap_or_else(|| {
        bundle_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("bundle")
            .to_owned()
    });
    let dst = if std::path::Path::new(&dst_name).is_absolute() {
        std::path::PathBuf::from(&dst_name)
    } else {
        ctx.env.cwd.join(&dst_name)
    };
    if dst.exists() {
        return Err(GitError::Invalid {
            detail: format!("destination {} already exists", dst.display()),
        });
    }
    std::fs::create_dir_all(&dst).map_err(|err| GitError::Io {
        detail: format!("creating {}: {err}", dst.display()),
    })?;
    let budget = std::sync::Arc::new(PreparationBudget::reference_defaults());
    let dst_store = Store::create(&dst.join(".ruk"), kind, budget).map_err(GitError::from)?;
    let staged = ingest_bundle_pack(&dst_store, kind, &parsed, &bytes)?;
    publish_staged(&dst_store, staged)?;

    let mut updates = Vec::new();
    let mut branches: Vec<(Vec<u8>, Oid)> = Vec::new();
    for (oid, name) in &parsed.heads {
        if name.as_slice() == b"HEAD" {
            continue;
        }
        if name.starts_with(b"refs/heads/") {
            let branch = RefName::new(name.clone()).map_err(|err| GitError::Invalid {
                detail: format!("bundle ref refused: {err}"),
            })?;
            updates.push(RefUpdate {
                name: branch,
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(*oid)),
            });
            let mut tracking = format!("refs/remotes/{origin}/").into_bytes();
            tracking.extend_from_slice(&name[b"refs/heads/".len()..]);
            let remote_name = RefName::new(tracking).map_err(|err| GitError::Invalid {
                detail: format!("remote-tracking ref refused: {err}"),
            })?;
            updates.push(RefUpdate {
                name: remote_name,
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(*oid)),
            });
            branches.push((name.clone(), *oid));
        } else if name.starts_with(b"refs/tags/") {
            let tag = RefName::new(name.clone()).map_err(|err| GitError::Invalid {
                detail: format!("bundle ref refused: {err}"),
            })?;
            updates.push(RefUpdate {
                name: tag,
                expected: RefExpect::Absent,
                change: RefChange::Set(RefTarget::Direct(*oid)),
            });
        }
    }
    if branches.is_empty() {
        return Err(GitError::NotFound {
            detail: "bundle holds no branch to clone".to_owned(),
        });
    }
    apply_refs(&dst_store, kind, updates)?;
    let head_target = parsed
        .heads
        .iter()
        .find(|(_, name)| name.as_slice() == b"HEAD")
        .and_then(|(oid, _)| {
            branches
                .iter()
                .find(|(_, tip)| *tip == *oid)
                .map(|(name, _)| name.clone())
        });
    let checkout_branch = match opts.single("branch")? {
        Some(short) => format!("refs/heads/{short}").into_bytes(),
        None => head_target
            .or_else(|| {
                branches
                    .iter()
                    .find(|(name, _)| *name == DEFAULT_BRANCH.as_bytes())
                    .map(|(name, _)| name.clone())
            })
            .unwrap_or_else(|| {
                branches
                    .first()
                    .map(|(name, _)| name.clone())
                    .unwrap_or_default()
            }),
    };
    let head_name = RefName::new(checkout_branch.clone()).map_err(|err| GitError::Invalid {
        detail: format!("branch refused: {err}"),
    })?;
    if super::state::read_ref(&dst_store, &head_name)?.is_none() {
        return Err(GitError::NotFound {
            detail: format!(
                "branch {:?} is not in the bundle",
                String::from_utf8_lossy(&checkout_branch)
            ),
        });
    }
    let workspace = GitCompatWorkspace::new(HeadRef::Symbolic(head_name), Scope::Full);
    let mutation = workspace_mutation(None, &workspace)?;
    dst_store
        .publish(
            Vec::new(),
            &[mutation],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .map_err(GitError::from)?;
    config_write(&dst_store, &format!("remote.{origin}.url"), src)?;
    config_write(
        &dst_store,
        &format!("remote.{origin}.fetch"),
        &format!("+refs/heads/*:refs/remotes/{origin}/*"),
    )?;
    Ok(format!("Cloned into {}\n", dst.display()).into_bytes())
}

/// Parses bundle bytes into its header and pack offset.
///
/// Accepts v2 (format inferred from the first oid's hex width) and v3
/// (`@object-format=` required when heads disagree, else inferred the same
/// way). Unknown `@` capabilities are ignored for forward compatibility.
pub(crate) fn parse_bundle(bytes: &[u8], label: &str) -> Result<ParsedBundle, GitError> {
    let corrupt = |why: &str| GitError::Corrupt {
        detail: format!("{label}: {why}"),
    };
    let sep = bytes
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .ok_or_else(|| corrupt("no header terminator"))?;
    let header = &bytes[..sep];
    let pack_offset = sep + 2;
    if bytes.len() <= pack_offset {
        return Err(corrupt("no pack follows the header"));
    }
    let mut lines = header.split(|byte| *byte == b'\n');
    let signature = lines.next().ok_or_else(|| corrupt("empty header"))?;
    if signature != SIG_V2.as_bytes() && signature != SIG_V3.as_bytes() {
        return Err(corrupt("not a bundle (bad signature)"));
    }
    let mut format: Option<HashKind> = None;
    let mut prereqs: Vec<(Oid, String)> = Vec::new();
    let mut heads: Vec<(Oid, Vec<u8>)> = Vec::new();
    for raw in lines {
        // Tolerate a trailing CR per line so bundles written through
        // text-mode transports still parse.
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        if let Some(cap) = line.strip_prefix(b"@") {
            if let Some(value) = cap.strip_prefix(b"object-format=") {
                format = Some(if value == b"sha1" {
                    HashKind::Sha1
                } else if value == b"sha256" {
                    HashKind::Sha256
                } else {
                    return Err(corrupt("unknown @object-format"));
                });
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix(b"-") {
            let (hex, rev) = split_head_line(rest)?;
            prereqs.push((parse_bundle_oid(hex, label)?, rev.to_owned()));
            continue;
        }
        let (hex, name) = split_head_line(line)?;
        if name.is_empty() || name.contains(' ') {
            return Err(corrupt("malformed head line"));
        }
        if name != "HEAD" {
            RefName::new(name.as_bytes()).map_err(|_| corrupt("bad ref name in head line"))?;
        }
        heads.push((parse_bundle_oid(hex, label)?, name.as_bytes().to_vec()));
    }
    if heads.is_empty() {
        return Err(corrupt("bundle holds no refs"));
    }
    let inferred = heads
        .iter()
        .map(|(oid, _)| oid.kind())
        .next()
        .unwrap_or(HashKind::DEFAULT);
    if let Some(declared) = format {
        for (oid, _) in &heads {
            if oid.kind() != declared {
                return Err(corrupt("head width disagrees with @object-format"));
            }
        }
        for (oid, _) in &prereqs {
            if oid.kind() != declared {
                return Err(corrupt("head width disagrees with @object-format"));
            }
        }
    }
    Ok(ParsedBundle {
        format: format.unwrap_or(inferred),
        prereqs,
        heads,
        pack_offset,
    })
}

/// Stages the bundle's pack without publishing, the way `verify-pack`
/// ingests in verify mode.
fn ingest_bundle_pack(
    store: &Store,
    kind: HashKind,
    parsed: &ParsedBundle,
    bytes: &[u8],
) -> Result<StagedPack, GitError> {
    ruk_git::transport::pack::ingest_pack(
        &bytes[parsed.pack_offset..],
        kind,
        store,
        IngestLimits::default(),
        &Interrupt::none(),
    )
}

/// Publishes staged bundle objects with their commit-record facts so
/// history verbs (`log`, `rev-list`, checkout) see the arrivals, mirroring
/// the local-fetch publication tail.
fn publish_staged(store: &Store, staged: StagedPack) -> Result<(), GitError> {
    let facts = ruk_git::transport::fetch::commit_record_facts(store, &staged)?;
    store
        .publish(
            staged.into_objects(),
            &facts,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .map_err(GitError::from)?;
    Ok(())
}

/// Maps one positive rev to its head oid and recorded ref name. Only refs
/// (and `HEAD`, recorded as the `HEAD` line) can head a bundle.
fn head_ref(store: &Store, kind: HashKind, rev: &str) -> Result<(Oid, Vec<u8>), GitError> {
    if rev == "HEAD" {
        let oid = resolve_rev(store, kind, rev)?;
        return Ok((oid, b"HEAD".to_vec()));
    }
    let refs = list_refs(store)?;
    for candidate in [
        rev.to_owned(),
        format!("refs/heads/{rev}"),
        format!("refs/tags/{rev}"),
    ] {
        if let Some((name, target)) = refs
            .iter()
            .find(|(name, _)| name.as_bytes() == candidate.as_bytes())
        {
            let oid = match target {
                RefTarget::Direct(oid) => *oid,
                RefTarget::Symbolic(target) => {
                    resolve_rev(store, kind, &String::from_utf8_lossy(target.as_bytes()))?
                }
            };
            return Ok((oid, name.as_bytes().to_vec()));
        }
    }
    Err(GitError::Invalid {
        detail: format!("cannot bundle {rev:?}: not a ref"),
    })
}

/// Peels one tip through annotated tags to a commit (at most 32 hops, the
/// same bound the rev-parse peel uses), returning every traversed oid plus
/// the commit. Anything that never resolves to a commit contributes its
/// traversed oids with no commit.
fn peel_to_commit(
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

/// Marks one tree and its subtree reachable: the tree itself plus every
/// entry oid, recursing into subtrees.
fn mark_tree(
    store: &Store,
    kind: HashKind,
    tree: Oid,
    reachable: &mut HashSet<Oid>,
) -> Result<(), GitError> {
    if !reachable.insert(tree) {
        return Ok(());
    }
    let (object_kind, body) = super::tree::read_object_bytes(store, tree)?;
    if object_kind != ObjectKind::Tree {
        return Err(GitError::Invalid {
            detail: format!("object {} is not a tree", tree.to_hex()),
        });
    }
    for entry in super::tree::parse_tree(kind, &body)? {
        if entry.mode.is_tree() {
            mark_tree(store, kind, entry.oid, reachable)?;
        } else {
            reachable.insert(entry.oid);
        }
    }
    Ok(())
}

/// Splits one `<hex> <rest>` header line at its first space.
fn split_head_line(line: &[u8]) -> Result<(&str, &str), GitError> {
    let text = std::str::from_utf8(line).map_err(|_| GitError::Corrupt {
        detail: "bundle header is not UTF-8".to_owned(),
    })?;
    text.split_once(' ').ok_or_else(|| GitError::Corrupt {
        detail: "malformed bundle header line".to_owned(),
    })
}

/// Parses one header oid, inferring its format from the hex width.
fn parse_bundle_oid(hex: &str, label: &str) -> Result<Oid, GitError> {
    Oid::from_hex(hex).map_err(|_| GitError::InvalidOid {
        input: hex.to_owned(),
        detail: format!("{label}: bad object id"),
    })
}

/// Refuses a bundle whose format disagrees with the open repository.
fn require_format(format: HashKind, kind: HashKind, file: &str) -> Result<(), GitError> {
    if format != kind {
        return Err(GitError::ObjectFormat {
            detail: format!(
                "{file} holds {}, this repository is {}",
                format.format_name(),
                kind.format_name()
            ),
        });
    }
    Ok(())
}

/// Matches one unbundle filter: exact ref or a single trailing-`*` prefix.
fn ref_matches(pattern: &[u8], name: &[u8]) -> bool {
    if let Some(prefix) = pattern.strip_suffix(b"*") {
        name.starts_with(prefix)
    } else {
        name == pattern
    }
}

/// Reads a bundle file relative to the command's working directory.
fn read_bundle_file(ctx: &Ctx, file: &str) -> Result<Vec<u8>, GitError> {
    let path = join_cwd(ctx, file);
    std::fs::read(&path).map_err(|err| GitError::Io {
        detail: format!("reading {}: {err}", path.display()),
    })
}

/// Resolves `path` against the command's working directory.
pub(crate) fn join_cwd(ctx: &Ctx, path: &str) -> std::path::PathBuf {
    let candidate = std::path::Path::new(path);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        ctx.env.cwd.join(candidate)
    }
}

/// First `\n`-terminated line without its newline.
fn first_line(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|byte| *byte == b'\n')?;
    std::str::from_utf8(&bytes[..end]).ok()
}
