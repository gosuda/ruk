//! Mirror-sync mapping for Forgejo pull/push mirrors.
//!
//! Forgejo syncs mirrors with plain Git commands run in the repository
//! directory (`services/mirror/`):
//!
//! - pull mirrors: `git fetch --prune --tags <remote>` (and
//!   `git remote update --prune <remote>` for wikis), then LFS object sync
//!   plus branch/tag bookkeeping through `cat-file --batch` pipelines;
//! - push mirrors: `git push --mirror --force <remote>`, with LFS objects
//!   uploaded beforehand through the LFS HTTP API (not through Git).
//!
//! Through the daemon command runner those verbs arrive as `ruk fetch`,
//! `ruk remote update`, and `ruk push`. This module holds the pure ref
//! mapping behind the two mirror-only spellings so the verbs stay thin:
//!
//! - [`prune_for_spec`]: destination refs one fetch refspec orphans (the
//!   `--prune` half of a pull-mirror sync);
//! - [`push_mirror_updates`]: the full set-plus-delete update list of
//!   `push --mirror` (the push-mirror sync).
//!
//! Deliberately out of scope (named gaps, not stubs):
//!
//! - HTTP remotes: [`parse_endpoint`](super::net::parse_endpoint) classifies
//!   them, and the verbs serve smart-http there (dumb-http stays the named
//!   gap); SSH and git-daemon remotes fetch and push for real;
//! - LFS content sync: [`Store::iter_objects`](ruk_core::store::Store::iter_objects)
//!   is the object census behind `cat-file --batch-check
//!   --batch-all-objects`, `ruk fetch --lfs` discovers pointer blobs in
//!   the fetched tips and pulls their payloads through the LFS batch API
//!   into the sidecar, and `ruk push --lfs` discovers pointer blobs in the
//!   outgoing push closure and uploads their sidecar-verified payloads
//!   through the LFS batch API before the pack moves (`lfs-payload-sync
//!   --upload` stays as the manual verb for the same transfer);
//! - symbolic refs are never mapped or pruned: only direct tips carry the
//!   CAS expectations these updates need.
//!
//! Oracle anchors: `git/builtin/fetch.c` (`--prune`),
//! `git/builtin/push.c` (`--mirror`), `git/builtin/remote.c` (`update`).

use std::collections::HashSet;

use ruk_core::ids::Oid;

/// One mirror update: the destination ref, its current tip (`None` when
/// absent), and the tip to write (`None` deletes it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorUpdate {
    /// Full destination ref name bytes.
    pub name: Vec<u8>,
    /// Current destination tip, if the ref exists.
    pub old: Option<Oid>,
    /// Tip to write; `None` deletes the ref.
    pub new: Option<Oid>,
}

/// Destination refs orphaned under one fetch refspec: local refs matching
/// the destination side whose source counterpart is no longer advertised.
///
/// `src`/`dst` are the two sides of `[+]<src>[:<dst>]` after the leading
/// `+` is stripped; either side may carry one `*`. A missing `dst`
/// (FETCH_HEAD-only refspec) prunes nothing. Matching is byte-exact
/// outside the single `*`, the way the fetch verb expands specs.
///
/// # Examples
///
/// ```ignore
/// // `+refs/heads/*:refs/remotes/origin/*` orphans
/// // `refs/remotes/origin/gone` once `refs/heads/gone` vanishes.
/// ```
#[must_use]
pub fn prune_for_spec(
    local: &[Vec<u8>],
    advertised: &HashSet<Vec<u8>>,
    src: &str,
    dst: Option<&str>,
) -> Vec<Vec<u8>> {
    let Some(dst) = dst else {
        return Vec::new();
    };
    let mut orphaned = Vec::new();
    for name in local {
        let Ok(text) = std::str::from_utf8(name) else {
            continue;
        };
        let Some(middle) = match_glob(dst, text) else {
            continue;
        };
        let counterpart = match src.split_once('*') {
            Some((prefix, suffix)) => format!("{prefix}{middle}{suffix}"),
            None => src.to_owned(),
        };
        if !advertised.contains(counterpart.as_bytes()) {
            orphaned.push(name.clone());
        }
    }
    orphaned
}

/// The `push --mirror` update list: every local direct ref written to the
/// same name on the destination, plus deletes for destination refs with no
/// local counterpart. Both lists arrive as `(name, tip)` pairs of direct
/// tips; symbolic refs never enter.
///
/// Force is implied for every set, the way the oracle's `--mirror` forces:
/// callers report the updates through the normal push path with force on.
#[must_use]
pub fn push_mirror_updates(
    local: &[(Vec<u8>, Oid)],
    remote: &[(Vec<u8>, Oid)],
) -> Vec<MirrorUpdate> {
    let mut updates = Vec::with_capacity(local.len());
    for (name, tip) in local {
        let old = remote
            .iter()
            .find(|(remote_name, _)| remote_name == name)
            .map(|(_, tip)| *tip);
        updates.push(MirrorUpdate {
            name: name.clone(),
            old,
            new: Some(*tip),
        });
    }
    for (name, tip) in remote {
        if local.iter().any(|(local_name, _)| local_name == name) {
            continue;
        }
        updates.push(MirrorUpdate {
            name: name.clone(),
            old: Some(*tip),
            new: None,
        });
    }
    updates
}

/// Matches `text` against a glob with at most one `*`, returning the
/// middle the star covers. A pattern without `*` matches only itself, with
/// an empty middle.
fn match_glob(pattern: &str, text: &str) -> Option<String> {
    match pattern.split_once('*') {
        None => (pattern == text).then(String::new),
        Some((prefix, suffix)) => text
            .strip_prefix(prefix)
            .and_then(|tail| tail.strip_suffix(suffix))
            .map(str::to_owned),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> HashSet<Vec<u8>> {
        names.iter().map(|name| name.as_bytes().to_vec()).collect()
    }

    #[test]
    fn prune_orphans_only_vanished_sources() {
        let local = vec![
            b"refs/remotes/origin/kept".to_vec(),
            b"refs/remotes/origin/gone".to_vec(),
            b"refs/heads/local".to_vec(),
        ];
        let advertised = set(&["refs/heads/kept"]);
        let orphaned = prune_for_spec(
            &local,
            &advertised,
            "refs/heads/*",
            Some("refs/remotes/origin/*"),
        );
        assert_eq!(orphaned, vec![b"refs/remotes/origin/gone".to_vec()]);
    }

    #[test]
    fn prune_exact_refspec_tracks_one_ref() {
        let local = vec![b"refs/remotes/origin/main".to_vec()];
        assert!(
            prune_for_spec(
                &local,
                &set(&["refs/heads/main"]),
                "refs/heads/main",
                Some("refs/remotes/origin/main")
            )
            .is_empty()
        );
        assert_eq!(
            prune_for_spec(
                &local,
                &set(&[]),
                "refs/heads/main",
                Some("refs/remotes/origin/main")
            ),
            vec![b"refs/remotes/origin/main".to_vec()]
        );
    }

    #[test]
    fn prune_fetch_head_only_spec_prunes_nothing() {
        let local = vec![b"refs/remotes/origin/gone".to_vec()];
        assert!(prune_for_spec(&local, &set(&[]), "refs/heads/*", None).is_empty());
    }

    #[test]
    fn mirror_sets_everything_and_deletes_stale() {
        use ruk_core::ids::HashKind;
        let kind = HashKind::Sha1;
        let oid = |hex: &str| Oid::from_hex(hex).expect("hex");
        let aaa = kind.hash_git_object("blob", b"a").expect("id");
        let bbb = kind.hash_git_object("blob", b"b").expect("id");
        let ccc = kind.hash_git_object("blob", b"c").expect("id");
        let old = oid("b7ee0f83149b8f52744bf4de0bc706afcd5302c8");
        let local = vec![
            (b"refs/heads/main".to_vec(), aaa),
            (b"refs/tags/v1".to_vec(), bbb),
        ];
        let remote = vec![
            (b"refs/heads/main".to_vec(), old),
            (b"refs/heads/stale".to_vec(), ccc),
        ];
        let updates = push_mirror_updates(&local, &remote);
        assert_eq!(updates.len(), 3);
        assert!(updates.contains(&MirrorUpdate {
            name: b"refs/heads/main".to_vec(),
            old: Some(old),
            new: Some(aaa),
        }));
        assert!(updates.contains(&MirrorUpdate {
            name: b"refs/tags/v1".to_vec(),
            old: None,
            new: Some(bbb),
        }));
        assert!(updates.contains(&MirrorUpdate {
            name: b"refs/heads/stale".to_vec(),
            old: Some(ccc),
            new: None,
        }));
    }
}
