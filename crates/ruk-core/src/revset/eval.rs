//! Revset evaluator: parsed AST to bounded paged commit sets.
//!
//! The parser ([`super::syntax`]) is syntax only; this module resolves names
//! against repository state and evaluates set expressions over the commit
//! graph. Data sources, all read-only:
//!
//! - [`GraphIndex`] for positions, parents, generations, head/change-id
//!   prefix resolution, and changed-path Bloom chunks (candidates only);
//! - `refs` ([`page_refs`]) for bookmarks (`refs/heads/`), remote bookmarks
//!   (`refs/remotes/`), and tags (`refs/tags/`);
//! - `FactTable::Commits` / `FactTable::Changes` via [`Records`] for
//!   descriptions, provenance sessions, and divergence;
//! - [`Store`] tree objects for exact `files()` verification;
//! - an injected [`AttestedQuery`] for `attested(kind,result)`.
//!
//! # Result order
//!
//! Result sets are ordered newest-first: descending [`Generation`], ties
//! broken by descending [`GlobalPosition`]. The order is deterministic for a
//! fixed graph because generations and positions are fixed per segment
//! layout. Pages slice that order; a [`RevsetCursor`] is an offset into it.
//! Order stability across calls is NOT promised (the protocol layer owns
//! durable cursors): a cursor is valid only against an unchanged graph and
//! store view.
//!
//! # Symbol resolution precedence
//!
//! A bare [`NodeKind::Symbol`] or [`NodeKind::StringLiteral`] atom is tried,
//! in order, as: exact bookmark short/full name, exact tag short/full name,
//! bookmark/tag prefix on the short name, change-id prefix (reverse hex),
//! head prefix (lowercase hex). Exact matches beat prefix matches inside one
//! ref namespace. Matches in more than one category (bookmark vs tag vs
//! change vs head), more than one ref inside one namespace, or an ambiguous
//! index prefix are all [`ErrorCode::EInvalid`] carrying the candidates —
//! never an arbitrary pick. A symbol starting with `refs/` matches on full
//! ref names (including `refs/remotes/`); otherwise only bookmarks and tags
//! participate.
//!
//! # Shallow boundaries
//!
//! Ancestor-direction walks run with the context's `shallow` heads as
//! cutoffs. A walk that touches a cutoff reports [`ErrorCode::EShallow`]
//! (fail closed: completeness is unprovable). Descendant walks expand the
//! indexed children map and are exact over indexed commits, so they never
//! raise shallow errors.
//!
//! # `files()` glob and tree diff
//!
//! No shared glob facility exists: [`PathPattern`](crate::capability::PathPattern)
//! admits whole-segment `*` and trailing `**` only and rejects
//! partial-segment wildcards such as `*.rs` — which the parser's own
//! `files("*.rs")` test shows the revset grammar must accept. The
//! byte-level matcher here ([`glob_match`]: `*` within a segment, `?` for
//! one byte, `**` across segments, full-path match) is the single matcher
//! for `files()` patterns and bookmark/tag short-name patterns until a
//! shared facility lands.
//!
//! Bloom chunks are prefilter only: a [`BloomMatch::DefinitelyNo`] on the
//! pattern's literal directory prefix skips the commit; every other commit
//! is verified by a real tree diff (child tree(s) versus parent tree(s))
//! read from the store. Commits whose trees cannot be flattened within the
//! entry/depth bounds fail the query with [`ErrorCode::ELimit`], never a
//! silent exclusion.
//!
//! # `attested()` wiring
//!
//! The query arrives as an [`AttestedQuery`] hook on the context — the same
//! seam as [`ExactPathVerifier`](crate::graph::types::ExactPathVerifier):
//! tests inject an in-memory map, production uses [`production_attested`],
//! which adapts [`crate::attestation::attested`] (open checkpoint; true when
//! at least one retained live-or-ambiguous statement matches) to the hook's
//! boolean shape. [`EvalContext::with_attestation`] builds that production
//! context; [`EvalContext::new`] leaves the hook unset. A query with no hook
//! configured is an explicit [`ErrorCode::ENotFound`] ("no attestation
//! source"), never a fake empty set. The hook carries no validity bound:
//! expiry-bounded land policy lives in the attestation query layer, not in
//! the revset grammar.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read as _;

use super::syntax::{AstArena, NodeId, NodeKind, RevsetAst, parse_str};
use crate::capability::{AttestKind, AttestResult};
use crate::change::{ChangeId, SessionId};
use crate::commit::CommitRecord;
use crate::error::{CoreError, ErrorCode};
use crate::graph::composite::GraphIndex;
use crate::graph::traversal::{AncestorStepper, find_heads, find_roots};
use crate::graph::types::{BloomMatch, Generation, GlobalPosition, PrefixResolution};
use crate::heads::Head;
use crate::ids::Oid;
use crate::protocol::{DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE};
use crate::records::reader::Records;
use crate::records::types::RecordPageBudget;
use crate::refdata::{RefName, RefTarget, resolve};
use crate::refs::{StoreRefs, page_refs};
use crate::store::Store;
use crate::store::types::ObjectKind;

/// Ref namespace owning bookmarks.
const BOOKMARKS_NS: &[u8] = b"refs/heads/";
/// Ref namespace owning remote bookmarks.
const REMOTES_NS: &[u8] = b"refs/remotes/";
/// Ref namespace owning tags.
const TAGS_NS: &[u8] = b"refs/tags/";

/// Rows per ref scan page.
const REF_SCAN_LIMIT: usize = 1000;
/// Rows per change scan page.
const CHANGE_SCAN_ROWS: usize = 256;
/// Bytes per change scan page.
const CHANGE_SCAN_BYTES: usize = 1024 * 1024;
/// Commits per ancestor stepper batch.
const ANCESTOR_BATCH: usize = 1000;
/// Flattened trees memoized per evaluation (correctness never depends on it).
const TREE_CACHE_CAP: usize = 256;
/// Largest flattened tree, in entries.
const MAX_TREE_ENTRIES: usize = 100_000;
/// Deepest tree walk, in levels.
const MAX_TREE_DEPTH: usize = 32;
/// Candidate names carried on ambiguity errors.
const MAX_CANDIDATES: usize = 8;
/// Opaque cursor tag.
const CURSOR_TAG: &str = "ruk-revset-v1:";

// ---------------------------------------------------------------------------
// Public (crate) surface
// ---------------------------------------------------------------------------

/// Decides whether a commit carries a retained verified statement matching
/// kind/result for `attested(kind,result)`.
///
/// Same seam as `ExactPathVerifier`: tests inject an in-memory map,
/// production injects [`production_attested`]. The subject is the exact
/// commit OID; Git heads only (conflicted heads have no OID subject and
/// never match).
pub(crate) type AttestedQuery<'a> =
    dyn Fn(&Store, &Oid, &AttestKind, &AttestResult) -> Result<bool, CoreError> + Send + Sync + 'a;

/// Production `attested(kind,result)` lookup over retained verified statements.
///
/// Adapts [`crate::attestation::attested`] to the [`AttestedQuery`] boolean
/// shape: true when at least one retained live-or-ambiguous statement
/// matches, false otherwise. Superseded statements never match; per-signer
/// ambiguity collapses to true here (the vector form keeps the detail for
/// land authorization). Runs under an open checkpoint: revset evaluation is
/// synchronous and unadmitted, so cancellation never fires.
pub(crate) fn production_attested(
    store: &Store,
    subject: &Oid,
    kind: &AttestKind,
    result: &AttestResult,
) -> Result<bool, CoreError> {
    let open = |_progress: crate::attestation::Progress| Ok::<(), CoreError>(());
    let retained = crate::attestation::attested(store, subject, kind, result, &open)?;
    Ok(!retained.is_empty())
}

/// Everything the evaluator needs that it must not look up itself.
///
/// The working-copy heads (`@` / `@-`), the `mine()` identity, the shallow
/// boundaries, and the attestation lookup arrive as parameters: the
/// evaluator never touches workspaces, sessions, or the attestation store
/// layout directly.
///
/// No `Debug` impl: [`GraphIndex`] and the query hook do not implement it.
pub(crate) struct EvalContext<'a> {
    /// Object, fact, and tree reads.
    pub(crate) store: &'a Store,
    /// Positions, parents, generations, prefix indexes, Bloom chunks.
    pub(crate) graph: &'a GraphIndex,
    /// Commits `@` denotes; `@-` denotes their parents.
    pub(crate) wc_heads: Vec<Head>,
    /// Provenance sessions `mine()` matches.
    pub(crate) mine_sessions: Vec<SessionId>,
    /// Shallow-boundary heads; ancestor walks touching one fail `E_SHALLOW`.
    pub(crate) shallow: Vec<Head>,
    /// Rows per page when the caller names no limit (`1..=1000`).
    pub(crate) default_limit: usize,
    /// `attested(kind,result)` lookup. `None` makes every `attested()`
    /// query an explicit error, never a fake empty set.
    pub(crate) attested_query: Option<&'a AttestedQuery<'a>>,
}

impl<'a> EvalContext<'a> {
    /// Builds a context with no working-copy heads, no identity, no shallow
    /// boundaries, no attestation lookup, and the protocol default page size.
    #[must_use]
    pub(crate) fn new(store: &'a Store, graph: &'a GraphIndex) -> Self {
        Self {
            store,
            graph,
            wc_heads: Vec::new(),
            mine_sessions: Vec::new(),
            shallow: Vec::new(),
            default_limit: DEFAULT_PAGE_SIZE,
            attested_query: None,
        }
    }

    /// Builds a production context: like [`EvalContext::new`], but
    /// `attested(kind,result)` resolves against stored verified statements
    /// through [`production_attested`]. The op that serves `log` and `query`
    /// builds its contexts here; tests needing isolation keep `new()` and
    /// inject their own hook.
    #[must_use]
    pub(crate) fn with_attestation(store: &'a Store, graph: &'a GraphIndex) -> Self {
        Self {
            store,
            graph,
            wc_heads: Vec::new(),
            mine_sessions: Vec::new(),
            shallow: Vec::new(),
            default_limit: DEFAULT_PAGE_SIZE,
            attested_query: Some(&production_attested),
        }
    }
}

/// An evaluated revset: positions in newest-first order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MatchSet {
    positions: Vec<GlobalPosition>,
}

impl MatchSet {
    /// Positions in newest-first order.
    #[must_use]
    pub(crate) fn positions(&self) -> &[GlobalPosition] {
        &self.positions
    }

    /// Number of matched commits.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.positions.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }

    /// Heads in result order.
    pub(crate) fn heads(&self, graph: &GraphIndex) -> Result<Vec<Head>, CoreError> {
        self.positions
            .iter()
            .map(|pos| graph.pos_to_head(*pos))
            .collect()
    }
}

/// Opaque resume position: an offset into one evaluation's newest-first
/// order. Bound to that order; the protocol layer owns durable cursors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RevsetCursor {
    offset: usize,
}

impl RevsetCursor {
    /// Renders the opaque wire form.
    #[must_use]
    pub(crate) fn to_opaque(self) -> Vec<u8> {
        format!("{CURSOR_TAG}{}", self.offset).into_bytes()
    }

    /// Parses the opaque wire form.
    pub(crate) fn from_opaque(bytes: &[u8]) -> Result<Self, CoreError> {
        let text = core::str::from_utf8(bytes)
            .map_err(|_| CoreError::new(ErrorCode::EInvalid, "revset cursor is not UTF-8"))?;
        let digits = text.strip_prefix(CURSOR_TAG).ok_or_else(|| {
            CoreError::new(ErrorCode::EInvalid, "revset cursor has the wrong tag")
        })?;
        let offset = digits.parse::<usize>().map_err(|_| {
            CoreError::new(ErrorCode::EInvalid, "revset cursor offset is not a number")
        })?;
        Ok(Self { offset })
    }
}

/// One bounded page of an evaluated revset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RevsetPage {
    /// Page positions in newest-first order.
    pub(crate) positions: Vec<GlobalPosition>,
    /// Page heads in newest-first order.
    pub(crate) heads: Vec<Head>,
    /// Total matches across all pages.
    pub(crate) total: usize,
    /// Cursor for the next page, or `None` at the end.
    pub(crate) next_cursor: Option<RevsetCursor>,
}

/// Parses `text` and returns its first page at the context default limit.
pub(crate) fn eval_str(ctx: &EvalContext<'_>, text: &str) -> Result<RevsetPage, CoreError> {
    let ast = parse_str(text)?;
    eval_page(ctx, &ast, None, None)
}

/// Evaluates `ast` to its full ordered match set (no paging).
pub(crate) fn evaluate(ctx: &EvalContext<'_>, ast: &RevsetAst) -> Result<MatchSet, CoreError> {
    let mut eval = Eval::new(ctx);
    let set = eval.node(ast.arena(), ast.root_id())?;
    eval.order(set)
}

/// Evaluates `ast` to one page: `limit` rows from `cursor` (both optional).
/// A limit above 1000 is refused, never clamped; zero is invalid.
pub(crate) fn eval_page(
    ctx: &EvalContext<'_>,
    ast: &RevsetAst,
    limit: Option<usize>,
    cursor: Option<&RevsetCursor>,
) -> Result<RevsetPage, CoreError> {
    let matched = evaluate(ctx, ast)?;
    let limit = resolve_limit(limit.unwrap_or(ctx.default_limit))?;
    let offset = cursor.map_or(0, |c| c.offset);
    let total = matched.len();
    let positions: Vec<GlobalPosition> = matched
        .positions()
        .iter()
        .skip(offset)
        .take(limit)
        .copied()
        .collect();
    let heads = positions
        .iter()
        .map(|pos| ctx.graph.pos_to_head(*pos))
        .collect::<Result<Vec<Head>, CoreError>>()?;
    let next_cursor = if offset.saturating_add(limit) < total {
        Some(RevsetCursor {
            offset: offset.saturating_add(limit),
        })
    } else {
        None
    };
    Ok(RevsetPage {
        positions,
        heads,
        total,
        next_cursor,
    })
}

/// Validates a page limit against the protocol bound.
fn resolve_limit(limit: usize) -> Result<usize, CoreError> {
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!("revset page limit {limit} is outside 1..={MAX_PAGE_SIZE}"),
        ));
    }
    Ok(limit)
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// One index-prefix outcome: absent, exactly one, or ambiguous.
enum IndexHit<T> {
    None,
    One(T),
    Ambiguous,
}

impl<T> IndexHit<T> {
    /// Whether this category participates in symbol resolution.
    fn present(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// One evaluation with lazy caches (children map, ref index, tree cache).
/// The AST is threaded explicitly so cache fills never fight borrows.
struct Eval<'a> {
    ctx: &'a EvalContext<'a>,
    records: Records<'a>,
    children: Option<Vec<Vec<GlobalPosition>>>,
    ref_index: Option<RefIndex>,
    tree_cache: HashMap<Oid, BTreeMap<Vec<u8>, Vec<u8>>>,
}

/// One ref with its resolved target OID, if any (unborn symbolic refs and
/// non-commit targets resolve to `None` and contribute no commits).
#[derive(Clone, Debug)]
struct IndexedRef {
    name: RefName,
    oid: Option<Oid>,
}

/// All refs, resolved once per evaluation.
#[derive(Clone, Debug, Default)]
struct RefIndex {
    entries: Vec<IndexedRef>,
}

impl<'a> Eval<'a> {
    fn new(ctx: &'a EvalContext<'a>) -> Self {
        Self {
            ctx,
            records: Records::new(ctx.store),
            children: None,
            ref_index: None,
            tree_cache: HashMap::new(),
        }
    }

    /// Orders a position set newest-first.
    fn order(&self, set: BTreeSet<GlobalPosition>) -> Result<MatchSet, CoreError> {
        let mut keyed: Vec<(Generation, GlobalPosition)> = Vec::with_capacity(set.len());
        for pos in set {
            keyed.push((self.ctx.graph.pos_to_generation(pos)?, pos));
        }
        keyed.sort_by(|a, b| b.cmp(a));
        Ok(MatchSet {
            positions: keyed.into_iter().map(|(_, pos)| pos).collect(),
        })
    }

    /// Every indexed position.
    fn universe(&self) -> BTreeSet<GlobalPosition> {
        let total = self.ctx.graph.num_total_commits();
        (0..total).map(GlobalPosition::from_raw_checked).collect()
    }

    /// Positions for heads, failing closed when a head is not indexed.
    fn heads_to_positions(
        &self,
        heads: &[Head],
        what: &str,
    ) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        let mut out = BTreeSet::new();
        for head in heads {
            let Some(pos) = self.ctx.graph.head_to_pos(head) else {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    format!("{what} head {} is not indexed", head_hex(head)),
                ));
            };
            out.insert(pos);
        }
        Ok(out)
    }

    /// Children adjacency, built once per evaluation.
    fn children_map(&mut self) -> Result<&[Vec<GlobalPosition>], CoreError> {
        if self.children.is_none() {
            let total = self.ctx.graph.num_total_commits() as usize;
            let mut children: Vec<Vec<GlobalPosition>> = vec![Vec::new(); total];
            for raw in 0..self.ctx.graph.num_total_commits() {
                let pos = GlobalPosition::from_raw_checked(raw);
                for parent in self.ctx.graph.pos_to_parents(pos)? {
                    if let Some(list) = children.get_mut(parent.as_usize()) {
                        list.push(pos);
                    }
                }
            }
            self.children = Some(children);
        }
        self.children.as_deref().ok_or_else(|| {
            CoreError::new(
                ErrorCode::ECorrupt,
                "revset children map vanished after build",
            )
        })
    }

    /// Ref index, built once per evaluation.
    fn refs(&mut self) -> Result<&RefIndex, CoreError> {
        if self.ref_index.is_none() {
            let reader = StoreRefs::new(self.ctx.store);
            let mut entries = Vec::new();
            let mut after: Option<Vec<u8>> = None;
            loop {
                let page = page_refs(self.ctx.store, after.as_deref(), REF_SCAN_LIMIT)?;
                for entry in &page.entries {
                    let oid = match &entry.target {
                        RefTarget::Direct(oid) => Some(*oid),
                        RefTarget::Symbolic(name) => resolve(&reader, name)?.oid,
                    };
                    entries.push(IndexedRef {
                        name: entry.name.clone(),
                        oid,
                    });
                }
                if !page.more {
                    break;
                }
                let Some(last) = entries.last() else {
                    break;
                };
                after = Some(last.name.as_bytes().to_vec());
            }
            self.ref_index = Some(RefIndex { entries });
        }
        self.ref_index.as_ref().ok_or_else(|| {
            CoreError::new(ErrorCode::ECorrupt, "revset ref index vanished after build")
        })
    }

    // -- graph walks --------------------------------------------------------

    /// Ancestors (inclusive) with shallow fail-closure.
    fn ancestors_of(
        &self,
        seeds: &BTreeSet<GlobalPosition>,
    ) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        let mut out = BTreeSet::new();
        if seeds.is_empty() {
            return Ok(out);
        }
        let seed_vec: Vec<GlobalPosition> = seeds.iter().copied().collect();
        let shallow_opt = if self.ctx.shallow.is_empty() {
            None
        } else {
            Some(self.ctx.shallow.as_slice())
        };
        let graph = self.ctx.graph;
        let mut stepper = AncestorStepper::new(graph, &seed_vec, shallow_opt)?;
        let no_cancel = || false;
        let total = graph.num_total_commits() as usize;
        let max_steps = total.saturating_mul(2).saturating_add(1024).max(1024);
        loop {
            let page = stepper.step_batch(
                graph,
                ANCESTOR_BATCH,
                &no_cancel as &dyn Fn() -> bool,
                max_steps,
            )?;
            out.extend(page.positions.iter().copied());
            if stepper.hit_shallow() {
                return Err(CoreError::new(
                    ErrorCode::EShallow,
                    "revset ancestor walk reached a shallow boundary; completeness is unprovable",
                ));
            }
            if !page.has_more {
                break;
            }
        }
        Ok(out)
    }

    /// Descendants (inclusive) over the indexed children map; exact.
    fn descendants_of(
        &mut self,
        seeds: &BTreeSet<GlobalPosition>,
    ) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        let mut out = BTreeSet::new();
        if seeds.is_empty() {
            return Ok(out);
        }
        let mut stack: Vec<GlobalPosition> = seeds.iter().copied().collect();
        while let Some(pos) = stack.pop() {
            if !out.insert(pos) {
                continue;
            }
            let children = self.children_map()?;
            let fresh: Vec<GlobalPosition> =
                children.get(pos.as_usize()).map_or_else(Vec::new, |list| {
                    list.iter().copied().filter(|p| !out.contains(p)).collect()
                });
            stack.extend(fresh);
        }
        Ok(out)
    }

    // -- node evaluation ----------------------------------------------------

    fn node(
        &mut self,
        arena: &AstArena,
        id: NodeId,
    ) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        match &arena.node(id).kind {
            NodeKind::At => self.heads_to_positions(&self.ctx.wc_heads, "working-copy"),
            NodeKind::AtMinus => self.at_minus(),
            NodeKind::Symbol(sid) => {
                let text = arena.string(*sid).to_owned();
                self.resolve_symbol(&text)
            }
            NodeKind::StringLiteral(sid) => {
                let text = arena.string(*sid).to_owned();
                self.resolve_symbol(&text)
            }
            NodeKind::Session(sid) => {
                let prefix = arena.string(*sid).to_owned();
                self.session_prefix(&prefix)
            }
            NodeKind::Change(sid) => {
                let prefix = arena.string(*sid).to_owned();
                self.change_prefix(&prefix)
            }
            NodeKind::Description(sid) => {
                let needle = arena.string(*sid).to_owned();
                self.scan_records(|record| {
                    Ok(String::from_utf8_lossy(record.message()).contains(needle.as_str()))
                })
            }
            NodeKind::Files(sid) => {
                let glob = arena.string(*sid).to_owned();
                self.files_glob(&glob)
            }
            NodeKind::Attested { kind, result } => {
                let (kind_text, result_text) = (
                    arena.string(*kind).to_owned(),
                    arena.string(*result).to_owned(),
                );
                self.attested(&kind_text, &result_text)
            }
            NodeKind::Heads(inner) => {
                let members: Vec<GlobalPosition> = self.node(arena, *inner)?.into_iter().collect();
                Ok(find_heads(
                    self.ctx.graph,
                    &members,
                    &never_cancel(),
                    self.walk_budget(),
                )?
                .into_iter()
                .collect())
            }
            NodeKind::Roots(inner) => {
                let members: Vec<GlobalPosition> = self.node(arena, *inner)?.into_iter().collect();
                Ok(find_roots(
                    self.ctx.graph,
                    &members,
                    &never_cancel(),
                    self.walk_budget(),
                )?
                .into_iter()
                .collect())
            }
            NodeKind::Ancestors(inner) => {
                let set = self.node(arena, *inner)?;
                self.ancestors_of(&set)
            }
            NodeKind::Descendants(inner) => {
                let set = self.node(arena, *inner)?;
                self.descendants_of(&set)
            }
            NodeKind::Bookmarks(pattern) => {
                let pat = pattern_text(arena, *pattern)?;
                self.refs_in(BOOKMARKS_NS, pat.as_deref())
            }
            NodeKind::RemoteBookmarks(pattern) => {
                let pat = pattern_text(arena, *pattern)?;
                self.refs_in(REMOTES_NS, pat.as_deref())
            }
            NodeKind::Tags(pattern) => {
                let pat = pattern_text(arena, *pattern)?;
                self.refs_in(TAGS_NS, pat.as_deref())
            }
            NodeKind::Conflicted => self.conflicted(),
            NodeKind::Divergent => self.divergent(),
            NodeKind::Mine => self.mine(),
            NodeKind::Negate(inner) => {
                let set = self.node(arena, *inner)?;
                Ok(self.universe().difference(&set).copied().collect())
            }
            NodeKind::Intersection(left, right) => {
                let (l, r) = (self.node(arena, *left)?, self.node(arena, *right)?);
                Ok(l.intersection(&r).copied().collect())
            }
            NodeKind::Union(left, right) => {
                let (mut l, r) = (self.node(arena, *left)?, self.node(arena, *right)?);
                l.extend(r);
                Ok(l)
            }
            NodeKind::Difference(left, right) => {
                let (l, r) = (self.node(arena, *left)?, self.node(arena, *right)?);
                Ok(l.difference(&r).copied().collect())
            }
            NodeKind::DagRange(left, right) => {
                let (l, r) = (self.node(arena, *left)?, self.node(arena, *right)?);
                let (desc, anc) = (self.descendants_of(&l)?, self.ancestors_of(&r)?);
                Ok(desc.intersection(&anc).copied().collect())
            }
            NodeKind::Range(left, right) => {
                let (l, r) = (self.node(arena, *left)?, self.node(arena, *right)?);
                let (anc_l, anc_r) = (self.ancestors_of(&l)?, self.ancestors_of(&r)?);
                Ok(anc_r.difference(&anc_l).copied().collect())
            }
            NodeKind::Group(inner) => self.node(arena, *inner),
        }
    }

    /// Parents of the working-copy heads.
    fn at_minus(&self) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        let mut out = BTreeSet::new();
        for head in &self.ctx.wc_heads {
            let Some(pos) = self.ctx.graph.head_to_pos(head) else {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    format!("working-copy head {} is not indexed", head_hex(head)),
                ));
            };
            out.extend(self.ctx.graph.pos_to_parents(pos)?.iter().copied());
        }
        Ok(out)
    }

    /// Commits whose tagged head is conflicted.
    fn conflicted(&self) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        let mut out = BTreeSet::new();
        for raw in 0..self.ctx.graph.num_total_commits() {
            let pos = GlobalPosition::from_raw_checked(raw);
            if matches!(self.ctx.graph.pos_to_head(pos)?, Head::Conflicted { .. }) {
                out.insert(pos);
            }
        }
        Ok(out)
    }

    /// Commits whose provenance session is in the context identity.
    fn mine(&self) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        self.scan_records(|record| {
            Ok(record
                .provenance()
                .is_some_and(|prov| self.ctx.mine_sessions.contains(&prov.session())))
        })
    }

    /// Per-pair step budget for `find_heads` / `find_roots`.
    fn walk_budget(&self) -> usize {
        let total = self.ctx.graph.num_total_commits() as usize;
        total.saturating_mul(2).saturating_add(1024).max(1024)
    }

    // -- record scans ---------------------------------------------------------

    /// Commits whose record satisfies `test`. Missing records fail closed.
    fn scan_records(
        &self,
        test: impl Fn(&CommitRecord) -> Result<bool, CoreError>,
    ) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        let mut out = BTreeSet::new();
        for raw in 0..self.ctx.graph.num_total_commits() {
            let pos = GlobalPosition::from_raw_checked(raw);
            if test(&self.commit_record(pos)?)? {
                out.insert(pos);
            }
        }
        Ok(out)
    }

    /// Commit record for a position; a missing row fails closed, never skips.
    fn commit_record(&self, pos: GlobalPosition) -> Result<CommitRecord, CoreError> {
        let head = self.ctx.graph.pos_to_head(pos)?;
        self.records.get_commit(&head)?.ok_or_else(|| {
            CoreError::new(
                ErrorCode::ENotFound,
                format!("commit record for {} is not stored", head_hex(&head)),
            )
        })
    }

    // -- symbols ---------------------------------------------------------------

    /// Bare-symbol resolution across bookmark / tag / change / head
    /// categories with explicit ambiguity errors.
    fn resolve_symbol(&mut self, text: &str) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        if text.is_empty() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "empty revset symbol matches nothing",
            ));
        }
        let full_form = text.starts_with("refs/");
        let bookmarks = self.ref_hits(BOOKMARKS_NS, text, full_form)?;
        let tags = self.ref_hits(TAGS_NS, text, full_form)?;
        let remotes = if full_form {
            self.ref_hits(REMOTES_NS, text, true)?
        } else {
            Vec::new()
        };
        let change = self.change_hit(text)?;
        let head = self.head_hit(text)?;
        let mut categories = 0;
        if !bookmarks.is_empty() {
            categories += 1;
        }
        if !tags.is_empty() {
            categories += 1;
        }
        if !remotes.is_empty() {
            categories += 1;
        }
        if change.present() {
            categories += 1;
        }
        if head.present() {
            categories += 1;
        }
        if categories == 0 {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("revset symbol {text:?} matches no bookmark, tag, change, or commit"),
            ));
        }
        if categories > 1 {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "revset symbol {text:?} is ambiguous across categories: {}",
                    self.symbol_candidates(&bookmarks, &tags, &remotes, &change, &head)
                ),
            ));
        }
        if !bookmarks.is_empty() {
            return self.ref_hit_positions(&bookmarks, text, "bookmark");
        }
        if !tags.is_empty() {
            return self.ref_hit_positions(&tags, text, "tag");
        }
        if !remotes.is_empty() {
            return self.ref_hit_positions(&remotes, text, "remote bookmark");
        }
        match change {
            IndexHit::One(id) => self.change_id_positions(&id),
            IndexHit::Ambiguous => Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "revset change prefix {text:?} is ambiguous; the index reports \
                     multiple matches without candidates, so spell a longer prefix"
                ),
            )),
            IndexHit::None => match head {
                IndexHit::One(head) => self.heads_to_positions(&[head], "commit"),
                IndexHit::Ambiguous => Err(CoreError::new(
                    ErrorCode::EInvalid,
                    format!(
                        "revset commit prefix {text:?} is ambiguous; the index reports \
                         multiple matches without candidates, so spell a longer prefix"
                    ),
                )),
                IndexHit::None => Err(CoreError::new(
                    ErrorCode::ECorrupt,
                    "revset symbol resolution lost its only category",
                )),
            },
        }
    }

    /// Change-id prefix outcome for one symbol, via the index. The
    /// segment change-id table is emitted in reverse-hex ascending
    /// order, so the indexed binary search resolves prefixes directly.
    /// Empty-prefix semantics mirror the index (ambiguous whenever the
    /// graph is non-empty).
    fn change_hit(&self, text: &str) -> Result<IndexHit<ChangeId>, CoreError> {
        if text.is_empty() {
            return Ok(if self.ctx.graph.num_total_commits() == 0 {
                IndexHit::None
            } else {
                IndexHit::Ambiguous
            });
        }
        match self.ctx.graph.resolve_change_id_prefix(text)? {
            PrefixResolution::NoMatch => Ok(IndexHit::None),
            PrefixResolution::SingleMatch(id) => Ok(IndexHit::One(id)),
            PrefixResolution::AmbiguousMatch => Ok(IndexHit::Ambiguous),
        }
    }

    /// Head prefix outcome for one symbol (lowercase hex only).
    fn head_hit(&self, text: &str) -> Result<IndexHit<Head>, CoreError> {
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(IndexHit::None);
        }
        match self
            .ctx
            .graph
            .resolve_head_prefix(&text.to_ascii_lowercase())?
        {
            PrefixResolution::NoMatch => Ok(IndexHit::None),
            PrefixResolution::SingleMatch(head) => Ok(IndexHit::One(head)),
            PrefixResolution::AmbiguousMatch => Ok(IndexHit::Ambiguous),
        }
    }

    /// Ref entry indexes in `namespace` matching `text` (exact, else prefix).
    /// Full-form symbols (`refs/...`) match full names; short symbols match
    /// short names below the namespace.
    fn ref_hits(
        &mut self,
        namespace: &[u8],
        text: &str,
        full_form: bool,
    ) -> Result<Vec<usize>, CoreError> {
        let index = self.refs()?;
        let text_bytes = text.as_bytes();
        let mut exact = Vec::new();
        let mut prefix = Vec::new();
        for (idx, entry) in index.entries.iter().enumerate() {
            let full = entry.name.as_bytes();
            let Some(short) = full.strip_prefix(namespace) else {
                continue;
            };
            let candidate: &[u8] = if full_form { full } else { short };
            if candidate == text_bytes {
                exact.push(idx);
            } else if candidate.starts_with(text_bytes) {
                prefix.push(idx);
            }
        }
        if exact.is_empty() {
            Ok(prefix)
        } else {
            Ok(exact)
        }
    }

    /// Candidate listing for cross-category ambiguity errors.
    fn symbol_candidates(
        &mut self,
        bookmarks: &[usize],
        tags: &[usize],
        remotes: &[usize],
        change_hit: &IndexHit<ChangeId>,
        head_hit: &IndexHit<Head>,
    ) -> String {
        let mut names: Vec<String> = Vec::new();
        if let Ok(index) = self.refs() {
            for idx in bookmarks
                .iter()
                .chain(tags)
                .chain(remotes)
                .take(MAX_CANDIDATES)
            {
                if let Some(entry) = index.entries.get(*idx) {
                    names.push(String::from_utf8_lossy(entry.name.as_bytes()).into_owned());
                }
            }
        }
        if change_hit.present() {
            names.push("a change id with this prefix".to_owned());
        }
        if head_hit.present() {
            names.push("a commit id with this prefix".to_owned());
        }
        names.join(", ")
    }

    /// Positions for winning ref hits; unresolvable targets contribute
    /// nothing (unborn branches, non-commit targets).
    fn ref_hit_positions(
        &mut self,
        hits: &[usize],
        text: &str,
        what: &str,
    ) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        if hits.len() > 1 {
            let index = self.refs()?;
            let mut names: Vec<String> = hits
                .iter()
                .filter_map(|idx| index.entries.get(*idx))
                .take(MAX_CANDIDATES)
                .map(|entry| String::from_utf8_lossy(entry.name.as_bytes()).into_owned())
                .collect();
            names.sort();
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("revset {what} {text:?} is ambiguous: {}", names.join(", ")),
            ));
        }
        let oid = self
            .refs()?
            .entries
            .get(hits[0])
            .and_then(|entry| entry.oid);
        let mut out = BTreeSet::new();
        if let Some(oid) = oid
            && let Some(pos) = self.ctx.graph.head_to_pos(&Head::Git { oid })
        {
            out.insert(pos);
        }
        Ok(out)
    }

    /// All positions carrying `id` (paged; a change may own many heads).
    fn change_id_positions(&self, id: &ChangeId) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        let mut out = BTreeSet::new();
        let mut cursor = None;
        loop {
            let page = self.ctx.graph.change_id_to_positions_page(id, cursor, 64)?;
            out.extend(page.items.iter().copied());
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }

    /// `change(prefix)`: exactly one change id, then all its positions.
    fn change_prefix(&self, prefix: &str) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        match self.change_hit(prefix)? {
            IndexHit::One(id) => self.change_id_positions(&id),
            IndexHit::None => Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("revset change prefix {prefix:?} matches no change"),
            )),
            IndexHit::Ambiguous => Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("revset change prefix {prefix:?} is ambiguous; spell a longer prefix"),
            )),
        }
    }

    /// `session(prefix)`: exactly one provenance session, then its commits.
    /// Matches the canonical hyphenated UUID text and the hyphen-stripped
    /// form, case-insensitively.
    fn session_prefix(&self, prefix: &str) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        let folded = prefix.to_ascii_lowercase();
        let mut matching: BTreeMap<String, SessionId> = BTreeMap::new();
        for raw in 0..self.ctx.graph.num_total_commits() {
            let record = self.commit_record(GlobalPosition::from_raw_checked(raw))?;
            if let Some(prov) = record.provenance() {
                let session = prov.session();
                let text = session.to_string();
                if text.starts_with(&folded) || text.replace('-', "").starts_with(&folded) {
                    matching.insert(text, session);
                }
            }
        }
        if matching.is_empty() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("revset session prefix {prefix:?} matches no provenance session"),
            ));
        }
        if matching.len() > 1 {
            let mut names: Vec<String> = matching.keys().take(MAX_CANDIDATES).cloned().collect();
            names.sort();
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "revset session prefix {prefix:?} is ambiguous: {}",
                    names.join(", ")
                ),
            ));
        }
        let wanted = matching.values().next().expect("exactly one session");
        self.scan_records(|record| {
            Ok(record
                .provenance()
                .is_some_and(|prov| prov.session() == *wanted))
        })
    }

    // -- refs with patterns -----------------------------------------------------

    /// Target commits of refs under `namespace`, filtered by `pattern`
    /// against the short name (or the full name).
    fn refs_in(
        &mut self,
        namespace: &[u8],
        pattern: Option<&str>,
    ) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        let index = self.refs()?.clone();
        let mut out = BTreeSet::new();
        for entry in &index.entries {
            let full = entry.name.as_bytes();
            let Some(short) = full.strip_prefix(namespace) else {
                continue;
            };
            if let Some(pat) = pattern {
                let pat_bytes = pat.as_bytes();
                if !glob_match(pat_bytes, short) && !glob_match(pat_bytes, full) {
                    continue;
                }
            }
            if let Some(oid) = entry.oid
                && let Some(pos) = self.ctx.graph.head_to_pos(&Head::Git { oid })
            {
                out.insert(pos);
            }
        }
        Ok(out)
    }

    // -- divergence ---------------------------------------------------------------

    /// Head commits of changes with more than one current head. Heads not
    /// yet indexed contribute nothing (records may run ahead of the graph).
    fn divergent(&self) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        let mut out = BTreeSet::new();
        let mut after: Option<ChangeId> = None;
        loop {
            let page = self.records.page_changes(
                after.as_ref(),
                RecordPageBudget::new(CHANGE_SCAN_ROWS, CHANGE_SCAN_BYTES),
            )?;
            for (_, entry) in &page.items {
                if entry.is_divergent() {
                    for head in &entry.heads {
                        if let Some(pos) = self.ctx.graph.head_to_pos(head) {
                            out.insert(pos);
                        }
                    }
                }
            }
            if !page.more {
                break;
            }
            after = page.next_cursor;
            if after.is_none() {
                break;
            }
        }
        Ok(out)
    }

    // -- attestations ---------------------------------------------------------------

    /// Commits with a retained verified statement matching kind/result, via
    /// the injected query. Git heads only; conflicted heads have no OID
    /// subject and never match.
    fn attested(
        &self,
        kind_text: &str,
        result_text: &str,
    ) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        let kind = AttestKind::new(kind_text)?;
        let result = AttestResult::new(result_text)?;
        let Some(query) = self.ctx.attested_query else {
            return Err(CoreError::new(
                ErrorCode::ENotFound,
                "no attestation source: attested() needs an attestation query in the \
                 evaluation context (production: attestation::attested over the exact subject OID)",
            ));
        };
        let mut out = BTreeSet::new();
        for raw in 0..self.ctx.graph.num_total_commits() {
            let pos = GlobalPosition::from_raw_checked(raw);
            if let Head::Git { oid } = self.ctx.graph.pos_to_head(pos)?
                && query(self.ctx.store, &oid, &kind, &result)?
            {
                out.insert(pos);
            }
        }
        Ok(out)
    }

    // -- files ------------------------------------------------------------------------

    /// Commits whose changed paths match `glob`: Bloom prefilter on the
    /// literal directory prefix, then exact tree diff verification.
    fn files_glob(&mut self, glob: &str) -> Result<BTreeSet<GlobalPosition>, CoreError> {
        if glob.is_empty() {
            return Ok(BTreeSet::new());
        }
        let glob_bytes = glob.as_bytes();
        let literal_dir = literal_dir_prefix(glob_bytes);
        let mut out = BTreeSet::new();
        for raw in 0..self.ctx.graph.num_total_commits() {
            let pos = GlobalPosition::from_raw_checked(raw);
            if !literal_dir.is_empty() && self.bloom_negative(pos, &literal_dir)? {
                continue;
            }
            let head = self.ctx.graph.pos_to_head(pos)?;
            let record = self.commit_record(pos)?;
            let changed = self.commit_changed_paths(&head, &record)?;
            if changed.iter().any(|path| glob_match(glob_bytes, path)) {
                out.insert(pos);
            }
        }
        Ok(out)
    }

    /// True when the commit's Bloom chunk definitely excludes `path`.
    fn bloom_negative(&self, pos: GlobalPosition, path: &[u8]) -> Result<bool, CoreError> {
        let (segment, local) = self.ctx.graph.find_segment_for_pos(pos)?;
        Ok(segment.bloom_filter_candidate(local, path) == BloomMatch::DefinitelyNo)
    }

    /// Exact changed paths: child tree(s) versus parent tree(s).
    ///
    /// Single-tree commits diff per parent (root: whole tree). Commits with
    /// conflict (multi-term) trees compare the union of child terms against
    /// the union of parent terms — still a real content comparison, never
    /// Bloom-only.
    fn commit_changed_paths(
        &mut self,
        head: &Head,
        record: &CommitRecord,
    ) -> Result<BTreeSet<Vec<u8>>, CoreError> {
        let child_terms: Vec<Oid> = record.tree().iter().copied().collect();
        let mut parent_term_lists: Vec<Vec<Oid>> = Vec::new();
        for parent in record.parents() {
            let parent_record = self.records.get_commit(parent)?.ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ENotFound,
                    format!(
                        "commit record for parent {} of {} is not stored",
                        head_hex(parent),
                        head_hex(head)
                    ),
                )
            })?;
            parent_term_lists.push(parent_record.tree().iter().copied().collect());
        }
        let all_single =
            child_terms.len() == 1 && parent_term_lists.iter().all(|terms| terms.len() == 1);
        if all_single && !parent_term_lists.is_empty() {
            let child_map = self.flatten_tree(child_terms[0])?;
            let mut changed = BTreeSet::new();
            for terms in &parent_term_lists {
                changed.extend(symdiff(&child_map, &self.flatten_tree(terms[0])?));
            }
            return Ok(changed);
        }
        let mut child_union = BTreeMap::new();
        for term in &child_terms {
            child_union.extend(self.flatten_tree(*term)?);
        }
        if parent_term_lists.is_empty() {
            return Ok(child_union.into_keys().collect());
        }
        let mut parent_union = BTreeMap::new();
        for terms in &parent_term_lists {
            for term in terms {
                parent_union.extend(self.flatten_tree(*term)?);
            }
        }
        Ok(symdiff(&child_union, &parent_union))
    }

    /// Flattens a tree object to path → mode+id bytes, with memoization.
    fn flatten_tree(&mut self, root: Oid) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, CoreError> {
        if let Some(hit) = self.tree_cache.get(&root) {
            return Ok(hit.clone());
        }
        let map = self.flatten_tree_uncached(root)?;
        if self.tree_cache.len() < TREE_CACHE_CAP {
            self.tree_cache.insert(root, map.clone());
        }
        Ok(map)
    }

    /// Flattens a tree object without consulting the memo cache.
    fn flatten_tree_uncached(&self, root: Oid) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, CoreError> {
        let mut map = BTreeMap::new();
        let mut stack = vec![(Vec::new(), root, 0usize)];
        let mut steps = 0usize;
        while let Some((prefix, oid, depth)) = stack.pop() {
            if depth > MAX_TREE_DEPTH {
                return Err(CoreError::new(
                    ErrorCode::ELimit,
                    format!(
                        "revset files(): tree {} is deeper than {MAX_TREE_DEPTH}",
                        oid.to_hex()
                    ),
                ));
            }
            let bytes = read_tree_bytes(self.ctx.store, oid)?;
            for entry in parse_tree_entries(self.ctx.store.hash_kind(), &bytes, oid)? {
                steps += 1;
                if steps > MAX_TREE_ENTRIES {
                    return Err(CoreError::new(
                        ErrorCode::ELimit,
                        format!(
                            "revset files(): tree {} exceeds {MAX_TREE_ENTRIES} entries",
                            root.to_hex()
                        ),
                    ));
                }
                let mut path = prefix.clone();
                if !path.is_empty() {
                    path.push(b'/');
                }
                path.extend_from_slice(&entry.name);
                if entry.dir {
                    stack.push((path, entry.id, depth + 1));
                } else {
                    let mut value = entry.mode;
                    value.extend_from_slice(entry.id.as_bytes());
                    map.insert(path, value);
                }
            }
        }
        Ok(map)
    }
}

/// Cancellation predicate that never fires; evaluation is synchronous.
fn never_cancel() -> impl Fn() -> bool {
    || false
}

/// Optional string/symbol pattern argument of the bookmarks/tags functions.
fn pattern_text(arena: &AstArena, pattern: Option<NodeId>) -> Result<Option<String>, CoreError> {
    pattern
        .map(|id| match &arena.node(id).kind {
            NodeKind::StringLiteral(sid) | NodeKind::Symbol(sid) => {
                Ok(arena.string(*sid).to_owned())
            }
            other => Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("revset ref pattern must be a string literal, got {other:?}"),
            )),
        })
        .transpose()
}

// ---------------------------------------------------------------------------
// Tree objects
// ---------------------------------------------------------------------------

/// One parsed tree entry.
struct TreeEntry {
    name: Vec<u8>,
    mode: Vec<u8>,
    dir: bool,
    id: Oid,
}

/// Reads and validates a tree object's bytes.
fn read_tree_bytes(store: &Store, oid: Oid) -> Result<Vec<u8>, CoreError> {
    let object = store.read(oid)?;
    if object.kind != ObjectKind::Tree {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            format!("revset files(): object {} is not a tree", oid.to_hex()),
        ));
    }
    let mut bytes = Vec::new();
    object.bytes.view().read_to_end(&mut bytes).map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("revset files(): reading tree {}: {err}", oid.to_hex()),
        )
    })?;
    Ok(bytes)
}

/// Parses `mode SP name NUL id` entries at the store's hash width.
fn parse_tree_entries(
    kind: crate::ids::HashKind,
    bytes: &[u8],
    oid: Oid,
) -> Result<Vec<TreeEntry>, CoreError> {
    let corrupt = |detail: String| {
        CoreError::new(
            ErrorCode::ECorrupt,
            format!("revset files(): tree {}: {detail}", oid.to_hex()),
        )
    };
    let width = kind.oid_len();
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| corrupt("entry without a mode".to_owned()))?;
        let mode = &rest[..space];
        let dir = matches!(mode, b"40000" | b"040000");
        let blob = matches!(
            mode,
            b"100644" | b"100664" | b"100755" | b"120000" | b"160000"
        );
        if !dir && !blob {
            return Err(corrupt(format!(
                "unknown mode {}",
                String::from_utf8_lossy(mode)
            )));
        }
        let after_mode = &rest[space + 1..];
        let nul = after_mode
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| corrupt("unterminated name".to_owned()))?;
        let name = &after_mode[..nul];
        if name.is_empty() || name.contains(&b'/') {
            return Err(corrupt("invalid entry name".to_owned()));
        }
        let after_name = &after_mode[nul + 1..];
        if after_name.len() < width {
            return Err(corrupt("truncated object id".to_owned()));
        }
        let id = Oid::from_bytes(&after_name[..width]).map_err(CoreError::from)?;
        out.push(TreeEntry {
            name: name.to_vec(),
            mode: mode.to_vec(),
            dir,
            id,
        });
        rest = &after_name[width..];
    }
    Ok(out)
}

/// Symmetric content difference between two flattened trees.
fn symdiff(a: &BTreeMap<Vec<u8>, Vec<u8>>, b: &BTreeMap<Vec<u8>, Vec<u8>>) -> BTreeSet<Vec<u8>> {
    let mut out = BTreeSet::new();
    for (path, value) in a {
        if b.get(path) != Some(value) {
            out.insert(path.clone());
        }
    }
    for path in b.keys() {
        if !a.contains_key(path) {
            out.insert(path.clone());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Glob
// ---------------------------------------------------------------------------

/// Byte-level glob: `*` spans a segment, `?` is one byte, `**` spans
/// segments; the pattern must match the whole path. `[` is literal.
pub(crate) fn glob_match(pattern: &[u8], path: &[u8]) -> bool {
    if pattern.is_empty() || path.is_empty() {
        return false;
    }
    let patterns: Vec<&[u8]> = pattern.split(|&b| b == b'/').collect();
    let segments: Vec<&[u8]> = path.split(|&b| b == b'/').collect();
    match_segments(&patterns, &segments)
}

/// Matches pattern segments against path segments. A middle or leading `**`
/// spans zero or more segments; a trailing `/**` requires at least one more
/// segment, so `src/**` means "files under src/", never a root file named
/// `src` itself.
fn match_segments(patterns: &[&[u8]], segments: &[&[u8]]) -> bool {
    if patterns.is_empty() {
        return segments.is_empty();
    }
    if patterns[0] == b"**" {
        if patterns.len() == 1 {
            return !segments.is_empty();
        }
        return (0..=segments.len()).any(|skip| match_segments(&patterns[1..], &segments[skip..]));
    }
    if segments.is_empty() || !segment_match(patterns[0], segments[0]) {
        return false;
    }
    match_segments(&patterns[1..], &segments[1..])
}

/// Matches one pattern segment against one path segment.
fn segment_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut px, mut sx) = (0usize, 0usize);
    let (mut star, mut resume) = (None, 0usize);
    while sx < text.len() {
        if px < pattern.len() && (pattern[px] == b'?' || pattern[px] == text[sx]) {
            px += 1;
            sx += 1;
        } else if px < pattern.len() && pattern[px] == b'*' {
            star = Some(px);
            px += 1;
            resume = sx;
        } else if let Some(star_pos) = star {
            px = star_pos + 1;
            resume += 1;
            sx = resume;
        } else {
            return false;
        }
    }
    while px < pattern.len() && pattern[px] == b'*' {
        px += 1;
    }
    px == pattern.len()
}

/// Bloom prefilter path of a glob: the literal full path when the glob has
/// no wildcard at all (the filter holds exact paths, so this is the most
/// precise probe); otherwise the literal portion up to the first `*`/`?`,
/// cut at the last `/`. Empty when the glob starts wild.
fn literal_dir_prefix(glob: &[u8]) -> Vec<u8> {
    let Some(end) = glob.iter().position(|&b| b == b'*' || b == b'?') else {
        return glob.to_vec();
    };
    let head = &glob[..end];
    match head.iter().rposition(|&b| b == b'/') {
        Some(slash) => head[..slash].to_vec(),
        None => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Short hex rendering of a head for messages.
fn head_hex(head: &Head) -> String {
    match head {
        Head::Git { oid } => oid.to_hex(),
        Head::Conflicted { key } => key.to_hex(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::attestation::{ATTEST_NAMESPACE, Progress, prepare_add};
    use crate::budget::ByteBudget;
    use crate::bytes::ByteString;
    use crate::commit::{NativeCommitInput, Provenance, ProvenanceClaims};
    use crate::conflict::{Signature, TzOffset};
    use crate::graph::bloom::{build_bloom_filter, check_bloom_filter};
    use crate::graph::composite::GraphIndexBuilder;
    use crate::graph::types::BloomMatch;
    use crate::ids::{CommitKey, HashKind};
    use crate::merge::Merge;
    use crate::protocol::{AttestAddArgs, AttestSignature, AttestStatement, Timestamp};
    use crate::records::codec::{encode_change_entry, encode_commit_record};
    use crate::records::keys::{change_key, head_key};
    use crate::records::types::{ChangeEntry, ChangeState};
    use crate::store::types::{FactExpectation, FactMutation, FactTable, ObjectKind};
    use crate::store::{EventContext, EventSource, PreparationBudget, Store};
    use ssh_key::private::Ed25519Keypair;
    use ssh_key::{HashAlg, LineEnding};

    /// Scratch store; removed on drop.
    struct Scratch {
        root: std::path::PathBuf,
        store: Store,
        kind: HashKind,
    }

    impl Scratch {
        fn new(tag: &str, kind: HashKind) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "ruk-revset-test-{}-{}-{tag}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&root);
            let budget = Arc::new(PreparationBudget::reference_defaults());
            let store = Store::create(&root, kind, budget).expect("create test store");
            Self { root, store, kind }
        }

        fn publish_facts(&self, facts: &[FactMutation]) {
            self.store
                .publish(
                    Vec::new(),
                    facts,
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("publish facts");
        }

        fn publish_commits(&self, rows: &[(Head, CommitRecord)]) {
            let facts: Vec<FactMutation> = rows
                .iter()
                .map(|(head, record)| FactMutation {
                    table: FactTable::Commits,
                    key: head_key(head),
                    expected: FactExpectation::Absent,
                    value: Some(encode_commit_record(record).expect("encode commit")),
                })
                .collect();
            self.publish_facts(&facts);
        }

        fn publish_changes(&self, rows: &[(ChangeId, ChangeEntry)]) {
            let facts: Vec<FactMutation> = rows
                .iter()
                .map(|(id, entry)| FactMutation {
                    table: FactTable::Changes,
                    key: change_key(id).to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(encode_change_entry(entry).expect("encode change")),
                })
                .collect();
            self.publish_facts(&facts);
        }

        fn publish_ref(&self, name: &str, target: RefTarget) {
            let refname = RefName::new(name.as_bytes().to_vec()).expect("ref name");
            let bytes = postcard::to_allocvec(&target).expect("encode ref");
            self.publish_facts(&[FactMutation {
                table: FactTable::Refs,
                key: refname.as_bytes().to_vec(),
                expected: FactExpectation::Absent,
                value: Some(bytes),
            }]);
        }

        fn put_object(&self, kind: ObjectKind, bytes: Vec<u8>) -> Oid {
            let oid = match kind {
                ObjectKind::Blob => self.kind.hash_git_object("blob", &bytes).expect("blob oid"),
                ObjectKind::Tree => self.kind.hash_git_object("tree", &bytes).expect("tree oid"),
                _ => panic!("test helper stores blobs and trees only"),
            };
            let prepared = self
                .store
                .prepare(kind, bytes.len() as u64, std::io::Cursor::new(bytes), None)
                .expect("prepare object");
            self.store
                .publish(
                    vec![prepared],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("publish object");
            oid
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn sig() -> Signature {
        Signature {
            name: ByteString::from("t"),
            email: ByteString::from("t@example.com"),
            timestamp: 1_700_000_000,
            offset: TzOffset::new(false, 0).expect("tz"),
        }
    }

    fn make_record(
        kind: HashKind,
        change: [u8; 16],
        parents: Vec<Head>,
        tree: Oid,
        msg: &str,
        session: Option<SessionId>,
    ) -> (Head, CommitRecord) {
        let input = NativeCommitInput {
            change_id: ChangeId::from_bytes(change),
            tree: Merge::resolved(tree),
            parents,
            predecessor: None,
            author: sig(),
            committer: sig(),
            extra_headers: Vec::new(),
            message: ByteString::from(msg),
            provenance: session.map(|s| Provenance::new(s, ProvenanceClaims::default())),
        };
        let record = CommitRecord::create(input, kind).expect("record");
        let head = record.head().expect("head");
        (head, record)
    }

    /// Diamond plus one rewrite child: A(0) <- B(1) <- D(3), A <- C(2) <- D,
    /// B <- B2(4). Sessions: B and D carry S1, C carries S2.
    struct Diamond {
        scratch: Scratch,
        graph: GraphIndex,
        a: Head,
        b: Head,
        c: Head,
        d: Head,
        b2: Head,
        change_b: ChangeId,
        s1: SessionId,
        s2: SessionId,
    }

    impl Diamond {
        fn new() -> Self {
            let kind = HashKind::Sha1;
            let scratch = Scratch::new("diamond", kind);
            let tree = kind
                .hash_git_object("blob", b"fixture")
                .expect("tree stand-in");
            let s1 = SessionId::from_bytes([
                0x11, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ]);
            let s2 = SessionId::from_bytes([
                0x11, 0xFF, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ]);
            let change_b = ChangeId::from_bytes([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF,
            ]);
            let change_c = ChangeId::from_bytes([
                0x00, 0x33, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFE,
            ]);
            let (a, ra) = make_record(kind, [1; 16], vec![], tree, "root commit", None);
            let (b, rb) = make_record(
                kind,
                *change_b.as_bytes(),
                vec![a],
                tree,
                "feature work",
                Some(s1),
            );
            let (c, rc) = make_record(
                kind,
                *change_c.as_bytes(),
                vec![a],
                tree,
                "other work",
                Some(s2),
            );
            let (d, rd) = make_record(kind, [4; 16], vec![b, c], tree, "merge both", Some(s1));
            let (b2, rb2) = make_record(kind, [6; 16], vec![b], tree, "feature rewrite", None);
            scratch.publish_commits(&[(a, ra), (b, rb), (c, rc), (d, rd), (b2, rb2)]);
            let mut entry_b = ChangeEntry::new(ChangeState::Active, b);
            entry_b.add_head(b2).expect("divergent head");
            scratch.publish_changes(&[
                (
                    ChangeId::from_bytes([1; 16]),
                    ChangeEntry::new(ChangeState::Active, a),
                ),
                (change_b, entry_b),
                (change_c, ChangeEntry::new(ChangeState::Active, c)),
                (
                    ChangeId::from_bytes([4; 16]),
                    ChangeEntry::new(ChangeState::Active, d),
                ),
                (
                    ChangeId::from_bytes([6; 16]),
                    ChangeEntry::new(ChangeState::Active, b2),
                ),
            ]);
            scratch.publish_ref("refs/heads/main", RefTarget::Direct(git_oid(&d)));
            scratch.publish_ref("refs/heads/feat", RefTarget::Direct(git_oid(&b)));
            scratch.publish_ref("refs/heads/feat2", RefTarget::Direct(git_oid(&b2)));
            scratch.publish_ref("refs/heads/dup", RefTarget::Direct(git_oid(&b)));
            scratch.publish_ref(
                "refs/heads/alias",
                RefTarget::Symbolic(RefName::new(b"refs/heads/main".to_vec()).expect("name")),
            );
            scratch.publish_ref("refs/tags/v1", RefTarget::Direct(git_oid(&a)));
            scratch.publish_ref("refs/tags/dup", RefTarget::Direct(git_oid(&a)));
            scratch.publish_ref("refs/remotes/origin/main", RefTarget::Direct(git_oid(&c)));

            let mut builder = GraphIndexBuilder::new(GraphIndex::empty(kind));
            builder
                .add_commit(a, ChangeId::from_bytes([1; 16]), &[], vec![])
                .expect("add a");
            builder
                .add_commit(b, change_b, &[a], vec![])
                .expect("add b");
            builder
                .add_commit(c, change_c, &[a], vec![])
                .expect("add c");
            builder
                .add_commit(d, ChangeId::from_bytes([4; 16]), &[b, c], vec![])
                .expect("add d");
            builder
                .add_commit(b2, ChangeId::from_bytes([6; 16]), &[b], vec![])
                .expect("add b2");
            let graph = builder.finish(&ByteBudget::new(1 << 20)).expect("graph");
            Self {
                scratch,
                graph,
                a,
                b,
                c,
                d,
                b2,
                change_b,
                s1,
                s2,
            }
        }

        fn ctx(&self) -> EvalContext<'_> {
            EvalContext::new(&self.scratch.store, &self.graph)
        }
    }

    fn git_oid(head: &Head) -> Oid {
        match head {
            Head::Git { oid } => *oid,
            Head::Conflicted { .. } => panic!("expected git head"),
        }
    }

    fn heads_of(page: &RevsetPage) -> BTreeSet<Head> {
        page.heads.iter().copied().collect()
    }

    fn eval(page_ctx: &EvalContext<'_>, text: &str) -> RevsetPage {
        eval_str(page_ctx, text).expect("eval revset")
    }

    #[test]
    fn algebra_union_intersection_difference_negation() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        let feat = r#"description("feature work")"#;
        let other = r#"description("other work")"#;
        let union = eval(&ctx, &format!("{feat} | {other}"));
        assert_eq!(heads_of(&union), BTreeSet::from([fx.b, fx.c]));
        let inter = eval(&ctx, &format!("{feat} & {other}"));
        assert!(heads_of(&inter).is_empty());
        let diff = eval(&ctx, &format!("{feat} ~ {other}"));
        assert_eq!(heads_of(&diff), BTreeSet::from([fx.b]));
        let neg = eval(&ctx, r#"~description("root commit")"#);
        assert_eq!(heads_of(&neg), BTreeSet::from([fx.b, fx.c, fx.d, fx.b2]));
        let grouped = eval(&ctx, r#"((description("root commit")))"#);
        assert_eq!(heads_of(&grouped), BTreeSet::from([fx.a]));
        let ast = parse_str(&format!("{feat} & {other}")).expect("parse");
        let set = evaluate(&ctx, &ast).expect("evaluate");
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert!(set.positions().is_empty());
    }

    #[test]
    fn dag_range_and_range() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        let dag = eval(
            &ctx,
            r#"description("feature work")::description("merge both")"#,
        );
        assert_eq!(heads_of(&dag), BTreeSet::from([fx.b, fx.d]));
        let range = eval(
            &ctx,
            r#"description("root commit")..description("merge both")"#,
        );
        assert_eq!(heads_of(&range), BTreeSet::from([fx.b, fx.c, fx.d]));
        let empty_range = eval(
            &ctx,
            r#"description("merge both")..description("root commit")"#,
        );
        assert!(heads_of(&empty_range).is_empty());
    }

    #[test]
    fn heads_roots_ancestors_descendants() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        let all = r#"descendants(description("root commit"))"#;
        assert_eq!(eval(&ctx, all).total, 5);
        let heads = eval(&ctx, &format!("heads({all})"));
        assert_eq!(heads_of(&heads), BTreeSet::from([fx.d, fx.b2]));
        let roots = eval(&ctx, &format!("roots({all})"));
        assert_eq!(heads_of(&roots), BTreeSet::from([fx.a]));
        let anc = eval(&ctx, r#"ancestors(description("merge both"))"#);
        assert_eq!(heads_of(&anc), BTreeSet::from([fx.a, fx.b, fx.c, fx.d]));
        let desc = eval(&ctx, r#"descendants(description("feature work"))"#);
        assert_eq!(heads_of(&desc), BTreeSet::from([fx.b, fx.d, fx.b2]));
    }

    #[test]
    fn at_and_at_minus() {
        let fx = Diamond::new();
        let mut ctx = fx.ctx();
        ctx.wc_heads = vec![fx.d];
        assert_eq!(heads_of(&eval(&ctx, "@")), BTreeSet::from([fx.d]));
        assert_eq!(heads_of(&eval(&ctx, "@-")), BTreeSet::from([fx.b, fx.c]));
        let bare = fx.ctx();
        assert!(heads_of(&eval(&bare, "@")).is_empty());
        assert!(heads_of(&eval(&bare, "@-")).is_empty());
    }

    #[test]
    fn change_prefix_full_and_short() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        let full = fx.change_b.to_reverse_hex();
        assert_eq!(
            heads_of(&eval(&ctx, &format!("change({full})"))),
            BTreeSet::from([fx.b])
        );
        let short = &full[..8];
        assert_eq!(
            heads_of(&eval(&ctx, &format!("change({short})"))),
            BTreeSet::from([fx.b])
        );
        let missing = eval_str(&ctx, "change(zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz)");
        assert_eq!(
            missing.expect_err("no such change").code,
            ErrorCode::EInvalid
        );
    }

    #[test]
    fn head_prefix_resolves() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        let hex = head_hex(&fx.b);
        let page = eval(&ctx, &hex[..12]);
        assert_eq!(heads_of(&page), BTreeSet::from([fx.b]));
    }

    #[test]
    fn symbol_ambiguity_rejected() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        // B and C share first change-id byte 0x00, whose reverse-hex pair is "zz".
        let err = eval_str(&ctx, "zz").expect_err("ambiguous change prefix");
        assert_eq!(err.code, ErrorCode::EInvalid);
        // Bookmark and tag both named "dup".
        let err = eval_str(&ctx, "dup").expect_err("cross-category ambiguity");
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(
            err.message.contains("ambiguous"),
            "message names ambiguity: {err}"
        );
        // An exact bookmark wins over longer names sharing the prefix.
        assert_eq!(heads_of(&eval(&ctx, "feat")), BTreeSet::from([fx.b]));
        // A pure prefix of two bookmarks is ambiguous with candidates.
        let err = eval_str(&ctx, "fea").expect_err("same-namespace ambiguity");
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(
            err.message.contains("refs/heads/feat"),
            "candidates listed: {err}"
        );
    }

    #[test]
    fn symbol_not_found() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        let err = eval_str(&ctx, "no-such-thing-xyz").expect_err("unknown symbol");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn bookmarks_tags_remote_bookmarks_and_patterns() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        assert_eq!(
            heads_of(&eval(&ctx, "bookmarks()")),
            BTreeSet::from([fx.d, fx.b, fx.b2])
        );
        assert_eq!(
            heads_of(&eval(&ctx, r#"bookmarks("feat")"#)),
            BTreeSet::from([fx.b])
        );
        assert_eq!(
            heads_of(&eval(&ctx, r#"bookmarks("feat*")"#)),
            BTreeSet::from([fx.b, fx.b2])
        );
        assert_eq!(heads_of(&eval(&ctx, "tags()")), BTreeSet::from([fx.a]));
        assert_eq!(
            heads_of(&eval(&ctx, "remote_bookmarks()")),
            BTreeSet::from([fx.c])
        );
        assert_eq!(
            heads_of(&eval(&ctx, r#"remote_bookmarks("origin/*")"#)),
            BTreeSet::from([fx.c])
        );
        // Exact bookmark and symbolic alias both resolve.
        assert_eq!(heads_of(&eval(&ctx, "main")), BTreeSet::from([fx.d]));
        assert_eq!(heads_of(&eval(&ctx, "alias")), BTreeSet::from([fx.d]));
        // Non-string patterns are rejected, not silently matched.
        let mut headed = fx.ctx();
        headed.wc_heads = vec![fx.d];
        let err = eval_str(&headed, "bookmarks(heads(@))").expect_err("non-string pattern");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn conflicted_lists_conflicted_heads() {
        let kind = HashKind::Sha1;
        let scratch = Scratch::new("conflicted", kind);
        let tree = kind.hash_git_object("blob", b"fixture").expect("tree");
        let (a, _) = make_record(kind, [1; 16], vec![], tree, "root", None);
        let key = CommitKey::from_bytes(&[0xEE; 32]).expect("key");
        let conflicted = Head::Conflicted { key };
        let mut builder = GraphIndexBuilder::new(GraphIndex::empty(kind));
        builder
            .add_commit(a, ChangeId::from_bytes([1; 16]), &[], vec![])
            .expect("a");
        builder
            .add_commit(conflicted, ChangeId::from_bytes([2; 16]), &[a], vec![])
            .expect("e");
        let graph = builder.finish(&ByteBudget::new(1 << 20)).expect("graph");
        let ctx = EvalContext::new(&scratch.store, &graph);
        assert_eq!(
            heads_of(&eval(&ctx, "conflicted()")),
            BTreeSet::from([conflicted])
        );
        // Ancestor walks need no commit records.
        assert_eq!(
            heads_of(&eval(&ctx, "ancestors(conflicted())")),
            BTreeSet::from([a, conflicted])
        );
    }

    #[test]
    fn divergent_lists_multi_head_changes() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        assert_eq!(
            heads_of(&eval(&ctx, "divergent()")),
            BTreeSet::from([fx.b, fx.b2])
        );
    }

    #[test]
    fn mine_session_description() {
        let fx = Diamond::new();
        let mut ctx = fx.ctx();
        ctx.mine_sessions = vec![fx.s1];
        assert_eq!(
            heads_of(&eval(&ctx, "mine()")),
            BTreeSet::from([fx.b, fx.d])
        );
        let bare = fx.ctx();
        assert!(heads_of(&eval(&bare, "mine()")).is_empty());
        let s2_prefix = &fx.s2.to_string()[..8];
        assert_eq!(
            heads_of(&eval(&bare, &format!("session({s2_prefix})"))),
            BTreeSet::from([fx.c])
        );
        assert_eq!(
            heads_of(&eval(&bare, r#"description("feature")"#)),
            BTreeSet::from([fx.b, fx.b2])
        );
    }

    #[test]
    fn session_ambiguity_rejected() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        // Both fixture sessions share the "11" UUID prefix.
        let err = eval_str(&ctx, "session(11)").expect_err("ambiguous session");
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(
            err.message.contains("ambiguous"),
            "candidates listed: {err}"
        );
        let err = eval_str(&ctx, "session(00)").expect_err("unknown session");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn paged_ordering_and_cursor() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        let ast = parse_str(r#"descendants(description("root commit"))"#).expect("parse");
        let full = evaluate(&ctx, &ast).expect("evaluate");
        let ordered = full.heads(&fx.graph).expect("heads");
        assert_eq!(ordered, vec![fx.b2, fx.d, fx.c, fx.b, fx.a]);
        let first = eval_page(&ctx, &ast, Some(2), None).expect("page 1");
        assert_eq!(first.total, 5);
        assert_eq!(first.heads, vec![fx.b2, fx.d]);
        let cursor = first.next_cursor.expect("more pages");
        let second = eval_page(&ctx, &ast, Some(2), Some(&cursor)).expect("page 2");
        assert_eq!(second.heads, vec![fx.c, fx.b]);
        let cursor = second.next_cursor.expect("last page pending");
        let third = eval_page(&ctx, &ast, Some(2), Some(&cursor)).expect("page 3");
        assert_eq!(third.heads, vec![fx.a]);
        assert!(third.next_cursor.is_none());
    }

    #[test]
    fn cursor_opaque_roundtrip_and_reject() {
        let cursor = RevsetCursor { offset: 17 };
        let back = RevsetCursor::from_opaque(&cursor.to_opaque()).expect("roundtrip");
        assert_eq!(back, cursor);
        assert!(RevsetCursor::from_opaque(b"bogus").is_err());
        let fx = Diamond::new();
        let ctx = fx.ctx();
        let ast = parse_str("@").expect("parse");
        for bad in [Some(0), Some(1001)] {
            assert_eq!(
                eval_page(&ctx, &ast, bad, None)
                    .expect_err("bad limit")
                    .code,
                ErrorCode::EInvalid
            );
        }
    }

    #[test]
    fn shallow_ancestor_errors() {
        let fx = Diamond::new();
        let mut ctx = fx.ctx();
        ctx.shallow = vec![fx.b];
        let err = eval_str(&ctx, r#"ancestors(description("merge both"))"#)
            .expect_err("shallow boundary");
        assert_eq!(err.code, ErrorCode::EShallow);
        // Walks that never reach the boundary still succeed.
        let page = eval(&ctx, r#"ancestors(description("root commit"))"#);
        assert_eq!(heads_of(&page), BTreeSet::from([fx.a]));
    }

    #[test]
    fn glob_match_unit_table() {
        let cases: &[(&[u8], &[u8], bool)] = &[
            (b"main.rs", b"main.rs", true),
            (b"*.rs", b"main.rs", true),
            (b"*.rs", b"src/main.rs", false),
            (b"**/*.rs", b"src/main.rs", true),
            (b"**/*.rs", b"a/b/c/main.rs", true),
            (b"src/**", b"src/main.rs", true),
            (b"src/**", b"src", false),
            (b"src/**", b"other/main.rs", false),
            (b"src/*/main.rs", b"src/a/main.rs", true),
            (b"src/*/main.rs", b"src/a/b/main.rs", false),
            (b"?.rs", b"a.rs", true),
            (b"?.rs", b"ab.rs", false),
            (b"**", b"a/b/c", true),
            (b"", b"a", false),
            (b"a", b"", false),
        ];
        for (pattern, path, want) in cases {
            assert_eq!(
                glob_match(pattern, path),
                *want,
                "pattern {pattern:?} path {path:?}"
            );
        }
        assert_eq!(literal_dir_prefix(b"src/**/*.rs"), b"src");
        assert_eq!(literal_dir_prefix(b"*.rs"), b"");
        assert_eq!(literal_dir_prefix(b"src/main.rs"), b"src/main.rs");
    }

    /// Real tree objects: R0 has the empty tree, R1 adds five files under src/.
    struct FilesFx {
        scratch: Scratch,
        graph: GraphIndex,
        r1: Head,
        changed: Vec<Vec<u8>>,
    }

    impl FilesFx {
        fn new() -> Self {
            let kind = HashKind::Sha1;
            let scratch = Scratch::new("files", kind);
            let blob = |name: &[u8]| {
                let mut content = b"content of ".to_vec();
                content.extend_from_slice(name);
                scratch.put_object(ObjectKind::Blob, content)
            };
            let entry = |mode: &[u8], name: &[u8], id: &[u8]| {
                let mut out = Vec::new();
                out.extend_from_slice(mode);
                out.push(b' ');
                out.extend_from_slice(name);
                out.push(0);
                out.extend_from_slice(id);
                out
            };
            let files = [b"main.rs".as_slice(), b"lib.rs", b"a.rs", b"b.rs", b"c.rs"];
            let mut dir = Vec::new();
            let mut changed = Vec::new();
            for file in files {
                let blob_oid = blob(file);
                dir.extend_from_slice(&entry(b"100644", file, blob_oid.as_bytes()));
                let mut path = b"src/".to_vec();
                path.extend_from_slice(file);
                changed.push(path);
            }
            let dir_oid = scratch.put_object(ObjectKind::Tree, dir);
            let mut root = Vec::new();
            root.extend_from_slice(&entry(b"40000", b"src", dir_oid.as_bytes()));
            let root_oid = scratch.put_object(ObjectKind::Tree, root);
            let empty_oid = scratch.put_object(ObjectKind::Tree, Vec::new());
            let (r0, rr0) = make_record(kind, [0xA0; 16], vec![], empty_oid, "empty root", None);
            let (r1, rr1) = make_record(kind, [0xA1; 16], vec![r0], root_oid, "add src", None);
            scratch.publish_commits(&[(r0, rr0), (r1, rr1)]);
            let mut builder = GraphIndexBuilder::new(GraphIndex::empty(kind));
            builder
                .add_commit(r0, ChangeId::from_bytes([0xA0; 16]), &[], vec![])
                .expect("r0");
            builder
                .add_commit(r1, ChangeId::from_bytes([0xA1; 16]), &[r0], changed.clone())
                .expect("r1");
            let graph = builder.finish(&ByteBudget::new(1 << 20)).expect("graph");
            Self {
                scratch,
                graph,
                r1,
                changed,
            }
        }
    }

    /// A path the R1 Bloom chunk definitely excludes, found deterministically.
    fn bloom_negative_path(changed: &[Vec<u8>]) -> Vec<u8> {
        let refs: Vec<&[u8]> = changed.iter().map(Vec::as_slice).collect();
        let filter = build_bloom_filter(&refs);
        for i in 0..10_000u32 {
            let candidate = format!("unrelated-{i}.md").into_bytes();
            if check_bloom_filter(&filter, &candidate) == BloomMatch::DefinitelyNo {
                return candidate;
            }
        }
        panic!("no definitely-negative path found");
    }

    #[test]
    fn files_glob_with_bloom_and_tree_diff() {
        let fx = FilesFx::new();
        let ctx = EvalContext::new(&fx.scratch.store, &fx.graph);
        assert_eq!(
            heads_of(&eval(&ctx, r#"files("**/*.rs")"#)),
            BTreeSet::from([fx.r1])
        );
        assert_eq!(
            heads_of(&eval(&ctx, r#"files("src/**")"#)),
            BTreeSet::from([fx.r1])
        );
        assert_eq!(
            heads_of(&eval(&ctx, r#"files("src/main.rs")"#)),
            BTreeSet::from([fx.r1])
        );
        // Full-path semantics: a bare file name never matches nested paths.
        assert!(heads_of(&eval(&ctx, r#"files("main.rs")"#)).is_empty());
        // Bloom-negative commits skip the tree read entirely.
        let negative = bloom_negative_path(&fx.changed);
        let glob = String::from_utf8(negative).expect("ascii path");
        assert!(heads_of(&eval(&ctx, &format!(r#"files("{glob}")"#))).is_empty());
        assert!(heads_of(&eval(&ctx, r#"files("")"#)).is_empty());
    }

    #[test]
    fn attested_hook_and_missing_source() {
        let fx = Diamond::new();
        let ctx = fx.ctx();
        let err =
            eval_str(&ctx, r#"attested("review", "approved")"#).expect_err("no attestation source");
        assert_eq!(err.code, ErrorCode::ENotFound);
        assert!(
            err.message.contains("no attestation source"),
            "message: {err}"
        );

        let mut approvals: HashMap<(Oid, String, String), ()> = HashMap::new();
        approvals.insert(
            (git_oid(&fx.b), "review".to_owned(), "approved".to_owned()),
            (),
        );
        let query = |_store: &Store,
                     oid: &Oid,
                     kind: &AttestKind,
                     result: &AttestResult|
         -> Result<bool, CoreError> {
            Ok(approvals.contains_key(&(*oid, kind.to_string(), result.to_string())))
        };
        let hooked = EvalContext {
            store: &fx.scratch.store,
            graph: &fx.graph,
            wc_heads: Vec::new(),
            mine_sessions: Vec::new(),
            shallow: Vec::new(),
            default_limit: DEFAULT_PAGE_SIZE,
            attested_query: Some(&query),
        };
        assert_eq!(
            heads_of(&eval(&hooked, r#"attested("review", "approved")"#)),
            BTreeSet::from([fx.b])
        );
        assert!(heads_of(&eval(&hooked, r#"attested("review", "rejected")"#)).is_empty());
        let err = eval_str(&hooked, r#"attested("", "approved")"#).expect_err("bad kind");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn with_attestation_resolves_stored_verified_statements() {
        let kind = HashKind::Sha1;
        let scratch = Scratch::new("production-attested", kind);
        let body = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nproduction subject\n";
        let prepared = scratch
            .store
            .prepare(
                ObjectKind::Commit,
                u64::try_from(body.len()).expect("object length"),
                body.as_slice(),
                None,
            )
            .expect("store commit object");
        let oid = prepared.oid();
        scratch
            .store
            .publish(
                vec![prepared],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish commit");

        let private = ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[0x11; 32]));
        let statement = AttestStatement {
            subject: oid,
            kind: AttestKind::new("review").expect("kind"),
            result: AttestResult::new("pass").expect("result"),
            signed_at: Timestamp::parse("2026-10-17T12:00:00Z").expect("timestamp"),
            supersedes: None,
        };
        let payload = statement
            .canonical_payload_v1(kind)
            .expect("canonical payload");
        let armor = private
            .sign(ATTEST_NAMESPACE, HashAlg::Sha256, &payload)
            .expect("sign")
            .to_pem(LineEnding::LF)
            .expect("armor");
        let args = AttestAddArgs {
            statement,
            signature: AttestSignature::new(armor).expect("signature"),
        };
        let open = |_: Progress| Ok::<(), CoreError>(());
        let attestations = prepare_add(&scratch.store, &args, &open).expect("prepare attestation");
        scratch
            .store
            .publish(
                Vec::new(),
                &attestations.mutations,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish attestation");

        let review = AttestKind::new("review").expect("kind");
        let pass = AttestResult::new("pass").expect("result");
        let fail = AttestResult::new("fail").expect("result");
        assert!(production_attested(&scratch.store, &oid, &review, &pass).expect("query match"));
        assert!(
            !production_attested(&scratch.store, &oid, &review, &fail).expect("query mismatch")
        );

        let head = Head::Git { oid };
        let mut builder = GraphIndexBuilder::new(GraphIndex::empty(kind));
        builder
            .add_commit(head, ChangeId::from_bytes([7; 16]), &[], vec![])
            .expect("index commit");
        let graph = builder.finish(&ByteBudget::new(1 << 20)).expect("graph");
        let ctx = EvalContext::with_attestation(&scratch.store, &graph);
        assert_eq!(
            heads_of(&eval(&ctx, r#"attested("review", "pass")"#)),
            BTreeSet::from([head])
        );
        assert!(heads_of(&eval(&ctx, r#"attested("review", "fail")"#)).is_empty());
    }
}
