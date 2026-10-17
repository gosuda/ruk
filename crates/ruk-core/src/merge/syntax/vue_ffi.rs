//! Audited FFI bridge to the vendored tree-sitter-vue parser.
//!
//! This module is the narrowly reviewed unsafe-code exception for exactly
//! one fixed linked function. It owns the `tree_sitter_vue` symbol
//! declaration over the vendored generated sources in
//! `crates/ruk-core/vendor/tree-sitter-vue/` and hands a single opaque
//! pointer to the parent-owned provider wiring, which converts it through
//! `tree-sitter-language::LanguageFn` and the checked
//! `Parser::set_language` gate. No raw parser pointer crosses the merge
//! API: [`merge_triplet`](super::alignment::merge_triplet) only ever sees
//! the [`Grammar`](super::grammar::Grammar) seam.
//!
//! Vendored source: `tree-sitter-grammars/tree-sitter-vue` at
//! `ce8011a414fdf8091f4e4071752efc376f4afb08` (MIT, Amaan Qureshi; license
//! retained verbatim in the vendor directory). The generated `parser.c`
//! declares `LANGUAGE_VERSION 15` and exports `const TSLanguage
//! *tree_sitter_vue(void)` (`TS_PUBLIC`, `parser.c:4383`). The upstream
//! Cargo wrapper is not used: it still depends on tree-sitter `~0.20.10`,
//! outside core 0.27.1's accepted ABI interval 13 through 15.
//!
//! Parent build integration (Slice 0 owns manifests and `build.rs`):
//!
//! * `[build-dependencies] cc = "=1.8.0"` in `crates/ruk-core/Cargo.toml`;
//! * compile `vendor/tree-sitter-vue/src/parser.c` and
//!   `vendor/tree-sitter-vue/src/scanner.c` through `cc::Build` with C11
//!   (`compiler.std("c11")`) and the vendored `src/` include directory
//!   (done by the crate `build.rs`);
//! * the workspace `unsafe_code` deny is discharged here with
//!   `#[expect(unsafe_code)]` on the two unsafe items; an inline
//!   `#[allow]` would trip the workspace `allow_attributes` deny;
//! * convert the pointer with the pinned `tree-sitter-language = "=0.1.9"`
//!   bridge and verify load through checked `set_language` plus the Vue
//!   readiness sample before readiness.
//!
//! Until the parent wires the C objects, calling [`vue_language_ptr`]
//! fails to link; nothing in this crate calls it, so the declaration alone
//! changes no build.

use tree_sitter_language::LanguageFn;

use crate::merge::syntax::grammar::Language;

/// Pinned upstream revision of the vendored Vue sources.
pub const VENDOR_REVISION: &str = "ce8011a414fdf8091f4e4071752efc376f4afb08";

/// Generated parser ABI declared by the vendored `parser.c`.
pub const VENDOR_ABI: u32 = 15;

/// The single fixed linked function this bridge owns.
pub const ENTRY_SYMBOL: &str = "tree_sitter_vue";

#[expect(
    unsafe_code,
    reason = "single audited extern declaration for the vendored Vue grammar"
)]
unsafe extern "C" {
    /// The vendored grammar's language entry point:
    /// `const TSLanguage *tree_sitter_vue(void)`.
    fn tree_sitter_vue() -> *const ();
}

/// The catalogued language this bridge serves.
#[must_use]
pub const fn language() -> Language {
    Language::Vue
}

/// Returns the opaque Vue language pointer for the parent-owned provider
/// wiring to convert through `tree-sitter-language::LanguageFn`.
///
/// The caller must convert the pointer immediately and never store or
/// dereference it: only the tree-sitter runtime may read the language
/// table, after the checked `set_language` gate accepts its ABI.
///
/// # Safety
///
/// This function is safe to call but links against the vendored C objects:
/// the caller (the parent build script) must link exactly
/// `vendor/tree-sitter-vue/src/parser.c` and `scanner.c` from
/// [`VENDOR_REVISION`] so the `tree_sitter_vue` symbol resolves to the
/// audited generated table. Calling without the linked objects is a
/// link-time failure, not undefined behavior; no caller obligation beyond
/// the documented conversion applies.
#[expect(
    unsafe_code,
    reason = "the only unsafe call site for the audited vendored Vue entry point"
)]
#[must_use]
pub fn vue_language_ptr() -> *const () {
    // SAFETY: `tree_sitter_vue` is the fixed `TS_PUBLIC` entry point of the
    // vendored generated parser, linked by the parent build script from the
    // exact pinned sources. It takes no arguments, touches no caller state,
    // and returns the grammar's static language table, which is valid for
    // the life of the process.
    unsafe { tree_sitter_vue() }
}

/// The vendored Vue grammar as a checked [`LanguageFn`] for provider
/// construction. This is the audited conversion point: the extern symbol
/// type already matches `LanguageFn`'s inner signature.
#[expect(
    unsafe_code,
    reason = "from_raw wraps the audited vendored grammar entry point"
)]
#[must_use]
pub fn vue_language_fn() -> LanguageFn {
    // SAFETY: `tree_sitter_vue` is the generated grammar entry point of the
    // pinned, vendored Vue parser sources compiled by build.rs; it is a
    // Tree-sitter CLI-generated language function, satisfying
    // `LanguageFn::from_raw`'s contract.
    unsafe { LanguageFn::from_raw(tree_sitter_vue) }
}
