//! Builds the vendored tree-sitter-vue parser objects.
//!
//! Compiles `vendor/tree-sitter-vue/src/parser.c` and `src/scanner.c` as
//! C11 with the vendored `src/` include directory, so the audited
//! `tree_sitter_vue` symbol resolves for `merge::syntax::vue_ffi`. The
//! upstream `Cargo.toml` is deliberately unused: it pins tree-sitter
//! `~0.20.10`, outside the 0.27.1 ABI interval 13..=15.

fn main() {
    let vendor = std::path::Path::new("vendor/tree-sitter-vue/src");
    cc::Build::new()
        .std("c11")
        .include(vendor)
        .file(vendor.join("parser.c"))
        .file(vendor.join("scanner.c"))
        .warnings(false)
        .compile("tree_sitter_vue_vendored");

    println!(
        "cargo:rerun-if-changed={}",
        vendor.join("parser.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        vendor.join("scanner.c").display()
    );
    println!("cargo:rerun-if-changed={}", vendor.join("tag.h").display());
}
