//! OCaml fixtures: implementation and interface.

use super::{DeclineReason, Expectation, Fixture};
use crate::merge::syntax::grammar::Language;

#[must_use]
pub fn fixtures() -> Vec<Fixture> {
    vec![
        // OCaml: opposite edits to distinct bindings coexist in order.
        Fixture {
            language: Language::Ocaml,
            name: "ocaml/disjoint-bindings",
            base: "let a = 1\nlet b = 2\n",
            ours: "let a = 10\nlet b = 2\n",
            theirs: "let a = 1\nlet b = 20\n",
            expect: Expectation::Merge("let a = 10\nlet b = 20\n"),
        },
        // OCaml: a mutually recursive group is one unit; edits to different
        // branches of the same group decline.
        Fixture {
            language: Language::Ocaml,
            name: "ocaml/and-group",
            base: "let rec f x = f x\nand g y = y\n",
            ours: "let rec f x = x\nand g y = y\n",
            theirs: "let rec f x = f x\nand g y = x\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // OCaml: shadowed bindings with differing bytes decline.
        Fixture {
            language: Language::Ocaml,
            name: "ocaml/shadowed",
            base: "let f = 1\nlet f = 2\nlet c = 0\n",
            ours: "let f = 1\nlet f = 2\nlet c = 1\n",
            theirs: "let f = 1\nlet f = 2\nlet c = 2\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // OCaml: one-sided edit yields the changed side byte-for-byte.
        Fixture {
            language: Language::Ocaml,
            name: "ocaml/one-sided",
            base: "let a = 1\n",
            ours: "let a = 2\n",
            theirs: "let a = 1\n",
            expect: Expectation::Merge("let a = 2\n"),
        },
        // OCaml: deletion on one side with an edit on the other declines.
        Fixture {
            language: Language::Ocaml,
            name: "ocaml/deleted-edited",
            base: "let a = 1\nlet b = 2\n",
            ours: "let b = 2\n",
            theirs: "let a = 10\nlet b = 2\n",
            expect: Expectation::Decline(DeclineReason::AmbiguousRename),
        },
        // OCaml interface: opposite edits to distinct specs coexist.
        Fixture {
            language: Language::OcamlInterface,
            name: "ocaml-interface/disjoint-specs",
            base: "val a : int\nval b : int\n",
            ours: "val a : string\nval b : int\n",
            theirs: "val a : int\nval b : string\n",
            expect: Expectation::Merge("val a : string\nval b : string\n"),
        },
        // OCaml interface: the same spec edited on both sides declines.
        Fixture {
            language: Language::OcamlInterface,
            name: "ocaml-interface/same-spec",
            base: "val a : int\n",
            ours: "val a : string\n",
            theirs: "val a : bool\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // OCaml interface: one-sided edit yields the changed side byte-for-byte.
        Fixture {
            language: Language::OcamlInterface,
            name: "ocaml-interface/one-sided",
            base: "val a : int\n",
            ours: "val a : string\n",
            theirs: "val a : int\n",
            expect: Expectation::Merge("val a : string\n"),
        },
        // OCaml interface: deletion on one side with an edit on the other declines.
        Fixture {
            language: Language::OcamlInterface,
            name: "ocaml-interface/deleted-edited",
            base: "val a : int\nval b : int\n",
            ours: "val b : int\n",
            theirs: "val a : string\nval b : int\n",
            expect: Expectation::Decline(DeclineReason::AmbiguousRename),
        },
        // OCaml interface: duplicate declarations with differing bytes decline.
        Fixture {
            language: Language::OcamlInterface,
            name: "ocaml-interface/duplicate-specs",
            base: "val a : int\nval a : string\nval c : int\n",
            ours: "val a : int\nval a : string\nval c : bool\n",
            theirs: "val a : int\nval a : string\nval c : float\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
    ]
}
