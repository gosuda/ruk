//! Data and document fixtures: JSON, TOML, YAML, CSS, HTML.

use super::{DeclineReason, Expectation, Fixture};
use crate::merge::syntax::grammar::Language;

#[must_use]
pub fn fixtures() -> Vec<Fixture> {
    vec![
        // JSON: opposite edits to distinct members coexist; key order kept.
        Fixture {
            language: Language::Json,
            name: "json/disjoint-members",
            base: "{\"a\": 1, \"b\": 2}",
            ours: "{\"a\": 10, \"b\": 2}",
            theirs: "{\"a\": 1, \"b\": 20}",
            expect: Expectation::Merge("{\"a\": 10, \"b\": 20}"),
        },
        // JSON: the same member edited on both sides declines.
        Fixture {
            language: Language::Json,
            name: "json/same-member",
            base: "{\"a\": 1}",
            ours: "{\"a\": 2}",
            theirs: "{\"a\": 3}",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // JSON: duplicate literal keys decline unconditionally.
        Fixture {
            language: Language::Json,
            name: "json/duplicate-keys",
            base: "{\"a\": 1, \"a\": 2, \"c\": 0}",
            ours: "{\"a\": 1, \"a\": 2, \"c\": 1}",
            theirs: "{\"a\": 1, \"a\": 2, \"c\": 2}",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // JSON: opposite edits to distinct nested members merge by descent.
        Fixture {
            language: Language::Json,
            name: "json/nested-members",
            base: "{\"a\": {\"x\": 1, \"y\": 2}}",
            ours: "{\"a\": {\"x\": 10, \"y\": 2}}",
            theirs: "{\"a\": {\"x\": 1, \"y\": 20}}",
            expect: Expectation::Merge("{\"a\": {\"x\": 10, \"y\": 20}}"),
        },
        // JSON: arrays are positional; double changes decline.
        Fixture {
            language: Language::Json,
            name: "json/array-double-change",
            base: "{\"a\": [1, 2]}",
            ours: "{\"a\": [1, 3]}",
            theirs: "{\"a\": [1, 4]}",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // TOML: opposite edits to distinct pairs coexist.
        Fixture {
            language: Language::Toml,
            name: "toml/disjoint-pairs",
            base: "[t]\na = 1\nb = 2\n",
            ours: "[t]\na = 10\nb = 2\n",
            theirs: "[t]\na = 1\nb = 20\n",
            expect: Expectation::Merge("[t]\na = 10\nb = 20\n"),
        },
        // TOML: a dotted-key insertion lands beside a disjoint edit.
        Fixture {
            language: Language::Toml,
            name: "toml/dotted-insert",
            base: "[t]\na = 1\n",
            ours: "[t]\na = 1\nb.c = 2\n",
            theirs: "[t]\na = 10\n",
            expect: Expectation::Merge("[t]\na = 10\nb.c = 2\n"),
        },
        // TOML: duplicate tables decline unconditionally.
        Fixture {
            language: Language::Toml,
            name: "toml/duplicate-tables",
            base: "[t]\na = 1\n[t]\nb = 2\nc = 0\n",
            ours: "[t]\na = 1\n[t]\nb = 2\nc = 1\n",
            theirs: "[t]\na = 1\n[t]\nb = 2\nc = 2\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // TOML: repeated array-of-table sections merge when untouched; their
        // contents stay opaque gaps (this is the Cargo.lock shape).
        Fixture {
            language: Language::Toml,
            name: "toml/array-sections-untouched",
            base: "[t]\na = 1\nb = 2\n[[x]]\np = 1\n[[x]]\nq = 2\n",
            ours: "[t]\na = 10\nb = 2\n[[x]]\np = 1\n[[x]]\nq = 2\n",
            theirs: "[t]\na = 1\nb = 20\n[[x]]\np = 1\n[[x]]\nq = 2\n",
            expect: Expectation::Merge("[t]\na = 10\nb = 20\n[[x]]\np = 1\n[[x]]\nq = 2\n"),
        },
        // TOML: edited multiline string contents decline.
        Fixture {
            language: Language::Toml,
            name: "toml/multiline-string",
            base: "[t]\na = \"\"\"x\ny\"\"\"\nb = 1\n",
            ours: "[t]\na = \"\"\"x\nz\"\"\"\nb = 1\n",
            theirs: "[t]\na = \"\"\"x\ny\"\"\"\nb = 2\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // YAML: opposite edits to distinct pairs coexist.
        Fixture {
            language: Language::Yaml,
            name: "yaml/disjoint-pairs",
            base: "a: 1\nb: 2\n",
            ours: "a: 10\nb: 2\n",
            theirs: "a: 1\nb: 20\n",
            expect: Expectation::Merge("a: 10\nb: 20\n"),
        },
        // YAML: anchors and aliases decline the whole file.
        Fixture {
            language: Language::Yaml,
            name: "yaml/anchor-alias",
            base: "a: &x 1\nb: *x\n",
            ours: "a: &x 1\nb: 3\n",
            theirs: "a: &x 1\nb: 4\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // YAML: merge keys decline the whole file.
        Fixture {
            language: Language::Yaml,
            name: "yaml/merge-key",
            base: "<<: 1\nb: 2\n",
            ours: "<<: 1\nb: 3\n",
            theirs: "<<: 1\nb: 4\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // YAML: sequences are positional; double changes decline.
        Fixture {
            language: Language::Yaml,
            name: "yaml/sequence-double-change",
            base: "a:\n  - 1\n",
            ours: "a:\n  - 1\n  - 2\n",
            theirs: "a:\n  - 1\n  - 3\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // CSS: opposite edits to distinct rules coexist; order kept.
        Fixture {
            language: Language::Css,
            name: "css/disjoint-rules",
            base: ".a {\n  color: red;\n}\n.b {\n  margin: 0;\n}\n",
            ours: ".a {\n  color: blue;\n}\n.b {\n  margin: 0;\n}\n",
            theirs: ".a {\n  color: red;\n}\n.b {\n  margin: 1px;\n}\n",
            expect: Expectation::Merge(".a {\n  color: blue;\n}\n.b {\n  margin: 1px;\n}\n"),
        },
        // CSS: opposite edits to distinct declarations merge by descent.
        Fixture {
            language: Language::Css,
            name: "css/disjoint-declarations",
            base: ".a {\n  color: red;\n  margin: 0;\n}",
            ours: ".a {\n  color: blue;\n  margin: 0;\n}",
            theirs: ".a {\n  color: red;\n  margin: 1px;\n}",
            expect: Expectation::Merge(".a {\n  color: blue;\n  margin: 1px;\n}"),
        },
        // CSS: duplicate selectors with differing bytes decline.
        Fixture {
            language: Language::Css,
            name: "css/duplicate-selectors",
            base: ".a {\n  color: red;\n}\n.a {\n  color: blue;\n}\n.c {\n  x: 1;\n}\n",
            ours: ".a {\n  color: red;\n}\n.a {\n  color: blue;\n}\n.c {\n  x: 2;\n}\n",
            theirs: ".a {\n  color: red;\n}\n.a {\n  color: blue;\n}\n.c {\n  x: 3;\n}\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // CSS: insertions at distinct gaps keep document order, never sort.
        Fixture {
            language: Language::Css,
            name: "css/ordered-inserts",
            base: ".b {\n  margin: 0;\n}\n",
            ours: ".a {\n  color: red;\n}\n.b {\n  margin: 0;\n}\n",
            theirs: ".b {\n  margin: 0;\n}\n.c {\n  padding: 0;\n}\n",
            expect: Expectation::Merge(
                ".a {\n  color: red;\n}\n.b {\n  margin: 0;\n}\n.c {\n  padding: 0;\n}\n",
            ),
        },
        // HTML: opposite edits inside distinctly identified elements merge.
        Fixture {
            language: Language::Html,
            name: "html/disjoint-ids",
            base: "<div id=\"a\"><p>x</p></div>\n<div id=\"b\"><p>y</p></div>\n",
            ours: "<div id=\"a\"><p>X</p></div>\n<div id=\"b\"><p>y</p></div>\n",
            theirs: "<div id=\"a\"><p>x</p></div>\n<div id=\"b\"><p>Y</p></div>\n",
            expect: Expectation::Merge(
                "<div id=\"a\"><p>X</p></div>\n<div id=\"b\"><p>Y</p></div>\n",
            ),
        },
        // HTML: repeated sibling tags without stable ids decline.
        Fixture {
            language: Language::Html,
            name: "html/repeated-siblings",
            base: "<ul>\n  <li>x</li>\n  <li>y</li>\n</ul>\n<p>0</p>\n",
            ours: "<ul>\n  <li>x</li>\n  <li>y</li>\n</ul>\n<p>1</p>\n",
            theirs: "<ul>\n  <li>x</li>\n  <li>y</li>\n</ul>\n<p>2</p>\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // HTML: the same element edited on both sides declines.
        Fixture {
            language: Language::Html,
            name: "html/same-element",
            base: "<div id=\"a\"><p>x</p></div>\n",
            ours: "<div id=\"a\"><p>y</p></div>\n",
            theirs: "<div id=\"a\"><p>z</p></div>\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // HTML: a one-sided script edit carries opaquely, never delegated.
        Fixture {
            language: Language::Html,
            name: "html/script-opaque",
            base: "<div><p>x</p></div>\n<script>let a = 1;</script>\n",
            ours: "<div><p>x</p></div>\n<script>let a = 2;</script>\n",
            theirs: "<div><p>X</p></div>\n<script>let a = 1;</script>\n",
            expect: Expectation::Merge(
                "<div><p>X</p></div>\n<script>let a = 2;</script>\n",
            ),
        },
    ]
}
