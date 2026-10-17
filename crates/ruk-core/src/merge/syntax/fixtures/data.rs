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
            expect: Expectation::Merge("<div><p>X</p></div>\n<script>let a = 2;</script>\n"),
        },
        // JSON: one-sided edit yields the changed side byte-for-byte.
        Fixture {
            language: Language::Json,
            name: "json/one-sided",
            base: "{\n  \"name\": \"ruk\",\n  \"version\": 1\n}\n",
            ours: "{\n  \"name\": \"ruk\",\n  \"version\": 2\n}\n",
            theirs: "{\n  \"name\": \"ruk\",\n  \"version\": 1\n}\n",
            expect: Expectation::Merge("{\n  \"name\": \"ruk\",\n  \"version\": 2\n}\n"),
        },
        // JSON: array order is positional; distinct-unit edits merge cleanly.
        Fixture {
            language: Language::Json,
            name: "json/array-positional",
            base: "{\n  \"items\": [1, 2],\n  \"title\": \"old\"\n}\n",
            ours: "{\n  \"items\": [1, 2, 3],\n  \"title\": \"old\"\n}\n",
            theirs: "{\n  \"items\": [1, 2],\n  \"title\": \"new\"\n}\n",
            expect: Expectation::Merge("{\n  \"items\": [1, 2, 3],\n  \"title\": \"new\"\n}\n"),
        },
        // JSON: duplicate literal keys inserted on one side decline.
        Fixture {
            language: Language::Json,
            name: "json/duplicate-key-insert",
            base: "{\n  \"a\": 1,\n  \"b\": 2\n}\n",
            ours: "{\n  \"a\": 1,\n  \"a\": 3,\n  \"b\": 2\n}\n",
            theirs: "{\n  \"a\": 1,\n  \"b\": 20\n}\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // JSON: competing insertions into the same object gap decline.
        Fixture {
            language: Language::Json,
            name: "json/competing-insertions",
            base: "{\n  \"a\": 1,\n  \"b\": 2\n}\n",
            ours: "{\n  \"a\": 1,\n  \"x\": 10,\n  \"b\": 2\n}\n",
            theirs: "{\n  \"a\": 1,\n  \"y\": 20,\n  \"b\": 2\n}\n",
            expect: Expectation::Decline(DeclineReason::CompetingInsertion),
        },
        // TOML: one-sided edit yields the changed side byte-for-byte.
        Fixture {
            language: Language::Toml,
            name: "toml/one-sided",
            base: "[server]\nhost = \"127.0.0.1\"\nport = 8080\n",
            ours: "[server]\nhost = \"0.0.0.0\"\nport = 8080\n",
            theirs: "[server]\nhost = \"127.0.0.1\"\nport = 8080\n",
            expect: Expectation::Merge("[server]\nhost = \"0.0.0.0\"\nport = 8080\n"),
        },
        // TOML: opposite edits to distinct tables merge cleanly.
        Fixture {
            language: Language::Toml,
            name: "toml/disjoint-tables",
            base: "[server]\nport = 8080\n\n[client]\ntimeout = 30\n",
            ours: "[server]\nport = 9090\n\n[client]\ntimeout = 30\n",
            theirs: "[server]\nport = 8080\n\n[client]\ntimeout = 60\n",
            expect: Expectation::Merge("[server]\nport = 9090\n\n[client]\ntimeout = 60\n"),
        },
        // TOML: dotted-key and table header collisions decline.
        Fixture {
            language: Language::Toml,
            name: "toml/dotted-table-collision",
            base: "[a]\nx = 1\n",
            ours: "[a]\nx = 1\nb = 2\n\n[a.b]\ny = 3\n",
            theirs: "[a]\nx = 2\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // TOML: duplicate keys in the same table decline.
        Fixture {
            language: Language::Toml,
            name: "toml/duplicate-keys",
            base: "[t]\na = 1\nb = 2\n",
            ours: "[t]\na = 1\na = 3\nb = 2\n",
            theirs: "[t]\na = 1\nb = 20\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // TOML: array-of-table elements have no stable identity; edits decline.
        Fixture {
            language: Language::Toml,
            name: "toml/array-table-edit",
            base: "[meta]\nname = \"ruk\"\n\n[[items]]\nid = 1\n",
            ours: "[meta]\nname = \"ruk-core\"\n\n[[items]]\nid = 1\n",
            theirs: "[meta]\nname = \"ruk\"\n\n[[items]]\nid = 2\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // YAML: one-sided edit yields the changed side byte-for-byte.
        Fixture {
            language: Language::Yaml,
            name: "yaml/one-sided",
            base: "name: ruk\nversion: 1\n",
            ours: "name: ruk\nversion: 2\n",
            theirs: "name: ruk\nversion: 1\n",
            expect: Expectation::Merge("name: ruk\nversion: 2\n"),
        },
        // YAML: flow sequences inside distinct pairs merge cleanly.
        Fixture {
            language: Language::Yaml,
            name: "yaml/sequence-distinct-pair",
            base: "items: [1, 2]\nenabled: true\n",
            ours: "items: [1, 2, 3]\nenabled: true\n",
            theirs: "items: [1, 2]\nenabled: false\n",
            expect: Expectation::Merge("items: [1, 2, 3]\nenabled: false\n"),
        },
        // YAML: duplicate keys in a mapping decline.
        Fixture {
            language: Language::Yaml,
            name: "yaml/duplicate-keys",
            base: "a: 1\na: 2\nc: 0\n",
            ours: "a: 1\na: 2\nc: 1\n",
            theirs: "a: 1\na: 2\nc: 2\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // YAML: explicit type tags decline the whole file.
        Fixture {
            language: Language::Yaml,
            name: "yaml/tags",
            base: "a: !!str 1\nb: 2\n",
            ours: "a: !!str 1\nb: 3\n",
            theirs: "a: !!str 1\nb: 4\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // YAML: block scalars decline the whole file.
        Fixture {
            language: Language::Yaml,
            name: "yaml/block-scalar",
            base: "desc: |\n  line1\n  line2\nx: 1\n",
            ours: "desc: |\n  line1\n  line2\nx: 2\n",
            theirs: "desc: |\n  line1\n  line2\nx: 3\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // CSS: one-sided edit yields the changed side byte-for-byte.
        Fixture {
            language: Language::Css,
            name: "css/one-sided",
            base: ".btn {\n  color: #333;\n  padding: 8px;\n}\n",
            ours: ".btn {\n  color: #fff;\n  padding: 8px;\n}\n",
            theirs: ".btn {\n  color: #333;\n  padding: 8px;\n}\n",
            expect: Expectation::Merge(".btn {\n  color: #fff;\n  padding: 8px;\n}\n"),
        },
        // CSS: custom-property token streams in distinct declarations merge.
        Fixture {
            language: Language::Css,
            name: "css/custom-properties",
            base: ":root {\n  --primary: #00f;\n  --bg: #fff;\n}\n",
            ours: ":root {\n  --primary: #00c;\n  --bg: #fff;\n}\n",
            theirs: ":root {\n  --primary: #00f;\n  --bg: #eee;\n}\n",
            expect: Expectation::Merge(":root {\n  --primary: #00c;\n  --bg: #eee;\n}\n"),
        },
        // CSS: nested rules merge without reordering or losing cascade.
        Fixture {
            language: Language::Css,
            name: "css/nesting",
            base: ".card {\n  .header {\n    color: red;\n  }\n  .footer {\n    color: blue;\n  }\n}\n",
            ours: ".card {\n  .header {\n    color: darkred;\n  }\n  .footer {\n    color: blue;\n  }\n}\n",
            theirs: ".card {\n  .header {\n    color: red;\n  }\n  .footer {\n    color: darkblue;\n  }\n}\n",
            expect: Expectation::Merge(
                ".card {\n  .header {\n    color: darkred;\n  }\n  .footer {\n    color: darkblue;\n  }\n}\n",
            ),
        },
        // CSS: duplicate properties with differing values decline.
        Fixture {
            language: Language::Css,
            name: "css/duplicate-properties",
            base: ".card {\n  display: block;\n  display: flex;\n  color: red;\n}\n",
            ours: ".card {\n  display: block;\n  display: flex;\n  color: blue;\n}\n",
            theirs: ".card {\n  display: block;\n  display: flex;\n  color: green;\n}\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // CSS: competing insertions into the same rule gap decline.
        Fixture {
            language: Language::Css,
            name: "css/competing-inserts",
            base: ".a {\n  color: red;\n}\n.b {\n  color: blue;\n}\n",
            ours: ".a {\n  color: red;\n}\n.x {\n  color: purple;\n}\n.b {\n  color: blue;\n}\n",
            theirs: ".a {\n  color: red;\n}\n.y {\n  color: orange;\n}\n.b {\n  color: blue;\n}\n",
            expect: Expectation::Decline(DeclineReason::CompetingInsertion),
        },
        // HTML: one-sided edit yields the changed side byte-for-byte.
        Fixture {
            language: Language::Html,
            name: "html/one-sided",
            base: "<div id=\"app\">\n  <header><h1>Welcome</h1></header>\n</div>\n",
            ours: "<div id=\"app\">\n  <header><h1>Hello World</h1></header>\n</div>\n",
            theirs: "<div id=\"app\">\n  <header><h1>Welcome</h1></header>\n</div>\n",
            expect: Expectation::Merge(
                "<div id=\"app\">\n  <header><h1>Hello World</h1></header>\n</div>\n",
            ),
        },
        // HTML: opposite edits inside distinctly identified elements merge in order.
        Fixture {
            language: Language::Html,
            name: "html/disjoint-elements",
            base: "<h1 id=\"title\">Old</h1>\n<p id=\"desc\">Alpha</p>\n",
            ours: "<h1 id=\"title\">New</h1>\n<p id=\"desc\">Alpha</p>\n",
            theirs: "<h1 id=\"title\">Old</h1>\n<p id=\"desc\">Beta</p>\n",
            expect: Expectation::Merge("<h1 id=\"title\">New</h1>\n<p id=\"desc\">Beta</p>\n"),
        },
        // HTML: editing an outer element around inner units modifies a gap and declines.
        Fixture {
            language: Language::Html,
            name: "html/non-unit-gap",
            base: "<div class=\"old\">\n  <p id=\"a\">x</p>\n</div>\n",
            ours: "<div class=\"new\">\n  <p id=\"a\">x</p>\n</div>\n",
            theirs: "<div class=\"old\">\n  <p id=\"a\">y</p>\n</div>\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // HTML: competing insertions into the same sibling gap decline.
        Fixture {
            language: Language::Html,
            name: "html/competing-inserts",
            base: "<div id=\"a\"><p>x</p></div>\n<div id=\"b\"><p>y</p></div>\n",
            ours: "<div id=\"a\"><p>x</p></div>\n<div id=\"c\"><p>z</p></div>\n<div id=\"b\"><p>y</p></div>\n",
            theirs: "<div id=\"a\"><p>x</p></div>\n<div id=\"d\"><p>w</p></div>\n<div id=\"b\"><p>y</p></div>\n",
            expect: Expectation::Decline(DeclineReason::CompetingInsertion),
        },
    ]
}
