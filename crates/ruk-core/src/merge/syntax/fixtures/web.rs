//! Web-language fixtures: JavaScript/JSX, TypeScript, TSX.

use super::{DeclineReason, Expectation, Fixture};
use crate::merge::syntax::grammar::Language;

#[must_use]
pub fn fixtures() -> Vec<Fixture> {
    vec![
        // JavaScript: opposite edits to distinct functions coexist.
        Fixture {
            language: Language::Javascript,
            name: "javascript/disjoint-funcs",
            base: "function a() {\n  return 1;\n}\nfunction b() {\n  return 2;\n}\n",
            ours: "function a() {\n  return 10;\n}\nfunction b() {\n  return 2;\n}\n",
            theirs: "function a() {\n  return 1;\n}\nfunction b() {\n  return 20;\n}\n",
            expect: Expectation::Merge(
                "function a() {\n  return 10;\n}\nfunction b() {\n  return 20;\n}\n",
            ),
        },
        // JavaScript: the same function edited on both sides declines.
        Fixture {
            language: Language::Javascript,
            name: "javascript/same-func",
            base: "function a() {\n  return 1;\n}\n",
            ours: "function a() {\n  return 2;\n}\n",
            theirs: "function a() {\n  return 3;\n}\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // JavaScript: a one-sided import addition lands without reordering.
        Fixture {
            language: Language::Javascript,
            name: "javascript/import-added",
            base: "import {x} from \"m\";\n\nexport function a() {\n  return 1;\n}\n",
            ours: "import {y} from \"n\";\nimport {x} from \"m\";\n\nexport function a() {\n  return 1;\n}\n",
            theirs: "import {x} from \"m\";\n\nexport function a() {\n  return 2;\n}\n",
            expect: Expectation::Merge(
                "import {y} from \"n\";\nimport {x} from \"m\";\n\nexport function a() {\n  return 2;\n}\n",
            ),
        },
        // JavaScript: competing same-gap import additions conflict.
        Fixture {
            language: Language::Javascript,
            name: "javascript/competing-imports",
            base: "export function a() {\n  return 1;\n}\n",
            ours: "import {y} from \"n\";\nexport function a() {\n  return 1;\n}\n",
            theirs: "import {z} from \"o\";\nexport function a() {\n  return 1;\n}\n",
            expect: Expectation::Decline(DeclineReason::CompetingInsertion),
        },
        // TypeScript: opposite edits to distinct interface members coexist.
        Fixture {
            language: Language::Typescript,
            name: "typescript/disjoint-members",
            base: "interface I {\n  a: string;\n  b: number;\n}\n",
            ours: "interface I {\n  a: number;\n  b: number;\n}\n",
            theirs: "interface I {\n  a: string;\n  b: string;\n}\n",
            expect: Expectation::Merge("interface I {\n  a: number;\n  b: string;\n}\n"),
        },
        // TypeScript: the same function edited on both sides declines.
        Fixture {
            language: Language::Typescript,
            name: "typescript/same-func",
            base: "export function f(x: string): number {\n  return 1;\n}\n",
            ours: "export function f(x: string): number {\n  return 2;\n}\n",
            theirs: "export function f(x: string): number {\n  return 3;\n}\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // TSX: opposite edits to distinct components coexist.
        Fixture {
            language: Language::Tsx,
            name: "tsx/disjoint-components",
            base: "export function A(): string {\n  return \"a\";\n}\nexport function B(): string {\n  return \"b\";\n}\n",
            ours: "export function A(): string {\n  return \"A\";\n}\nexport function B(): string {\n  return \"b\";\n}\n",
            theirs: "export function A(): string {\n  return \"a\";\n}\nexport function B(): string {\n  return \"B\";\n}\n",
            expect: Expectation::Merge(
                "export function A(): string {\n  return \"A\";\n}\nexport function B(): string {\n  return \"B\";\n}\n",
            ),
        },
        // TSX: a top-level JSX value is an ordered gap, never a unit.
        Fixture {
            language: Language::Tsx,
            name: "tsx/top-level-jsx-gap",
            base: "const el = <div />;\nfunction a() {\n  return 1;\n}\n",
            ours: "const el = <span />;\nfunction a() {\n  return 1;\n}\n",
            theirs: "const el = <div />;\nfunction a() {\n  return 2;\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
    ]
}
