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
        // JavaScript: opposite edits to distinct class methods coexist.
        Fixture {
            language: Language::Javascript,
            name: "javascript/disjoint-methods",
            base: "class C {\n  m1() {\n    return 1;\n  }\n  m2() {\n    return 2;\n  }\n}\n",
            ours: "class C {\n  m1() {\n    return 10;\n  }\n  m2() {\n    return 2;\n  }\n}\n",
            theirs: "class C {\n  m1() {\n    return 1;\n  }\n  m2() {\n    return 20;\n  }\n}\n",
            expect: Expectation::Merge(
                "class C {\n  m1() {\n    return 10;\n  }\n  m2() {\n    return 20;\n  }\n}\n",
            ),
        },
        // JavaScript: duplicate computed property names with differing bytes decline.
        Fixture {
            language: Language::Javascript,
            name: "javascript/computed-key",
            base: "class C {\n  [k]() {\n    return 1;\n  }\n  [k]() {\n    return 2;\n  }\n  f() {\n    return 0;\n  }\n}\n",
            ours: "class C {\n  [k]() {\n    return 1;\n  }\n  [k]() {\n    return 2;\n  }\n  f() {\n    return 1;\n  }\n}\n",
            theirs: "class C {\n  [k]() {\n    return 1;\n  }\n  [k]() {\n    return 2;\n  }\n  f() {\n    return 2;\n  }\n}\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
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
        // TypeScript: opposite edits to distinct functions coexist.
        Fixture {
            language: Language::Typescript,
            name: "typescript/disjoint-funcs",
            base: "export function a(): number {\n  return 1;\n}\nexport function b(): number {\n  return 2;\n}\n",
            ours: "export function a(): number {\n  return 10;\n}\nexport function b(): number {\n  return 2;\n}\n",
            theirs: "export function a(): number {\n  return 1;\n}\nexport function b(): number {\n  return 20;\n}\n",
            expect: Expectation::Merge(
                "export function a(): number {\n  return 10;\n}\nexport function b(): number {\n  return 20;\n}\n",
            ),
        },
        // TypeScript: competing same-gap import additions conflict.
        Fixture {
            language: Language::Typescript,
            name: "typescript/competing-imports",
            base: "export function a(): number {\n  return 1;\n}\n",
            ours: "import {y} from \"n\";\nexport function a(): number {\n  return 1;\n}\n",
            theirs: "import {z} from \"o\";\nexport function a(): number {\n  return 1;\n}\n",
            expect: Expectation::Decline(DeclineReason::CompetingInsertion),
        },
        // TypeScript: class overload signatures sharing keys with differing bytes decline.
        Fixture {
            language: Language::Typescript,
            name: "typescript/class-overloads",
            base: "class C {\n  m(x: string): string;\n  m(x: string): number;\n  f(): number {\n    return 0;\n  }\n}\n",
            ours: "class C {\n  m(x: string): string;\n  m(x: string): number;\n  f(): number {\n    return 1;\n  }\n}\n",
            theirs: "class C {\n  m(x: string): string;\n  m(x: string): number;\n  f(): number {\n    return 2;\n  }\n}\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
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
        // TSX: opposite edits to distinct class methods coexist.
        Fixture {
            language: Language::Tsx,
            name: "tsx/disjoint-methods",
            base: "class Page {\n  header(): string {\n    return \"h1\";\n  }\n  footer(): string {\n    return \"f1\";\n  }\n}\n",
            ours: "class Page {\n  header(): string {\n    return \"h2\";\n  }\n  footer(): string {\n    return \"f1\";\n  }\n}\n",
            theirs: "class Page {\n  header(): string {\n    return \"h1\";\n  }\n  footer(): string {\n    return \"f2\";\n  }\n}\n",
            expect: Expectation::Merge(
                "class Page {\n  header(): string {\n    return \"h2\";\n  }\n  footer(): string {\n    return \"f2\";\n  }\n}\n",
            ),
        },
        // TSX: competing same-gap import additions conflict.
        Fixture {
            language: Language::Tsx,
            name: "tsx/competing-imports",
            base: "export function A(): string {\n  return \"a\";\n}\n",
            ours: "import {y} from \"n\";\nexport function A(): string {\n  return \"a\";\n}\n",
            theirs: "import {z} from \"o\";\nexport function A(): string {\n  return \"a\";\n}\n",
            expect: Expectation::Decline(DeclineReason::CompetingInsertion),
        },
        // TSX: edits to sibling JSX elements in a list decline as non-unit gap changes.
        Fixture {
            language: Language::Tsx,
            name: "tsx/jsx-sibling-list",
            base: "const items = (\n  <ul>\n    <li>one</li>\n    <li>two</li>\n  </ul>\n);\n\nexport function A(): string {\n  return \"a\";\n}\n",
            ours: "const items = (\n  <ul>\n    <li>first</li>\n    <li>two</li>\n  </ul>\n);\n\nexport function A(): string {\n  return \"a\";\n}\n",
            theirs: "const items = (\n  <ul>\n    <li>one</li>\n    <li>two</li>\n  </ul>\n);\n\nexport function A(): string {\n  return \"b\";\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
    ]
}
