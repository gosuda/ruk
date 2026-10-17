//! Compiled-language fixtures: Rust, Go, C, C++, Java, C#, Kotlin, Swift.

use super::{DeclineReason, Expectation, Fixture};
use crate::merge::syntax::grammar::Language;

#[must_use]
pub fn fixtures() -> Vec<Fixture> {
    vec![
        // Rust: one-sided edit yields the changed side byte-for-byte.
        Fixture {
            language: Language::Rust,
            name: "rust/one-sided",
            base: "fn a() -> u32 {\n    1\n}\n",
            ours: "fn a() -> u32 {\n    2\n}\n",
            theirs: "fn a() -> u32 {\n    1\n}\n",
            expect: Expectation::Merge("fn a() -> u32 {\n    2\n}\n"),
        },
        // Rust: opposite edits to distinct items coexist in order.
        Fixture {
            language: Language::Rust,
            name: "rust/disjoint-items",
            base: "fn a() -> u32 {\n    1\n}\nfn b() -> u32 {\n    2\n}\n",
            ours: "fn a() -> u32 {\n    10\n}\nfn b() -> u32 {\n    2\n}\n",
            theirs: "fn a() -> u32 {\n    1\n}\nfn b() -> u32 {\n    20\n}\n",
            expect: Expectation::Merge("fn a() -> u32 {\n    10\n}\nfn b() -> u32 {\n    20\n}\n"),
        },
        // Rust: the same item edited on both sides declines.
        Fixture {
            language: Language::Rust,
            name: "rust/same-item",
            base: "fn a() -> u32 {\n    1\n}\n",
            ours: "fn a() -> u32 {\n    2\n}\n",
            theirs: "fn a() -> u32 {\n    3\n}\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // Rust: duplicate methods across impl blocks with differing bytes
        // decline even though the edited unit is unrelated.
        Fixture {
            language: Language::Rust,
            name: "rust/duplicate-impl-methods",
            base: "struct S;\nimpl S {\n    fn m(&self) -> u32 {\n        1\n    }\n}\nimpl S {\n    fn m(&self) -> u32 {\n        2\n    }\n}\nfn c() {}\n",
            ours: "struct S;\nimpl S {\n    fn m(&self) -> u32 {\n        1\n    }\n}\nimpl S {\n    fn m(&self) -> u32 {\n        2\n    }\n}\nfn c() {\n    1\n}\n",
            theirs: "struct S;\nimpl S {\n    fn m(&self) -> u32 {\n        1\n    }\n}\nimpl S {\n    fn m(&self) -> u32 {\n        2\n    }\n}\nfn c() {\n    2\n}\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // Rust: deletion on one side with an edit on the other declines.
        Fixture {
            language: Language::Rust,
            name: "rust/deleted-edited",
            base: "fn a() {}\nfn b() {}\n",
            ours: "fn b() {}\n",
            theirs: "fn a() {\n    1\n}\nfn b() {}\n",
            expect: Expectation::Decline(DeclineReason::AmbiguousRename),
        },
        // Rust: an unparseable side declines instead of merging.
        Fixture {
            language: Language::Rust,
            name: "rust/parse-error",
            base: "fn a() {}\nfn b() {}\n",
            ours: "fn a() {}\nfn b() {\n",
            theirs: "fn a() {\n    1\n}\nfn b() {}\n",
            expect: Expectation::Decline(DeclineReason::ParseFailed),
        },
        // Rust: NUL bytes are binary content and never parsed.
        Fixture {
            language: Language::Rust,
            name: "rust/binary-nul",
            base: "fn a() {}\n",
            ours: "fn a() {}\n\0",
            theirs: "fn a() {\n    1\n}\n",
            expect: Expectation::Decline(DeclineReason::BinaryContent),
        },
        // Rust: a macro-body edit is an opaque gap change and declines.
        Fixture {
            language: Language::Rust,
            name: "rust/macro-body",
            base: "fn a() {}\nmacro_rules! m {\n    () => {};\n}\n",
            ours: "fn a() {}\nmacro_rules! m {\n    ($x:expr) => {};\n}\n",
            theirs: "fn a() {\n    1\n}\nmacro_rules! m {\n    () => {};\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // Go: one-sided method edit carries.
        Fixture {
            language: Language::Go,
            name: "go/one-sided",
            base: "package p\n\nfunc A() int {\n\treturn 1\n}\n",
            ours: "package p\n\nfunc A() int {\n\treturn 2\n}\n",
            theirs: "package p\n\nfunc A() int {\n\treturn 1\n}\n",
            expect: Expectation::Merge("package p\n\nfunc A() int {\n\treturn 2\n}\n"),
        },
        // Go: a function and a type spec edited on opposite sides merge.
        Fixture {
            language: Language::Go,
            name: "go/disjoint-func-and-type",
            base: "package p\n\nfunc A() int {\n\treturn 1\n}\n\ntype T struct {\n\tX int\n}\n",
            ours: "package p\n\nfunc A() int {\n\treturn 10\n}\n\ntype T struct {\n\tX int\n}\n",
            theirs: "package p\n\nfunc A() int {\n\treturn 1\n}\n\ntype T struct {\n\tY int\n}\n",
            expect: Expectation::Merge(
                "package p\n\nfunc A() int {\n\treturn 10\n}\n\ntype T struct {\n\tY int\n}\n",
            ),
        },
        // Go: same-name methods on different receivers are distinct units.
        Fixture {
            language: Language::Go,
            name: "go/distinct-receivers",
            base: "package p\n\ntype S struct{}\ntype T struct{}\n\nfunc (s S) M() {}\n\nfunc (t T) M() {}\n",
            ours: "package p\n\ntype S struct{}\ntype T struct{}\n\nfunc (s S) M() {\n\ts.Hook()\n}\n\nfunc (t T) M() {}\n",
            theirs: "package p\n\ntype S struct{}\ntype T struct{}\n\nfunc (s S) M() {}\n\nfunc (t T) M() {\n\tt.Hook()\n}\n",
            expect: Expectation::Merge(
                "package p\n\ntype S struct{}\ntype T struct{}\n\nfunc (s S) M() {\n\ts.Hook()\n}\n\nfunc (t T) M() {\n\tt.Hook()\n}\n",
            ),
        },
        // Go: the same function edited on both sides declines.
        Fixture {
            language: Language::Go,
            name: "go/same-func",
            base: "package p\n\nfunc A() int {\n\treturn 1\n}\n",
            ours: "package p\n\nfunc A() int {\n\treturn 2\n}\n",
            theirs: "package p\n\nfunc A() int {\n\treturn 3\n}\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // C: one-sided function edit carries.
        Fixture {
            language: Language::C,
            name: "c/one-sided",
            base: "int a(void) {\n  return 1;\n}\n",
            ours: "int a(void) {\n  return 2;\n}\n",
            theirs: "int a(void) {\n  return 1;\n}\n",
            expect: Expectation::Merge("int a(void) {\n  return 2;\n}\n"),
        },
        // C: opposite edits to distinct functions coexist.
        Fixture {
            language: Language::C,
            name: "c/disjoint-funcs",
            base: "int a(void) {\n  return 1;\n}\nint b(void) {\n  return 2;\n}\n",
            ours: "int a(void) {\n  return 10;\n}\nint b(void) {\n  return 2;\n}\n",
            theirs: "int a(void) {\n  return 1;\n}\nint b(void) {\n  return 20;\n}\n",
            expect: Expectation::Merge(
                "int a(void) {\n  return 10;\n}\nint b(void) {\n  return 20;\n}\n",
            ),
        },
        // C: a preprocessor edit declines; units inside branches stay gaps.
        Fixture {
            language: Language::C,
            name: "c/preprocessor-branch",
            base: "#define X 1\n\nint a(void) {\n  return X;\n}\n",
            ours: "#define X 2\n\nint a(void) {\n  return X;\n}\n",
            theirs: "#define X 1\n\nint a(void) {\n  return X + 1;\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // C++: distinct overloads keyed by parameter spelling merge. The
        // one-sided change keeps the declaration shape: a declaration to
        // definition transition would be a delete plus an insert, which the
        // driver conservatively declines instead of pairing across kinds.
        Fixture {
            language: Language::Cpp,
            name: "cpp/distinct-overloads",
            base: "int f(int x);\nint f(double x);\nint g() {\n  return 0;\n}\n",
            ours: "int f(int x);\nint f(double x);\nint g() {\n  return 1;\n}\n",
            theirs: "long f(int x);\nint f(double x);\nint g() {\n  return 0;\n}\n",
            expect: Expectation::Merge(
                "long f(int x);\nint f(double x);\nint g() {\n  return 1;\n}\n",
            ),
        },
        // C++: the same overload edited on both sides declines.
        Fixture {
            language: Language::Cpp,
            name: "cpp/same-overload",
            base: "int f(int x) {\n  return x;\n}\n",
            ours: "int f(int x) {\n  return x + 1;\n}\n",
            theirs: "int f(int x) {\n  return x + 2;\n}\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // C++: a template-body edit declines; templates stay opaque.
        Fixture {
            language: Language::Cpp,
            name: "cpp/template-body",
            base: "template <typename T>\nT id(T x) {\n  return x;\n}\nint g() {\n  return 0;\n}\n",
            ours: "template <typename T>\nT id(T x) {\n  return T{};\n}\nint g() {\n  return 0;\n}\n",
            theirs: "template <typename T>\nT id(T x) {\n  return x;\n}\nint g() {\n  return 1;\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // Java: opposite edits to distinct methods coexist.
        Fixture {
            language: Language::Java,
            name: "java/disjoint-methods",
            base: "class C {\n  int m1() {\n    return 1;\n  }\n  int m2() {\n    return 2;\n  }\n}\n",
            ours: "class C {\n  int m1() {\n    return 10;\n  }\n  int m2() {\n    return 2;\n  }\n}\n",
            theirs: "class C {\n  int m1() {\n    return 1;\n  }\n  int m2() {\n    return 20;\n  }\n}\n",
            expect: Expectation::Merge(
                "class C {\n  int m1() {\n    return 10;\n  }\n  int m2() {\n    return 20;\n  }\n}\n",
            ),
        },
        // Java: overloads with different signatures are distinct units.
        Fixture {
            language: Language::Java,
            name: "java/distinct-overloads",
            base: "class C {\n  int f(int x) {\n    return x;\n  }\n  int f(String x) {\n    return 0;\n  }\n}\n",
            ours: "class C {\n  int f(int x) {\n    return x + 1;\n  }\n  int f(String x) {\n    return 0;\n  }\n}\n",
            theirs: "class C {\n  int f(int x) {\n    return x;\n  }\n  int f(String x) {\n    return 1;\n  }\n}\n",
            expect: Expectation::Merge(
                "class C {\n  int f(int x) {\n    return x + 1;\n  }\n  int f(String x) {\n    return 1;\n  }\n}\n",
            ),
        },
        // Java: the same method edited on both sides declines.
        Fixture {
            language: Language::Java,
            name: "java/same-method",
            base: "class C {\n  int m() {\n    return 1;\n  }\n}\n",
            ours: "class C {\n  int m() {\n    return 2;\n  }\n}\n",
            theirs: "class C {\n  int m() {\n    return 3;\n  }\n}\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // C#: opposite edits to distinct members coexist.
        Fixture {
            language: Language::CSharp,
            name: "csharp/disjoint-members",
            base: "class C {\n  int M1() {\n    return 1;\n  }\n  int M2() {\n    return 2;\n  }\n}\n",
            ours: "class C {\n  int M1() {\n    return 10;\n  }\n  int M2() {\n    return 2;\n  }\n}\n",
            theirs: "class C {\n  int M1() {\n    return 1;\n  }\n  int M2() {\n    return 20;\n  }\n}\n",
            expect: Expectation::Merge(
                "class C {\n  int M1() {\n    return 10;\n  }\n  int M2() {\n    return 20;\n  }\n}\n",
            ),
        },
        // C#: identical partial members with differing bytes decline.
        Fixture {
            language: Language::CSharp,
            name: "csharp/partial-duplicate",
            base: "partial class P {\n  int M() {\n    return 1;\n  }\n}\npartial class P {\n  int M() {\n    return 2;\n  }\n}\nclass H {\n  int V() {\n    return 0;\n  }\n}\n",
            ours: "partial class P {\n  int M() {\n    return 1;\n  }\n}\npartial class P {\n  int M() {\n    return 2;\n  }\n}\nclass H {\n  int V() {\n    return 1;\n  }\n}\n",
            theirs: "partial class P {\n  int M() {\n    return 1;\n  }\n}\npartial class P {\n  int M() {\n    return 2;\n  }\n}\nclass H {\n  int V() {\n    return 2;\n  }\n}\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // Kotlin: opposite edits to distinct functions coexist.
        Fixture {
            language: Language::Kotlin,
            name: "kotlin/disjoint-funcs",
            base: "fun a(): Int {\n  return 1\n}\nfun b(): Int {\n  return 2\n}\n",
            ours: "fun a(): Int {\n  return 10\n}\nfun b(): Int {\n  return 2\n}\n",
            theirs: "fun a(): Int {\n  return 1\n}\nfun b(): Int {\n  return 20\n}\n",
            expect: Expectation::Merge(
                "fun a(): Int {\n  return 10\n}\nfun b(): Int {\n  return 20\n}\n",
            ),
        },
        // Kotlin: the same function edited on both sides declines.
        Fixture {
            language: Language::Kotlin,
            name: "kotlin/same-func",
            base: "fun a(): Int {\n  return 1\n}\n",
            ours: "fun a(): Int {\n  return 2\n}\n",
            theirs: "fun a(): Int {\n  return 3\n}\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // Swift: opposite edits to distinct functions coexist.
        Fixture {
            language: Language::Swift,
            name: "swift/disjoint-funcs",
            base: "func a() -> Int {\n  return 1\n}\nfunc b() -> Int {\n  return 2\n}\n",
            ours: "func a() -> Int {\n  return 10\n}\nfunc b() -> Int {\n  return 2\n}\n",
            theirs: "func a() -> Int {\n  return 1\n}\nfunc b() -> Int {\n  return 20\n}\n",
            expect: Expectation::Merge(
                "func a() -> Int {\n  return 10\n}\nfunc b() -> Int {\n  return 20\n}\n",
            ),
        },
        // Swift: the same function edited on both sides declines.
        Fixture {
            language: Language::Swift,
            name: "swift/same-func",
            base: "func a() -> Int {\n  return 1\n}\n",
            ours: "func a() -> Int {\n  return 2\n}\n",
            theirs: "func a() -> Int {\n  return 3\n}\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // Rust: opposite edits to distinct methods in an impl block coexist.
        Fixture {
            language: Language::Rust,
            name: "rust/disjoint-impl-methods",
            base: "struct S;\nimpl S {\n    fn a(&self) -> u32 {\n        1\n    }\n    fn b(&self) -> u32 {\n        2\n    }\n}\n",
            ours: "struct S;\nimpl S {\n    fn a(&self) -> u32 {\n        10\n    }\n    fn b(&self) -> u32 {\n        2\n    }\n}\n",
            theirs: "struct S;\nimpl S {\n    fn a(&self) -> u32 {\n        1\n    }\n    fn b(&self) -> u32 {\n        20\n    }\n}\n",
            expect: Expectation::Merge(
                "struct S;\nimpl S {\n    fn a(&self) -> u32 {\n        10\n    }\n    fn b(&self) -> u32 {\n        20\n    }\n}\n",
            ),
        },
        // Rust: moving a method across impl blocks is a cross-boundary move.
        Fixture {
            language: Language::Rust,
            name: "rust/move-changed-key",
            base: "struct A;\nimpl A {\n    fn m(&self) -> u32 {\n        1\n    }\n}\nstruct B;\nimpl B {}\n",
            ours: "struct A;\nimpl A {}\nstruct B;\nimpl B {\n    fn m(&self) -> u32 {\n        1\n    }\n}\n",
            theirs: "struct A;\nimpl A {\n    fn m(&self) -> u32 {\n        2\n    }\n}\nstruct B;\nimpl B {}\n",
            expect: Expectation::Decline(DeclineReason::ChangedKey),
        },
        // Go: an import edit is an opaque gap change and declines.
        Fixture {
            language: Language::Go,
            name: "go/import-edit",
            base: "package p\n\nimport \"fmt\"\n\nfunc A() int {\n\treturn 1\n}\n",
            ours: "package p\n\nimport \"os\"\n\nfunc A() int {\n\treturn 1\n}\n",
            theirs: "package p\n\nimport \"fmt\"\n\nfunc A() int {\n\treturn 2\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // Go: duplicate methods on the same receiver with differing bytes decline.
        Fixture {
            language: Language::Go,
            name: "go/duplicate-receiver-methods",
            base: "package p\n\ntype S struct{}\n\nfunc (s S) M() int {\n\treturn 1\n}\nfunc (s S) M() int {\n\treturn 2\n}\nfunc A() int {\n\treturn 0\n}\n",
            ours: "package p\n\ntype S struct{}\n\nfunc (s S) M() int {\n\treturn 1\n}\nfunc (s S) M() int {\n\treturn 2\n}\nfunc A() int {\n\treturn 1\n}\n",
            theirs: "package p\n\ntype S struct{}\n\nfunc (s S) M() int {\n\treturn 1\n}\nfunc (s S) M() int {\n\treturn 2\n}\nfunc A() int {\n\treturn 2\n}\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // C: the same function edited on both sides declines.
        Fixture {
            language: Language::C,
            name: "c/same-func",
            base: "int a(void) {\n  return 1;\n}\n",
            ours: "int a(void) {\n  return 2;\n}\n",
            theirs: "int a(void) {\n  return 3;\n}\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // C: a macro-body edit is an opaque gap change and declines.
        Fixture {
            language: Language::C,
            name: "c/macro-body",
            base: "#define LIMIT 10\n\nint a(void) {\n  return 1;\n}\n",
            ours: "#define LIMIT 20\n\nint a(void) {\n  return 1;\n}\n",
            theirs: "#define LIMIT 10\n\nint a(void) {\n  return 2;\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // C++: one-sided function edit carries.
        Fixture {
            language: Language::Cpp,
            name: "cpp/one-sided",
            base: "int a() {\n  return 1;\n}\n",
            ours: "int a() {\n  return 2;\n}\n",
            theirs: "int a() {\n  return 1;\n}\n",
            expect: Expectation::Merge("int a() {\n  return 2;\n}\n"),
        },
        // C++: a macro-body edit declines; macro definitions stay opaque.
        Fixture {
            language: Language::Cpp,
            name: "cpp/macro-body",
            base: "#define LIMIT 10\n\nint a() {\n  return 1;\n}\n",
            ours: "#define LIMIT 20\n\nint a() {\n  return 1;\n}\n",
            theirs: "#define LIMIT 10\n\nint a() {\n  return 2;\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // Java: one-sided method edit carries.
        Fixture {
            language: Language::Java,
            name: "java/one-sided",
            base: "class C {\n  int m() {\n    return 1;\n  }\n}\n",
            ours: "class C {\n  int m() {\n    return 2;\n  }\n}\n",
            theirs: "class C {\n  int m() {\n    return 1;\n  }\n}\n",
            expect: Expectation::Merge("class C {\n  int m() {\n    return 2;\n  }\n}\n"),
        },
        // Java: an annotation edit on a class boundary is a gap change and declines.
        Fixture {
            language: Language::Java,
            name: "java/boundary-annotation",
            base: "class C {\n  int m() {\n    return 1;\n  }\n}\n",
            ours: "@Deprecated\nclass C {\n  int m() {\n    return 1;\n  }\n}\n",
            theirs: "class C {\n  int m() {\n    return 2;\n  }\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // C#: one-sided member edit carries.
        Fixture {
            language: Language::CSharp,
            name: "csharp/one-sided",
            base: "class C {\n  int M() {\n    return 1;\n  }\n}\n",
            ours: "class C {\n  int M() {\n    return 2;\n  }\n}\n",
            theirs: "class C {\n  int M() {\n    return 1;\n  }\n}\n",
            expect: Expectation::Merge("class C {\n  int M() {\n    return 2;\n  }\n}\n"),
        },
        // C#: distinct overloads keyed by parameter list merge.
        Fixture {
            language: Language::CSharp,
            name: "csharp/distinct-overloads",
            base: "class C {\n  int F(int x) {\n    return x;\n  }\n  int F(string x) {\n    return 0;\n  }\n}\n",
            ours: "class C {\n  int F(int x) {\n    return x + 1;\n  }\n  int F(string x) {\n    return 0;\n  }\n}\n",
            theirs: "class C {\n  int F(int x) {\n    return x;\n  }\n  int F(string x) {\n    return 1;\n  }\n}\n",
            expect: Expectation::Merge(
                "class C {\n  int F(int x) {\n    return x + 1;\n  }\n  int F(string x) {\n    return 1;\n  }\n}\n",
            ),
        },
        // C#: an attribute edit on an enclosing class is a gap change and declines.
        Fixture {
            language: Language::CSharp,
            name: "csharp/boundary-attribute",
            base: "class C {\n  int M() {\n    return 1;\n  }\n}\n",
            ours: "[System.Serializable]\nclass C {\n  int M() {\n    return 1;\n  }\n}\n",
            theirs: "class C {\n  int M() {\n    return 2;\n  }\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // Kotlin: one-sided function edit carries.
        Fixture {
            language: Language::Kotlin,
            name: "kotlin/one-sided",
            base: "fun a(): Int {\n  return 1\n}\n",
            ours: "fun a(): Int {\n  return 2\n}\n",
            theirs: "fun a(): Int {\n  return 1\n}\n",
            expect: Expectation::Merge("fun a(): Int {\n  return 2\n}\n"),
        },
        // Kotlin: same-name functions in different class scopes coexist.
        Fixture {
            language: Language::Kotlin,
            name: "kotlin/distinct-scopes",
            base: "class A {\n  fun m(): Int {\n    return 1\n  }\n}\nclass B {\n  fun m(): Int {\n    return 2\n  }\n}\n",
            ours: "class A {\n  fun m(): Int {\n    return 10\n  }\n}\nclass B {\n  fun m(): Int {\n    return 2\n  }\n}\n",
            theirs: "class A {\n  fun m(): Int {\n    return 1\n  }\n}\nclass B {\n  fun m(): Int {\n    return 20\n  }\n}\n",
            expect: Expectation::Merge(
                "class A {\n  fun m(): Int {\n    return 10\n  }\n}\nclass B {\n  fun m(): Int {\n    return 20\n  }\n}\n",
            ),
        },
        // Kotlin: moving a function between classes is a cross-scope move and declines.
        Fixture {
            language: Language::Kotlin,
            name: "kotlin/move-changed-key",
            base: "class A {\n  fun m(): Int {\n    return 1\n  }\n}\nclass B {}\n",
            ours: "class A {}\nclass B {\n  fun m(): Int {\n    return 1\n  }\n}\n",
            theirs: "class A {\n  fun m(): Int {\n    return 2\n  }\n}\nclass B {}\n",
            expect: Expectation::Decline(DeclineReason::ChangedKey),
        },
        // Kotlin: same-name extension functions on different types collide as duplicate keys.
        Fixture {
            language: Language::Kotlin,
            name: "kotlin/extension-duplicate",
            base: "fun String.ext(): Int {\n  return 1\n}\nfun Int.ext(): Int {\n  return 2\n}\nfun c(): Int {\n  return 0\n}\n",
            ours: "fun String.ext(): Int {\n  return 1\n}\nfun Int.ext(): Int {\n  return 2\n}\nfun c(): Int {\n  return 10\n}\n",
            theirs: "fun String.ext(): Int {\n  return 1\n}\nfun Int.ext(): Int {\n  return 2\n}\nfun c(): Int {\n  return 20\n}\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // Swift: one-sided function edit carries.
        Fixture {
            language: Language::Swift,
            name: "swift/one-sided",
            base: "func a() -> Int {\n  return 1\n}\n",
            ours: "func a() -> Int {\n  return 2\n}\n",
            theirs: "func a() -> Int {\n  return 1\n}\n",
            expect: Expectation::Merge("func a() -> Int {\n  return 2\n}\n"),
        },
        // Swift: same-name functions in different class scopes coexist.
        Fixture {
            language: Language::Swift,
            name: "swift/distinct-scopes",
            base: "class A {\n  func m() -> Int {\n    return 1\n  }\n}\nclass B {\n  func m() -> Int {\n    return 2\n  }\n}\n",
            ours: "class A {\n  func m() -> Int {\n    return 10\n  }\n}\nclass B {\n  func m() -> Int {\n    return 2\n  }\n}\n",
            theirs: "class A {\n  func m() -> Int {\n    return 1\n  }\n}\nclass B {\n  func m() -> Int {\n    return 20\n  }\n}\n",
            expect: Expectation::Merge(
                "class A {\n  func m() -> Int {\n    return 10\n  }\n}\nclass B {\n  func m() -> Int {\n    return 20\n  }\n}\n",
            ),
        },
        // Swift: duplicate methods across class and extension blocks with differing bytes decline.
        Fixture {
            language: Language::Swift,
            name: "swift/extension-duplicate",
            base: "class C {\n  func m() -> Int {\n    return 1\n  }\n}\nextension C {\n  func m() -> Int {\n    return 2\n  }\n}\nclass H {\n  func v() -> Int {\n    return 0\n  }\n}\n",
            ours: "class C {\n  func m() -> Int {\n    return 1\n  }\n}\nextension C {\n  func m() -> Int {\n    return 2\n  }\n}\nclass H {\n  func v() -> Int {\n    return 1\n  }\n}\n",
            theirs: "class C {\n  func m() -> Int {\n    return 1\n  }\n}\nextension C {\n  func m() -> Int {\n    return 2\n  }\n}\nclass H {\n  func v() -> Int {\n    return 2\n  }\n}\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
    ]
}
