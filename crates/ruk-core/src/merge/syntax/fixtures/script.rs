//! Script-language fixtures: Python, Ruby, PHP, Bash, Lua.

use super::{DeclineReason, Expectation, Fixture};
use crate::merge::syntax::grammar::Language;

#[must_use]
pub fn fixtures() -> Vec<Fixture> {
    vec![
        // Python: opposite edits to distinct methods coexist with class context.
        Fixture {
            language: Language::Python,
            name: "python/disjoint-methods",
            base: "class C:\n    def m1(self):\n        return 1\n    def m2(self):\n        return 2\n",
            ours: "class C:\n    def m1(self):\n        return 10\n    def m2(self):\n        return 2\n",
            theirs: "class C:\n    def m1(self):\n        return 1\n    def m2(self):\n        return 20\n",
            expect: Expectation::Merge(
                "class C:\n    def m1(self):\n        return 10\n    def m2(self):\n        return 20\n",
            ),
        },
        // Python: the same function edited on both sides declines.
        Fixture {
            language: Language::Python,
            name: "python/same-func",
            base: "def f():\n    return 1\n",
            ours: "def f():\n    return 2\n",
            theirs: "def f():\n    return 3\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // Python: a decorator addition travels with its definition.
        Fixture {
            language: Language::Python,
            name: "python/decorator-added",
            base: "@dec\ndef f():\n    return 1\ndef g():\n    return 2\n",
            ours: "@dec\n@other\ndef f():\n    return 1\ndef g():\n    return 2\n",
            theirs: "@dec\ndef f():\n    return 1\ndef g():\n    return 20\n",
            expect: Expectation::Merge(
                "@dec\n@other\ndef f():\n    return 1\ndef g():\n    return 20\n",
            ),
        },
        // Python: moving a method to another class is a cross-boundary move.
        Fixture {
            language: Language::Python,
            name: "python/move-changed-key",
            base: "class A:\n    def m(self):\n        return 1\nclass B:\n    pass\n",
            ours: "class A:\n    pass\nclass B:\n    def m(self):\n        return 1\n",
            theirs: "class A:\n    def m(self):\n        return 2\nclass B:\n    pass\n",
            expect: Expectation::Decline(DeclineReason::ChangedKey),
        },
        // Python: duplicate definitions with differing bytes decline.
        Fixture {
            language: Language::Python,
            name: "python/duplicate-defs",
            base: "def f():\n    return 1\ndef f():\n    return 2\ndef g():\n    return 0\n",
            ours: "def f():\n    return 1\ndef f():\n    return 2\ndef g():\n    return 1\n",
            theirs: "def f():\n    return 1\ndef f():\n    return 2\ndef g():\n    return 2\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // Ruby: opposite edits to distinct methods coexist.
        Fixture {
            language: Language::Ruby,
            name: "ruby/disjoint-methods",
            base: "class C\n  def m1\n    1\n  end\n  def m2\n    2\n  end\nend\n",
            ours: "class C\n  def m1\n    10\n  end\n  def m2\n    2\n  end\nend\n",
            theirs: "class C\n  def m1\n    1\n  end\n  def m2\n    20\n  end\nend\n",
            expect: Expectation::Merge(
                "class C\n  def m1\n    10\n  end\n  def m2\n    20\n  end\nend\n",
            ),
        },
        // Ruby: the same method reopened in two blocks declines when touched.
        Fixture {
            language: Language::Ruby,
            name: "ruby/reopened-duplicate",
            base: "class C\n  def m\n    1\n  end\nend\nclass C\n  def m\n    2\n  end\nend\ndef g\n  0\nend\n",
            ours: "class C\n  def m\n    1\n  end\nend\nclass C\n  def m\n    2\n  end\nend\ndef g\n  1\nend\n",
            theirs: "class C\n  def m\n    1\n  end\nend\nclass C\n  def m\n    2\n  end\nend\ndef g\n  2\nend\n",
            expect: Expectation::Decline(DeclineReason::DuplicateKey),
        },
        // Ruby: the same method edited on both sides declines.
        Fixture {
            language: Language::Ruby,
            name: "ruby/same-method",
            base: "def m\n  1\nend\n",
            ours: "def m\n  2\nend\n",
            theirs: "def m\n  3\nend\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // PHP: opposite edits to distinct functions coexist across HTML.
        Fixture {
            language: Language::Php,
            name: "php/disjoint-funcs",
            base: "<?php\nfunction a(): int {\n  return 1;\n}\n?>\n<p>hi</p>\n<?php\nfunction b(): int {\n  return 2;\n}\n",
            ours: "<?php\nfunction a(): int {\n  return 10;\n}\n?>\n<p>hi</p>\n<?php\nfunction b(): int {\n  return 2;\n}\n",
            theirs: "<?php\nfunction a(): int {\n  return 1;\n}\n?>\n<p>hi</p>\n<?php\nfunction b(): int {\n  return 20;\n}\n",
            expect: Expectation::Merge(
                "<?php\nfunction a(): int {\n  return 10;\n}\n?>\n<p>hi</p>\n<?php\nfunction b(): int {\n  return 20;\n}\n",
            ),
        },
        // PHP: a unit crossing a PHP/template boundary declines.
        Fixture {
            language: Language::Php,
            name: "php/template-crossing",
            base: "<?php\nfunction a() {\n?>\n<p>x</p>\n<?php\n  return 1;\n}\nfunction b() {\n  return 2;\n}\n",
            ours: "<?php\nfunction a() {\n?>\n<p>x</p>\n<?php\n  return 10;\n}\nfunction b() {\n  return 2;\n}\n",
            theirs: "<?php\nfunction a() {\n?>\n<p>x</p>\n<?php\n  return 1;\n}\nfunction b() {\n  return 20;\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // Bash: opposite edits to distinct functions coexist.
        Fixture {
            language: Language::Bash,
            name: "bash/disjoint-funcs",
            base: "foo() {\n  echo 1\n}\nbar() {\n  echo 2\n}\n",
            ours: "foo() {\n  echo 10\n}\nbar() {\n  echo 2\n}\n",
            theirs: "foo() {\n  echo 1\n}\nbar() {\n  echo 20\n}\n",
            expect: Expectation::Merge("foo() {\n  echo 10\n}\nbar() {\n  echo 20\n}\n"),
        },
        // Bash: the same function edited on both sides declines.
        Fixture {
            language: Language::Bash,
            name: "bash/same-func",
            base: "foo() {\n  echo 1\n}\n",
            ours: "foo() {\n  echo 2\n}\n",
            theirs: "foo() {\n  echo 3\n}\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
        // Bash: a function with a heredoc carries opaquely one-sided,
        // exercising the external scanner without splitting the body.
        Fixture {
            language: Language::Bash,
            name: "bash/heredoc-carry",
            base: "#!/usr/bin/env bash\nfoo() {\n  cat <<EOF\nhello\nEOF\n}\nbar() {\n  echo 1\n}\n",
            ours: "#!/usr/bin/env bash\nfoo() {\n  cat <<EOF\nhello\nEOF\n}\nbar() {\n  echo 2\n}\n",
            theirs: "#!/usr/bin/env bash\nfoo() {\n  cat <<EOF\nworld\nEOF\n}\nbar() {\n  echo 1\n}\n",
            expect: Expectation::Merge(
                "#!/usr/bin/env bash\nfoo() {\n  cat <<EOF\nworld\nEOF\n}\nbar() {\n  echo 2\n}\n",
            ),
        },
        // Bash: a top-level command edit is an ordered gap change.
        Fixture {
            language: Language::Bash,
            name: "bash/top-level-command",
            base: "echo hi\nfoo() {\n  echo 1\n}\n",
            ours: "echo yo\nfoo() {\n  echo 1\n}\n",
            theirs: "echo hi\nfoo() {\n  echo 2\n}\n",
            expect: Expectation::Decline(DeclineReason::UnsupportedConstruct),
        },
        // Lua: opposite edits to distinct functions coexist.
        Fixture {
            language: Language::Lua,
            name: "lua/disjoint-funcs",
            base: "local function a()\n  return 1\nend\nlocal function b()\n  return 2\nend\n",
            ours: "local function a()\n  return 10\nend\nlocal function b()\n  return 2\nend\n",
            theirs: "local function a()\n  return 1\nend\nlocal function b()\n  return 20\nend\n",
            expect: Expectation::Merge(
                "local function a()\n  return 10\nend\nlocal function b()\n  return 20\nend\n",
            ),
        },
        // Lua: the same function edited on both sides declines.
        Fixture {
            language: Language::Lua,
            name: "lua/same-func",
            base: "local function a()\n  return 1\nend\n",
            ours: "local function a()\n  return 2\nend\n",
            theirs: "local function a()\n  return 3\nend\n",
            expect: Expectation::Decline(DeclineReason::SameUnitChanged),
        },
    ]
}
