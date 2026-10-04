import dataclasses

from checkride.astutils import FileContext
from checkride.config import RuleConfig
from checkride.rules import oversight


def run(src: str, config: RuleConfig | None = None, scope: str = "all"):
    """Rule mechanics are tested in scope "all" (every function with a sink
    is a tool), so a snippet needs no tool decorator to be judged. Tool-
    scope behavior has its own tests below and in test_callgraph.py."""
    config = dataclasses.replace(config or RuleConfig(), scope=scope)
    return oversight.check(FileContext.from_source(src, path="mem.py", config=config))


def test_unguarded_sensitive_call_fails():
    sites, passed, findings = run(
        "import shutil\n"
        "def wipe(path):\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)
    assert len(findings) == 1
    assert findings[0].line == 3
    assert "file delete" in findings[0].message
    assert findings[0].critical is True


def test_guard_clause_approval_passes():
    # The dangerous call is NOT inside the if -- guard-clause style.
    sites, passed, findings = run(
        "def wipe(path):\n"
        "    if not request_approval('wipe', path):\n"
        "        return\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_approval_decorator_passes():
    sites, passed, _ = run(
        "@requires_human_approval\n"
        "def wipe(path):\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 1)


def test_builtin_input_counts_as_oversight():
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    answer = input('really? ')\n"
        "    if answer == 'y':\n"
        "        shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 1)


def test_no_sensitive_calls_means_no_sites():
    sites, passed, findings = run("def add(a, b):\n    return a + b\n")
    assert (sites, passed, findings) == (0, 0, [])


def test_dead_approval_variable_no_longer_grants_a_false_pass():
    # Formerly a documented false pass: a name merely mentioning approval
    # vocabulary satisfied the rule even if nothing ever checked it. Fixed
    # by requiring an *enforcing position* (call, if/while/assert test, or
    # decorator) -- a bare assignment no one reads is none of those.
    sites, passed, findings = run(
        "def wipe(path):\n"
        "    approved = False\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)
    assert len(findings) == 1


def test_keyword_argument_named_like_approval_does_not_pass():
    # "require_approval=False" passed to an unrelated call used to satisfy
    # this rule on vocabulary alone (rule 6 catches the polarity). Only the
    # callee's own name counts now, not the names of its keyword arguments.
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    configure(require_approval=False)\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)


def test_if_test_with_unrelated_keyword_argument_does_not_pass():
    # Same bypass as test_keyword_argument_named_like_approval_does_not_pass,
    # but wrapped in an if -- the keyword name must not count just because
    # it now sits inside a test expression's subtree.
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    if configure(require_approval=False):\n"
        "        pass\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)


def test_if_test_naming_approval_passes():
    # The vocabulary sits in the if's *test*, not in a dead assignment --
    # an enforcing position even though the tested name is a bare Name,
    # not a call.
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    approved = check_policy()\n"
        "    if approved:\n"
        "        shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 1)


def test_assert_naming_approval_passes():
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    assert approved\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 1)


def test_aliased_import_sensitive_call_is_still_a_site():
    # The documented blind spot: `import subprocess as sp; sp.run(...)` used
    # to be invisible to the sensitive-call table entirely.
    sites, passed, findings = run(
        "import subprocess as sp\n"
        "def run_it(cmd):\n"
        "    sp.run(cmd, shell=True)\n"
    )
    assert (sites, passed) == (1, 0)
    assert "shell exec" in findings[0].message
    assert "subprocess.run" in findings[0].message


def test_aliased_import_sensitive_call_can_be_guarded():
    sites, passed, findings = run(
        "import subprocess as sp\n"
        "def run_it(cmd):\n"
        "    if not request_approval('run', cmd):\n"
        "        return\n"
        "    sp.run(cmd, shell=True)\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_extra_approval_marker_from_config_is_recognized():
    config = RuleConfig(approval_markers=("greenlight",))
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    if not greenlight(path):\n"
        "        return\n"
        "    shutil.rmtree(path)\n",
        config=config,
    )
    assert (sites, passed) == (1, 1)


# --- the approval signal must be in the SAME execution scope ---

def test_approval_in_an_unrelated_function_does_not_cover_a_module_level_call():
    # Critical-gate evasion: a module-level sink used to be checked against
    # the whole module tree, so any function anywhere in the file that
    # mentioned approval vocabulary silenced it -- and with it FAIL_CRITICAL.
    sites, passed, findings = run(
        "import os\n"
        "def unrelated():\n"
        "    if confirm():\n"
        "        pass\n"
        "os.system('rm -rf /')\n"
    )
    assert (sites, passed) == (1, 0)
    assert findings[0].critical is True
    assert "at module level" in findings[0].message


def test_approval_in_a_nested_helper_does_not_cover_the_outer_call():
    # A check inside a helper does not run when the surrounding code does.
    sites, passed, _findings = run(
        "import shutil\n"
        "def wipe(path):\n"
        "    def _helper():\n"
        "        return request_approval(path)\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)


def test_module_level_approval_still_covers_a_module_level_call():
    sites, passed, findings = run(
        "import os\n"
        "if not request_approval('boot'):\n"
        "    raise SystemExit\n"
        "os.system('setup.sh')\n"
    )
    assert (sites, passed) == (1, 1)
    assert findings == []


def test_class_body_shares_the_module_scope():
    # A class body executes at definition time in the surrounding scope,
    # so a module-level approval check does cover it.
    sites, passed, _findings = run(
        "import os\n"
        "if not confirm():\n"
        "    raise SystemExit\n"
        "class Boot:\n"
        "    os.system('setup.sh')\n"
    )
    assert (sites, passed) == (1, 1)


def test_own_decorator_still_counts_as_an_enforcing_position():
    sites, passed, _findings = run(
        "import shutil\n"
        "@requires_approval\n"
        "def wipe(path):\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 1)


def test_nested_function_decorator_does_not_cover_the_outer_call():
    sites, passed, _findings = run(
        "import shutil\n"
        "def wipe(path):\n"
        "    @requires_approval\n"
        "    def _inner():\n"
        "        pass\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)


def test_many_sensitive_calls_in_one_scope_are_all_judged():
    # Guards the per-scope memoization added for performance: caching the
    # scope's answer must not change how many sites are counted.
    src = "import subprocess\ndef f(c):\n" + "    subprocess.run(c)\n" * 25
    sites, passed, findings = run(src)
    assert (sites, passed) == (25, 0)
    assert len(findings) == 25


def test_memoized_scope_answer_is_shared_correctly_across_scopes():
    src = (
        "import shutil\n"
        "def guarded(path):\n"
        "    if not confirm():\n"
        "        return\n"
        "    shutil.rmtree(path)\n"
        "    shutil.rmtree(path)\n"
        "def naked(path):\n"
        "    shutil.rmtree(path)\n"
    )
    sites, passed, findings = run(src)
    assert (sites, passed) == (3, 2)
    assert [f.line for f in findings] == [8]
