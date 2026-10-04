from checkride.astutils import FileContext
from checkride.config import RuleConfig
from checkride.rules import errorhandling


def run(src: str, scope: str = "all"):
    """Mechanics are tested in scope "all"; tool scope has its own tests."""
    config = RuleConfig(scope=scope)
    return errorhandling.check(FileContext.from_source(src, path="mem.py", config=config))


def test_while_true_without_exit_fails():
    sites, passed, findings = run(
        "def poll_forever():\n"
        "    while True:\n"
        "        poll()\n"
    )
    assert (sites, passed) == (1, 0)
    assert findings[0].line == 2
    assert "while True" in findings[0].message


def test_while_true_with_break_passes():
    sites, passed, findings = run(
        "while True:\n"
        "    if done():\n"
        "        break\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_break_in_nested_loop_does_not_count():
    # The break exits the inner for-loop; the outer while True never ends.
    # A naive "subtree contains a break" check would wrongly pass this.
    sites, passed, _ = run(
        "while True:\n"
        "    for item in queue:\n"
        "        if item.stop:\n"
        "            break\n"
    )
    assert (sites, passed) == (1, 0)


def test_return_inside_while_true_passes():
    sites, passed, _ = run(
        "def wait():\n"
        "    while True:\n"
        "        if ready():\n"
        "            return True\n"
    )
    assert (sites, passed) == (1, 1)


def test_sensitive_call_wrapped_in_try_passes():
    sites, passed, findings = run(
        "def wipe(path):\n"
        "    try:\n"
        "        shutil.rmtree(path)\n"
        "    except OSError:\n"
        "        logger.error('failed')\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_unwrapped_sensitive_call_fails():
    sites, passed, findings = run(
        "def wipe(path):\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)
    assert "try/except" in findings[0].message


def test_call_in_except_handler_is_not_protected():
    # The rmtree lives in the handler -- the try protects prepare(), not it.
    # A naive "has a Try ancestor" check would wrongly pass this.
    sites, passed, _ = run(
        "def cleanup(path):\n"
        "    try:\n"
        "        prepare()\n"
        "    except Exception:\n"
        "        shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)


def test_loop_and_call_sites_both_counted():
    sites, passed, _ = run(
        "def worker(path):\n"
        "    while True:\n"
        "        poll()\n"
        "    try:\n"
        "        shutil.rmtree(path)\n"
        "    except OSError:\n"
        "        pass\n"
    )
    assert (sites, passed) == (2, 1)  # loop fails, wrapped call passes


def test_no_sites_in_benign_code():
    sites, passed, findings = run("def add(a, b):\n    return a + b\n")
    assert (sites, passed, findings) == (0, 0, [])


def test_aliased_import_sensitive_call_is_still_a_site():
    sites, passed, findings = run(
        "import subprocess as sp\n"
        "def run_it(cmd):\n"
        "    sp.run(cmd, shell=True)\n"
    )
    assert (sites, passed) == (1, 0)
    assert "subprocess.run" in findings[0].message


def test_aliased_sys_exit_counts_as_a_loop_exit():
    sites, passed, _findings = run(
        "import sys as s\n"
        "def poll():\n"
        "    while True:\n"
        "        if done():\n"
        "            s.exit(0)\n"
    )
    assert (sites, passed) == (1, 1)


def test_broad_handler_that_discards_the_error_is_not_handling():
    _sites, _passed, findings = run(
        "def f(p):\n    try:\n        os.remove(p)\n    except Exception:\n        pass\n"
    )
    call_sites = [f for f in findings if "os.remove" in f.message]
    assert call_sites and "silently discards" in call_sites[0].message


def test_bare_except_with_only_a_docstring_is_swallowing():
    _, _, findings = run(
        "def f(p):\n    try:\n        os.remove(p)\n    except:\n        'ignore'\n"
    )
    assert any("silently discards" in f.message for f in findings)


def test_specific_exception_ignored_on_purpose_is_handling():
    sites, passed, _ = run(
        "def f(p):\n    try:\n        os.remove(p)\n    except FileNotFoundError:\n        pass\n"
    )
    assert (sites, passed) == (1, 1)


def test_try_finally_without_handler_is_not_handling():
    sites, passed, _ = run(
        "def f(p):\n    try:\n        os.remove(p)\n    finally:\n        cleanup()\n"
    )
    assert (sites, passed) == (1, 0)


def test_try_in_an_outer_function_does_not_protect_a_nested_def():
    sites, passed, _ = run(
        "def f(p):\n    try:\n        def g():\n            os.remove(p)\n"
        "        g()\n    except OSError:\n        raise\n"
    )
    assert passed < sites


def test_unreachable_loops_are_out_of_scope_in_tool_scope():
    assert run("def f():\n    while True:\n        pass\n", scope="tools")[0] == 0
