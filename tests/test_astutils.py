import ast

import pytest

from checkride.astutils import (
    FileContext,
    build_import_aliases,
    build_parent_map,
    call_name,
    dotted_name,
    enclosing_function,
    is_critical,
    iter_scope,
    iter_sensitive_calls,
    sensitive_label,
)


def first_call(src: str) -> ast.Call:
    """Test helper: parse a snippet and return its first Call node."""
    tree = ast.parse(src)
    return next(n for n in ast.walk(tree) if isinstance(n, ast.Call))


# --- what is being called? ---

def test_call_name_resolves_dotted_chain():
    assert call_name(first_call("os.path.join(a, b)")) == "os.path.join"


def test_call_name_resolves_bare_name():
    assert call_name(first_call("eval(payload)")) == "eval"


def test_call_name_is_none_for_dynamic_call():
    # funcs["rm"](x): the thing being called is a subscript, not a name.
    # A static scan cannot know the target, so we must get None, not a crash.
    assert call_name(first_call('funcs["rm"](x)')) is None


# --- is it sensitive? ---

def test_exact_sensitive_match():
    assert sensitive_label(first_call("subprocess.run(cmd, shell=True)")) == "shell exec"


def test_suffix_sensitive_match_on_any_receiver():
    assert sensitive_label(first_call("client.charge(amount)")) == "payment"


def test_platform_system_is_not_flagged():
    # os.system is sensitive; platform.system is harmless. This pins down
    # that we exact-match "os.system" instead of suffix-matching "system".
    assert sensitive_label(first_call("platform.system()")) is None


def test_iter_sensitive_calls_finds_all_and_only_sensitive():
    src = "shutil.rmtree(tmp)\nprint('hi')\ngateway.charge(9)\n"
    labels = sorted(label for _, label in iter_sensitive_calls(ast.parse(src)))
    assert labels == ["file delete", "payment"]


# --- is it a critical-consequence sink? ---

def test_every_sensitive_label_is_critical():
    # Today's sensitive-call vocabulary is entirely made of the five
    # catastrophic consequence categories -- there is no low-risk sink yet.
    labels = {"file delete", "shell exec", "code exec", "payment", "remote delete"}
    assert all(is_critical(label) for label in labels)


def test_unknown_label_is_not_critical():
    assert is_critical("some future low-risk label") is False


# --- what surrounds a node? ---

def test_enclosing_function_finds_nearest_def():
    src = (
        "def outer():\n"
        "    def inner():\n"
        "        os.remove(path)\n"
    )
    tree = ast.parse(src)
    parents = build_parent_map(tree)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    fn = enclosing_function(call, parents)
    assert fn is not None
    assert fn.name == "inner"  # nearest def, not the outermost


def test_enclosing_function_none_at_module_level():
    tree = ast.parse("os.remove(path)")
    parents = build_parent_map(tree)
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    assert enclosing_function(call, parents) is None


# --- import aliasing ---

def test_build_import_aliases_maps_module_asname():
    tree = ast.parse("import subprocess as sp\n")
    assert build_import_aliases(tree) == {"sp": "subprocess"}


def test_build_import_aliases_maps_from_import_asname():
    tree = ast.parse("from shutil import rmtree as rt\n")
    assert build_import_aliases(tree) == {"rt": "shutil.rmtree"}


def test_build_import_aliases_maps_plain_from_import():
    # `from subprocess import run` binds the bare name "run", which the
    # suffix table excludes as too generic -- without this entry the call
    # `run(cmd, shell=True)` resolved to nothing at all.
    tree = ast.parse("from subprocess import run\n")
    assert build_import_aliases(tree) == {"run": "subprocess.run"}


def test_build_import_aliases_ignores_plain_module_import():
    # `import os.path` binds "os"; dotted_name already walks the Attribute
    # chain from there, so no entry is needed.
    tree = ast.parse("import os.path\n")
    assert build_import_aliases(tree) == {}


def test_build_import_aliases_skips_star_import():
    # `from subprocess import *` binds names we cannot enumerate statically.
    tree = ast.parse("from subprocess import *\n")
    assert build_import_aliases(tree) == {}


def test_build_import_aliases_skips_relative_imports():
    tree = ast.parse("from . import helper as h\n")
    assert build_import_aliases(tree) == {}


def test_build_import_aliases_resolves_a_rebinding_chain_in_document_order():
    # Pins the ordering the single-walk implementation has to preserve:
    # imports are all collected before any assignment is resolved, and
    # assignments are then resolved in the order they appear, so each hop
    # can see the one before it.
    tree = ast.parse("import shutil as sh\nA = sh.rmtree\nB = A\n")

    assert build_import_aliases(tree) == {
        "sh": "shutil",
        "A": "shutil.rmtree",
        "B": "shutil.rmtree",
    }


def test_build_import_aliases_resolution_is_order_dependent():
    # The documented limit of the above: a rebinding written before the
    # name it refers to resolves only as far as what was known at that
    # point. Pinned so the behavior is a decision, not an accident -- and
    # so a future refactor cannot quietly change it in either direction.
    tree = ast.parse("B = A\nA = sh.rmtree\nimport shutil as sh\n")

    assert build_import_aliases(tree) == {
        "sh": "shutil",
        "A": "shutil.rmtree",
        "B": "A",
    }


def test_dotted_name_resolves_module_alias():
    aliases = {"sp": "subprocess"}
    assert dotted_name(first_call("sp.run(cmd)").func, aliases) == "subprocess.run"


def test_dotted_name_resolves_bare_name_alias():
    aliases = {"rt": "shutil.rmtree"}
    assert dotted_name(first_call("rt(path)").func, aliases) == "shutil.rmtree"


def test_dotted_name_without_aliases_is_unchanged():
    # Default (no aliases arg) behaves exactly as before this feature existed.
    assert dotted_name(first_call("sp.run(cmd)").func) == "sp.run"


def test_sensitive_label_sees_through_module_import_alias():
    # The documented blind spot in RULES.md: `import subprocess as sp; sp.run(...)`.
    aliases = {"sp": "subprocess"}
    assert sensitive_label(first_call("sp.run(cmd, shell=True)"), aliases) == "shell exec"


def test_sensitive_label_sees_through_from_import_alias():
    aliases = {"rt": "shutil.rmtree"}
    assert sensitive_label(first_call("rt(path)"), aliases) == "file delete"


def test_iter_sensitive_calls_accepts_aliases():
    src = "import subprocess as sp\nsp.run(cmd)\n"
    tree = ast.parse(src)
    aliases = build_import_aliases(tree)
    labels = [label for _, label in iter_sensitive_calls(tree, aliases)]
    assert labels == ["shell exec"]


# --- inline suppression comments ---

def test_is_suppressed_for_unqualified_ignore_comment():
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # checkride: ignore\n", path="mem.py"
    )
    assert ctx.is_suppressed("human-oversight", 1) is True
    assert ctx.is_suppressed("error-handling", 1) is True


def test_is_suppressed_for_rule_scoped_ignore_comment():
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # checkride: ignore[human-oversight]\n", path="mem.py"
    )
    assert ctx.is_suppressed("human-oversight", 1) is True
    assert ctx.is_suppressed("error-handling", 1) is False


def test_is_suppressed_for_multiple_rule_scoped_ignore_comment():
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # checkride: ignore[human-oversight, error-handling]\n",
        path="mem.py",
    )
    assert ctx.is_suppressed("human-oversight", 1) is True
    assert ctx.is_suppressed("error-handling", 1) is True
    assert ctx.is_suppressed("audit-logging", 1) is False


def test_is_suppressed_is_false_for_unmarked_lines():
    ctx = FileContext.from_source("shutil.rmtree(path)\n", path="mem.py")
    assert ctx.is_suppressed("human-oversight", 1) is False


def test_suppression_marker_in_a_string_literal_is_not_a_comment():
    # Only real COMMENT tokens count -- a string that happens to contain the
    # marker text must not accidentally suppress anything.
    ctx = FileContext.from_source(
        'msg = "# checkride: ignore"\nshutil.rmtree(path)\n', path="mem.py"
    )
    assert ctx.is_suppressed("human-oversight", 2) is False


# --- vocabulary coverage for sinks that the first tables missed ---

def test_pathlib_unlink_is_a_file_delete_sink():
    # Path(p).unlink() is the modern deletion idiom; a table that only knew
    # os.remove/shutil.rmtree scored such code a clean 100.
    assert sensitive_label(first_call("target.unlink()")) == "file delete"


def test_async_subprocess_is_a_shell_exec_sink():
    src = "asyncio.create_subprocess_shell(cmd)"
    assert sensitive_label(first_call(src)) == "shell exec"


def test_async_subprocess_on_any_receiver_is_a_shell_exec_sink():
    assert sensitive_label(first_call("loop.create_subprocess_exec(*argv)")) == "shell exec"


def test_subprocess_getoutput_is_a_shell_exec_sink():
    assert sensitive_label(first_call("subprocess.getoutput(cmd)")) == "shell exec"


def test_pickle_loads_is_a_code_exec_sink():
    assert sensitive_label(first_call("pickle.loads(blob)")) == "code exec"


def test_yaml_load_is_not_flagged_but_unsafe_load_is():
    # yaml.load(s, Loader=SafeLoader) is safe and ubiquitous -- flagging it
    # would make the critical gate untrustworthy. yaml.unsafe_load names
    # its own risk, so it is fair game.
    assert sensitive_label(first_call("yaml.load(text, Loader=SafeLoader)")) is None
    assert sensitive_label(first_call("yaml.unsafe_load(text)")) == "code exec"


def test_bulk_remote_deletion_is_a_sink():
    assert sensitive_label(first_call("s3.delete_bucket(Bucket=b)")) == "remote delete"
    assert sensitive_label(first_call("col.delete_many(query)")) == "remote delete"


def test_stripe_style_payment_calls_are_sinks():
    src = "stripe.PaymentIntent.create_payment_intent(amount=n)"
    assert sensitive_label(first_call(src)) == "payment"


def test_generic_delete_is_still_not_flagged():
    # The suffix table must stay distinctive: a cache eviction or a list
    # removal is not a governance event.
    assert sensitive_label(first_call("cache.delete(key)")) is None
    assert sensitive_label(first_call("items.remove(x)")) is None


def test_sensitive_label_sees_through_plain_from_import():
    # from os import system; system(cmd) -- the bare name "system" is
    # deliberately absent from the suffix table (platform.system and
    # friends), so only alias resolution can catch this shape.
    tree = ast.parse("from os import system\nsystem(cmd)\n")
    aliases = build_import_aliases(tree)
    assert [label for _, label in iter_sensitive_calls(tree, aliases)] == ["shell exec"]


def test_plain_from_import_of_subprocess_run_is_detected():
    tree = ast.parse("from subprocess import run\nrun(cmd, shell=True)\n")
    aliases = build_import_aliases(tree)
    assert [label for _, label in iter_sensitive_calls(tree, aliases)] == ["shell exec"]


def test_suffix_table_matches_through_a_dynamic_receiver():
    # dotted_name gives up on Path(p).unlink -- the receiver is a call
    # result, not a name chain. The suffix table is receiver-agnostic by
    # construction, so the attribute name alone must still be honored.
    assert sensitive_label(first_call("Path(p).unlink()")) == "file delete"
    assert sensitive_label(first_call("clients[k].charge(n)")) == "payment"


def test_dynamic_receiver_fallback_stays_suffix_only():
    # The fallback must not promote a generic method name; only the
    # distinctive suffix table applies.
    assert sensitive_label(first_call("get_db().delete(row)")) is None


# --- scope boundaries ---

def test_iter_scope_does_not_enter_nested_functions():
    tree = ast.parse(
        "x = 1\n"
        "def helper():\n"
        "    y = 2\n"
        "class C:\n"
        "    z = 3\n"
    )
    names = {n.id for n in iter_scope(tree) if isinstance(n, ast.Name)}
    assert names == {"x", "z"}  # y lives in helper's own scope


def test_iter_scope_of_a_function_yields_the_function_itself():
    fn = ast.parse("def f():\n    pass\n").body[0]
    assert next(iter_scope(fn)) is fn


# --- malformed suppressions must not escalate into blanket ones ---

def test_empty_bracket_suppression_is_malformed_and_suppresses_nothing():
    # "ignore[]" reads as "suppress nothing"; the first pattern failed to
    # match the bracketed form, fell back to bare "ignore", and suppressed
    # every rule on the line instead.
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # checkride: ignore[]\n", path="mem.py"
    )
    assert ctx.is_suppressed("human-oversight", 1) is False
    assert len(ctx.malformed_suppressions) == 1
    assert ctx.malformed_suppressions[0][0] == 1


def test_invalid_rule_id_in_brackets_is_malformed_not_blanket():
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # checkride: ignore[human oversight!]\n", path="mem.py"
    )
    assert ctx.is_suppressed("human-oversight", 1) is False
    assert ctx.is_suppressed("error-handling", 1) is False
    assert ctx.malformed_suppressions


def test_ignore_inside_a_longer_word_is_not_a_marker():
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # checkride: ignored this in review\n", path="mem.py"
    )
    assert ctx.is_suppressed("human-oversight", 1) is False
    assert ctx.malformed_suppressions == []


def test_unknown_but_well_formed_rule_id_suppresses_nothing_real():
    # Well-formed shape, so not "malformed" -- but it names no real rule,
    # which the scoring pass reports as an ineffective suppression.
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # checkride: ignore[oversight]\n", path="mem.py"
    )
    assert ctx.is_suppressed("human-oversight", 1) is False
    assert ctx.suppressions[1] == frozenset({"oversight"})
    assert ctx.malformed_suppressions == []


def test_trailing_reason_after_a_rule_list_still_parses():
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # checkride: ignore[human-oversight] gateway gates this\n",
        path="mem.py",
    )
    assert ctx.is_suppressed("human-oversight", 1) is True
    assert ctx.is_suppressed("error-handling", 1) is False


# --- rebinding an import to another name ---

def test_build_import_aliases_resolves_a_rebound_import():
    tree = ast.parse("import subprocess\nrun = subprocess.run\n")
    assert build_import_aliases(tree)["run"] == "subprocess.run"


def test_build_import_aliases_resolves_a_rebinding_through_an_alias():
    tree = ast.parse("import subprocess as sp\nrun = sp.run\n")
    assert build_import_aliases(tree)["run"] == "subprocess.run"


def test_rebound_sink_is_detected():
    # rm = shutil.rmtree; rm(path) -- a normal refactor, and the cheapest
    # way to walk a sink past a name-based scan.
    tree = ast.parse("import shutil\nrm = shutil.rmtree\nrm(path)\n")
    aliases = build_import_aliases(tree)
    assert [label for _, label in iter_sensitive_calls(tree, aliases)] == ["file delete"]


def test_call_result_assignment_is_not_an_alias():
    # logger = logging.getLogger(__name__) names nothing static; treating
    # it as an alias would be a guess, not a resolution.
    tree = ast.parse("import logging\nlogger = logging.getLogger(__name__)\n")
    assert "logger" not in build_import_aliases(tree)


def test_an_import_wins_over_a_later_assignment_to_the_same_name():
    tree = ast.parse("from shutil import rmtree\nrmtree = something.else_\n")
    assert build_import_aliases(tree)["rmtree"] == "shutil.rmtree"


def test_self_referential_assignment_is_not_an_alias():
    tree = ast.parse("run = run\n")
    assert build_import_aliases(tree) == {}


def test_multi_target_assignment_is_not_an_alias():
    # a = b = os.remove: which name is the alias is ambiguous enough that
    # guessing is worse than missing it.
    tree = ast.parse("import os\na = b = os.remove\n")
    aliases = build_import_aliases(tree)
    assert "a" not in aliases and "b" not in aliases


def test_bare_ignore_followed_by_prose_is_malformed():
    # "# checkride: ignore rate-limiting" -- brackets forgotten -- used to
    # suppress EVERY rule on the line, including rules added in later
    # versions. The narrowest reading of a directive we cannot parse is
    # that no exemption was granted.
    ctx = FileContext.from_source(
        "shutil.rmtree(path)  # checkride: ignore rate-limiting\n", path="mem.py"
    )
    assert ctx.is_suppressed("rate-limiting", 1) is False
    assert ctx.is_suppressed("human-oversight", 1) is False
    assert "unexpected text" in ctx.malformed_suppressions[0][1]


def test_bare_ignore_with_a_delimited_reason_still_suppresses():
    for comment in (
        "# checkride: ignore -- the gateway gates this",
        "# checkride: ignore: gateway",
        "# checkride: ignore # gateway",
        "# checkride: ignore",
    ):
        ctx = FileContext.from_source(f"auto_approve = True  {comment}\n", path="m.py")
        assert ctx.is_suppressed("permissive-defaults", 1) is True, comment
        assert ctx.malformed_suppressions == [], comment


def test_ignore_all_is_not_a_directive():
    ctx = FileContext.from_source(
        "auto_approve = True  # checkride: ignore-all\n", path="mem.py"
    )
    assert ctx.is_suppressed("permissive-defaults", 1) is False
    assert ctx.malformed_suppressions


# --- contextual sinks: indirection, dynamic SQL, payment HTTP --------------


def labels(src: str) -> list[str]:
    ctx = FileContext.from_source(src)
    return [label for _call, label in ctx.sensitive_calls]


def test_static_getattr_resolves_to_the_named_sink():
    assert labels("import os\ngetattr(os, 'system')(cmd)\n") == ["shell exec"]


def test_dunder_import_resolves_to_the_named_module():
    assert labels("__import__('subprocess').run(cmd)\n") == ["shell exec"]
    assert labels(
        "import importlib\nimportlib.import_module('shutil').rmtree(p)\n"
    ) == ["file delete"]


def test_dynamic_getattr_on_an_unknown_object_stays_unresolved():
    # A computed attribute on a dangerous module is a sink (see below); on
    # an arbitrary object there is nothing to resolve it to.
    assert labels("getattr(handler, name)(cmd)\n") == []


def test_dynamic_sql_on_a_cursor_is_a_sink():
    assert labels("def f(q):\n    cursor.execute(q)\n") == ["sql exec"]
    assert labels("def f(t):\n    conn.execute(f'DELETE FROM {t}')\n") == ["sql exec"]
    assert labels("def f(t):\n    db.executescript('DROP ' + t)\n") == ["sql exec"]


def test_constant_sql_is_not_a_sink():
    assert labels("cursor.execute('SELECT 1 WHERE id = ?', (x,))\n") == []
    assert labels("Q = 'SELECT 1'\ndef f():\n    cursor.execute(Q)\n") == []
    assert labels("session.execute(text('SELECT 1'))\n") == []


def test_execute_on_a_non_database_receiver_is_not_a_sink():
    assert labels("def f(task):\n    executor.execute(task)\n") == []


def test_sql_label_is_critical():
    assert is_critical("sql exec")


def test_http_post_to_a_payment_api_is_a_payment_sink():
    assert labels("requests.post('https://api.stripe.com/v1/charges', data=d)\n") == [
        "payment"
    ]
    assert labels(
        "BASE = 'https://api-m.paypal.com'\n"
        "def pay():\n    httpx.post(f'{BASE}/v2/payments', json=d)\n"
    ) == ["payment"]
    assert labels("client.request('POST', url='https://api.stripe.com/v1/refunds')\n") == [
        "payment"
    ]


def test_http_post_elsewhere_is_not_a_sink():
    assert labels("requests.post('https://example.com/api', data=d)\n") == []
    assert labels("requests.get('https://api.stripe.com/v1/charges')\n") == []


@pytest.mark.parametrize("src", [
    "stripe.Refund.create(charge=c)",
    "stripe.PaymentIntent.confirm(pi)",
    "client.payment_intents.create(amount=1)",
    "client.v1.refunds.create(params)",
    "gateway.transaction.sale({'amount': '10.00'})",
    "stripe.Transfer.create(amount=1, destination=a)",
])
def test_payment_sdk_writes_are_payment_sinks(src):
    assert labels(src + "\n") == ["payment"]


@pytest.mark.parametrize("src", [
    "stripe.Refund.retrieve(r)",
    "client.payment_intents.list()",
    "invoice_builder.create()",
    "users.create(name=n)",
])
def test_payment_sdk_reads_and_unrelated_creates_are_not_sinks(src):
    assert labels(src + "\n") == []


def test_kubernetes_deletes_are_remote_delete_sinks():
    assert labels("v1.delete_namespaced_pod(name, ns)\n") == ["remote delete"]
    assert labels("v1.delete_collection_namespaced_secret(ns)\n") == ["remote delete"]


# --- sinks without a static name -------------------------------------------

@pytest.mark.parametrize("src, label", [
    ("ACTIONS = {'rm': shutil.rmtree}\ndef f(a, p):\n    ACTIONS[a](p)\n", "file delete"),
    ("ACTIONS = {'rm': shutil.rmtree, 'sh': os.system}\ndef f(a, p):\n    ACTIONS.get(a)(p)\n", "shell exec"),
    ("from subprocess import run\nRUNNERS = [run]\ndef f(i, c):\n    RUNNERS[i](c)\n", "shell exec"),
    ("import os\ndef f(name, cmd):\n    getattr(os, name)(cmd)\n", "shell exec"),
    ("import pickle as p\ndef f(name, b):\n    getattr(p, name)(b)\n", "code exec"),
])
def test_dispatch_tables_and_computed_attributes_are_sinks(src, label):
    assert labels(src) == [label]


@pytest.mark.parametrize("src", [
    "HANDLERS = {'a': print}\ndef f(a):\n    HANDLERS[a]('x')\n",
    "def f(obj, name):\n    getattr(obj, name)()\n",
    "import math\ndef f(name, x):\n    getattr(math, name)(x)\n",
])
def test_harmless_tables_and_attributes_are_not_sinks(src):
    assert labels(src) == []

