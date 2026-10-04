"""Approval dominance (approval.py) as the human-oversight rule sees it.

Every snippet is a real tool (`@mcp.tool()`), judged in the default tool
scope. The bypass cases are the ones a vocabulary-near-the-sink heuristic
passes; each must stay a critical finding.
"""

import pytest

from checkride.approval import is_approval_name
from checkride.astutils import FileContext
from checkride.config import RuleConfig
from checkride.rules import oversight


def judge(body: str, params: str = "path", config: RuleConfig | None = None):
    src = (
        "import shutil, subprocess, os\n"
        "@mcp.tool()\n"
        f"def tool({params}):\n" + "".join(f"    {line}\n" for line in body.splitlines())
    )
    return oversight.check(FileContext.from_source(src, path="mem.py", config=config))


def gated(body: str, params: str = "path", config: RuleConfig | None = None) -> bool:
    sites, passed, _findings = judge(body, params, config)
    assert sites >= 1
    return sites == passed


# --- shapes that must pass --------------------------------------------------

@pytest.mark.parametrize("body", [
    "if not request_approval('wipe', path):\n    return\nshutil.rmtree(path)",
    "if not await confirm_with_user(path):\n    raise PermissionError\nshutil.rmtree(path)",
    "if request_approval(path):\n    shutil.rmtree(path)",
    "require_approval('wipe', path)\nshutil.rmtree(path)",
    "await ctx.elicit('Delete?')\nshutil.rmtree(path)",
    "assert human_review(path)\nshutil.rmtree(path)",
    "ok = request_approval(path)\nif not ok:\n    return\nshutil.rmtree(path)",
    "answer = input('really? ')\nif answer == 'y':\n    shutil.rmtree(path)",
    "request_approval(path) and shutil.rmtree(path)",
    "with approval_session(path):\n    shutil.rmtree(path)",
    "[shutil.rmtree(p) for p in paths if is_confirmed(p)]",
    "if not consent_given(path):\n    return\nfor p in [path]:\n    shutil.rmtree(p)",
    "try:\n    if not request_approval(path):\n        return\n    shutil.rmtree(path)\nexcept OSError:\n    raise",
])
def test_gated_shapes_pass(body):
    assert gated(body)


def test_mcp_elicitation_through_the_injected_context_passes():
    body = (
        "result = await ctx.elicit(message='Delete?', schema=Confirm)\n"
        "if result.action != 'accept':\n"
        "    return\n"
        "shutil.rmtree(path)"
    )
    assert gated(body, params="path, ctx: Context")


def test_approval_decorator_passes():
    src = (
        "import shutil\n"
        "@mcp.tool()\n"
        "@requires_approval\n"
        "def tool(path):\n"
        "    shutil.rmtree(path)\n"
    )
    sites, passed, _ = oversight.check(FileContext.from_source(src, path="mem.py"))
    assert (sites, passed) == (1, 1)


# --- bypasses that must stay critical --------------------------------------

@pytest.mark.parametrize("body", [
    # approval after the sink
    "shutil.rmtree(path)\nif not request_approval(path):\n    return",
    "shutil.rmtree(path)\nif approved:\n    pass",
    # a non-terminating if is not a guard
    "if confirm_flag:\n    pass\nshutil.rmtree(path)",
    # machine authorization is not human approval
    "if not user.is_authorized('delete'):\n    raise PermissionError\nshutil.rmtree(path)",
    # vocabulary lookalikes
    "size = humanize.naturalsize(1)\nshutil.rmtree(path)",
    "if is_human_readable(path):\n    shutil.rmtree(path)",
    # hardcoded approval
    "approved = True\nif approved:\n    shutil.rmtree(path)",
    # permissive flags read as approval words
    "if settings.auto_approve:\n    shutil.rmtree(path)",
    "if SKIP_CONFIRMATION:\n    shutil.rmtree(path)",
    # approval in an unrelated branch
    "if x:\n    if not request_approval(path):\n        return\nshutil.rmtree(path)",
    # approval in a nested helper never runs here
    "def check():\n    return request_approval(path)\nshutil.rmtree(path)",
])
def test_bypass_shapes_stay_critical(body):
    sites, passed, findings = judge(body)
    assert passed < sites
    assert any(f.critical for f in findings)


def test_tool_argument_is_not_approval():
    sites, passed, findings = judge(
        "if not confirm:\n    return\nshutil.rmtree(path)", params="path, confirm: bool = False"
    )
    assert (sites, passed) == (1, 0)
    assert "model chooses" in findings[0].message


def test_attribute_of_a_tool_argument_is_not_approval():
    _sites, passed, _ = judge(
        "if not args.confirmed:\n    return\nshutil.rmtree(args.path)", params="args"
    )
    assert passed == 0


def test_sink_cannot_approve_itself_through_config_vocabulary():
    # Config validation rejects such a marker; the analysis must not depend
    # on that alone.
    _sites, passed, _ = judge(
        "subprocess.run(path)", config=RuleConfig(approval_markers=("run",))
    )
    assert passed == 0


def test_approval_named_receiver_inside_the_sink_does_not_count():
    _sites, passed, _ = judge("approval_client.charge(path)")
    assert passed == 0


# --- vocabulary ------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "request_approval", "approve", "confirm", "user_consent", "ctx.elicit",
    "ask_human", "askHuman", "human_in_the_loop", "input", "self.approvals.check",
])
def test_approval_names(name):
    assert is_approval_name(name)


@pytest.mark.parametrize("name", [
    "auto_approve", "settings.auto_approve", "skip_confirmation", "humanize",
    "is_authorized", "authorize", "human_readable", "inputs",
])
def test_non_approval_names(name):
    assert not is_approval_name(name)


# --- polarity: the call must be on the approved side ----------------------

@pytest.mark.parametrize("body", [
    # acts exactly when approval was refused
    "if request_approval(path):\n    return 'ok'\nshutil.rmtree(path)",
    "if not request_approval(path):\n    shutil.rmtree(path)",
    "answer = input('ok? ')\nif answer == 'no':\n    shutil.rmtree(path)",
    "result = await ctx.elicit('Delete?')\nif result.action == 'accept':\n    return\nshutil.rmtree(path)",
    "if user_declined_approval(path):\n    shutil.rmtree(path)",
    "assert not request_approval(path)\nshutil.rmtree(path)",
    "if request_approval(path):\n    pass\nelse:\n    shutil.rmtree(path)",
])
def test_call_on_the_refused_side_is_not_gated(body):
    sites, passed, _ = judge(body, params="path, ctx: Context")
    assert passed < sites


@pytest.mark.parametrize("body", [
    "result = await ctx.elicit('Delete?')\nif result.action != 'accept':\n    return\nshutil.rmtree(path)",
    "answer = input('ok? ')\nif answer != 'y':\n    raise SystemExit\nshutil.rmtree(path)",
    "if request_approval(path) is False:\n    return\nshutil.rmtree(path)",
    "if not request_approval(path):\n    return\nelse:\n    shutil.rmtree(path)",
    "if request_approval(path):\n    shutil.rmtree(path)\nelse:\n    return",
])
def test_call_on_the_approved_side_is_gated(body):
    assert gated(body, params="path, ctx: Context")

