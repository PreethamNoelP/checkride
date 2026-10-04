import dataclasses

import pytest

from checkride.astutils import FileContext
from checkride.config import RuleConfig
from checkride.rules import audit


def run(src: str, config: RuleConfig | None = None, scope: str = "all"):
    """Rule mechanics are tested in scope "all" (every function with a sink
    is a tool), so a snippet needs no tool decorator to be judged. Tool-
    scope behavior has its own tests below and in test_callgraph.py."""
    config = dataclasses.replace(config or RuleConfig(), scope=scope)
    return audit.check(FileContext.from_source(src, path="mem.py", config=config))


def test_mcp_tool_without_logging_fails():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def fetch(url):\n"
        "    return http.get(url)\n"
    )
    assert (sites, passed) == (1, 0)
    assert "'fetch'" in findings[0].message


def test_mcp_tool_with_logger_call_passes():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def fetch(url):\n"
        "    logger.info('fetch %s', url)\n"
        "    return http.get(url)\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_custom_audit_call_passes():
    sites, passed, _ = run(
        "@tool\n"
        "def fetch(url):\n"
        "    audit_log('fetch', url)\n"
        "    return http.get(url)\n"
    )
    assert (sites, passed) == (1, 1)


def test_login_call_is_not_logging():
    # Token matching, not substring: login() must not satisfy the rule.
    sites, passed, _ = run(
        "@mcp.tool()\n"
        "def connect():\n"
        "    session.login()\n"
    )
    assert (sites, passed) == (1, 0)


def test_undecorated_function_with_sensitive_call_is_a_site():
    # No @tool decorator, but it deletes files -> it must be audited.
    sites, passed, _ = run(
        "def wipe(path):\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 0)


def test_plain_helper_is_not_a_site():
    sites, passed, findings = run("def add(a, b):\n    return a + b\n")
    assert (sites, passed, findings) == (0, 0, [])


def test_extra_log_token_from_config_is_recognized():
    config = RuleConfig(log_tokens=frozenset({"telemetry"}))
    sites, passed, _ = run(
        "@mcp.tool()\ndef fetch(url):\n    telemetry.record(url)\n    return http.get(url)\n",
        config=config,
    )
    assert (sites, passed) == (1, 1)


def test_aliased_log_helper_still_counts():
    # `from telemetry import audit_log as al` leaves the local call spelled
    # `al(...)`, which carries none of the vocabulary the rule matches on.
    sites, passed, findings = run(
        "from telemetry import audit_log as al\n"
        "import shutil\n"
        "def wipe(path):\n"
        "    al('wipe', path)\n"
        "    shutil.rmtree(path)\n"
    )
    assert (sites, passed) == (1, 1)
    assert findings == []


@pytest.mark.parametrize("call", ["math.log(2)", "np.log(x)", "torch.log(t)", "math.log10(3)"])
def test_math_log_is_not_audit_logging(call):
    sites, passed, _ = run(f"@tool\ndef t(x):\n    {call}\n    return x\n")
    assert (sites, passed) == (1, 0)


@pytest.mark.parametrize("call", [
    "logging.info('x')", "log.warning('x')", "self.logger.error('x')",
    "await ctx.info('x')", "audit.write(event)", "structlog.get_logger().info('x')",
    "record_audit(x)",
])
def test_real_logging_calls_count(call):
    src = f"@tool\nasync def t(self, x, ctx: Context):\n    {call}\n    return x\n"
    assert run(src)[:2] == (1, 1)
