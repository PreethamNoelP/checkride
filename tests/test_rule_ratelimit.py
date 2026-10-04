import dataclasses

import pytest

from checkride.astutils import FileContext
from checkride.config import RuleConfig
from checkride.rules import ratelimit


def run(src: str, config: RuleConfig | None = None, scope: str = "all"):
    """Rule mechanics are tested in scope "all" (every function with a sink
    is a tool), so a snippet needs no tool decorator to be judged. Tool-
    scope behavior has its own tests below and in test_callgraph.py."""
    config = dataclasses.replace(config or RuleConfig(), scope=scope)
    return ratelimit.check(FileContext.from_source(src, path="mem.py", config=config))


def test_tool_without_rate_limit_fails():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def fetch(url):\n"
        "    return http.get(url)\n"
    )
    assert (sites, passed) == (1, 0)
    assert "'fetch'" in findings[0].message


def test_limiter_decorator_passes():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "@limiter.limit('10/minute')\n"
        "def fetch(url):\n"
        "    return http.get(url)\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_ratelimit_library_limits_decorator_passes():
    sites, passed, _ = run(
        "@tool\n"
        "@limits(calls=10, period=60)\n"
        "def fetch(url):\n"
        "    return http.get(url)\n"
    )
    assert (sites, passed) == (1, 1)


def test_inline_throttle_reference_passes():
    sites, passed, _ = run(
        "@mcp.tool()\n"
        "def fetch(url):\n"
        "    throttle.wait()\n"
        "    return http.get(url)\n"
    )
    assert (sites, passed) == (1, 1)


def test_generic_limit_param_does_not_count():
    # `limit=10` is pagination, not rate limiting. Must still fail.
    sites, passed, _ = run(
        "@mcp.tool()\n"
        "def search(query, limit=10):\n"
        "    return db.find(query, limit)\n"
    )
    assert (sites, passed) == (1, 0)


def test_plain_helper_is_not_a_site():
    sites, passed, findings = run("def add(a, b):\n    return a + b\n")
    assert (sites, passed, findings) == (0, 0, [])


def test_assume_external_rate_limiting_makes_every_tool_not_applicable():
    config = RuleConfig(assume_external_rate_limiting=True)
    sites, passed, findings = run(
        "@mcp.tool()\ndef fetch(url):\n    return http.get(url)\n",
        config=config,
    )
    assert (sites, passed, findings) == (0, 0, [])


def test_extra_rate_marker_from_config_is_recognized():
    config = RuleConfig(rate_markers=("throughput_cap",))
    sites, passed, _ = run(
        "@mcp.tool()\ndef fetch(url):\n    throughput_cap.check()\n    return http.get(url)\n",
        config=config,
    )
    assert (sites, passed) == (1, 1)


# --- a limiter has to be used, not just named ------------------------------

@pytest.mark.parametrize("body", [
    "rate_limiter = None\n    return 1",
    "throttle_seconds = 5\n    return throttle_seconds",
    "return fetch(limiter=None)",
])
def test_a_limiter_that_is_only_named_does_not_count(body):
    sites, passed, _ = run(f"@tool\ndef t():\n    {body}\n", scope="tools")
    assert (sites, passed) == (1, 0)


def test_a_limiter_parameter_does_not_count():
    sites, passed, _ = run("@tool\ndef t(rate_limit: int = 10):\n    return 1\n", scope="tools")
    assert (sites, passed) == (1, 0)


@pytest.mark.parametrize("src", [
    "@tool\ndef t():\n    rate_limiter.acquire()\n",
    "@tool\nasync def t():\n    await self.throttle.wait()\n",
    "@tool\nasync def t():\n    async with limiter:\n        return 1\n",
    "@tool\n@limiter.limit('10/minute')\ndef t():\n    return 1\n",
    "@tool\n@limits(calls=10, period=60)\ndef t():\n    return 1\n",
])
def test_a_limiter_that_is_used_counts(src):
    assert run(src, scope="tools")[:2] == (1, 1)

