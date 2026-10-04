"""End-to-end proof: the full pipeline separates a realistic vulnerable
server from a realistic clean one, decisively."""

import subprocess
import sys
from pathlib import Path

from checkride.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT_ROOT = Path(__file__).parent.parent

ALL_RULE_IDS = {
    "human-oversight",
    "audit-logging",
    "rate-limiting",
    "error-handling",
    "input-validation",
    "permissive-defaults",
}


def test_vulnerable_server_scores_zero_and_every_category_fires():
    report = scan(FIXTURES / "vulnerable_server.py")

    assert report.score == 0.0
    assert {f.rule for f in report.findings} == ALL_RULE_IDS
    assert report.verdict == "FAIL_CRITICAL"


def test_clean_server_scores_perfect_with_no_findings():
    # The false-positive canary: legitimate governance patterns must
    # never be flagged.
    report = scan(FIXTURES / "clean_server.py")

    assert report.score == 100.0
    assert report.findings == []
    assert report.verdict == "PASS"


def test_python_dash_m_entrypoint_end_to_end():
    # A real subprocess proves the __main__ wiring and exit-code
    # propagation that in-process main() calls cannot.
    proc = subprocess.run(
        [sys.executable, "-m", "checkride", str(FIXTURES / "clean_server.py")],
        capture_output=True,
        check=False,
        text=True,
        cwd=PROJECT_ROOT,
    )
    assert proc.returncode == 0
    assert "100.0 / 100" in proc.stdout


def test_min_score_gate_end_to_end():
    proc = subprocess.run(
        [
            sys.executable, "-m", "checkride",
            str(FIXTURES / "vulnerable_server.py"),
            "--min-score", "70",
        ],
        capture_output=True,
        check=False,
        text=True,
        cwd=PROJECT_ROOT,
    )
    assert proc.returncode == 1


def test_critical_verdict_fails_end_to_end_without_min_score():
    # No --min-score at all: a live critical finding must still fail the
    # build (critical-site dilution) rather than defaulting to a pass.
    proc = subprocess.run(
        [sys.executable, "-m", "checkride", str(FIXTURES / "vulnerable_server.py")],
        capture_output=True,
        check=False,
        text=True,
        cwd=PROJECT_ROOT,
    )
    assert proc.returncode == 1
    assert "FAIL_CRITICAL" in proc.stdout


def test_vulnerable_fixture_covers_every_detection_shape():
    # Each tool below is a shape some version of checkride, or an obvious
    # implementation of it, scored as clean. Pinning each one by name means
    # a regression names what broke instead of just moving a number.
    report = scan(FIXTURES / "vulnerable_server.py")
    critical_in = {
        f.function for f in report.findings
        if f.rule == "human-oversight" and f.critical
    }

    for tool in [
        "delete_path",                      # plain dotted sink
        "run_via_from_import",              # from-import alias
        "wipe_via_rebinding",               # rebound sink
        "unlink_file",                      # dynamic receiver
        "shell_async",                      # asyncio sink
        "load_state",                       # deserialization
        "evaluate",                         # eval
        "approve_after_the_fact",           # approval after the sink
        "model_confirms_itself",            # approval from a tool argument
        "authz_is_not_approval",            # machine authz, not a human
        "hardcoded_approval",               # constant-bound approval flag
        "humanize_is_not_a_human",          # vocabulary lookalike
        "check_output_validates_nothing",   # sink named like a validator
        "run_query",                        # dynamic SQL
        "refund_via_http",                  # payment over plain HTTP
        "dynamic_lookup",                   # getattr(os, "system")
        "_remove_tree",                     # helper reached from a tool
        "delete_requested",                 # input-model field
        "handle_call",                      # low-level call_tool dispatch
        "ShellTool._run",                   # class-based tool
        "clean_directory",                  # registered via tools=[...]
    ]:
        assert tool in critical_in, tool

    messages = {f.function: f.message for f in report.findings}
    assert "model chooses" in " ".join(
        f.message for f in report.findings if f.function == "model_confirms_itself"
    )
    assert any(
        "silently discards" in f.message
        for f in report.findings if f.function == "swallowed_failure"
    )
    assert any(
        f.rule == "input-validation" and "input model 'FileRequest'" in f.message
        for f in report.findings
    )
    assert any(
        f.rule == "input-validation" and "argument 'path'" in f.message
        for f in report.findings
    )
    assert any(
        f.function == "read_note" and "reaches a file path" in f.message
        for f in report.findings
    )
    assert messages  # every finding names its function
    # The module-level setup call is not agent-reachable: counted, not judged.
    assert report.out_of_scope_sensitive_calls == 1
    assert not any(f.function is None and f.rule == "human-oversight" for f in report.findings)


def test_clean_fixture_exercises_every_category():
    # A false-positive canary is only worth having if every rule actually
    # gets a chance to fire on it.
    report = scan(FIXTURES / "clean_server.py")

    assert report.findings == []
    assert all(c.sites > 0 for c in report.categories), [
        c.name for c in report.categories if c.sites == 0
    ]
