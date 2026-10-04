import json

import pytest

from checkride import __version__, cli
from checkride.cli import _print_report, main
from checkride.models import CategoryResult, Finding
from checkride.scoring import ScanReport

# A tool with every control present, so a test can add exactly one problem
# to it and observe that problem alone.
GOVERNED = (
    "import shutil\n"
    "@mcp.tool()\n"
    "def wipe(path):\n"
    "    if not path.startswith('/data/'):\n"
    "        raise ValueError('outside sandbox')\n"
    "    if not request_approval('wipe', path):\n"
    "        return False\n"
    "    rate_limiter.acquire()\n"
    "    try:\n"
    "        shutil.rmtree(path)\n"
    "    except OSError as exc:\n"
    "        logger.error('wipe failed: %s', exc)\n"
    "    audit_log('wipe', path)\n"
    "    return True\n"
)


def test_clean_scan_prints_score_and_exits_zero(tmp_path, capsys):
    (tmp_path / "clean.py").write_text("def add(a, b):\n    return a + b\n")

    code = main([str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "100.0 / 100" in out


def test_min_score_gate_returns_one(tmp_path, capsys):
    (tmp_path / "bad.py").write_text(
        "@mcp.tool()\ndef wipe(path):\n    shutil.rmtree(path)\n"
    )

    code = main([str(tmp_path), "--min-score", "70"])

    assert code == 1
    assert "fix:" in capsys.readouterr().out  # findings still printed


def test_critical_finding_returns_one_even_without_min_score(tmp_path, capsys):
    # A live, unguarded critical action must fail the build on its own --
    # no --min-score needed to catch it (critical-site dilution).
    (tmp_path / "bad.py").write_text(
        "@mcp.tool()\ndef wipe(path):\n    shutil.rmtree(path)\n"
    )

    code = main([str(tmp_path)])

    assert code == 1
    assert "FAIL_CRITICAL" in capsys.readouterr().out


def test_critical_finding_returns_one_even_above_min_score(tmp_path, capsys):
    # A permissive --min-score must not buy back a pass on a critical
    # finding just because the aggregate score clears the bar.
    (tmp_path / "bad.py").write_text(
        "@mcp.tool()\ndef wipe(path):\n    shutil.rmtree(path)\n"
    )

    code = main([str(tmp_path), "--min-score", "1"])

    assert code == 1


def test_json_output_is_parseable(tmp_path, capsys):
    (tmp_path / "flags.py").write_text(GOVERNED + "auto_approve = True\n")

    code = main([str(tmp_path), "--json"])

    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["score"] == 90.0
    assert data["verdict"] == "PASS"
    assert data["findings"][0]["rule"] == "permissive-defaults"
    assert data["findings"][0]["critical"] is False


def test_missing_target_returns_two(capsys):
    code = main(["definitely_not_a_real_path_xyz"])

    assert code == 2
    assert "not found" in capsys.readouterr().err


def test_directory_with_no_python_files_returns_two(tmp_path, capsys):
    # A pure-JS MCP server must not get a green 100/100 from a scanner
    # that looked at nothing.
    (tmp_path / "server.js").write_text("// not python\n")

    code = main([str(tmp_path)])

    assert code == 2
    assert "no Python or MCP config files" in capsys.readouterr().err


def test_all_files_unparseable_returns_two(tmp_path, capsys):
    (tmp_path / "broken.py").write_text("def broken(:\n")

    code = main([str(tmp_path)])

    err = capsys.readouterr().err
    assert code == 2
    assert "skipped" in err
    assert "no Python or MCP config files" in err


def test_directory_with_only_a_config_file_is_not_zero_evidence(tmp_path, capsys):
    # The bug this pins: files_scanned only counts .py files, so a
    # directory holding nothing but a recognized MCP config JSON file used
    # to be rejected as "zero evidence" even though the config scanner
    # found and evaluated something real.
    (tmp_path / "mcp.json").write_text('{"autoApprove": true}\n')

    code = main([str(tmp_path), "--json"])

    assert code == 0  # permissive-defaults is never critical
    out = json.loads(capsys.readouterr().out)
    assert out["config_files_scanned"] == 1
    assert out["findings"][0]["rule"] == "permissive-defaults"


def test_sarif_output_is_parseable(tmp_path, capsys):
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    code = main([str(tmp_path), "--sarif"])

    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["ruleId"] == "permissive-defaults"


def test_json_and_sarif_are_mutually_exclusive(tmp_path, capsys):
    # argparse itself rejects the combination before main() gets to run --
    # it exits via SystemExit(2), the same as any other malformed invocation.
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    with pytest.raises(SystemExit) as exc_info:
        main([str(tmp_path), "--json", "--sarif"])

    assert exc_info.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_min_score_from_config_file_gates_without_a_cli_flag(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.checkride]\nmin_score = 95\n")
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    code = main([str(tmp_path)])

    assert code == 1  # 90.0 scored, below the config's min_score of 95


def test_cli_min_score_flag_overrides_config_file(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.checkride]\nmin_score = 95\n")
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    code = main([str(tmp_path), "--min-score", "50"])

    assert code == 0  # CLI flag (50) wins over the config file's 95


def test_explicit_config_flag_is_used_instead_of_discovery(tmp_path, capsys):
    (tmp_path / "flags.py").write_text("auto_approve = True\n")
    custom = tmp_path / "custom.toml"
    custom.write_text("[tool.checkride]\nmin_score = 50\n")

    code = main([str(tmp_path), "--config", str(custom)])

    assert code == 0


def test_malformed_config_file_returns_two(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.checkride\nmin_score = 1\n")
    (tmp_path / "flags.py").write_text("auto_approve = True\n")

    code = main([str(tmp_path)])

    assert code == 2
    assert "pyproject.toml" in capsys.readouterr().err


def test_inline_suppression_is_reflected_in_output(tmp_path, capsys):
    (tmp_path / "flags.py").write_text(
        "auto_approve = True  # checkride: ignore\n"
    )

    code = main([str(tmp_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "100.0 / 100" in out
    assert "1 finding(s) suppressed" in out


def test_version_flag_prints_the_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_fail_on_incomplete_turns_a_partial_scan_red(tmp_path, capsys):
    # A file checkride could not parse is a hole in its coverage; a repo
    # that wants CI to reflect that can now say so.
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "broken.py").write_text("def broken(:\n")

    assert main([str(tmp_path)]) == 0
    assert main([str(tmp_path), "--fail-on-incomplete"]) == 1
    assert "INCOMPLETE" in capsys.readouterr().out


def test_fail_on_incomplete_does_not_affect_a_complete_scan(tmp_path):
    (tmp_path / "ok.py").write_text(GOVERNED + "auto_approve = False\n")

    assert main([str(tmp_path), "--fail-on-incomplete"]) == 0


def test_zero_sites_cannot_pass_the_strictest_gate(tmp_path, capsys):
    # The hole: a repo checkride recognized nothing in scored 100.0/100
    # and exited 0 under `--min-score 100 --fail-on-incomplete` -- the
    # strictest invocation available. A team reading that green build
    # concluded "governed" when the truthful answer was "not measured".
    (tmp_path / "util.py").write_text("def add(a, b):\n    return a + b\n")

    code = main([str(tmp_path), "--min-score", "100", "--fail-on-incomplete"])

    captured = capsys.readouterr()
    assert code == 1
    assert "INCOMPLETE" in captured.out
    assert "APPLICABLE SITES" in captured.out
    assert "no tool entry points recognized" in captured.err


def test_zero_sites_in_scope_all_cannot_pass_the_strictest_gate(tmp_path, capsys):
    (tmp_path / "util.py").write_text("def add(a, b):\n    return a + b\n")

    code = main([str(tmp_path), "--scope", "all", "--min-score", "100", "--fail-on-incomplete"])

    captured = capsys.readouterr()
    assert code == 1
    assert "INCOMPLETE" in captured.out
    assert "absence of anything to check" in captured.err


def test_excluded_file_count_is_shown_to_the_reader(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.checkride]\nexclude = ['hidden/*']\n"
    )
    (tmp_path / "hidden").mkdir()
    (tmp_path / "hidden" / "server.py").write_text("auto_approve = True\n")
    (tmp_path / "kept.py").write_text("auto_approve = False\n")

    main([str(tmp_path)])

    captured = capsys.readouterr()
    assert "EXCLUDED BY CONFIG" in captured.out
    assert "1 file(s)" in captured.out


def test_disabled_gate_rule_is_warned_about_and_not_a_pass(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.checkride]\ndisabled_rules = ['human-oversight']\n"
    )
    (tmp_path / "server.py").write_text(GOVERNED.replace(
        "    if not request_approval('wipe', path):\n        return False\n", ""
    ))

    code = main([str(tmp_path), "--fail-on-incomplete"])

    captured = capsys.readouterr()
    assert code == 1
    assert "INCOMPLETE" in captured.out
    assert "FAIL_CRITICAL gate" in captured.err


def test_config_source_is_reported_so_an_ignored_config_is_visible(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.checkride]\nmin_score = 1\n")
    (tmp_path / "server.py").write_text("x = 1\n")

    main([str(tmp_path)])

    assert "config: " in capsys.readouterr().out


def test_no_config_source_line_when_no_config_applies(tmp_path, capsys):
    (tmp_path / "server.py").write_text("x = 1\n")

    main([str(tmp_path)])

    assert "config: " not in capsys.readouterr().out


def test_json_output_carries_the_config_source(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.checkride]\nmin_score = 1\n")
    (tmp_path / "server.py").write_text("x = 1\n")

    main([str(tmp_path), "--json"])

    data = json.loads(capsys.readouterr().out)
    assert data["config_source"].endswith("pyproject.toml")


def test_control_characters_in_output_are_defanged(capsys):
    # File names are attacker-controlled on a scanned repo (a newline or an
    # ANSI escape is a legal POSIX filename), and they reach the terminal
    # verbatim. A path must not be able to repaint the report around it.
    escape = chr(27)
    report = ScanReport(categories=[], files_scanned=1)
    report.categories.append(
        CategoryResult(
            name="Permissive defaults",
            weight=10,
            sites=1,
            findings=[
                Finding(
                    rule="permissive-defaults",
                    file=f"evil{escape}[2Jname.py",
                    line=1,
                    message="permissive default",
                    fix="flip it",
                )
            ],
        )
    )

    _print_report(report, f"target{escape}[2J", None)

    out = capsys.readouterr().out
    assert escape not in out
    assert "\\x1b[2Jname.py" in out


def test_bidi_and_c1_characters_in_output_are_defanged(capsys):
    # Before: only C0 controls and DEL were escaped, so three ways of
    # misleading the reader survived. U+202E RIGHT-TO-LEFT OVERRIDE in a
    # file name reverses the rest of the line as it renders, which is the
    # Trojan Source trick (CVE-2021-42574) aimed at the report rather than
    # at source; 0x9B is CSI to a terminal in 8-bit mode, reaching the same
    # capability the C0 range already blocked through a different encoding;
    # and zero-width characters hide content outright. All are legal in a
    # POSIX filename, so all are attacker-controlled on a scanned repo.
    rlo, csi, zwsp = chr(0x202E), chr(0x9B), chr(0x200B)
    report = ScanReport(categories=[], files_scanned=1)
    report.categories.append(
        CategoryResult(
            name="Permissive defaults",
            weight=10,
            sites=1,
            findings=[
                Finding(
                    rule="permissive-defaults",
                    file=f"safe{rlo}gnp.py",
                    line=1,
                    message=f"flagged{csi}[2J",
                    fix=f"fix{zwsp}it",
                )
            ],
        )
    )

    _print_report(report, "target", None)

    out = capsys.readouterr().out
    for raw in (rlo, csi, zwsp):
        assert raw not in out
    assert "safe\\u202egnp.py" in out
    assert "flagged\\x9b[2J" in out
    assert "fix\\u200bit" in out


def test_unknown_config_key_is_a_usage_error(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text("[tool.checkride]\nexcludes = ['x']\n")
    (tmp_path / "server.py").write_text("x = 1\n")

    code = main([str(tmp_path)])

    assert code == 2
    assert "unknown key" in capsys.readouterr().err


def test_scan_with_no_applicable_sites_says_so(tmp_path, capsys):
    (tmp_path / "server.py").write_text("def add(a, b):\n    return a + b\n")

    code = main([str(tmp_path), "--scope", "all"])

    captured = capsys.readouterr()
    assert code == 0
    assert "100.0 / 100" in captured.out
    assert "absence of anything to check" in captured.err


def _break_the_pipe(monkeypatch):
    """Make every print in cli.py raise BrokenPipeError, the way a closed
    pipe does, without touching the real stdout descriptor pytest is using.
    A module-level `print` shadows the builtin for that module only."""
    def exploding_print(*_args, **_kwargs):
        raise BrokenPipeError

    monkeypatch.setattr(cli, "print", exploding_print, raising=False)
    redirected = []
    monkeypatch.setattr(cli.os, "dup2", lambda *a: redirected.append(a))
    return redirected


def test_closed_stdout_pipe_does_not_break_the_exit_code(tmp_path, monkeypatch):
    # `checkride . --json | head -1` closes the pipe mid-write. That is a
    # consumer finishing early, not a scan failure, so the exit code must
    # still reflect the governance result.
    (tmp_path / "bad.py").write_text(
        "import shutil\n@mcp.tool()\ndef wipe(path):\n    shutil.rmtree(path)\n"
    )
    redirected = _break_the_pipe(monkeypatch)

    assert main([str(tmp_path), "--json"]) == 1
    assert redirected  # stdout was pointed at the null device


def test_closed_stdout_pipe_on_the_human_report_is_also_survivable(
    tmp_path, monkeypatch
):
    (tmp_path / "ok.py").write_text("auto_approve = False\n")
    _break_the_pipe(monkeypatch)

    assert main([str(tmp_path)]) == 0


def test_closed_stdout_pipe_on_sarif_is_survivable(tmp_path, monkeypatch):
    (tmp_path / "ok.py").write_text("auto_approve = True\n")
    _break_the_pipe(monkeypatch)

    assert main([str(tmp_path), "--sarif"]) == 0


# --- baseline mode ---


def test_update_baseline_without_baseline_flag_is_a_usage_error(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("x = 1\n")

    with pytest.raises(SystemExit) as exc_info:
        main([str(tmp_path), "--update-baseline"])

    assert exc_info.value.code == 2
    assert "--update-baseline requires --baseline" in capsys.readouterr().err


def test_update_baseline_writes_current_findings_and_exits_zero(tmp_path, capsys):
    (tmp_path / "bad.py").write_text("auto_approve = True\n")
    baseline_path = tmp_path / "baseline.json"

    code = main(
        [str(tmp_path), "--baseline", str(baseline_path), "--update-baseline"]
    )

    assert code == 0
    assert baseline_path.is_file()
    assert "baseline updated: 1 finding(s) written" in capsys.readouterr().out


def test_baseline_gates_only_on_new_findings(tmp_path, capsys):
    (tmp_path / "server.py").write_text("auto_approve = True\n")
    baseline_path = tmp_path / "baseline.json"

    assert main(
        [str(tmp_path), "--baseline", str(baseline_path), "--update-baseline"]
    ) == 0

    # Rerunning against the unchanged repo: nothing new, exit 0.
    assert main([str(tmp_path), "--baseline", str(baseline_path)]) == 0
    capsys.readouterr()  # discard output from the two runs above

    # A second, different violation appears: exactly one new finding, exit 1.
    (tmp_path / "server.py").write_text(
        "auto_approve = True\nskip_confirmation = True\n"
    )
    code = main([str(tmp_path), "--baseline", str(baseline_path), "--json"])
    out = json.loads(capsys.readouterr().out)

    assert code == 1
    assert out["baseline_applied"] is True
    assert len(out["baseline_new"]) == 1
    assert "skip_confirmation" in out["baseline_new"][0]["message"]


def test_baseline_never_suppresses_a_critical_finding(tmp_path):
    (tmp_path / "server.py").write_text(
        "import shutil\n@mcp.tool()\ndef wipe(path):\n    shutil.rmtree(path)\n"
    )
    baseline_path = tmp_path / "baseline.json"

    # Baseline the critical finding away, in spirit -- write_baseline drops
    # critical findings unconditionally, so this baseline is really empty.
    main([str(tmp_path), "--baseline", str(baseline_path), "--update-baseline"])

    code = main([str(tmp_path), "--baseline", str(baseline_path)])

    assert code == 1  # FAIL_CRITICAL, unaffected by the baseline


def test_missing_baseline_file_is_treated_as_empty_with_a_warning(tmp_path, capsys):
    (tmp_path / "server.py").write_text("auto_approve = True\n")

    code = main(
        [str(tmp_path), "--baseline", str(tmp_path / "does-not-exist.json")]
    )

    assert code == 1  # everything is "new" against an empty baseline
    assert "does not exist yet" in capsys.readouterr().err


def test_malformed_baseline_file_returns_two(tmp_path, capsys):
    (tmp_path / "server.py").write_text("x = 1\n")
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text("{not json")

    code = main([str(tmp_path), "--baseline", str(baseline_path)])

    assert code == 2
    assert "baseline" in capsys.readouterr().err.lower()


def test_baseline_hides_pre_existing_findings_from_human_output(tmp_path, capsys):
    (tmp_path / "server.py").write_text("auto_approve = True\n")
    baseline_path = tmp_path / "baseline.json"
    main([str(tmp_path), "--baseline", str(baseline_path), "--update-baseline"])
    capsys.readouterr()

    code = main([str(tmp_path), "--baseline", str(baseline_path)])
    out = capsys.readouterr().out

    assert code == 0
    assert "Findings" not in out  # nothing new to list
    assert "hidden by baseline" in out


# --- new flags --------------------------------------------------------------

def test_default_floor_fails_a_poorly_governed_scan(tmp_path, capsys):
    (tmp_path / "s.py").write_text(
        GOVERNED.replace("    audit_log('wipe', path)\n", "")
        .replace("    rate_limiter.acquire()\n", "")
        .replace("        logger.error('wipe failed: %s', exc)\n", "        return False\n")
    )
    assert main([str(tmp_path)]) == 1
    assert "FAIL_SCORE" in capsys.readouterr().out
    assert main([str(tmp_path), "--min-score", "0"]) == 0


def test_min_score_out_of_range_is_a_usage_error(tmp_path):
    (tmp_path / "s.py").write_text(GOVERNED)
    assert main([str(tmp_path), "--min-score", "150"]) == 2


def test_scope_flag_overrides_config(tmp_path, capsys):
    (tmp_path / "s.py").write_text("import os\ndef f(p):\n    os.remove(p)\n")
    assert main([str(tmp_path)]) == 0  # INCOMPLETE: no tools recognized
    capsys.readouterr()
    assert main([str(tmp_path), "--scope", "all"]) == 1
    assert "FAIL_CRITICAL" in capsys.readouterr().out


def test_accepted_risks_are_listed_and_can_be_ignored(tmp_path, capsys):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.checkride]\n"
        "[[tool.checkride.accepted_risks]]\n"
        'rule = "human-oversight"\nfile = "s.py"\nfunction = "wipe"\n'
        'reason = "deletes only the scratch dir it created"\n'
    )
    (tmp_path / "s.py").write_text(
        GOVERNED.replace("    if not request_approval('wipe', path):\n        return False\n", "")
    )
    import os

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert main(["."]) == 0
        out = capsys.readouterr().out
        assert "Accepted risks (1)" in out
        assert "deletes only the scratch dir it created" in out
        assert main([".", "--ignore-accepted-risks"]) == 1
    finally:
        os.chdir(cwd)


def test_report_shows_tool_entry_points_and_out_of_scope_sinks(tmp_path, capsys):
    (tmp_path / "s.py").write_text(GOVERNED + "def maintenance():\n    os.system('make')\n")
    main([str(tmp_path)])
    out = capsys.readouterr().out
    assert "TOOL ENTRY POINTS" in out
    assert "NOT AGENT-REACHABLE" in out


def test_javascript_project_gets_an_explicit_unsupported_message(tmp_path, capsys):
    (tmp_path / "server.ts").write_text("export const x = 1;\n")
    (tmp_path / "node_modules").mkdir()

    assert main([str(tmp_path)]) == 2
    assert "JavaScript/TypeScript project" in capsys.readouterr().err


def test_empty_python_free_directory_gets_no_javascript_hint(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("hello\n")

    assert main([str(tmp_path)]) == 2
    assert "JavaScript" not in capsys.readouterr().err

