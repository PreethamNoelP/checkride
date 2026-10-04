"""Command-line interface: `checkride <path> [--json|--sarif] [--min-score N]`.

Exit codes are the contract for CI:
  0  verdict is PASS, or INCOMPLETE without --fail-on-incomplete, and (with
     --baseline) nothing new since the baseline
  1  verdict is FAIL_CRITICAL (an agent-reachable critical action with no
     approval check before it) or FAIL_SCORE (score below --min-score /
     min_score, default 70); OR the verdict is INCOMPLETE and
     --fail-on-incomplete was passed; OR --baseline found a new finding
  2  bad invocation: target missing, nothing scanned, a malformed config or
     baseline file, --update-baseline without --baseline
"""

import argparse
import dataclasses
import json
import os
import sys
from pathlib import Path

from checkride import __version__
from checkride.baseline import (
    BaselineError,
    diff_against_baseline,
    load_baseline,
    write_baseline,
)
from checkride.config import SCOPES, Config, ConfigError, load_config
from checkride.sarif import build_sarif
from checkride.scanner import scan
from checkride.scoring import ScanReport

# Scanned repositories are untrusted input, and file names reach the
# terminal verbatim. A path containing an ANSI escape (legal on Linux and
# macOS) could otherwise repaint or erase the report a reviewer is reading.
_ESCAPES: dict[int, str] = {c: f"\\x{c:02x}" for c in range(32)}
_ESCAPES[127] = "\\x7f"
_ESCAPES[ord("\t")] = "    "

# C1 controls. A terminal in 8-bit mode reads 0x9b as CSI -- the single-byte
# equivalent of the ESC-[ that the C0 range above already defangs -- so
# escaping only C0 left the same capability reachable through a different
# encoding of it.
_ESCAPES.update({c: f"\\x{c:02x}" for c in range(0x80, 0xA0)})

# Characters that reorder or hide text without being "control characters" at
# all. A file named with U+202E RIGHT-TO-LEFT OVERRIDE makes the rest of a
# finding line render in reverse, so a reviewer reading the report sees a
# path, rule id or fix that is not the one checkride found -- the Trojan
# Source trick (CVE-2021-42574) pointed at the report instead of at source.
# Zero-width characters hide content in the same spirit. None of these have
# any legitimate place in a rendered finding, so they are shown escaped
# rather than obeyed.
_ESCAPES.update(
    {
        c: f"\\u{c:04x}"
        for c in (
            *range(0x202A, 0x202F),  # LRE RLE PDF LRO RLO
            *range(0x2066, 0x206A),  # LRI RLI FSI PDI
            0x200B,                  # zero-width space
            0x200C,                  # zero-width non-joiner
            0x200D,                  # zero-width joiner
            0x2060,                  # word joiner
            0xFEFF,                  # zero-width no-break space / BOM
        )
    }
)


def _safe(text: str) -> str:
    """Render text from the scanned repo with control characters defanged."""
    return str(text).translate(_ESCAPES)


def _print_report(
    report: ScanReport,
    target: str,
    config_source: str | None,
    baseline_written: int | None = None,
) -> None:
    print(f"checkride: {_safe(target)}")
    print(f"scanned {report.files_scanned} Python file(s)", end="")
    if report.config_files_scanned:
        print(f" and {report.config_files_scanned} MCP config file(s)", end="")
    print(f" (config: {_safe(config_source)})\n" if config_source else "\n")

    for c in report.categories:
        status = (
            "(no applicable sites)"
            if c.sites == 0
            else f"({c.passed}/{c.sites} sites passed)"
        )
        print(f"  {c.name:<34}{c.score:>6.1f} / {c.weight:<3} {status}")
    print("  " + "-" * 58)
    print(f"  {'GOVERNANCE SCORE':<34}{report.score:>6.1f} / {report.max_score}")
    print(f"  {'VERDICT':<34}{report.verdict}")

    # The denominator behind the score, in the one place a reader cannot
    # miss it. A 100.0 over 0 sites and a 100.0 over 200 are the same
    # number and completely different claims; printing only the number let
    # the first pass for the second.
    print(f"  {'APPLICABLE SITES':<34}{report.total_sites}")
    if report.min_score is not None:
        print(f"  {'PASS THRESHOLD':<34}{report.min_score:g}")
    if report.scope == "tools":
        print(f"  {'TOOL ENTRY POINTS':<34}{len(report.tool_functions)}")
        if report.out_of_scope_sensitive_calls:
            print(
                f"  {'NOT AGENT-REACHABLE':<34}{report.out_of_scope_sensitive_calls}"
                " sensitive call(s), not judged"
            )
    else:
        print(f"  {'SCOPE':<34}all code")
    if report.excluded:
        print(f"  {'EXCLUDED BY CONFIG':<34}{report.excluded} file(s)")

    if report.suppressed:
        print(f"  ({report.suppressed} finding(s) suppressed by inline comment)")
    if report.critical_suppressed:
        print(
            f"  ({report.critical_suppressed} suppressed finding(s) were critical -- "
            "still counted toward FAIL_CRITICAL; suppression cannot buy back the verdict)"
        )

    if report.accepted:
        print(f"\nAccepted risks ({len(report.accepted)}):")
        for a in report.accepted:
            f = a.finding
            print(f"\n  {_safe(f.file)}:{f.line}  [{f.rule}]")
            print(f"    {_safe(f.message)}")
            print(f"    accepted: {_safe(a.reason)}")

    if baseline_written is not None:
        print(f"  (baseline updated: {baseline_written} finding(s) written)")

    # Baseline mode changes which findings are *listed*, never the score or
    # verdict above -- those always reflect the whole scan. Listing only the
    # new ones is the entire point of adopting a baseline on a legacy repo:
    # decluttering a backlog no one is fixing today without hiding it from
    # the score that already accounts for it.
    shown = report.baseline_new if report.baseline_applied else report.findings
    if shown:
        print(f"\nFindings ({len(shown)}):")
        for f in shown:
            print(f"\n  {_safe(f.file)}:{f.line}  [{f.rule}]")
            print(f"    {_safe(f.message)}")
            print(f"    fix: {_safe(f.fix)}")
    if report.baseline_applied and len(report.findings) > len(shown):
        hidden = len(report.findings) - len(shown)
        print(
            f"\n({hidden} pre-existing finding(s) hidden by baseline -- "
            "see --update-baseline to accept the current state, or omit "
            "--baseline to see everything)"
        )

    _print_warnings(report)


def _print_warnings(report: ScanReport) -> None:
    for entry in report.warnings:
        print(f"warning: {_safe(entry)}", file=sys.stderr)
    for entry in report.skipped:
        print(f"warning: skipped {_safe(entry)}", file=sys.stderr)


_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")


def _has_javascript(target: Path) -> bool:
    """True if the target holds JS/TS sources (outside the usual noise
    directories). Stops at the first one found."""
    from checkride.fswalk import SKIP_DIRS

    if target.is_file():
        return target.suffix in _JS_SUFFIXES
    for _dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if any(name.endswith(_JS_SUFFIXES) for name in filenames):
            return True
    return False


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="checkride",
        description="Static governance scanner for MCP servers and "
                    "AI agent tool-calling code.",
    )
    parser.add_argument("target", help="Python file or repo directory to scan")
    parser.add_argument(
        "--version", action="version", version=f"checkride {__version__}"
    )
    output_format = parser.add_mutually_exclusive_group()
    output_format.add_argument(
        "--json", action="store_true", help="emit a machine-readable JSON report"
    )
    output_format.add_argument(
        "--sarif",
        action="store_true",
        help="emit a SARIF 2.1.0 report for GitHub/GitLab code scanning",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        metavar="N",
        help="the score a PASS needs; below it the verdict is FAIL_SCORE "
             "(default 70, or [tool.checkride] min_score; 0 disables)",
    )
    parser.add_argument(
        "--scope",
        choices=SCOPES,
        default=None,
        help="'tools' (default) judges only code reachable from a recognized "
             "tool entry point; 'all' treats every function that performs a "
             "sensitive action as a tool (overrides [tool.checkride] scope)",
    )
    parser.add_argument(
        "--ignore-accepted-risks",
        action="store_true",
        help="judge findings covered by [tool.checkride] accepted_risks as "
             "if those entries did not exist",
    )
    parser.add_argument(
        "--fail-on-incomplete",
        action="store_true",
        help="exit with code 1 on an INCOMPLETE verdict -- a file that could "
             "not be parsed, or a disabled critical-gate rule, means the scan "
             "did not see everything it claims to cover",
    )
    config_source = parser.add_mutually_exclusive_group()
    config_source.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="path to a TOML file with a [tool.checkride] table; "
             "default is to look for pyproject.toml next to the target",
    )
    config_source.add_argument(
        "--no-config",
        action="store_true",
        help="ignore the target's own pyproject.toml and use the built-in "
             "defaults. Use this when scanning code you do not control: its "
             "[tool.checkride] table can exclude files, disable rules and "
             "accept risks, so a repository can otherwise grade itself",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        metavar="PATH",
        help="only exit non-zero for findings not already recorded in this "
             "baseline file -- for adopting checkride on an existing repo "
             "without fixing every finding on day one. Never suppresses a "
             "critical finding: --min-score and the FAIL_CRITICAL verdict "
             "still apply exactly as without a baseline",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="write the current non-critical findings to --baseline instead "
             "of gating on it; requires --baseline PATH",
    )
    return parser


def _emit(
    report: ScanReport,
    args: argparse.Namespace,
    config_source: str | None,
    baseline_written: int | None = None,
) -> None:
    """Write the report in the requested format.

    A consumer closing the pipe (`checkride . --json | head`) is a normal
    end to the conversation, not a scan failure: swallow it, point stdout at
    the null device so the interpreter's exit-time flush does not re-raise,
    and let the exit code still reflect the governance result.
    """
    try:
        if args.json:
            payload = report.to_dict()
            payload["config_source"] = config_source
            print(json.dumps(payload, indent=2))
        elif args.sarif:
            print(json.dumps(build_sarif(report, config_source), indent=2))
        else:
            _print_report(report, args.target, config_source, baseline_written)
            return
        _print_warnings(report)
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError, AttributeError):
            # No real file descriptor behind stdout (a captured or wrapped
            # stream). Nothing to redirect, and nothing left to flush.
            pass


def _escape_unencodable_output() -> None:
    """Make a character the console cannot encode print as an escape instead
    of raising. File names come from the scanned repository, so a single
    non-ASCII file name under a cp1252 console would otherwise end the report with a
    traceback halfway through -- and exit 1, the governance-failure code."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _escape_unencodable_output()
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.update_baseline and args.baseline is None:
        parser.error("--update-baseline requires --baseline PATH")

    target = Path(args.target)
    if not target.exists():
        # Without this check, scanning a typo'd path would find zero files,
        # zero sites -- and report a perfect 100.
        print(f"checkride: target not found: {_safe(args.target)}", file=sys.stderr)
        return 2

    try:
        config = Config() if args.no_config else load_config(target, args.config)
    except ConfigError as exc:
        print(f"checkride: {exc}", file=sys.stderr)
        return 2

    if args.scope is not None:
        config = dataclasses.replace(
            config, rules=dataclasses.replace(config.rules, scope=args.scope)
        )
    if args.ignore_accepted_risks:
        config = dataclasses.replace(config, accepted_risks=())
    if args.min_score is not None:
        if not 0 <= args.min_score <= 100:
            print("checkride: --min-score must be between 0 and 100", file=sys.stderr)
            return 2
        config = dataclasses.replace(config, min_score=args.min_score)

    report = scan(target, config=config)

    if report.files_scanned == 0 and report.config_files_scanned == 0:
        # A score over zero evidence is vacuous, and a vacuous score must
        # not look like a passing one. Covers empty repos, non-Python repos,
        # and directories where every file failed to parse. Checked against
        # both counters: a directory holding only a recognized MCP config
        # file (no .py files at all) is real evidence, not zero evidence,
        # even though files_scanned alone would read as zero.
        _print_warnings(report)
        print(
            f"checkride: no Python or MCP config files scanned under "
            f"{_safe(args.target)} -- refusing to report a score based on "
            "zero evidence",
            file=sys.stderr,
        )
        if _has_javascript(target):
            print(
                "checkride: this looks like a JavaScript/TypeScript project; "
                "only Python agent code is supported for now",
                file=sys.stderr,
            )
        return 2

    baseline_written = None
    if args.baseline is not None:
        if args.update_baseline:
            # scan()/score_contexts() know nothing of --baseline, so this is
            # set here rather than inside scan() -- baseline is a CLI-level
            # adoption convenience layered on top of the score/verdict, not
            # a thing that changes them (see baseline.py's module docstring).
            baseline_written = write_baseline(args.baseline, report.findings)
        else:
            if not args.baseline.is_file():
                report.warnings.append(
                    f"--baseline {args.baseline} does not exist yet -- "
                    "treating it as empty; every finding below is 'new' "
                    "until you run with --update-baseline"
                )
            try:
                baseline = load_baseline(args.baseline)
            except BaselineError as exc:
                print(f"checkride: {exc}", file=sys.stderr)
                return 2
            report.baseline_applied = True
            report.baseline_new = diff_against_baseline(report.findings, baseline)

    _emit(report, args, config.source, baseline_written)

    verdict = report.verdict
    if verdict in ("FAIL_CRITICAL", "FAIL_SCORE"):
        return 1
    if args.fail_on_incomplete and verdict == "INCOMPLETE":
        return 1
    # The baseline is an additional gate; it never relaxes the ones above.
    if report.baseline_applied and report.baseline_new:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
