"""Scoring aggregator: run every rule over every parsed file, merge the
per-file (sites, passed, findings) tuples into per-category CategoryResults,
and wrap them in a ScanReport with the 0-100 score and the verdict.

Contexts are consumed one at a time; no rule logic or point math lives
here. Scan-wide concerns do: disabled rules, inline suppressions and
accepted risks (each converts a failing site into a recorded, visible pass
rather than hiding it), and the scope statistics that say how much of the
code was judged at all.
"""

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from checkride.astutils import FileContext
from checkride.config import AcceptedRisk
from checkride.models import CategoryResult, Finding
from checkride.rules import (
    audit,
    defaults,
    errorhandling,
    oversight,
    ratelimit,
    validation,
)

# The single registry every downstream consumer (scanner, CLI) uses.
ALL_RULES = [oversight, audit, ratelimit, errorhandling, validation, defaults]

# Rules whose findings are the source of `critical`, and therefore of
# FAIL_CRITICAL. Disabling one removes the gate itself, so such a scan is
# never a PASS (see ScanReport.verdict).
CRITICAL_GATE_RULES = frozenset({oversight.RULE_ID})

VERDICTS = ("PASS", "FAIL_CRITICAL", "FAIL_SCORE", "INCOMPLETE")


@dataclass(frozen=True)
class AcceptedFinding:
    finding: Finding
    reason: str


@dataclass(frozen=True)
class ToolFunction:
    file: str
    line: int
    name: str


@dataclass
class ScanReport:
    """Everything a scan produced: six category tallies plus bookkeeping."""

    categories: list[CategoryResult]
    files_scanned: int = 0
    config_files_scanned: int = 0
    skipped: list[str] = field(default_factory=list)
    excluded: int = 0
    suppressed: int = 0
    critical_suppressed: int = 0
    suppressed_findings: list[Finding] = field(default_factory=list)
    accepted: list[AcceptedFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    gate_disabled: tuple[str, ...] = ()
    # "tools": only code reachable from a tool entry point was judged.
    scope: str = "tools"
    tool_functions: list[ToolFunction] = field(default_factory=list)
    out_of_scope_sensitive_calls: int = 0
    # The PASS threshold. None: no score floor (library use).
    min_score: float | None = None
    # Baseline mode, set by cli.py; never affects score or verdict.
    baseline_applied: bool = False
    baseline_new: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> float:
        return sum(c.score for c in self.categories)

    @property
    def max_score(self) -> int:
        """Normally 100; lower only if disabled_rules removed a category.
        The maximum shrinks honestly instead of renormalizing to 100."""
        return sum(c.weight for c in self.categories)

    @property
    def total_sites(self) -> int:
        return sum(c.sites for c in self.categories)

    @property
    def no_tools_found(self) -> bool:
        """Python was scanned in tool scope, but no tool entry point was
        recognized -- so nothing agent-reachable was judged."""
        return self.scope == "tools" and self.files_scanned > 0 and not self.tool_functions

    @property
    def verdict(self) -> str:
        """PASS / FAIL_CRITICAL / FAIL_SCORE / INCOMPLETE.

        FAIL_CRITICAL: an agent-reachable critical action (payment, file
        delete, shell/code exec, dynamic SQL, remote delete) has no approval
        check before it. No score, suppression comment or baseline buys it
        back; only a fix or a reviewed `accepted_risks` entry does.

        FAIL_SCORE: no critical finding, but the score is below the floor.

        INCOMPLETE: the scan cannot support a PASS -- a file could not be
        parsed, the critical-gate rule is disabled, nothing applicable was
        found, or no tool entry point was recognized.
        """
        if any(f.critical for f in self.findings) or self.critical_suppressed:
            return "FAIL_CRITICAL"
        if self.min_score is not None and self.score < self.min_score:
            return "FAIL_SCORE"
        if self.skipped or self.gate_disabled or self.total_sites == 0 or self.no_tools_found:
            return "INCOMPLETE"
        return "PASS"

    @property
    def findings(self) -> list[Finding]:
        """All findings across categories, in a fully specified order (two
        findings can share a location, so file and line alone would leave
        their order to rule registration)."""
        return sorted(
            (f for c in self.categories for f in c.findings),
            key=lambda f: (f.file, f.line, f.column, f.rule, f.message),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "max_score": self.max_score,
            "min_score": self.min_score,
            "verdict": self.verdict,
            "files_scanned": self.files_scanned,
            "config_files_scanned": self.config_files_scanned,
            "total_sites": self.total_sites,
            "critical_gate_active": not self.gate_disabled,
            "scope": self.scope,
            "tool_functions": [asdict(t) for t in self.tool_functions],
            "out_of_scope_sensitive_calls": self.out_of_scope_sensitive_calls,
            "categories": [
                {
                    "name": c.name,
                    "weight": c.weight,
                    "sites": c.sites,
                    "passed": c.passed,
                    "score": round(c.score, 1),
                }
                for c in self.categories
            ],
            "findings": [asdict(f) for f in self.findings],
            "accepted_risks": [
                {**asdict(a.finding), "reason": a.reason} for a in self.accepted
            ],
            "skipped": self.skipped,
            "excluded": self.excluded,
            "suppressed": self.suppressed,
            "critical_suppressed": self.critical_suppressed,
            "warnings": self.warnings,
            "baseline_applied": self.baseline_applied,
            "baseline_new": [asdict(f) for f in self.baseline_new],
        }


def _suppression_warnings(ctx: FileContext, known_rule_ids: set[str]) -> list[str]:
    """Suppression comments that do not do what their author meant: markers
    that could not be parsed (they grant nothing), and markers naming a rule
    id that does not exist."""
    notes = [
        f"{ctx.path}:{line}: malformed checkride suppression ({reason}) "
        "-- nothing was suppressed"
        for line, reason in ctx.malformed_suppressions
    ]
    for line, rules in sorted(ctx.suppressions.items()):
        if rules is None:
            continue
        for unknown in sorted(rules - known_rule_ids):
            notes.append(
                f"{ctx.path}:{line}: checkride suppression names unknown rule "
                f"'{unknown}' -- it has no effect"
            )
    return notes


def _matches(risk: AcceptedRisk, finding: Finding, call: str | None) -> bool:
    if risk.rule != finding.rule:
        return False
    if finding.file != risk.file and not finding.file.endswith("/" + risk.file):
        return False
    if risk.function is not None:
        qual = finding.function or "<module>"
        if risk.function not in (qual, qual.rsplit(".", 1)[-1]):
            return False
    return not (risk.call is not None and risk.call != call)


def _finding_call(finding: Finding) -> str | None:
    """The sink name quoted in a finding message ("... call 'x.y' ...")."""
    marker = " call '"
    start = finding.message.find(marker)
    if start < 0:
        return None
    start += len(marker)
    end = finding.message.find("'", start)
    return finding.message[start:end] if end > start else None


def score_contexts(
    contexts: Iterable[FileContext],
    disabled_rules: frozenset[str] = frozenset(),
    accepted_risks: tuple[AcceptedRisk, ...] = (),
    scope: str = "tools",
) -> ScanReport:
    active_rules = [rule for rule in ALL_RULES if rule.RULE_ID not in disabled_rules]
    categories = [
        CategoryResult(name=rule.CATEGORY, weight=rule.WEIGHT)
        for rule in active_rules
    ]
    known_rule_ids = {rule.RULE_ID for rule in ALL_RULES}
    report = ScanReport(categories=categories, scope=scope)
    used_risks: set[int] = set()
    for ctx in contexts:  # one context alive at a time; never materialized
        report.files_scanned += 1
        report.warnings.extend(_suppression_warnings(ctx, known_rule_ids))
        report.tool_functions.extend(
            ToolFunction(ctx.path, fn.lineno, ctx.qualname(fn) or fn.name)
            for fn in sorted(ctx.tool_functions, key=lambda f: (f.lineno, f.col_offset))
        )
        report.out_of_scope_sensitive_calls += ctx.out_of_scope_sensitive_calls
        for rule, cat in zip(active_rules, categories):
            sites, passed, findings = rule.check(ctx)
            kept = []
            for f in findings:
                risk_index = next(
                    (
                        i for i, risk in enumerate(accepted_risks)
                        if _matches(risk, f, _finding_call(f))
                    ),
                    None,
                )
                if risk_index is not None:
                    # A reviewed, recorded decision: the site passes and the
                    # finding is listed with its reason in every report.
                    used_risks.add(risk_index)
                    passed += 1
                    report.accepted.append(
                        AcceptedFinding(f, accepted_risks[risk_index].reason)
                    )
                elif ctx.is_suppressed(f.rule, f.line):
                    # Credited toward the score, but a critical one still
                    # trips the verdict: an inline comment is not a review.
                    passed += 1
                    report.suppressed += 1
                    report.suppressed_findings.append(f)
                    if f.critical:
                        report.critical_suppressed += 1
                else:
                    kept.append(f)
            cat.sites += sites
            cat.passed += passed
            cat.findings.extend(kept)

    report.gate_disabled = tuple(sorted(disabled_rules & CRITICAL_GATE_RULES))
    for rule_id in report.gate_disabled:
        report.warnings.append(
            f"'{rule_id}' is disabled, which removes the FAIL_CRITICAL gate "
            "entirely -- no ungated payment, deletion or shell-exec call can "
            "be detected in this scan, so its verdict is INCOMPLETE"
        )
    for i, risk in enumerate(accepted_risks):
        if i not in used_risks:
            report.warnings.append(
                f"accepted_risks entry for {risk.rule} in {risk.file}"
                + (f" ({risk.function})" if risk.function else "")
                + " matched no finding -- remove it if the risk is gone"
            )
    if report.no_tools_found:
        report.warnings.append(
            f"no tool entry points recognized in {report.files_scanned} file(s), "
            "so no agent-reachable code was judged and the verdict is INCOMPLETE. "
            "If this is agent code, name its tools with extra_tool_decorators / "
            "extra_tool_entry_points, or set scope = \"all\""
        )
    elif report.files_scanned and report.total_sites == 0:
        report.warnings.append(
            f"no governance-relevant sites found in {report.files_scanned} file(s): "
            "this score reflects the absence of anything to check, not "
            "evidence of governance -- the verdict is INCOMPLETE for that "
            "reason, and --fail-on-incomplete turns it into a red build"
        )
    return report
