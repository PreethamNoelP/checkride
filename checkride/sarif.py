"""SARIF 2.1.0 rendering: the format GitHub/GitLab code scanning, and most
enterprise AppSec dashboards, ingest natively. Kept separate from
ScanReport.to_dict() -- that one is checkride's own JSON shape, this one
exists to satisfy an external spec.

What a code-scanning consumer gets beyond results:
  - `partialFingerprints` that ignore line numbers, so an unrelated edit
    above a finding does not close it and open a "new" one;
  - per-rule `security-severity` (GitHub's severity scale) and help links;
  - inline-suppressed and accepted-risk findings as results carrying a
    SARIF `suppressions` entry, so the decision stays on record;
  - an invocation record of everything the scan could not read.

https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import hashlib
import re
from typing import Any

from checkride import __version__
from checkride.models import Finding
from checkride.scoring import ALL_RULES, ScanReport

SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/PreethamNoelP/checkride"
RULES_DOC = f"{INFORMATION_URI}/blob/main/RULES.md"

_RULE_INDEX = {rule.RULE_ID: i for i, rule in enumerate(ALL_RULES)}

# GitHub maps security-severity to critical (>= 9.0), high (>= 7.0),
# medium (>= 4.0) and low. A missing approval gate on a destructive action
# is the case this tool exists for; missing telemetry is not.
_SECURITY_SEVERITY = {
    "human-oversight": "9.0",
    "input-validation": "7.5",
    "permissive-defaults": "7.0",
    "error-handling": "4.0",
    "audit-logging": "4.0",
    "rate-limiting": "4.0",
}
FINGERPRINT_KEY = "checkride/v1"


def _rule_descriptors() -> list[dict[str, Any]]:
    """One reportingDescriptor per registered rule, whether or not it fired:
    a stable catalog lets a dashboard track a rule across scans."""
    descriptors = []
    for rule in ALL_RULES:
        doc = (rule.__doc__ or rule.CATEGORY).strip()
        descriptors.append({
            "id": rule.RULE_ID,
            "name": rule.CATEGORY.replace(" ", "").replace("&", "And"),
            "shortDescription": {"text": rule.CATEGORY},
            "fullDescription": {"text": doc.split("\n\n")[0].replace("\n", " ")},
            "helpUri": f"{RULES_DOC}#{rule.RULE_ID}",
            "help": {"text": doc, "markdown": doc},
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "category": rule.CATEGORY,
                "weight": rule.WEIGHT,
                "tags": ["security", "ai-agents", "mcp"],
                "precision": "medium",
                "security-severity": _SECURITY_SEVERITY[rule.RULE_ID],
            },
        })
    return descriptors


def _invocation(report: ScanReport, config_source: str | None) -> dict[str, Any]:
    """The run's invocation record: what checkride could not read, so a
    file skipped for a syntax error does not vanish from the dashboard."""
    invocation: dict[str, Any] = {
        # True even with notifications present: checkride itself ran to
        # completion. Per-file failures are reported, not run failures.
        "executionSuccessful": True,
        "toolExecutionNotifications": [
            {"level": "warning", "message": {"text": text}}
            for text in [f"skipped {entry}" for entry in report.skipped]
            + list(report.warnings)
        ],
    }
    if config_source is not None:
        invocation["properties"] = {"configSource": config_source}
    return invocation


def _fingerprints(findings: list[Finding]) -> list[str]:
    """Line-independent identity: rule, file, enclosing function and
    message, plus an occurrence index for byte-identical findings."""
    seen: dict[str, int] = {}
    result = []
    for f in findings:
        base = "\x1f".join((f.rule, f.file, f.function or "", f.message))
        index = seen.get(base, 0)
        seen[base] = index + 1
        digest = hashlib.sha256(f"{base}\x1f{index}".encode()).hexdigest()
        result.append(f"{digest[:32]}:{index}")
    return result


_URI_UNRESERVED = re.compile(rb"[A-Za-z0-9._~/-]")


def _file_uri(path: str) -> str:
    """A repository-relative path as a SARIF URI reference (RFC 3986).

    `artifactLocation.uri` is a URI, not a file name: a space, `#` or `%` in
    a path left raw is read as a fragment or an escape, so the result
    resolves to no file in code scanning. Percent-encode every byte outside
    the unreserved set, keeping `/`. Hand-rolled rather than urllib.parse so
    the package's documented import list stays unchanged.
    """
    return "".join(
        chr(b) if _URI_UNRESERVED.fullmatch(bytes([b])) else f"%{b:02X}"
        for b in path.encode("utf-8")
    )


def _result(f: Finding, fingerprint: str) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": f.line}
    if f.column:
        region["startColumn"] = f.column
    result: dict[str, Any] = {
        "ruleId": f.rule,
        "ruleIndex": _RULE_INDEX[f.rule],
        "level": "error" if f.critical else "warning",
        "message": {"text": f"{f.message}. Fix: {f.fix}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _file_uri(f.file)},
                    "region": region,
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint},
        "properties": {"critical": f.critical},
    }
    if f.function:
        result["locations"][0]["logicalLocations"] = [
            {"fullyQualifiedName": f.function, "kind": "function"}
        ]
    return result


def build_sarif(
    report: ScanReport, config_source: str | None = None
) -> dict[str, Any]:
    """Render a ScanReport as a SARIF 2.1.0 log. Critical findings are
    "error" (build-breaking), everything else "warning" -- the same split
    the verdict uses, so a dashboard's severity filter agrees with the exit
    code."""
    active = report.findings
    suppressed = sorted(
        report.suppressed_findings, key=lambda f: (f.file, f.line, f.column, f.rule)
    )
    accepted = sorted(report.accepted, key=lambda a: (a.finding.file, a.finding.line))
    every = active + suppressed + [a.finding for a in accepted]
    prints = _fingerprints(every)

    results = [_result(f, fp) for f, fp in zip(active, prints)]
    offset = len(active)
    for f, fp in zip(suppressed, prints[offset:]):
        r = _result(f, fp)
        r["suppressions"] = [{"kind": "inSource", "status": "accepted"}]
        results.append(r)
    offset += len(suppressed)
    for a, fp in zip(accepted, prints[offset:]):
        r = _result(a.finding, fp)
        r["suppressions"] = [
            {"kind": "external", "status": "accepted", "justification": a.reason}
        ]
        results.append(r)

    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "checkride",
                        # Which build produced a result: without it, a
                        # detection change looks like a code change.
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": _rule_descriptors(),
                    }
                },
                "invocations": [_invocation(report, config_source)],
                "results": results,
                "properties": {
                    "score": round(report.score, 1),
                    "maxScore": report.max_score,
                    "minScore": report.min_score,
                    "verdict": report.verdict,
                    "filesScanned": report.files_scanned,
                    "configFilesScanned": report.config_files_scanned,
                    "excluded": report.excluded,
                    "totalSites": report.total_sites,
                    "suppressed": report.suppressed,
                    "criticalSuppressed": report.critical_suppressed,
                    "acceptedRisks": len(report.accepted),
                    "criticalGateActive": not report.gate_disabled,
                    "scope": report.scope,
                    "toolEntryPoints": len(report.tool_functions),
                    "outOfScopeSensitiveCalls": report.out_of_scope_sensitive_calls,
                },
            }
        ],
    }
