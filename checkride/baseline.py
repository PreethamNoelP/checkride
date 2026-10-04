"""Baseline mode: let an existing repo adopt checkride without fixing
every finding on day one, while keeping the one guarantee this tool
promises cannot be bought back -- a baseline can never silence a critical
finding (see ScanReport.verdict in scoring.py for the same guarantee
applied to inline suppression and disabled_rules).

Identity problem this module has to solve: neither a Finding's full
identity (file, rule, line, message) nor a line-free one (file, rule,
message) is a safe key on its own.

  - Keying on `line` breaks the common case: any unrelated edit above a
    finding shifts every subsequent line number, which would mark every
    one of them "new" on the next scan even though nothing about them
    changed.
  - Dropping `line` isn't safe either: some rules produce byte-identical
    messages for multiple sites in one file (errorhandling.py's
    unconditional-loop finding is a bare string literal with no
    interpolation at all), so two such loops in the same file would
    collapse to one key and be indistinguishable.

The resolution is counting, not identity: a baseline stores how many
findings existed for each (file, rule, message) key, not which specific
instance. A scan's findings for that key are matched against the stored
count in existing sort order (already sorted by file, line, rule, message
-- see ScanReport.findings); anything beyond that count is "new". An
unrelated edit that shifts lines still matches (same key, same count); a
genuinely new instance of a recurring message is still caught, at the cost
of not being able to say *which* of several identical-looking instances is
the new one -- a documented, deliberate imprecision, not an oversight (see
RULES.md's "Baseline mode" section).
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from checkride.models import Finding

_SCHEMA_VERSION = 1


class BaselineError(Exception):
    """Raised for a present-but-malformed baseline file. Never raised for a
    missing one -- a missing baseline is the normal first-run state, not an
    error (mirrors config.ConfigError's own "missing is fine, malformed is
    not" split)."""


@dataclass(frozen=True)
class BaselineKey:
    file: str
    rule: str
    message: str


def _key(finding: Finding) -> BaselineKey:
    return BaselineKey(finding.file, finding.rule, finding.message)


def load_baseline(path: Path) -> dict[BaselineKey, int]:
    """Read a baseline file into a per-key count. A missing file returns an
    empty baseline -- the common first-run state, not an error. A present
    but unreadable/malformed one raises BaselineError, the same "silently
    differing from what the author believes" failure mode config.py already
    refuses to tolerate for [tool.checkride]."""
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"could not read baseline {path}: {exc}") from exc

    if not isinstance(data, dict) or data.get("version") != _SCHEMA_VERSION:
        raise BaselineError(
            f"{path} is not a recognized checkride baseline file "
            f"(expected {{'version': {_SCHEMA_VERSION}, 'findings': [...]}})"
        )
    entries = data.get("findings")
    if not isinstance(entries, list):
        raise BaselineError(f"{path}: 'findings' must be a list")

    counts: dict[BaselineKey, int] = {}
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("file"), str)
            or not isinstance(entry.get("rule"), str)
            or not isinstance(entry.get("message"), str)
            or not isinstance(entry.get("count"), int)
            or entry["count"] < 1
        ):
            raise BaselineError(f"{path}: malformed baseline entry {entry!r}")
        counts[BaselineKey(entry["file"], entry["rule"], entry["message"])] = (
            entry["count"]
        )
    return counts


def write_baseline(path: Path, findings: list[Finding]) -> int:
    """Write the given findings to a baseline file, grouped and counted by
    key. Critical findings are dropped unconditionally, never written --
    structurally, not just by convention, so a baseline file cannot be the
    mechanism that finally lets a critical finding through. Returns the
    number of (non-critical) findings written.

    Sorted by (file, rule, message) for a deterministic, reviewable diff --
    a baseline file is meant to be read in a pull request, the same way a
    lockfile is."""
    counts: dict[BaselineKey, int] = {}
    written = 0
    for finding in findings:
        if finding.critical:
            continue
        counts[_key(finding)] = counts.get(_key(finding), 0) + 1
        written += 1

    entries: list[dict[str, Any]] = [
        {"file": key.file, "rule": key.rule, "message": key.message, "count": count}
        for key, count in sorted(counts.items(), key=lambda kv: (kv[0].file, kv[0].rule, kv[0].message))
    ]
    payload = {"version": _SCHEMA_VERSION, "findings": entries}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return written


def diff_against_baseline(
    findings: list[Finding], baseline: dict[BaselineKey, int]
) -> list[Finding]:
    """Return the findings not already accounted for by the baseline.

    Critical findings always pass through as new -- the guarantee this
    module exists to keep: a baseline cannot be the reason a critical
    finding stops failing the build. Non-critical findings are grouped by
    key in the order they arrive (the caller passes ScanReport.findings,
    already sorted by file/line/rule/message); within each group, the
    first `baseline.get(key, 0)` occurrences are treated as known and the
    rest as new. Which specific instances count as "the new ones" among
    several identical-looking findings is an arbitrary but deterministic
    tie-break (whichever sort to last within the group), not a claim about
    which one was literally added most recently.
    """
    seen: dict[BaselineKey, int] = {}
    new: list[Finding] = []
    for finding in findings:
        if finding.critical:
            new.append(finding)
            continue
        key = _key(finding)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > baseline.get(key, 0):
            new.append(finding)
    return new
