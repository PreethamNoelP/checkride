"""JSON config-file scanning: the same "permissive defaults" governance
question as checkride/rules/defaults.py (rule 6), sourced from known MCP
client config filenames instead of Python AST.

Real deployments set these flags in JSON, not Python -- RULES.md names
`claude_desktop_config.json` as rule 6's largest documented blind spot:
a Python-only AST scanner cannot see a flag that never appears in Python
source at all. This module closes that gap for the filenames real MCP
clients actually use, sharing the AST rule's vocabulary tables and name
normalization so a flag named `auto_approve` is judged identically
wherever it lives.

Findings from here report `rule=defaults.RULE_ID` and are merged by
scanner.scan() into the same "Permissive defaults" CategoryResult the AST
rule already produces -- this is deliberately not a seventh entry in
ALL_RULES, so it adds no new weight and needs no rebalancing (see
CONTRIBUTING.md's "every rule must total 100" invariant).
"""

import json
import re
from collections.abc import Callable, Iterator
from pathlib import Path

from checkride.config import RuleConfig
from checkride.fswalk import MAX_FILE_BYTES, SKIP_DIRS, is_excluded
from checkride.models import Finding
from checkride.rules.defaults import (
    DANGEROUS_WHEN_FALSE,
    DANGEROUS_WHEN_TRUE,
    RULE_ID,
    collapse_flag_name,
)

# Exact basenames recognized as MCP client configuration files, matched
# case-sensitively like every other exclude/skip check in this tool.
# Filename-based on purpose, the same way the rest of checkride's
# vocabulary is name-based rather than content-sniffed -- extend an
# unlisted client's filename via extra_config_filenames in
# [tool.checkride] rather than widening this to something fuzzier.
KNOWN_CONFIG_FILENAMES = frozenset({
    "claude_desktop_config.json",  # Claude Desktop
    "mcp.json",                    # generic / VS Code / Cursor (.cursor/mcp.json)
    ".mcp.json",                   # Claude Code, project-scoped
    "cline_mcp_settings.json",     # Cline (VS Code extension)
    "mcp_settings.json",           # other MCP clients using this name
})

# A literal JSON boolean bound to a quoted key: "key": true|false. Matched
# on raw text rather than by walking the parsed object, because plain JSON
# carries no line numbers once parsed -- this mirrors rule 6's own
# philosophy of judging literal constants only. A quoted "true"/"false"
# string is not a site (same blind spot RULES.md already documents for the
# AST rule: `AUTO_APPROVE = "true"` is invisible there too), and neither is
# an array -- some real MCP clients spell per-tool auto-approval as a list
# of tool names (`"autoApprove": ["run_command"]`), which this regex simply
# does not match.
_BOOL_BINDING_RE = re.compile(r'"([^"\\]+)"\s*:\s*(true|false)\b')


def iter_config_files(
    root: Path,
    extra_filenames: frozenset[str] = frozenset(),
    exclude: tuple[str, ...] = (),
    on_excluded: Callable[[Path], None] | None = None,
) -> Iterator[Path]:
    """Yield known MCP config files under root, in sorted (deterministic)
    order -- or root itself if it is a single file whose own name is
    recognized.

    Mirrors scanner.iter_python_files: SKIP_DIRS and `exclude` patterns
    apply identically to a directory walk, via the same shared helpers
    (not reimplemented here). Naming a single `.py` file as the scan target
    does not implicitly pull in sibling config files from its directory --
    a config file is only scanned if it is itself the named target or is
    found under a directory target, the same "explicit target is exactly
    what you asked for" rule scanner.py already applies to Python files.
    """
    filenames = KNOWN_CONFIG_FILENAMES | extra_filenames
    if root.is_file():
        if root.name in filenames:
            yield root
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name not in filenames:
            continue
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if exclude and is_excluded(rel.as_posix(), exclude):
            if on_excluded is not None:
                on_excluded(path)
            continue
        yield path


class _LineCounter:
    """Line numbers for increasing offsets, counting only the text between
    one lookup and the next. Counting from the start of the file for every
    match is quadratic, and a few megabytes of flagged booleans stalls a
    scan for minutes."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._offset = 0
        self._line = 1

    def line_of(self, offset: int) -> int:
        self._line += self._text.count("\n", self._offset, offset)
        self._offset = offset
        return self._line


def scan_config_file(
    path: Path, rel: str, config: RuleConfig
) -> tuple[int, int, list[Finding], str | None]:
    """Check one JSON file for permissive-default flags.

    Returns (sites, passed, findings, skip_reason). skip_reason is not None
    for a file that could not be read or parsed as JSON at all, which the
    caller records in report.skipped -- exactly the same "unparseable file
    -> skipped, verdict becomes INCOMPLETE" treatment scanner.py already
    gives an unparseable Python file.
    """
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return 0, 0, [], (
                f"file is larger than the {MAX_FILE_BYTES // 1_000_000} "
                "MB scan limit"
            )
        # utf-8-sig tolerates a BOM, which some editors write into JSON
        # files and plain utf-8 would choke on.
        text = path.read_text(encoding="utf-8-sig")
        json.loads(text)  # validate only -- detection below reads raw text,
        # since a parsed dict carries no line numbers to report a finding at.
    except (OSError, UnicodeDecodeError) as exc:
        return 0, 0, [], f"unreadable ({exc})"
    except json.JSONDecodeError as exc:
        return 0, 0, [], f"invalid JSON ({exc})"

    # Config-supplied flag names go through the same normalization as the
    # built-in tables, matching rules/defaults.py's own extension mechanism
    # exactly -- one vocabulary, extended the same way regardless of source.
    dangerous_when_true = DANGEROUS_WHEN_TRUE | {
        collapse_flag_name(n) for n in config.dangerous_when_true
    }
    dangerous_when_false = DANGEROUS_WHEN_FALSE | {
        collapse_flag_name(n) for n in config.dangerous_when_false
    }

    lines = _LineCounter(text)
    sites, passed, findings = 0, 0, []
    basename = path.name
    for match in _BOOL_BINDING_RE.finditer(text):
        name, literal = match.group(1), match.group(2)
        collapsed = collapse_flag_name(name)
        value = literal == "true"
        if collapsed in dangerous_when_true:
            safe = value is False
        elif collapsed in dangerous_when_false:
            safe = value is True
        else:
            continue
        sites += 1
        if safe:
            passed += 1
            continue
        findings.append(
            Finding(
                rule=RULE_ID,
                file=rel,
                line=lines.line_of(match.start()),
                message=f"permissive default: '{name}={literal}' disables "
                        f"a safety control (in {basename})",
                fix=f"Set {name}={'false' if value else 'true'} in "
                    f"{basename} and require explicit per-action opt-in "
                    "instead",
            )
        )
    return sites, passed, findings, None
