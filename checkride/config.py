"""Optional project configuration: `[tool.checkride]` in pyproject.toml.

A scan with no config file behaves identically to one with an empty table.
Validation is strict: an unknown key, an unknown rule id, a malformed value,
or a vocabulary entry that would neuter its rule is an error, never a
silent no-op.

Two dataclasses:
  - RuleConfig travels with every FileContext and is read by rule modules
    (vocabulary extensions, scope, entry points).
  - Config is scan-level (disabled rules, min score, excludes, accepted
    risks) and is consumed by scanner.py / scoring.py / cli.py.
"""

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from checkride.rules import RULE_IDS

# Recognized [tool.checkride] keys that extend a rule's built-in vocabulary,
# additively -- a config can only add markers, never remove the defaults
# documented in RULES.md.
_VOCAB_KEYS = {
    "extra_approval_markers": "approval_markers",
    "extra_log_tokens": "log_tokens",
    "extra_rate_limit_markers": "rate_markers",
    "extra_validation_tokens": "validation_tokens",
    "extra_risky_params": "risky_param_tokens",
    "extra_dangerous_when_true": "dangerous_when_true",
    "extra_dangerous_when_false": "dangerous_when_false",
}

_TUPLE_FIELDS = {"approval_markers", "rate_markers"}

# Every key [tool.checkride] understands. An unrecognized key is an error,
# not a no-op: "excludes = [...]" or "min_scores = 90" would otherwise scan
# with silently different settings than the author believed they had asked
# for, which for a governance gate is the worst possible failure mode.
_KNOWN_KEYS = frozenset(
    {
        "min_score", "exclude", "disabled_rules",
        "assume_external_rate_limiting", "extra_config_filenames",
        "scope", "extra_tool_decorators", "extra_tool_entry_points",
        "accepted_risks",
    }
    | set(_VOCAB_KEYS)
)

SCOPES = ("tools", "all")

# The score a scan must reach for a PASS verdict when neither --min-score
# nor `min_score` says otherwise. `min_score = 0` turns the floor off.
DEFAULT_MIN_SCORE = 70.0

_ACCEPTED_RISK_KEYS = frozenset({"rule", "file", "function", "call", "reason"})
# Long enough that "ok" or "fp" is not a justification.
_MIN_REASON_LENGTH = 15

# Vocabulary entries are matched as substrings or stems, so a very short one
# matches nearly every identifier: extra_approval_markers = ["e"] makes the
# human-oversight rule pass on any call whose name contains an "e", which
# turns the critical gate off through a config file. Three characters is
# short enough for real words ("vet") and long enough not to be a wildcard.
_MIN_VOCAB_LENGTH = 3


@dataclass(frozen=True)
class AcceptedRisk:
    """A reviewed decision that a specific finding is an acceptable risk.

    Matches findings by rule and file, optionally narrowed to an enclosing
    function and the sensitive call's name. A matching finding is removed
    from the failing set -- critical or not -- and listed in every report
    under "accepted risks" together with its reason."""

    rule: str
    file: str
    reason: str
    function: str | None = None
    call: str | None = None


class ConfigError(Exception):
    """Raised for a present-but-malformed config file. Never raised for a
    missing one -- no config file is the common case, not an error."""


@dataclass(frozen=True)
class RuleConfig:
    """Per-scan settings a rule's check(ctx) may consult via ctx.config."""

    disabled_rules: frozenset[str] = frozenset()
    assume_external_rate_limiting: bool = False
    approval_markers: tuple[str, ...] = ()
    log_tokens: frozenset[str] = frozenset()
    rate_markers: tuple[str, ...] = ()
    validation_tokens: frozenset[str] = frozenset()
    risky_param_tokens: frozenset[str] = frozenset()
    dangerous_when_true: frozenset[str] = frozenset()
    dangerous_when_false: frozenset[str] = frozenset()
    # "tools": judge only code reachable from a recognized tool entry point.
    # "all": treat every function that performs a sensitive action as a tool.
    scope: str = "tools"
    tool_decorators: frozenset[str] = frozenset()
    entry_points: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config:
    """Everything loaded from [tool.checkride]."""

    min_score: float | None = DEFAULT_MIN_SCORE
    exclude: tuple[str, ...] = ()
    # Scan-level, like `exclude` -- not RuleConfig -- because filename
    # discovery happens in scanner.py, not inside a rule's check(ctx).
    # Additive to configscan.KNOWN_CONFIG_FILENAMES, matching the
    # extra-vocabulary keys' "add, never override" convention.
    extra_config_filenames: frozenset[str] = frozenset()
    rules: RuleConfig = field(default_factory=RuleConfig)
    accepted_risks: tuple[AcceptedRisk, ...] = ()
    # The file these settings came from, or None when no config was found.
    # Reported by the CLI: "my [tool.checkride] table was ignored" is
    # otherwise invisible, and discovery deliberately does not search
    # upwards (see _discover_path). Named by display_path, so it never
    # carries an absolute path into a CI log.
    source: str | None = None


def _as_str_tuple(value: object, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"[tool.checkride] '{key}' must be a list of strings")
    return tuple(value)


def _as_vocabulary(value: object, key: str) -> tuple[str, ...]:
    """A vocabulary list, rejecting entries too short to be words. See
    _MIN_VOCAB_LENGTH: a one- or two-character marker is a wildcard that
    silently makes its rule pass everywhere."""
    entries = _as_str_tuple(value, key)
    for entry in entries:
        stripped = entry.strip()
        if len(stripped) < _MIN_VOCAB_LENGTH:
            raise ConfigError(
                f"[tool.checkride] '{key}' entry {entry!r} is shorter than "
                f"{_MIN_VOCAB_LENGTH} characters -- it would match almost every "
                "identifier and effectively disable the rule"
            )
    return entries


def _check_marker_is_not_a_sink(entry: str) -> None:
    """An approval marker that also matches a sensitive call's own name
    would let that call approve itself: extra_approval_markers = ["run"]
    makes every subprocess.run its own approval."""
    from checkride.astutils import SENSITIVE_EXACT, SENSITIVE_SUFFIX

    needle = entry.lower().replace("_", "")
    for sink in (*SENSITIVE_EXACT, *SENSITIVE_SUFFIX):
        if needle in sink.lower().replace("_", "").replace(".", ""):
            raise ConfigError(
                f"[tool.checkride] 'extra_approval_markers' entry {entry!r} "
                f"also matches the sensitive call '{sink}', which would then "
                "count as its own approval"
            )


def _as_accepted_risks(value: object) -> tuple[AcceptedRisk, ...]:
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise ConfigError(
            "[tool.checkride] 'accepted_risks' must be an array of tables "
            "([[tool.checkride.accepted_risks]])"
        )
    risks = []
    for i, entry in enumerate(value):
        where = f"[tool.checkride] accepted_risks[{i}]"
        unknown = sorted(set(entry) - _ACCEPTED_RISK_KEYS)
        if unknown:
            raise ConfigError(
                f"{where}: unknown key(s) {', '.join(map(repr, unknown))}; "
                f"valid keys are {', '.join(sorted(_ACCEPTED_RISK_KEYS))}"
            )
        for required in ("rule", "file", "reason"):
            if not isinstance(entry.get(required), str) or not entry[required].strip():
                raise ConfigError(f"{where}: '{required}' is required and must be a string")
        for optional in ("function", "call"):
            if optional in entry and not isinstance(entry[optional], str):
                raise ConfigError(f"{where}: '{optional}' must be a string")
        if entry["rule"] not in RULE_IDS:
            raise ConfigError(
                f"{where}: unknown rule {entry['rule']!r}; valid ids are "
                f"{', '.join(RULE_IDS)}"
            )
        if len(entry["reason"].strip()) < _MIN_REASON_LENGTH:
            raise ConfigError(
                f"{where}: 'reason' must explain the decision "
                f"(at least {_MIN_REASON_LENGTH} characters)"
            )
        risks.append(
            AcceptedRisk(
                rule=entry["rule"],
                file=entry["file"].strip().replace("\\", "/").removeprefix("./"),
                reason=entry["reason"].strip(),
                function=entry.get("function"),
                call=entry.get("call"),
            )
        )
    return tuple(risks)


def _build_rule_config(table: dict[str, Any]) -> RuleConfig:
    kwargs: dict[str, Any] = {}

    disabled = _as_str_tuple(table.get("disabled_rules", []), "disabled_rules")
    unknown = sorted(set(disabled) - set(RULE_IDS))
    if unknown:
        raise ConfigError(
            f"[tool.checkride] 'disabled_rules' names unknown rule(s) "
            f"{', '.join(repr(u) for u in unknown)}; valid ids are "
            f"{', '.join(RULE_IDS)}"
        )
    kwargs["disabled_rules"] = frozenset(disabled)

    assume_external = table.get("assume_external_rate_limiting", False)
    if not isinstance(assume_external, bool):
        raise ConfigError(
            "[tool.checkride] 'assume_external_rate_limiting' must be true/false"
        )
    kwargs["assume_external_rate_limiting"] = assume_external

    scope = table.get("scope", "tools")
    if scope not in SCOPES:
        raise ConfigError(
            f"[tool.checkride] 'scope' must be one of {', '.join(map(repr, SCOPES))}"
        )
    kwargs["scope"] = scope
    kwargs["tool_decorators"] = frozenset(
        _as_vocabulary(table.get("extra_tool_decorators", []), "extra_tool_decorators")
    )
    kwargs["entry_points"] = _as_vocabulary(
        table.get("extra_tool_entry_points", []), "extra_tool_entry_points"
    )

    for toml_key, field_name in _VOCAB_KEYS.items():
        if toml_key not in table:
            continue
        values = _as_vocabulary(table[toml_key], toml_key)
        if toml_key == "extra_approval_markers":
            for value in values:
                _check_marker_is_not_a_sink(value)
        normalized = tuple(v.lower() for v in values)
        kwargs[field_name] = (
            normalized if field_name in _TUPLE_FIELDS else frozenset(normalized)
        )

    return RuleConfig(**kwargs)


def _parse(data: dict[str, Any], source: str | None = None) -> Config:
    tool = data.get("tool", {})
    table = tool.get("checkride", {}) if isinstance(tool, dict) else {}
    if not isinstance(table, dict):
        raise ConfigError("[tool.checkride] must be a table")
    if not isinstance(tool, dict) or "checkride" not in tool:
        # A pyproject.toml with no [tool.checkride] table contributed
        # nothing, so naming it as the config source would be misleading.
        source = None

    unknown = sorted(set(table) - _KNOWN_KEYS)
    if unknown:
        raise ConfigError(
            f"[tool.checkride] unknown key(s) "
            f"{', '.join(repr(u) for u in unknown)}; valid keys are "
            f"{', '.join(sorted(_KNOWN_KEYS))}"
        )

    min_score = table.get("min_score", DEFAULT_MIN_SCORE)
    # bool is a subclass of int in Python, so `min_score = true` would
    # otherwise silently become a threshold of 1.0.
    if isinstance(min_score, bool) or not isinstance(min_score, (int, float)):
        raise ConfigError("[tool.checkride] 'min_score' must be a number")
    if not 0 <= min_score <= 100:
        raise ConfigError("[tool.checkride] 'min_score' must be between 0 and 100")

    exclude = _as_str_tuple(table.get("exclude", []), "exclude")
    extra_config_filenames = frozenset(
        _as_str_tuple(
            table.get("extra_config_filenames", []), "extra_config_filenames"
        )
    )

    return Config(
        min_score=float(min_score),
        exclude=exclude,
        extra_config_filenames=extra_config_filenames,
        rules=_build_rule_config(table),
        accepted_risks=_as_accepted_risks(table.get("accepted_risks", [])),
        source=source,
    )


def _discover_path(target: Path) -> Path | None:
    """Look for pyproject.toml next to the scan target: inside it if target
    is a directory, alongside it if target is a single file. No upward
    directory search -- predictable discovery beats "found a config
    somewhere above me" surprise, especially for a CI tool."""
    directory = target if target.is_dir() else target.parent
    candidate = directory / "pyproject.toml"
    return candidate if candidate.is_file() else None


def display_path(path: Path) -> str:
    """How a config file's location is named in output.

    Relative to the working directory when the file is under it, absolute
    otherwise. Both the reported config source and every ConfigError go
    through this: an absolute path in a CI log discloses the runner's (or a
    developer's) directory layout for no benefit, and it makes the same
    commit produce different output on different machines. os.path.abspath
    rather than Path.resolve() so a symlinked checkout is named the way the
    caller spelled it.
    """
    absolute = Path(os.path.abspath(path))
    try:
        return absolute.relative_to(Path(os.path.abspath(os.curdir))).as_posix()
    except ValueError:
        return absolute.as_posix()


def load_config(target: Path, explicit_path: Path | None = None) -> Config:
    """Load [tool.checkride] from an explicit path or by discovery next to
    `target`. Returns the all-defaults Config if nothing is found -- a
    missing config file is not an error, a malformed one is."""
    path = explicit_path if explicit_path is not None else _discover_path(target)
    if path is None:
        return Config()
    shown = display_path(path)
    if not path.is_file():
        raise ConfigError(f"config file not found: {shown}")
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {shown}: {exc}") from exc
    try:
        return _parse(data, source=shown)
    except ConfigError as exc:
        raise ConfigError(f"{shown}: {exc}") from exc
