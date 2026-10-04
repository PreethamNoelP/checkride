"""The `checkride: ignore` marker grammar.

The comment introducer is a parameter (`marker_pattern`); everything after
it -- the optional bracketed rule list, the reason delimiter, the rule-id
shape, and every malformed-marker message -- is defined once here.

A malformed marker suppresses *nothing*. Validation happens after a greedy
match, so `ignore[]` or `ignore[bad id!]` is reported as malformed instead
of silently falling back to the unqualified form (which would suppress
every rule on the line, including rules added in later versions).
"""

import re
from dataclasses import dataclass

# The part of the marker that follows the comment introducer. The bracket
# group captures anything up to "]" rather than only well-formed rule ids,
# so an invalid list stays invalid instead of falling back to the bare form.
# The \b stops "ignored"/"ignoring" in prose from reading as a directive.
_BODY = r"\s*checkride:\s*ignore\b[ \t]*(\[[^\]]*\])?[ \t]*(.*)$"

# A free-text reason may follow a bare `ignore`, but it has to announce
# itself. Forgetting the brackets around a rule name must not suppress
# every rule on the line.
_REASON_RE = re.compile(r"^(--|:|#)")

# Rule ids are lowercase kebab-case ("human-oversight"). Anything else in a
# suppression list is a typo, not a rule we might not know about yet.
_RULE_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")

_MARKER_WORD_RE = re.compile(r"checkride", re.IGNORECASE)


@dataclass(frozen=True)
class Marker:
    """One parsed suppression marker.

    `rules` is None for an unqualified marker (covers every rule, including
    ones added later). `malformed` is a human-readable reason when the
    marker could not be understood -- such a marker grants no exemption at
    all, and the reason is surfaced as a scan warning so a typo does not
    just sit there silently failing to do its job.
    """

    rules: frozenset[str] | None
    malformed: str | None = None


def marker_pattern(introducer: str) -> re.Pattern[str]:
    """Compile the marker regex for a language's comment introducer.

    `introducer` is a regex fragment, not a literal (`"#"` for Python).
    Requiring the introducer (rather than searching for the bare word) is
    what keeps prose that merely mentions the marker from suppressing
    anything.
    """
    return re.compile(introducer + _BODY, re.IGNORECASE)


def contains_marker_word(text: str) -> bool:
    """Cheap pre-check: a source without the word cannot hold a marker.

    Tokenizing every file to find a marker almost none of them contain was
    ~8% of scan time.
    """
    return _MARKER_WORD_RE.search(text) is not None


def parse_marker(comment: str, pattern: re.Pattern[str]) -> Marker | None:
    """Parse one comment. None means it carries no marker at all."""
    match = pattern.search(comment)
    if match is None:
        return None

    brackets = match.group(1)
    trailing = match.group(2).strip()

    if brackets is None:
        if trailing and not _REASON_RE.match(trailing):
            return Marker(
                rules=None,
                malformed=f"unexpected text after 'ignore': {trailing!r} "
                          "-- name rules as ignore[rule-id], or start a "
                          "reason with '--'",
            )
        return Marker(rules=None)

    rules = [r.strip().lower() for r in brackets[1:-1].split(",")]
    rules = [r for r in rules if r]
    if not rules:
        return Marker(rules=None, malformed="empty rule list in 'ignore[]'")
    bad = next((r for r in rules if not _RULE_ID_RE.match(r)), None)
    if bad is not None:
        return Marker(rules=None, malformed=f"'{bad}' is not a valid rule id")
    return Marker(rules=frozenset(rules))
