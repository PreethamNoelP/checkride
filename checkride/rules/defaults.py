"""Rule 6 of 6: Permissive defaults (10 points).

Inverted category: rules 1-5 ask "where risk exists, is a control present?"
-- this one asks "where a governance knob exists, is it set to the safe
side?" Sites are bindings of recognized flag names to boolean constants:
assignments, keyword arguments, function-parameter defaults, and
string-keyed dict entries. Bindings to non-constants are not sites; we
can't judge a value we can't see.
"""

import ast
from collections.abc import Iterable, Iterator

from checkride.astutils import FileContext
from checkride.models import Finding

RULE_ID = "permissive-defaults"
CATEGORY = "Permissive defaults"
WEIGHT = 10

# Matched against lowercased names with underscores/hyphens stripped, so
# auto_approve, AUTO_APPROVE and autoApprove all hit "autoapprove".
DANGEROUS_WHEN_TRUE = frozenset({
    "autoapprove", "autoconfirm", "autoaccept", "autorun", "autoexecute",
    "skipapproval", "skipconfirm", "skipconfirmation", "skipreview",
    "noconfirm", "noapproval",
    "allowall", "trustall", "unsafe",
    "disableauth", "disablesafety", "bypassapproval", "bypasssafety",
})

DANGEROUS_WHEN_FALSE = frozenset({
    "requireapproval", "approvalrequired",
    "requireconfirmation", "confirmationrequired", "requireconfirm",
    "requireauth", "authrequired",
    "requirehuman", "humanintheloop", "humanreview",
    "verify", "verifyssl", "sslverify", "verifysslcerts", "verifycerts",
    "verifycertificate", "checkhostname", "validatecerts",
    "safemode", "sandbox", "sandboxed",
})


def collapse_flag_name(name: str) -> str:
    """Normalize a flag name for vocabulary matching: lowercase, with
    underscores and hyphens stripped, so auto_approve/AUTO_APPROVE/
    autoApprove/auto-approve all collapse to the same "autoapprove".

    Public (not just this module's own concern): checkride/configscan.py
    reuses it so a flag is judged identically whether it lives in Python
    source or a JSON MCP config file."""
    return name.lower().replace("_", "").replace("-", "")


# Old name kept as an alias at existing call sites in this module -- purely
# cosmetic, no behavior change.
_collapsed = collapse_flag_name


def _flag_bindings(nodes: Iterable[ast.AST]) -> Iterator[tuple[str, ast.expr, int]]:
    """Yield (name, value_node, lineno) for every name-to-value binding:
    assignments, keyword arguments, parameter defaults, and dict entries
    with a literal string key."""
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    yield target.id, node.value, node.lineno
                elif isinstance(target, ast.Attribute):
                    yield target.attr, node.value, node.lineno
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.target, ast.Name):
                yield node.target.id, node.value, node.lineno
            elif isinstance(node.target, ast.Attribute):
                yield node.target.attr, node.value, node.lineno
        elif isinstance(node, ast.keyword) and node.arg is not None:
            yield node.arg, node.value, node.value.lineno
        elif isinstance(node, ast.Dict):
            # Settings dicts are how a Python MCP server usually spells its
            # own config -- SERVER = {"auto_approve": True} is the same
            # governance decision as auto_approve = True, and was invisible.
            # String keys only: a computed key names no flag we can judge.
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and value is not None
                ):
                    yield key.value, value, key.lineno
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            pos = [*node.args.posonlyargs, *node.args.args]
            defaults = node.args.defaults
            for arg, default in zip(pos[len(pos) - len(defaults):], defaults):
                yield arg.arg, default, arg.lineno
            # A separate name from `default` above: kw_defaults is
            # list[expr | None] (a keyword-only arg with no default is a
            # None slot), and reusing the name would widen the other loop's
            # type for no reason.
            for arg, kw_default in zip(node.args.kwonlyargs, node.args.kw_defaults):
                if kw_default is not None:
                    yield arg.arg, kw_default, arg.lineno


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    sites, passed, findings = 0, 0, []
    # Config-supplied flag names go through the same _collapsed() normalization
    # as the built-in tables, so "extra_dangerous_when_true = ['yolo_mode']"
    # matches YOLO_MODE / yoloMode / yolo-mode identically to a built-in entry.
    dangerous_when_true = DANGEROUS_WHEN_TRUE | {
        _collapsed(n) for n in ctx.config.dangerous_when_true
    }
    dangerous_when_false = DANGEROUS_WHEN_FALSE | {
        _collapsed(n) for n in ctx.config.dangerous_when_false
    }
    for name, value, lineno in _flag_bindings(ctx.all_nodes):
        if not (isinstance(value, ast.Constant) and isinstance(value.value, bool)):
            continue
        collapsed = _collapsed(name)
        if collapsed in dangerous_when_true:
            safe = value.value is False
        elif collapsed in dangerous_when_false:
            safe = value.value is True
        else:
            continue
        sites += 1
        if safe:
            passed += 1
            continue
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=lineno,
                message=f"permissive default: '{name}={value.value}' "
                        "disables a safety control",
                fix=f"Set {name}={not value.value} and require explicit "
                    "per-action opt-in instead",
            )
        )
    return sites, passed, findings
