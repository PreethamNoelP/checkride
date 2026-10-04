"""Rule 3 of 6: Rate limiting (15 points).

Every tool entry point must *use* a rate limiter -- in its body, its
decorators, or a function it calls. Use means the limiter is called
(`limiter.acquire()`, `await throttle.wait()`), applied as a decorator
(`@limiter.limit("10/minute")`, the ratelimit library's `@limits`), or
entered as a context manager (`async with rate_limiter:`). A name that is
only assigned (`rate_limiter = None`), declared as a parameter, or passed
as a keyword does not count. Limiter vocabulary: identifiers containing
"ratelimit", "throttle" or "limiter" (underscores ignored), plus
`extra_rate_limit_markers`.

The rule confirms a limiter is invoked, not that its limits are sensible.
`assume_external_rate_limiting = true` marks the category not applicable
when a gateway limits calls outside the scanned code.
"""

import ast
from collections.abc import Iterable, Iterator

from checkride.astutils import FileContext
from checkride.config import RuleConfig
from checkride.models import Finding

RULE_ID = "rate-limiting"
CATEGORY = "Rate limiting"
WEIGHT = 15

# Bare "limit" is deliberately absent: pagination params (limit=10) and SQL
# LIMIT would drown the rule in false passes.
RATE_MARKERS = ("ratelimit", "throttle", "limiter")


def mentions_rate_limit(
    fn: ast.AST, config: RuleConfig, scope: Iterable[ast.AST] | None = None
) -> bool:
    """True if `fn` uses a rate limiter (see the module docstring). With
    `scope` (the function's own-scope nodes), nested defs are skipped -- the
    call-graph summary covers those separately."""
    # Config entries are collapsed the same way identifiers are, so
    # "rate_limit" still matches "rate_limit_check".
    markers = RATE_MARKERS + tuple(m.replace("_", "") for m in config.rate_markers)
    nodes = scope if scope is not None else ast.walk(fn)
    for ident in _used_identifiers(nodes):
        collapsed = ident.lower().replace("_", "")
        if collapsed == "limits":  # the ratelimit library's @limits decorator
            return True
        if any(marker in collapsed for marker in markers):
            return True
    return False


def _chain_identifiers(expr: ast.AST) -> list[str]:
    """Names along a callee or decorator expression: `self.limiter.acquire`
    gives self, limiter, acquire; `limiter.limit("10/m")` gives limiter,
    limit."""
    names: list[str] = []
    while True:
        if isinstance(expr, ast.Call):
            expr = expr.func
        elif isinstance(expr, ast.Attribute):
            names.append(expr.attr)
            expr = expr.value
        elif isinstance(expr, ast.Subscript):
            expr = expr.value
        elif isinstance(expr, ast.Name):
            names.append(expr.id)
            return names
        else:
            return names


def _used_identifiers(nodes: Iterable[ast.AST]) -> Iterator[str]:
    for node in nodes:
        if isinstance(node, ast.Call):
            yield from _chain_identifiers(node.func)
        elif isinstance(node, ast.withitem):
            yield from _chain_identifiers(node.context_expr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                yield from _chain_identifiers(dec)


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    if ctx.config.assume_external_rate_limiting:
        return 0, 0, []

    sites, passed, findings = 0, 0, []
    for fn in ctx.functions:
        if fn not in ctx.tool_functions:
            continue
        sites += 1
        if mentions_rate_limit(fn, ctx.config) or ctx.rate_limited_via_calls(fn):
            passed += 1
            continue
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=fn.lineno,
                column=fn.col_offset + 1,
                function=ctx.qualname(fn),
                message=f"tool function '{fn.name}' has no rate-limit "
                        "or throttle reference",
                fix="Apply a limiter, e.g. `@limiter.limit('10/minute')` or a "
                    "token-bucket check at the top of the function",
            )
        )
    return sites, passed, findings
