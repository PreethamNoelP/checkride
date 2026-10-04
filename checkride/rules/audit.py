"""Rule 2 of 6: Audit logging (20 points).

Every tool entry point must record what it did: the tool itself, or a
function it calls (in any scanned file), makes a logging or audit call.

A logging call is one of:
  - anything on the `logging` module, `structlog` or `loguru`;
  - a level method (info, warning, error, exception, ...) on a receiver
    named like a logger (`logger.info`, `self.log.warning`, `audit.write`);
  - MCP's own client logging, `ctx.info(...)` / `await ctx.error(...)`;
  - a function named for it (`audit_log(...)`, `log_event(...)`,
    `record_audit(...)`), plus `extra_log_tokens` from config.

Math functions that happen to be called log (`math.log`, `np.log`,
`torch.log`, `log10`, ...) never count.
"""

import ast
from collections.abc import Iterable

from checkride.astutils import FileContext, call_name, iter_scope, name_tokens
from checkride.config import RuleConfig
from checkride.models import Finding

RULE_ID = "audit-logging"
CATEGORY = "Audit logging"
WEIGHT = 20

LOG_TOKENS = frozenset(
    {"log", "logger", "logging", "logged", "audit", "auditing", "audited"}
)
_LOGGER_RECEIVER_TOKENS = frozenset(
    {"log", "logger", "logging", "audit", "auditor", "audits", "journal"}
)
_LOG_METHODS = frozenset({
    "debug", "info", "warning", "warn", "error", "exception", "critical",
    "fatal", "log", "msg", "event", "record", "write", "emit", "audit",
})
_MCP_CONTEXT_RECEIVERS = frozenset({"ctx", "context"})
_MCP_LOG_METHODS = frozenset({"debug", "info", "warning", "error", "log"})
_LOGGING_MODULES = frozenset({"logging", "structlog", "loguru"})
_MATH_ROOTS = frozenset({
    "math", "cmath", "numpy", "np", "torch", "jax", "jnp", "scipy",
    "tensorflow", "tf", "sympy", "mpmath", "decimal", "pandas", "pd",
})
_MATH_FUNCS = frozenset({
    "log1p", "log2", "log10", "logaddexp", "logaddexp2", "logsumexp",
    "loggamma", "lgamma", "logit", "log_softmax", "logspace",
})


def is_log_call(name: str, extra_tokens: frozenset[str] = frozenset()) -> bool:
    parts = name.split(".")
    root, last = parts[0], parts[-1]
    if root in _MATH_ROOTS or last.lower() in _MATH_FUNCS:
        return False
    if root in _LOGGING_MODULES:
        return True
    receiver = parts[:-1]
    receiver_tokens = {t for p in receiver for t in name_tokens(p)}
    if receiver_tokens & _LOGGER_RECEIVER_TOKENS and last in _LOG_METHODS:
        return True
    if receiver and receiver[-1] in _MCP_CONTEXT_RECEIVERS and last in _MCP_LOG_METHODS:
        return True
    if name_tokens(last) & LOG_TOKENS:
        return True
    return bool(extra_tokens and name_tokens(name) & extra_tokens)


def makes_log_call(
    fn: ast.AST,
    config: RuleConfig,
    aliases: dict[str, str],
    nodes: Iterable[ast.AST] | None = None,
) -> bool:
    """True if `fn`'s own scope makes a logging/audit call. `nodes` is the
    precomputed scope (FileContext.scope_nodes) when the caller has it."""
    for node in nodes if nodes is not None else iter_scope(fn):
        if isinstance(node, ast.Call):
            # Alias-aware: with `from telemetry import audit_log as al`, the
            # local spelling `al(...)` carries none of the vocabulary.
            name = call_name(node, aliases)
            if name is not None and is_log_call(name, config.log_tokens):
                return True
    return False


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    sites, passed, findings = 0, 0, []
    for fn in ctx.functions:
        if fn not in ctx.tool_functions:
            continue
        sites += 1
        if makes_log_call(
            fn, ctx.config, ctx.import_aliases, ctx.scope_nodes(fn)
        ) or ctx.logs_via_calls(fn):
            passed += 1
            continue
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=fn.lineno,
                column=fn.col_offset + 1,
                function=ctx.qualname(fn),
                message=f"tool function '{fn.name}' makes no audit/log call",
                fix="Record the invocation, e.g. `logger.info(...)` or "
                    "`audit_log(actor, action, args)` inside the function",
            )
        )
    return sites, passed, findings
