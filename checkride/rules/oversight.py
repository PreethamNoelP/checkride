"""Rule 1 of 6: Human oversight (25 points).

Every agent-reachable sensitive call (file delete, shell exec, code exec,
dynamic SQL, payment, remote delete) must be *dominated* by a human-approval
check: one that runs before it, in its own execution scope, on the way to it
-- or every call path into the helper that contains it must be. See
approval.py for exactly what counts, and callgraph.py for what "agent-
reachable" means.

Approval derived from a tool's own parameters does not count: the model
chooses those values.
"""

from checkride.astutils import (
    FileContext,
    call_name,
    enclosing_function,
    is_critical,
)
from checkride.models import Finding

RULE_ID = "human-oversight"
CATEGORY = "Human oversight"
WEIGHT = 25


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    sites, passed, findings = 0, 0, []
    approval = ctx.approval
    for call, label in ctx.sensitive_calls:
        fn = enclosing_function(call, ctx.parents)
        if not ctx.in_scope(fn):
            continue
        sites += 1
        scope = fn if fn is not None else ctx.tree
        model_controlled = fn is not None and ctx.is_entry(fn)
        if approval.is_dominated(call, scope, exclude_params=model_controlled) or (
            fn is not None and (approval.decorated(fn) or ctx.is_gated(fn))
        ):
            passed += 1
            continue

        name = call_name(call, ctx.import_aliases) or "<dynamic>"
        where = f"in '{fn.name}'" if fn is not None else "at module level"
        if model_controlled and approval.is_dominated(call, scope, exclude_params=False):
            message = (
                f"{label} call '{name}' {where} is gated only by a tool "
                "argument, which the model chooses"
            )
            fix = (
                "Get the approval from a human, not from the tool's input: MCP "
                "elicitation (`await ctx.elicit(...)`), a confirmation UI, or "
                "an approval service checked before the call"
            )
        else:
            message = f"{label} call '{name}' {where} has no human-approval check before it"
            fix = (
                "Gate the call behind an explicit approval that runs first, e.g. "
                "`if not await request_approval(...): return` before it executes"
            )
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=call.lineno,
                column=call.col_offset + 1,
                function=ctx.qualname(fn),
                message=message,
                fix=fix,
                critical=is_critical(label),
            )
        )
    return sites, passed, findings
