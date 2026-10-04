"""Rule 4 of 6: Error handling (15 points).

Two kinds of agent-reachable sites feed this category:
  1. Unconditional loops (while True / while 1): must contain an exit that
     actually leaves them -- a break at THIS loop's level (not a nested
     loop's), a return/raise (not inside a nested def), or sys.exit.
  2. Sensitive calls: must sit inside the *body* of a try that handles the
     failure -- in their own function, or at every reachable call site of
     the helper that contains them ("helper raises, caller handles"). Handlers, else and finally don't count -- code there isn't
     protected by that try -- and neither does a try with no handler or one
     whose broad handler silently discards the error (`except Exception:
     pass`), which hides a failed destructive action from everyone.
"""

import ast
from typing import TypeGuard

from checkride.astutils import FileContext, call_name, enclosing_function
from checkride.models import Finding

RULE_ID = "error-handling"
CATEGORY = "Error handling"
WEIGHT = 15

_EXIT_CALLS = frozenset({"sys.exit", "os._exit", "exit", "quit"})
_TRY_TYPES = (ast.Try, ast.TryStar)
_BROAD_EXCEPTIONS = frozenset({"Exception", "BaseException", "builtins.Exception"})


def _is_unconditional_loop(node: ast.AST) -> TypeGuard[ast.While]:
    """True for `while True:` / `while 1:`."""
    return (
        isinstance(node, ast.While)
        and isinstance(node.test, ast.Constant)
        and bool(node.test.value)
    )


def _loop_can_exit(loop: ast.While, aliases: dict[str, str]) -> bool:
    """True if the loop contains an exit that actually leaves it. A break
    inside a nested loop only exits that inner loop; a return inside a
    nested def doesn't unwind this loop at all -- neither counts."""

    def scan(node: ast.AST, in_nested_loop: bool) -> bool:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(child, (ast.Return, ast.Raise)):
                return True
            if isinstance(child, ast.Break) and not in_nested_loop:
                return True
            if isinstance(child, ast.Call) and call_name(child, aliases) in _EXIT_CALLS:
                return True
            nested = in_nested_loop or isinstance(
                child, (ast.For, ast.AsyncFor, ast.While)
            )
            if scan(child, nested):
                return True
        return False

    return scan(loop, False)


def _is_broad(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    for t in types:
        name = call_name(ast.Call(func=t, args=[], keywords=[]))
        if name in _BROAD_EXCEPTIONS:
            return True
    return False


def _is_silent(handler: ast.ExceptHandler) -> bool:
    """A broad handler whose body only discards the error."""
    if not _is_broad(handler):
        return False
    return all(
        isinstance(stmt, (ast.Pass, ast.Continue, ast.Break))
        or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant))
        for stmt in handler.body
    )


def _handled(try_node: ast.Try | ast.TryStar) -> bool:
    return bool(try_node.handlers) and not any(_is_silent(h) for h in try_node.handlers)


def protection(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    """'handled', 'swallowed', or 'none' for the nearest try whose body holds
    the node. Climbs the parent map; at each Try, `prev` is the direct child
    climbed through, which tells which compartment held the node."""
    prev, current = node, parents.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return "none"
        if isinstance(current, _TRY_TYPES) and any(prev is s for s in current.body):
            if _handled(current):
                return "handled"
            if current.handlers:
                return "swallowed"
        prev, current = current, parents.get(current)
    return "none"


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    sites, passed, findings = 0, 0, []

    for node in ctx.all_nodes:
        if not _is_unconditional_loop(node):
            continue
        fn = enclosing_function(node, ctx.parents)
        if not ctx.in_scope(fn):
            continue
        sites += 1
        if _loop_can_exit(node, ctx.import_aliases):
            passed += 1
            continue
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=node.lineno,
                column=node.col_offset + 1,
                function=ctx.qualname(fn),
                message="unbounded 'while True' loop with no break, return or raise",
                fix="Add a termination path: a max-iteration counter, a timeout, "
                    "or a break on a stop signal",
            )
        )

    for call, label in ctx.sensitive_calls:
        fn = enclosing_function(call, ctx.parents)
        if not ctx.in_scope(fn):
            continue
        sites += 1
        state = protection(call, ctx.parents)
        if state == "handled" or (
            state == "none" and fn is not None and ctx.is_protected(fn)
        ):
            passed += 1
            continue
        name = call_name(call, ctx.import_aliases) or "<dynamic>"
        if state == "swallowed":
            message = (
                f"{label} call '{name}' is wrapped in a try whose broad "
                "handler silently discards the error"
            )
        else:
            message = f"{label} call '{name}' is not wrapped in try/except"
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=call.lineno,
                column=call.col_offset + 1,
                function=ctx.qualname(fn),
                message=message,
                fix="Catch the specific failure; log it and return a safe error "
                    "to the caller instead of crashing or hiding it",
            )
        )

    return sites, passed, findings
