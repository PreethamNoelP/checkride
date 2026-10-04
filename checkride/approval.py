"""Human-approval analysis: is a node *dominated* by an approval check?

A sensitive call counts as gated only when an approval check runs before it
on the way to it, in the same execution scope:

  - it sits inside an `if`/`while`/conditional expression, `with` block,
    `and` chain or comprehension filter whose condition mentions approval;
  - or an earlier statement in an enclosing block is a guard: an `assert`
    on approval, an `if <approval>: return/raise/...`, or a bare call to an
    approval function (`require_approval(...)`, `await ctx.confirm(...)`),
    which is assumed to raise on denial;
  - or the enclosing function carries an approval decorator.

"Mentions approval" means an approval-named call (approv/confirm/consent,
MCP elicitation, ask-a-human phrasing, builtin `input()`), an
approval-named variable, or a variable assigned from such a call. Excluded,
because none of them is evidence that a human decided anything:

  - the sensitive call itself, and calls nested inside it;
  - permissive-flag names (`auto_approve`, `skip_confirmation`, ...);
  - names bound only to constants (`approved = True`);
  - for tool entry points, the function's own parameters: a tool argument
    is chosen by the model, so `if confirm:` on a `confirm` parameter is
    the model approving itself.

Polarity is checked: a condition is read as true-when-approved (`if
approved:`, `answer == "y"`) or true-when-refused (`if not approved:`,
`result.action != "accept"`, `answer == "no"`, `if user_declined:`), and
the sensitive call must sit on the approved side -- so `if approved():
return` before the call, which acts exactly when approval was refused, is
not a gate. A condition whose polarity cannot be read is accepted either
way rather than guessed.

Known limit: a value is not traced further than two assignments.
"""

import ast
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from functools import lru_cache

from checkride.astutils import FunctionNode, call_name, iter_scope

APPROVAL_STEMS = ("approv", "confirm", "consent")
# Matched against the name with underscores removed, so ask_human,
# askHuman and ASK_HUMAN all hit.
APPROVAL_PHRASES = (
    "humanintheloop", "humanreview", "humanapproval", "askhuman", "askuser",
    "requesthuman", "manualreview", "signoff", "elicit",
)
EXIT_CALLS = frozenset({"sys.exit", "os._exit", "exit", "quit"})

# Words that make a condition true when approval was refused.
DENIAL_WORDS = frozenset({
    "decline", "declined", "deny", "denied", "reject", "rejected", "refuse",
    "refused", "cancel", "cancelled", "canceled", "abort", "aborted", "no",
    "n", "false", "veto", "vetoed",
})
APPROVED, UNKNOWN, REFUSED = 1, 0, -1


def collapse(name: str) -> str:
    return name.lower().replace("_", "").replace("-", "")


def _permissive_flags() -> frozenset[str]:
    # Imported lazily: rules.defaults imports astutils, which this module
    # also imports, and the flag table is defaults' to own.
    from checkride.rules.defaults import DANGEROUS_WHEN_TRUE

    return DANGEROUS_WHEN_TRUE


@lru_cache(maxsize=65536)
def is_approval_name(name: str, extra_markers: tuple[str, ...] = ()) -> bool:
    """True if any component of a (dotted) name is approval vocabulary.

    Judged per component so `settings.auto_approve` is read as the
    permissive flag it is rather than as an approval."""
    if name == "input":
        return True
    permissive = _permissive_flags()
    markers = APPROVAL_STEMS + APPROVAL_PHRASES + tuple(
        collapse(m) for m in extra_markers
    )
    for part in name.split("."):
        collapsed = collapse(part)
        if not collapsed or collapsed in permissive:
            continue
        if any(marker in collapsed for marker in markers):
            return True
    return False


def _terminates(block: list[ast.stmt]) -> bool:
    if not block:
        return False
    last = block[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        name = call_name(last.value)
        return name in EXIT_CALLS
    return False


def _root_name(node: ast.expr) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    while isinstance(node, ast.Call):
        node = node.func
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
    return node.id if isinstance(node, ast.Name) else None


FRAMEWORK_PARAM_NAMES = frozenset({"self", "cls", "ctx", "context"})


def is_framework_param(arg: ast.arg) -> bool:
    """Parameters the framework injects rather than the model choosing:
    `self`, and MCP/agent-SDK context objects (`ctx: Context`,
    `run_context: RunContextWrapper`, `tool_context: ToolContext`)."""
    if arg.arg in FRAMEWORK_PARAM_NAMES:
        return True
    annotation = arg.annotation
    if isinstance(annotation, ast.Subscript):
        annotation = annotation.value
    if isinstance(annotation, (ast.Name, ast.Attribute)):
        name = annotation.id if isinstance(annotation, ast.Name) else annotation.attr
        return name.endswith(("Context", "ContextWrapper"))
    return False


def _function_params(fn: FunctionNode) -> frozenset[str]:
    """The model-controlled parameters of a tool function."""
    a = fn.args
    args = [*a.posonlyargs, *a.args, *a.kwonlyargs]
    if a.vararg:
        args.append(a.vararg)
    if a.kwarg:
        args.append(a.kwarg)
    return frozenset(x.arg for x in args if not is_framework_param(x))


@dataclass(frozen=True)
class _Facts:
    params: frozenset[str]        # names that must not count (model-controlled)
    constant_names: frozenset[str]  # bound only to literals in this scope
    bound_names: frozenset[str]   # bound at all in this scope
    tainted: frozenset[str]       # assigned from an approval call


class ApprovalAnalyzer:
    """Per-file approval analysis. `is_sink` tells it which calls are
    sensitive, so a sink can never count as its own approval."""

    def __init__(
        self,
        tree: ast.AST,
        parents: dict[ast.AST, ast.AST],
        aliases: dict[str, str],
        extra_markers: tuple[str, ...],
        is_sink: Callable[[ast.Call], bool],
        scope_nodes: Callable[[ast.AST], Iterable[ast.AST]] = iter_scope,
    ) -> None:
        self.tree = tree
        self.parents = parents
        self.aliases = aliases
        self.extra = extra_markers
        self.is_sink = is_sink
        self.scope_nodes = scope_nodes
        self._facts: dict[tuple[int, bool], _Facts] = {}
        self._may_approve: dict[int, bool] = {}

    # -- scope facts ---------------------------------------------------

    def _bindings(self, scope: ast.AST) -> dict[str, list[ast.expr | None]]:
        bindings: dict[str, list[ast.expr | None]] = {}

        def bind(target: ast.expr, value: ast.expr | None) -> None:
            if isinstance(target, ast.Name):
                bindings.setdefault(target.id, []).append(value)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for elt in target.elts:
                    bind(elt, None)

        for node in self.scope_nodes(scope):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    bind(t, node.value)
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
                bind(node.target, node.value)
            elif isinstance(node, ast.AugAssign):
                bind(node.target, None)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.withitem)):
                target = node.target if not isinstance(node, ast.withitem) else node.optional_vars
                if target is not None:
                    value = node.context_expr if isinstance(node, ast.withitem) else None
                    bind(target, value)
        return bindings

    def facts(self, scope: ast.AST, exclude_params: bool) -> _Facts:
        key = (id(scope), exclude_params)
        cached = self._facts.get(key)
        if cached is not None:
            return cached
        params = (
            _function_params(scope)
            if exclude_params and isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            else frozenset()
        )
        bindings = self._bindings(scope)
        constant = {
            name for name, values in bindings.items()
            if values and all(isinstance(v, ast.Constant) for v in values)
        }
        if scope is not self.tree:
            module = self.facts(self.tree, False)
            constant |= {
                n for n in module.constant_names if n not in bindings
            }
        partial = _Facts(params, frozenset(constant), frozenset(bindings), frozenset())
        tainted: set[str] = set()
        # Two rounds: `ok = request_approval()` then `allowed = ok`.
        for _ in range(2):
            current = _Facts(params, partial.constant_names, partial.bound_names, frozenset(tainted))
            for name, values in bindings.items():
                if name in params or name in tainted:
                    continue
                if any(v is not None and self._mentions(v, current) for v in values):
                    tainted.add(name)
        result = _Facts(params, partial.constant_names, partial.bound_names, frozenset(tainted))
        self._facts[key] = result
        return result

    # -- "mentions approval" -------------------------------------------

    def _approval_call(self, call: ast.Call, facts: _Facts) -> bool:
        if self.is_sink(call):
            return False
        name = call_name(call, self.aliases)
        if name is None:
            return False
        root = _root_name(call.func)
        if root is not None and root in facts.params:
            return False
        return is_approval_name(name, self.extra)

    def _mentions(self, expr: ast.AST, facts: _Facts) -> bool:
        stack: list[ast.AST] = [expr]
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(node, ast.Call):
                if self._approval_call(node, facts):
                    return True
                if self.is_sink(node):
                    # Neither the sink's name nor anything inside it counts.
                    continue
                stack.extend(node.args)
                stack.extend(kw.value for kw in node.keywords)
                if isinstance(node.func, ast.Attribute):
                    stack.append(node.func.value)
                continue
            if isinstance(node, ast.Name):
                if node.id in facts.tainted:
                    return True
                if (
                    node.id not in facts.params
                    and node.id not in facts.constant_names
                    and is_approval_name(node.id, self.extra)
                ):
                    return True
                continue
            if isinstance(node, ast.Attribute):
                root = _root_name(node)
                if (root is None or root not in facts.params) and is_approval_name(
                    node.attr, self.extra
                ):
                    return True
                stack.append(node.value)
                continue
            stack.extend(ast.iter_child_nodes(node))
        return False

    def mentions(self, expr: ast.AST, scope: ast.AST, exclude_params: bool) -> bool:
        return self._mentions(expr, self.facts(scope, exclude_params))

    # -- dominance -----------------------------------------------------

    # -- polarity --------------------------------------------------------

    def _polarity(self, test: ast.AST, facts: _Facts) -> int:
        """APPROVED if `test` is true when approval was given, REFUSED if it
        is true when approval was refused, UNKNOWN if it cannot be read."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return -self._polarity(test.operand, facts)
        if isinstance(test, ast.Await):
            return self._polarity(test.value, facts)
        if isinstance(test, ast.BoolOp):
            parts = {
                self._polarity(v, facts) for v in test.values if self._mentions(v, facts)
            }
            return parts.pop() if len(parts) == 1 else UNKNOWN
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op, right = test.ops[0], test.comparators[0]
            constant = right if isinstance(right, ast.Constant) else (
                test.left if isinstance(test.left, ast.Constant) else None
            )
            if constant is None:
                return UNKNOWN
            value = constant.value
            refusal = value in (False, None, 0) or (
                isinstance(value, str) and value.strip().lower() in DENIAL_WORDS
            )
            if isinstance(op, (ast.Eq, ast.Is, ast.In)):
                return REFUSED if refusal else APPROVED
            if isinstance(op, (ast.NotEq, ast.IsNot, ast.NotIn)):
                return APPROVED if refusal else REFUSED
            return UNKNOWN
        if isinstance(test, (ast.Name, ast.Attribute, ast.Call)):
            words = set()
            for node in ast.walk(test):
                name = (
                    node.id if isinstance(node, ast.Name)
                    else node.attr if isinstance(node, ast.Attribute) else None
                )
                if name:
                    words |= {w for w in name.lower().replace("-", "_").split("_") if w}
            return REFUSED if words & DENIAL_WORDS else APPROVED
        return UNKNOWN

    def _approves(self, test: ast.AST, facts: _Facts, when_true: bool) -> bool:
        """True if `test` mentions approval and the branch taken when it is
        `when_true` is the approved one (or polarity is unknown)."""
        if not self._mentions(test, facts):
            return False
        polarity = self._polarity(test, facts)
        return polarity != (REFUSED if when_true else APPROVED)

    def _is_guard(self, stmt: ast.stmt, facts: _Facts) -> bool:
        """A statement after which execution continues only if approved."""
        if isinstance(stmt, ast.Assert):
            return self._approves(stmt.test, facts, when_true=True)
        if isinstance(stmt, ast.If):
            # The body exits: execution continues when the test is false, so
            # the false side must be the approved one -- and vice versa.
            return (
                _terminates(stmt.body) and self._approves(stmt.test, facts, when_true=False)
            ) or (
                _terminates(stmt.orelse) and self._approves(stmt.test, facts, when_true=True)
            )
        if isinstance(stmt, ast.Expr):
            value = stmt.value
            if isinstance(value, ast.Await):
                value = value.value
            return isinstance(value, ast.Call) and self._approval_call(value, facts)
        return False

    def _scope_may_approve(self, scope: ast.AST) -> bool:
        """Cheap pre-check: a scope with no approval vocabulary anywhere in
        it cannot dominate anything. True for most functions in most repos,
        and it skips the full analysis for all of them."""
        cached = self._may_approve.get(id(scope))
        if cached is None:
            cached = False
            for node in self.scope_nodes(scope):
                name = (
                    node.id if isinstance(node, ast.Name)
                    else node.attr if isinstance(node, ast.Attribute)
                    else None
                )
                if name is not None and is_approval_name(name, self.extra):
                    cached = True
                    break
            self._may_approve[id(scope)] = cached
        return cached

    def is_dominated(self, node: ast.AST, scope: ast.AST, exclude_params: bool) -> bool:
        """True if an approval check runs before `node` on every path to it
        within `scope` (see the module docstring for what counts)."""
        if not self._scope_may_approve(scope):
            return False
        facts = self.facts(scope, exclude_params)
        child: ast.AST = node
        parent = self.parents.get(child)
        while parent is not None:
            if isinstance(parent, (ast.If, ast.While, ast.IfExp)) and child is not parent.test:
                in_true_branch = (
                    child is parent.body if isinstance(parent, ast.IfExp)
                    else any(s is child for s in parent.body)
                )
                if self._approves(parent.test, facts, when_true=in_true_branch):
                    return True
            elif isinstance(parent, ast.BoolOp) and isinstance(parent.op, ast.And):
                for value in parent.values:
                    if value is child:
                        break
                    if self._approves(value, facts, when_true=True):
                        return True
            elif isinstance(parent, (ast.With, ast.AsyncWith)):
                if any(s is child for s in parent.body) and any(
                    self._mentions(item.context_expr, facts) for item in parent.items
                ):
                    return True
            elif isinstance(
                parent, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
            ) and any(
                self._approves(cond, facts, when_true=True)
                for gen in parent.generators
                for cond in gen.ifs
            ):
                return True
            for field_name in ("body", "orelse", "finalbody"):
                block = getattr(parent, field_name, None)
                if not isinstance(block, list):
                    continue
                for index, stmt in enumerate(block):
                    if stmt is child:
                        if any(self._is_guard(s, facts) for s in block[:index]):
                            return True
                        break
            if parent is scope:
                break
            child, parent = parent, self.parents.get(parent)
        return False

    def decorated(self, fn: FunctionNode) -> bool:
        """True if the function carries an approval decorator
        (@requires_approval, @human_in_the_loop(...))."""
        for dec in fn.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            name = call_name(ast.Call(func=target, args=[], keywords=[]), self.aliases)
            if name is not None and is_approval_name(name, self.extra):
                return True
        return False
