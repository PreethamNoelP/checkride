"""Tool entry points and agent reachability, across the whole scan.

A sensitive call is only an agent risk if the model can reach it. This
module finds the functions the model can call directly (tool entry points)
and everything those functions call, transitively and across files, so the
rules can judge exactly that code.

Entry points are recognized by:

  - a decorator naming a tool: @mcp.tool(), @tool, @server.call_tool(),
    @function_tool, @agent.tool_plain, @kernel_function,
    @register_for_llm(), plus `extra_tool_decorators` from config;
  - registration by reference: mcp.add_tool(fn), Tool(func=fn),
    FunctionTool.from_defaults(fn=fn), StructuredTool.from_function(fn),
    register_function(fn, ...), any call with `tools=[...]`/`functions=[...]`,
    and module-level `TOOLS = [...]`/`tool_map = {...}` tables;
  - class-based tools: run/_run/_arun/invoke/forward/... on a class whose
    base names a tool (BaseTool, Tool);
  - `extra_tool_entry_points` from config (dotted or bare names).

Calls are resolved statically: local names, `self.method`, module
attributes through imports (including relative imports), constructors, and
functions passed as callbacks. A method call on an unknown receiver links to
every same-named function in the same file -- an over-approximation, which
errs toward judging more code, never less.

Each analysis also records whether every path into a helper is gated by an
approval check (see approval.py), so `def _rm(p): shutil.rmtree(p)` called
only from behind `if not request_approval(...): return` is not reported.
"""

import ast
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from checkride.astutils import FunctionNode, dotted_name, word_tokens

if TYPE_CHECKING:
    from checkride.astutils import FileContext

Key = tuple[str, int, int]  # (file path as reported, def lineno, def col)

TOOL_DECORATOR_NAMES = frozenset({
    "kernel_function", "register_for_llm", "register_for_execution",
    "function_tool", "ai_function", "llm_tool",
})
REGISTER_CALL_NAMES = frozenset({
    "add_tool", "register_tool", "register_function", "from_function",
    "register_for_llm", "register_for_execution",
})
TOOL_KWARGS = frozenset({"tools", "functions", "function_map", "tool_map"})
FUNC_KWARGS = frozenset({"fn", "func", "function", "coroutine", "handler", "callable"})
TOOL_CLASS_METHODS = frozenset({
    "_run", "_arun", "run", "arun", "invoke", "ainvoke", "__call__",
    "call", "acall", "execute", "forward",
})


def key_of(path: str, fn: FunctionNode) -> Key:
    return (path, fn.lineno, fn.col_offset)


def is_tool_decorator(
    dec: ast.expr, aliases: dict[str, str], extra: frozenset[str] = frozenset()
) -> bool:
    target = dec.func if isinstance(dec, ast.Call) else dec
    name = dotted_name(target, aliases)
    if name is None:
        return False
    last = name.rsplit(".", 1)[-1]
    return (
        "tool" in word_tokens(name)
        or last in TOOL_DECORATOR_NAMES
        or name in extra
        or last in extra
    )


# -- per-file summary -------------------------------------------------------

Ref = tuple[str, str, str]
# ("name", id, "")          bare call foo()
# ("method", class, attr)   self.attr() inside class
# ("dotted", dotted, "")    module-qualified call, alias-resolved
# ("attr", "", attr)        attr() on an unknown receiver


@dataclass
class Edge:
    ref: Ref
    site: tuple[int, int]  # (lineno, col_offset) of the call
    gated: bool         # dominated by approval, caller params allowed
    gated_strict: bool  # dominated by approval, caller params excluded
    handled: bool = False  # inside a try body whose handler deals with failure


@dataclass
class FuncInfo:
    key: Key
    name: str
    qualname: str
    class_name: str | None
    parent: Key | None
    entry: bool
    approval_decorated: bool
    has_sink: bool
    logs: bool
    rate: bool
    edges: list[Edge] = field(default_factory=list)
    # The function is a decorator whose wrapper asks for approval before
    # calling the function it wraps (see _is_approval_decorator).
    approval_decorator: bool = False
    decorator_refs: list[Ref] = field(default_factory=list)


@dataclass
class FileSummary:
    path: str
    module: str
    functions: dict[Key, FuncInfo]
    toplevel: dict[str, Key]
    classes: dict[str, dict[str, Key]]
    nested: dict[Key, dict[str, Key]]
    aliases: dict[str, str]
    registrations: list[Ref]


def _module_aliases(
    nodes: Iterable[ast.AST], module: str, is_package: bool
) -> dict[str, str]:
    """Import aliases including relative imports, resolved against `module`."""
    package = module if is_package else module.rpartition(".")[0]
    aliases: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    aliases[alias.asname] = alias.name
                else:
                    # `import ops` binds ops; `import a.b` binds a.
                    root = alias.name.split(".", 1)[0]
                    aliases.setdefault(root, root)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = package.split(".") if package else []
                if node.level > 1:
                    base_parts = base_parts[: len(base_parts) - (node.level - 1)]
                base = ".".join(base_parts)
                source = ".".join(p for p in (base, node.module or "") if p)
            else:
                source = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                aliases[local] = f"{source}.{alias.name}" if source else alias.name
    return aliases


def _ref_for(func: ast.expr, aliases: dict[str, str], class_name: str | None) -> Ref | None:
    if isinstance(func, ast.Name):
        if func.id in aliases:
            return ("dotted", aliases[func.id], "")
        return ("name", func.id, "")
    if isinstance(func, ast.Attribute):
        root: ast.expr = func
        while isinstance(root, ast.Attribute):
            root = root.value
        if (
            isinstance(root, ast.Name)
            and root.id in ("self", "cls")
            and func.value is root
            and class_name is not None
        ):
            return ("method", class_name, func.attr)
        if isinstance(root, ast.Name) and root.id in aliases:
            dotted = dotted_name(func, aliases)
            if dotted is not None:
                return ("dotted", dotted, "")
        if isinstance(root, ast.Name) and func.value is root:
            return ("method", root.id, func.attr)  # Class.method or obj.method
        return ("attr", "", func.attr)
    return None


def _value_refs(node: ast.expr, aliases: dict[str, str], class_name: str | None) -> list[Ref]:
    """Function references inside a value: a name, an attribute, or the
    elements of a list/tuple/set/dict of them."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [r for e in node.elts for r in _value_refs(e, aliases, class_name)]
    if isinstance(node, ast.Dict):
        return [r for v in node.values for r in _value_refs(v, aliases, class_name)]
    if isinstance(node, ast.Call):
        # Tool(func=f) inside a list: recurse into its arguments.
        return [
            r
            for a in [*node.args, *(kw.value for kw in node.keywords)]
            for r in _value_refs(a, aliases, class_name)
        ]
    if isinstance(node, (ast.Name, ast.Attribute)):
        ref = _ref_for(node, aliases, class_name)
        return [ref] if ref is not None else []
    return []


def _registration_refs(call: ast.Call, aliases: dict[str, str]) -> list[Ref]:
    refs: list[Ref] = []
    name = dotted_name(call.func, aliases)
    if name is not None:
        tokens = word_tokens(name)
        last = name.rsplit(".", 1)[-1]
        if tokens & {"tool", "tools"} or last in REGISTER_CALL_NAMES:
            for arg in call.args:
                if isinstance(arg, (ast.Name, ast.Attribute)):
                    refs.extend(_value_refs(arg, aliases, None))
            for kw in call.keywords:
                if kw.arg in FUNC_KWARGS:
                    refs.extend(_value_refs(kw.value, aliases, None))
    for kw in call.keywords:
        if kw.arg in TOOL_KWARGS:
            refs.extend(_value_refs(kw.value, aliases, None))
    return refs


def summarize(ctx: "FileContext", module: str, is_package: bool = False) -> FileSummary:
    """Everything the cross-file analysis needs from one file. Holds no AST
    nodes, so a whole repository's summaries stay small."""
    from checkride.rules.audit import makes_log_call
    from checkride.rules.errorhandling import protection
    from checkride.rules.ratelimit import mentions_rate_limit

    tree = ctx.tree
    aliases = _module_aliases(ctx.all_nodes, module, is_package)
    config = ctx.config
    decorators = config.tool_decorators
    analyzer = ctx.approval
    sink_scopes = {
        id(ctx.enclosing_scope(call)) for call, _label in ctx.candidate_sensitive_calls
    }

    functions: dict[Key, FuncInfo] = {}
    toplevel: dict[str, Key] = {}
    classes: dict[str, dict[str, Key]] = {}
    nested: dict[Key, dict[str, Key]] = {}
    registrations: list[Ref] = []

    def visit(body: Iterable[ast.stmt], prefix: str, class_name: str | None,
              tool_class: bool, parent: Key | None) -> None:
        for stmt in body:
            if isinstance(stmt, ast.ClassDef):
                bases = [dotted_name(b, aliases) or "" for b in stmt.bases]
                is_tool_class = any("tool" in word_tokens(b) for b in bases)
                classes.setdefault(stmt.name, {})
                visit(
                    ctx.direct_defs(stmt), f"{prefix}{stmt.name}.", stmt.name,
                    is_tool_class, parent,
                )
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = key_of(ctx.path, stmt)
                entry = not _is_stub(stmt, aliases) and (
                    any(is_tool_decorator(d, aliases, decorators) for d in stmt.decorator_list)
                    or (tool_class and stmt.name in TOOL_CLASS_METHODS)
                )
                info = FuncInfo(
                    key=key,
                    name=stmt.name,
                    qualname=f"{prefix}{stmt.name}",
                    class_name=class_name,
                    parent=parent,
                    entry=entry,
                    approval_decorated=analyzer.decorated(stmt),
                    has_sink=id(stmt) in sink_scopes,
                    logs=makes_log_call(stmt, config, aliases, ctx.scope_nodes(stmt)),
                    rate=mentions_rate_limit(stmt, config, ctx.scope_nodes(stmt)),
                    approval_decorator=_is_approval_decorator(stmt, ctx),
                    decorator_refs=[
                        ref for dec in stmt.decorator_list
                        if (ref := _ref_for(
                            dec.func if isinstance(dec, ast.Call) else dec,
                            aliases, class_name,
                        )) is not None
                    ],
                )
                functions[key] = info
                if parent is not None:
                    nested.setdefault(parent, {})[stmt.name] = key
                elif class_name is not None:
                    classes[class_name][stmt.name] = key
                else:
                    toplevel[stmt.name] = key
                for node in ctx.scope_nodes(stmt):
                    if not isinstance(node, ast.Call):
                        continue
                    refs: list[Ref] = []
                    ref = _ref_for(node.func, aliases, class_name)
                    if ref is not None:
                        refs.append(ref)
                    # Functions handed over as callbacks run as a result of
                    # this call: to_thread(helper), executor.submit(job).
                    for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                        if isinstance(arg, ast.Name):
                            cb = _ref_for(arg, aliases, class_name)
                            if cb is not None:
                                refs.append(cb)
                    if refs:
                        gated = analyzer.is_dominated(node, stmt, exclude_params=False)
                        strict = analyzer.is_dominated(node, stmt, exclude_params=True)
                        handled = protection(node, ctx.parents) == "handled"
                        site = (node.lineno, node.col_offset)
                        info.edges.extend(
                            Edge(r, site, gated, strict, handled) for r in refs
                        )
                    registrations.extend(_registration_refs(node, aliases))
                visit(ctx.direct_defs(stmt), f"{prefix}{stmt.name}.", None, False, key)

    visit(ctx.direct_defs(tree), "", None, False, None)

    # Module-level and class-level registrations and tool tables.
    for node in ctx.scope_nodes(tree):
        if isinstance(node, ast.Call):
            registrations.extend(_registration_refs(node, aliases))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                name = dotted_name(target) if isinstance(target, (ast.Name, ast.Attribute)) else None
                if name and word_tokens(name) & {"tool", "tools"}:
                    registrations.extend(_value_refs(node.value, aliases, None))

    return FileSummary(
        path=ctx.path,
        module=module,
        functions=functions,
        toplevel=toplevel,
        classes=classes,
        nested=nested,
        aliases=aliases,
        registrations=registrations,
    )


def _is_approval_decorator(fn: FunctionNode, ctx: "FileContext") -> bool:
    """True if `fn` is a decorator (or decorator factory) whose wrapper calls
    the wrapped function only behind an approval check:

        def policy_checked(func):
            def wrapper(*args, **kwargs):
                if not request_approval(func.__name__, args):
                    raise PermissionError
                return func(*args, **kwargs)
            return wrapper

    The wrapped function is any parameter of `fn` or of a function nested
    between `fn` and the wrapper (a factory's inner decorator)."""
    from checkride.approval import _function_params

    def search(outer: ast.AST, wrapped: frozenset[str], depth: int) -> bool:
        for inner in ctx.direct_defs(outer):
            if not isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ctx.scope_nodes(inner):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in wrapped
                    and ctx.approval.is_dominated(node, inner, exclude_params=False)
                ):
                    return True
            if depth < 2 and search(inner, wrapped | _function_params(inner), depth + 1):
                return True
        return False

    params = _function_params(fn)
    return bool(params) and search(fn, params, 1)


def _is_stub(fn: FunctionNode, aliases: dict[str, str]) -> bool:
    """Abstract methods, protocol stubs and properties: code the model can
    never execute as a tool body."""
    for dec in fn.decorator_list:
        name = dotted_name(dec.func if isinstance(dec, ast.Call) else dec, aliases)
        if name and name.rsplit(".", 1)[-1] in (
            "abstractmethod", "property", "overload", "cached_property"
        ):
            return True
    body = [
        s for s in fn.body
        if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
    ]
    if not body:
        return True
    if len(body) == 1:
        stmt = body[0]
        if isinstance(stmt, ast.Pass):
            return True
        if isinstance(stmt, ast.Raise) and stmt.exc is not None:
            exc = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
            return dotted_name(exc) == "NotImplementedError"
    return False


# -- whole-program index ----------------------------------------------------


@dataclass
class ProgramIndex:
    """The cross-file answers each FileContext consults."""

    scope: str
    entries: set[Key]
    reachable: set[Key]
    gated: set[Key]
    protected: set[Key]
    # (path, lineno, col) of calls that resolved to a scanned function.
    resolved_sites: set[tuple[str, int, int]]
    logs_closure: set[Key]
    rate_closure: set[Key]
    qualnames: dict[Key, str]

    @classmethod
    def build(
        cls,
        summaries: list[FileSummary],
        scope: str = "tools",
        extra_entry_points: tuple[str, ...] = (),
    ) -> "ProgramIndex":
        funcs: dict[Key, FuncInfo] = {}
        file_of: dict[Key, FileSummary] = {}
        dotted: dict[str, list[Key]] = {}
        by_name: dict[str, dict[str, list[Key]]] = {}  # path -> name -> keys

        for summary in summaries:
            parts = summary.module.split(".") if summary.module else []
            suffixes = [".".join(parts[i:]) for i in range(len(parts))] or [""]
            names = by_name.setdefault(summary.path, {})
            for key, info in summary.functions.items():
                funcs[key] = info
                file_of[key] = summary
                names.setdefault(info.name, []).append(key)
                if info.parent is None:
                    for suffix in suffixes:
                        full = f"{suffix}.{info.qualname}" if suffix else info.qualname
                        dotted.setdefault(full, []).append(key)
            for class_name, methods in summary.classes.items():
                init = methods.get("__init__")
                if init is not None:
                    for suffix in suffixes:
                        full = f"{suffix}.{class_name}" if suffix else class_name
                        dotted.setdefault(full, []).append(init)

        def resolve(ref: Ref, summary: FileSummary, caller: FuncInfo | None) -> list[Key]:
            kind, a, b = ref
            if kind == "name":
                scope_key = caller.key if caller else None
                while scope_key is not None:
                    hit = summary.nested.get(scope_key, {}).get(a)
                    if hit is not None:
                        return [hit]
                    scope_key = funcs[scope_key].parent
                if a in summary.toplevel:
                    return [summary.toplevel[a]]
                if a in summary.classes and "__init__" in summary.classes[a]:
                    return [summary.classes[a]["__init__"]]
                return []
            if kind == "dotted":
                return dotted.get(a, [])
            if kind == "method":
                methods = summary.classes.get(a)
                if methods is not None and b in methods:
                    return [methods[b]]
                    # Inherited or defined elsewhere in the file.
                return [
                    k for k in by_name[summary.path].get(b, [])
                    if funcs[k].class_name is not None or funcs[k].parent is None
                ]
            if kind == "attr":
                return list(by_name[summary.path].get(b, []))
            return []

        entries = {k for k, info in funcs.items() if info.entry}
        for summary in summaries:
            for ref in summary.registrations:
                entries.update(resolve(ref, summary, None))
        for wanted in extra_entry_points:
            for key, info in funcs.items():
                full = f"{file_of[key].module}.{info.qualname}"
                if wanted in (info.qualname, info.name) or full.endswith(f".{wanted}") or full == wanted:
                    entries.add(key)
        if scope == "all":
            entries |= {k for k, info in funcs.items() if info.has_sink}

        callees: dict[Key, set[Key]] = {k: set() for k in funcs}
        callers: dict[Key, list[tuple[Key, Edge]]] = {k: [] for k in funcs}
        children: dict[Key, set[Key]] = {k: set() for k in funcs}
        resolved_sites: set[tuple[str, int, int]] = set()
        for key, info in funcs.items():
            if info.parent is not None:
                children[info.parent].add(key)
            summary = file_of[key]
            for edge in info.edges:
                targets = resolve(edge.ref, summary, info)
                # Only an exact resolution means "this call runs that code";
                # a same-named method on an unknown receiver may be anything.
                if targets and edge.ref[0] in ("name", "dotted", "method") and (
                    edge.ref[0] != "method" or edge.ref[1] in summary.classes
                    or edge.ref[1] in ("self", "cls")
                ):
                    resolved_sites.add((summary.path, *edge.site))
                for target in targets:
                    if target == key:
                        continue
                    callees[key].add(target)
                    callers[target].append((key, edge))

        def closure(start: Iterable[Key]) -> set[Key]:
            seen = set(start)
            queue = deque(seen)
            while queue:
                current = queue.popleft()
                for nxt in callees[current] | children[current]:
                    if nxt not in seen:
                        seen.add(nxt)
                        queue.append(nxt)
            return seen

        reachable = closure(entries) if scope != "all" else set(funcs)

        def every_path(start: set[Key], edge_ok: "Callable[[Key, Edge], bool]") -> set[Key]:
            """Functions every reachable call path into which satisfies
            `edge_ok` or comes from a function already in the set. Least
            fixed point, so call cycles never qualify by assumption; entry
            points are called by the model and never qualify through edges."""
            result = set(start)
            changed = True
            while changed:
                changed = False
                for key, info in funcs.items():
                    if key in result or key in entries or key not in reachable:
                        continue
                    incoming = [(c, e) for c, e in callers[key] if c in reachable]
                    if incoming:
                        ok = all(edge_ok(c, e) or c in result for c, e in incoming)
                    elif info.parent is not None:
                        ok = info.parent in result
                    else:
                        ok = False
                    if ok:
                        result.add(key)
                        changed = True
            return result

        approval_decorators = {k for k, info in funcs.items() if info.approval_decorator}
        decorated_by_approval = {
            key for key, info in funcs.items()
            if any(
                target in approval_decorators
                for ref in info.decorator_refs
                for target in resolve(ref, file_of[key], None)
            )
        }
        gated = every_path(
            {k for k, info in funcs.items() if info.approval_decorated}
            | decorated_by_approval,
            lambda c, e: e.gated_strict if c in entries else e.gated,
        )
        protected = every_path(set(), lambda c, e: e.handled)

        logs_closure: set[Key] = set()
        rate_closure: set[Key] = set()
        for entry in entries:
            members = closure([entry])
            if any(funcs[m].logs for m in members):
                logs_closure.add(entry)
            if any(funcs[m].rate for m in members):
                rate_closure.add(entry)

        return cls(
            scope=scope,
            entries=entries,
            reachable=reachable,
            gated=gated,
            protected=protected,
            resolved_sites=resolved_sites,
            logs_closure=logs_closure,
            rate_closure=rate_closure,
            qualnames={k: info.qualname for k, info in funcs.items()},
        )
