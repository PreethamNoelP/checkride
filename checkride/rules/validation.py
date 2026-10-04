"""Rule 5 of 6: Tool scope & input validation (15 points).

Model-supplied inputs must be validated before they reach a sensitive call
or a file path. Inputs are:

  - parameters of tool entry points that have a risky name (path, cmd,
    query, url, ... in snake_case or camelCase), or that -- whatever their
    name -- flow into a sensitive call or into building a file path
    (`open(name)`, `Path(name)`, `os.path.join(ROOT, name)`, `ROOT / name`):
    `read_note(name)` doing `(NOTES / name).read_text()` is path traversal
    no matter what the parameter is called. Numeric and boolean parameters
    are not inputs of this kind;
  - risky-named fields of a Pydantic-style input model a tool takes as a
    parameter (a class defined in the same file);
  - risky keys read from a low-level MCP `arguments` dict
    (`arguments["path"]`, `arguments.get("cmd")`).

Validation evidence, any of:
  - a constraining type: `Literal[...]`, an Enum class, `Annotated[T,
    Field(pattern=...)]` (or StringConstraints/constr with a constraint, or
    an After/Before/PlainValidator), a model `Field(...)` with a constraint,
    or a `@field_validator`/`@model_validator` covering the field;
  - an if/while/assert test that actually tests the value -- a comparison,
    membership or method check (`path.startswith(ROOT)`, `cmd in ALLOWED`).
    Bare truthiness, `is None` and isinstance() checks do not count;
  - passing it to a validator-named call (validate, sanitize, check,
    verify, allowlist, quote, safe_*, secure_*, ensure_*, ...), which is not
    itself a sensitive call: `subprocess.check_output(cmd)` validates
    nothing.

Ordering: when the input reaches a sensitive call, the validation must
start before that call (a sanitizer wrapping the argument, such as
`run(shlex.quote(cmd))`, counts).

One assignment hop is followed: with `argv = shlex.split(command)`, an
allowlist check on `argv[0]` validates `command`, provided `command` itself
never reaches a sink unvalidated.
"""

import ast
from collections.abc import Iterator
from dataclasses import dataclass

from checkride.approval import is_approval_name
from checkride.astutils import (
    FileContext,
    FunctionNode,
    call_name,
    dotted_name,
    name_tokens,
    word_tokens,
)
from checkride.models import Finding

RULE_ID = "input-validation"
CATEGORY = "Tool scope & input validation"
WEIGHT = 15

RISKY_PARAM_TOKENS = frozenset({
    "path", "file", "filename", "filepath", "dir", "directory", "folder",
    "cmd", "command", "shell", "script",
    "query", "sql",
    "url", "uri", "host", "endpoint",
    "target", "dest", "destination",
})

VALIDATION_TOKENS = frozenset({
    "validate", "validated", "validation", "validator",
    "sanitize", "sanitized", "sanitise", "sanitised",
    "check", "checked",
    "verify", "verified",
    "allowed", "allowlist", "whitelist", "permitted",
    "escape", "quote",
    "safe", "secure", "ensure", "restrict", "restricted",
})

_NON_VALIDATING_CALLS = frozenset(
    {"isinstance", "hasattr", "callable", "type", "bool", "str", "repr", "print"}
)
_ARGUMENT_DICT_NAMES = frozenset(
    {"arguments", "args", "params", "kwargs", "inputs", "input", "payload", "tool_input"}
)
_CONSTRAINT_KWARGS = frozenset({
    "pattern", "regex", "max_length", "min_length", "ge", "gt", "le", "lt",
    "multiple_of", "max_digits", "decimal_places",
})
_CONSTRAINT_CALLS = frozenset({"Field", "StringConstraints", "constr", "conint", "confloat"})
_VALIDATOR_CALLS = frozenset(
    {"AfterValidator", "BeforeValidator", "PlainValidator", "WrapValidator"}
)
_ENUM_BASES = frozenset({"Enum", "StrEnum", "IntEnum", "Flag", "IntFlag"})
# Calls that turn a string into a filesystem location.
_PATH_CALLS = frozenset({
    "open", "io.open", "os.open", "Path", "pathlib.Path", "PurePath",
    "pathlib.PurePath", "PosixPath", "WindowsPath", "os.path.join",
    "os.path.expanduser", "os.path.abspath", "os.path.realpath",
    "os.path.normpath", "os.listdir", "os.scandir", "os.stat", "os.walk",
    "shutil.copy", "shutil.copyfile", "shutil.copytree", "shutil.move",
})
_SCALAR_ANNOTATIONS = frozenset({"int", "float", "bool", "complex"})
# Sinks that interpret a string's content -- as a path, a command, code or a
# query. An identifier handed to a payment or cloud API is authorized by that
# API, so flowing into one does not by itself make a parameter an input.
_INTERPRETING_LABELS = frozenset({"file delete", "shell exec", "code exec", "sql exec"})


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _is_risky(name: str, risky: frozenset[str]) -> bool:
    return bool(word_tokens(name) & risky) or name.lower() in risky


def _is_validator_call(call: ast.Call, ctx: FileContext, tokens: frozenset[str]) -> bool:
    if ctx.is_sensitive(call):
        return False
    name = call_name(call, ctx.import_aliases)
    return name is not None and bool(name_tokens(name) & tokens)


def _tested_names(test: ast.expr) -> set[str]:
    """Names a condition genuinely tests -- not bare truthiness, `is None`,
    or isinstance()."""
    if isinstance(test, ast.BoolOp):
        return set().union(*(_tested_names(v) for v in test.values))
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _tested_names(test.operand)
    if isinstance(test, ast.Name):
        return set()
    if isinstance(test, ast.Compare):
        trivial = isinstance(test.left, ast.Name) and all(
            isinstance(op, (ast.Is, ast.IsNot, ast.Eq, ast.NotEq))
            and isinstance(c, ast.Constant)
            and c.value in (None, "", 0, False)
            for op, c in zip(test.ops, test.comparators)
        )
        return set() if trivial else _names_in(test)
    if isinstance(test, ast.Call):
        name = call_name(test)
        if name in _NON_VALIDATING_CALLS:
            return set()
        # Asking a human about a value is approval, not input validation.
        if name is not None and is_approval_name(name):
            return set()
    if isinstance(test, ast.Await):
        return _tested_names(test.value)
    return _names_in(test)


@dataclass
class _Evidence:
    line: int
    col: int
    names: set[str]


def _evidence(fn: FunctionNode, ctx: FileContext, tokens: frozenset[str]) -> list[_Evidence]:
    found: list[_Evidence] = []
    for node in ctx.scope_nodes(fn):
        if isinstance(node, (ast.If, ast.While, ast.Assert)):
            names = _tested_names(node.test)
            if names:
                found.append(_Evidence(node.lineno, node.col_offset, names))
        elif isinstance(node, ast.Call) and _is_validator_call(node, ctx, tokens):
            found.append(_Evidence(node.lineno, node.col_offset, _names_in(node)))
    return found


def _raw_names(node: ast.AST, ctx: FileContext, tokens: frozenset[str]) -> set[str]:
    """Names used inside a sink call, skipping validator-call subtrees:
    in run(shlex.quote(cmd)) the sink never sees raw `cmd`."""
    names: set[str] = set()
    stack: list[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if current is not node and isinstance(current, ast.Call) and _is_validator_call(
            current, ctx, tokens
        ):
            continue
        if isinstance(current, ast.Name):
            names.add(current.id)
        stack.extend(ast.iter_child_nodes(current))
    return names


def _first_raw_use(
    fn: FunctionNode,
    ctx: FileContext,
    tokens: frozenset[str],
    labels: frozenset[str] | None = None,
) -> dict[str, tuple[int, int]]:
    """Where each name first reaches a sensitive call unsanitized, optionally
    only for calls with the given labels."""
    first: dict[str, tuple[int, int]] = {}
    for call, label in ctx.sensitive_calls_by_function.get(id(fn), ()):
        if labels is not None and label not in labels:
            continue
        position = (call.lineno, call.col_offset)
        for name in _raw_names(call, ctx, tokens):
            if name not in first or position < first[name]:
                first[name] = position
    return first


def _validated_directly(
    name: str, evidence: list[_Evidence], first_use: dict[str, tuple[int, int]]
) -> bool:
    limit = first_use.get(name)
    return any(
        name in e.names and (limit is None or (e.line, e.col) < limit)
        for e in evidence
    )


def _derived_names(fn: FunctionNode, ctx: FileContext) -> dict[str, set[str]]:
    """name -> the names its assigned value was computed from, for simple
    `x = <expr>` assignments in the function's own scope."""
    derived: dict[str, set[str]] = {}
    for node in ctx.scope_nodes(fn):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            derived.setdefault(node.targets[0].id, set()).update(_names_in(node.value))
    return derived


def _is_validated(
    name: str,
    evidence: list[_Evidence],
    first_use: dict[str, tuple[int, int]],
    derived: dict[str, set[str]] | None = None,
) -> bool:
    if _validated_directly(name, evidence, first_use):
        return True
    if derived is None or name in first_use:
        # Used raw in a sink: only validation of the value itself counts.
        return False
    return any(
        name in sources and _validated_directly(alias, evidence, first_use)
        for alias, sources in derived.items()
        if alias != name
    )


# -- type-level evidence ----------------------------------------------------


def _has_constraint(call: ast.Call) -> bool:
    return any(kw.arg in _CONSTRAINT_KWARGS for kw in call.keywords)


def _last(name: str | None) -> str | None:
    return name.rsplit(".", 1)[-1] if name else None


def _class_defs(nodes: list[ast.AST]) -> dict[str, ast.ClassDef]:
    return {n.name: n for n in nodes if isinstance(n, ast.ClassDef)}


def _is_enum(cls: ast.ClassDef) -> bool:
    return any(_last(dotted_name(b)) in _ENUM_BASES for b in cls.bases)


def _annotation_is_constrained(
    annotation: ast.expr | None, classes: dict[str, ast.ClassDef] | None = None
) -> bool:
    if annotation is None:
        return False
    if isinstance(annotation, ast.Call):
        return _last(call_name(annotation)) in _CONSTRAINT_CALLS and _has_constraint(annotation)
    if isinstance(annotation, (ast.Name, ast.Attribute)):
        cls = (classes or {}).get(_last(dotted_name(annotation)) or "")
        return cls is not None and _is_enum(cls)
    if not isinstance(annotation, ast.Subscript):
        return False
    base = _last(dotted_name(annotation.value))
    if base == "Literal":
        return True
    if base == "Annotated":
        meta = annotation.slice
        # Annotated[T, m1, m2]: the slice is the tuple (T, m1, m2).
        metadata = meta.elts[1:] if isinstance(meta, ast.Tuple) else []
        for elt in metadata:
            if not isinstance(elt, ast.Call):
                continue
            callee = _last(call_name(elt))
            if callee in _VALIDATOR_CALLS:
                return True
            if callee in _CONSTRAINT_CALLS and _has_constraint(elt):
                return True
        return False
    if base == "Optional":
        return _annotation_is_constrained(annotation.slice, classes)
    return False


def _model_validated_fields(cls: ast.ClassDef) -> tuple[set[str], bool]:
    """(fields named by @field_validator/@validator, any model-level validator)."""
    named: set[str] = set()
    whole = False
    for stmt in cls.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in stmt.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            last = _last(dotted_name(target))
            if last in ("model_validator", "root_validator"):
                whole = True
            elif last in ("field_validator", "validator") and isinstance(dec, ast.Call):
                for arg in dec.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        named.add(arg.value)
    return named, whole


def _model_field_sites(
    cls: ast.ClassDef, risky: frozenset[str], classes: dict[str, ast.ClassDef]
) -> Iterator[tuple[ast.AnnAssign, str, bool]]:
    named, whole = _model_validated_fields(cls)
    for stmt in cls.body:
        if not (isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)):
            continue
        field_name = stmt.target.id
        if not _is_risky(field_name, risky):
            continue
        ok = (
            whole
            or field_name in named
            or _annotation_is_constrained(stmt.annotation, classes)
            or (
                isinstance(stmt.value, ast.Call)
                and _last(call_name(stmt.value)) in _CONSTRAINT_CALLS
                and _has_constraint(stmt.value)
            )
        )
        yield stmt, field_name, ok


# -- the rule ----------------------------------------------------------------


def _params(fn: FunctionNode) -> list[ast.arg]:
    from checkride.approval import is_framework_param

    return [
        a for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)
        if not is_framework_param(a)
    ]


def _is_dict_annotation(annotation: ast.expr | None) -> bool:
    if isinstance(annotation, ast.Subscript):
        annotation = annotation.value
    if not isinstance(annotation, (ast.Name, ast.Attribute)):
        return False
    return _last(dotted_name(annotation)) in ("dict", "Dict", "Mapping")


def _argument_reads(
    fn: FunctionNode, risky: frozenset[str], ctx: FileContext
) -> Iterator[tuple[str, int, int, str | None, ast.AST]]:
    """(key, line, col, local name or None, node) for risky keys read from an
    arguments dict parameter."""
    dict_params = {
        a.arg for a in _params(fn)
        if a.arg in _ARGUMENT_DICT_NAMES or _is_dict_annotation(a.annotation)
    }
    if not dict_params:
        return
    for node in ctx.scope_nodes(fn):
        if not isinstance(node, (ast.Subscript, ast.Call)):
            continue
        key: str | None = None
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id in dict_params
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            key = node.slice.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in dict_params
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            key = node.args[0].value
        if key is None or not _is_risky(key, risky):
            continue
        parent = ctx.parents.get(node)
        local = None
        if (
            isinstance(parent, ast.Assign)
            and len(parent.targets) == 1
            and isinstance(parent.targets[0], ast.Name)
        ):
            local = parent.targets[0].id
        yield key, node.lineno, node.col_offset, local, node


def _inside_validation(node: ast.AST, fn: FunctionNode, ctx: FileContext, tokens: frozenset[str]) -> bool:
    child, parent = node, ctx.parents.get(node)
    while parent is not None and parent is not fn:
        if isinstance(parent, (ast.If, ast.While, ast.Assert)) and child is parent.test:
            return True
        if isinstance(parent, ast.Call) and _is_validator_call(parent, ctx, tokens):
            return True
        child, parent = parent, ctx.parents.get(parent)
    return False


def _path_like_names(nodes: list[ast.AST], ctx: FileContext) -> set[str]:
    """Names bound to a filesystem location anywhere in the file:
    `NOTES = Path.home() / "notes"`, `root = os.path.join(BASE, "x")`."""
    found: set[str] = set()
    for _ in range(2):  # one more round for names built from path-like names
        for node in nodes:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and _builds_path(node.value, ctx, found)
            ):
                found.add(node.targets[0].id)
    return found


def _builds_path(expr: ast.AST, ctx: FileContext, path_like: set[str]) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Call):
            name = call_name(node, ctx.import_aliases)
            if name is not None and (name in _PATH_CALLS or name.endswith(("Path.home", "Path.cwd"))):
                return True
        elif isinstance(node, ast.Name) and node.id in path_like:
            return True
    return False


def _path_flow_names(fn: FunctionNode, ctx: FileContext, path_like: set[str]) -> set[str]:
    """Names used to build a file path in `fn`: arguments of a path call, or
    the right side of `<path-like> / name`."""
    names: set[str] = set()
    for node in ctx.scope_nodes(fn):
        if isinstance(node, ast.Call):
            name = call_name(node, ctx.import_aliases)
            if name is not None and name in _PATH_CALLS:
                for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                    names |= _names_in(arg)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            if _builds_path(node.left, ctx, path_like):
                names |= _names_in(node.right)
    return names


def _is_scalar(annotation: ast.expr | None) -> bool:
    return isinstance(annotation, ast.Name) and annotation.id in _SCALAR_ANNOTATIONS


def _flows_to_risk(
    name: str,
    first_use: dict[str, tuple[int, int]],
    path_flow: set[str],
    derived: dict[str, set[str]],
) -> bool:
    """True if a parameter reaches a sink or a path, directly or through one
    assignment (`target = NOTES / name` then `os.remove(target)`)."""
    if name in first_use or name in path_flow:
        return True
    return any(
        name in sources and (alias in first_use or alias in path_flow)
        for alias, sources in derived.items()
    )


def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    sites, passed, findings = 0, 0, []
    tokens = VALIDATION_TOKENS | ctx.config.validation_tokens
    risky = RISKY_PARAM_TOKENS | ctx.config.risky_param_tokens
    classes = _class_defs(ctx.all_nodes)
    seen_models: set[str] = set()
    path_like = _path_like_names(ctx.all_nodes, ctx) if ctx.tool_functions else set()

    def report(line: int, col: int, fn: FunctionNode, message: str) -> None:
        findings.append(
            Finding(
                rule=RULE_ID,
                file=ctx.path,
                line=line,
                column=col + 1,
                function=ctx.qualname(fn),
                message=message,
                fix="Validate before use: an allowlist or containment check "
                    "(`if not Path(path).resolve().is_relative_to(ROOT): raise`), "
                    "a constrained type (`Literal[...]`, `Field(pattern=...)`), "
                    "or a sanitizer (`shlex.quote(cmd)`)",
            )
        )

    for fn in ctx.functions:
        if fn not in ctx.tool_functions:
            continue
        evidence = _evidence(fn, ctx, tokens)
        first_use = _first_raw_use(fn, ctx, tokens)
        derived = _derived_names(fn, ctx)
        path_flow = _path_flow_names(fn, ctx, path_like)
        interpreted = _first_raw_use(fn, ctx, tokens, _INTERPRETING_LABELS)

        for arg in _params(fn):
            by_name = _is_risky(arg.arg, risky)
            model = classes.get(
                (_last(dotted_name(arg.annotation)) or "")
                if isinstance(arg.annotation, (ast.Name, ast.Attribute)) else ""
            )
            by_flow = (
                not by_name
                and not _is_scalar(arg.annotation)
                and model is None  # an input model's fields are judged one by one
                # an arguments dict's keys are judged one by one
                and arg.arg not in _ARGUMENT_DICT_NAMES
                and not _is_dict_annotation(arg.annotation)
                and _flows_to_risk(arg.arg, interpreted, path_flow, derived)
            )
            if by_name or by_flow:
                sites += 1
                if _annotation_is_constrained(arg.annotation, classes) or _is_validated(
                    arg.arg, evidence, first_use, derived
                ):
                    passed += 1
                elif by_name:
                    report(arg.lineno, arg.col_offset, fn,
                           f"risky parameter '{arg.arg}' of tool '{fn.name}' "
                           "is used without validation")
                else:
                    report(arg.lineno, arg.col_offset, fn,
                           f"parameter '{arg.arg}' of tool '{fn.name}' reaches a "
                           "file path or sensitive call without validation")
            model_name = (
                _last(dotted_name(arg.annotation))
                if isinstance(arg.annotation, (ast.Name, ast.Attribute)) else None
            )
            model = classes.get(model_name or "")
            if model is None or model.name in seen_models or _is_enum(model):
                continue
            seen_models.add(model.name)
            for stmt, field_name, ok in _model_field_sites(model, risky, classes):
                sites += 1
                if ok:
                    passed += 1
                else:
                    report(stmt.lineno, stmt.col_offset, fn,
                           f"field '{field_name}' of input model '{model.name}' "
                           f"(taken by tool '{fn.name}') has no validation")

        for key, line, col, local, node in _argument_reads(fn, risky, ctx):
            sites += 1
            ok = (
                _is_validated(local, evidence, first_use, derived) if local is not None
                else _inside_validation(node, fn, ctx, tokens)
            )
            if ok:
                passed += 1
            else:
                report(line, col, fn,
                       f"risky argument '{key}' of tool '{fn.name}' is used "
                       "without validation")
    return sites, passed, findings
