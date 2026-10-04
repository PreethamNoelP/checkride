"""AST helpers shared by every checkride rule.

Everything here answers one of three questions about a parsed file:
  1. What is this call actually calling?   -> dotted_name / call_name
  2. Is that call a sensitive action?      -> sensitive_label / iter_sensitive_calls
  3. What surrounds this node in the tree? -> build_parent_map / enclosing_function
"""

import ast
import io
import re
import tokenize
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING

from checkride import suppression
from checkride.config import RuleConfig

if TYPE_CHECKING:
    from checkride.approval import ApprovalAnalyzer
    from checkride.callgraph import ProgramIndex

# Full dotted names that always mean a sensitive action. Matched exactly,
# so harmless lookalikes (platform.system, df.eval) are not flagged.
SENSITIVE_EXACT: dict[str, str] = {
    # file destruction
    "os.remove": "file delete",
    "os.unlink": "file delete",
    "os.rmdir": "file delete",
    "os.removedirs": "file delete",
    "os.truncate": "file delete",
    "shutil.rmtree": "file delete",
    # shell / process execution
    "os.system": "shell exec",
    "os.popen": "shell exec",
    "subprocess.run": "shell exec",
    "subprocess.call": "shell exec",
    "subprocess.check_call": "shell exec",
    "subprocess.check_output": "shell exec",
    "subprocess.Popen": "shell exec",
    "subprocess.getoutput": "shell exec",
    "subprocess.getstatusoutput": "shell exec",
    "os.execl": "shell exec",
    "os.execle": "shell exec",
    "os.execlp": "shell exec",
    "os.execv": "shell exec",
    "os.execve": "shell exec",
    "os.execvp": "shell exec",
    "os.execvpe": "shell exec",
    "os.posix_spawn": "shell exec",
    "os.posix_spawnp": "shell exec",
    "os.spawnl": "shell exec",
    "os.spawnv": "shell exec",
    "pty.spawn": "shell exec",
    # async process execution -- the asyncio equivalents of subprocess.*,
    # which an agent server written with async handlers is more likely to
    # use than the blocking API.
    "asyncio.create_subprocess_shell": "shell exec",
    "asyncio.create_subprocess_exec": "shell exec",
    # dynamic code execution
    "eval": "code exec",
    "exec": "code exec",
    # deserialization that is equivalent to code execution on untrusted
    # input -- the realistic shape being "agent output -> loads()". Only
    # APIs with no safe mode are listed: yaml.load is deliberately absent
    # (yaml.load(s, Loader=SafeLoader) is safe and far too common to flag),
    # while yaml.unsafe_load names its own risk.
    "pickle.load": "code exec",
    "pickle.loads": "code exec",
    "marshal.load": "code exec",
    "marshal.loads": "code exec",
    "dill.load": "code exec",
    "dill.loads": "code exec",
    "yaml.unsafe_load": "code exec",
    # state-changing HTTP
    "requests.delete": "remote delete",
    "httpx.delete": "remote delete",
}

# Bare method names distinctive enough to flag on ANY receiver
# (client.rmtree(...), gateway.charge(...)). Deliberately excludes generic
# names like "run", "call", "delete", "system" -- those would flag half of
# any normal repo.
SENSITIVE_SUFFIX: dict[str, str] = {
    "rmtree": "file delete",
    "unlink": "file delete",       # pathlib.Path.unlink -- the modern idiom
    "rmdir": "file delete",
    "removedirs": "file delete",
    "delete_file": "file delete",
    "remove_file": "file delete",
    "delete_directory": "file delete",
    "remove_directory": "file delete",
    "Popen": "shell exec",
    "check_output": "shell exec",
    "getoutput": "shell exec",
    "getstatusoutput": "shell exec",
    "create_subprocess_shell": "shell exec",
    "create_subprocess_exec": "shell exec",
    "unsafe_load": "code exec",
    # bulk/remote destruction: object stores, databases, cloud instances.
    # All distinctive multi-word names -- bare "delete"/"drop" stay out.
    "delete_object": "remote delete",
    "delete_objects": "remote delete",
    "delete_bucket": "remote delete",
    "delete_many": "remote delete",
    "delete_all": "remote delete",
    "destroy_all": "remote delete",
    "drop_table": "remote delete",
    "drop_database": "remote delete",
    "drop_collection": "remote delete",
    "truncate_table": "remote delete",
    "terminate_instances": "remote delete",
    "charge": "payment",
    "create_charge": "payment",
    "create_payment": "payment",
    "create_payment_intent": "payment",
    "send_payment": "payment",
    "send_money": "payment",
    "transfer_funds": "payment",
    "wire_transfer": "payment",
    "create_transfer": "payment",
    "capture_payment": "payment",
    "refund": "payment",
    "payout": "payment",
    "create_payout": "payment",
}

# Consequence categories severe enough that a single missed approval gate
# must fail CI outright -- no volume of compliant sites elsewhere should be
# able to average this away (score averaging otherwise dilutes one
# catastrophic site across many low-risk ones -- see "critical-site
# dilution" in RULES.md).
CRITICAL_LABELS = frozenset(
    {"file delete", "shell exec", "code exec", "payment", "remote delete",
     "sql exec"}
)

# Database-API methods that run a query string. Generic names, so they only
# count on a receiver that looks like a DB handle *and* with a query that is
# not a string constant: a fixed, parameterized query is not the risk; a
# query assembled from (or equal to) model input is.
SQL_METHODS = frozenset({"execute", "executemany", "executescript", "exec_driver_sql"})
SQL_RECEIVER_TOKENS = frozenset({
    "cursor", "cur", "conn", "connection", "con", "db", "database",
    "session", "engine", "sqlite", "sqlite3", "pg", "postgres", "mysql",
    "duckdb", "pool", "tx", "transaction",
})

# Payment-SDK resources (Stripe's stripe.Refund / client.refunds, and the
# same nouns in Braintree, Adyen, Square, PayPal SDKs) and the methods that
# move money on them: stripe.Refund.create(...), client.payment_intents
# .confirm(...), gateway.transaction.sale(...).
PAYMENT_RESOURCES = frozenset({
    "charge", "charges", "paymentintent", "paymentintents", "refund",
    "refunds", "transfer", "transfers", "payout", "payouts", "payment",
    "payments", "transaction", "transactions", "subscription",
    "subscriptions", "invoice", "invoices",
})
PAYMENT_METHODS = frozenset({
    "create", "capture", "confirm", "pay", "send", "sale", "submit",
    "create_and_confirm", "submit_for_settlement",
})

# Kubernetes client deletes: delete_namespaced_pod, delete_collection_
# namespaced_secret, delete_cluster_role, ...
REMOTE_DELETE_PREFIXES = ("delete_namespaced_", "delete_collection_", "delete_cluster_")

# HTTP methods that create or move money when aimed at a payment API.
HTTP_WRITE_METHODS = frozenset({"post", "put", "patch", "request", "fetch"})
PAYMENT_HOSTS = (
    "api.stripe.com", "api.paypal.com", "api-m.paypal.com",
    "api-m.sandbox.paypal.com", "connect.squareup.com",
    "api.braintreegateway.com", "checkout.adyen.com", "checkout-test.adyen.com",
    "api.razorpay.com", "api.checkout.com", "api.mollie.com",
    "api.paystack.co", "api.flutterwave.com", "api.wise.com",
    "api.coinbase.com",
)


def is_critical(label: str) -> bool:
    """True if a sensitive-call label names a critical-consequence sink."""
    return label in CRITICAL_LABELS


FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def build_parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Map every node to its parent. AST nodes have no .parent attribute,
    so upward questions ("am I inside a try?") need this built once per file."""
    return {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def dotted_name(node: ast.expr, aliases: dict[str, str] | None = None) -> str | None:
    """Unwind an Attribute chain: the AST for `os.path.join` becomes the
    string "os.path.join". Returns None for anything dynamic (subscripts,
    call results, lambdas) whose target a static scan cannot know.

    `aliases` (see build_import_aliases) resolves the chain's root through
    import aliasing: with {"sp": "subprocess"}, `sp.run` resolves to
    "subprocess.run" instead of the literal, alias-blind "sp.run"."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Call):
        # getattr(os, "system"), __import__("os"), importlib.import_module("os")
        # with constant arguments name a target exactly as statically as
        # os.system does; only the spelling differs.
        base_name = _static_call_target(node, aliases)
        if base_name is None:
            return None
        return base_name if not parts else f"{base_name}.{'.'.join(reversed(parts))}"
    if isinstance(node, ast.Name):
        base = node.id
        if aliases and base in aliases:
            resolved = aliases[base]
            return resolved if not parts else f"{resolved}.{'.'.join(reversed(parts))}"
        parts.append(base)
        return ".".join(reversed(parts))
    return None


def _const_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _static_call_target(
    call: ast.Call, aliases: dict[str, str] | None
) -> str | None:
    """The dotted name a constant-argument getattr/__import__ call evaluates
    to, or None for anything else."""
    func = call.func
    func_name = (
        func.id if isinstance(func, ast.Name)
        else dotted_name(func, aliases) if isinstance(func, ast.Attribute)
        else None
    )
    if func_name == "getattr" and len(call.args) >= 2:
        attr = _const_str(call.args[1])
        obj = dotted_name(call.args[0], aliases)
        if attr is not None and obj is not None:
            return f"{obj}.{attr}"
    if func_name in ("__import__", "importlib.import_module") and call.args:
        return _const_str(call.args[0])
    return None


def call_name(call: ast.Call, aliases: dict[str, str] | None = None) -> str | None:
    """Dotted name of what a Call node is calling, or None if dynamic."""
    return dotted_name(call.func, aliases)


def word_tokens(name: str) -> set[str]:
    """Lowercase word tokens of a name, splitting on dots, underscores and
    camelCase: 'FunctionTool.from_defaults' -> {function, tool, from, defaults}."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return {t for t in re.split(r"[._]", spaced.lower()) if t}


def _string_value(node: ast.expr, constants: dict[str, str]) -> str | None:
    """The text of a string-ish expression as far as it is statically known:
    literals, module string constants, and the literal parts of an f-string
    or `+` concatenation -- enough to see a host name."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.JoinedStr):
        pieces = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                pieces.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                pieces.append(_string_value(v.value, constants) or "")
        return "".join(pieces)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return (_string_value(node.left, constants) or "") + (
            _string_value(node.right, constants) or ""
        )
    return None


def _is_constant_query(node: ast.expr, constants: dict[str, str]) -> bool:
    """True if a query argument is a fixed string: a literal, a name bound
    only to string literals in this file, or `text("...")`/`sql.SQL("...")`
    wrapping one. f-strings, concatenation, .format() and %-formatting are
    the dynamic shapes that make a query injectable."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.Name):
        return node.id in constants
    if isinstance(node, ast.Call) and len(node.args) == 1:
        func = node.func
        wrapper = (
            func.id if isinstance(func, ast.Name)
            else func.attr if isinstance(func, ast.Attribute)
            else None
        )
        if wrapper in ("text", "SQL"):
            return _is_constant_query(node.args[0], constants)
    return False


def _receiver_tokens(func: ast.Attribute) -> set[str]:
    receiver = func.value
    while isinstance(receiver, ast.Call):
        receiver = receiver.func
    if not isinstance(receiver, (ast.Name, ast.Attribute)):
        return set()
    name = dotted_name(receiver)
    return word_tokens(name) if name else set()


def _contextual_label(call: ast.Call, constants: dict[str, str]) -> str | None:
    """Sinks a name alone cannot identify: dynamic SQL on a DB handle, and
    HTTP writes aimed at a payment API."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    if func.attr.startswith(REMOTE_DELETE_PREFIXES):
        return "remote delete"
    if func.attr in PAYMENT_METHODS:
        receiver = func.value
        while isinstance(receiver, ast.Call):
            receiver = receiver.func
        if isinstance(receiver, ast.Attribute):
            noun = receiver.attr.lower().replace("_", "")
            if noun in PAYMENT_RESOURCES:
                return "payment"
    if (
        func.attr in SQL_METHODS
        and call.args
        and _receiver_tokens(func) & SQL_RECEIVER_TOKENS
        and not _is_constant_query(call.args[0], constants)
    ):
        return "sql exec"
    if func.attr in HTTP_WRITE_METHODS:
        url_args = list(call.args[:2]) + [
            kw.value for kw in call.keywords if kw.arg in ("url", "endpoint")
        ]
        for arg in url_args:
            text = _string_value(arg, constants)
            if text and any(host in text for host in PAYMENT_HOSTS):
                return "payment"
    return None


# A computed attribute on one of these modules can be its most dangerous
# member: getattr(os, name)(cmd) may well be os.system.
DYNAMIC_MODULE_LABELS: dict[str, str] = {
    "os": "shell exec",
    "subprocess": "shell exec",
    "pty": "shell exec",
    "asyncio": "shell exec",
    "shutil": "file delete",
    "builtins": "code exec",
    "pickle": "code exec",
    "marshal": "code exec",
    "dill": "code exec",
}
_LABEL_RANK = ("code exec", "shell exec", "sql exec", "payment", "remote delete", "file delete")


def _name_label(name: str) -> str | None:
    return SENSITIVE_EXACT.get(name) or SENSITIVE_SUFFIX.get(name.rsplit(".", 1)[-1])


def build_sink_tables(
    nodes: Iterable[ast.AST], aliases: dict[str, str] | None = None
) -> dict[str, str]:
    """Names bound to a dict, list, tuple or set literal containing a
    sensitive function -- a dispatch table such as
    `ACTIONS = {"remove": shutil.rmtree, "run": os.system}` -- mapped to the
    most severe label among its members."""
    tables: dict[str, str] = {}
    for node in nodes:
        if not (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            continue
        value = node.value
        if isinstance(value, ast.Dict):
            members = [v for v in value.values if v is not None]
        elif isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            members = list(value.elts)
        else:
            continue
        labels = {
            label
            for member in members
            if isinstance(member, (ast.Name, ast.Attribute))
            and (resolved := dotted_name(member, aliases)) is not None
            and (label := _name_label(resolved)) is not None
        }
        if labels:
            tables[node.targets[0].id] = min(labels, key=_LABEL_RANK.index)
    return tables


def _dynamic_label(
    call: ast.Call, aliases: dict[str, str] | None, tables: dict[str, str]
) -> str | None:
    """Sinks reached without a static name: through a dispatch table
    (`ACTIONS[name](p)`, `ACTIONS.get(name)(p)`) or a computed attribute on a
    dangerous module (`getattr(os, name)(cmd)`)."""
    func = call.func
    if isinstance(func, ast.Subscript) and isinstance(func.value, ast.Name):
        return tables.get(func.value.id)
    if not isinstance(func, ast.Call):
        return None
    inner = func.func
    if (
        isinstance(inner, ast.Attribute)
        and inner.attr == "get"
        and isinstance(inner.value, ast.Name)
    ):
        return tables.get(inner.value.id)
    if isinstance(inner, ast.Name) and inner.id == "getattr" and len(func.args) >= 2:
        if isinstance(func.args[1], ast.Constant):
            return None  # resolved statically by dotted_name
        module = dotted_name(func.args[0], aliases)
        return DYNAMIC_MODULE_LABELS.get(module or "")
    return None


def sensitive_label(
    call: ast.Call,
    aliases: dict[str, str] | None = None,
    constants: dict[str, str] | None = None,
    tables: dict[str, str] | None = None,
) -> str | None:
    """Action label ("file delete", "shell exec", ...) if this call looks
    sensitive, else None. Exact table first, then the suffix table, then the
    contextual checks (dynamic SQL, payment HTTP) that read the arguments,
    then dispatch tables and computed attributes.

    `constants` maps names bound only to string literals to their value
    (see build_string_constants); `tables` maps dispatch-table names to a
    label (see build_sink_tables)."""
    name = call_name(call, aliases)
    label: str | None = None
    if name is not None:
        label = SENSITIVE_EXACT.get(name) or SENSITIVE_SUFFIX.get(
            name.rsplit(".", 1)[-1]
        )
    elif isinstance(call.func, ast.Attribute):
        # The receiver is dynamic (Path(p).unlink(), clients[key].charge()).
        # The suffix table is receiver-agnostic by construction, so it still
        # applies; the exact table requires a known module chain.
        label = SENSITIVE_SUFFIX.get(call.func.attr)
    if label is None:
        label = _contextual_label(call, constants or {})
    if label is None:
        label = _dynamic_label(call, aliases, tables or {})
    return label


def build_string_constants(
    tree: ast.AST, nodes: Iterable[ast.AST] | None = None
) -> dict[str, str]:
    """Names bound only to string literals anywhere in the file (`QUERY =
    "SELECT ..."`, `STRIPE_URL = "https://api.stripe.com/v1"`). A name that
    is ever bound to anything else is left out: its value is not known."""
    values: dict[str, str] = {}
    poisoned: set[str] = set()
    for node in nodes if nodes is not None else ast.walk(tree):
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        elif isinstance(node, (ast.AugAssign, ast.NamedExpr, ast.For, ast.AsyncFor, ast.comprehension)):
            targets = [node.target]
        elif isinstance(node, ast.arg):
            poisoned.add(node.arg)
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                values.setdefault(target.id, value.value)
            else:
                poisoned.add(target.id)
    return {k: v for k, v in values.items() if k not in poisoned}


def iter_sensitive_calls(
    tree: ast.AST,
    aliases: dict[str, str] | None = None,
    constants: dict[str, str] | None = None,
    tables: dict[str, str] | None = None,
) -> Iterator[tuple[ast.Call, str]]:
    """Yield (call_node, action_label) for every sensitive call in the tree."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            label = sensitive_label(node, aliases, constants, tables)
            if label is not None:
                yield node, label


def build_import_aliases(
    tree: ast.AST, nodes: Iterable[ast.AST] | None = None
) -> dict[str, str]:
    """Map every locally-bound import name to the dotted name it actually
    refers to, so a call written through an import binding resolves to its
    canonical target instead of vanishing behind the local spelling:

        import subprocess as sp   ->  {"sp": "subprocess"}
        from shutil import rmtree ->  {"rmtree": "shutil.rmtree"}
        from os import system as s ->  {"s": "os.system"}

    `from X import y` matters as much as the `as` form: `from subprocess
    import run; run(cmd, shell=True)` resolves to nothing but the bare name
    "run", which the suffix table deliberately excludes as too generic --
    so without this mapping that call was invisible entirely.

    A plain `import os.path` needs no entry: it binds "os", and dotted_name
    already walks the Attribute chain from there. Relative imports
    (`from . import x`) are skipped -- their target isn't a static dotted
    name we could resolve to.

    Rebinding an import to another name is also resolved, because
    `rm = shutil.rmtree; rm(path)` is both a normal refactor and the
    cheapest way to walk a sink past a name-based scan:

        run = subprocess.run     ->  {"run": "subprocess.run"}
        Path = pathlib.Path      ->  {"Path": "pathlib.Path"}

    Only assignments whose value is itself a static dotted name count; a
    call result (`logger = logging.getLogger(__name__)`) names nothing we
    could resolve, and a second layer of indirection is still missed.

    Scope-blind by design: this is one flat map per file, so a local
    variable that shadows an imported name still resolves to the import
    (documented in RULES.md).
    """
    aliases: dict[str, str] = {}
    # Assignments are set aside and resolved after every import is known
    # (the second loop). Walk order is stable, so a chain like
    # `_a = sh.rmtree` then `_b = _a` resolves in document order.
    assignments: list[ast.Assign] = []
    for node in nodes if nodes is not None else ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.level:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname if alias.asname is not None else alias.name
                aliases[local] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            assignments.append(node)
    # Second pass: imports are collected first so a rebinding can resolve
    # through them (`import subprocess as sp` then `run = sp.run`), and so
    # an import always wins over an assignment to the same name.
    for assign in assignments:
        target = assign.targets[0]
        if not isinstance(target, ast.Name) or target.id in aliases:
            continue
        resolved = dotted_name(assign.value, aliases)
        if resolved is not None and resolved != target.id:
            aliases[target.id] = resolved
    return aliases


def iter_scope(scope: ast.AST) -> Iterator[ast.AST]:
    """Yield `scope` and every descendant that executes in the *same* scope.

    Nested def/async def bodies are separate scopes and are not entered: a
    check written inside a helper function does not run when the code around
    that helper does. This is what makes "is there an approval check in
    scope?" answerable without confusing a call at module level with an
    unrelated function that happens to live in the same file.

    Class bodies *are* entered -- `class C: os.system(x)` executes at
    definition time in the surrounding scope, so its statements belong to it.
    Lambdas are entered too: a lambda body is an expression evaluated where
    it is written.
    """
    yield scope
    queue = deque(ast.iter_child_nodes(scope))
    while queue:
        node = queue.popleft()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        yield node
        queue.extend(ast.iter_child_nodes(node))


def enclosing_function(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> FunctionNode | None:
    """Climb the parent map to the nearest def/async def containing `node`."""
    current = parents.get(node)
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        current = parents.get(current)
    return None


"""Suppression marker introducer.

Deliberately documented in a docstring rather than in `#` comments: this
module is scanned by checkride like any other, and the tokenizer sees a
real comment containing the marker followed by prose as a malformed
directive -- correctly, since that is exactly the "brackets forgotten"
shape the strictness exists to catch. Writing the examples in a string
keeps the module's own self-scan clean. See RULES.md.

Only the introducer lives here; the grammar is checkride/suppression.py.
"""
_SUPPRESS_RE = suppression.marker_pattern(r"#")


def _parse_suppressions(
    source: str,
) -> tuple[dict[int, frozenset[str] | None], list[tuple[int, str]]]:
    """Scan comment tokens (not a text search -- a string literal that
    happens to contain the marker must not count) for suppression markers.

    Returns (suppressions, malformed):
      - suppressions maps line number -> None (suppress everything on that
        line) or a frozenset of rule ids (suppress only those).
      - malformed lists (line, reason) for markers that could not be parsed.
        A malformed marker suppresses *nothing*: a suppression is a security
        decision, and the safe reading of one we cannot understand is that
        no exemption was granted. The reason is surfaced as a scan warning so
        a typo does not just sit there silently failing to do its job.

    Best-effort: a source that parses with ast.parse but somehow fails to
    tokenize just gets no suppressions rather than aborting the scan.
    """
    suppressions: dict[int, frozenset[str] | None] = {}
    malformed: list[tuple[int, str]] = []
    if not suppression.contains_marker_word(source):
        return suppressions, malformed
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type != tokenize.COMMENT:
                continue
            marker = suppression.parse_marker(tok.string, _SUPPRESS_RE)
            if marker is None:
                continue
            if marker.malformed is not None:
                malformed.append((tok.start[0], marker.malformed))
            else:
                suppressions[tok.start[0]] = marker.rules
    except (tokenize.TokenError, SyntaxError, IndentationError):
        pass
    return suppressions, malformed


@dataclass
class FileContext:
    """Everything a rule needs to know about one parsed file. Rules all
    share one signature: check(ctx) -> (sites, passed, findings).

    Every view is cached and derived from one walk of the tree (all_nodes):
    the parent map, per-scope node buckets, the definition index, functions,
    calls and sensitive calls. Reachability comes from `program`, the
    scan-wide index, or from this file alone when there is none.
    """

    path: str
    tree: ast.AST
    import_aliases: dict[str, str] = field(default_factory=dict)
    config: RuleConfig = field(default_factory=RuleConfig)
    suppressions: dict[int, frozenset[str] | None] = field(default_factory=dict)
    # (line, reason) for suppression comments that could not be parsed; they
    # grant no exemption and are reported as warnings by the scoring pass.
    malformed_suppressions: list[tuple[int, str]] = field(default_factory=list)
    # Dotted module name, for resolving calls from other files.
    module: str = ""
    # Whole-scan reachability. None means "this file on its own".
    program: "ProgramIndex | None" = None
    _parent_map: dict[ast.AST, ast.AST] = field(default_factory=dict, repr=False)
    _scope_buckets: dict[int, list[ast.AST]] = field(default_factory=dict, repr=False)
    _direct_defs: dict[int, list[ast.stmt]] = field(default_factory=dict, repr=False)

    @classmethod
    def from_source(
        cls,
        source: str,
        path: str = "<memory>",
        config: RuleConfig | None = None,
        module: str = "",
        program: "ProgramIndex | None" = None,
    ) -> "FileContext":
        tree = ast.parse(source)
        suppressions, malformed = _parse_suppressions(source)
        ctx = cls(
            path=path,
            tree=tree,
            config=config if config is not None else RuleConfig(),
            suppressions=suppressions,
            malformed_suppressions=malformed,
            module=module,
            program=program,
        )
        ctx.import_aliases = build_import_aliases(tree, ctx.all_nodes)
        return ctx

    @cached_property
    def all_nodes(self) -> list[ast.AST]:
        """Every node in the file in ast.walk order, from a single walk that
        also builds the parent map. Rules filter this list instead of each
        walking the tree again -- a tree walk is the whole cost of a scan."""
        nodes: list[ast.AST] = []
        parents: dict[ast.AST, ast.AST] = {}
        buckets: dict[int, list[ast.AST]] = {}
        defs: dict[int, list[ast.stmt]] = {}
        definers = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        # (node, enclosing function scope, nearest enclosing def-or-class)
        queue: deque[tuple[ast.AST, ast.AST, ast.AST]] = deque(
            [(self.tree, self.tree, self.tree)]
        )
        while queue:
            node, scope, container = queue.popleft()
            nodes.append(node)
            buckets.setdefault(id(scope), []).append(node)
            for child in ast.iter_child_nodes(node):
                parents[child] = node
                child_scope = (
                    child if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    else scope
                )
                if isinstance(child, definers):
                    defs.setdefault(id(container), []).append(child)
                    child_container: ast.AST = child
                else:
                    child_container = container
                queue.append((child, child_scope, child_container))
        self._parent_map = parents
        self._scope_buckets = buckets
        self._direct_defs = defs
        return nodes

    def direct_defs(self, container: ast.AST) -> list[ast.stmt]:
        """Functions and classes defined directly inside `container` (the
        module, a class or a function), however deeply nested in if/try/with
        blocks, without descending into other definitions. Source order."""
        self.all_nodes  # noqa: B018 -- builds the index as a side effect
        found = self._direct_defs.get(id(container), [])
        return sorted(found, key=lambda n: (n.lineno, n.col_offset))

    def scope_nodes(self, scope: ast.AST) -> list[ast.AST]:
        """The same nodes iter_scope(scope) yields, precomputed: `scope`
        itself and everything executing in it, nested defs excluded."""
        self.all_nodes  # noqa: B018 -- builds the buckets as a side effect
        return self._scope_buckets.get(id(scope), [scope])

    @cached_property
    def parents(self) -> dict[ast.AST, ast.AST]:
        """Node -> parent (AST nodes carry no parent pointer)."""
        self.all_nodes  # noqa: B018 -- builds the parent map as a side effect
        return self._parent_map

    @cached_property
    def _defs_and_calls(self) -> tuple[list["FunctionNode"], list[ast.Call]]:
        """Every def/async def and every Call in the file, in walk order."""
        functions: list[FunctionNode] = []
        calls: list[ast.Call] = []
        for node in self.all_nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(node)
            elif isinstance(node, ast.Call):
                calls.append(node)
        return functions, calls

    @cached_property
    def functions(self) -> list["FunctionNode"]:
        """Every def/async def in the file, nested ones included."""
        return self._defs_and_calls[0]

    @cached_property
    def string_constants(self) -> dict[str, str]:
        """Names bound only to string literals (see build_string_constants)."""
        return build_string_constants(self.tree, self.all_nodes)

    @cached_property
    def candidate_sensitive_calls(self) -> list[tuple[ast.Call, str]]:
        """Every call whose name or arguments look sensitive, alias-resolved,
        before cross-file resolution (see sensitive_calls)."""
        aliases = self.import_aliases
        constants = self.string_constants
        tables = self.sink_tables
        return [
            (call, label)
            for call in self._defs_and_calls[1]
            if (label := sensitive_label(call, aliases, constants, tables)) is not None
        ]

    @cached_property
    def sink_tables(self) -> dict[str, str]:
        """Dispatch tables holding sensitive functions (see build_sink_tables)."""
        return build_sink_tables(self.all_nodes, self.import_aliases)

    @cached_property
    def sensitive_calls(self) -> list[tuple[ast.Call, str]]:
        """The sensitive calls the rules judge. A call that resolves to a
        function in the scanned code -- `ops.remove_file(path)` where ops.py
        defines remove_file -- is not itself a sink: the sinks inside that
        function are judged where they are, and reporting the call site as
        well would count the same risk twice."""
        resolved = self.index.resolved_sites
        if not resolved:
            return self.candidate_sensitive_calls
        return [
            (call, label) for call, label in self.candidate_sensitive_calls
            if (self.path, call.lineno, call.col_offset) not in resolved
        ]

    @cached_property
    def sensitive_calls_by_function(
        self,
    ) -> dict[int, list[tuple[ast.Call, str]]]:
        """sensitive_calls grouped by id() of the enclosing function, built
        in one pass. A rule that asks "which sinks are in this function" for
        every tool would otherwise rescan every sink in the file per tool --
        quadratic in file size, and a few thousand tiny tools under the size
        cap is enough to stall a scan for minutes."""
        grouped: dict[int, list[tuple[ast.Call, str]]] = {}
        for call, label in self.sensitive_calls:
            fn = enclosing_function(call, self.parents)
            if fn is not None:
                grouped.setdefault(id(fn), []).append((call, label))
        return grouped

    @cached_property
    def sensitive_call_ids(self) -> frozenset[int]:
        return frozenset(id(call) for call, _label in self.candidate_sensitive_calls)

    def is_sensitive(self, call: ast.Call) -> bool:
        return id(call) in self.sensitive_call_ids

    def enclosing_scope(self, node: ast.AST) -> ast.AST:
        """The function a node executes in, or the module tree."""
        fn = enclosing_function(node, self.parents)
        return fn if fn is not None else self.tree

    @cached_property
    def approval(self) -> "ApprovalAnalyzer":
        """Approval-dominance analysis for this file (see approval.py)."""
        from checkride.approval import ApprovalAnalyzer

        return ApprovalAnalyzer(
            self.tree,
            self.parents,
            self.import_aliases,
            self.config.approval_markers,
            self.is_sensitive,
            self.scope_nodes,
        )

    @cached_property
    def index(self) -> "ProgramIndex":
        """Reachability facts: the scan-wide index if one was supplied,
        otherwise one built from this file alone."""
        if self.program is not None:
            return self.program
        from checkride.callgraph import ProgramIndex, summarize

        module = self.module or self.path.rsplit("/", 1)[-1].removesuffix(".py")
        return ProgramIndex.build(
            [summarize(self, module)], self.config.scope, self.config.entry_points
        )

    def key(self, fn: "FunctionNode") -> tuple[str, int, int]:
        return (self.path, fn.lineno, fn.col_offset)

    def is_entry(self, fn: "FunctionNode") -> bool:
        """True if the model can call this function directly."""
        return self.key(fn) in self.index.entries

    def in_scope(self, fn: "FunctionNode | None") -> bool:
        """True if code in `fn` (None: module level) is judged at all. With
        scope = "tools" that is code reachable from a tool entry point."""
        if self.index.scope == "all":
            return True
        return fn is not None and self.key(fn) in self.index.reachable

    def is_gated(self, fn: "FunctionNode") -> bool:
        """True if every reachable call path into `fn` passes an approval
        check (or `fn` has an approval decorator)."""
        return self.key(fn) in self.index.gated

    def is_protected(self, fn: "FunctionNode") -> bool:
        """True if every reachable call into `fn` sits in a try body whose
        handler deals with the failure."""
        return self.key(fn) in self.index.protected

    def logs_via_calls(self, fn: "FunctionNode") -> bool:
        return self.key(fn) in self.index.logs_closure

    def rate_limited_via_calls(self, fn: "FunctionNode") -> bool:
        return self.key(fn) in self.index.rate_closure

    def qualname(self, fn: "FunctionNode | None") -> str | None:
        if fn is None:
            return None
        return self.index.qualnames.get(self.key(fn), fn.name)

    @cached_property
    def tool_functions(self) -> set["FunctionNode"]:
        """Tool entry points in this file: the functions held to
        tool-governance standards by rules 2, 3 and 5."""
        entries = self.index.entries
        return {fn for fn in self.functions if self.key(fn) in entries}

    @cached_property
    def out_of_scope_sensitive_calls(self) -> int:
        """Sensitive calls not reachable from any tool, so not judged."""
        return sum(
            1 for call, _label in self.sensitive_calls
            if not self.in_scope(enclosing_function(call, self.parents))
        )

    def is_suppressed(self, rule: str, line: int) -> bool:
        """True if an `# checkride: ignore` comment on this line covers
        this rule -- either unqualified (covers every rule) or naming it
        explicitly by RULE_ID."""
        if line not in self.suppressions:
            return False
        rules = self.suppressions[line]
        return rules is None or rule in rules


def iter_functions(tree: ast.AST) -> Iterator["FunctionNode"]:
    """Yield every def/async def in the tree, nested ones included."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def iter_identifiers(scope: ast.AST) -> Iterator[str]:
    """Yield every identifier-ish string in a subtree: variable names,
    attribute accesses, def/class names, parameters, keyword-arg names.
    Rules match governance vocabulary ("approv", "throttle") against these."""
    for node in ast.walk(scope):
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name
        elif isinstance(node, (ast.arg, ast.keyword)) and node.arg is not None:
            yield node.arg


def name_tokens(name: str) -> set[str]:
    """Split a (possibly dotted) name into lowercase word tokens:
    'audit_log' -> {'audit', 'log'}; 'logger.info' -> {'logger', 'info'}.
    Token matching avoids substring accidents like 'log' inside 'login'."""
    return {t for t in re.split(r"[._]", name.lower()) if t}
