"""Tool entry points and reachability (callgraph.py), single-file and
across files through the scanner."""

import pytest

from checkride.astutils import FileContext
from checkride.config import Config, RuleConfig
from checkride.scanner import scan


def tools(src: str, config: RuleConfig | None = None) -> set[str]:
    ctx = FileContext.from_source(src, path="mem.py", config=config)
    return {ctx.qualname(fn) or fn.name for fn in ctx.tool_functions}


# --- entry-point recognition ---------------------------------------------

@pytest.mark.parametrize("src", [
    "@mcp.tool()\ndef t():\n    return 1\n",
    "@mcp.tool\ndef t():\n    return 1\n",
    "@tool\ndef t():\n    return 1\n",
    "@tool('name')\ndef t():\n    return 1\n",
    "@server.call_tool()\nasync def t(name, arguments):\n    return []\n",
    "@function_tool\ndef t():\n    return 1\n",
    "@agent.tool_plain\ndef t():\n    return 1\n",
    "@kernel_function(description='x')\ndef t():\n    return 1\n",
    "@assistant.register_for_llm(description='x')\ndef t():\n    return 1\n",
    "def t():\n    return 1\nmcp.add_tool(t)\n",
    "def t():\n    return 1\nx = Tool(name='t', func=t, description='d')\n",
    "def t():\n    return 1\nx = FunctionTool.from_defaults(fn=t)\n",
    "def t():\n    return 1\nx = StructuredTool.from_function(t)\n",
    "def t():\n    return 1\nregister_function(t, caller=a, executor=b)\n",
    "def t():\n    return 1\nagent = Agent(tools=[t])\n",
    "def t():\n    return 1\nTOOLS = [t]\n",
    "def t():\n    return 1\ntool_map = {'t': t}\n",
])
def test_entry_point_shapes_are_recognized(src):
    assert "t" in tools(src)


def test_class_based_tool_methods_are_entry_points():
    src = (
        "class ShellTool(BaseTool):\n"
        "    def _run(self, command):\n"
        "        return 1\n"
        "    def helper(self):\n"
        "        return 2\n"
    )
    assert tools(src) == {"ShellTool._run"}


def test_abstract_stubs_and_properties_are_not_entry_points():
    src = (
        "class Base(BaseTool):\n"
        "    @abstractmethod\n"
        "    def _run(self, q): ...\n"
        "    def call(self, q):\n"
        "        raise NotImplementedError\n"
        "    @property\n"
        "    def invoke(self):\n"
        "        return self._x\n"
    )
    assert tools(src) == set()


def test_plain_functions_are_not_entry_points():
    assert tools("def helper(p):\n    return p\n") == set()


def test_extra_tool_decorators_from_config():
    src = "@expose\ndef t():\n    return 1\n"
    assert tools(src) == set()
    assert tools(src, RuleConfig(tool_decorators=frozenset({"expose"}))) == {"t"}


def test_extra_tool_entry_points_from_config():
    src = "def handle(p):\n    return p\n"
    assert tools(src, RuleConfig(entry_points=("handle",))) == {"handle"}


def test_scope_all_makes_every_sink_function_a_tool():
    src = "import os\ndef f(p):\n    os.remove(p)\ndef g():\n    return 1\n"
    assert tools(src) == set()
    assert tools(src, RuleConfig(scope="all")) == {"f"}


# --- reachability ----------------------------------------------------------

def ctx_of(src: str) -> FileContext:
    return FileContext.from_source(src, path="mem.py")


def test_helpers_called_by_a_tool_are_in_scope():
    ctx = ctx_of(
        "import os\n"
        "def _rm(p):\n    os.remove(p)\n"
        "def _unused(p):\n    os.remove(p)\n"
        "@mcp.tool()\ndef t(p):\n    _rm(p)\n"
    )
    by_name = {fn.name: fn for fn in ctx.functions}
    assert ctx.in_scope(by_name["_rm"])
    assert not ctx.in_scope(by_name["_unused"])
    assert ctx.out_of_scope_sensitive_calls == 1


def test_methods_reached_through_self_are_in_scope():
    ctx = ctx_of(
        "class S:\n"
        "    def _rm(self, p):\n        os.remove(p)\n"
        "    @tool\n"
        "    def t(self, p):\n        self._rm(p)\n"
    )
    assert all(ctx.in_scope(fn) for fn in ctx.functions)


def test_callbacks_handed_to_another_call_are_in_scope():
    ctx = ctx_of(
        "def _rm(p):\n    os.remove(p)\n"
        "@tool\nasync def t(p):\n    await asyncio.to_thread(_rm, p)\n"
    )
    assert all(ctx.in_scope(fn) for fn in ctx.functions)


def test_module_level_code_is_out_of_scope():
    ctx = ctx_of("import os\nos.system('x')\n@tool\ndef t():\n    return 1\n")
    assert not ctx.in_scope(None)
    assert ctx.out_of_scope_sensitive_calls == 1


def test_gating_at_every_call_site_covers_the_helper():
    src = (
        "import shutil\n"
        "def _rm(p):\n    shutil.rmtree(p)\n"
        "@tool\ndef a(p):\n    if not request_approval(p):\n        return\n    _rm(p)\n"
        "@tool\ndef b(p):\n    if not request_approval(p):\n        return\n    _rm(p)\n"
    )
    ctx = ctx_of(src)
    helper = next(fn for fn in ctx.functions if fn.name == "_rm")
    assert ctx.is_gated(helper)


def test_one_ungated_call_site_leaves_the_helper_ungated():
    src = (
        "import shutil\n"
        "def _rm(p):\n    shutil.rmtree(p)\n"
        "@tool\ndef a(p):\n    if not request_approval(p):\n        return\n    _rm(p)\n"
        "@tool\ndef b(p):\n    _rm(p)\n"
    )
    ctx = ctx_of(src)
    helper = next(fn for fn in ctx.functions if fn.name == "_rm")
    assert not ctx.is_gated(helper)


def test_call_site_gated_only_by_a_tool_argument_does_not_gate_the_helper():
    src = (
        "import shutil\n"
        "def _rm(p):\n    shutil.rmtree(p)\n"
        "@tool\ndef a(p, confirm):\n    if not confirm:\n        return\n    _rm(p)\n"
    )
    ctx = ctx_of(src)
    helper = next(fn for fn in ctx.functions if fn.name == "_rm")
    assert not ctx.is_gated(helper)


def test_recursion_is_never_gated_by_assumption():
    src = (
        "import shutil\n"
        "def _a(p):\n    _b(p)\n    shutil.rmtree(p)\n"
        "def _b(p):\n    _a(p)\n"
        "@tool\ndef t(p):\n    _a(p)\n"
    )
    ctx = ctx_of(src)
    assert not any(ctx.is_gated(fn) for fn in ctx.functions)


def test_error_handling_at_every_call_site_protects_the_helper():
    ctx = ctx_of(
        "import shutil\n"
        "def _rm(p):\n    shutil.rmtree(p)\n"
        "@tool\ndef t(p):\n    try:\n        _rm(p)\n    except OSError:\n        return False\n"
    )
    helper = next(fn for fn in ctx.functions if fn.name == "_rm")
    assert ctx.is_protected(helper)


def test_logging_in_a_called_helper_counts_for_the_tool():
    ctx = ctx_of(
        "def _record(x):\n    logger.info('did %s', x)\n"
        "@tool\ndef t(x):\n    _record(x)\n"
    )
    tool = next(fn for fn in ctx.functions if fn.name == "t")
    assert ctx.logs_via_calls(tool)


# --- across files -----------------------------------------------------------

def test_reachability_crosses_files_through_imports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "fs.py").write_text(
        "import shutil\ndef remove_tree(p):\n    shutil.rmtree(p)\n"
        "def unused(p):\n    shutil.rmtree(p)\n"
    )
    (pkg / "server.py").write_text(
        "from pkg.fs import remove_tree\n@mcp.tool()\ndef wipe(path):\n    remove_tree(path)\n"
    )
    report = scan(tmp_path)

    oversight = [f for f in report.findings if f.rule == "human-oversight"]
    assert [(f.file, f.function) for f in oversight] == [("pkg/fs.py", "remove_tree")]
    assert report.out_of_scope_sensitive_calls == 1
    assert report.verdict == "FAIL_CRITICAL"


def test_relative_imports_resolve(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "fs.py").write_text("import os\ndef rm(p):\n    os.remove(p)\n")
    (pkg / "server.py").write_text(
        "from . import fs\nfrom .fs import rm\n"
        "@tool\ndef a(p):\n    fs.rm(p)\n"
        "@tool\ndef b(p):\n    rm(p)\n"
    )
    report = scan(tmp_path)
    assert report.out_of_scope_sensitive_calls == 0
    assert any(f.file == "pkg/fs.py" and f.critical for f in report.findings)


def test_tools_registered_from_another_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tools.py").write_text("import os\ndef nuke(p):\n    os.system(p)\n")
    (tmp_path / "agent.py").write_text(
        "from tools import nuke\nagent = Agent(tools=[nuke])\n"
    )
    report = scan(tmp_path)
    assert [t.name for t in report.tool_functions] == ["nuke"]
    assert report.verdict == "FAIL_CRITICAL"


def test_gating_in_another_file_covers_the_helper(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "fs.py").write_text(
        "import shutil\ndef remove_tree(p):\n    try:\n        shutil.rmtree(p)\n"
        "    except OSError:\n        raise\n"
    )
    (tmp_path / "server.py").write_text(
        "import fs\n@mcp.tool()\ndef wipe(path):\n"
        "    if not request_approval(path):\n        return\n    fs.remove_tree(path)\n"
    )
    report = scan(tmp_path, Config(min_score=0))
    assert report.out_of_scope_sensitive_calls == 0  # the helper was reached
    assert not any(f.rule == "human-oversight" for f in report.findings)


def test_plain_module_import_resolves_and_the_call_site_is_not_a_second_sink(tmp_path, monkeypatch):
    # `ops.remove_file(path)` matches the suffix table by name, but it
    # resolves to scanned code: the real sink is os.remove inside it, and
    # that is the one place the risk is reported.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ops.py").write_text("import os\ndef remove_file(p):\n    os.remove(p)\n")
    (tmp_path / "server.py").write_text(
        "import ops\n@mcp.tool()\ndef clear(path):\n    ops.remove_file(path)\n"
    )
    report = scan(tmp_path, Config(min_score=0))
    oversight = [(f.file, f.line) for f in report.findings if f.rule == "human-oversight"]
    assert oversight == [("ops.py", 3)]


def test_unresolved_suffix_sink_is_still_a_sink(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "server.py").write_text(
        "@mcp.tool()\ndef clear(file_id):\n    storage_client.delete_file(file_id)\n"
    )
    report = scan(tmp_path, Config(min_score=0))
    assert any(f.rule == "human-oversight" and f.critical for f in report.findings)


def test_definitions_under_if_and_try_blocks_are_seen():
    src = (
        "import os\n"
        "try:\n"
        "    @tool\n"
        "    def a(p):\n"
        "        os.remove(p)\n"
        "except ImportError:\n"
        "    pass\n"
        "class K:\n"
        "    if True:\n"
        "        @tool\n"
        "        def b(self, p):\n"
        "            os.remove(p)\n"
    )
    assert tools(src) == {"a", "K.b"}


# --- approval decorators defined in the scanned code ----------------------

POLICY = (
    "import functools, shutil\n"
    "def policy_checked(func):\n"
    "    @functools.wraps(func)\n"
    "    def wrapper(*args, **kwargs):\n"
    "        if not request_approval(func.__name__, args):\n"
    "            raise PermissionError('denied')\n"
    "        return func(*args, **kwargs)\n"
    "    return wrapper\n"
)


def test_a_decorator_whose_wrapper_asks_first_gates_the_tool():
    ctx = ctx_of(POLICY + "@mcp.tool()\n@policy_checked\ndef wipe(p):\n    shutil.rmtree(p)\n")
    tool = next(fn for fn in ctx.functions if fn.name == "wipe")
    assert ctx.is_gated(tool)


def test_a_decorator_factory_whose_wrapper_asks_first_gates_the_tool():
    src = (
        "import shutil\n"
        "def policy(reason):\n"
        "    def deco(func):\n"
        "        def wrapper(*a):\n"
        "            if not confirm_with_operator(reason):\n"
        "                return None\n"
        "            return func(*a)\n"
        "        return wrapper\n"
        "    return deco\n"
        "@mcp.tool()\n@policy('wipe')\ndef wipe(p):\n    shutil.rmtree(p)\n"
    )
    ctx = ctx_of(src)
    tool = next(fn for fn in ctx.functions if fn.name == "wipe")
    assert ctx.is_gated(tool)


@pytest.mark.parametrize("body", [
    # calls the function first, asks afterwards
    "        result = func(*args)\n        request_approval('x')\n        return result\n",
    # never asks
    "        log(args)\n        return func(*args)\n",
    # asks, but on the refused side
    "        if request_approval('x'):\n            return None\n        return func(*args)\n",
])
def test_a_decorator_that_does_not_ask_first_does_not_gate(body):
    src = (
        "import shutil\n"
        "def wrap(func):\n"
        "    def wrapper(*args):\n" + body +
        "    return wrapper\n"
        "@mcp.tool()\n@wrap\ndef wipe(p):\n    shutil.rmtree(p)\n"
    )
    ctx = ctx_of(src)
    tool = next(fn for fn in ctx.functions if fn.name == "wipe")
    assert not ctx.is_gated(tool)


def test_an_approval_decorator_in_another_file_gates_the_tool(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "policy.py").write_text(POLICY)
    (tmp_path / "server.py").write_text(
        "import shutil\nfrom policy import policy_checked\n"
        "@mcp.tool()\n@policy_checked\ndef wipe(path):\n"
        "    try:\n        shutil.rmtree(path)\n    except OSError:\n        raise\n"
    )
    report = scan(tmp_path, Config(min_score=0))
    assert not any(f.rule == "human-oversight" for f in report.findings)

