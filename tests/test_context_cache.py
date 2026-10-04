"""The cached FileContext views must answer exactly what the uncached
primitives answer. They exist only so six rules asking the same question do
not walk the same subtrees again -- a performance change that silently
altered the site population would be far worse than a slow scan.
"""

import ast
from pathlib import Path

import pytest

from checkride.astutils import (
    FileContext,
    build_import_aliases,
    build_parent_map,
    build_string_constants,
    iter_functions,
    iter_scope,
    iter_sensitive_calls,
)

FIXTURES = Path(__file__).parent / "fixtures"

SHAPES = [
    "def plain():\n    return 1\n",
    "import shutil\ndef wipe(p):\n    shutil.rmtree(p)\n",
    "@mcp.tool()\ndef fetch(url):\n    return http.get(url)\n",
    "import os\ndef outer():\n    def inner(p):\n        os.remove(p)\n    return inner\n",
    "import os\ndef make():\n    class C:\n        def m(self, p):\n            os.remove(p)\n    return C\n",
    "import asyncio\nasync def run(c):\n    await asyncio.create_subprocess_shell(c)\n",
    "import os\nf = lambda p: os.remove(p)\n",
    "import os\nos.system('x')\n",
    "from subprocess import run\n@tool\ndef go(cmd):\n    run(cmd)\n",
    "@app.tool\ndef ping():\n    return 'pong'\n",
    "Q = 'SELECT 1'\n@tool\ndef q(sql):\n    cursor.execute(sql)\n    cursor.execute(Q)\n",
    "@d(lambda: os.remove(p))\ndef f():\n    @g\n    def h(x=os.system('y')):\n        pass\n",
]


def _sources():
    yield from SHAPES
    for fixture in ("clean_server.py", "vulnerable_server.py"):
        yield (FIXTURES / fixture).read_text()


@pytest.mark.parametrize("src", list(_sources()))
def test_cached_views_match_the_primitives(src):
    ctx = FileContext.from_source(src, path="mem.py")
    tree = ast.parse(src)
    assert [ast.dump(f) for f in ctx.functions] == [
        ast.dump(f) for f in iter_functions(tree)
    ]
    assert ctx.candidate_sensitive_calls == list(
        iter_sensitive_calls(
            ctx.tree, ctx.import_aliases, ctx.string_constants, ctx.sink_tables
        )
    )
    assert ctx.parents == build_parent_map(ctx.tree)
    assert ctx.import_aliases == build_import_aliases(tree)
    assert ctx.string_constants == build_string_constants(tree)


@pytest.mark.parametrize("src", list(_sources()))
def test_scope_buckets_match_iter_scope(src):
    ctx = FileContext.from_source(src, path="mem.py")
    for scope in [ctx.tree, *ctx.functions]:
        assert {id(n) for n in ctx.scope_nodes(scope)} == {
            id(n) for n in iter_scope(scope)
        }


def test_cached_views_are_computed_once():
    ctx = FileContext.from_source("import os\ndef f(p):\n    os.remove(p)\n")
    assert ctx.sensitive_calls is ctx.sensitive_calls
    assert ctx.parents is ctx.parents
    assert ctx.functions is ctx.functions
    assert ctx.index is ctx.index


@pytest.mark.parametrize("src", list(_sources()))
def test_direct_defs_match_a_bounded_walk(src):
    ctx = FileContext.from_source(src, path="mem.py")
    definers = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)

    def bounded(container):
        found, queue = [], list(ast.iter_child_nodes(container))
        while queue:
            node = queue.pop()
            if isinstance(node, definers):
                found.append(node)
                continue
            queue.extend(ast.iter_child_nodes(node))
        return {id(n) for n in found}

    containers = [ctx.tree] + [n for n in ctx.all_nodes if isinstance(n, definers)]
    for container in containers:
        assert {id(n) for n in ctx.direct_defs(container)} == bounded(container)

