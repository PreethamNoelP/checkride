import dataclasses

import pytest

from checkride.astutils import FileContext
from checkride.config import RuleConfig
from checkride.rules import validation


def run(src: str, config: RuleConfig | None = None, scope: str = "all"):
    """Rule mechanics are tested in scope "all" (every function with a sink
    is a tool), so a snippet needs no tool decorator to be judged. Tool-
    scope behavior has its own tests below and in test_callgraph.py."""
    config = dataclasses.replace(config or RuleConfig(), scope=scope)
    return validation.check(FileContext.from_source(src, path="mem.py", config=config))


def test_raw_risky_param_fails():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def read(path):\n"
        "    return open(path).read()\n"
    )
    assert (sites, passed) == (1, 0)
    assert "'path'" in findings[0].message


def test_prefix_check_passes():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def read(path):\n"
        "    if not path.startswith('/data/'):\n"
        "        raise ValueError('outside sandbox')\n"
        "    return open(path).read()\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_sanitizer_call_passes():
    sites, passed, _ = run(
        "@mcp.tool()\n"
        "def sh(cmd):\n"
        "    safe = shlex.quote(cmd)\n"
        "    return subprocess.run(safe, shell=False)\n"
    )
    assert (sites, passed) == (1, 1)


def test_each_risky_param_is_its_own_site():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def go(url, query):\n"
        "    validate_url(url)\n"
        "    return http.get(url, query)\n"
    )
    assert (sites, passed) == (2, 1)  # url validated, query not
    assert "'query'" in findings[0].message


def test_safe_param_names_are_not_sites():
    sites, passed, findings = run(
        "@mcp.tool()\n"
        "def add(a, b):\n"
        "    return a + b\n"
    )
    assert (sites, passed, findings) == (0, 0, [])


def test_non_tool_function_is_ignored():
    # No tool decorator, no sensitive call -> rule doesn't apply.
    sites, passed, findings = run(
        "def helper(path):\n"
        "    return path.upper()\n"
    )
    assert (sites, passed, findings) == (0, 0, [])


def test_literal_annotation_counts_as_validation():
    # A closed set of allowed values is validation by construction -- the
    # documented "highest-value v2 improvement" from RULES.md.
    sites, passed, findings = run(
        "from typing import Literal\n"
        "@mcp.tool()\n"
        "def read(path: Literal['a', 'b']):\n"
        "    return open(path).read()\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_annotated_field_counts_as_validation():
    sites, passed, findings = run(
        "from typing import Annotated\n"
        "from pydantic import Field\n"
        "@mcp.tool()\n"
        "def query(query: Annotated[str, Field(pattern=r'^SELECT')]):\n"
        "    return db.execute(query)\n"
    )
    assert (sites, passed, findings) == (1, 1, [])


def test_annotated_without_field_does_not_count_as_validation():
    # Annotated[T, ...] alone carries no declared constraint -- only a
    # Field(...) call in the metadata is evidence.
    sites, passed, _findings = run(
        "from typing import Annotated\n"
        "@mcp.tool()\n"
        "def query(query: Annotated[str, 'some docstring metadata']):\n"
        "    return db.execute(query)\n"
    )
    assert (sites, passed) == (1, 0)


def test_plain_str_annotation_does_not_count_as_validation():
    sites, passed, _findings = run(
        "@mcp.tool()\n"
        "def read(path: str):\n"
        "    return open(path).read()\n"
    )
    assert (sites, passed) == (1, 0)


def test_extra_risky_param_from_config_is_a_site():
    config = RuleConfig(risky_param_tokens=frozenset({"apikey"}))
    sites, passed, _findings = run(
        "@mcp.tool()\ndef configure(apikey):\n    store(apikey)\n",
        config=config,
    )
    assert (sites, passed) == (1, 0)


def test_extra_validation_token_from_config_passes():
    config = RuleConfig(validation_tokens=frozenset({"scrub"}))
    sites, passed, _ = run(
        "@mcp.tool()\ndef read(path):\n    scrub(path)\n    return open(path).read()\n",
        config=config,
    )
    assert (sites, passed) == (1, 1)


def test_aliased_validator_still_counts():
    sites, passed, findings = run(
        "from utils import sanitize as scrub\n"
        "import shutil\n"
        "def wipe(path):\n"
        "    shutil.rmtree(scrub(path))\n"
    )
    assert (sites, passed) == (1, 1)
    assert findings == []


# --- evidence must be real validation, before use --------------------------

def tool(body: str, params: str = "path") -> str:
    return "@mcp.tool()\n" f"def t({params}):\n" + "".join(
        f"    {line}\n" for line in body.splitlines()
    )


def test_truthiness_is_not_validation():
    sites, passed, _ = run(tool("if not path:\n    return\nos.remove(path)"))
    assert (sites, passed) == (1, 0)


def test_none_check_is_not_validation():
    sites, passed, _ = run(tool("if path is None:\n    return\nos.remove(path)"))
    assert (sites, passed) == (1, 0)


def test_isinstance_is_not_validation():
    sites, passed, _ = run(tool("assert isinstance(path, str)\nos.remove(path)"))
    assert (sites, passed) == (1, 0)


def test_membership_and_comparison_are_validation():
    assert run(tool("if path not in ALLOWED:\n    raise ValueError\nos.remove(path)"))[:2] == (1, 1)
    assert run(tool("if not Path(path).resolve().is_relative_to(ROOT):\n    raise ValueError\nos.remove(path)"))[:2] == (1, 1)


def test_a_sink_named_like_a_validator_validates_nothing():
    sites, passed, _ = run(tool("return subprocess.check_output(cmd, shell=True)", "cmd"))
    assert (sites, passed) == (1, 0)


def test_validation_after_the_sink_does_not_count():
    sites, passed, _ = run(tool("os.remove(path)\nvalidate_path(path)"))
    assert (sites, passed) == (1, 0)


def test_sanitizer_wrapping_the_sink_argument_counts():
    sites, passed, _ = run(tool("subprocess.run(shlex.quote(cmd), shell=True)", "cmd"))
    assert (sites, passed) == (1, 1)


def test_safe_and_ensure_helpers_count():
    assert run(tool("p = safe_join(ROOT, path)\nos.remove(p)"))[:2] == (1, 1)
    assert run(tool("ensure_within_root(path)\nos.remove(path)"))[:2] == (1, 1)


def test_camel_case_risky_parameters_are_seen():
    sites, _, findings = run(tool("os.remove(filePath)", "filePath"))
    assert sites == 1
    assert "filePath" in findings[0].message


def test_enum_annotation_counts_as_validation():
    src = "class Mode(Enum):\n    A = 'a'\n" + tool("os.remove(target)", "target: Mode")
    assert run(src)[:2] == (1, 1)


def test_annotated_field_without_a_constraint_does_not_count():
    sites, passed, _ = run(tool("os.remove(path)", "path: Annotated[str, Field(description='p')]"))
    assert (sites, passed) == (1, 0)


def test_annotated_validator_counts():
    assert run(tool("os.remove(path)", "path: Annotated[str, AfterValidator(check)]"))[:2] == (1, 1)


def test_framework_context_parameter_is_not_an_input():
    sites, _, _ = run(tool("return 1", "ctx: Context, run_context: RunContextWrapper, context=None"))
    assert sites == 0


# --- input models ------------------------------------------------------------

def test_unvalidated_model_field_is_a_site():
    src = "class Req(BaseModel):\n    path: str\n    note: str\n" + tool("os.remove(req.path)", "req: Req")
    sites, passed, findings = run(src)
    assert (sites, passed) == (1, 0)
    assert "input model 'Req'" in findings[0].message


@pytest.mark.parametrize("field", [
    "path: str = Field(pattern=r'^/data/')",
    "path: Annotated[str, Field(max_length=64)]",
    "path: Literal['a', 'b']",
])
def test_constrained_model_field_passes(field):
    src = f"class Req(BaseModel):\n    {field}\n" + tool("os.remove(req.path)", "req: Req")
    assert run(src)[:2] == (1, 1)


def test_field_validator_covers_its_field():
    src = (
        "class Req(BaseModel):\n    path: str\n    url: str\n"
        "    @field_validator('path')\n    def _p(cls, v):\n        return v\n"
    ) + tool("os.remove(req.path)", "req: Req")
    sites, passed, findings = run(src)
    assert (sites, passed) == (2, 1)
    assert "'url'" in findings[0].message


def test_model_validator_covers_every_field():
    src = (
        "class Req(BaseModel):\n    path: str\n    url: str\n"
        "    @model_validator(mode='after')\n    def _v(self):\n        return self\n"
    ) + tool("os.remove(req.path)", "req: Req")
    assert run(src)[:2] == (2, 2)


# --- low-level arguments dicts -------------------------------------------------

def test_risky_key_from_arguments_dict_is_a_site():
    src = "@server.call_tool()\nasync def h(name, arguments):\n    os.remove(arguments['path'])\n"
    sites, passed, findings = run(src)
    assert (sites, passed) == (1, 0)
    assert "argument 'path'" in findings[0].message


def test_validated_local_from_arguments_dict_passes():
    src = (
        "@server.call_tool()\nasync def h(name, arguments):\n"
        "    path = arguments.get('path')\n"
        "    if not path.startswith(ROOT):\n        raise ValueError\n"
        "    os.remove(path)\n"
    )
    assert run(src)[:2] == (1, 1)


def test_an_approval_check_is_not_input_validation():
    sites, passed, _ = run(tool(
        "if not request_approval('delete', path):\n    return\nos.remove(path)"
    ))
    assert (sites, passed) == (1, 0)


def test_validation_of_a_derived_value_counts():
    src = tool(
        "argv = shlex.split(command)\n"
        "if not argv or argv[0] not in ALLOWED:\n    raise ValueError\n"
        "subprocess.run(argv)",
        "command",
    )
    assert run(src)[:2] == (1, 1)


def test_derived_validation_does_not_cover_raw_use_of_the_input():
    src = tool(
        "argv = shlex.split(command)\n"
        "if argv[0] not in ALLOWED:\n    raise ValueError\n"
        "subprocess.run(command, shell=True)",
        "command",
    )
    assert run(src)[:2] == (1, 0)


# --- inputs found by where they flow, not by their name -------------------

def test_innocently_named_param_building_a_path_is_an_input():
    src = (
        "from pathlib import Path\n"
        "NOTES = Path.home() / 'notes'\n"
        "@mcp.tool()\n"
        "def read_note(name: str) -> str:\n"
        "    return (NOTES / name).read_text()\n"
    )
    sites, passed, findings = run(src, scope="tools")
    assert (sites, passed) == (1, 0)
    assert "reaches a file path" in findings[0].message


@pytest.mark.parametrize("use", [
    "open(name).read()",
    "os.path.join(ROOT, name)",
    "Path(ROOT, name).unlink()",
    "target = Path(ROOT) / name\n    os.remove(target)",
    "subprocess.run(['grep', pattern])",
])
def test_param_flowing_into_a_path_or_sink_is_an_input(use):
    param = "pattern" if "pattern" in use else "name"
    src = f"@mcp.tool()\ndef t({param}):\n    {use}\n"
    sites, passed, _ = run(src, scope="tools")
    assert (sites, passed) == (1, 0)


def test_flowing_param_validated_first_passes():
    src = (
        "@mcp.tool()\ndef t(name):\n"
        "    if '/' in name or name.startswith('.'):\n        raise ValueError\n"
        "    return open(os.path.join(ROOT, name)).read()\n"
    )
    assert run(src, scope="tools")[:2] == (1, 1)


def test_numeric_params_and_unrelated_params_are_not_inputs():
    src = (
        "@mcp.tool()\ndef t(seconds: int, title):\n"
        "    subprocess.run(['sleep', str(seconds)])\n"
        "    return title.upper()\n"
    )
    assert run(src, scope="tools")[0] == 0

