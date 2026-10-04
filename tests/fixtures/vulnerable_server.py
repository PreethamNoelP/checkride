"""Deliberately vulnerable MCP server fixture.

Never imported or executed -- only parsed by the scanner. Every one of the
six checkride categories must produce at least one finding here, the file
must score exactly 0.0, and every shape below is one that some version of
checkride (or an obvious implementation of it) scored as clean.
"""

import asyncio
import math
import os
import pickle
import shutil
import sqlite3
import subprocess
from pathlib import Path
from subprocess import run  # plain from-import: the bare name "run"

import humanize
import requests

auto_approve = True
SETTINGS = {"skip_confirmation": True}
STRIPE_API = "https://api.stripe.com/v1"

rm = shutil.rmtree  # a sink rebound to another name


@mcp.tool()
def delete_path(path):
    """No approval, no logging, no rate limit, no try, no validation."""
    shutil.rmtree(path)


@mcp.tool()
def run_command(cmd):
    """Nothing between the model and your shell."""
    return subprocess.run(cmd, shell=True)


@mcp.tool()
def run_via_from_import(cmd):
    """The bare name `run` is not in the suffix table; only alias
    resolution catches this."""
    return run(cmd, shell=True)


@mcp.tool()
def wipe_via_rebinding(path):
    """`rm` resolves to shutil.rmtree only through assignment aliasing."""
    rm(path)


@mcp.tool()
def unlink_file(path):
    """pathlib deletion through a dynamic receiver."""
    Path(path).unlink()


@mcp.tool()
async def shell_async(cmd):
    """The asyncio equivalent of subprocess."""
    return await asyncio.create_subprocess_shell(cmd)


@mcp.tool()
def load_state(path):
    """Deserialization as code execution."""
    return pickle.loads(open(path, "rb").read())


@mcp.tool()
def evaluate(expression):
    """Arbitrary code execution as a service."""
    return eval(expression)


@mcp.tool()
def approve_after_the_fact(path):
    """The approval check runs after the deletion it is meant to gate."""
    shutil.rmtree(path)
    if not request_approval("delete", path):
        return False


@mcp.tool()
def model_confirms_itself(path, confirm: bool = False):
    """`confirm` is a tool argument: the model sets it."""
    if not confirm:
        return "call again with confirm=True"
    shutil.rmtree(path)


@mcp.tool()
def authz_is_not_approval(path):
    """A permission check on the caller is not a human approving this call."""
    if not user.is_authorized("delete"):
        raise PermissionError("denied")
    shutil.rmtree(path)


@mcp.tool()
def hardcoded_approval(path):
    """An enforcing position over a constant enforces nothing."""
    approved = True
    if approved:
        shutil.rmtree(path)


@mcp.tool()
def humanize_is_not_a_human(path):
    """'human' inside a library name is not a human in the loop."""
    print(humanize.naturalsize(os.path.getsize(path)))
    shutil.rmtree(path)


@mcp.tool()
def check_output_validates_nothing(cmd):
    """'check' in a sink's own name is not input validation."""
    return subprocess.check_output(cmd, shell=True)


@mcp.tool()
def math_log_is_not_audit(path):
    """math.log is not an audit trail; a truthiness test is not validation."""
    math.log(len(path))
    if path:
        os.remove(path)


@mcp.tool()
def swallowed_failure(path):
    """A broad handler that discards the error hides a failed deletion."""
    try:
        os.remove(path)
    except Exception:
        pass


@mcp.tool()
def run_query(sql):
    """Model-written SQL, executed as-is."""
    conn = sqlite3.connect("app.db")
    return conn.execute(sql).fetchall()


@mcp.tool()
def refund_via_http(charge_id):
    """Money moves through a plain HTTP call to the payment API."""
    return requests.post(f"{STRIPE_API}/refunds", data={"charge": charge_id})


@mcp.tool()
def dynamic_lookup(cmd):
    """getattr with a constant name is os.system with extra steps."""
    return getattr(os, "system")(cmd)


def _remove_tree(path):
    """The sink lives in a helper; its only caller does not gate it."""
    shutil.rmtree(path)


@mcp.tool()
def delete_via_helper(path):
    """Reachability crosses the call: the helper's sink is this tool's."""
    _remove_tree(path)


class FileRequest(BaseModel):
    path: str


@mcp.tool()
def delete_requested(request: FileRequest):
    """The risky input arrives as a field of an input model."""
    shutil.rmtree(request.path)


@server.call_tool()
async def handle_call(name, arguments):
    """Low-level MCP SDK dispatch: inputs arrive in an arguments dict."""
    if name == "delete":
        shutil.rmtree(arguments["path"])


class ShellTool(BaseTool):
    """A LangChain-style class-based tool."""

    def _run(self, command):
        return os.system(command)


def clean_directory(directory):
    """Registered by reference rather than by decorator."""
    return subprocess.run(["rm", "-rf", directory])


agent = Agent(tools=[clean_directory])


@mcp.tool()
def read_note(name):
    """Not called `path`, but it builds one: path traversal by another name."""
    return open(os.path.join("/srv/notes", name)).read()


@mcp.tool()
def watch_forever(queue_name):
    """An agent-reachable loop that can never end."""
    while True:
        process_next(queue_name)


def helper_that_mentions_approval():
    """Bait: approval vocabulary in an unrelated function covers nothing."""
    if request_approval("anything"):
        return True
    return False


# Not reachable from any tool: reported as out of scope, never judged.
subprocess.check_call(["setup.sh"])
