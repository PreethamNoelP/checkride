"""Hard cases. Every tool here validates its obvious input and handles its
errors; each remaining issue is labelled with what a reviewer would say,
including the ones checkride still gets wrong. Choosing which function to
run (`action`, `which`) is itself an unvalidated input: the model can pick
os.system."""
# expect-verdict: FAIL_CRITICAL

import logging
import os
import shutil
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("limits")
log = logging.getLogger(__name__)
ROOT = "/srv/data/"
ACTIONS = {"remove": shutil.rmtree, "shell": os.system}


@mcp.tool()
def wrong_polarity(path: str) -> str:
    if not path.startswith(ROOT):
        raise ValueError("outside root")
    if request_approval(f"delete {path}"):
        return "approved, then returns without acting"
    try:
        # Runs exactly when approval was refused: caught by polarity checks.
        shutil.rmtree(path)  # expect: human-oversight
    except OSError:
        raise
    return "done"


@mcp.tool()
def table_dispatch(action: str, path: str) -> str:  # expect: input-validation
    if not path.startswith(ROOT):
        raise ValueError("outside root")
    try:
        # A sink looked up in a dispatch table: caught through the table.
        ACTIONS[action](path)  # expect: human-oversight
    except OSError:
        raise
    return "done"


@mcp.tool()
def dynamic_attribute(cmd: str, which: str) -> str:  # expect: input-validation
    if cmd not in {"uptime", "df"}:
        raise ValueError("not allowed")
    try:
        getattr(os, which)(cmd)  # expect: human-oversight
    except OSError:
        raise
    return "done"


@mcp.tool()
@guarded_by_policy_service
def gated_by_middleware(path: str) -> str:
    if not path.startswith(ROOT):
        raise ValueError("outside root")
    try:
        # A decorator from an unscanned library asks a human; its name says
        # nothing and its code is not available to read.
        shutil.rmtree(path)  # known-fp: human-oversight
    except OSError:
        raise
    return "done"


def policy_checked(func):
    """A project decorator with no approval word in its name: its wrapper
    asks before calling the tool, and that is what checkride reads."""
    def wrapper(*args, **kwargs):
        if not request_approval(func.__name__, args):
            raise PermissionError("denied by policy")
        return func(*args, **kwargs)
    return wrapper


@mcp.tool()
@policy_checked
def gated_by_project_decorator(path: str) -> str:
    if not path.startswith(ROOT):
        raise ValueError("outside root")
    try:
        shutil.rmtree(path)
    except OSError:
        raise
    return "done"


@mcp.tool()
def unrecognized_validator(path: str) -> str:  # known-fp: input-validation
    target = normalize_under_root(path)  # raises outside ROOT; name not recognized
    if not request_approval(f"delete {target}"):
        return "declined"
    try:
        os.remove(target)
    except OSError:
        raise
    return "done"


def _git(*args: str) -> str:
    try:
        # Only reached from a read-only tool, with fixed arguments.
        return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout  # known-fp: human-oversight
    except subprocess.CalledProcessError:
        raise


@mcp.tool()
def git_log() -> str:
    log.info("log")
    return _git("log", "--oneline", "-5")
