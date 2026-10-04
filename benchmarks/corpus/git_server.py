"""Git server: read-only status, an approved push, and an ungated
`reset --hard`."""
# expect-verdict: FAIL_CRITICAL

import logging
import re
import subprocess

from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("git")
log = logging.getLogger(__name__)


@mcp.tool()
def git_status() -> str:
    log.info("status")
    try:
        # A fixed, read-only command needs no human; checkride treats every
        # subprocess call as shell execution.
        return subprocess.run(  # known-fp: human-oversight
            ["git", "status", "--short"], capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError as exc:
        log.error("status failed: %s", exc)
        return ""


@mcp.tool()
async def git_push(branch: str, ctx: Context) -> str:
    if not re.fullmatch(r"[\w./-]+", branch):
        raise ValueError("bad branch name")
    answer = await ctx.elicit(f"Push {branch} to origin?", schema=Confirm)
    if answer.action != "accept":
        return "cancelled"
    try:
        subprocess.run(["git", "push", "origin", branch], check=True)
    except subprocess.CalledProcessError as exc:
        await ctx.error(f"push failed: {exc}")
        return "failed"
    await ctx.info(f"pushed {branch}")
    return "pushed"


@mcp.tool()
def git_reset_hard(ref: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{7,40}", ref):
        raise ValueError("not a commit id")
    log.info("reset to %s", ref)
    subprocess.run(["git", "reset", "--hard", ref], check=True)  # expect: human-oversight, error-handling
    return "reset"
