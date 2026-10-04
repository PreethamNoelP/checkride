"""LangChain tools: a decorated search tool and two class-based tools."""
# expect-verdict: FAIL_CRITICAL

import logging
import os
import subprocess

from langchain_core.tools import BaseTool, tool

log = logging.getLogger(__name__)
SCRATCH = "/tmp/agent-scratch/"


@tool
def search_docs(query: str) -> str:  # known-fp: input-validation
    """Search the documentation index. A search string is not dangerous;
    checkride flags any parameter named like a query."""
    log.info("search")
    return index.search(query, k=5)


class TerminalTool(BaseTool):
    name: str = "terminal"
    description: str = "Run a shell command."

    def _run(self, command: str) -> str:  # expect: input-validation
        log.info("terminal")
        return subprocess.run(command, shell=True, capture_output=True, text=True).stdout  # expect: human-oversight, error-handling


class SafeDeleteTool(BaseTool):
    name: str = "safe_delete"
    description: str = "Delete a scratch file after operator approval."

    def _run(self, path: str) -> str:
        if not path.startswith(SCRATCH):
            raise ValueError("only scratch files may be deleted")
        if not confirm_with_operator(f"delete {path}?"):
            return "declined"
        try:
            os.remove(path)
        except FileNotFoundError:
            return "already gone"
        log.info("deleted %s", path)
        return "deleted"
