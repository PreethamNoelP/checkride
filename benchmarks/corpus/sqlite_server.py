"""SQLite server in the shape of the reference MCP sqlite server: a read
tool, a write tool, and a schema helper."""
# expect-verdict: FAIL_CRITICAL

import logging
import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sqlite")
log = logging.getLogger(__name__)
conn = sqlite3.connect("data.db")


def _tables() -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    return {row[0] for row in rows}


@mcp.tool()
def read_query(query: str) -> list:
    if not query.lstrip().upper().startswith("SELECT"):
        raise ValueError("only SELECT statements are allowed")
    try:
        # sqlite3 runs one statement per execute(), so a validated SELECT
        # cannot modify data; checkride cannot know that.
        return conn.execute(query).fetchall()  # known-fp: human-oversight
    except sqlite3.Error as exc:
        log.error("query failed: %s", exc)
        raise


@mcp.tool()
def write_query(query: str) -> str:  # expect: input-validation
    conn.execute(query)  # expect: human-oversight, error-handling
    conn.commit()
    log.info("write executed")
    return "ok"


@mcp.tool()
def describe_table(table_name: str) -> list:
    if table_name not in _tables():
        raise ValueError(f"no table {table_name!r}")
    log.info("describe %s", table_name)
    # Allowlisted name, read-only pragma: dynamic SQL, but not a risk.
    return conn.execute(f"PRAGMA table_info({table_name})").fetchall()  # known-fp: human-oversight, error-handling
