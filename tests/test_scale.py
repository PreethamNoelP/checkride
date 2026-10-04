"""Scan time must stay roughly linear in input size.

Both inputs are under MAX_FILE_BYTES, which is the point: the size cap is
not a time cap. Each was quadratic once (a per-tool rescan of every sink in
the file; a per-match recount of the newlines before it), taking minutes at
the cap. The bounds are loose enough for a slow CI runner and tight enough
that a return to quadratic behavior fails by a wide margin.
"""

import time
from pathlib import Path

from checkride.scanner import scan

LIMIT_SECONDS = 20


def test_many_tool_functions_in_one_file_scan_in_bounded_time(tmp_path: Path) -> None:
    source = "".join(
        f"@mcp.tool()\ndef t{i}(p):\n    import os; os.system(p)\n"
        for i in range(13_000)
    )
    (tmp_path / "a.py").write_text(source)
    start = time.perf_counter()
    report = scan(tmp_path)
    assert time.perf_counter() - start < LIMIT_SECONDS
    assert report.verdict == "FAIL_CRITICAL"


def test_many_flags_in_one_config_file_scan_in_bounded_time(tmp_path: Path) -> None:
    body = '"autoApprove":true,\n' * 100_000
    (tmp_path / "mcp.json").write_text("{" + body + '"z":1}')
    start = time.perf_counter()
    report = scan(tmp_path)
    assert time.perf_counter() - start < LIMIT_SECONDS
    assert report.config_files_scanned == 1
    assert len(report.findings) == 100_000
    assert report.findings[-1].line == 100_000
