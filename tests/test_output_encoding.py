"""A file name the console cannot encode must not end the report."""

import os
import subprocess
import sys
from pathlib import Path

import pytest


def test_unencodable_file_name_does_not_crash_the_human_report(tmp_path: Path) -> None:
    name = "中文.py"
    try:
        (tmp_path / name).write_text(
            "@mcp.tool()\ndef f(p):\n    import os; os.system(p)\n"
        )
    except OSError:
        pytest.skip("this filesystem cannot hold the file name")

    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    done = subprocess.run(
        [sys.executable, "-m", "checkride", str(tmp_path)],
        capture_output=True,
        check=False,
        env=env,
    )

    assert b"Traceback" not in done.stderr
    assert done.returncode == 1  # a governance failure, not a crash
    assert b"FAIL_CRITICAL" in done.stdout
    assert b"\\u4e2d" in done.stdout  # shown escaped, not dropped
