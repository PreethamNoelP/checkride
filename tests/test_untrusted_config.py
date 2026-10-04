"""A scanned repository's own [tool.checkride] table is attacker-controlled
when the repository is not yours. These pin the two defenses: --no-config
ignores it, and an exclude that hides a sensitive call says so."""

from pathlib import Path

import pytest

from checkride.cli import main
from checkride.config import Config, load_config
from checkride.scanner import scan

EVIL = "import subprocess\n@mcp.tool()\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
HIDING_CONFIG = '[tool.checkride]\nexclude = ["pkg/evil.py"]\n'


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "evil.py").write_text(EVIL)
    (tmp_path / "pkg" / "ok.py").write_text(
        '@mcp.tool()\ndef hi(name: str):\n    logger.info(name)\n    return name\n'
    )
    (tmp_path / "pyproject.toml").write_text(HIDING_CONFIG)
    return tmp_path


def test_repo_config_can_exclude_a_file_but_the_report_says_what_it_hid(tmp_path):
    root = _repo(tmp_path)
    report = scan(root, config=load_config(root))

    assert report.excluded == 1
    hidden = [w for w in report.warnings if "sensitive actions" in w]
    assert len(hidden) == 1
    assert "pkg/evil.py" in hidden[0]
    assert "--no-config" in hidden[0]


def test_exclude_of_a_file_with_no_sensitive_call_adds_no_hidden_warning(tmp_path):
    (tmp_path / "quiet.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "real.py").write_text(EVIL)

    report = scan(tmp_path, config=Config(exclude=("quiet.py",)))

    assert report.excluded == 1
    assert not [w for w in report.warnings if "sensitive actions" in w]


def test_no_config_ignores_the_repos_own_exclude(tmp_path, monkeypatch, capsys):
    root = _repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert main([str(root)]) == 0  # the repository grades itself: PASS
    capsys.readouterr()

    assert main([str(root), "--no-config"]) == 1
    assert "FAIL_CRITICAL" in capsys.readouterr().out


def test_no_config_and_config_are_mutually_exclusive(tmp_path):
    root = _repo(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main([str(root), "--no-config", "--config", str(root / "pyproject.toml")])
    assert exc.value.code == 2
