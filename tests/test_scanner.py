import subprocess
import sys
from pathlib import Path

import pytest

import checkride.scanner as scanner_module
from checkride.astutils import FileContext
from checkride.config import Config, RuleConfig
from checkride.scanner import escapes_scan_root, iter_python_files, scan


def test_scan_walks_directory_and_skips_junk_dirs(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "server.py").write_text(
        "@mcp.tool()\ndef wipe(path):\n    shutil.rmtree(path)\n"
    )
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("auto_approve = True\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert any(f.file == "pkg/server.py" for f in report.findings)
    defaults_cat = next(
        c for c in report.categories if c.name == "Permissive defaults"
    )
    assert defaults_cat.sites == 0  # the .venv flag was never seen


def test_syntax_error_is_reported_not_fatal(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n")
    (tmp_path / "good.py").write_text("x = 1\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert len(report.skipped) == 1
    assert "bad.py" in report.skipped[0]


def test_recursion_error_is_skipped_not_fatal(tmp_path, monkeypatch):
    # The nesting depth at which ast.parse overflows varies by platform and
    # Python version (Linux 3.13 parses chains that crash Windows 3.11), so
    # simulate the RecursionError instead of trying to provoke a real one --
    # the contract under test is the scanner's handling, not CPython's stack.
    (tmp_path / "deep.py").write_text("x = 1\n")
    (tmp_path / "good.py").write_text("auto_approve = True\n")

    class ExplodingFileContext:
        @staticmethod
        def from_source(source, path="<memory>", config=None, **kwargs):
            if path == "deep.py":
                raise RecursionError
            return FileContext.from_source(source, path=path, config=config, **kwargs)

    monkeypatch.setattr(scanner_module, "FileContext", ExplodingFileContext)

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert len(report.skipped) == 1
    assert "deep.py" in report.skipped[0]
    assert any(f.rule == "permissive-defaults" for f in report.findings)


def test_scan_accepts_a_single_file(tmp_path):
    target = tmp_path / "one.py"
    target.write_text("auto_approve = True\n")

    report = scan(target)

    assert report.files_scanned == 1
    assert report.findings[0].file == "one.py"
    assert report.score == 90.0  # only permissive-defaults loses its 10


def test_exclude_glob_skips_matching_files(tmp_path):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "vulnerable.py").write_text("auto_approve = True\n")
    (tmp_path / "server.py").write_text("auto_approve = True\n")

    config = Config(exclude=("fixtures/*",))
    report = scan(tmp_path, config=config)

    assert report.files_scanned == 1
    assert report.findings[0].file == "server.py"


def test_iter_python_files_honors_exclude_patterns(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "generated_b.py").write_text("x = 1\n")

    paths = list(iter_python_files(tmp_path, exclude=("generated_*.py",)))

    assert [p.name for p in paths] == ["a.py"]


def test_scan_disables_rules_from_config(tmp_path):
    (tmp_path / "server.py").write_text(
        "@mcp.tool()\ndef fetch(url):\n    return http.get(url)\n"
    )
    config = Config(rules=RuleConfig(disabled_rules=frozenset({"rate-limiting"})))

    report = scan(tmp_path, config=config)

    assert "Rate limiting" not in {c.name for c in report.categories}
    assert report.max_score == 85


def test_scan_with_no_config_behaves_exactly_as_before(tmp_path):
    (tmp_path / "server.py").write_text("auto_approve = True\n")

    report = scan(tmp_path)

    assert report.max_score == 100
    assert report.suppressed == 0

# --- skip-dir matching must be relative to the scan root ---

def test_repo_living_under_a_skip_named_directory_is_still_scanned(tmp_path):
    # SKIP_DIRS used to be matched against every component of the absolute
    # path, so a checkout in ~/dev/build/ or C:\...\dist\ had every file
    # skipped and the scan exited "no Python files scanned".
    root = tmp_path / "build" / "myrepo"
    root.mkdir(parents=True)
    (root / "server.py").write_text("import shutil\n@mcp.tool()\ndef f(p):\n    shutil.rmtree(p)\n")

    report = scan(root)

    assert report.files_scanned == 1
    assert report.verdict == "FAIL_CRITICAL"


def test_skip_dirs_still_apply_inside_the_scan_root(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "generated.py").write_text("auto_approve = True\n")
    (tmp_path / "app.py").write_text("x = 1\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1


# --- exclude pattern semantics ---

def test_double_star_prefix_also_matches_at_the_root(tmp_path):
    # "**/generated_*.py" is how people write "at any depth", but fnmatch
    # reads "**/" as "characters then a literal slash", so this pattern
    # silently matched nothing in the repo root.
    (tmp_path / "generated_a.py").write_text("x = 1\n")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "generated_b.py").write_text("x = 1\n")
    (tmp_path / "pkg" / "real.py").write_text("x = 1\n")

    paths = list(iter_python_files(tmp_path, exclude=("**/generated_*.py",)))

    assert [p.name for p in paths] == ["real.py"]


def test_directory_pattern_excludes_everything_under_it(tmp_path):
    (tmp_path / "vendor" / "deep").mkdir(parents=True)
    (tmp_path / "vendor" / "deep" / "lib.py").write_text("x = 1\n")
    (tmp_path / "app.py").write_text("x = 1\n")

    for pattern in ("vendor", "vendor/"):
        paths = list(iter_python_files(tmp_path, exclude=(pattern,)))
        assert [p.name for p in paths] == ["app.py"], pattern


def test_slash_free_pattern_matches_the_basename_at_any_depth(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "thing.gen.py").write_text("x = 1\n")
    (tmp_path / "keep.py").write_text("x = 1\n")

    paths = list(iter_python_files(tmp_path, exclude=("*.gen.py",)))

    assert [p.name for p in paths] == ["keep.py"]


def test_exclude_matching_is_case_sensitive_on_every_platform(tmp_path):
    # fnmatch (not fnmatchcase) normalizes case via os.path.normcase, which
    # would make the same config exclude different files on Windows than on
    # Linux. A CI tool must not be platform-dependent here.
    (tmp_path / "Server.py").write_text("x = 1\n")

    paths = list(iter_python_files(tmp_path, exclude=("server.py",)))

    assert [p.name for p in paths] == ["Server.py"]


def test_explicit_single_file_target_ignores_exclude_patterns(tmp_path):
    target = tmp_path / "server.py"
    target.write_text("auto_approve = True\n")

    report = scan(target, config=Config(exclude=("*.py",)))

    assert report.files_scanned == 1


# --- hostile or unreadable sources are skipped, never fatal ---

def test_source_with_null_bytes_is_skipped(tmp_path):
    (tmp_path / "nul.py").write_bytes(b"x = 1\ny = '\x00'\n")
    (tmp_path / "ok.py").write_text("auto_approve = True\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert any("nul.py" in entry for entry in report.skipped)
    assert report.verdict == "INCOMPLETE"


def test_unknown_encoding_declaration_is_skipped(tmp_path):
    (tmp_path / "enc.py").write_bytes(b"# -*- coding: not-a-real-codec -*-\nx = 1\n")
    (tmp_path / "ok.py").write_text("x = 1\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert any("enc.py" in entry for entry in report.skipped)


def test_oversized_file_is_skipped_rather_than_parsed(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_module, "MAX_FILE_BYTES", 32)
    (tmp_path / "huge.py").write_text("x = 1\n" * 100)
    (tmp_path / "ok.py").write_text("x = 1\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert any("huge.py" in entry and "limit" in entry for entry in report.skipped)


# --- reported paths ---

def test_findings_are_reported_relative_to_the_working_directory(tmp_path, monkeypatch):
    # SARIF results and clickable terminal output both need a path that
    # resolves from where the tool was invoked. A root-relative path meant
    # `checkride src/` reported "server.py" for src/server.py.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "server.py").write_text("auto_approve = True\n")
    monkeypatch.chdir(tmp_path)

    report = scan(Path("src"))

    assert [f.file for f in report.findings] == ["src/server.py"]


def test_single_file_target_keeps_its_directory_in_the_reported_path(
    tmp_path, monkeypatch
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "server.py").write_text("auto_approve = True\n")
    monkeypatch.chdir(tmp_path)

    report = scan(Path("src/server.py"))

    assert report.findings[0].file == "src/server.py"


def test_target_outside_the_working_directory_falls_back_to_root_relative(
    tmp_path, monkeypatch
):
    other = tmp_path / "elsewhere"
    (other / "pkg").mkdir(parents=True)
    (other / "pkg" / "server.py").write_text("auto_approve = True\n")
    unrelated = tmp_path / "cwd"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)

    report = scan(other)

    assert report.findings[0].file == "pkg/server.py"


def test_skip_reason_does_not_leak_an_absolute_path(tmp_path, monkeypatch):
    # "unknown encoding for <abs path>" would make the same commit produce
    # a different report on every machine, which breaks log diffing.
    (tmp_path / "enc.py").write_bytes(b"# -*- coding: nope -*-\nx = 1\n")
    (tmp_path / "ok.py").write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)

    report = scan(Path("."))

    entry = next(e for e in report.skipped if e.startswith("enc.py"))
    assert str(tmp_path) not in entry


# --- symlinks: a scanned repo must not be able to redirect us out of it ---

def _can_symlink(tmp_path) -> bool:
    """Symlink creation needs elevated privileges on Windows, so these tests
    verify on POSIX (and on the Linux half of the CI matrix) and skip
    elsewhere rather than silently passing."""
    try:
        (tmp_path / "_probe_target").write_text("x = 1\n")
        (tmp_path / "_probe_link").symlink_to(tmp_path / "_probe_target")
    except (OSError, NotImplementedError):
        return False
    (tmp_path / "_probe_link").unlink()
    (tmp_path / "_probe_target").unlink()
    return True


def test_symlink_out_of_the_tree_is_refused_and_reported(tmp_path):
    if not _can_symlink(tmp_path):
        pytest.skip("this platform does not allow creating symlinks")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.py").write_text("import os\n@mcp.tool()\ndef f(p):\n    os.remove(p)\n")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "real.py").write_text("auto_approve = True\n")
    (root / "config.py").symlink_to(outside / "private.py")

    report = scan(root)

    assert report.files_scanned == 1
    assert any("symlink not followed" in entry for entry in report.skipped)
    # The refusal is visible, not silent: a file we declined to read is a
    # hole in coverage.
    assert report.verdict == "INCOMPLETE"
    assert not any("os.remove" in f.message for f in report.findings)


def test_symlink_inside_the_tree_is_followed(tmp_path):
    if not _can_symlink(tmp_path):
        pytest.skip("this platform does not allow creating symlinks")

    root = tmp_path / "repo"
    (root / "shared").mkdir(parents=True)
    (root / "shared" / "util.py").write_text(
        "import shutil\n@mcp.tool()\ndef wipe(p):\n    shutil.rmtree(p)\n"
    )
    (root / "pkg").mkdir()
    (root / "pkg" / "util.py").symlink_to(root / "shared" / "util.py")

    report = scan(root)

    # Both the real file and the in-tree link are ordinary repo layout.
    assert report.files_scanned == 2
    assert report.skipped == []
    assert report.verdict == "FAIL_CRITICAL"


def test_broken_symlink_is_refused_not_fatal(tmp_path):
    if not _can_symlink(tmp_path):
        pytest.skip("this platform does not allow creating symlinks")

    root = tmp_path / "repo"
    root.mkdir()
    (root / "ok.py").write_text("x = 1\n")
    (root / "dangling.py").symlink_to(tmp_path / "does_not_exist.py")

    report = scan(root)

    assert report.files_scanned == 1
    assert any("dangling.py" in entry for entry in report.skipped)


def test_explicitly_named_symlink_target_is_still_scanned(tmp_path):
    # Exclude patterns don't overrule an explicit target, and neither does
    # this: pointing checkride at a link is the caller's own decision.
    if not _can_symlink(tmp_path):
        pytest.skip("this platform does not allow creating symlinks")

    real = tmp_path / "real.py"
    real.write_text("auto_approve = True\n")
    link = tmp_path / "link.py"
    link.symlink_to(real)

    report = scan(link)

    assert report.files_scanned == 1
    assert report.findings[0].rule == "permissive-defaults"


def test_escapes_scan_root_is_false_for_ordinary_files(tmp_path):
    # Platform-independent: no symlink needed, so this runs everywhere and
    # pins the "don't penalize normal files" half of the contract.
    (tmp_path / "plain.py").write_text("x = 1\n")

    assert escapes_scan_root(tmp_path / "plain.py", tmp_path) is False


class _FakeLink:
    """Minimal stand-in for a Path, so the decision logic in
    escapes_scan_root can be pinned on platforms that cannot create real
    symlinks. The POSIX tests above exercise the same branches against the
    real filesystem in CI; this one runs everywhere."""

    def __init__(self, resolved, *, symlink=True):
        self._resolved = resolved
        self._symlink = symlink

    def is_symlink(self):
        return self._symlink

    def resolve(self, strict=False):
        if isinstance(self._resolved, Exception):
            raise self._resolved
        return self._resolved


def test_escapes_scan_root_allows_a_link_resolving_inside(tmp_path):
    inside = _FakeLink(tmp_path / "pkg" / "util.py")
    assert escapes_scan_root(inside, tmp_path) is False


def test_escapes_scan_root_refuses_a_link_resolving_outside(tmp_path):
    outside = _FakeLink(Path("/etc/passwd").absolute())
    assert escapes_scan_root(outside, tmp_path) is True


def test_escapes_scan_root_refuses_an_unresolvable_link(tmp_path):
    # A loop (OSError/ELOOP) or a dangling target: "cannot prove it stays
    # inside" gets the same answer as "leaves".
    for error in (OSError("ELOOP"), FileNotFoundError(), RuntimeError()):
        assert escapes_scan_root(_FakeLink(error), tmp_path) is True


def test_escapes_scan_root_ignores_plain_files_without_resolving(
    tmp_path, monkeypatch
):
    # A plain file under plain directories must short-circuit before any
    # resolve() call -- that is what keeps the check off the hot path for
    # every ordinary file.
    (tmp_path / "pkg").mkdir()
    plain = tmp_path / "pkg" / "plain.py"
    plain.write_text("x = 1\n")

    def no_resolve(self, strict=False):
        raise AssertionError("resolve must not be called")

    monkeypatch.setattr(Path, "resolve", no_resolve)
    assert escapes_scan_root(plain, tmp_path) is False


def _make_junction(link: Path, target: Path) -> bool:
    if sys.platform != "win32":
        return False
    done = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
    )
    return done.returncode == 0


def test_junction_out_of_the_tree_is_refused_and_reported(tmp_path):
    # Windows directory junctions are not symlinks (is_symlink() is False)
    # yet rglob descends through them, so a junction used to pull files from
    # outside the scan root into the report.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.py").write_text(
        "@mcp.tool()\ndef OUTSIDE_FUNC(p):\n    import os; os.system(p)\n"
    )
    (outside / "mcp.json").write_text('{"autoApprove": true}')
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.py").write_text("x = 1\n")
    if not _make_junction(root / "linked", outside):
        pytest.skip("directory junctions are only available on Windows")

    report = scan(root, config=Config(rules=RuleConfig(scope="all")))

    assert "OUTSIDE_FUNC" not in str(report.to_dict())
    assert report.config_files_scanned == 0
    assert sum("not followed" in entry for entry in report.skipped) == 2
    assert report.verdict == "INCOMPLETE"


# --- config excludes must be visible in the report ---

def test_excluded_files_are_counted_and_warned_about(tmp_path):
    # Before: the report said "scanned 1 Python file(s)" whether or not an
    # exclude pattern had removed a hundred more. A reader could not tell a
    # small repo from a heavily filtered one.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("auto_approve = True\n")
    (tmp_path / "src" / "b.py").write_text("auto_approve = True\n")
    (tmp_path / "keep.py").write_text("auto_approve = False\n")

    report = scan(tmp_path, config=Config(exclude=("src/*",)))

    assert report.files_scanned == 1
    assert report.excluded == 2
    assert report.to_dict()["excluded"] == 2
    assert any("exclude" in w for w in report.warnings)


def test_skip_dirs_are_not_counted_as_config_exclusions(tmp_path):
    # .venv/node_modules are built-in noise filters every run applies the
    # same way, not a project decision worth reporting.
    (tmp_path / "keep.py").write_text("auto_approve = False\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("auto_approve = True\n")

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert report.excluded == 0
    assert not any("exclude" in w for w in report.warnings)


def test_exclude_hiding_every_sink_cannot_produce_a_pass(tmp_path):
    # The hole this closes: `exclude` removed the only file with sinks, so
    # every category scored "no applicable sites" -> full marks -> 100.0,
    # and the verdict was PASS with exit 0 even under the strictest flags.
    # disabled_rules was already blocked from doing this; exclude was not.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "server.py").write_text(
        "import shutil\n@mcp.tool()\ndef wipe(path):\n    shutil.rmtree(path)\n"
    )
    (tmp_path / "harmless.py").write_text("def add(a, b):\n    return a + b\n")

    unfiltered = scan(tmp_path)
    assert unfiltered.verdict == "FAIL_CRITICAL"

    filtered = scan(tmp_path, config=Config(exclude=("src/*",)))

    assert filtered.score == 100.0          # the arithmetic is unchanged
    assert filtered.total_sites == 0
    assert filtered.verdict == "INCOMPLETE"  # the conclusion is not
    assert filtered.excluded == 1


# --- JSON config-file scanning (configscan.py) ---


def test_scan_finds_permissive_default_in_known_config_file(tmp_path):
    (tmp_path / "claude_desktop_config.json").write_text(
        '{"mcpServers": {"shell": {"autoApprove": true}}}\n'
    )

    report = scan(tmp_path)

    assert report.config_files_scanned == 1
    assert any(
        f.file == "claude_desktop_config.json" and f.rule == "permissive-defaults"
        for f in report.findings
    )


def test_scan_merges_config_file_sites_into_permissive_defaults_category(tmp_path):
    (tmp_path / "server.py").write_text("auto_approve = True\n")
    (tmp_path / "mcp.json").write_text('{"autoApprove": true}\n')

    report = scan(tmp_path)

    defaults_cat = next(
        c for c in report.categories if c.name == "Permissive defaults"
    )
    assert defaults_cat.sites == 2  # one from the .py file, one from the JSON
    assert len(report.categories) == 6  # not a new, seventh category


def test_scan_skips_config_scanning_when_the_rule_is_disabled(tmp_path):
    (tmp_path / "mcp.json").write_text('{"autoApprove": true}\n')

    config = Config(rules=RuleConfig(disabled_rules=frozenset({"permissive-defaults"})))
    report = scan(tmp_path, config=config)

    assert report.config_files_scanned == 0
    assert not any(f.rule == "permissive-defaults" for f in report.findings)


def test_scan_reports_malformed_json_config_as_skipped(tmp_path):
    (tmp_path / "mcp.json").write_text("{not valid json")

    report = scan(tmp_path)

    assert any("invalid JSON" in entry for entry in report.skipped)
    assert report.verdict == "INCOMPLETE"


def test_scan_config_file_exclude_pattern_is_honored(tmp_path):
    (tmp_path / "mcp.json").write_text('{"autoApprove": true}\n')

    report = scan(tmp_path, config=Config(exclude=("mcp.json",)))

    assert report.config_files_scanned == 0
    assert report.excluded == 1


# --- directories named env/build/dist are source unless proven otherwise ---

_WIPE = "import os\n@mcp.tool()\ndef wipe(p):\n    os.remove(p)\n"


@pytest.mark.parametrize("name", ["env", "build", "dist"])
def test_package_named_like_an_artifact_dir_is_scanned(tmp_path, name):
    # These names used to be skipped silently, hiding the code in them.
    (tmp_path / "src" / name).mkdir(parents=True)
    (tmp_path / "src" / name / "s.py").write_text(_WIPE)

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert report.verdict == "FAIL_CRITICAL"


def test_virtualenv_is_skipped_by_pyvenv_cfg_whatever_its_name(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    venv = tmp_path / "env"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (venv / "lib.py").write_text(_WIPE)

    assert [p.name for p in iter_python_files(tmp_path)] == ["app.py"]


def test_root_build_dir_beside_packaging_file_is_pruned_and_reported(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "copy.py").write_text(_WIPE)

    report = scan(tmp_path)

    assert report.files_scanned == 1
    assert any("build/" in w for w in report.warnings)


def test_root_build_dir_without_packaging_file_is_scanned(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "s.py").write_text(_WIPE)

    assert scan(tmp_path).files_scanned == 1
