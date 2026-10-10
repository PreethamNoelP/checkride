"""File-walking scanner: bridge from a path on disk to a ScanReport.

Finds .py files under a root (or accepts a single file), parses each into
a FileContext, and streams them to the scoring aggregator one at a time --
memory stays flat regardless of repo size. Unparseable files are recorded
in report.skipped rather than aborting the scan -- a skipped file
contributes nothing to the score, in either direction, and makes the
verdict INCOMPLETE so a partial view never looks like a full pass.
"""

import functools
import os
import tokenize
from collections.abc import Callable, Iterator
from pathlib import Path

from checkride import callgraph, configscan
from checkride.astutils import FileContext
from checkride.config import Config
from checkride.fswalk import MAX_FILE_BYTES, SKIP_DIRS, is_excluded, walk_files
from checkride.rules import defaults
from checkride.scoring import ScanReport, score_contexts

__all__ = [
    "MAX_FILE_BYTES",
    "SKIP_DIRS",
    "escapes_scan_root",
    "is_excluded",
    "iter_python_files",
    "scan",
]


def iter_python_files(
    root: Path,
    exclude: tuple[str, ...] = (),
    on_excluded: Callable[[Path], None] | None = None,
    on_artifact_dir: Callable[[Path], None] | None = None,
) -> Iterator[Path]:
    """Yield .py files under root in sorted (deterministic) order,
    or root itself if it is a single file. An explicitly named file is
    always scanned -- exclude patterns filter a walk, they do not overrule
    the target the caller asked for.

    `on_excluded` is called once per file an `exclude` pattern removed, so
    the report can say how much of the tree config kept it from seeing.
    Noise directories (.venv, node_modules, caches) are deliberately not
    reported: those are built-in filters every run applies identically, not
    a project decision a reader of the report needs to know about. The one
    exception is packaging output (see fswalk.classify_dir), which is
    pruned on a guess and so is announced through `on_artifact_dir`.
    """
    if root.is_file():
        yield root
        return
    found = walk_files(root, lambda n: n.endswith(".py"), on_artifact_dir)
    for path in sorted(found):
        rel = path.relative_to(root)
        if exclude and is_excluded(rel.as_posix(), exclude):
            if on_excluded is not None:
                on_excluded(path)
            continue
        yield path


# FILE_ATTRIBUTE_REPARSE_POINT. Windows directory junctions and mount points
# carry it but are not symlinks: Path.is_symlink() is False for them while
# the directory walk descends straight through.
_REPARSE_POINT = 0x400


@functools.lru_cache(maxsize=8192)
def _is_redirect(path: Path) -> bool:
    """True if `path` is a symlink or a Windows reparse point (junction).
    An entry that cannot be inspected counts as a redirect: the caller then
    falls through to the strict resolve() check."""
    try:
        st = path.lstat()
    except OSError:
        return True
    return path.is_symlink() or bool(
        getattr(st, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _reached_through_redirect(path: Path, root: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    return any(_is_redirect(root / parent) for parent in rel.parents if parent.parts)


def escapes_scan_root(path: Path, root: Path) -> bool:
    """True if `path` is a link, or sits under a redirected directory, whose
    real location lies outside `root`.

    Scanned repositories are untrusted. A file named `config.py` that is
    really a link to ~/.aws/credentials would otherwise be read and parsed,
    and while checkride never executes what it reads and never reports
    string values, identifier names from a file outside the tree could
    surface in the report under an in-tree path. Refusing to follow the link
    removes the question.

    Links that stay *inside* the scan root are followed normally -- they
    are ordinary repository layout (a shared module linked into a package),
    and skipping them would silently shrink coverage.

    pathlib's `**` does not descend into symlinked directories, but on
    Windows it does descend into directory junctions, which is_symlink()
    does not report. So the check covers every directory between the root
    and the file as well as the file itself. Ordinary files under ordinary
    directories short-circuit before any resolve() call; only a path with a
    redirect somewhere above it pays for one.

    An unresolvable link -- a loop, or a target on a filesystem that errors
    -- counts as escaping. "Cannot prove it stays inside" is the same answer
    as "leaves" for this purpose.
    """
    if not _reached_through_redirect(path, root):
        return False
    try:
        # Both sides resolved, so a checkout that itself lives under a
        # symlink (/tmp -> /private/tmp on macOS) compares consistently.
        path.resolve(strict=True).relative_to(root.resolve())
    except (ValueError, OSError, RuntimeError):
        return True
    return False


def _display_path(path: Path, root: Path, cwd: Path) -> str:
    """The path checkride reports for a finding.

    Relative to the current working directory whenever the file is under
    it, because that is the path a developer can click and -- more
    importantly -- the path GitHub/GitLab code scanning resolves a SARIF
    result against. Reporting root-relative paths meant `checkride src/`
    emitted "server.py" for src/server.py, which no code-scanning
    dashboard can map back to a file in the repository.

    os.path.abspath rather than Path.resolve(): a symlinked source tree
    should be reported under the path the caller used, not its target.
    """
    absolute = Path(os.path.abspath(path))
    try:
        return absolute.relative_to(cwd).as_posix()
    except ValueError:
        pass
    if root.is_file():
        return path.name
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _relativize(reason: str, path: Path, rel: str) -> str:
    """Replace any spelling of the file's absolute path in an exception
    message with the reported relative one, so the same commit produces the
    same report on every machine."""
    for spelling in {str(path), os.path.abspath(path)}:
        reason = reason.replace(spelling, rel)
    return reason


def _read_source(path: Path) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(
            f"file is larger than the {MAX_FILE_BYTES // 1_000_000} MB scan limit"
        )
    # tokenize.open honors PEP 263 coding declarations that plain utf-8
    # open() would crash on.
    with tokenize.open(path) as fh:
        return fh.read()


# Parsed files are kept between the two passes while their total source
# size stays under this; past it, pass 2 re-parses each file, so memory
# stays bounded by one file's AST however large the repository is. A kept
# file costs roughly 40x its source size (measured: 2.7 MB of source peaks
# at ~104 MB kept, ~17 MB re-parsed), so 8 MB of source is ~300 MB.
REUSE_PARSED_BYTES = 8_000_000


def _excluded_with_sensitive_calls(
    paths: list[Path],
    parse: Callable[[Path, str, Callable[[str], None] | None], FileContext | None],
    root: Path,
    cwd: Path,
) -> list[str]:
    """Display paths of excluded files that contain a sensitive call.

    Files are parsed one at a time and dropped, so memory stays bounded by
    one file's AST, as in the scan itself. A file that cannot be read or
    parsed is not reported here: it could not have been judged either way.
    """
    hidden = []
    for path in paths:
        if escapes_scan_root(path, root):
            continue
        rel = _display_path(path, root, cwd)
        ctx = parse(path, rel, None)
        if ctx is not None and ctx.candidate_sensitive_calls:
            hidden.append(rel)
    return hidden


def module_name(path: Path, root: Path) -> tuple[str, bool]:
    """Dotted module name for a file, relative to the scan root, and whether
    it is a package's __init__."""
    rel = Path(path.name) if root.is_file() else path.relative_to(root)
    parts = list(rel.with_suffix("").parts)
    is_package = bool(parts) and parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    return ".".join(parts), is_package


def scan(
    target: str | Path,
    config: Config | None = None,
    progress: Callable[[str, int, int], None] | None = None,
) -> ScanReport:
    """Scan a file or directory.

    `progress(phase, done, total)` is called after each file of each pass,
    so a front end can show that a large repository is still being worked on.

    Two passes. The first summarizes every file (tool entry points, call
    edges, logging) into a ProgramIndex, so reachability crosses files; the
    second runs the rules against that index.
    """
    root = Path(target)
    config = config if config is not None else Config()
    cwd = Path(os.path.abspath(os.curdir))
    skipped: list[str] = []
    excluded = 0

    excluded_py: list[Path] = []

    def count_excluded(path: Path) -> None:
        nonlocal excluded
        excluded += 1
        if path.suffix == ".py":
            excluded_py.append(path)

    artifact_dirs: list[Path] = []
    paths = list(
        iter_python_files(root, config.exclude, count_excluded, artifact_dirs.append)
    )

    def parse(path: Path, rel: str, note: Callable[[str], None] | None) -> FileContext | None:
        module, _is_package = module_name(path, root)
        try:
            return FileContext.from_source(
                _read_source(path), path=rel, config=config.rules, module=module
            )
        except SyntaxError as exc:
            where = f" at line {exc.lineno}" if exc.lineno else ""
            reason = f"syntax error{where} ({exc.msg})"
        except RecursionError:
            reason = "too deeply nested to parse"
        except MemoryError:
            reason = "ran out of memory while parsing"
        # ValueError: NUL bytes or the size guard. LookupError: a PEP 263
        # declaration naming an unknown encoding. Both are reachable from any
        # untrusted repository and neither should end the scan.
        except (OSError, UnicodeDecodeError, ValueError, LookupError) as exc:
            reason = f"unreadable ({exc})"
        if note is not None:
            note(reason)
        return None

    def refused(path: Path) -> bool:
        # An explicitly named target is never second-guessed.
        return not root.is_file() and escapes_scan_root(path, root)

    # Pass 1: summaries for cross-file reachability.
    summaries = []
    kept: dict[Path, FileContext] = {}
    kept_bytes = 0
    for done, path in enumerate(paths, 1):
        if progress is not None:
            progress("indexing", done, len(paths))
        if refused(path):
            continue
        rel = _display_path(path, root, cwd)
        ctx = parse(path, rel, None)
        if ctx is None:
            continue
        _module, is_package = module_name(path, root)
        summaries.append(callgraph.summarize(ctx, ctx.module, is_package))
        try:
            size = path.stat().st_size
        except OSError:
            size = REUSE_PARSED_BYTES
        if kept_bytes + size <= REUSE_PARSED_BYTES:
            kept[path] = ctx
            kept_bytes += size
    program = callgraph.ProgramIndex.build(
        summaries, config.rules.scope, config.rules.entry_points
    )
    del summaries

    def iter_contexts() -> Iterator[FileContext]:
        for done, path in enumerate(paths, 1):
            if progress is not None:
                progress("checking", done, len(paths))
            rel = _display_path(path, root, cwd)

            def note(reason: str, path: Path = path, rel: str = rel) -> None:
                # Some messages ("unknown encoding for <path>") embed the
                # absolute path; report the same text on every machine.
                skipped.append(f"{rel}: {_relativize(reason, path, rel)}")

            # A file we declined to read is a hole in coverage, which is
            # what INCOMPLETE is for -- so the refusal is reported.
            if refused(path):
                note(
                    "symlink not followed (target is outside the scan root, "
                    "or could not be resolved)"
                )
                continue
            ctx = kept.pop(path, None) or parse(path, rel, note)
            if ctx is not None:
                ctx.program = program
                ctx.__dict__.pop("index", None)
                yield ctx

    report = score_contexts(
        iter_contexts(),
        disabled_rules=config.rules.disabled_rules,
        accepted_risks=config.accepted_risks,
        scope=config.rules.scope,
    )
    report.skipped = skipped
    report.min_score = config.min_score

    # MCP client config files feed the "Permissive defaults" category (see
    # configscan.py). Skipped when that rule is disabled: a disabled rule
    # means "we didn't look", not "we looked and it's fine".
    defaults_category = next(
        (c for c in report.categories if c.name == defaults.CATEGORY), None
    )
    if defaults_category is not None:
        config_files_scanned = 0
        for path in configscan.iter_config_files(
            root, config.extra_config_filenames, config.exclude, count_excluded
        ):
            rel = _display_path(path, root, cwd)
            if not root.is_file() and escapes_scan_root(path, root):
                skipped.append(
                    f"{rel}: symlink not followed (target is outside the "
                    "scan root, or could not be resolved)"
                )
                continue
            sites, passed, findings, skip_reason = configscan.scan_config_file(
                path, rel, config.rules
            )
            if skip_reason is not None:
                skipped.append(f"{rel}: {_relativize(skip_reason, path, rel)}")
                continue
            config_files_scanned += 1
            defaults_category.sites += sites
            defaults_category.passed += passed
            defaults_category.findings.extend(findings)
        report.config_files_scanned = config_files_scanned

    # Excluding files is a project decision, not a coverage gap, so it does
    # not make the verdict INCOMPLETE -- but it is always reported.
    report.excluded = excluded
    if artifact_dirs:
        names = ", ".join(sorted(f"{d.name}/" for d in artifact_dirs))
        report.warnings.append(
            f"{names} not scanned: packaging output next to a project file "
            "(pyproject.toml / setup.py). Scan it by naming it as the target "
            "if it holds source"
        )
    if excluded:
        report.warnings.append(
            f"{excluded} file(s) were not scanned because an 'exclude' pattern "
            "in the config matched them"
        )
        # The config belongs to the scanned repository, so an exclude is
        # also a way for it to hide a sink. Say so when that is what it hid.
        hidden = _excluded_with_sensitive_calls(excluded_py, parse, root, cwd)
        if hidden:
            shown = ", ".join(hidden[:5]) + (", ..." if len(hidden) > 5 else "")
            report.warnings.append(
                f"{len(hidden)} excluded file(s) contain calls checkride "
                f"treats as sensitive actions and were not judged: {shown}. "
                "If you do not control this repository, rerun with --no-config"
            )
    return report
