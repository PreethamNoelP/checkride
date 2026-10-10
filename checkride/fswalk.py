"""Shared file-walk primitives: the parts of "which files does a scan
look at" that don't care whether the file being considered is Python or
JSON. Split out of scanner.py so checkride/configscan.py (the JSON
config-file scanner) can reuse them without scanner.py and configscan.py
importing each other -- scanner.py orchestrates both walks and imports
configscan.py, so configscan.py cannot import scanner.py back.
"""

import fnmatch
import os
from collections.abc import Callable, Iterator
from pathlib import Path

# Directories whose contents are never the user's own tool code, whatever
# else is true of the tree. Scanning your own .venv is the classic way to
# drown a report in library noise. Matched against the path *relative to the
# scan root* only: matching absolute path components instead meant a repo
# that happened to live in ~/dev/build/ or C:\...\dist\ had every one of
# its files skipped.
#
# `env`, `build` and `dist` are deliberately NOT here. They are ordinary
# names for ordinary packages (`src/env/`, `tools/build/`), and skipping one
# silently hides exactly the code a security scanner exists to read. They
# are pruned only when there is evidence they are not source -- see
# `classify_dir`.
SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    ".eggs", ".venv", "venv", "node_modules", "site-packages",
}

# Names that are packaging output only when a packaging file sits beside
# them at the scan root.
_ARTIFACT_NAMES = {"build", "dist"}
_PACKAGING_FILES = ("pyproject.toml", "setup.py", "setup.cfg")

# Guard against a single pathological file exhausting CI memory: ast.parse
# builds a tree many times the size of its source, so a hostile
# multi-hundred-megabyte "module" is a cheap way to OOM a scanner that runs
# on untrusted repositories. No hand-written module comes close to this;
# anything over it is skipped visibly (INCOMPLETE), never silently. JSON
# config files are held to the same limit -- json.loads() builds an object
# graph with the same "many times the source size" property ast.parse has.
MAX_FILE_BYTES = 5_000_000


def _match_variants(pattern: str) -> list[str]:
    """Spellings of an exclude pattern that should behave identically.

    A trailing slash is decoration ("vendor/" == "vendor"), and a leading
    "**/" is how people write "at any depth" -- but fnmatch reads it as
    "some characters, then a literal slash", so "**/generated_*.py" would
    match nothing at the repo root. Both spellings are normalized here
    rather than by translating patterns into regexes by hand.
    """
    pattern = pattern.rstrip("/") or pattern
    variants = [pattern]
    if pattern.startswith("**/"):
        variants.append(pattern[3:])
    return variants


def is_excluded(rel_posix: str, patterns: tuple[str, ...]) -> bool:
    """Match an exclude pattern against the scan-relative posix path with
    gitignore-shaped semantics, using only fnmatch:

      - "tests/fixtures/*"  -- path match, as before
      - "**/generated_*.py" -- also matches at the root
      - "vendor" / "vendor/" -- the directory and everything under it
      - "*.gen.py"          -- a slash-free pattern matches the basename
                               at any depth

    fnmatchcase, not fnmatch: plain fnmatch normalizes case through
    os.path.normcase, which would make excludes case-insensitive on Windows
    and case-sensitive on Linux -- the same config producing different
    scans per platform.
    """
    parts = rel_posix.split("/")
    # The file itself, then each of its parent directories.
    candidates = [rel_posix] + ["/".join(parts[:i]) for i in range(1, len(parts))]
    for pattern in patterns:
        for variant in _match_variants(pattern):
            basename_only = "/" not in variant
            for candidate in candidates:
                if fnmatch.fnmatchcase(candidate, variant):
                    return True
                if basename_only and fnmatch.fnmatchcase(
                    candidate.rsplit("/", 1)[-1], variant
                ):
                    return True
    return False


def classify_dir(parent: Path, name: str, at_root: bool) -> str | None:
    """Decide whether the walk should descend into `parent / name`.

    Returns "noise" for directories that are never reported (VCS metadata,
    caches, virtual environments), "artifact" for packaging output that is
    pruned but reported, and None for a directory to scan.

    A directory holding `pyvenv.cfg` is a virtual environment whatever it is
    called, which is how a plain `env/` is told apart from a package named
    `env`. `build/` and `dist/` are artifacts only at the scan root and only
    beside a pyproject.toml / setup.py / setup.cfg, i.e. in a project that
    would have produced them.
    """
    if name in SKIP_DIRS:
        return "noise"
    path = parent / name
    if (path / "pyvenv.cfg").is_file():
        return "noise"
    if (
        at_root
        and name in _ARTIFACT_NAMES
        and any((parent / f).is_file() for f in _PACKAGING_FILES)
    ):
        return "artifact"
    return None


def walk_files(
    root: Path,
    wanted: Callable[[str], bool],
    on_artifact_dir: Callable[[Path], None] | None = None,
) -> Iterator[Path]:
    """Yield files under directory `root` whose name satisfies `wanted`,
    pruning unscannable directories *before* descending into them -- a
    `rglob` followed by a filter walks every file of a 100,000-file
    node_modules only to throw it away. Order is not guaranteed; callers
    sort, as they always have.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        at_root = here == root
        kept = []
        for name in dirnames:
            kind = classify_dir(here, name, at_root)
            if kind is None:
                kept.append(name)
            elif kind == "artifact" and on_artifact_dir is not None:
                on_artifact_dir(here / name)
        dirnames[:] = kept
        for name in filenames:
            if wanted(name):
                yield here / name
