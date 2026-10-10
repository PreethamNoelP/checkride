# Contributing to checkride

Contributions are welcome — especially new rules, vocabulary additions, and
reports of false positives or false negatives.

## Setup

```console
$ git clone https://github.com/PreethamNoelP/checkride.git
$ cd checkride
$ pip install -e ".[dev]"
$ python -m pytest tests/ -q     # 4 symlink tests skip on Windows without
                                  # symlink privilege; Linux CI runs them
$ python -m pytest tests/ -q --cov=checkride   # CI requires >= 95%
$ mypy                            # --strict, configured in pyproject.toml
$ ruff check checkride/ tests/
```

Python 3.11+ and no other runtime dependency. `mypy` and `ruff` are
dev-only and both gate CI: the package ships a `py.typed` marker, which
promises anyone writing a third-party rule that the annotations are real,
and an unenforced promise is how it silently stops being true.

`tests/fixtures/` is excluded from ruff. Those files are scanner *input* —
they reference undefined names on purpose because they are only ever
`ast.parse`d, never imported — so their F821s are the point of the files.

## The bar for a change

**Every behavior change needs a test that fails without it.** Not a test
that merely exercises the new code — a test that pins the specific wrong
answer the old code gave. Most of this project's real bugs looked like
"scored 100/100 on code that shells out"; the suite's job is to make each
of those irreproducible.

**Zero runtime dependencies.** A governance scanner that drags in a
dependency tree is a worse deal for a CI step than one that is slightly
less clever. If you need a library, make the case in an issue first.

**Never execute scanned code.** No `import`, `eval`, `exec`, or subprocess
of anything under the scan target. `ast.parse` and `tokenize` only.

**Document the blind spot.** Every heuristic in `RULES.md` states what it
does *not* catch. A rule without that is not finished — overstating what a
static scan can prove is the fastest way to make this tool useless.

## Adding a rule

A rule is one module in `checkride/rules/` exposing four names:

```python
RULE_ID = "my-rule"      # lowercase kebab-case; suppressions name it
CATEGORY = "My category"
WEIGHT = 10              # points out of 100

def check(ctx: FileContext) -> tuple[int, int, list[Finding]]:
    """Return (sites, passed, findings)."""
```

Then:

1. Register it in `ALL_RULES` in `checkride/scoring.py`.
2. Add its id to `RULE_IDS` in `checkride/rules/__init__.py`
   (`test_rules_package.py` fails if you forget).
3. Rebalance `WEIGHT`s so they still total 100 — also checked by
   `test_rules_package.py`. Changing weights changes every user's score,
   so say so in `CHANGELOG.md`.
4. Ask the context for what you need instead of walking the tree
   yourself: `ctx.all_nodes`, `ctx.scope_nodes(fn)`, `ctx.functions`,
   `ctx.sensitive_calls`, `ctx.tool_functions` (entry points),
   `ctx.in_scope(fn)` (agent-reachable), `ctx.is_entry(fn)`,
   `ctx.is_gated(fn)`, `ctx.approval` and `ctx.parents` are all built from
   one shared walk. A rule that walks the tree again is a rule that makes
   every scan slower.
5. Judge only reachable code: skip sites where `not ctx.in_scope(fn)`,
   unless the rule is about deployment settings (as permissive defaults
   is). Fill `column` and `function` (`ctx.qualname(fn)`) on every finding.
6. Add tests: `tests/test_rule_<name>.py`, plus a case in
   `tests/fixtures/vulnerable_server.py` (must fire) and, if the rule can
   pass, `tests/fixtures/clean_server.py` (must not fire). If reviewers can
   judge the rule independently of its own definition, add it to
   `MEASURED_RULES` in `benchmarks/run.py` and label the corpus.

Invariants your rule must keep, because scoring relies on them:

- `sites == passed + len(findings)`. Every applicable place is either
  compliant or has exactly one finding.
- Zero sites means the rule did not apply, which scores full marks. Never
  report a site you cannot judge. Note the scan-level consequence: if
  *every* rule reports zero sites the scan has proved nothing, so its
  verdict is `INCOMPLETE` rather than a vacuous 100/100 `PASS`. A rule that
  invents sites to avoid looking inapplicable breaks that guarantee.
- `critical=True` only for consequences that must fail a build on their
  own. A new source of critical findings means updating
  `CRITICAL_GATE_RULES` in `scoring.py`, or the verdict will not know the
  gate depends on your rule.

## Vocabulary

Sink tables live in `checkride/astutils.py`. `SENSITIVE_EXACT` requires a
full dotted name; `SENSITIVE_SUFFIX` matches a method name on *any*
receiver, so an entry there must be distinctive enough that a false
positive is implausible (`rmtree`, `delete_bucket`, `transfer_funds` — not
`run`, `delete`, `send`). A false positive on a critical sink fails
someone's build for no reason, which costs more trust than a missed
finding does.

## The benchmark

`python benchmarks/run.py` must pass. It fails whenever checkride's output
differs from the corpus labels, in either direction, so:

- **A detection change** that adds or removes findings needs the matching
  label change in the same commit: `expect` for a real issue now caught,
  remove a `known-fp` that is now fixed, turn a `known-miss` into `expect`.
- **Labels state what a reviewer would conclude**, never what checkride
  currently does. If the tool is wrong, the label is `known-fp` or
  `known-miss` and the case stays in the numbers.
- **A reported false positive or negative** is best turned into a corpus
  case (or a `known_limits.py` entry) as well as a unit test.

See [benchmarks/README.md](benchmarks/README.md).

## Releasing

1. Bump `__version__` in `checkride/__init__.py` and date the version's
   section in `CHANGELOG.md`.
2. Update the version in the README's Action and pre-commit examples.
3. Merge to `main`, then tag: `git tag -a vX.Y.Z -m "checkride X.Y.Z"` and
   `git push origin vX.Y.Z`.
4. Publish a GitHub Release for the tag. `.github/workflows/release.yml`
   checks the tag matches the package version, runs the tests and the
   benchmark, and publishes to PyPI through trusted publishing. PyPI
   versions are permanent: a mistake needs a new version, not a re-upload.

## Pull requests

- Branch from `main`, one logical change per commit.
- `python -m pytest tests/ -q`, `mypy`, `ruff check checkride/ tests/
  benchmarks/` and `python benchmarks/run.py` green, and CI green on every
  matrix entry —
  including Windows, where path handling and glob case sensitivity have
  broken before.
- Update `CHANGELOG.md` under `Unreleased`.
- Update `RULES.md` if you changed what a rule catches or misses.
