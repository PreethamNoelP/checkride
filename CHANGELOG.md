# Changelog

All notable changes to checkride (named agentgauge until 0.5.0) are
documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [semantic versioning](https://semver.org/). For a
scanner, "breaking" includes anything that can change a repository's score
or verdict, since that is what CI gates on — those are called out
explicitly.

## [Unreleased]

### Fixed

- **SARIF file locations are percent-encoded.** `artifactLocation.uri` is a
  URI reference, so a path containing a space, `#` or `%` (a checkout under
  `My Project/`, say) was emitted raw and resolved to no file in code
  scanning.
- A JSON MCP config named directly as the target is no longer also parsed as
  Python and reported as a "Python file".

### Documentation

- The README's code-scanning example uses `upload-sarif@v4`.

## [0.5.1] — 2026-10-10

### Fixed

- **Directories named `env`, `build` or `dist` are no longer skipped
  silently.** They were pruned by name, so an agent tool under `src/env/`
  was never scanned. Virtual environments are now recognized by
  `pyvenv.cfg` (whatever their name), and `build/` / `dist/` are pruned only
  at the scan root beside a `pyproject.toml` / `setup.py` / `setup.cfg`, with
  a warning. Repositories that had such a directory can see new findings.
- The directory walk prunes before descending, instead of listing every
  file under `node_modules` and `.venv` and filtering afterwards.

### Added

- Scan progress on stderr when it is a terminal (never for pipes, CI logs
  or `--json` / `--sarif` consumers).

## [0.5.0] — 2026-10-04

### Changed — renamed from agentgauge to checkride (breaking)

The PyPI name `agentgauge` collides with an existing, unrelated AI-agent
project, `agent-gauge` (PyPI treats the two spellings as the same name and
would refuse the upload, and users could confuse them). The project is now
**checkride** — after the test a pilot must pass before being trusted with
a plane.

- Install and run: `pip install checkride`, then `checkride .`
- Python package: `import checkride`
- Configuration table: `[tool.checkride]` (was `[tool.agentgauge]`)
- Suppression comments: `# checkride: ignore[rule-id]` (was
  `# agentgauge: ignore`)
- SARIF: tool name `checkride`, fingerprint key `checkride/v1`
- GitHub Action and pre-commit hook: `PreethamNoelP/checkride`, hook id
  `checkride`

No detection or scoring changes. Releases 0.2.0–0.4.0 below were tagged
under the old name and never published to PyPI.

## [0.4.0] — 2026-10-03

The first release intended for PyPI (0.3.0 was tagged but not published).
Every change here can change verdicts, toward finding more real issues.

### Changed

- **Approval polarity is checked.** A sensitive call must sit where
  approval was *given*: `if approved(): return` before the call, `if not
  approved(): <call>`, `answer == "no"` and `if user_declined:` no longer
  count as gates. Unreadable conditions are still accepted rather than
  guessed.
- **Rate limiters must be used**: called, applied as a decorator, or
  entered with `with`. A name that is only assigned, a parameter or a
  keyword argument no longer passes.

### Added

- **Sinks without a static name:** calls through a dispatch table holding a
  sensitive function (`ACTIONS[name](p)`, `ACTIONS.get(name)(p)`), and
  computed attributes on dangerous modules (`getattr(os, name)(cmd)`). The
  parameter choosing the function is an unvalidated input too.
- **Approval decorators recognized by behavior:** a decorator or decorator
  factory in the scanned code whose wrapper asks before calling the wrapped
  function gates every function it decorates, in any file, whatever its
  name.
- Benchmark: every former known miss is now detected. 84.7% precision,
  100% recall on the corpus, 14/14 critical verdicts.

## [0.3.0] — 2026-10-03

Tagged, not published to PyPI.

### Changed

- **License: Apache License 2.0** (was MIT). The same permissions, plus an
  explicit patent grant and contribution terms. 0.2.0 and earlier remain
  available under MIT.
- **Input validation finds inputs by where they flow** (changes scores). A
  tool parameter of any name that reaches a file path (`open`, `Path`,
  `os.path.join`, `ROOT / name`) or a string-interpreting sink (file
  delete, shell, code, SQL) is now an input. Found by testing a
  tutorial-style notes server, whose `read_note(name)` path traversal was
  invisible because the parameter was not called `path`.

### Added

- `.github/workflows/release.yml`: publish to PyPI from a GitHub Release
  via trusted publishing, after checking the tag matches the version and
  re-running the tests and benchmark.
- A clear message when the scanned directory is a JavaScript/TypeScript
  project, which is not supported yet.
- `CODE_OF_CONDUCT.md`, a pull request template, and issue-chooser links.
- README rewritten for first-time readers and the PyPI page; package
  metadata with a clearer summary, keywords and classifiers.
- Benchmark corpus: `notes_server.py`. Now 83.3% precision, 93.8% recall,
  14/14 critical verdicts.

## [0.2.0] — 2026-10-03

Everything in this section changes scores and verdicts. Most repositories
will see different results; the reasons are listed in order of impact.

### Changed — what is judged (breaking)

- **Only agent-reachable code is judged.** Tool entry points are found from
  tool decorators, registration by reference (`add_tool`, `Tool(func=...)`,
  `FunctionTool.from_defaults`, `tools=[...]`, `TOOLS` tables), class-based
  tools and config, and a two-pass scan follows their calls across files
  (absolute and relative imports, `self.` methods, constructors,
  callbacks). Sinks nothing reaches are counted as
  `out_of_scope_sensitive_calls` and not judged. Previously every sink in a
  repository was an agent action: `pip`, `requests` and `black` all failed
  critical on their own cache and build code; they now report zero
  critical findings. `scope = "all"` / `--scope all` keeps the old
  population.
- **A scan with no recognized tool entry point is `INCOMPLETE`**, with a
  warning naming the config keys that teach agentgauge your framework.
- **Rules 2, 3 and 5 apply to tool entry points**, not to every function
  with a sink; audit logging and rate limiting are satisfied by anything the
  tool calls.

### Changed — human oversight (breaking)

- **Approval must dominate the sink.** It has to run before the call on the
  way to it: an enclosing condition, an earlier guard statement, an
  approval decorator, or the same at every reachable call site of the
  helper containing the sink. Each of these used to turn an ungated
  `subprocess.run(cmd, shell=True)` into `PASS` and now fails critical: an
  approval check after the sink; a tool parameter named `confirm` (the
  model sets it); `approved = True`; `if settings.auto_approve:`;
  `user.is_authorized(...)`; a call into `humanize`;
  `extra_approval_markers = ["run"]`.
- Vocabulary: `authoriz` and the bare `human` substring are removed;
  MCP elicitation (`ctx.elicit`) and ask-a-human phrasing are added.
  Framework-injected context (`ctx: Context`, `RunContextWrapper`) is not
  treated as a model-controlled parameter.

### Changed — other rules (breaking)

- **Input validation** needs a real test or validator before use. Bare
  truthiness, `is None`, `isinstance()` and approval calls no longer count;
  a sensitive call is never a validator (`subprocess.check_output(cmd)`
  validated `cmd` because of "check"); `Annotated[str, Field()]` without a
  constraint no longer counts. New inputs: camelCase names, Pydantic
  input-model fields, low-level `arguments["path"]` reads. New evidence:
  `Enum` types, constrained `Field`/`StringConstraints`, Pydantic
  validators, `safe_*`/`secure_*`/`ensure_*` helpers, one assignment hop.
- **Audit logging** needs a logger-shaped call: `math.log`, `np.log` and
  friends no longer count; MCP `ctx.info(...)` does.
- **Error handling** reports a broad handler that only discards the error,
  and a `try`/`finally` with no handler; it accepts handling at every call
  site of a helper.

### Added

- **New sinks:** dynamic SQL on a DB handle (`sql exec`, critical);
  payment-SDK writes (`stripe.Refund.create`, `client.payment_intents
  .confirm`); HTTP writes to payment API hosts; Kubernetes deletes;
  `getattr(os, "system")`, `__import__`, `importlib.import_module` with
  constant arguments. A call that resolves to a scanned function is no
  longer itself a sink.
- **`FAIL_SCORE` verdict** and a default score floor: `min_score` defaults
  to 70 (`0` disables). Previously the recommended verdict-only gate passed
  a 35/100 scan.
- **`accepted_risks`** — reviewed, reasoned exceptions in config that clear
  a specific finding (critical included), are listed with their reason in
  every report and as SARIF `external` suppressions; stale entries warn;
  `--ignore-accepted-risks` turns them off.
- Config: `scope`, `extra_tool_decorators`, `extra_tool_entry_points`;
  `min_score` range check; approval markers that match a sink name are
  rejected. CLI: `--scope`, `--ignore-accepted-risks`. Action: `scope`.
- Findings carry `column` and `function`. JSON adds `min_score`, `scope`,
  `tool_functions`, `out_of_scope_sensitive_calls`, `accepted_risks`.
- **SARIF:** line-independent `partialFingerprints`, columns, logical
  locations, `helpUri`, help text, GitHub `security-severity`, suppressed
  and accepted findings as results with `suppressions`.
- **Benchmark:** a labelled corpus (`benchmarks/`) with per-rule
  precision/recall, gated in CI. Current: 83.0% precision, 92.9% recall over
  the four measured rules; 13/13 critical verdicts.
- CI builds the wheel and runs it from a clean virtualenv.
- TLS-verification flags: `verify_ssl_certs`, `check_hostname`,
  `validate_certs`, ... set to `False` are permissive defaults.
- **`--no-config`** (Action: `no-config`) ignores the scanned repository's
  own `pyproject.toml`. Use it on code you do not control: the config can
  exclude files, disable rules and accept risks. An `exclude` that hides a
  file containing a sensitive call now produces a warning naming the file.

### Fixed

- Tools defined under `try`/`if` blocks at module or class level were not
  seen.
- Invariant tests now enforce the README's privacy table: the only write is
  the requested baseline, the environment is never read, and the documented
  import list matches the code.
- **Scan time is linear in file size.** A single file of many tiny tool
  functions (800 KB: 83 s) and an `mcp.json` of many flagged booleans
  (4.9 MB: over two minutes) were quadratic and stayed under the 5 MB size
  cap, so a pull request could stall CI. Both now finish in seconds.
- **Directory junctions no longer leave the scan root.** On Windows,
  pathlib descends through junctions, which `is_symlink()` does not report;
  files outside the target were read and their identifiers reported. They
  are now refused and the verdict is `INCOMPLETE`.
- A file name the console cannot encode no longer ends the human report
  with a traceback.
- The Action passes the target after `--`, so a `path` beginning with a dash
  is never read as an option, and `pyproject.toml` pins the build backend
  to an exact version.

### Earlier changes since 0.1.0

### Removed

- The vendored in-browser playground (`docs/`, including the hand-synced
  `docs/vendor/` copy of the package and `tests/test_playground_assets.py`,
  the test that kept the copy honest). It was never published — `docs/`
  had no GitHub Pages workflow, and `docs/README.md` said so itself — and a
  manually-`cp`'d second copy of six modules is exactly the kind of drift
  risk this project's own `RULES.md` would flag in someone else's repo.
  `[tool.agentgauge] exclude` and `[tool.ruff] extend-exclude` both drop
  their `docs/vendor` entries accordingly.

### Added

- **Baseline mode.** `--baseline PATH` gates the exit code only on findings
  not already recorded in that file, and `--update-baseline` writes the
  current non-critical findings to it — the roadmap item this file already
  flagged as needing a decision first ("a baseline that can silence a
  critical finding would be the one thing this tool promises cannot
  happen"). Resolved structurally: `--update-baseline` drops every critical
  finding unconditionally, so even a hand-edited baseline claiming to
  contain one has no effect, and `FAIL_CRITICAL`/`--min-score` are checked
  exactly as without a baseline before the baseline's own gate applies.
  Identity is by count per `(file, rule, message)`, not by line or full
  identity — a plain line-based key would falsely flag every finding below
  an unrelated edit as "new" on every scan; a plain `(file, rule, message)`
  key would collide for rules whose message carries no per-site detail
  (rule 4's unconditional-loop finding is a static string). See RULES.md's
  "Baseline mode" section for the full algorithm and its documented
  imprecision. The score and verdict are **never** affected by a baseline —
  only the exit code and which findings are printed. New JSON fields:
  `baseline_applied`, `baseline_new`; deliberately not added to `--sarif`
  (redundant with code-scanning's own new-vs-existing tracking).

- **JSON config-file scanning.** Every scan now also checks known MCP
  client config filenames (`claude_desktop_config.json`, `mcp.json`,
  `.mcp.json`, `cline_mcp_settings.json`, `mcp_settings.json`, extendable
  via `extra_config_filenames`) for permissive-default flags — this closes
  rule 6's largest documented blind spot, since real deployments set
  `auto_approve`-shaped flags in JSON, not Python. Findings merge into the
  existing "Permissive defaults" category (same rule id, same weight) —
  this is not a seventh rule, and the 100-point model is unchanged.
  `config_files_scanned` is a new field in the JSON/human/SARIF report.
  `[tool.agentgauge] exclude` and `[tool.ruff]`-style `.venv`/`node_modules`
  skip-dirs apply to config files exactly as they already do to `.py`
  files, via the same shared matching (`agentgauge/fswalk.py`, extracted
  from `scanner.py` so the JSON scanner could reuse it without a circular
  import).

### Fixed

- **A directory containing only a recognized MCP config file (no `.py`
  files at all) was rejected as "zero evidence" and exited 2.** The
  zero-evidence guard checked `files_scanned` alone, which only counts
  Python files; it now also accepts `config_files_scanned` as real
  evidence. Found while smoke-testing the config-file scanner above.

### Changed

- README examples for the GitHub Action and pre-commit hook now show the
  recommended verdict-only gate (no `min-score`) as the primary form, with
  `min-score` as a clearly-labeled optional stricter floor. The previous
  examples set `min-score: "70"` by default, which contradicted both
  `action.yml`'s own description ("Left empty, only the verdict gates the
  build — which is the recommended setup") and this file's own "What makes
  it different" section ("the verdict, not the score, is what belongs in a
  CI gate").

### Fixed — the verdict (this changes CI outcomes)

- **A scan with zero applicable sites reported `PASS`.** Every category
  scores full marks when it never applied, so a repository agentgauge
  recognized nothing in scored exactly 100.0/100 and exited `0` — even
  under `--min-score 100 --fail-on-incomplete`, the strictest invocation
  available. The verdict is now `INCOMPLETE`, which `--fail-on-incomplete`
  turns into a red build.

  Two realistic routes reached this without any hostile intent: an agent
  codebase built on an SDK whose sinks are not in our tables, and an
  `exclude` pattern that happened to cover the only file that mattered.
  The second was the more serious one — `disabled_rules` had already been
  blocked from neutering the gate, but `exclude` could still do it, and
  excluding the deliberately-vulnerable fixture (44 findings,
  `FAIL_CRITICAL`) produced a clean 100.0/100 `PASS`.

  **This can change an existing pipeline from green to red**, and where it
  does, the previous green was not meaningful. If a repository genuinely
  has no agent tool-calling code, drop `--fail-on-incomplete` for it rather
  than treating 100/100 as a governance result.

### Security

- Terminal output escaping covered only C0 controls and DEL, leaving three
  ways for a scanned repository to mislead the person reading the report.
  All three are legal in a POSIX filename, so all three are
  attacker-controlled on an untrusted repo, and SECURITY.md already treats
  output injection as in scope.

  U+202E RIGHT-TO-LEFT OVERRIDE in a file name reverses the rest of the
  line as it renders -- the Trojan Source trick (CVE-2021-42574) pointed at
  the report instead of at source, so a reviewer sees a path, rule id or
  fix that is not the one agentgauge found. Byte 0x9B is CSI to a terminal
  in 8-bit mode, reaching the same repaint-the-screen capability the C0
  range already blocked through a different encoding of it. Zero-width
  characters hide content outright.

  C1 controls, the bidi embedding/override and isolate ranges, and the
  zero-width set are now escaped rather than obeyed.

### Added

- Excluded files are counted and reported: `excluded` in JSON and SARIF, an
  `EXCLUDED BY CONFIG` line in the human report, and a stderr warning.
  Config exclusions do **not** by themselves make a scan `INCOMPLETE` —
  excluding files is a project decision, not a coverage gap — but the
  report no longer hides that they happened.
- `APPLICABLE SITES` is printed next to the governance score. A 100.0 over
  0 sites and a 100.0 over 200 are the same number and entirely different
  claims; the denominator is no longer invisible in the human output.
- A GitHub composite action (`action.yml`) and a pre-commit hook
  (`.pre-commit-hooks.yaml`). The action installs from its own checkout, so
  the version that runs is exactly the ref the caller pinned. A single
  action run both gates the build and writes SARIF, because SARIF output
  already carries the governance exit code.

### Changed

- `mypy --strict` and `ruff` now gate CI, and the package is clean under
  both. agentgauge ships a `py.typed` marker; that marker was previously an
  unverified claim, and `mypy --strict` reported 31 errors against it —
  including two real type mismatches where a `set[str]` was passed to a
  parameter declared `frozenset[str]`.
- Rule vocabulary tables (`LOG_TOKENS`, `VALIDATION_TOKENS`,
  `RISKY_PARAM_TOKENS`, `DANGEROUS_WHEN_TRUE`/`_FALSE`, `CRITICAL_LABELS`,
  `_EXIT_CALLS`) are `frozenset`s. They are module-level constants that
  nothing should mutate, and it makes the set-union types line up.
- Removed a dead `hasattr(ast, "TryStar")` compatibility branch: `TryStar`
  has existed since 3.11, which is this package's floor.
- CI's self-scan gate no longer asserts `--min-score 100
  --fail-on-incomplete` on agentgauge's own source. That gate passed for a
  reason it did not advertise — agentgauge's own source has zero sites, so
  it was asserting arithmetic over an empty set. It now asserts what is
  actually true (no findings, nothing skipped), the clean fixture carries
  the "scores 100 against 24 real sites" claim, and a new gate pins that a
  scan recognizing nothing cannot report `PASS`.

### Performance

- ~15% faster scans, with byte-identical findings, score and verdict.
  `build_import_aliases` made two full `ast.walk` passes over every file
  and now makes one (imports are collected and assignments set aside in the
  same pass, preserving the document-order resolution a rebinding chain
  depends on); `functions` and `sensitive_calls` each walked the whole tree
  and now share a single pass. Measured best-of-5 on a 517-file / 77k-LOC
  corpus: 1.99 s → 1.69 s.
- `RULES.md`'s performance table is re-measured and now states its method.
  The previous figures (~25 s for 123k LOC, ~57 s for a 960-file stdlib
  tree) were roughly 6× high: that workload is millions of tiny `ast.walk`
  calls, which is precisely what a deterministic profiler over-charges.
  The 960-file tree is ~13 s.

### Fixed — detection (these change scores)

- `from subprocess import run; run(cmd, shell=True)`, and every other plain
  `from X import y` sink call, was invisible: the local binding resolved
  only to a bare name, which the suffix table excludes as too generic.
  Such files previously scored 100/100.
- Method calls on a dynamic receiver (`Path(p).unlink()`,
  `clients[key].charge()`) were invisible, because dotted-name resolution
  gave up at the receiver even though the suffix table is
  receiver-agnostic by design.
- The human-oversight rule looked for approval vocabulary anywhere in the
  enclosing subtree, so a module-level sink was satisfied by any unrelated
  function in the same file that mentioned approval — silencing
  `FAIL_CRITICAL`. The signal must now share the call's execution scope.
- An `if`/`while`/`assert` test containing an unrelated call with a
  keyword argument spelled like the approval vocabulary
  (`if configure(require_approval=False):`) satisfied the human-oversight
  rule, because the test-walk picked up keyword-argument names along with
  real identifiers. The bare-statement form of this shape was already
  caught; only the `if`-wrapped form was not. Test expressions now only
  match a directly-referenced name or attribute, not a keyword name.
- New sinks: `pathlib` deletion (`unlink`, `rmdir`), `asyncio`
  subprocesses, the `os.exec*` / `os.spawn*` family,
  `subprocess.getoutput` / `getstatusoutput`, unsafe deserialization
  (`pickle`, `marshal`, `dill`, `yaml.unsafe_load`), bulk remote deletion
  (`delete_bucket`, `delete_many`, `drop_table`, `terminate_instances`),
  and more payment APIs. `yaml.load` is deliberately *not* flagged: the
  `SafeLoader` form is safe and far too common for a critical gate.
- Vocabulary matching is alias-aware in the audit, validation and
  error-handling rules, so `from telemetry import audit_log as al`,
  `from utils import sanitize as scrub` and `import sys as s; s.exit()` no
  longer penalize code that is doing the right thing.
- Permissive defaults now reads string-keyed dict entries:
  `SERVER = {"auto_approve": True}` is the same decision as
  `auto_approve = True`.

### Fixed — the critical gate

- `disabled_rules = ["human-oversight"]` removed the only rule producing
  critical findings, so an ungated `shutil.rmtree` reported `PASS` and
  exited 0. Such a scan is now `INCOMPLETE`, with a warning, and reports
  `critical_gate_active: false`.
- `# agentgauge: ignore[]` and `# agentgauge: ignore[bad id!]` failed to
  match the bracketed form of the marker, fell back to the bare `ignore`
  form, and silently suppressed *every* rule on the line. A malformed
  marker now suppresses nothing and is reported.
- `extra_approval_markers = ["e"]` made every call name containing an "e"
  count as an approval check. Vocabulary entries must now be at least
  three characters.

### Fixed — scanning and paths

- Skip directories (`build`, `dist`, `venv`, …) were matched against
  absolute path components, so a checkout in `~/dev/build/` or
  `C:\...\dist\` skipped every file and exited 2.
- Exclude patterns used `fnmatch`, which normalizes case through
  `os.path.normcase` — the same config excluded different files on Windows
  than on Linux. Now `fnmatchcase`, with `**/`-prefixed, trailing-slash and
  bare-directory patterns behaving as documented.
- Findings were reported relative to the scan root, so `agentgauge src/`
  emitted `server.py` for `src/server.py` and no code-scanning dashboard
  could resolve the SARIF result. Paths are now relative to the working
  directory when the file is under it.
- Sources with NUL bytes, unknown PEP 263 encodings, or a size past
  `MAX_FILE_BYTES` (5 MB) are skipped rather than ending the scan.
- Skip reasons no longer embed absolute paths, so the same commit produces
  the same report on every machine. Neither does the reported config source:
  `config_source` in JSON and in the SARIF invocation, and every
  `ConfigError` message, now name the file relative to the working directory
  when it is under it.
- Symlinks pointing outside the scan root are no longer followed. A scanned
  repository is untrusted, and a `*.py` file that is really a link to
  `~/.aws/credentials` should not be read. In-tree symlinks are still
  followed; a refusal is reported, so it shows up as `INCOMPLETE` rather
  than as silently reduced coverage.

### Added

- `--version`.
- `--fail-on-incomplete`: exit 1 on an `INCOMPLETE` verdict. Previously a
  file that failed to parse shrank coverage while CI stayed green.
- The config file in effect is reported in the human output, in JSON
  (`config_source`) and in the SARIF invocation. Discovery deliberately
  does not search upwards, which made an ignored `[tool.agentgauge]` table
  invisible.
- `warnings` in the report: malformed and ineffective suppressions,
  disabled gate rules, and scans where no category had a single applicable
  site (`total_sites: 0`, where 100/100 means "nothing to check", not
  "well governed").
- SARIF: driver version, rule indices, and an `invocations` record carrying
  skipped files and scan warnings, which a results-only view dropped
  entirely.
- `py.typed` marker, for third-party rules written against `FileContext`.
- `.github/dependabot.yml`, and CI actions pinned to commit SHAs rather than
  movable major tags, with `permissions: contents: read` declared at the top
  of the workflow instead of inherited from a repository setting.

### Changed

- Unrecognized `[tool.agentgauge]` keys and unknown ids in
  `disabled_rules` are errors (exit 2) instead of silent no-ops.
- `min_score = true` is rejected; it previously became a threshold of 1.0.
- Control characters from scanned input are escaped before printing.
- A closed stdout pipe (`agentgauge . --json | head`) no longer raises
  `BrokenPipeError` over the exit code.
- Finding order includes rule and message, so two findings on one line
  cannot swap places between runs of the same commit.
- `is_tool_function` was split: `has_tool_decorator` is the decorator half,
  and `FileContext.tool_functions` is the cached whole-file answer rules
  should use. `FileContext.parents` is now a lazily built property rather
  than a constructor argument.
- Performance: 123k LOC of dense tool code, 59s to 25s; CPython's own
  stdlib (960 files), 64s to 57s.

## [0.1.0]

First release: six weighted governance categories, site-based scoring, the
`PASS` / `FAIL_CRITICAL` / `INCOMPLETE` verdict, `[tool.agentgauge]`
configuration, inline suppression, import-alias resolution, and JSON and
SARIF 2.1.0 output.
