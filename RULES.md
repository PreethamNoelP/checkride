# checkride rules

Every rule is a *heuristic*: a static approximation of a governance property
that really depends on runtime behavior. This document states each one
precisely, including what it will **not** catch, so you can decide how much
to trust a finding or a pass. Measured accuracy is in
[benchmarks/README.md](benchmarks/README.md).

## Contents

- [What gets judged: tool entry points and reachability](#what-gets-judged)
- [Scoring and verdicts](#scoring-and-verdicts)
- [Sensitive calls](#sensitive-calls)
- [Rule 1 — Human oversight](#human-oversight)
- [Rule 2 — Audit logging](#audit-logging)
- [Rule 3 — Rate limiting](#rate-limiting)
- [Rule 4 — Error handling](#error-handling)
- [Rule 5 — Tool scope & input validation](#input-validation)
- [Rule 6 — Permissive defaults](#permissive-defaults)
- [What checkride reads, and what it skips](#what-checkride-reads)
- [Configuration](#configuration)
- [Accepted risks, suppressions and baselines](#accepted-risks-suppressions-and-baselines)
- [Output formats](#output-formats)
- [Performance](#performance)

<a id="what-gets-judged"></a>
## What gets judged: tool entry points and reachability

A destructive call is an *agent* risk only if a model can reach it. A build
script that runs `rm -rf build/` is not an agent tool, and treating it as
one makes every real repository fail. So checkride first works out which
functions a model can call, then judges exactly the code those functions
reach.

**Tool entry points** — functions the model calls directly:

| Shape | Examples |
|---|---|
| A decorator naming a tool | `@mcp.tool()`, `@tool`, `@tool("name")`, `@server.call_tool()`, `@function_tool`, `@agent.tool_plain`, `@kernel_function`, `@register_for_llm()` |
| Registration by reference | `mcp.add_tool(fn)`, `Tool(func=fn)`, `FunctionTool.from_defaults(fn=fn)`, `StructuredTool.from_function(fn)`, `register_function(fn, ...)`, any call with `tools=[...]`, `functions=[...]` or `function_map={...}` |
| A tool table | module-level `TOOLS = [fn, ...]`, `tool_map = {"name": fn}` |
| A class-based tool | `run`, `_run`, `_arun`, `invoke`, `__call__`, `call`, `execute`, `forward` on a class whose base names a tool (`BaseTool`, `Tool`) |
| Configuration | `extra_tool_decorators`, `extra_tool_entry_points` |

Abstract methods, `...`/`pass`/`raise NotImplementedError` stubs and
`@property` accessors are never entry points.

**Reachability.** Everything an entry point calls is in scope, transitively
and across files: local names, `self.method()`, module attributes through
imports (absolute and relative), class constructors, and functions passed as
callbacks (`asyncio.to_thread(helper)`). A method call on an unknown receiver
links to every same-named function in the same file — an over-approximation
that errs toward judging more code, never less. A call that resolves to a
scanned function is not itself treated as a sink; the sinks inside that
function are judged where they are.

Code no tool reaches — module-level statements, maintenance scripts,
unreferenced helpers — is **not judged**, and is counted in every report as
`out_of_scope_sensitive_calls` ("NOT AGENT-REACHABLE" in human output).

`scope = "all"` (or `--scope all`) restores the conservative alternative:
every function that performs a sensitive action is a tool, and module-level
code is judged too.

<a id="scoring-and-verdicts"></a>
## Scoring and verdicts

Each rule reports **sites** (places it applied), **passed** (compliant
sites) and **findings** (one per failing site, with a fix). Category points
are `weight × passed / sites`; a category with no sites scores full marks.

| Category | Weight | Sites | Evidence |
|---|---|---|---|
| Human oversight | 25 | reachable sensitive calls | approval check that dominates the call |
| Audit logging | 20 | tool entry points | a logging call in the tool or anything it calls |
| Rate limiting | 15 | tool entry points | rate-limit vocabulary in the tool or anything it calls |
| Error handling | 15 | reachable `while True` loops and sensitive calls | AST structure |
| Tool scope & input validation | 15 | risky tool inputs | a real test or validator before use, or a constraining type |
| Permissive defaults | 10 | governance-flag bindings | literal values |

The **verdict** is the output that belongs in a CI gate:

| Verdict | Meaning | Exit |
|---|---|---|
| `FAIL_CRITICAL` | an agent-reachable critical action (file delete, shell exec, code exec, dynamic SQL, payment, remote delete) has no approval check before it | 1 |
| `FAIL_SCORE` | no critical finding, but the score is below `min_score` (default **70**; `0` disables) | 1 |
| `INCOMPLETE` | the scan cannot support a PASS: a file could not be parsed, the human-oversight rule is disabled, nothing applicable was found, or no tool entry point was recognized | 0, or 1 with `--fail-on-incomplete` |
| `PASS` | none of the above | 0 |

Precedence is top to bottom. Two things never change a verdict: averaging
(99 governed payment tools cannot dilute one ungated one — that is why the
verdict exists separately from the score), and inline suppressions or
baselines on critical findings. The only way to clear a critical finding
without fixing it is a reviewed [accepted risk](#accepted-risks).

**How much to trust the score.** Rules 1, 4, 5 and 6 judge structure and
values; rules 2 and 3 (35 points) check that a logging call is made and a
rate limiter is invoked, not that what is logged or the limits chosen are
right. The weights are
considered judgement, not fitted to data. Treat the score as a trend line and
a floor a team agrees on, not as a certification.

<a id="sensitive-calls"></a>
## Sensitive calls

Defined in `checkride/astutils.py`. Every label below is **critical**.

| Label | Detected as |
|---|---|
| file delete | `os.remove`/`unlink`/`rmdir`/`removedirs`/`truncate`, `shutil.rmtree`; `.rmtree()`, `.unlink()`, `.rmdir()`, `.delete_file()`, `.remove_directory()` on any receiver |
| shell exec | `os.system`, `os.popen`, `subprocess.*`, `os.exec*`, `os.spawn*`, `os.posix_spawn*`, `pty.spawn`, `asyncio.create_subprocess_*`; `.Popen()`, `.check_output()` on any receiver |
| code exec | `eval`, `exec`, `pickle.load(s)`, `marshal.load(s)`, `dill.load(s)`, `yaml.unsafe_load` |
| sql exec | `execute`/`executemany`/`executescript`/`exec_driver_sql` on a DB-handle-shaped receiver (`cursor`, `conn`, `db`, `session`, `engine`, ...) **with a non-constant query** |
| payment | `.charge()`, `.refund()`, `.payout()`, `.create_payment_intent()`, `.transfer_funds()`, ...; a money-moving method (`create`, `capture`, `confirm`, `sale`, ...) on a payment-resource receiver (`stripe.Refund`, `client.payment_intents`, `gateway.transaction`); `post`/`put`/`patch`/`request` to a known payment API host (Stripe, PayPal, Square, Braintree, Adyen, Razorpay, ...) |
| remote delete | `requests.delete`, `httpx.delete`; `.delete_object(s)()`, `.delete_bucket()`, `.delete_many()`, `.drop_table()`, `.terminate_instances()`, Kubernetes `delete_namespaced_*`/`delete_collection_*`/`delete_cluster_*` |

**Name resolution.** Calls resolve through a per-file alias map:
`import subprocess as sp`, `from shutil import rmtree`, one hop of rebinding
(`rm = shutil.rmtree`), and constant-argument indirection
(`getattr(os, "system")`, `__import__("subprocess")`,
`importlib.import_module("shutil")`). Queries and URLs are read through
literals, f-string and `+` fragments, and module names bound only to string
literals (`QUERY = "SELECT ..."`, `STRIPE_URL = "https://api.stripe.com"`).

**Deliberate non-entries.** Generic method names (`run`, `call`, `delete`,
`drop`, `send`, `system`) on unknown receivers; `yaml.load` (safe with
`SafeLoader` and ubiquitous); `open(path, "w")`; HTTP `GET`s; constant,
parameterized SQL.

**Sinks without a static name.** A call through a dispatch table holding a
sensitive function (`ACTIONS = {"rm": shutil.rmtree}` then
`ACTIONS[name](p)` or `ACTIONS.get(name)(p)`) takes the most severe label
in the table; a computed attribute on a dangerous module
(`getattr(os, name)(cmd)`) takes that module's worst member's label.

**Limits shared by every rule.** A sink reached through a function's return
value (`get_deleter()(p)`), a table built at run time, or a star import is
invisible. Aliasing is one flat map
per file, so a local variable shadowing an imported name still resolves to
the import. Python only: TypeScript/JavaScript MCP servers are not read.

<a id="human-oversight"></a>
## Rule 1 — Human oversight (`human-oversight`, 25 pts)

**Every reachable sensitive call must be dominated by a human-approval
check** — one that runs before it, in its own execution scope, on the way to
it. Implemented in `checkride/approval.py`.

A call is gated if any of these holds:

1. It sits inside an `if`/`while`/conditional expression, a `with` block, an
   `and` chain or a comprehension filter whose condition mentions approval:
   `if request_approval(p): rmtree(p)`.
2. An earlier statement in an enclosing block is a guard: `if not
   approved(p): return` (any branch that returns, raises, breaks or exits),
   `assert human_review(p)`, or a bare call to an approval function —
   `require_approval(p)`, `await ctx.confirm(p)` — which is assumed to raise
   on denial.
3. The enclosing function has an approval decorator — named for approval
   (`@requires_approval`), or defined in the scanned code with a wrapper
   that asks before calling the function it wraps (`@policy_checked`,
   including decorator factories), in any file.
4. It lives in a helper, and **every reachable call path** into that helper
   is itself gated. Call cycles are never gated by assumption.

*Mentions approval* means a call or name containing `approv`, `confirm` or
`consent`; MCP elicitation (`ctx.elicit`); ask-a-human phrasing
(`ask_human`, `human_review`, `human_in_the_loop`, `sign_off`, ...); builtin
`input()`; `extra_approval_markers`; or a variable assigned from any of
those (`answer = await ctx.elicit(...)`, `ok = request_approval(p)`), up to
two assignment hops.

**Never counts as approval:**

- the sensitive call itself, or anything inside it;
- **a tool's own parameters** — `def delete(path, confirm: bool)` with `if
  not confirm: return` is the model approving itself. Framework-injected
  context (`ctx: Context`, `RunContextWrapper`, `ToolContext`) is not a
  model-chosen parameter, so `await ctx.elicit(...)` does count. A finding
  caused by this says "gated only by a tool argument, which the model
  chooses";
- permissive flags (`if settings.auto_approve:`, `if SKIP_CONFIRMATION:`);
- names bound only to constants (`approved = True; if approved:`);
- machine authorization (`is_authorized`, `authorize`) and lookalikes
  (`humanize`, `is_human_readable`);
- a check after the call, in a sibling branch, or in a nested function;
- a check on the wrong side: the call must sit where approval was *given*.
  `if approved(p): return` followed by the call, `if not approved(p):
  <call>`, `answer == "no"` and `if user_declined:` all act when approval
  was refused. A condition whose polarity cannot be read is accepted
  rather than guessed.

**Known limits.** Approval enforced by a decorator or middleware from a
library that is not scanned, with a name that says nothing (`@guarded`), is
a false failure — name it via `extra_approval_markers`, or record an
[accepted risk](#accepted-risks). A read-only command through a shared
subprocess helper (`git log`) is judged like any other shell exec. Values
are followed through at most two assignments.

<a id="audit-logging"></a>
## Rule 2 — Audit logging (`audit-logging`, 20 pts)

**Every tool entry point must record what it did** — in its own body or in
any function it calls. A logging call is one of:

- anything on `logging`, `structlog` or `loguru`;
- a level method (`info`, `warning`, `error`, `exception`, `log`, `write`,
  `record`, ...) on a logger-named receiver (`logger`, `log`, `audit`,
  `self.logger`);
- MCP client logging (`ctx.info(...)`, `await ctx.error(...)`);
- a function named for it (`audit_log`, `log_event`, `record_audit`), or a
  call matching `extra_log_tokens`.

Math functions named `log` (`math.log`, `np.log`, `torch.log`, `log10`,
`logsumexp`, ...) never count; `login()` never counted.

**Known limits.** Any logging call passes, however uninformative; the rule
cannot check that the actor, action and arguments are recorded.

<a id="rate-limiting"></a>
## Rule 3 — Rate limiting (`rate-limiting`, 15 pts)

**Every tool entry point must use a rate limiter** — in its body, its
decorators, or anything it calls. *Use* means the limiter is called
(`limiter.acquire()`, `await throttle.wait()`), applied as a decorator
(`@limiter.limit("10/minute")`, the `ratelimit` library's `@limits`), or
entered as a context manager (`async with rate_limiter:`). A name that is
only assigned (`rate_limiter = None`), a parameter or a keyword argument
does not count. Limiter vocabulary: identifiers containing `ratelimit`,
`throttle` or `limiter` (underscores ignored), plus
`extra_rate_limit_markers`. Bare `limit` does not count (pagination, SQL
`LIMIT`).

**Known limits.** The rule confirms a limiter is invoked, not that its
limits are sensible. Limiting done by a gateway is invisible — set
`assume_external_rate_limiting = true`, which marks the category not
applicable.

<a id="error-handling"></a>
## Rule 4 — Error handling (`error-handling`, 15 pts)

Two kinds of reachable sites:

1. **Unconditional loops** (`while True`, `while 1`) must contain an exit
   that leaves *this* loop: a `break` at its own level (not a nested
   loop's), a `return`/`raise` not inside a nested function, or `sys.exit`.
2. **Sensitive calls** must sit in the **body** of a `try` whose handlers
   deal with the failure — in their own function, or at every reachable
   call site of the helper that contains them ("helper raises, caller
   handles"). Handlers, `else` and `finally` are not protected regions; a
   `try`/`finally` with no handler does not count; and a broad handler
   (`except:`, `except Exception`) whose body only discards the error
   (`pass`, `...`, `continue`) is reported as swallowing it. Catching a
   specific exception and ignoring it on purpose (`except
   FileNotFoundError: pass`) is fine.

**Known limits.** Termination is undecidable; only syntactically
unconditional loops are checked (`while not done:` is not). An unreachable
exit (`if False: break`) passes.

<a id="input-validation"></a>
## Rule 5 — Tool scope & input validation (`input-validation`, 15 pts)

**Model-supplied inputs must be validated before they reach a sensitive call
or a file path.** Inputs are:

- parameters of tool entry points whose name has a risky token — `path`,
  `file`, `filename`, `dir`, `directory`, `folder`, `cmd`, `command`,
  `shell`, `script`, `query`, `sql`, `url`, `uri`, `host`, `endpoint`,
  `target`, `dest`, `destination`, plus `extra_risky_params` — split on
  `.`, `_` and camelCase (`filePath`, `sqlQuery`);
- parameters of any name that flow — directly or through one assignment —
  into building a file path (`open(name)`, `Path(name)`,
  `os.path.join(ROOT, name)`, `ROOT / name` where `ROOT` is a path) or into
  a sink that interprets strings (file delete, shell exec, code exec, SQL).
  `read_note(name)` doing `(NOTES / name).read_text()` is path traversal
  whatever the parameter is called. Not counted: `int`/`float`/`bool`
  parameters, identifiers passed to payment or cloud APIs (those APIs
  authorize them), and input models or `arguments` dicts, whose fields and
  keys are judged individually;
- risky-named fields of a Pydantic-style input model the tool takes as a
  parameter, when the class is defined in the same file;
- risky keys read from a low-level `arguments` dict (`arguments["path"]`,
  `arguments.get("cmd")`).

**Evidence**, any of:

- a constraining type: `Literal[...]`, an `Enum` class, `Annotated[T,
  Field(pattern=..., max_length=..., ge=..., ...)]` (a `Field` with no
  constraint does not count), `StringConstraints`/`constr` with a
  constraint, an `After`/`Before`/`Plain`/`WrapValidator`; for model fields,
  a constrained `Field(...)` default or a `@field_validator`/`@validator`
  naming the field, or any `@model_validator`;
- an `if`/`while`/`assert` that actually tests the value: a comparison,
  membership or method check (`path.startswith(ROOT)`, `cmd in ALLOWED`,
  `Path(p).resolve().is_relative_to(ROOT)`). Bare truthiness (`if path:`),
  `is None` checks, `isinstance()` and approval calls do not count;
- passing it to a validator-named call — `validate`, `sanitize`, `check`,
  `verify`, `allowlist`, `escape`, `quote`, `safe_*`, `secure_*`,
  `ensure_*`, `restrict*`, plus `extra_validation_tokens` — that is not
  itself a sensitive call (`subprocess.check_output(cmd)` validates nothing).

**Ordering.** When the input reaches a sensitive call, the evidence must
start before that call; a sanitizer wrapping the argument
(`run(shlex.quote(cmd))`) counts. One assignment hop is followed: with
`argv = shlex.split(command)`, an allowlist check on `argv[0]` validates
`command`, as long as `command` itself never reaches a sink unvalidated.

**Known limits.** Validators with unrecognized names (`normalize(path)`)
are false failures; extend the vocabulary. A parameter passed as one
element of an argv list (`["git", "commit", "-m", message]`) is reported
even when, as there, no injection is possible — option injection through
argv is a real attack class, so the rule does not try to tell the cases
apart. A risky value in an innocently
named parameter (`p`, `cmdline`) is invisible. Any tested comparison counts,
correct or not. Input models defined in another file are not inspected.

<a id="permissive-defaults"></a>
## Rule 6 — Permissive defaults (`permissive-defaults`, 10 pts)

Sites exist only where a governance knob appears. Every binding of a
recognized flag name to a boolean literal is judged — assignments (including
attributes and annotated assignments), keyword arguments, parameter
defaults, and string-keyed dict entries. Names are compared lowercased with
`_` and `-` removed, so `auto_approve`, `AUTO_APPROVE` and `autoApprove` are
one flag.

- **Must be `False`:** `auto_approve`, `auto_confirm`, `auto_run`,
  `skip_approval`, `skip_confirmation`, `no_confirm`, `allow_all`,
  `trust_all`, `unsafe`, `disable_auth`, `bypass_safety`, ... and
  `extra_dangerous_when_true`.
- **Must be `True`:** `require_approval`, `require_confirmation`,
  `require_auth`, `human_in_the_loop`, `human_review`, `verify`,
  `verify_ssl`, `verify_ssl_certs`, `check_hostname`, `validate_certs`,
  `safe_mode`, `sandbox`, ... and `extra_dangerous_when_false`.

This is the only rule that judges code whether or not a tool reaches it: a
permissive flag is a deployment decision wherever it is written.

**MCP client config files.** `claude_desktop_config.json`, `mcp.json`,
`.mcp.json`, `cline_mcp_settings.json`, `mcp_settings.json` and anything in
`extra_config_filenames` are checked for the same flags bound to JSON
booleans, merged into this category. Quoted strings (`"true"`) and arrays
(`"autoApprove": ["run_command"]`) are not interpreted. An invalid JSON file
is skipped and makes the verdict `INCOMPLETE`.

**Known limits.** Flags are matched by name, so `verify=False` on an
unrelated helper is flagged, and `sandbox=False` in a payment SDK usually
means "production". String values and environment variables
(`os.environ.get("AUTO_APPROVE", "true")`) are invisible, as are `.env` and
YAML files.

<a id="what-checkride-reads"></a>
## What checkride reads, and what it skips

`.py` files under the target in sorted order, plus the MCP config files
above. Nothing is imported, executed or evaluated — `ast.parse` and
`tokenize` only. Recorded in `skipped`, which makes the verdict
`INCOMPLETE`:

- files that do not parse (syntax errors, NUL bytes, unknown PEP 263
  encodings, nesting deep enough to exhaust the parser);
- files over 5 MB (`MAX_FILE_BYTES`) — `ast.parse` builds a tree many times
  the source size, and scanned repositories are untrusted;
- symlinks whose target is outside the scan root or cannot be resolved.

Not scanned and not reported: `.git`, `__pycache__`, `.venv`, `venv`,
`node_modules`, `site-packages`, tool caches, and any directory containing a
`pyvenv.cfg` (a virtual environment, whatever it is named), matched relative
to the scan root.

Not scanned, but reported as a warning: a `build/` or `dist/` directory at
the scan root, next to a `pyproject.toml`, `setup.py` or `setup.cfg` (packaging
output). A directory merely *named* `env`, `build` or `dist` anywhere else is
ordinary source and is scanned.

<a id="configuration"></a>
## Configuration

An optional `[tool.checkride]` table in `pyproject.toml` next to the scan
target (or a file passed with `--config`). No upward search: the report
names the config file it applied, so one that was not picked up is visible.

```toml
[tool.checkride]
min_score = 70                        # PASS threshold; 0 disables; --min-score overrides
scope = "tools"                       # or "all"; --scope overrides
exclude = ["tests/*", "**/generated_*.py", "vendor/"]
disabled_rules = ["rate-limiting"]    # category removed; max score drops below 100
assume_external_rate_limiting = false
extra_tool_decorators = ["expose"]    # @expose marks a tool
extra_tool_entry_points = ["handlers.dispatch"]
extra_approval_markers = ["greenlight"]
extra_log_tokens = ["telemetry"]
extra_rate_limit_markers = ["throughput_cap"]
extra_validation_tokens = ["scrub"]
extra_risky_params = ["secret"]
extra_dangerous_when_true = ["yolo_mode"]
extra_dangerous_when_false = ["least_privilege"]
extra_config_filenames = ["my_client_mcp.json"]

[[tool.checkride.accepted_risks]]
rule = "human-oversight"
file = "src/server.py"
function = "rebuild_index"            # optional; qualified or bare name
call = "subprocess.run"               # optional
reason = "Runs a fixed make target; no model input reaches it (SEC-142)"
```

Validation is strict — these are usage errors (exit 2), not no-ops: an
unknown key; an unknown rule id; a vocabulary entry under three characters;
an approval marker that also matches a sensitive call's name
(`extra_approval_markers = ["run"]` would make `subprocess.run` its own
approval); `min_score` outside 0–100 or not a number; an unknown `scope`; an
accepted risk with an unknown key, a missing `rule`/`file`/`reason`, or a
reason under 15 characters.

**Exclude patterns** match case-sensitively against the path relative to
the scan root: `tests/fixtures/*` (a directory's contents), `**/gen_*.py`
(any depth, including the root), `vendor` or `vendor/` (a directory at any
depth), `*.gen.py` (a basename anywhere). An explicitly named file is always
scanned. Excluded files are counted in every report — an exclude is the
bluntest way to make this tool say nothing, so read a project's `exclude`
list before trusting its result.

**`disabled_rules`** removes a category; the maximum score drops rather than
the rest renormalizing to 100. Disabling `human-oversight` removes the
critical gate entirely, so such a scan is `INCOMPLETE` with
`critical_gate_active: false`, never `PASS`.

<a id="accepted-risks"></a>
<a id="accepted-risks-suppressions-and-baselines"></a>
## Accepted risks, suppressions and baselines

Three ways to live with a finding, deliberately different in strength:

| Mechanism | Scope | Clears a critical finding? | Where it is recorded |
|---|---|---|---|
| `accepted_risks` in config | rule + file (+ function, + call) | **yes** | config file under review; listed with its reason in every report; SARIF `external` suppression |
| `# checkride: ignore[rule-id]` | one line | no — still `FAIL_CRITICAL` | the source line; SARIF `inSource` suppression |
| `--baseline FILE` | the findings that existed when it was written | no — critical findings are never written into a baseline | the baseline file |

**Accepted risks** exist because a static heuristic will sometimes be wrong
about a critical finding, and the alternative — renaming code until the
heuristic stops matching — is worse for everyone. An entry needs a reason
of at least 15 characters, matches by rule and file (a path suffix, so
`server.py` matches `src/server.py`), optionally narrowed by enclosing
function and sink name. The site counts as passed. Every report lists
accepted findings with their reasons; an entry that matches nothing is a
warning; `--ignore-accepted-risks` judges the code as if none existed.

**Inline suppressions** declutter non-critical findings during adoption.
`# checkride: ignore` on a finding's line covers every rule;
`# checkride: ignore[rule-a, rule-b]` only those. A free-text reason may
follow a bracketed list, or follow a bare `ignore` after `--`, `:` or `#`.
The site counts as passed. Markers are read from real comment tokens, never
string literals. A malformed marker (`ignore[]`, `ignore[bad id!]`, `ignore
rate-limiting` without brackets) suppresses nothing and is warned about, as
is one naming a rule that does not exist.

**Baselines** gate only on findings that are new since the baseline was
written; score and verdict are unaffected.

```console
$ checkride . --baseline .checkride-baseline.json --update-baseline   # record today's state
$ checkride . --baseline .checkride-baseline.json                     # CI: fail on new findings
```

A baseline counts findings per `(file, rule, message)`, so an edit that only
shifts line numbers matches, and a new instance of a recurring message is
still caught; among identical findings, which one is "new" is an arbitrary
but stable choice. A missing baseline file is treated as empty, with a
warning; a malformed one is a usage error. Format:

```json
{"version": 1, "findings": [{"file": "server.py", "rule": "audit-logging", "message": "...", "count": 2}]}
```

<a id="output-formats"></a>
## Output formats

**Human** (default): category table, score, verdict, applicable sites,
threshold, tool entry points, out-of-scope sinks, findings with fixes,
accepted risks; warnings on stderr. Text from the scanned repository is
rendered with control, C1, bidi-override and zero-width characters escaped.

**`--json`**: checkride's own shape. Top-level keys and finding keys
(`rule`, `file`, `line`, `column`, `function`, `message`, `fix`,
`critical`) are pinned by tests; keys may be added, not renamed or removed,
without a major version. Includes `tool_functions`,
`out_of_scope_sensitive_calls`, `accepted_risks`, `baseline_new`.

**`--sarif`**: SARIF 2.1.0. Critical findings are `error`, others
`warning`. Results carry columns, the enclosing function as a logical
location, and line-independent `partialFingerprints`. Rule descriptors carry
help text, `helpUri` anchors into this document and GitHub
`security-severity` (human-oversight 9.0, input-validation 7.5,
permissive-defaults 7.0, the rest 4.0). Suppressed and accepted findings are
emitted with SARIF `suppressions`. The invocation lists skipped files and
warnings.

Paths are relative to the working directory, which is what a code-scanning
upload resolves; run checkride from the repository root.

<a id="performance"></a>
## Performance

Two passes: the first summarizes every file (entry points, call edges,
logging), the second runs the rules against the whole-program index. Each
file is walked once per pass into a shared node list, parent map, per-scope
buckets and a definition index. Parsed files are reused between passes
while their total source stays under 8 MB (a kept file costs roughly 40×
its source size, so about 300 MB); beyond that, pass two re-parses each
file and memory stays bounded by one file's AST.

Measured on the same machine against the previous single-pass release
(wall clock, `scan()` only, best of two):

| Corpus | Files | Previous | This version |
|---|---|---|---|
| `llama_index` | 517 | — | 3.5 s |
| `pip` | 487 | 5.5 s | 8.7 s |
| CPython standard library | 960 | 28.0 s | 31.6 s |

A typical MCP server repository (tens of files) scans in well under a
second.
