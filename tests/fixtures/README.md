# Test fixtures — parse-only data, never executed

> **`vulnerable_server.py` is deliberately dangerous code. Do not import it,
> run it, or copy from it.** It exists so that checkride's detection can be
> proven against something realistic.

## What these files are

Two Python files that checkride's test suite and CI **parse** with
`ast.parse`. Nothing here is ever imported, executed, or evaluated — by the
tests, by CI, or by checkride itself, whose entire design forbids executing
the code it reads.

| File | Must score | Purpose |
|---|---|---|
| `vulnerable_server.py` | exactly **0.0 / 100** over 127 sites, verdict `FAIL_CRITICAL` | Every rule must fire. Each tool is a shape some version of checkride, or an obvious implementation of it, scored as clean — including every approval bypass (check after the sink, model-supplied `confirm`, authorization, constants, lookalikes) and path traversal through an innocently named parameter. |
| `clean_server.py` | exactly **100.0 / 100** over 48 sites, zero findings | The false-positive canary: approval through MCP elicitation, helpers gated and protected at their call sites, input models, low-level dispatch. Legitimate governance patterns must never be flagged. |

Both numbers are asserted in `tests/test_integration.py` and gated in CI, so
a detection regression fails the build rather than quietly passing.

## Why `vulnerable_server.py` looks alarming

It contains `eval()`, `pickle.loads()`, `subprocess.run(..., shell=True)`,
`asyncio.create_subprocess_shell()`, model-written SQL, Stripe refunds over
raw HTTP and unguarded `shutil.rmtree()`. Its one module-level
`subprocess.check_call()` is not reachable from any tool and must be
reported as out of scope, not judged. That is the point: a scanner for
ungoverned agent tool-calling code needs a specimen of ungoverned agent
tool-calling code.

Consequences worth knowing:

- **Your security tooling may flag this repository.** Corporate AV, SAST
  scanners, and GitHub code scanning can all raise alerts on this file. Those
  alerts are correct about the code and wrong about the risk — it is inert
  test data.
- **Never copy from it.** If you want an example of how tool code *should*
  look, read `clean_server.py` instead. It is the same operations, properly
  gated: approval check, allowlist or type constraint, rate limiter,
  `try`/`except`, audit log.

## If you are adding a fixture case

- Add the failing shape to `vulnerable_server.py`; confirm the file still
  scores exactly `0.0` (`tests/test_integration.py` asserts it).
- If the rule can also *pass*, add the governed equivalent to
  `clean_server.py`; confirm it still scores exactly `100.0` with zero
  findings.
- Make it its own `@mcp.tool()` function and add the function's name to
  `test_vulnerable_fixture_covers_every_detection_shape`, so a regression
  names what broke instead of just moving a number. Code no tool reaches is
  not judged.
- Keep both files importable-looking but never actually importable as a
  server — undefined names like `mcp`, `logger` and `request_approval` are
  intentional. A parser does not need them to exist.
