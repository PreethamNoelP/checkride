---
name: Bug report
about: A crash, a wrong exit code, malformed output, or config not applying
labels: bug
---

## What happened

## What you expected

## Reproduction

```console
$ checkride ... 
```

Include the exit code (`echo $?`) — for a CI tool it is usually the whole
story.

## Environment

- `checkride --version`:
- Python version:
- OS:
- `[tool.checkride]` config in effect (the human output prints which file
  was applied, if any):

## Notes

- Config not applying at all: discovery looks for `pyproject.toml` next to
  the scan target only and does not search upwards, so `checkride src/`
  does not pick up a root config. The report prints the config source it
  used; pass `--config` to be explicit.
- If a file was skipped, the report says why. Skipped files make the
  verdict `INCOMPLETE`.
