## What this changes

## Why

## Checklist

- [ ] A test that fails without this change
- [ ] `python -m pytest tests/ -q`, `mypy`, `ruff check checkride/ tests/ benchmarks/` pass
- [ ] `python benchmarks/run.py` passes (if detection changed, the corpus labels changed with it)
- [ ] `RULES.md` updated if a rule now catches or misses something different
- [ ] `CHANGELOG.md` updated, noting any change to scores or verdicts
