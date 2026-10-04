"""Measure checkride against a labelled corpus.

Every entry directly under the corpus directory (a file, or a directory
for cross-file cases) is one scan unit. Ground truth is written next to
the code it describes, as a trailing comment:

    shutil.rmtree(path)        # expect: human-oversight, error-handling
    os.remove(p)               # known-miss: human-oversight
    if not normalize(path):    # known-fp: input-validation

  expect      a real issue checkride must report on this line
  known-miss  a real issue checkride does not report (a false negative)
  known-fp    something checkride reports that is not a real issue

and, once per unit, the verdict a reviewer would give it:

    # expect-verdict: FAIL_CRITICAL      (or NOT_CRITICAL)

Precision and recall are computed against expect + known-miss. The run
fails if what checkride reports differs in any way from expect + known-fp:
a regression and an unrecorded improvement both need a label change, made
on purpose, in the same commit.

Only the four rules whose ground truth a reviewer can judge independently
of checkride's own definition are measured. Audit logging and rate
limiting are presence checks -- "is there a logging call" -- so labelling
them would only restate the rule.

    python benchmarks/run.py [--corpus DIR] [--markdown]
"""

import argparse
import io
import os
import re
import sys
import tokenize
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checkride.config import Config
from checkride.scanner import scan

MEASURED_RULES = (
    "human-oversight",
    "input-validation",
    "error-handling",
    "permissive-defaults",
)
LABEL_RE = re.compile(r"#\s*(expect|known-miss|known-fp)\s*:\s*([a-z, -]+)")
VERDICT_RE = re.compile(r"#\s*expect-verdict\s*:\s*(FAIL_CRITICAL|NOT_CRITICAL)")

Key = tuple[str, int, str]  # (file relative to the corpus, line, rule)


@dataclass
class Unit:
    name: str
    path: Path
    expect: set[Key] = field(default_factory=set)
    known_miss: set[Key] = field(default_factory=set)
    known_fp: set[Key] = field(default_factory=set)
    verdict: str | None = None


def _labels(unit: Unit, corpus: Path) -> None:
    files = [unit.path] if unit.path.is_file() else sorted(unit.path.rglob("*.py"))
    for file in files:
        rel = file.relative_to(corpus).as_posix()
        source = file.read_text(encoding="utf-8")
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type != tokenize.COMMENT:
                continue
            verdict = VERDICT_RE.search(tok.string)
            if verdict:
                unit.verdict = verdict.group(1)
                continue
            for match in LABEL_RE.finditer(tok.string):
                kind = match.group(1)
                for rule in (r.strip() for r in match.group(2).split(",")):
                    if not rule:
                        continue
                    if rule not in MEASURED_RULES:
                        raise SystemExit(f"{rel}:{tok.start[0]}: unmeasured rule {rule!r}")
                    key = (rel, tok.start[0], rule)
                    {"expect": unit.expect, "known-miss": unit.known_miss,
                     "known-fp": unit.known_fp}[kind].add(key)
    if unit.verdict is None:
        raise SystemExit(f"{unit.name}: missing '# expect-verdict:' label")


def _detected(unit: Unit, corpus: Path) -> tuple[set[Key], str]:
    cwd = os.getcwd()
    os.chdir(corpus)
    try:
        report = scan(unit.path.relative_to(corpus), Config(min_score=0))
    finally:
        os.chdir(cwd)
    found = {
        (f.file, f.line, f.rule) for f in report.findings if f.rule in MEASURED_RULES
    }
    verdict = "FAIL_CRITICAL" if report.verdict == "FAIL_CRITICAL" else "NOT_CRITICAL"
    return found, verdict


def _ratio(num: int, den: int) -> str:
    return f"{100 * num / den:.1f}%" if den else "n/a"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--corpus", type=Path, default=Path(__file__).resolve().parent / "corpus"
    )
    parser.add_argument("--markdown", action="store_true", help="print a Markdown table")
    args = parser.parse_args(argv)
    corpus = args.corpus.resolve()

    units = [
        Unit(p.name, p) for p in sorted(corpus.iterdir())
        if p.suffix == ".py" or (p.is_dir() and not p.name.startswith(("_", ".")))
    ]
    stats = {rule: {"tp": 0, "fp": 0, "fn": 0} for rule in MEASURED_RULES}
    drift: list[str] = []
    verdicts_right = 0

    for unit in units:
        _labels(unit, corpus)
        found, verdict = _detected(unit, corpus)
        truth = unit.expect | unit.known_miss
        for rule in MEASURED_RULES:
            mine = {k for k in found if k[2] == rule}
            real = {k for k in truth if k[2] == rule}
            stats[rule]["tp"] += len(mine & real)
            stats[rule]["fp"] += len(mine - real)
            stats[rule]["fn"] += len(real - mine)
        should_report = unit.expect | unit.known_fp
        for key in sorted(found - should_report):
            drift.append(f"unexpected finding  {key[0]}:{key[1]}  [{key[2]}]")
        for key in sorted(should_report - found):
            drift.append(f"missing finding     {key[0]}:{key[1]}  [{key[2]}]")
        if verdict == unit.verdict:
            verdicts_right += 1
        else:
            drift.append(f"verdict             {unit.name}: {verdict}, labelled {unit.verdict}")

    totals = {k: sum(s[k] for s in stats.values()) for k in ("tp", "fp", "fn")}
    rows = [
        (rule, s["tp"], s["fp"], s["fn"],
         _ratio(s["tp"], s["tp"] + s["fp"]), _ratio(s["tp"], s["tp"] + s["fn"]))
        for rule, s in stats.items()
    ]
    rows.append((
        "all measured rules", totals["tp"], totals["fp"], totals["fn"],
        _ratio(totals["tp"], totals["tp"] + totals["fp"]),
        _ratio(totals["tp"], totals["tp"] + totals["fn"]),
    ))

    if args.markdown:
        print("| Rule | TP | FP | FN | Precision | Recall |")
        print("|---|---:|---:|---:|---:|---:|")
        for row in rows:
            print("| " + " | ".join(str(c) for c in row) + " |")
        print(
            f"\nCritical-verdict accuracy: {verdicts_right}/{len(units)} scan units "
            f"({_ratio(verdicts_right, len(units))})."
        )
    else:
        print(f"{'rule':<22}{'TP':>5}{'FP':>5}{'FN':>5}{'precision':>12}{'recall':>9}")
        for row in rows:
            print(f"{row[0]:<22}{row[1]:>5}{row[2]:>5}{row[3]:>5}{row[4]:>12}{row[5]:>9}")
        print(f"\ncritical verdict correct for {verdicts_right}/{len(units)} scan units")

    if drift:
        print("\nresults differ from the labels:", file=sys.stderr)
        for line in drift:
            print(f"  {line}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
