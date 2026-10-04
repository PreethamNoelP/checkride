import json

import pytest

from checkride.baseline import (
    BaselineError,
    BaselineKey,
    diff_against_baseline,
    load_baseline,
    write_baseline,
)
from checkride.models import Finding


def finding(file="a.py", rule="error-handling", message="msg", line=1, critical=False):
    return Finding(
        rule=rule, file=file, line=line, message=message, fix="fix", critical=critical
    )


def test_load_missing_baseline_returns_empty(tmp_path):
    assert load_baseline(tmp_path / "nope.json") == {}


def test_write_then_load_round_trips(tmp_path):
    path = tmp_path / "baseline.json"
    findings = [finding(line=1), finding(line=2)]

    written = write_baseline(path, findings)

    assert written == 2
    baseline = load_baseline(path)
    assert baseline == {BaselineKey("a.py", "error-handling", "msg"): 2}


def test_diff_reports_no_new_findings_when_nothing_changed(tmp_path):
    path = tmp_path / "baseline.json"
    findings = [finding(line=1)]
    write_baseline(path, findings)

    baseline = load_baseline(path)
    new = diff_against_baseline(findings, baseline)

    assert new == []


def test_diff_ignores_line_drift_from_an_unrelated_edit(tmp_path):
    # The whole point of count-per-key matching: an edit above a finding
    # shifts its line number, but it's still the same finding.
    path = tmp_path / "baseline.json"
    write_baseline(path, [finding(line=5)])
    baseline = load_baseline(path)

    shifted = [finding(line=42)]  # same file/rule/message, different line
    assert diff_against_baseline(shifted, baseline) == []


def test_diff_finds_a_genuinely_new_finding(tmp_path):
    path = tmp_path / "baseline.json"
    write_baseline(path, [finding(file="a.py", message="old")])
    baseline = load_baseline(path)

    findings = [finding(file="a.py", message="old"), finding(file="b.py", message="new")]
    new = diff_against_baseline(findings, baseline)

    assert [f.file for f in new] == ["b.py"]


def test_diff_count_based_dedup_for_identical_messages(tmp_path):
    # errorhandling.py's unconditional-loop finding is a bare string with
    # no interpolation -- two such loops in one file produce byte-identical
    # Findings except for line. Baselining one must leave exactly one new.
    path = tmp_path / "baseline.json"
    write_baseline(path, [finding(line=1)])
    baseline = load_baseline(path)

    findings = [finding(line=1), finding(line=2), finding(line=3)]
    new = diff_against_baseline(findings, baseline)

    assert len(new) == 2  # 3 total, 1 already baselined


def test_critical_findings_are_never_written_to_a_baseline(tmp_path):
    path = tmp_path / "baseline.json"
    findings = [finding(critical=True), finding(file="b.py", critical=False)]

    written = write_baseline(path, findings)

    assert written == 1
    baseline = load_baseline(path)
    assert BaselineKey("a.py", "error-handling", "msg") not in baseline
    assert BaselineKey("b.py", "error-handling", "msg") in baseline


def test_critical_findings_are_always_new_regardless_of_baseline_content(tmp_path):
    # The guarantee: even a baseline file hand-edited to claim it contains
    # this exact critical finding must not suppress it.
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "findings": [
                    {"file": "a.py", "rule": "human-oversight", "message": "msg", "count": 5}
                ],
            }
        )
    )
    baseline = load_baseline(path)

    critical_finding = finding(rule="human-oversight", critical=True)
    new = diff_against_baseline([critical_finding], baseline)

    assert new == [critical_finding]


def test_malformed_baseline_json_raises(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("{not json")
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_baseline_missing_version_key_raises(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"findings": []}))
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_baseline_with_malformed_entry_raises(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"version": 1, "findings": [{"file": "a.py"}]}))
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_write_baseline_output_is_sorted_and_deterministic(tmp_path):
    path = tmp_path / "baseline.json"
    write_baseline(
        path,
        [
            finding(file="z.py", message="m"),
            finding(file="a.py", message="m"),
        ],
    )
    data = json.loads(path.read_text())
    files = [e["file"] for e in data["findings"]]
    assert files == sorted(files)
