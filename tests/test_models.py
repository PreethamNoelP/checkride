import dataclasses

import pytest

from checkride.models import CategoryResult, Finding


def test_no_applicable_sites_scores_full_weight():
    # The core design decision: a rule that never applied cannot be failed.
    cat = CategoryResult(name="Rate limiting", weight=15)
    assert cat.score == 15.0


def test_all_sites_passing_scores_full_weight():
    cat = CategoryResult(name="Audit logging", weight=20, sites=4, passed=4)
    assert cat.score == 20.0


def test_partial_pass_scores_proportionally():
    cat = CategoryResult(name="Human oversight", weight=25, sites=4, passed=3)
    assert cat.score == pytest.approx(18.75)


def test_zero_passes_scores_zero():
    cat = CategoryResult(name="Human oversight", weight=25, sites=2, passed=0)
    assert cat.score == 0.0


def test_findings_are_immutable():
    f = Finding(rule="human-oversight", file="server.py", line=10,
                message="unguarded delete", fix="add approval check")
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.line = 99


def test_finding_defaults_to_not_critical():
    f = Finding(rule="audit-logging", file="server.py", line=5,
                message="no log call", fix="add logging")
    assert f.critical is False


def test_finding_can_be_marked_critical():
    f = Finding(rule="human-oversight", file="server.py", line=10,
                message="unguarded payment call", fix="add approval check",
                critical=True)
    assert f.critical is True
