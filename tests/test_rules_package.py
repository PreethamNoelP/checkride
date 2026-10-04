"""The rule registry and the rule-id list config validates against must
never drift apart -- they live in different modules only to avoid a circular
import (checkride.config -> checkride.rules -> astutils -> config)."""

from checkride.rules import RULE_IDS
from checkride.scoring import ALL_RULES


def test_rule_ids_match_the_registry():
    assert set(RULE_IDS) == {rule.RULE_ID for rule in ALL_RULES}


def test_rule_ids_has_no_duplicates():
    assert len(RULE_IDS) == len(set(RULE_IDS))


def test_every_rule_exposes_the_plugin_contract():
    for rule in ALL_RULES:
        assert isinstance(rule.RULE_ID, str) and rule.RULE_ID
        assert isinstance(rule.CATEGORY, str) and rule.CATEGORY
        assert isinstance(rule.WEIGHT, int) and rule.WEIGHT > 0
        assert callable(rule.check)


def test_weights_sum_to_one_hundred():
    # The 0-100 score is only meaningful if the weights actually total 100.
    assert sum(rule.WEIGHT for rule in ALL_RULES) == 100


def test_rule_ids_are_kebab_case():
    # Inline suppressions validate rule ids against this shape; a rule id
    # that did not match could never be suppressed by name.
    import re

    for rule_id in RULE_IDS:
        assert re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", rule_id), rule_id
