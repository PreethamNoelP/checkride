"""The six governance rule modules. Each exposes RULE_ID, CATEGORY, WEIGHT,
and check(ctx: FileContext) -> (sites, passed, findings)."""

# The rule ids config files may name (disabled_rules, inline suppressions),
# spelled out as a literal rather than derived from the modules: config.py
# needs to validate against this list, and importing the rule modules here
# would make checkride.config -> checkride.rules -> checkride.astutils ->
# checkride.config circular. test_rules_package.py pins this tuple to the
# actual registry in scoring.ALL_RULES, so the two cannot drift.
RULE_IDS: tuple[str, ...] = (
    "human-oversight",
    "audit-logging",
    "rate-limiting",
    "error-handling",
    "input-validation",
    "permissive-defaults",
)
