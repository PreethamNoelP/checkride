from checkride import __version__
from checkride.astutils import FileContext
from checkride.sarif import build_sarif
from checkride.scoring import ALL_RULES, score_contexts


def ctx(src: str, path: str = "mem.py") -> FileContext:
    return FileContext.from_source(src, path=path)


def test_sarif_has_one_rule_descriptor_per_registered_rule():
    report = score_contexts([ctx("x = 1\n")])
    sarif = build_sarif(report)
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rule_ids == {rule.RULE_ID for rule in ALL_RULES}


def test_sarif_result_maps_critical_finding_to_error_level():
    report = score_contexts([ctx("@mcp.tool()\ndef wipe(path):\n    shutil.rmtree(path)\n")])
    sarif = build_sarif(report)
    results = sarif["runs"][0]["results"]
    oversight_result = next(r for r in results if r["ruleId"] == "human-oversight")
    assert oversight_result["level"] == "error"


def test_sarif_result_maps_non_critical_finding_to_warning_level():
    report = score_contexts([ctx("auto_approve = True\n")])
    sarif = build_sarif(report)
    results = sarif["runs"][0]["results"]
    assert results[0]["level"] == "warning"


def test_sarif_result_location_has_file_and_line():
    report = score_contexts([ctx("auto_approve = True\n", "flags.py")])
    sarif = build_sarif(report)
    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "flags.py"
    assert location["region"]["startLine"] == 1


def test_sarif_clean_scan_has_no_results():
    report = score_contexts([ctx("def add(a, b):\n    return a + b\n")])
    sarif = build_sarif(report)
    assert sarif["runs"][0]["results"] == []


def test_sarif_run_properties_carry_score_and_verdict():
    report = score_contexts([ctx("def add(a, b):\n    return a + b\n")])
    sarif = build_sarif(report)
    props = sarif["runs"][0]["properties"]
    assert props == {
        "score": 100.0,
        "maxScore": 100,
        # 100.0 over zero sites is INCOMPLETE, not PASS -- a dashboard
        # reading only `score` would otherwise see a perfect result for a
        # scan that recognized nothing.
        "verdict": "INCOMPLETE",
        "filesScanned": 1,
        "configFilesScanned": 0,
        "excluded": 0,
        "totalSites": 0,
        "suppressed": 0,
        "criticalSuppressed": 0,
        "acceptedRisks": 0,
        "criticalGateActive": True,
        "minScore": None,
        "scope": "tools",
        "toolEntryPoints": 0,
        "outOfScopeSensitiveCalls": 0,
    }


def test_sarif_version_and_schema_are_2_1_0():
    report = score_contexts([ctx("x = 1\n")])
    sarif = build_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")


# --- the invocation record: coverage gaps a results-only view would hide ---

def test_sarif_reports_the_tool_version():
    # Without a driver version, a dashboard cannot tell a detection change
    # in checkride apart from a change in the scanned code.
    sarif = build_sarif(score_contexts([ctx("x = 1\n")]))
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["version"] == __version__
    assert driver["semanticVersion"] == __version__


def test_sarif_results_carry_a_rule_index():
    report = score_contexts([ctx("auto_approve = True\n")])
    result = build_sarif(report)["runs"][0]["results"][0]
    rules = build_sarif(report)["runs"][0]["tool"]["driver"]["rules"]
    assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_sarif_invocation_reports_skipped_files():
    report = score_contexts([ctx("x = 1\n")])
    report.skipped = ["broken.py: syntax error at line 1 (invalid syntax)"]

    invocation = build_sarif(report)["runs"][0]["invocations"][0]

    assert invocation["executionSuccessful"] is True
    texts = [n["message"]["text"] for n in invocation["toolExecutionNotifications"]]
    assert any("broken.py" in t for t in texts)


def test_sarif_invocation_reports_scan_warnings():
    report = score_contexts(
        [ctx("import shutil\n@mcp.tool()\ndef f(p):\n    shutil.rmtree(p)\n")],
        disabled_rules=frozenset({"human-oversight"}),
    )

    invocation = build_sarif(report)["runs"][0]["invocations"][0]
    texts = [n["message"]["text"] for n in invocation["toolExecutionNotifications"]]

    assert any("FAIL_CRITICAL gate" in t for t in texts)
    assert build_sarif(report)["runs"][0]["properties"]["criticalGateActive"] is False


def test_sarif_records_the_config_source_when_there_is_one():
    report = score_contexts([ctx("x = 1\n")])

    with_config = build_sarif(report, "pyproject.toml")["runs"][0]["invocations"][0]
    without = build_sarif(report)["runs"][0]["invocations"][0]

    assert with_config["properties"] == {"configSource": "pyproject.toml"}
    assert "properties" not in without


# --- code-scanning ergonomics -------------------------------------------------

WIPE = "import shutil\n@mcp.tool()\ndef wipe(path):\n    shutil.rmtree(path)\n"


def _results(src: str, **kw):
    return build_sarif(score_contexts([ctx(src)], **kw))["runs"][0]["results"]


def test_fingerprints_survive_an_unrelated_edit_above_the_finding():
    before = {r["partialFingerprints"]["checkride/v1"] for r in _results(WIPE)}
    after = {
        r["partialFingerprints"]["checkride/v1"]
        for r in _results("# a new comment\n\n" + WIPE)
    }
    assert before and before == after


def test_identical_findings_get_distinct_fingerprints():
    src = (
        "@mcp.tool()\ndef t():\n"
        "    while True:\n        pass\n"
        "    while True:\n        pass\n"
    )
    prints = [
        r["partialFingerprints"]["checkride/v1"]
        for r in _results(src) if "while True" in r["message"]["text"]
    ]
    assert len(prints) == 2 and len(set(prints)) == 2


def test_results_carry_column_and_function():
    result = next(r for r in _results(WIPE) if r["ruleId"] == "human-oversight")
    location = result["locations"][0]
    assert location["physicalLocation"]["region"] == {"startLine": 4, "startColumn": 5}
    assert location["logicalLocations"][0]["fullyQualifiedName"] == "wipe"


def test_rule_descriptors_carry_help_links_and_security_severity():
    driver = build_sarif(score_contexts([ctx("x = 1\n")]))["runs"][0]["tool"]["driver"]
    for rule in driver["rules"]:
        assert rule["helpUri"].endswith(f"RULES.md#{rule['id']}")
        assert float(rule["properties"]["security-severity"]) > 0
    oversight = next(r for r in driver["rules"] if r["id"] == "human-oversight")
    assert float(oversight["properties"]["security-severity"]) >= 9.0


def test_inline_suppressions_are_recorded_not_dropped():
    src = WIPE.replace("shutil.rmtree(path)", "shutil.rmtree(path)  # checkride: ignore[error-handling]")
    suppressed = [r for r in _results(src) if "suppressions" in r]
    assert [r["ruleId"] for r in suppressed] == ["error-handling"]
    assert suppressed[0]["suppressions"][0]["kind"] == "inSource"


def test_accepted_risks_are_external_suppressions_with_their_reason():
    from checkride.config import AcceptedRisk

    risk = AcceptedRisk(rule="human-oversight", file="mem.py", reason="reviewed in SEC-123")
    accepted = [r for r in _results(WIPE, accepted_risks=(risk,)) if "suppressions" in r]
    assert accepted[0]["suppressions"][0] == {
        "kind": "external", "status": "accepted", "justification": "reviewed in SEC-123"
    }


def test_sarif_location_uri_is_percent_encoded():
    # artifactLocation.uri is an RFC 3986 reference: a raw space, '#' or '%'
    # in a path is read as a separator or an escape and resolves to no file.
    report = score_contexts(
        [ctx("auto_approve = True\n", path="my project/a#b%c é.py")]
    )
    uri = build_sarif(report)["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]["artifactLocation"]["uri"]
    assert uri == "my%20project/a%23b%25c%20%C3%A9.py"
