import pytest

from checkride.config import Config, ConfigError, RuleConfig, load_config


def load(tmp_path, toml: str) -> Config:
    """Test helper: write a pyproject.toml next to the target and load it."""
    (tmp_path / "pyproject.toml").write_text(toml)
    return load_config(tmp_path)


def test_missing_config_file_returns_all_defaults(tmp_path):
    config = load_config(tmp_path)
    assert config == Config()


def test_discovers_pyproject_next_to_directory_target(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.checkride]\nmin_score = 80\n"
    )
    config = load_config(tmp_path)
    assert config.min_score == 80.0


def test_discovers_pyproject_next_to_single_file_target(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.checkride]\nmin_score = 80\n"
    )
    target = tmp_path / "server.py"
    target.write_text("x = 1\n")
    config = load_config(target)
    assert config.min_score == 80.0


def test_pyproject_without_tool_checkride_table_is_all_defaults(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "unrelated"\n'
    )
    config = load_config(tmp_path)
    assert config == Config()


def test_explicit_config_path_overrides_discovery(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.checkride]\nmin_score = 10\n")
    custom = tmp_path / "custom.toml"
    custom.write_text("[tool.checkride]\nmin_score = 90\n")

    config = load_config(tmp_path, explicit_path=custom)
    assert config.min_score == 90.0


def test_missing_explicit_config_path_is_an_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path, explicit_path=tmp_path / "nope.toml")


def test_malformed_toml_is_an_error(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.checkride\nmin_score = 1\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_min_score_must_be_a_number(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.checkride]\nmin_score = "high"\n'
    )
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_exclude_reads_a_list_of_globs(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.checkride]\nexclude = ["tests/fixtures/*", "**/generated_*.py"]\n'
    )
    config = load_config(tmp_path)
    assert config.exclude == ("tests/fixtures/*", "**/generated_*.py")


def test_disabled_rules_reads_into_rule_config(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.checkride]\ndisabled_rules = ["rate-limiting"]\n'
    )
    config = load_config(tmp_path)
    assert config.rules.disabled_rules == frozenset({"rate-limiting"})


def test_assume_external_rate_limiting_must_be_boolean(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.checkride]\nassume_external_rate_limiting = "yes"\n'
    )
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_extra_vocabulary_lists_populate_rule_config(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.checkride]\n"
        'extra_approval_markers = ["vet"]\n'
        'extra_log_tokens = ["telemetry"]\n'
        'extra_risky_params = ["apikey"]\n'
    )
    config = load_config(tmp_path)
    assert config.rules.approval_markers == ("vet",)
    assert config.rules.log_tokens == frozenset({"telemetry"})
    assert config.rules.risky_param_tokens == frozenset({"apikey"})


def test_extra_vocabulary_must_be_a_list_of_strings(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.checkride]\nextra_log_tokens = "telemetry"\n'
    )
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_rule_config_defaults_are_all_empty():
    rules = RuleConfig()
    assert rules.disabled_rules == frozenset()
    assert rules.assume_external_rate_limiting is False
    assert rules.approval_markers == ()
    assert rules.log_tokens == frozenset()


# --- a config file that does not do what its author meant is an error ---

def test_unknown_key_is_rejected(tmp_path):
    # "excludes" instead of "exclude" used to scan with no excludes at all
    # and say nothing. For a governance gate, silently different settings
    # are worse than a failed invocation.
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, "[tool.checkride]\nexcludes = ['tests/*']\n")
    assert "unknown key" in str(exc.value)
    assert "exclude" in str(exc.value)


def test_unknown_disabled_rule_id_is_rejected(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, "[tool.checkride]\ndisabled_rules = ['rate_limiting']\n")
    assert "unknown rule" in str(exc.value)
    assert "rate-limiting" in str(exc.value)  # the error names the valid ids


def test_known_disabled_rule_id_is_accepted(tmp_path):
    config = load(tmp_path, "[tool.checkride]\ndisabled_rules = ['rate-limiting']\n")
    assert config.rules.disabled_rules == frozenset({"rate-limiting"})


def test_vocabulary_entry_shorter_than_three_characters_is_rejected(tmp_path):
    # extra_approval_markers = ["e"] made every call name containing an "e"
    # count as an approval check -- the critical gate turned off by config.
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, "[tool.checkride]\nextra_approval_markers = ['e']\n")
    assert "shorter than 3" in str(exc.value)


def test_three_character_vocabulary_entry_is_accepted(tmp_path):
    config = load(tmp_path, "[tool.checkride]\nextra_approval_markers = ['vet']\n")
    assert config.rules.approval_markers == ("vet",)


def test_boolean_min_score_is_rejected(tmp_path):
    # bool is a subclass of int, so `min_score = true` silently became 1.0.
    with pytest.raises(ConfigError) as exc:
        load(tmp_path, "[tool.checkride]\nmin_score = true\n")
    assert "must be a number" in str(exc.value)


# --- config paths in output must not disclose the machine's layout ---

def test_config_source_is_relative_to_the_working_directory(tmp_path, monkeypatch):
    # An absolute path in a CI log discloses the runner's (or a developer's)
    # directory layout for no benefit, and makes the same commit produce
    # different output on different machines.
    (tmp_path / "pyproject.toml").write_text("[tool.checkride]\nmin_score = 50\n")
    monkeypatch.chdir(tmp_path)

    config = load_config(tmp_path.absolute())

    assert config.source == "pyproject.toml"


def test_config_source_in_a_subdirectory_keeps_its_relative_prefix(
    tmp_path, monkeypatch
):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "pyproject.toml").write_text(
        "[tool.checkride]\nmin_score = 50\n"
    )
    monkeypatch.chdir(tmp_path)

    config = load_config(tmp_path / "sub")

    assert config.source == "sub/pyproject.toml"


def test_config_error_names_the_file_relatively(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text("[tool.checkride\nmin_score = 1\n")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ConfigError) as exc:
        load_config(tmp_path.absolute())

    message = str(exc.value)
    assert "pyproject.toml" in message
    assert str(tmp_path) not in message


def test_validation_error_also_names_the_file_relatively(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text("[tool.checkride]\nexcludes = ['x']\n")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ConfigError) as exc:
        load_config(tmp_path.absolute())

    assert str(tmp_path) not in str(exc.value)


def test_config_outside_the_working_directory_stays_absolute(tmp_path, monkeypatch):
    # There is no shorter honest way to name it, and the caller passed this
    # path explicitly with --config, so it is their own path either way.
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "custom.toml").write_text("[tool.checkride]\nmin_score = 50\n")
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    config = load_config(cwd, outside / "custom.toml")

    assert config.source.endswith("elsewhere/custom.toml")
    assert config.source.startswith(("/", tmp_path.drive or "/"))


# --- scope, entry points, score floor -------------------------------------

def test_default_min_score_is_the_documented_floor(tmp_path):
    from checkride.config import DEFAULT_MIN_SCORE

    assert load_config(tmp_path).min_score == DEFAULT_MIN_SCORE == 70.0


def test_min_score_zero_disables_the_floor(tmp_path):
    assert load(tmp_path, "[tool.checkride]\nmin_score = 0\n").min_score == 0.0


@pytest.mark.parametrize("value", ["-1", "101"])
def test_min_score_out_of_range_is_rejected(tmp_path, value):
    with pytest.raises(ConfigError, match="between 0 and 100"):
        load(tmp_path, f"[tool.checkride]\nmin_score = {value}\n")


def test_scope_is_read_and_validated(tmp_path):
    assert load(tmp_path, '[tool.checkride]\nscope = "all"\n').rules.scope == "all"
    with pytest.raises(ConfigError, match="'scope' must be one of"):
        load(tmp_path, '[tool.checkride]\nscope = "everything"\n')


def test_extra_tool_decorators_and_entry_points(tmp_path):
    config = load(
        tmp_path,
        "[tool.checkride]\n"
        'extra_tool_decorators = ["expose"]\n'
        'extra_tool_entry_points = ["handlers.dispatch"]\n',
    )
    assert config.rules.tool_decorators == frozenset({"expose"})
    assert config.rules.entry_points == ("handlers.dispatch",)


@pytest.mark.parametrize("marker", ["run", "exec", "load", "rmtree", "charge"])
def test_approval_marker_matching_a_sink_name_is_rejected(tmp_path, marker):
    # extra_approval_markers = ["run"] made every subprocess.run its own
    # approval: the critical gate, switched off through a config file.
    with pytest.raises(ConfigError, match="count as its own approval"):
        load(tmp_path, f'[tool.checkride]\nextra_approval_markers = ["{marker}"]\n')


def test_ordinary_approval_marker_is_accepted(tmp_path):
    config = load(tmp_path, '[tool.checkride]\nextra_approval_markers = ["greenlight"]\n')
    assert config.rules.approval_markers == ("greenlight",)


# --- accepted risks ----------------------------------------------------------

RISK = (
    "[[tool.checkride.accepted_risks]]\n"
    'rule = "human-oversight"\n'
    'file = "src/server.py"\n'
    'function = "rebuild"\n'
    'reason = "runs a fixed make target, no model input reaches it"\n'
)


def test_accepted_risk_is_parsed(tmp_path):
    from checkride.config import AcceptedRisk

    config = load(tmp_path, "[tool.checkride]\n" + RISK)
    assert config.accepted_risks == (
        AcceptedRisk(
            rule="human-oversight",
            file="src/server.py",
            function="rebuild",
            reason="runs a fixed make target, no model input reaches it",
        ),
    )


@pytest.mark.parametrize("broken, message", [
    (RISK.replace('reason = "runs a fixed make target, no model input reaches it"', 'reason = "ok"'), "must explain"),
    (RISK.replace('rule = "human-oversight"', 'rule = "oversight"'), "unknown rule"),
    (RISK.replace('file = "src/server.py"\n', ""), "'file' is required"),
    (RISK + 'line = 3\n', "unknown key"),
])
def test_malformed_accepted_risk_is_rejected(tmp_path, broken, message):
    with pytest.raises(ConfigError, match=message):
        load(tmp_path, "[tool.checkride]\n" + broken)


def test_accepted_risks_must_be_an_array_of_tables(tmp_path):
    with pytest.raises(ConfigError, match="array of tables"):
        load(tmp_path, '[tool.checkride]\naccepted_risks = ["x"]\n')
