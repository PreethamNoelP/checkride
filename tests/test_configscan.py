import json

from checkride import configscan
from checkride.config import RuleConfig


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def run(tmp_path, name, content, config=None):
    path = _write(tmp_path, name, content)
    return configscan.scan_config_file(
        path, name, config if config is not None else RuleConfig()
    )


def test_dangerous_true_flag_fails(tmp_path):
    sites, passed, findings, skip = run(
        tmp_path, "mcp.json", '{"autoApprove": true}\n'
    )
    assert skip is None
    assert (sites, passed) == (1, 0)
    assert "autoApprove" in findings[0].message
    assert findings[0].rule == "permissive-defaults"
    assert findings[0].critical is False


def test_dangerous_true_flag_set_false_passes(tmp_path):
    sites, passed, findings, skip = run(
        tmp_path, "mcp.json", '{"autoApprove": false}\n'
    )
    assert (sites, passed, findings, skip) == (1, 1, [], None)


def test_dangerous_when_false_flag_fails(tmp_path):
    sites, passed, findings, _skip = run(
        tmp_path, "mcp.json", '{"requireApproval": false}\n'
    )
    assert (sites, passed) == (1, 0)
    assert "requireApproval" in findings[0].message


def test_unrecognized_key_is_not_a_site(tmp_path):
    sites, passed, findings, skip = run(
        tmp_path, "mcp.json", '{"someOtherFlag": true}\n'
    )
    assert (sites, passed, findings, skip) == (0, 0, [], None)


def test_string_valued_flag_is_not_a_site(tmp_path):
    # Same documented blind spot as rule 6: a quoted "true" is not a
    # literal boolean constant.
    sites, passed, findings, skip = run(
        tmp_path, "mcp.json", '{"autoApprove": "true"}\n'
    )
    assert (sites, passed, findings, skip) == (0, 0, [], None)


def test_array_valued_flag_is_not_a_site(tmp_path):
    # Real MCP clients also spell auto-approval as a list of tool names --
    # documented as out of scope in RULES.md.
    sites, passed, findings, skip = run(
        tmp_path, "mcp.json", '{"autoApprove": ["run_command"]}\n'
    )
    assert (sites, passed, findings, skip) == (0, 0, [], None)


def test_nested_object_flag_is_still_found(tmp_path):
    sites, passed, _findings, _skip = run(
        tmp_path,
        "claude_desktop_config.json",
        json.dumps(
            {"mcpServers": {"shell": {"env": {"skip_confirmation": True}}}}
        ),
    )
    assert (sites, passed) == (1, 0)


def test_malformed_json_is_skipped_with_a_reason(tmp_path):
    sites, passed, findings, skip = run(tmp_path, "mcp.json", "{not json")
    assert (sites, passed, findings) == (0, 0, [])
    assert skip is not None and "invalid JSON" in skip


def test_line_number_points_at_the_flag(tmp_path):
    content = '{\n  "servers": {},\n  "autoApprove": true\n}\n'
    _sites, _passed, findings, _skip = run(tmp_path, "mcp.json", content)
    assert findings[0].line == 3


def test_extra_config_filenames_config_is_recognized(tmp_path):
    config = RuleConfig(dangerous_when_true=frozenset({"yolo_mode"}))
    sites, passed, findings, _skip = run(
        tmp_path, "mcp.json", '{"yolo_mode": true}\n', config=config
    )
    assert (sites, passed) == (1, 0)
    assert "yolo_mode" in findings[0].message


def test_oversized_file_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(configscan, "MAX_FILE_BYTES", 8)
    sites, passed, findings, skip = run(
        tmp_path, "mcp.json", '{"autoApprove": true}\n'
    )
    assert (sites, passed, findings) == (0, 0, [])
    assert skip is not None and "scan limit" in skip


# --- iter_config_files discovery ---


def test_iter_config_files_finds_known_names_in_a_directory(tmp_path):
    (tmp_path / "claude_desktop_config.json").write_text("{}")
    (tmp_path / "unrelated.json").write_text("{}")
    found = list(configscan.iter_config_files(tmp_path))
    assert [p.name for p in found] == ["claude_desktop_config.json"]


def test_iter_config_files_respects_skip_dirs(tmp_path):
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "mcp.json").write_text("{}")
    assert list(configscan.iter_config_files(tmp_path)) == []


def test_iter_config_files_respects_exclude_patterns(tmp_path):
    (tmp_path / "mcp.json").write_text("{}")
    excluded = []
    found = list(
        configscan.iter_config_files(
            tmp_path, exclude=("mcp.json",), on_excluded=excluded.append
        )
    )
    assert found == []
    assert len(excluded) == 1


def test_iter_config_files_extends_via_extra_filenames(tmp_path):
    (tmp_path / "my_client_config.json").write_text("{}")
    assert list(configscan.iter_config_files(tmp_path)) == []
    found = list(
        configscan.iter_config_files(
            tmp_path, extra_filenames=frozenset({"my_client_config.json"})
        )
    )
    assert [p.name for p in found] == ["my_client_config.json"]


def test_iter_config_files_single_file_target_must_match_by_name(tmp_path):
    # Naming a .py file doesn't implicitly pull in sibling JSON files, and
    # naming an unrecognized JSON file doesn't force it to be scanned either
    # -- the target itself has to be a recognized config filename.
    other = tmp_path / "notes.json"
    other.write_text("{}")
    assert list(configscan.iter_config_files(other)) == []

    known = tmp_path / "mcp.json"
    known.write_text("{}")
    assert [p.name for p in configscan.iter_config_files(known)] == ["mcp.json"]
