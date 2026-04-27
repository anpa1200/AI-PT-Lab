from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.core.config_loader import _walk, list_scenarios, load_yaml
from app.core.exceptions import ScenarioNotFound


def test_env_interpolation_with_value(monkeypatch):
    monkeypatch.setenv("TEST_VAR", "hello")
    result = _walk("${TEST_VAR:default}")
    assert result == "hello"


def test_env_interpolation_with_default(monkeypatch):
    monkeypatch.delenv("MISSING_VAR", raising=False)
    result = _walk("${MISSING_VAR:fallback}")
    assert result == "fallback"


def test_env_interpolation_nested(monkeypatch):
    monkeypatch.setenv("MY_DIR", "/data")
    result = _walk({"path": "${MY_DIR:/tmp}/logs"})
    assert result == {"path": "/data/logs"}


def test_env_interpolation_list(monkeypatch):
    monkeypatch.setenv("LEVEL", "DEBUG")
    result = _walk(["${LEVEL:INFO}", "static"])
    assert result == ["DEBUG", "static"]


def test_load_yaml_parses_valid_file(tmp_path):
    f = tmp_path / "test.yaml"
    f.write_text("key: value\nnum: 42\n")
    data = load_yaml(f)
    assert data == {"key": "value", "num": 42}


def test_load_scenario_raises_for_missing(tmp_path):
    with pytest.raises(ScenarioNotFound):
        from app.core.config_loader import load_scenario
        load_scenario("nonexistent", tmp_path)


def test_list_scenarios_returns_yaml_stems(tmp_path):
    scen_dir = tmp_path / "scenarios"
    scen_dir.mkdir()
    (scen_dir / "foo.yaml").write_text("scenario:\n  id: foo\n")
    (scen_dir / "bar.yaml").write_text("scenario:\n  id: bar\n")
    result = list_scenarios(tmp_path)
    assert sorted(result) == ["bar", "foo"]
