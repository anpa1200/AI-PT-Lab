from __future__ import annotations

import pytest

from app.core.exceptions import ConfigError
from app.course.catalog import get_course_module, list_course_modules, load_course


def test_course_manifest_is_cti_grounded():
    course = load_course()
    assert course["id"] == "ai-security-engineering"
    assert course["status"] == "under_construction"
    assert course["evidence_policy"]["required"] is True
    assert {module["id"] for module in course["modules"]} >= {"module-00", "module-01"}


def test_module_summaries_preserve_lab_mappings():
    modules = list_course_modules()
    module_one = next(module for module in modules if module["id"] == "module-01")
    assert module_one["labs"][0]["scenario_id"] == "soc_copilot"


def test_get_course_module_returns_full_lesson_content():
    module = get_course_module("module-01")
    assert module["lessons"][0]["evidence"][0]["source_type"] == "threat_research"
    assert module["lessons"][0]["labs"][0]["suggested_input"]


def test_invalid_course_manifest_is_rejected(tmp_path):
    manifest = tmp_path / "invalid.yaml"
    manifest.write_text("course:\n  id: broken\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="missing required field"):
        load_course(manifest)
