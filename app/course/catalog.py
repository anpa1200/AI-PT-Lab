from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.config_loader import load_yaml
from app.core.exceptions import ConfigError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
COURSE_CONFIG_FILE = PROJECT_ROOT / "configs" / "course" / "ai-security-engineering.yaml"


def load_course(path: Path = COURSE_CONFIG_FILE) -> dict[str, Any]:
    """Load and validate the published course manifest.

    Course content is deliberately data-driven. Adding a module or lesson
    should normally require only a manifest change, not a Python deployment.
    """
    if not path.exists():
        raise ConfigError(f"Course manifest not found: {path}")

    document = load_yaml(path)
    course = document.get("course")
    if not isinstance(course, dict):
        raise ConfigError("Course manifest must contain a 'course' mapping")

    for field in ("id", "title", "version", "modules"):
        if field not in course:
            raise ConfigError(f"Course manifest is missing required field: {field}")

    modules = course["modules"]
    if not isinstance(modules, list) or not modules:
        raise ConfigError("Course manifest must contain at least one module")

    module_ids: set[str] = set()
    for module in modules:
        if not isinstance(module, dict):
            raise ConfigError("Each course module must be a mapping")
        module_id = module.get("id")
        if not isinstance(module_id, str) or not module_id:
            raise ConfigError("Each course module requires a non-empty id")
        if module_id in module_ids:
            raise ConfigError(f"Duplicate course module id: {module_id}")
        module_ids.add(module_id)
        if not isinstance(module.get("lessons", []), list):
            raise ConfigError(f"Course module '{module_id}' lessons must be a list")

    return course


def list_course_modules(path: Path = COURSE_CONFIG_FILE) -> list[dict[str, Any]]:
    """Return compact module records for syllabus views."""
    course = load_course(path)
    summaries: list[dict[str, Any]] = []
    for module in course["modules"]:
        summary = {
            key: module[key]
            for key in ("id", "title", "status", "summary", "prerequisites", "lessons", "labs")
            if key in module
        }
        if "labs" not in summary:
            summary["labs"] = [
                lab
                for lesson in module.get("lessons", [])
                for lab in lesson.get("labs", [])
            ]
        summaries.append(summary)
    return summaries


def get_course_module(module_id: str, path: Path = COURSE_CONFIG_FILE) -> dict[str, Any]:
    """Return one module or raise ``KeyError`` when it is not in the manifest."""
    course = load_course(path)
    for module in course["modules"]:
        if module.get("id") == module_id:
            return module
    raise KeyError(module_id)
