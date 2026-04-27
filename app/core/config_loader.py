from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

_ENV_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::([^}]*))?\}")

CONFIGS_DIR = Path(__file__).parent.parent.parent / "configs"


def _interpolate(value: str) -> str:
    def replace(m: re.Match) -> str:  # type: ignore[type-arg]
        var, default = m.group(1), m.group(2)
        return os.environ.get(var, default or "")

    return _ENV_RE.sub(replace, value)


def _walk(obj: Any) -> Any:
    if isinstance(obj, str):
        return _interpolate(obj)
    if isinstance(obj, dict):
        return {k: _walk(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(item) for item in obj]
    return obj


def load_yaml(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return _walk(raw)


def load_scenario(scenario_id: str, configs_dir: Path = CONFIGS_DIR) -> dict[str, Any]:
    path = configs_dir / "scenarios" / f"{scenario_id}.yaml"
    if not path.exists():
        from app.core.exceptions import ScenarioNotFound
        raise ScenarioNotFound(f"Scenario config not found: {path}")
    return load_yaml(path)


def load_provider(provider_name: str, configs_dir: Path = CONFIGS_DIR) -> dict[str, Any]:
    path = configs_dir / "providers" / f"{provider_name}.yaml"
    if not path.exists():
        from app.core.exceptions import ConfigError
        raise ConfigError(f"Provider config not found: {path}")
    return load_yaml(path)


def list_scenarios(configs_dir: Path = CONFIGS_DIR) -> list[str]:
    scenario_dir = configs_dir / "scenarios"
    if not scenario_dir.exists():
        return []
    return sorted(p.stem for p in scenario_dir.glob("*.yaml"))
