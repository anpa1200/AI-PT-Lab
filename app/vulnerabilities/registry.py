# Implemented in Phase 2
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Any

from app.core.exceptions import ModuleLoadError
from app.vulnerabilities.base import VulnerabilityModule


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, type[VulnerabilityModule]] = {}

    def register(self, cls: type[VulnerabilityModule]) -> None:
        instance = cls()
        self._modules[instance.module_id] = cls

    def autodiscover(self, package: str = "app.vulnerabilities.modules") -> None:
        pkg = importlib.import_module(package)
        pkg_dir = Path(pkg.__file__).parent  # type: ignore[arg-type]
        for _, name, _ in pkgutil.iter_modules([str(pkg_dir)]):
            importlib.import_module(f"{package}.{name}")

    def instantiate(self, module_id: str, config: dict[str, Any]) -> VulnerabilityModule:
        if module_id not in self._modules:
            raise ModuleLoadError(f"Unknown vulnerability module: '{module_id}'")
        instance = self._modules[module_id]()
        instance.on_load(config)
        return instance

    def list_available(self) -> list[str]:
        return sorted(self._modules.keys())


_registry = ModuleRegistry()


def register(cls: type[VulnerabilityModule]) -> type[VulnerabilityModule]:
    _registry.register(cls)
    return cls


def get_registry() -> ModuleRegistry:
    return _registry
