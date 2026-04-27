# Implemented in Phase 2
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from app.core.context import RunContext


class VulnerabilityModule(ABC):
    """Base class for all vulnerability modules. Implemented fully in Phase 2."""

    @property
    @abstractmethod
    def module_id(self) -> str: ...

    @property
    def priority(self) -> int:
        return 100

    def on_load(self, config: dict[str, Any]) -> None:
        self._config = config

    def on_unload(self) -> None:
        pass

    def before_prompt(self, ctx: RunContext) -> None:
        pass

    def after_prompt(self, ctx: RunContext) -> None:
        pass

    def before_retrieval(self, ctx: RunContext) -> None:
        pass

    def after_retrieval(self, ctx: RunContext) -> None:
        pass

    def before_tool_call(self, ctx: RunContext, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        return args

    def after_tool_call(self, ctx: RunContext, tool_name: str, result: Any) -> Any:
        return result

    def before_response(self, ctx: RunContext) -> None:
        pass

    def after_response(self, ctx: RunContext) -> None:
        pass

    def score(self, ctx: RunContext) -> list[dict[str, Any]]:
        return []

    def cleanup(self, ctx: RunContext) -> None:
        pass
