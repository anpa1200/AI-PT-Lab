# Implemented in Phase 4
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.core.context import RunContext


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    usage: dict[str, int] = field(default_factory=dict)


class LLMRouter(ABC):
    @abstractmethod
    async def complete(
        self,
        messages: list[dict[str, Any]],
        ctx: RunContext,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse: ...


def build_llm_router(config: dict[str, Any]) -> LLMRouter:
    provider = config.get("provider", "")
    if provider == "openai":
        from app.models.adapters.openai_adapter import OpenAIAdapter
        return OpenAIAdapter(config)
    if provider == "ollama":
        from app.models.adapters.ollama_adapter import OllamaAdapter
        return OllamaAdapter(config)
    if provider == "anthropic":
        from app.models.adapters.anthropic_adapter import AnthropicAdapter
        return AnthropicAdapter(config)
    if provider == "gemini":
        from app.models.adapters.gemini_adapter import GeminiAdapter
        return GeminiAdapter(config)
    if provider == "openai_compatible":
        from app.models.adapters.openai_compatible_adapter import OpenAICompatibleAdapter
        return OpenAICompatibleAdapter(config)
    raise ValueError(f"Unsupported provider: '{provider}'")
