from __future__ import annotations

import logging
from typing import Any

from openai import AsyncOpenAI

from app.core.context import RunContext
from app.core.exceptions import ProviderError
from app.core.settings import settings
from app.models.adapters.openai_adapter import _parse_openai_tool_calls
from app.models.router import LLMResponse, LLMRouter

logger = logging.getLogger(__name__)


class OpenAICompatibleAdapter(LLMRouter):
    """
    Works with any OpenAI-compatible server: vLLM, LM Studio, llama.cpp server,
    Text Generation WebUI, Mistral API, Groq, OpenRouter, etc.

    Set provider: openai_compatible and base_url_env (or base_url) in the provider config.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        base_url = (
            config.get("base_url")
            or settings.vllm_base_url
        )
        # Some providers need a real key; others (vLLM local) accept any string
        api_key = config.get("api_key", "EMPTY")
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=config.get("timeout_seconds", 120),
        )

    async def complete(
        self,
        messages: list[dict[str, Any]],
        ctx: RunContext,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        model = self._config.get("model", "")
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": self._config.get("temperature", 0.2),
            "max_tokens": self._config.get("max_tokens", 2048),
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        ctx.emit_event("llm_call_start", {"provider": "openai_compatible", "model": model})
        logger.debug("OpenAI-compatible call: model=%s messages=%d", model, len(messages))

        try:
            resp = await self._client.chat.completions.create(**kwargs)
        except Exception as exc:
            ctx.emit_event("llm_call_error", {"provider": "openai_compatible", "error": str(exc)})
            raise ProviderError(f"OpenAI-compatible API error: {exc}") from exc

        usage = resp.usage.model_dump() if resp.usage else {}
        ctx.emit_event("llm_call_end", {"provider": "openai_compatible", "usage": usage})

        msg = resp.choices[0].message
        tool_calls = _parse_openai_tool_calls(msg.tool_calls or [])

        return LLMResponse(
            content=msg.content or "",
            tool_calls=tool_calls,
            raw=resp.model_dump(),
            usage=usage,
        )
