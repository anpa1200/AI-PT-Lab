from __future__ import annotations

import json
import logging
from typing import Any

from openai import AsyncOpenAI

from app.core.context import RunContext
from app.core.exceptions import ProviderError
from app.core.settings import settings
from app.models.router import LLMResponse, LLMRouter, ToolCall

logger = logging.getLogger(__name__)


class OpenAIAdapter(LLMRouter):
    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        api_key = settings.openai_api_key or config.get("api_key", "")
        base_url = config.get("base_url") or None
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=config.get("timeout_seconds", 60),
        )

    async def complete(
        self,
        messages: list[dict[str, Any]],
        ctx: RunContext,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        model = self._config.get("model", "gpt-4o-mini")
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": _serialize_tool_arguments(messages),
            "temperature": self._config.get("temperature", 0.2),
            "max_tokens": self._config.get("max_tokens", 2048),
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        ctx.emit_event("llm_call_start", {"provider": "openai", "model": model})
        logger.debug("OpenAI call: model=%s messages=%d", model, len(messages))

        try:
            resp = await self._client.chat.completions.create(**kwargs)
        except Exception as exc:
            ctx.emit_event("llm_call_error", {"provider": "openai", "error": str(exc)})
            raise ProviderError(f"OpenAI API error: {exc}") from exc

        usage = resp.usage.model_dump() if resp.usage else {}
        ctx.emit_event("llm_call_end", {"provider": "openai", "usage": usage})

        msg = resp.choices[0].message
        tool_calls = _parse_openai_tool_calls(msg.tool_calls or [])

        return LLMResponse(
            content=msg.content or "",
            tool_calls=tool_calls,
            raw=resp.model_dump(),
            usage=usage,
        )


def _serialize_tool_arguments(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """OpenAI requires tool_calls.function.arguments as a JSON string, not a dict."""
    result = []
    for msg in messages:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            msg = dict(msg)
            msg["tool_calls"] = [
                {
                    **tc,
                    "function": {
                        **tc["function"],
                        "arguments": (
                            json.dumps(tc["function"]["arguments"])
                            if isinstance(tc["function"].get("arguments"), dict)
                            else tc["function"]["arguments"]
                        ),
                    },
                }
                for tc in msg["tool_calls"]
            ]
        result.append(msg)
    return result


def _parse_openai_tool_calls(raw_calls: list) -> list[ToolCall]:
    result = []
    for tc in raw_calls:
        try:
            args = json.loads(tc.function.arguments)
        except (json.JSONDecodeError, AttributeError):
            args = {}
        result.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))
    return result
