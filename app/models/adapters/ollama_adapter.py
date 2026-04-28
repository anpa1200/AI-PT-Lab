from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.core.context import RunContext
from app.core.exceptions import ProviderError
from app.core.settings import settings
from app.models.router import LLMResponse, LLMRouter, ToolCall

logger = logging.getLogger(__name__)


class OllamaAdapter(LLMRouter):
    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._base_url = (
            settings.ollama_base_url.rstrip("/")
            or config.get("base_url", "http://localhost:11434")
        )
        self._client = httpx.AsyncClient(
            timeout=config.get("timeout_seconds", 120),
        )

    async def complete(
        self,
        messages: list[dict[str, Any]],
        ctx: RunContext,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        model = self._config.get("model", "llama3.2")
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "think": self._config.get("think", False),
            "options": {
                "temperature": self._config.get("temperature", 0.2),
                "num_predict": self._config.get("max_tokens", 2048),
            },
        }
        if tools:
            payload["tools"] = tools

        ctx.emit_event("llm_call_start", {"provider": "ollama", "model": model})
        logger.debug("Ollama call: model=%s messages=%d", model, len(messages))

        try:
            resp = await self._client.post(
                f"{self._base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            ctx.emit_event("llm_call_error", {"provider": "ollama", "status": exc.response.status_code})
            raise ProviderError(f"Ollama HTTP {exc.response.status_code}: {exc.response.text}") from exc
        except Exception as exc:
            ctx.emit_event("llm_call_error", {"provider": "ollama", "error": str(exc)})
            raise ProviderError(f"Ollama connection error: {exc}") from exc

        data = resp.json()
        ctx.emit_event("llm_call_end", {"provider": "ollama"})

        msg = data.get("message", {})
        content: str = msg.get("content", "")

        # Native tool calls (llama3.1+, mistral-nemo, qwen2.5)
        native_tcs = msg.get("tool_calls", [])
        if native_tcs:
            tool_calls = _parse_ollama_tool_calls(native_tcs)
        elif tools and content:
            # Fallback: some models emit JSON tool calls inside content
            tool_calls = _extract_tool_calls_from_text(content, tools)
        else:
            tool_calls = []

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            raw=data,
            usage={},
        )


def _parse_ollama_tool_calls(raw_calls: list[dict]) -> list[ToolCall]:
    result = []
    for i, tc in enumerate(raw_calls):
        fn = tc.get("function", {})
        args = fn.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        result.append(ToolCall(
            id=tc.get("id", f"ollama-tc-{i}"),
            name=fn.get("name", ""),
            arguments=args,
        ))
    return result


def _extract_tool_calls_from_text(
    content: str,
    tools: list[dict[str, Any]],
) -> list[ToolCall]:
    """
    Fallback parser for models that emit tool calls as JSON inside content.
    Uses json.JSONDecoder.raw_decode to correctly handle nested objects.
    Only returns calls whose name matches a registered tool.
    """
    tool_names = {t["function"]["name"] for t in tools if "function" in t}
    decoder = json.JSONDecoder()
    calls: list[ToolCall] = []
    idx = 0
    while idx < len(content):
        start = content.find("{", idx)
        if start == -1:
            break
        try:
            obj, offset = decoder.raw_decode(content, start)
            if isinstance(obj, dict):
                name = obj.get("name") or obj.get("function")
                args = obj.get("arguments") or obj.get("parameters") or {}
                if name in tool_names and isinstance(args, dict):
                    calls.append(ToolCall(
                        id=f"fallback-{len(calls)}",
                        name=name,
                        arguments=args,
                    ))
            idx = start + offset
        except (json.JSONDecodeError, ValueError):
            idx = start + 1
    return calls
