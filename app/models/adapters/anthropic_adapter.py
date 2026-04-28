from __future__ import annotations

import json
import logging
from typing import Any

import anthropic

from app.core.context import RunContext
from app.core.exceptions import ProviderError
from app.core.settings import settings
from app.models.router import LLMResponse, LLMRouter, ToolCall

logger = logging.getLogger(__name__)


class AnthropicAdapter(LLMRouter):
    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._client = anthropic.AsyncAnthropic(
            api_key=settings.anthropic_api_key or config.get("api_key", ""),
            timeout=config.get("timeout_seconds", 60),
        )

    async def complete(
        self,
        messages: list[dict[str, Any]],
        ctx: RunContext,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        model = self._config.get("model", "claude-haiku-4-5-20251001")

        # Anthropic separates system prompt from the messages list
        system_prompt, anthropic_messages = _split_messages(messages)

        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": self._config.get("max_tokens", 2048),
            "temperature": self._config.get("temperature", 0.2),
            "messages": anthropic_messages,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        if tools:
            kwargs["tools"] = _convert_tools_to_anthropic(tools)

        ctx.emit_event("llm_call_start", {"provider": "anthropic", "model": model})
        logger.debug("Anthropic call: model=%s messages=%d", model, len(anthropic_messages))

        try:
            resp = await self._client.messages.create(**kwargs)
        except anthropic.APIError as exc:
            ctx.emit_event("llm_call_error", {"provider": "anthropic", "error": str(exc)})
            raise ProviderError(f"Anthropic API error: {exc}") from exc
        except Exception as exc:
            ctx.emit_event("llm_call_error", {"provider": "anthropic", "error": str(exc)})
            raise ProviderError(f"Anthropic error: {exc}") from exc

        usage = {
            "input_tokens": resp.usage.input_tokens,
            "output_tokens": resp.usage.output_tokens,
        }
        ctx.emit_event("llm_call_end", {"provider": "anthropic", "usage": usage})

        # Parse content blocks — text and tool_use
        content_text = ""
        tool_calls: list[ToolCall] = []
        for block in resp.content:
            if block.type == "text":
                content_text += block.text
            elif block.type == "tool_use":
                args = block.input if isinstance(block.input, dict) else {}
                tool_calls.append(ToolCall(id=block.id, name=block.name, arguments=args))

        return LLMResponse(
            content=content_text,
            tool_calls=tool_calls,
            raw=resp.model_dump(),
            usage=usage,
        )


def _split_messages(
    messages: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    """Extract system prompt; convert tool messages to Anthropic format."""
    system = ""
    out: list[dict[str, Any]] = []
    for msg in messages:
        role = msg.get("role", "")
        if role == "system":
            system = msg.get("content", "")
            continue
        if role == "tool":
            # Convert OpenAI tool-result message to Anthropic user message
            out.append({
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": msg.get("tool_call_id", ""),
                        "content": msg.get("content", ""),
                    }
                ],
            })
            continue
        if role == "assistant" and msg.get("tool_calls"):
            # Convert OpenAI assistant+tool_calls to Anthropic assistant with tool_use blocks
            content_blocks: list[dict[str, Any]] = []
            if msg.get("content"):
                content_blocks.append({"type": "text", "text": msg["content"]})
            for tc in msg["tool_calls"]:
                fn = tc.get("function", {})
                raw_args = fn.get("arguments", {})
                if isinstance(raw_args, str):
                    try:
                        args = json.loads(raw_args)
                    except json.JSONDecodeError:
                        args = {}
                else:
                    args = raw_args
                content_blocks.append({
                    "type": "tool_use",
                    "id": tc.get("id", ""),
                    "name": fn.get("name", ""),
                    "input": args,
                })
            out.append({"role": "assistant", "content": content_blocks})
            continue
        out.append(msg)
    return system, out


def _convert_tools_to_anthropic(
    tools: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert OpenAI function schema format to Anthropic tool format."""
    result = []
    for tool in tools:
        fn = tool.get("function", tool)
        result.append({
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
        })
    return result
