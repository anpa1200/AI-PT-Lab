from __future__ import annotations

import logging
from typing import Any

from app.core.context import RunContext
from app.core.exceptions import ProviderError
from app.core.settings import settings
from app.models.router import LLMResponse, LLMRouter, ToolCall

logger = logging.getLogger(__name__)


class GeminiAdapter(LLMRouter):
    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._model_name = config.get("model", "gemini-2.0-flash")
        self._client = None          # lazy-init to avoid import cost at startup
        self._client_system: str = ""  # system prompt the cached client was built for

    def _get_client(self, system_instruction: str = ""):
        # Recreate the model whenever the system instruction changes — it is baked
        # into GenerativeModel at construction time, not passed per-call.
        if self._client is None or self._client_system != system_instruction:
            try:
                import google.generativeai as genai
            except ImportError as exc:
                raise ProviderError(
                    "google-generativeai package not installed. "
                    "Run: pip install google-generativeai"
                ) from exc
            api_key = settings.google_api_key or self._config.get("api_key", "")
            genai.configure(api_key=api_key)
            self._client = genai.GenerativeModel(
                self._model_name,
                system_instruction=system_instruction or None,
            )
            self._client_system = system_instruction
        return self._client

    async def complete(
        self,
        messages: list[dict[str, Any]],
        ctx: RunContext,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        import asyncio

        model = self._model_name
        ctx.emit_event("llm_call_start", {"provider": "gemini", "model": model})
        logger.debug("Gemini call: model=%s messages=%d", model, len(messages))

        try:
            gemini_messages, system_prompt = _convert_messages(messages)
            client = self._get_client(system_prompt)

            generation_config = {
                "temperature": self._config.get("temperature", 0.2),
                "max_output_tokens": self._config.get("max_tokens", 2048),
            }
            gemini_tools = _convert_tools(tools) if tools else None

            # google-generativeai is synchronous; run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: client.generate_content(
                    gemini_messages,
                    generation_config=generation_config,
                    tools=gemini_tools,
                ),
            )
        except Exception as exc:
            ctx.emit_event("llm_call_error", {"provider": "gemini", "error": str(exc)})
            raise ProviderError(f"Gemini API error: {exc}") from exc

        ctx.emit_event("llm_call_end", {"provider": "gemini"})

        content_text = ""
        tool_calls: list[ToolCall] = []

        try:
            candidate = resp.candidates[0]
            for part in candidate.content.parts:
                if hasattr(part, "text") and part.text:
                    content_text += part.text
                elif hasattr(part, "function_call") and part.function_call:
                    fc = part.function_call
                    args = dict(fc.args) if fc.args else {}
                    tool_calls.append(ToolCall(
                        id=f"gemini-{fc.name}",
                        name=fc.name,
                        arguments=args,
                    ))
        except (IndexError, AttributeError) as exc:
            logger.warning("Gemini response parse error: %s", exc)

        return LLMResponse(
            content=content_text,
            tool_calls=tool_calls,
            raw={},
            usage={},
        )


def _convert_messages(
    messages: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], str]:
    """Convert OpenAI-style messages to Gemini format. Returns (contents, system_prompt)."""
    system_prompt = ""
    contents = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system":
            system_prompt = content
            continue
        gemini_role = "model" if role == "assistant" else "user"
        contents.append({"role": gemini_role, "parts": [{"text": content or ""}]})
    return contents, system_prompt


def _convert_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert OpenAI function schema to Gemini function declarations."""
    declarations = []
    for tool in tools:
        fn = tool.get("function", tool)
        declarations.append({
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "parameters": fn.get("parameters", {}),
        })
    return [{"function_declarations": declarations}]
