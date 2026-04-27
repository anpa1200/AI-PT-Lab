from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.context import RunContext
from app.core.exceptions import ProviderError
from app.models.adapters.anthropic_adapter import (
    AnthropicAdapter,
    _convert_tools_to_anthropic,
    _split_messages,
)
from app.models.adapters.ollama_adapter import (
    OllamaAdapter,
    _extract_tool_calls_from_text,
    _parse_ollama_tool_calls,
)
from app.models.adapters.openai_adapter import OpenAIAdapter, _parse_openai_tool_calls
from app.models.router import LLMResponse, build_llm_router

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def ctx() -> RunContext:
    return RunContext(scenario_id="test", user_input="test")


@pytest.fixture
def simple_messages() -> list[dict]:
    return [
        {"role": "system", "content": "You are a SOC analyst."},
        {"role": "user", "content": "Check IOC 185.220.101.47"},
    ]


TOOL_SCHEMA = [{
    "type": "function",
    "function": {
        "name": "get_ioc_details",
        "description": "Get IOC metadata",
        "parameters": {
            "type": "object",
            "properties": {"ioc": {"type": "string"}},
            "required": ["ioc"],
        },
    },
}]


# ── build_llm_router dispatch ─────────────────────────────────────────────────

def test_build_llm_router_openai():
    from app.models.adapters.openai_adapter import OpenAIAdapter
    router = build_llm_router({"provider": "openai", "model": "gpt-4o-mini"})
    assert isinstance(router, OpenAIAdapter)


def test_build_llm_router_ollama():
    from app.models.adapters.ollama_adapter import OllamaAdapter
    router = build_llm_router({"provider": "ollama", "model": "llama3.2"})
    assert isinstance(router, OllamaAdapter)


def test_build_llm_router_anthropic():
    from app.models.adapters.anthropic_adapter import AnthropicAdapter
    router = build_llm_router({"provider": "anthropic", "model": "claude-haiku-4-5-20251001"})
    assert isinstance(router, AnthropicAdapter)


def test_build_llm_router_openai_compatible():
    from app.models.adapters.openai_compatible_adapter import OpenAICompatibleAdapter
    router = build_llm_router({"provider": "openai_compatible", "model": "mistral"})
    assert isinstance(router, OpenAICompatibleAdapter)


def test_build_llm_router_unknown_raises():
    with pytest.raises(ValueError, match="Unsupported provider"):
        build_llm_router({"provider": "unknown_llm"})


# ── OpenAI: _parse_openai_tool_calls ─────────────────────────────────────────

def _make_openai_tc(id: str, name: str, args: dict) -> MagicMock:
    tc = MagicMock()
    tc.id = id
    tc.function.name = name
    tc.function.arguments = json.dumps(args)
    return tc


def test_parse_openai_tool_calls_single():
    raw = [_make_openai_tc("call-1", "get_ioc_details", {"ioc": "1.2.3.4"})]
    result = _parse_openai_tool_calls(raw)
    assert len(result) == 1
    assert result[0].name == "get_ioc_details"
    assert result[0].arguments == {"ioc": "1.2.3.4"}
    assert result[0].id == "call-1"


def test_parse_openai_tool_calls_invalid_json():
    tc = MagicMock()
    tc.id = "call-bad"
    tc.function.name = "bad_tool"
    tc.function.arguments = "not-json"
    result = _parse_openai_tool_calls([tc])
    assert result[0].arguments == {}


def test_parse_openai_tool_calls_empty():
    assert _parse_openai_tool_calls([]) == []


# ── OpenAI adapter: full complete() ──────────────────────────────────────────

def _make_openai_response(content: str, tool_calls=None) -> MagicMock:
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = tool_calls or []
    usage = MagicMock()
    usage.model_dump.return_value = {"prompt_tokens": 10, "completion_tokens": 20}
    choice = MagicMock()
    choice.message = msg
    resp = MagicMock()
    resp.choices = [choice]
    resp.usage = usage
    resp.model_dump.return_value = {"choices": []}
    return resp


@pytest.mark.asyncio
async def test_openai_adapter_returns_content(ctx, simple_messages):
    adapter = OpenAIAdapter({"provider": "openai", "model": "gpt-4o-mini"})
    mock_resp = _make_openai_response("IOC is malicious.")
    adapter._client.chat.completions.create = AsyncMock(return_value=mock_resp)

    result = await adapter.complete(simple_messages, ctx)

    assert isinstance(result, LLMResponse)
    assert result.content == "IOC is malicious."
    assert result.tool_calls == []


@pytest.mark.asyncio
async def test_openai_adapter_parses_tool_calls(ctx, simple_messages):
    adapter = OpenAIAdapter({"provider": "openai", "model": "gpt-4o-mini"})
    raw_tc = [_make_openai_tc("c1", "get_ioc_details", {"ioc": "185.220.101.47"})]
    mock_resp = _make_openai_response("", tool_calls=raw_tc)
    adapter._client.chat.completions.create = AsyncMock(return_value=mock_resp)

    result = await adapter.complete(simple_messages, ctx, tools=TOOL_SCHEMA)

    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "get_ioc_details"
    assert result.tool_calls[0].arguments == {"ioc": "185.220.101.47"}


@pytest.mark.asyncio
async def test_openai_adapter_emits_events(ctx, simple_messages):
    adapter = OpenAIAdapter({"provider": "openai", "model": "gpt-4o-mini"})
    adapter._client.chat.completions.create = AsyncMock(
        return_value=_make_openai_response("ok")
    )
    await adapter.complete(simple_messages, ctx)
    event_types = [e["event_type"] for e in ctx.telemetry_events]
    assert "llm_call_start" in event_types
    assert "llm_call_end" in event_types


@pytest.mark.asyncio
async def test_openai_adapter_raises_provider_error_on_api_failure(ctx, simple_messages):
    adapter = OpenAIAdapter({"provider": "openai", "model": "gpt-4o-mini"})
    adapter._client.chat.completions.create = AsyncMock(
        side_effect=Exception("connection refused")
    )
    with pytest.raises(ProviderError):
        await adapter.complete(simple_messages, ctx)


# ── Ollama: _parse_ollama_tool_calls ─────────────────────────────────────────

def test_parse_ollama_tool_calls_native():
    raw = [{"id": "tc-1", "function": {"name": "search_incidents", "arguments": {"query": "brute"}}}]
    result = _parse_ollama_tool_calls(raw)
    assert result[0].name == "search_incidents"
    assert result[0].arguments == {"query": "brute"}


def test_parse_ollama_tool_calls_string_args():
    raw = [{"function": {"name": "get_ioc_details", "arguments": '{"ioc": "1.2.3.4"}'}}]
    result = _parse_ollama_tool_calls(raw)
    assert result[0].arguments == {"ioc": "1.2.3.4"}


def test_parse_ollama_tool_calls_bad_json_args():
    raw = [{"function": {"name": "bad_tool", "arguments": "not-json"}}]
    result = _parse_ollama_tool_calls(raw)
    assert result[0].arguments == {}


def test_extract_tool_calls_from_text_finds_json():
    content = 'Sure. {"name": "get_ioc_details", "arguments": {"ioc": "8.8.8.8"}}'
    result = _extract_tool_calls_from_text(content, TOOL_SCHEMA)
    assert len(result) == 1
    assert result[0].name == "get_ioc_details"
    assert result[0].arguments == {"ioc": "8.8.8.8"}


def test_extract_tool_calls_unknown_name_ignored():
    content = '{"name": "unknown_tool", "arguments": {}}'
    result = _extract_tool_calls_from_text(content, TOOL_SCHEMA)
    assert result == []


# ── Ollama adapter: full complete() ──────────────────────────────────────────

def _make_ollama_response(content: str, tool_calls: list | None = None) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = {
        "message": {
            "role": "assistant",
            "content": content,
            "tool_calls": tool_calls or [],
        }
    }
    resp.raise_for_status = MagicMock()
    return resp


@pytest.mark.asyncio
async def test_ollama_adapter_returns_content(ctx, simple_messages):
    adapter = OllamaAdapter({"provider": "ollama", "model": "llama3.2"})
    adapter._client.post = AsyncMock(return_value=_make_ollama_response("No threats found."))
    result = await adapter.complete(simple_messages, ctx)
    assert result.content == "No threats found."
    assert result.tool_calls == []


@pytest.mark.asyncio
async def test_ollama_adapter_parses_native_tool_calls(ctx, simple_messages):
    native = [{"id": "t1", "function": {"name": "get_ioc_details", "arguments": {"ioc": "1.1.1.1"}}}]
    adapter = OllamaAdapter({"provider": "ollama", "model": "llama3.2"})
    adapter._client.post = AsyncMock(
        return_value=_make_ollama_response("", tool_calls=native)
    )
    result = await adapter.complete(simple_messages, ctx, tools=TOOL_SCHEMA)
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "get_ioc_details"


@pytest.mark.asyncio
async def test_ollama_adapter_raises_on_http_error(ctx, simple_messages):
    import httpx
    adapter = OllamaAdapter({"provider": "ollama", "model": "llama3.2"})
    http_response = MagicMock()
    http_response.status_code = 500
    http_response.text = "internal error"
    adapter._client.post = AsyncMock(
        side_effect=httpx.HTTPStatusError("error", request=MagicMock(), response=http_response)
    )
    with pytest.raises(ProviderError):
        await adapter.complete(simple_messages, ctx)


# ── Anthropic: _split_messages ────────────────────────────────────────────────

def test_split_messages_extracts_system():
    msgs = [
        {"role": "system", "content": "You are a SOC analyst."},
        {"role": "user", "content": "Check IOC"},
    ]
    system, out = _split_messages(msgs)
    assert system == "You are a SOC analyst."
    assert len(out) == 1
    assert out[0]["role"] == "user"


def test_split_messages_tool_result_converted():
    msgs = [
        {"role": "tool", "tool_call_id": "tc-1", "content": '{"reputation": "malicious"}'},
    ]
    _, out = _split_messages(msgs)
    assert out[0]["role"] == "user"
    assert out[0]["content"][0]["type"] == "tool_result"
    assert out[0]["content"][0]["tool_use_id"] == "tc-1"


def test_split_messages_assistant_with_tool_calls():
    msgs = [{
        "role": "assistant",
        "content": "",
        "tool_calls": [{
            "id": "tc-1",
            "function": {"name": "search_incidents", "arguments": '{"query": "brute"}'},
        }],
    }]
    _, out = _split_messages(msgs)
    assert out[0]["role"] == "assistant"
    assert any(b["type"] == "tool_use" for b in out[0]["content"])


def test_convert_tools_to_anthropic():
    result = _convert_tools_to_anthropic(TOOL_SCHEMA)
    assert result[0]["name"] == "get_ioc_details"
    assert "input_schema" in result[0]
    assert result[0]["input_schema"]["properties"]["ioc"]["type"] == "string"


# ── Anthropic adapter: full complete() ───────────────────────────────────────

def _make_anthropic_response(text: str, tool_calls: list | None = None) -> MagicMock:
    blocks = []
    if text:
        block = MagicMock()
        block.type = "text"
        block.text = text
        blocks.append(block)
    for tc in (tool_calls or []):
        block = MagicMock()
        block.type = "tool_use"
        block.id = tc["id"]
        block.name = tc["name"]
        block.input = tc["input"]
        blocks.append(block)
    usage = MagicMock()
    usage.input_tokens = 10
    usage.output_tokens = 20
    resp = MagicMock()
    resp.content = blocks
    resp.usage = usage
    resp.model_dump.return_value = {}
    return resp


@pytest.mark.asyncio
async def test_anthropic_adapter_returns_content(ctx, simple_messages):
    adapter = AnthropicAdapter({"provider": "anthropic", "model": "claude-haiku-4-5-20251001"})
    adapter._client.messages.create = AsyncMock(
        return_value=_make_anthropic_response("All clear.")
    )
    result = await adapter.complete(simple_messages, ctx)
    assert result.content == "All clear."
    assert result.tool_calls == []


@pytest.mark.asyncio
async def test_anthropic_adapter_parses_tool_use(ctx, simple_messages):
    tcs = [{"id": "tu-1", "name": "get_ioc_details", "input": {"ioc": "185.220.101.47"}}]
    adapter = AnthropicAdapter({"provider": "anthropic", "model": "claude-haiku-4-5-20251001"})
    adapter._client.messages.create = AsyncMock(
        return_value=_make_anthropic_response("", tool_calls=tcs)
    )
    result = await adapter.complete(simple_messages, ctx, tools=TOOL_SCHEMA)
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "get_ioc_details"
    assert result.tool_calls[0].arguments == {"ioc": "185.220.101.47"}


@pytest.mark.asyncio
async def test_anthropic_adapter_emits_events(ctx, simple_messages):
    adapter = AnthropicAdapter({"provider": "anthropic", "model": "claude-haiku-4-5-20251001"})
    adapter._client.messages.create = AsyncMock(
        return_value=_make_anthropic_response("ok")
    )
    await adapter.complete(simple_messages, ctx)
    event_types = [e["event_type"] for e in ctx.telemetry_events]
    assert "llm_call_start" in event_types
    assert "llm_call_end" in event_types
