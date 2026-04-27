from __future__ import annotations

import pytest

from app.core.context import RunContext
from app.core.exceptions import ToolSandboxError
from app.tools.executor import ToolExecutor


@pytest.fixture
def executor() -> ToolExecutor:
    return ToolExecutor.from_config([
        {"id": "search_incidents"},
        {"id": "get_ioc_details"},
        {"id": "escalate_incident"},
        {"id": "run_osint_lookup"},
    ])


@pytest.fixture
def ctx() -> RunContext:
    return RunContext(scenario_id="test", user_input="test")


def test_from_config_registers_all_tools(executor):
    assert sorted(executor._registered_tools) == sorted([
        "search_incidents", "get_ioc_details", "escalate_incident", "run_osint_lookup"
    ])


def test_unregistered_tool_raises(ctx):
    ex = ToolExecutor()

    async def _run():
        await ex.execute("nonexistent_tool", {}, ctx)

    with pytest.raises(ToolSandboxError):
        import asyncio
        asyncio.run(_run())


@pytest.mark.asyncio
async def test_execute_emits_start_and_end_events(executor, ctx):
    await executor.execute("search_incidents", {"query": "brute"}, ctx)
    event_types = [e["event_type"] for e in ctx.telemetry_events]
    assert "tool_execute_start" in event_types
    assert "tool_execute_end" in event_types


@pytest.mark.asyncio
async def test_to_openai_schema_returns_list(executor):
    schemas = executor.to_openai_schema()
    assert isinstance(schemas, list)
    assert len(schemas) == 4
    names = {s["function"]["name"] for s in schemas}
    assert "search_incidents" in names
    assert "run_osint_lookup" in names


def test_from_config_raises_on_unknown_tool():
    with pytest.raises(ValueError, match="No sandboxed handler found"):
        ToolExecutor.from_config([{"id": "nonexistent_tool"}])
