from __future__ import annotations

import pytest

from app.core.context import RunContext
from app.tools.sandboxed_tools import (
    handle_escalate_incident,
    handle_get_ioc_details,
    handle_run_osint_lookup,
    handle_search_incidents,
)


@pytest.fixture
def ctx() -> RunContext:
    return RunContext(scenario_id="test", user_input="test")


@pytest.mark.asyncio
async def test_search_incidents_returns_list(ctx):
    result = await handle_search_incidents({"query": "brute"}, ctx)
    assert isinstance(result, list)
    assert any("brute" in inc["title"].lower() for inc in result)


@pytest.mark.asyncio
async def test_search_incidents_empty_query_returns_all(ctx):
    result = await handle_search_incidents({"query": ""}, ctx)
    assert len(result) == 5  # all FAKE_INCIDENTS


@pytest.mark.asyncio
async def test_search_incidents_emits_event(ctx):
    await handle_search_incidents({"query": "phishing"}, ctx)
    assert any(e["event_type"] == "tool_result" for e in ctx.telemetry_events)


@pytest.mark.asyncio
async def test_get_ioc_known(ctx):
    result = await handle_get_ioc_details({"ioc": "185.220.101.47"}, ctx)
    assert result["reputation"] == "malicious"
    assert "tor_exit_node" in result["tags"]


@pytest.mark.asyncio
async def test_get_ioc_unknown(ctx):
    result = await handle_get_ioc_details({"ioc": "1.2.3.4"}, ctx)
    assert result["reputation"] == "unknown"
    assert result["confidence"] == 0.0


@pytest.mark.asyncio
async def test_escalate_incident_returns_ticket(ctx):
    result = await handle_escalate_incident({"incident_id": "INC-001", "reason": "critical"}, ctx)
    assert result["status"] == "escalated"
    assert result["incident_id"] == "INC-001"
    assert result["ticket"].startswith("T2-")
    assert "SANDBOX" in result["note"]


@pytest.mark.asyncio
async def test_run_osint_lookup_echoes_target(ctx):
    result = await handle_run_osint_lookup({"target": "evil.com"}, ctx)
    assert result["target"] == "evil.com"
    assert "evil.com" in result["result"]
    assert "SANDBOX" in result["note"]
