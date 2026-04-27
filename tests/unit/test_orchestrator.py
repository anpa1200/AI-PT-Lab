from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from typing import Any

import pytest

from app.core.context import HookTrace, RunContext
from app.core.orchestrator import ScenarioOrchestrator
from app.models.router import LLMResponse, ToolCall
from app.scoring.engine import ScoringEngine
from app.telemetry.writer import TelemetryWriter
from app.vulnerabilities.base import VulnerabilityModule


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_orchestrator(
    modules: list[VulnerabilityModule] | None = None,
    llm_response: LLMResponse | None = None,
    rag_pipeline=None,
    tool_executor=None,
    scoring_rules: list[dict] | None = None,
    scenario_config: dict | None = None,
) -> ScenarioOrchestrator:
    if llm_response is None:
        llm_response = LLMResponse(content="All systems normal.", tool_calls=[])

    mock_llm = AsyncMock()
    mock_llm.complete = AsyncMock(return_value=llm_response)

    mock_telemetry = AsyncMock(spec=TelemetryWriter)
    mock_telemetry.flush = AsyncMock()

    return ScenarioOrchestrator(
        modules=modules or [],
        llm_router=mock_llm,
        rag_pipeline=rag_pipeline,
        tool_executor=tool_executor,
        scoring_engine=ScoringEngine(scoring_rules or []),
        telemetry_writer=mock_telemetry,
        scenario_config=scenario_config or {"system_prompt": "You are a helpful assistant."},
    )


def _ctx(user_input: str = "hello") -> RunContext:
    return RunContext(scenario_id="test", user_input=user_input)


# ── Snapshot and diff ─────────────────────────────────────────────────────────

def test_snapshot_captures_key_fields():
    ctx = _ctx("test input")
    ctx.system_prompt = "sys"
    ctx.llm_response = "response"
    snap = ScenarioOrchestrator._snapshot(ctx)
    assert snap["user_input"] == "test input"
    assert snap["system_prompt"] == "sys"
    assert snap["llm_response"] == "response"
    assert "retrieved_docs_count" in snap


def test_diff_detects_changed_field():
    before = {"user_input": "hello", "system_prompt": "sys", "llm_response": ""}
    after  = {"user_input": "hello INJECTED", "system_prompt": "sys", "llm_response": ""}
    diffs = ScenarioOrchestrator._diff(before, after)
    assert "user_input changed" in diffs
    assert "system_prompt changed" not in diffs


def test_diff_empty_when_no_changes():
    snap = {"user_input": "hello", "system_prompt": "sys"}
    assert ScenarioOrchestrator._diff(snap, snap.copy()) == []


# ── Hook dispatch ─────────────────────────────────────────────────────────────

def test_dispatch_hook_calls_modules_in_order():
    order: list[str] = []

    class _Mod(VulnerabilityModule):
        def __init__(self, name: str, prio: int):
            self._name = name
            self._prio = prio

        @property
        def module_id(self) -> str:
            return self._name

        @property
        def priority(self) -> int:
            return self._prio

        def before_prompt(self, ctx: RunContext) -> None:
            order.append(self._name)

    modules = sorted([_Mod("c", 100), _Mod("a", 10), _Mod("b", 50)], key=lambda m: m.priority)
    orch = _make_orchestrator(modules=modules)
    ctx = _ctx()
    orch._dispatch_hook("before_prompt", ctx)
    assert order == ["a", "b", "c"]


def test_dispatch_hook_records_trace_when_mutation_occurs():
    class _MutatingMod(VulnerabilityModule):
        @property
        def module_id(self) -> str:
            return "mutating"

        def before_prompt(self, ctx: RunContext) -> None:
            ctx.user_input = ctx.user_input + " [mutated]"

    orch = _make_orchestrator(modules=[_MutatingMod()])
    ctx = _ctx("original")
    orch._dispatch_hook("before_prompt", ctx)

    assert len(ctx.hook_traces) == 1
    assert ctx.hook_traces[0].module_id == "mutating"
    assert "user_input changed" in ctx.hook_traces[0].mutations


def test_dispatch_hook_no_trace_when_no_mutation():
    class _NoopMod(VulnerabilityModule):
        @property
        def module_id(self) -> str:
            return "noop"

        def before_prompt(self, ctx: RunContext) -> None:
            pass  # explicitly no mutation

    orch = _make_orchestrator(modules=[_NoopMod()])
    ctx = _ctx()
    orch._dispatch_hook("before_prompt", ctx)
    assert ctx.hook_traces == []


def test_dispatch_hook_continues_after_module_exception():
    ran: list[str] = []

    class _BrokenMod(VulnerabilityModule):
        @property
        def module_id(self) -> str:
            return "broken"

        def before_prompt(self, ctx: RunContext) -> None:
            raise RuntimeError("intentional failure")

    class _GoodMod(VulnerabilityModule):
        @property
        def module_id(self) -> str:
            return "good"

        @property
        def priority(self) -> int:
            return 200

        def before_prompt(self, ctx: RunContext) -> None:
            ran.append("good")

    orch = _make_orchestrator(modules=[_BrokenMod(), _GoodMod()])
    ctx = _ctx()
    orch._dispatch_hook("before_prompt", ctx)  # must not raise
    assert "good" in ran


# ── Augmented prompt ──────────────────────────────────────────────────────────

def test_build_augmented_prompt_no_docs():
    orch = _make_orchestrator()
    ctx = _ctx("What is the threat?")
    result = orch._build_augmented_prompt(ctx)
    assert result == "What is the threat?"


def test_build_augmented_prompt_with_docs():
    orch = _make_orchestrator()
    ctx = _ctx("Investigate IOC")
    ctx.retrieved_docs = [
        {"content": "185.220.101.47 is a Tor exit node.", "metadata": {"source": "threat_intel"}},
        {"content": "DNS tunneling detected.", "metadata": {"source": "playbook"}},
    ]
    result = orch._build_augmented_prompt(ctx)
    assert "Investigate IOC" in result
    assert "185.220.101.47" in result
    assert "[Source 1" in result
    assert "[Source 2" in result


def test_build_augmented_prompt_includes_source_label():
    orch = _make_orchestrator()
    ctx = _ctx("query")
    ctx.retrieved_docs = [{"content": "doc content", "metadata": {"source": "incidents"}}]
    result = orch._build_augmented_prompt(ctx)
    assert "incidents" in result


# ── Message builder ───────────────────────────────────────────────────────────

def test_build_messages_with_system_prompt():
    orch = _make_orchestrator()
    ctx = _ctx("hello")
    ctx.system_prompt = "You are a SOC analyst."
    ctx.augmented_prompt = "hello augmented"
    msgs = orch._build_messages(ctx)
    assert msgs[0]["role"] == "system"
    assert msgs[0]["content"] == "You are a SOC analyst."
    assert msgs[1]["role"] == "user"
    assert msgs[1]["content"] == "hello augmented"


def test_build_messages_no_system_prompt():
    orch = _make_orchestrator(scenario_config={})
    ctx = _ctx("hi")
    ctx.system_prompt = ""
    ctx.augmented_prompt = "hi"
    msgs = orch._build_messages(ctx)
    assert msgs[0]["role"] == "user"
    assert len(msgs) == 1


# ── Full run (mocked LLM, no RAG/tools) ──────────────────────────────────────

@pytest.mark.asyncio
async def test_run_returns_final_response():
    orch = _make_orchestrator(
        llm_response=LLMResponse(content="Incident confirmed. Escalating."),
    )
    ctx = _ctx("Check INC-001")
    result = await orch.run(ctx)

    assert result.final_response == "Incident confirmed. Escalating."
    assert result.score_result is not None
    assert "overall_status" in result.score_result


@pytest.mark.asyncio
async def test_run_sets_active_modules():
    class _Mod(VulnerabilityModule):
        @property
        def module_id(self) -> str:
            return "active_mod"

    orch = _make_orchestrator(modules=[_Mod()])
    ctx = _ctx("hello")
    result = await orch.run(ctx)
    assert "active_mod" in result.active_modules


@pytest.mark.asyncio
async def test_run_emits_run_start_and_run_complete_events():
    orch = _make_orchestrator()
    ctx = _ctx("hello")
    result = await orch.run(ctx)

    event_types = [e["event_type"] for e in result.telemetry_events]
    assert "run_start" in event_types
    assert "run_complete" in event_types


@pytest.mark.asyncio
async def test_run_calls_module_hooks_in_sequence():
    hook_log: list[str] = []

    class _LoggingMod(VulnerabilityModule):
        @property
        def module_id(self) -> str:
            return "logging_mod"

        def before_prompt(self, ctx: RunContext) -> None:
            hook_log.append("before_prompt")

        def after_prompt(self, ctx: RunContext) -> None:
            hook_log.append("after_prompt")

        def before_response(self, ctx: RunContext) -> None:
            hook_log.append("before_response")

        def after_response(self, ctx: RunContext) -> None:
            hook_log.append("after_response")

    orch = _make_orchestrator(modules=[_LoggingMod()])
    await orch.run(_ctx("test"))

    assert hook_log.index("before_prompt") < hook_log.index("after_prompt")
    assert hook_log.index("after_prompt") < hook_log.index("before_response")
    assert hook_log.index("before_response") < hook_log.index("after_response")


@pytest.mark.asyncio
async def test_run_cleanup_called_on_exception():
    cleaned_up: list[str] = []

    class _CleanupMod(VulnerabilityModule):
        @property
        def module_id(self) -> str:
            return "cleanup_mod"

        def cleanup(self, ctx: RunContext) -> None:
            cleaned_up.append("cleaned")

    mock_llm = AsyncMock()
    mock_llm.complete = AsyncMock(side_effect=RuntimeError("LLM exploded"))
    mock_telemetry = AsyncMock(spec=TelemetryWriter)
    mock_telemetry.flush = AsyncMock()

    orch = ScenarioOrchestrator(
        modules=[_CleanupMod()],
        llm_router=mock_llm,
        rag_pipeline=None,
        tool_executor=None,
        scoring_engine=ScoringEngine([]),
        telemetry_writer=mock_telemetry,
        scenario_config={"system_prompt": ""},
    )

    with pytest.raises(RuntimeError):
        await orch.run(_ctx("test"))

    assert "cleaned" in cleaned_up


# ── Tool loop ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_with_tool_call_executes_tool():
    tool_called: list[tuple] = []

    async def _fake_search(tool_name, args, ctx):
        tool_called.append((tool_name, args))
        return [{"id": "INC-001", "title": "Brute force"}]

    tool_exec = MagicMock()
    tool_exec.execute = AsyncMock(side_effect=_fake_search)
    tool_exec.to_openai_schema = MagicMock(return_value=[])

    # First call: returns a tool call. Second call: returns content.
    tc = ToolCall(id="call-1", name="search_incidents", arguments={"query": "brute force"})
    first = LLMResponse(content="", tool_calls=[tc])
    second = LLMResponse(content="I found INC-001.")

    mock_llm = AsyncMock()
    mock_llm.complete = AsyncMock(side_effect=[first, second])
    mock_telemetry = AsyncMock(spec=TelemetryWriter)
    mock_telemetry.flush = AsyncMock()

    orch = ScenarioOrchestrator(
        modules=[],
        llm_router=mock_llm,
        rag_pipeline=None,
        tool_executor=tool_exec,
        scoring_engine=ScoringEngine([]),
        telemetry_writer=mock_telemetry,
        scenario_config={"system_prompt": ""},
    )

    result = await orch.run(_ctx("search brute force"))
    assert result.final_response == "I found INC-001."
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["name"] == "search_incidents"
