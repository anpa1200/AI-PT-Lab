from __future__ import annotations

from app.core.context import HookTrace, RunContext


def test_run_context_has_unique_session_id():
    a = RunContext()
    b = RunContext()
    assert a.session_id != b.session_id


def test_emit_event_appends_to_telemetry(run_ctx):
    run_ctx.emit_event("test_event", {"key": "value"})
    assert len(run_ctx.telemetry_events) == 1
    ev = run_ctx.telemetry_events[0]
    assert ev["event_type"] == "test_event"
    assert ev["key"] == "value"
    assert ev["session_id"] == run_ctx.session_id
    assert "timestamp" in ev


def test_emit_event_multiple(run_ctx):
    run_ctx.emit_event("a", {})
    run_ctx.emit_event("b", {})
    run_ctx.emit_event("c", {})
    assert len(run_ctx.telemetry_events) == 3
    types = [e["event_type"] for e in run_ctx.telemetry_events]
    assert types == ["a", "b", "c"]


def test_hook_trace_stored(run_ctx):
    trace = HookTrace(
        hook_point="before_prompt",
        module_id="test_module",
        input_snapshot={"user_input": "hello"},
        output_snapshot={"user_input": "hello INJECTED"},
        mutations=["user_input changed"],
    )
    run_ctx.hook_traces.append(trace)
    assert len(run_ctx.hook_traces) == 1
    assert run_ctx.hook_traces[0].module_id == "test_module"


def test_run_context_default_empty_collections():
    ctx = RunContext()
    assert ctx.retrieved_docs == []
    assert ctx.tool_calls == []
    assert ctx.tool_results == []
    assert ctx.active_modules == []
    assert ctx.hook_traces == []
    assert ctx.telemetry_events == []
    assert ctx.score_evidence == []
    assert ctx.score_result is None
