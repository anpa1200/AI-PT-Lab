from __future__ import annotations

import pytest

from app.core.context import RunContext
from app.vulnerabilities.modules.insecure_tool_invocation import InsecureToolInvocation


@pytest.fixture
def module() -> InsecureToolInvocation:
    m = InsecureToolInvocation()
    m.on_load({})
    return m


@pytest.fixture
def ctx() -> RunContext:
    return RunContext(scenario_id="test", user_input="lookup 185.220.101.47")


# ── on_load ───────────────────────────────────────────────────────────────────

def test_default_bypass_tool(module):
    assert module._bypass_tool == "run_osint_lookup"


def test_custom_bypass_tool():
    m = InsecureToolInvocation()
    m.on_load({"bypass_tool": "escalate_incident"})
    assert m._bypass_tool == "escalate_incident"


def test_path_traversal_enabled_by_default(module):
    assert module._allow_path_traversal is True


def test_arbitrary_arguments_enabled_by_default(module):
    assert module._allow_arbitrary_arguments is True


# ── before_tool_call ──────────────────────────────────────────────────────────

def test_different_tool_not_flagged(module, ctx):
    args = {"query": "test"}
    result = module.before_tool_call(ctx, "search_incidents", args)
    assert result == args
    assert len(ctx.hook_traces) == 0


def test_bypass_tool_returns_args_unchanged(module, ctx):
    args = {"target": "185.220.101.47"}
    result = module.before_tool_call(ctx, "run_osint_lookup", args)
    assert result == args


def test_bypass_tool_triggers_hook_trace(module, ctx):
    module.before_tool_call(ctx, "run_osint_lookup", {"target": "safe-value"})
    assert any(t.hook_point == "before_tool_call" for t in ctx.hook_traces)


def test_bypass_tool_emits_event(module, ctx):
    module.before_tool_call(ctx, "run_osint_lookup", {"target": "safe-value"})
    assert any(e["event_type"] == "tool_validation_bypassed" for e in ctx.telemetry_events)


def test_user_input_reflection_detected(module, ctx):
    # user_input is "lookup 185.220.101.47"
    module.before_tool_call(ctx, "run_osint_lookup", {"target": "lookup 185.220.101.47"})
    evidence = [e for e in ctx.score_evidence if e.get("event") == "tool_validation_bypassed"]
    assert len(evidence) == 1
    assert evidence[0]["user_input_reflected"] is True


def test_user_input_not_reflected(module, ctx):
    module.before_tool_call(ctx, "run_osint_lookup", {"target": "completely-different"})
    evidence = [e for e in ctx.score_evidence if e.get("event") == "tool_validation_bypassed"]
    assert evidence[0]["user_input_reflected"] is False


def test_path_traversal_detected(module, ctx):
    module.before_tool_call(ctx, "run_osint_lookup", {"target": "../../etc/passwd"})
    evidence = [e for e in ctx.score_evidence if e.get("event") == "tool_validation_bypassed"]
    assert evidence[0]["traversal_detected"] is True


def test_no_traversal_in_clean_args(module, ctx):
    module.before_tool_call(ctx, "run_osint_lookup", {"target": "8.8.8.8"})
    evidence = [e for e in ctx.score_evidence if e.get("event") == "tool_validation_bypassed"]
    assert evidence[0]["traversal_detected"] is False


# ── score ─────────────────────────────────────────────────────────────────────

def test_score_no_bypass_both_false(module, ctx):
    results = module.score(ctx)
    assert all(r["passed"] is False for r in results)


def test_score_bypass_detected_after_hook(module, ctx):
    module.before_tool_call(ctx, "run_osint_lookup", {"target": "lookup 185.220.101.47"})
    results = module.score(ctx)
    bypass_rule = next(r for r in results if r["rule_id"] == "tool_validation_bypassed")
    assert bypass_rule["passed"] is True


def test_score_user_input_in_args(module, ctx):
    module.before_tool_call(ctx, "run_osint_lookup", {"target": "lookup 185.220.101.47"})
    results = module.score(ctx)
    ui_rule = next(r for r in results if r["rule_id"] == "user_input_in_tool_args")
    assert ui_rule["passed"] is True


def test_score_returns_two_rules(module, ctx):
    assert len(module.score(ctx)) == 2


def test_score_severity_high(module, ctx):
    results = module.score(ctx)
    assert all(r["severity"] == "high" for r in results)


# ── metadata ──────────────────────────────────────────────────────────────────

def test_metadata_owasp(module):
    assert "LLM06:2025" in module.metadata["owasp_llm_top10"]
    assert "LLM08:2025" in module.metadata["owasp_llm_top10"]


def test_module_id(module):
    assert module.module_id == "insecure_tool_invocation"


def test_priority(module):
    assert module.priority == 20
