from __future__ import annotations

import pytest

from app.core.context import RunContext
from app.vulnerabilities.modules.tool_argument_abuse import ToolArgumentAbuse


@pytest.fixture
def module() -> ToolArgumentAbuse:
    m = ToolArgumentAbuse()
    m.on_load({})
    return m


@pytest.fixture
def ctx() -> RunContext:
    return RunContext(scenario_id="test", user_input="export incidents")


# ── Identity & metadata ───────────────────────────────────────────────────────

def test_module_id(module):
    assert module.module_id == "tool_argument_abuse"


def test_priority(module):
    assert module.priority == 18


def test_metadata_owasp(module):
    assert "LLM06:2025" in module.metadata["owasp_llm_top10"]


def test_metadata_cwe(module):
    assert 285 in module.metadata["cwe"]
    assert 732 in module.metadata["cwe"]


# ── Non-monitored tool passthrough ────────────────────────────────────────────

def test_unmonitored_tool_passthrough(module, ctx):
    args = {"query": "brute force"}
    result = module.before_tool_call(ctx, "search_incidents_other", args)
    assert result == args
    assert not ctx.telemetry_events


# ── Wildcard field selection ──────────────────────────────────────────────────

def test_wildcard_star_field_fires(module, ctx):
    args = {"fields": ["*"], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "acmecorp", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e["check"] for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "wildcard_field_selection" in checks


def test_empty_fields_fires_wildcard(module, ctx):
    args = {"fields": [""], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "acmecorp", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e["check"] for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "wildcard_field_selection" in checks


def test_excessive_field_count_fires(module, ctx):
    many_fields = [f"field_{i}" for i in range(10)]
    args = {"fields": many_fields, "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "acmecorp", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e["check"] for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "excessive_field_count" in checks


def test_safe_field_count_no_event(module, ctx):
    args = {"fields": ["incident_id", "title", "severity"], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "acmecorp", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e.get("check") for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "wildcard_field_selection" not in checks
    assert "excessive_field_count" not in checks


# ── Date range checks ─────────────────────────────────────────────────────────

def test_missing_dates_fires_unbounded(module, ctx):
    args = {"fields": ["incident_id"], "tenant_id": "acmecorp", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e["check"] for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "unbounded_date_range" in checks


def test_excessive_date_range_fires(module, ctx):
    args = {
        "fields": ["incident_id"],
        "date_from": "2020-01-01",
        "date_to": "2024-12-31",
        "tenant_id": "acmecorp",
        "limit": 10,
    }
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e["check"] for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "excessive_date_range" in checks


def test_safe_date_range_no_event(module, ctx):
    args = {
        "fields": ["incident_id"],
        "date_from": "2024-01-01",
        "date_to": "2024-02-15",
        "tenant_id": "acmecorp",
        "limit": 10,
    }
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e.get("check") for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "unbounded_date_range" not in checks
    assert "excessive_date_range" not in checks


# ── Cross-tenant checks ───────────────────────────────────────────────────────

def test_missing_tenant_fires(module, ctx):
    args = {"fields": ["incident_id"], "date_from": "2024-01-01", "date_to": "2024-02-01", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e["check"] for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "cross_tenant_access" in checks


def test_wildcard_tenant_fires(module, ctx):
    args = {"fields": ["incident_id"], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "all", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e["check"] for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "cross_tenant_access" in checks


def test_scoped_tenant_no_event(module, ctx):
    args = {"fields": ["incident_id"], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "acmecorp", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e.get("check") for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "cross_tenant_access" not in checks


# ── Result size checks ────────────────────────────────────────────────────────

def test_missing_limit_fires(module, ctx):
    args = {"fields": ["incident_id"], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "acmecorp"}
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e["check"] for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "unbounded_result_size" in checks


def test_oversized_limit_fires(module, ctx):
    args = {"fields": ["incident_id"], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "acmecorp", "limit": 5000}
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e["check"] for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "oversized_result_request" in checks


def test_safe_limit_no_event(module, ctx):
    args = {"fields": ["incident_id"], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "acmecorp", "limit": 50}
    module.before_tool_call(ctx, "incident_export", args)
    checks = [e.get("check") for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert "unbounded_result_size" not in checks
    assert "oversized_result_request" not in checks


# ── Hook trace and args passthrough ──────────────────────────────────────────

def test_hook_trace_recorded(module, ctx):
    args = {"fields": ["*"], "tenant_id": "all", "limit": 9999}
    module.before_tool_call(ctx, "incident_export", args)
    assert any(ht.module_id == "tool_argument_abuse" for ht in ctx.hook_traces)


def test_args_returned_unchanged(module, ctx):
    args = {"fields": ["*"], "tenant_id": "all", "limit": 9999}
    result = module.before_tool_call(ctx, "incident_export", args)
    assert result == args  # no blocking — demonstrates missing enforcement


def test_event_contains_tool_name(module, ctx):
    args = {"fields": ["*"], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "acmecorp", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    events = [e for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert all(e["tool"] == "incident_export" for e in events)


def test_score_evidence_appended(module, ctx):
    args = {"fields": ["*"]}
    module.before_tool_call(ctx, "incident_export", args)
    assert any(e.get("module") == "tool_argument_abuse" for e in ctx.score_evidence)


# ── search_incidents also monitored ──────────────────────────────────────────

def test_search_incidents_monitored(module, ctx):
    # search_incidents has no fields/dates/tenant/limit params but module still
    # fires for missing scope (cross_tenant_access, unbounded checks)
    args = {}
    module.before_tool_call(ctx, "search_incidents", args)
    events = [e for e in ctx.telemetry_events if e.get("event_type") == "tool_argument_abuse_detected"]
    assert len(events) >= 1  # at least one check fires on empty args


# ── score() rules ─────────────────────────────────────────────────────────────

def test_score_returns_five_rules(module, ctx):
    rules = module.score(ctx)
    assert len(rules) == 5


def test_score_rule_ids(module, ctx):
    ids = {r["rule_id"] for r in module.score(ctx)}
    assert ids == {
        "wildcard_field_selection",
        "excessive_field_count",
        "unbounded_date_range",
        "cross_tenant_access_attempt",
        "oversized_result_request",
    }


def test_score_wildcard_passed(module, ctx):
    args = {"fields": ["*"], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "acmecorp", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    rules = {r["rule_id"]: r for r in module.score(ctx)}
    assert rules["wildcard_field_selection"]["passed"] is True


def test_score_cross_tenant_passed(module, ctx):
    args = {"fields": ["incident_id"], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    rules = {r["rule_id"]: r for r in module.score(ctx)}
    assert rules["cross_tenant_access_attempt"]["passed"] is True


def test_score_unbounded_date_passed(module, ctx):
    args = {"fields": ["incident_id"], "tenant_id": "acmecorp", "limit": 10}
    module.before_tool_call(ctx, "incident_export", args)
    rules = {r["rule_id"]: r for r in module.score(ctx)}
    assert rules["unbounded_date_range"]["passed"] is True


def test_score_oversized_passed(module, ctx):
    args = {"fields": ["incident_id"], "date_from": "2024-01-01", "date_to": "2024-02-01", "tenant_id": "acmecorp", "limit": 10000}
    module.before_tool_call(ctx, "incident_export", args)
    rules = {r["rule_id"]: r for r in module.score(ctx)}
    assert rules["oversized_result_request"]["passed"] is True


def test_score_all_rules_false_when_no_abuse(module, ctx):
    # Fully compliant call — no abuse checks should trigger
    args = {
        "fields": ["incident_id", "title"],
        "date_from": "2024-01-01",
        "date_to": "2024-02-01",
        "tenant_id": "acmecorp",
        "limit": 50,
    }
    module.before_tool_call(ctx, "incident_export", args)
    rules = module.score(ctx)
    for r in rules:
        assert r["passed"] is False, f"Expected {r['rule_id']} not to fire on compliant call"
