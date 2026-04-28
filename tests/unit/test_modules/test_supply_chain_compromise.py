from __future__ import annotations

import pytest
import yaml

from app.core.context import RunContext
from app.vulnerabilities.modules.supply_chain_compromise import SupplyChainCompromise


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_module(registry: dict, tmp_path) -> SupplyChainCompromise:
    reg_file = tmp_path / "tool_registry.yaml"
    reg_file.write_text(yaml.dump(registry), encoding="utf-8")
    m = SupplyChainCompromise()
    m.on_load({"registry_path": str(reg_file)})
    return m


def _clean_registry() -> dict:
    return {
        "tools": [
            {
                "name": "email_send_stub",
                "version": "1.0.0",
                "scopes": ["send:internal"],
                "expected_hash": "aabbccdd",
                "actual_hash": "aabbccdd",
                "approved": True,
                "change_ticket": "ITSM-1001",
                "scope_expanded": False,
            }
        ]
    }


@pytest.fixture
def ctx() -> RunContext:
    return RunContext(scenario_id="test", user_input="any")


# ── on_load / metadata ────────────────────────────────────────────────────────

def test_module_id(tmp_path):
    m = _make_module(_clean_registry(), tmp_path)
    assert m.module_id == "supply_chain_compromise"


def test_priority(tmp_path):
    m = _make_module(_clean_registry(), tmp_path)
    assert m.priority == 1


def test_metadata_owasp(tmp_path):
    m = _make_module(_clean_registry(), tmp_path)
    assert "LLM03:2025" in m.metadata["owasp_llm_top10"]


def test_missing_registry_no_crash(tmp_path):
    m = SupplyChainCompromise()
    m.on_load({"registry_path": str(tmp_path / "nonexistent.yaml")})
    assert m._drift == []


# ── drift detection — individual conditions ───────────────────────────────────

def test_unapproved_tool_detected(tmp_path, ctx):
    registry = {
        "tools": [{
            "name": "exfil_backdoor",
            "version": "0.1.0",
            "scopes": ["read:all"],
            "expected_hash": None,
            "actual_hash": "deadbeef",
            "approved": False,
            "change_ticket": None,
            "scope_expanded": False,
        }]
    }
    m = _make_module(registry, tmp_path)
    findings = [f["finding"] for f in m._drift]
    assert "unapproved_tool" in findings


def test_scope_expansion_detected(tmp_path, ctx):
    registry = {
        "tools": [{
            "name": "webhook_post_stub",
            "version": "1.2.0",
            "scopes": ["post:any_url"],
            "expected_hash": "aaaa",
            "actual_hash": "aaaa",
            "approved": True,
            "change_ticket": "ITSM-999",
            "scope_expanded": True,
            "scope_change_detail": "widened scopes",
        }]
    }
    m = _make_module(registry, tmp_path)
    findings = [f["finding"] for f in m._drift]
    assert "scope_expansion" in findings


def test_hash_mismatch_detected(tmp_path, ctx):
    registry = {
        "tools": [{
            "name": "run_osint_lookup",
            "version": "2.1.0",
            "scopes": ["read:external"],
            "expected_hash": "aabbccdd",
            "actual_hash": "11223344",
            "approved": True,
            "change_ticket": "ITSM-500",
            "scope_expanded": False,
        }]
    }
    m = _make_module(registry, tmp_path)
    findings = [f["finding"] for f in m._drift]
    assert "hash_mismatch" in findings


def test_change_without_ticket_detected(tmp_path, ctx):
    registry = {
        "tools": [{
            "name": "webhook_post_stub",
            "version": "1.2.0",
            "scopes": ["post:any_url"],
            "expected_hash": "aabb",
            "actual_hash": "ccdd",  # hash mismatch triggers "changed"
            "approved": True,
            "change_ticket": None,  # but no ticket
            "scope_expanded": False,
        }]
    }
    m = _make_module(registry, tmp_path)
    findings = [f["finding"] for f in m._drift]
    assert "change_without_ticket" in findings


def test_clean_tool_no_drift(tmp_path, ctx):
    m = _make_module(_clean_registry(), tmp_path)
    assert m._drift == []


# ── before_prompt ─────────────────────────────────────────────────────────────

def test_clean_registry_no_events(tmp_path, ctx):
    m = _make_module(_clean_registry(), tmp_path)
    m.before_prompt(ctx)
    assert not ctx.telemetry_events


def test_drift_emits_event(tmp_path, ctx):
    registry = {
        "tools": [{
            "name": "exfil_backdoor",
            "version": "0.1.0",
            "scopes": ["read:all"],
            "expected_hash": None,
            "actual_hash": "deadbeef",
            "approved": False,
            "change_ticket": None,
            "scope_expanded": False,
        }]
    }
    m = _make_module(registry, tmp_path)
    m.before_prompt(ctx)
    assert any(e["event_type"] == "registry_drift_detected" for e in ctx.telemetry_events)


def test_drift_event_contains_tool_name(tmp_path, ctx):
    registry = {
        "tools": [{
            "name": "exfil_backdoor",
            "approved": False,
            "scope_expanded": False,
            "expected_hash": None,
            "actual_hash": "x",
            "change_ticket": None,
        }]
    }
    m = _make_module(registry, tmp_path)
    m.before_prompt(ctx)
    events = [e for e in ctx.telemetry_events if e["event_type"] == "registry_drift_detected"]
    assert any(e["tool"] == "exfil_backdoor" for e in events)


def test_hook_trace_recorded_on_drift(tmp_path, ctx):
    registry = {
        "tools": [{
            "name": "evil",
            "approved": False,
            "scope_expanded": False,
            "expected_hash": None,
            "actual_hash": "x",
            "change_ticket": None,
        }]
    }
    m = _make_module(registry, tmp_path)
    m.before_prompt(ctx)
    assert any(t.hook_point == "before_prompt" for t in ctx.hook_traces)


# ── score ─────────────────────────────────────────────────────────────────────

def test_score_clean_registry_all_fail(tmp_path, ctx):
    m = _make_module(_clean_registry(), tmp_path)
    m.before_prompt(ctx)
    results = m.score(ctx)
    assert all(not r["passed"] for r in results)


def test_score_returns_four_rules(tmp_path, ctx):
    m = _make_module(_clean_registry(), tmp_path)
    assert len(m.score(ctx)) == 4


def test_score_registry_drift_detected(tmp_path, ctx):
    registry = {
        "tools": [{
            "name": "exfil_backdoor",
            "approved": False,
            "scope_expanded": False,
            "expected_hash": None,
            "actual_hash": "x",
            "change_ticket": None,
        }]
    }
    m = _make_module(registry, tmp_path)
    m.before_prompt(ctx)
    results = m.score(ctx)
    r = next(r for r in results if r["rule_id"] == "registry_drift_detected")
    assert r["passed"] is True


def test_score_unapproved_tool(tmp_path, ctx):
    registry = {
        "tools": [{
            "name": "evil_tool",
            "approved": False,
            "scope_expanded": False,
            "expected_hash": None,
            "actual_hash": "x",
            "change_ticket": None,
        }]
    }
    m = _make_module(registry, tmp_path)
    m.before_prompt(ctx)
    results = m.score(ctx)
    r = next(r for r in results if r["rule_id"] == "unapproved_tool_in_registry")
    assert r["passed"] is True


def test_score_scope_expansion(tmp_path, ctx):
    registry = {
        "tools": [{
            "name": "webhook_post_stub",
            "approved": True,
            "scope_expanded": True,
            "expected_hash": "aa",
            "actual_hash": "aa",
            "change_ticket": "ITSM-1",
            "scope_change_detail": "widened",
        }]
    }
    m = _make_module(registry, tmp_path)
    results = m.score(ctx)
    r = next(r for r in results if r["rule_id"] == "scope_expansion_without_approval")
    assert r["passed"] is True


def test_score_hash_mismatch(tmp_path, ctx):
    registry = {
        "tools": [{
            "name": "run_osint_lookup",
            "approved": True,
            "scope_expanded": False,
            "expected_hash": "aabb",
            "actual_hash": "ccdd",
            "change_ticket": "ITSM-2",
        }]
    }
    m = _make_module(registry, tmp_path)
    results = m.score(ctx)
    r = next(r for r in results if r["rule_id"] == "tool_manifest_hash_mismatch")
    assert r["passed"] is True
