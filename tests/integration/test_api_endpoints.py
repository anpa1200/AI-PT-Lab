from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.models.router import LLMResponse


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def mock_llm():
    """Patch LLM router, RAGPipeline and TelemetryWriter for no real I/O."""
    llm_mock = AsyncMock()
    llm_mock.complete = AsyncMock(
        return_value=LLMResponse(content="Incident confirmed. No active threats.")
    )

    rag_mock = AsyncMock()
    rag_mock.retrieve = AsyncMock(return_value=[])

    telemetry_mock = AsyncMock()
    telemetry_mock.flush = AsyncMock()

    with (
        patch("app.core.scenario_loader.build_llm_router", return_value=llm_mock),
        patch("app.core.scenario_loader.RAGPipeline") as rag_cls,
        patch("app.core.scenario_loader.TelemetryWriter") as tel_cls,
        patch("app.rag.pipeline.RAGPipeline"),   # suppress startup seed I/O
    ):
        rag_cls.from_config.return_value = rag_mock
        tel_cls.default.return_value = telemetry_mock
        yield llm_mock


@pytest.fixture
def mock_llm_code():
    """Variant for code_assistant: returns a code review response."""
    llm_mock = AsyncMock()
    llm_mock.complete = AsyncMock(
        return_value=LLMResponse(content="Security review complete. No critical issues.")
    )

    rag_mock = AsyncMock()
    rag_mock.retrieve = AsyncMock(return_value=[])

    telemetry_mock = AsyncMock()
    telemetry_mock.flush = AsyncMock()

    with (
        patch("app.core.scenario_loader.build_llm_router", return_value=llm_mock),
        patch("app.core.scenario_loader.RAGPipeline") as rag_cls,
        patch("app.core.scenario_loader.TelemetryWriter") as tel_cls,
        patch("app.rag.pipeline.RAGPipeline"),
    ):
        rag_cls.from_config.return_value = rag_mock
        tel_cls.default.return_value = telemetry_mock
        yield llm_mock


# ── Health ────────────────────────────────────────────────────────────────────

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_root(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Vulnerable AI Lab" in resp.json()["name"]


# ── Scenarios list ────────────────────────────────────────────────────────────

def test_list_scenarios_returns_soc_copilot(client):
    resp = client.get("/api/v1/scenarios")
    assert resp.status_code == 200
    assert "soc_copilot" in resp.json()["scenarios"]


def test_list_scenarios_returns_code_assistant(client):
    resp = client.get("/api/v1/scenarios")
    assert resp.status_code == 200
    assert "code_assistant" in resp.json()["scenarios"]


def test_get_scenario_info_soc_copilot(client):
    resp = client.get("/api/v1/scenarios/soc_copilot")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "soc_copilot"
    assert "name" in data
    assert data["rag_enabled"] is True


def test_get_scenario_info_code_assistant(client):
    resp = client.get("/api/v1/scenarios/code_assistant")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "code_assistant"
    assert data["rag_enabled"] is True
    assert "run_code_snippet" in data["tools"]


def test_get_scenario_info_returns_vulnerability_modules(client):
    resp = client.get("/api/v1/scenarios/soc_copilot")
    assert resp.status_code == 200
    mods = resp.json()["vulnerability_modules"]
    assert "indirect_prompt_injection_rag" in mods
    assert "insecure_tool_invocation" in mods
    assert "weak_output_validation" in mods


def test_get_scenario_info_code_assistant_modules(client):
    resp = client.get("/api/v1/scenarios/code_assistant")
    assert resp.status_code == 200
    mods = resp.json()["vulnerability_modules"]
    assert "indirect_prompt_injection_rag" in mods
    assert "system_prompt_leakage" in mods
    assert "insecure_tool_invocation" in mods


def test_get_scenario_info_unknown_returns_404(client):
    resp = client.get("/api/v1/scenarios/does_not_exist")
    assert resp.status_code == 404


# ── Modules list ──────────────────────────────────────────────────────────────

def test_list_modules(client):
    resp = client.get("/api/v1/modules")
    assert resp.status_code == 200
    modules = resp.json()["modules"]
    assert "indirect_prompt_injection_rag" in modules
    assert "insecure_tool_invocation" in modules
    assert "weak_output_validation" in modules
    assert "system_prompt_leakage" in modules


# ── Run endpoint — soc_copilot ────────────────────────────────────────────────

def test_run_returns_200_and_response(client, mock_llm):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "soc_copilot",
        "user_input": "Check IOC 185.220.101.47",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["final_response"] == "Incident confirmed. No active threats."
    assert "session_id" in data
    assert data["scenario_id"] == "soc_copilot"


def test_run_returns_score_result(client, mock_llm):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "soc_copilot",
        "user_input": "Search for brute force incidents",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "score_result" in data
    assert "overall_status" in data["score_result"]


def test_run_returns_hook_summary(client, mock_llm):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "soc_copilot",
        "user_input": "hello",
    })
    assert resp.status_code == 200
    assert "hook_summary" in resp.json()
    assert "active_modules" in resp.json()


def test_run_soc_copilot_has_all_modules_active(client, mock_llm):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "soc_copilot",
        "user_input": "any query",
    })
    assert resp.status_code == 200
    active = resp.json()["active_modules"]
    assert "indirect_prompt_injection_rag" in active
    assert "insecure_tool_invocation" in active
    assert "weak_output_validation" in active


def test_run_rag_injection_hook_fires(client, mock_llm):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "soc_copilot",
        "user_input": "Check IOC 185.220.101.47",
    })
    assert resp.status_code == 200
    hook_summary = resp.json()["hook_summary"]
    module_ids = [h["module_id"] for h in hook_summary]
    assert "indirect_prompt_injection_rag" in module_ids


def test_run_score_result_has_evidence(client, mock_llm):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "soc_copilot",
        "user_input": "Show me all incidents",
    })
    assert resp.status_code == 200
    evidence = resp.json()["score_result"]["evidence"]
    assert len(evidence) > 0
    rule_ids = [e["rule_id"] for e in evidence]
    assert "injection_doc_inserted" in rule_ids


# ── Run endpoint — code_assistant ─────────────────────────────────────────────

def test_run_code_assistant_returns_200(client, mock_llm_code):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "code_assistant",
        "user_input": "Review PR-42 for security issues",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario_id"] == "code_assistant"
    assert data["final_response"] == "Security review complete. No critical issues."


def test_run_code_assistant_has_correct_modules(client, mock_llm_code):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "code_assistant",
        "user_input": "Review PR-42",
    })
    assert resp.status_code == 200
    active = resp.json()["active_modules"]
    assert "indirect_prompt_injection_rag" in active
    assert "system_prompt_leakage" in active
    assert "insecure_tool_invocation" in active


def test_run_code_assistant_rag_injection_hook_fires(client, mock_llm_code):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "code_assistant",
        "user_input": "Review this security-critical PR",
    })
    assert resp.status_code == 200
    hook_module_ids = [h["module_id"] for h in resp.json()["hook_summary"]]
    assert "indirect_prompt_injection_rag" in hook_module_ids


def test_run_code_assistant_has_score_result(client, mock_llm_code):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "code_assistant",
        "user_input": "Review PR-1",
    })
    assert resp.status_code == 200
    assert resp.json()["score_result"] is not None


# ── Error cases ───────────────────────────────────────────────────────────────

def test_run_unknown_scenario_returns_404(client):
    resp = client.post("/api/v1/run", json={
        "scenario_id": "no_such_scenario",
        "user_input": "test",
    })
    assert resp.status_code == 404


def test_run_missing_user_input_returns_422(client):
    resp = client.post("/api/v1/run", json={"scenario_id": "soc_copilot"})
    assert resp.status_code == 422
