from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.core.scenario_loader import build_orchestrator


def test_build_orchestrator_uses_override_provider_without_reusing_default_model():
    scenario_cfg = {
        "scenario": {
            "provider": {
                "name": "openai",
                "model": "gpt-4o-mini",
                "temperature": 0.1,
                "max_tokens": 111,
            },
            "vulnerability_modules": [],
            "rag": {"enabled": False},
            "tools": [],
            "scoring": {"rules": []},
        }
    }

    with (
        patch("app.core.scenario_loader.load_scenario", return_value=scenario_cfg),
        patch(
            "app.core.scenario_loader.load_provider",
            return_value={
                "provider": "ollama",
                "model": "llama3.2",
                "temperature": 0.2,
                "max_tokens": 2048,
            },
        ) as load_provider_mock,
        patch("app.core.scenario_loader.build_llm_router", return_value=MagicMock()) as router_mock,
        patch("app.core.scenario_loader.TelemetryWriter") as telemetry_cls,
    ):
        telemetry_cls.default.return_value = MagicMock()
        build_orchestrator("soc_copilot", provider_override="ollama")

    provider_cfg = router_mock.call_args.args[0]
    load_provider_mock.assert_called_once_with("ollama")
    assert provider_cfg["provider"] == "ollama"
    assert provider_cfg["model"] == "llama3.2"
    assert provider_cfg["temperature"] == 0.1
    assert provider_cfg["max_tokens"] == 111
