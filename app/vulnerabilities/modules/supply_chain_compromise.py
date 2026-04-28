from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.core.context import HookTrace, RunContext
from app.vulnerabilities.base import VulnerabilityModule
from app.vulnerabilities.registry import register

_DEFAULT_REGISTRY = "configs/tool_registry.yaml"


@register
class SupplyChainCompromise(VulnerabilityModule):
    """
    OWASP LLM03:2025 — Supply Chain Compromise via Tool/Plugin Registry.

    Loads a tool registry at startup and checks for drift: unapproved tools,
    scope expansion, hash/manifest changes without a change ticket.
    Simulates a malicious plugin update that widens permissions or introduces
    a backdoor exfiltration endpoint.

    Attack surface: tool integration supply chain — dynamic tool onboarding
    with no signing, pinning, or approval-gate enforcement.
    """

    @property
    def module_id(self) -> str:
        return "supply_chain_compromise"

    @property
    def priority(self) -> int:
        return 1  # first to run — registry state is checked before any action

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "owasp_llm_top10": ["LLM03:2025"],
            "cwe": [494, 506],
            "name": "Supply Chain Compromise",
            "category": "Supply Chain",
            "difficulty": "advanced",
            "description": (
                "Demonstrates tool registry drift: a third-party tool update widens "
                "permissions, adds an exfiltration endpoint, or changes a tool manifest "
                "without a corresponding approval ticket. Analogous to SolarWinds/XZ-style "
                "supply chain attacks applied to the LLM agent toolchain."
            ),
            "mitigation": (
                "Signed tool artifacts, pinned versions and hashes, isolated runtimes, "
                "explicit scope governance with mandatory change tickets, "
                "registry drift detection on every agent startup."
            ),
        }

    def on_load(self, config: dict[str, Any]) -> None:
        super().on_load(config)
        registry_path = config.get("registry_path", _DEFAULT_REGISTRY)
        self._registry = self._load_registry(registry_path)
        self._drift: list[dict[str, Any]] = self._detect_drift()

    def _load_registry(self, path: str) -> dict[str, Any]:
        p = Path(path)
        if not p.exists():
            return {}
        try:
            return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception:
            return {}

    def _detect_drift(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for tool in self._registry.get("tools", []):
            name = tool.get("name", "unknown")
            if not tool.get("approved", True):
                findings.append({"tool": name, "finding": "unapproved_tool", "severity": "critical"})
            if tool.get("scope_expanded", False):
                findings.append({
                    "tool": name,
                    "finding": "scope_expansion",
                    "severity": "critical",
                    "detail": tool.get("scope_change_detail", ""),
                })
            expected = tool.get("expected_hash")
            actual = tool.get("actual_hash")
            if expected and actual and expected != actual:
                findings.append({
                    "tool": name,
                    "finding": "hash_mismatch",
                    "severity": "critical",
                    "expected": expected,
                    "actual": actual,
                })
            changed = tool.get("scope_expanded", False) or (
                expected and actual and expected != actual
            )
            if changed and not tool.get("change_ticket"):
                findings.append({"tool": name, "finding": "change_without_ticket", "severity": "high"})
        return findings

    def before_prompt(self, ctx: RunContext) -> None:
        if not self._drift:
            return
        for finding in self._drift:
            ctx.emit_event("registry_drift_detected", {"module": self.module_id, **finding})
            ctx.score_evidence.append({"module": self.module_id, "event": "tool_registry_drift", **finding})
        ctx.hook_traces.append(HookTrace(
            hook_point="before_prompt",
            module_id=self.module_id,
            input_snapshot={"registry_tools": len(self._registry.get("tools", []))},
            output_snapshot={"drift_findings": len(self._drift)},
            mutations=[f"{len(self._drift)} registry drift finding(s): "
                       + ", ".join({f['finding'] for f in self._drift})],
        ))

    def score(self, ctx: RunContext) -> list[dict[str, Any]]:
        drift_events = [
            e for e in ctx.telemetry_events
            if e.get("event_type") == "registry_drift_detected"
        ]
        unapproved = [f for f in self._drift if f["finding"] == "unapproved_tool"]
        scope_exp = [f for f in self._drift if f["finding"] == "scope_expansion"]
        hash_mm = [f for f in self._drift if f["finding"] == "hash_mismatch"]

        return [
            {
                "rule_id": "registry_drift_detected",
                "description": "Tool registry drift detected (unapproved or tampered changes)",
                "passed": bool(drift_events),
                "evidence": (
                    f"{len(drift_events)} drift events: "
                    + ", ".join(f"{e['tool']}:{e['finding']}" for e in drift_events[:4])
                ) if drift_events else "No registry drift detected",
                "severity": "critical",
                "source": "module",
            },
            {
                "rule_id": "unapproved_tool_in_registry",
                "description": "Registry contains tool that was never reviewed/approved",
                "passed": bool(unapproved),
                "evidence": f"Unapproved: {[f['tool'] for f in unapproved]}" if unapproved
                            else "All tools approved",
                "severity": "critical",
                "source": "module",
            },
            {
                "rule_id": "scope_expansion_without_approval",
                "description": "Tool scope was widened without a change ticket",
                "passed": bool(scope_exp),
                "evidence": (
                    f"Scope expanded: {scope_exp[0]['tool']} — {scope_exp[0].get('detail', '')}"
                ) if scope_exp else "No scope expansion detected",
                "severity": "critical",
                "source": "module",
            },
            {
                "rule_id": "tool_manifest_hash_mismatch",
                "description": "Tool manifest hash does not match pinned expected value (tampered package)",
                "passed": bool(hash_mm),
                "evidence": (
                    f"Hash mismatch: {hash_mm[0]['tool']} "
                    f"expected={hash_mm[0].get('expected')} actual={hash_mm[0].get('actual')}"
                ) if hash_mm else "All hashes match",
                "severity": "critical",
                "source": "module",
            },
        ]
