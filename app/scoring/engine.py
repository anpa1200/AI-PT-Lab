from __future__ import annotations

import logging
import re
from typing import Any

from app.core.context import RunContext
from app.vulnerabilities.base import VulnerabilityModule

logger = logging.getLogger(__name__)


class ScoringEngine:
    """
    Aggregates evidence from two sources:
      1. Each module's score() method — module-specific rule evaluation.
      2. YAML-defined rules from the scenario config.
    """

    def __init__(self, yaml_rules: list[dict[str, Any]]) -> None:
        self._yaml_rules = yaml_rules

    async def score(
        self,
        ctx: RunContext,
        modules: list[VulnerabilityModule],
    ) -> dict[str, Any]:
        all_evidence: list[dict[str, Any]] = []

        # 1. Collect per-module evidence
        for module in modules:
            try:
                module_evidence = module.score(ctx)
                all_evidence.extend(module_evidence)
            except Exception as exc:
                logger.warning("score() failed for module %s: %s", module.module_id, exc)
                all_evidence.append({
                    "rule_id": f"{module.module_id}_score_error",
                    "description": f"Scoring error in {module.module_id}: {exc}",
                    "passed": False,
                    "evidence": str(exc),
                    "severity": "info",
                    "source": "module_error",
                })

        # 2. Evaluate YAML-defined rules
        for rule in self._yaml_rules:
            try:
                all_evidence.append(self._evaluate_yaml_rule(rule, ctx))
            except Exception as exc:
                logger.warning("YAML rule %s failed: %s", rule.get("rule_id"), exc)

        # 3. Build summary
        triggered = [e for e in all_evidence if e.get("passed")]
        by_severity = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
        for e in triggered:
            sev = e.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "total_rules": len(all_evidence),
            "triggered": len(triggered),
            "critical_triggered": by_severity["critical"],
            "high_triggered": by_severity["high"],
            "evidence": all_evidence,
            "overall_status": "vulnerable" if triggered else "not_triggered",
        }

    # ── YAML rule evaluators ──────────────────────────────────────────────────

    def _evaluate_yaml_rule(self, rule: dict[str, Any], ctx: RunContext) -> dict[str, Any]:
        condition = rule.get("condition", {})
        passed = False
        evidence_text = "Condition not met"

        if "response_matches_pattern" in condition:
            passed, evidence_text = self._check_pattern(
                condition["response_matches_pattern"], ctx
            )

        elif "hook_trace_contains" in condition:
            passed, evidence_text = self._check_hook_trace(
                condition["hook_trace_contains"], ctx
            )

        elif "tool_call_matches" in condition:
            passed, evidence_text = self._check_tool_call(
                condition["tool_call_matches"], ctx
            )

        elif "event_type_present" in condition:
            event_type = condition["event_type_present"]
            match = next(
                (e for e in ctx.telemetry_events if e.get("event_type") == event_type),
                None,
            )
            if match:
                passed = True
                evidence_text = f"Event '{event_type}' found in telemetry"

        return {
            "rule_id": rule["rule_id"],
            "description": rule.get("description", ""),
            "passed": passed,
            "evidence": evidence_text,
            "severity": rule.get("severity", "info"),
            "source": "yaml_rule",
        }

    @staticmethod
    def _check_pattern(cond: dict[str, Any], ctx: RunContext) -> tuple[bool, str]:
        patterns: list[str] = cond.get("patterns", [])
        target = cond.get("field", "final_response")
        text = getattr(ctx, target, "") or ""
        for pattern in patterns:
            if re.search(pattern, text):
                return True, f"Pattern '{pattern}' matched in {target}"
        return False, "No patterns matched"

    @staticmethod
    def _check_hook_trace(cond: dict[str, Any], ctx: RunContext) -> tuple[bool, str]:
        hook_point = cond.get("hook_point")
        module_id = cond.get("module_id")
        field = cond.get("field", "mutations")
        value = cond.get("value", "")

        for trace in ctx.hook_traces:
            if hook_point and trace.hook_point != hook_point:
                continue
            if module_id and trace.module_id != module_id:
                continue
            field_val = " ".join(getattr(trace, field, []))
            if value in field_val:
                return True, f"Hook trace found: {trace.hook_point}/{trace.module_id} — '{value}'"
        return False, "No matching hook trace found"

    @staticmethod
    def _check_tool_call(cond: dict[str, Any], ctx: RunContext) -> tuple[bool, str]:
        tool_name = cond.get("tool_name")
        for tc in ctx.tool_calls:
            if tool_name and tc.get("name") != tool_name:
                continue
            return True, f"Tool '{tool_name}' was called with args: {tc.get('args', {})}"
        return False, f"Tool '{tool_name}' was not called"
