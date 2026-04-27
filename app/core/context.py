from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class HookTrace:
    hook_point: str
    module_id: str
    input_snapshot: dict[str, Any]
    output_snapshot: dict[str, Any]
    mutations: list[str]


@dataclass
class RunContext:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scenario_id: str = ""
    provider_config: dict[str, Any] = field(default_factory=dict)

    # Mutable payload — modules modify these fields via hooks
    user_input: str = ""
    system_prompt: str = ""
    retrieval_query: str = ""
    retrieved_docs: list[dict[str, Any]] = field(default_factory=list)
    augmented_prompt: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    llm_response: str = ""
    final_response: str = ""

    # Audit trail
    active_modules: list[str] = field(default_factory=list)
    hook_traces: list[HookTrace] = field(default_factory=list)
    telemetry_events: list[dict[str, Any]] = field(default_factory=list)

    # Scoring
    score_evidence: list[dict[str, Any]] = field(default_factory=list)
    score_result: dict[str, Any] | None = None

    # Escape hatch for module-specific data
    metadata: dict[str, Any] = field(default_factory=dict)

    def emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        self.telemetry_events.append(
            {
                "session_id": self.session_id,
                "event_type": event_type,
                "timestamp": time.time(),
                **data,
            }
        )
