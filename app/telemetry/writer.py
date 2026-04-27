from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from app.core.context import RunContext
from app.core.settings import settings

logger = logging.getLogger(__name__)


class TelemetryWriter:
    def __init__(self, output_dir: Path) -> None:
        self._dir = output_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def default(cls) -> "TelemetryWriter":
        return cls(Path(settings.data_dir) / "telemetry")

    async def flush(self, ctx: RunContext) -> None:
        date_str = time.strftime("%Y-%m-%d")
        log_path = self._dir / f"session_{date_str}.jsonl"

        record = {
            "session_id": ctx.session_id,
            "scenario_id": ctx.scenario_id,
            "timestamp": time.time(),
            "active_modules": ctx.active_modules,
            "user_input_length": len(ctx.user_input),
            "final_response_length": len(ctx.final_response),
            "retrieved_docs_count": len(ctx.retrieved_docs),
            "tool_calls_count": len(ctx.tool_calls),
            "events": ctx.telemetry_events,
            "hook_traces": [
                {
                    "hook_point": t.hook_point,
                    "module_id": t.module_id,
                    "mutations": t.mutations,
                }
                for t in ctx.hook_traces
            ],
            "score_result": ctx.score_result,
        }

        try:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            logger.debug("Telemetry flushed: session=%s path=%s", ctx.session_id, log_path)
        except OSError as exc:
            logger.warning("Telemetry write failed: %s", exc)
