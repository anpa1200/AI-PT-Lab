from __future__ import annotations

import json
import logging
from typing import Any

from app.core.context import HookTrace, RunContext
from app.models.router import LLMResponse, LLMRouter
from app.rag.pipeline import RAGPipeline
from app.scoring.engine import ScoringEngine
from app.telemetry.writer import TelemetryWriter
from app.tools.executor import ToolExecutor
from app.vulnerabilities.base import VulnerabilityModule

logger = logging.getLogger(__name__)

_SNAPSHOT_FIELDS = (
    "user_input",
    "system_prompt",
    "retrieval_query",
    "augmented_prompt",
    "llm_response",
    "final_response",
)


class ScenarioOrchestrator:
    """
    Stateless orchestrator: execute one full run from user_input to scored response.

    Modules are pre-sorted by priority before being passed in.
    All hook dispatch, tool loop, and telemetry flushing happens here.
    """

    def __init__(
        self,
        modules: list[VulnerabilityModule],
        llm_router: LLMRouter,
        rag_pipeline: RAGPipeline | None,
        tool_executor: ToolExecutor | None,
        scoring_engine: ScoringEngine,
        telemetry_writer: TelemetryWriter,
        scenario_config: dict[str, Any],
    ) -> None:
        self._modules = modules
        self._llm = llm_router
        self._rag = rag_pipeline
        self._tools = tool_executor
        self._scorer = scoring_engine
        self._telemetry = telemetry_writer
        self._scenario_config = scenario_config

    # ── Main entry point ─────────────────────────────────────────────────────

    async def run(self, ctx: RunContext) -> RunContext:
        ctx.active_modules = [m.module_id for m in self._modules]
        ctx.emit_event("run_start", {
            "scenario_id": ctx.scenario_id,
            "active_modules": ctx.active_modules,
        })
        logger.info("Run started: session=%s scenario=%s modules=%s",
                    ctx.session_id, ctx.scenario_id, ctx.active_modules)

        try:
            # 1. Apply system prompt from scenario config
            ctx.system_prompt = self._scenario_config.get("system_prompt", "")

            # 2. Pre-prompt hook — modules may modify user_input or system_prompt
            self._dispatch_hook("before_prompt", ctx)

            # 3. RAG retrieval (when enabled)
            if self._rag is not None:
                ctx.retrieval_query = ctx.retrieval_query or ctx.user_input
                self._dispatch_hook("before_retrieval", ctx)
                ctx.retrieved_docs = await self._rag.retrieve(
                    query=ctx.retrieval_query,
                    ctx=ctx,
                )
                self._dispatch_hook("after_retrieval", ctx)

            # 4. Build augmented prompt and fire after_prompt
            ctx.augmented_prompt = self._build_augmented_prompt(ctx)
            self._dispatch_hook("after_prompt", ctx)

            # 5. LLM call (with optional tool loop)
            ctx.llm_response = await self._llm_with_tools(ctx)

            # 6. Output hooks
            self._dispatch_hook("before_response", ctx)
            ctx.final_response = ctx.llm_response
            self._dispatch_hook("after_response", ctx)

            # 7. Scoring
            ctx.score_result = await self._scorer.score(ctx, self._modules)
            ctx.emit_event("run_complete", {"score": ctx.score_result})
            logger.info("Run complete: session=%s status=%s",
                        ctx.session_id, ctx.score_result.get("overall_status"))

        except Exception as exc:
            ctx.emit_event("run_error", {
                "error": str(exc),
                "type": type(exc).__name__,
            })
            logger.exception("Run failed: session=%s", ctx.session_id)
            raise

        finally:
            for module in self._modules:
                try:
                    module.cleanup(ctx)
                except Exception:
                    logger.warning("Cleanup failed for module %s", module.module_id, exc_info=True)
            try:
                await self._telemetry.flush(ctx)
            except Exception:
                logger.warning("Telemetry flush failed: session=%s", ctx.session_id, exc_info=True)

        return ctx

    # ── Hook dispatch ─────────────────────────────────────────────────────────

    def _dispatch_hook(self, hook_name: str, ctx: RunContext) -> None:
        for module in self._modules:
            hook_fn = getattr(module, hook_name, None)
            if hook_fn is None:
                continue

            before = self._snapshot(ctx)
            try:
                hook_fn(ctx)
            except Exception as exc:
                ctx.emit_event("hook_error", {
                    "hook_point": hook_name,
                    "module_id": module.module_id,
                    "error": str(exc),
                })
                logger.warning("Hook %s/%s raised: %s", hook_name, module.module_id, exc)
                continue

            after = self._snapshot(ctx)
            mutations = self._diff(before, after)

            if mutations:
                trace = HookTrace(
                    hook_point=hook_name,
                    module_id=module.module_id,
                    input_snapshot=before,
                    output_snapshot=after,
                    mutations=mutations,
                )
                ctx.hook_traces.append(trace)
                ctx.emit_event("hook_executed", {
                    "hook_point": hook_name,
                    "module_id": module.module_id,
                    "mutations": mutations,
                })

    # ── LLM + tool loop ───────────────────────────────────────────────────────

    async def _llm_with_tools(self, ctx: RunContext) -> str:
        max_rounds: int = self._scenario_config.get("max_tool_rounds", 5)
        messages = self._build_messages(ctx)
        tool_schemas = self._build_tool_schemas()

        for round_num in range(max_rounds):
            ctx.emit_event("llm_round_start", {"round": round_num})
            response: LLMResponse = await self._llm.complete(
                messages=messages,
                ctx=ctx,
                tools=tool_schemas if tool_schemas else None,
            )

            if not response.tool_calls:
                return response.content

            messages.append({
                "role": "assistant",
                "content": response.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": tc.arguments,
                        },
                    }
                    for tc in response.tool_calls
                ],
            })

            # Execute each tool call through the hook chain
            for tc in response.tool_calls:
                args: dict[str, Any] = tc.arguments

                # before_tool_call hooks (can modify args)
                for module in self._modules:
                    args = module.before_tool_call(ctx, tc.name, args)

                # Execute in sandboxed tool executor
                result: Any
                if self._tools is not None:
                    result = await self._tools.execute(tc.name, args, ctx=ctx)
                else:
                    result = f"[tool {tc.name!r} not available — no executor configured]"

                # after_tool_call hooks (can modify result)
                for module in self._modules:
                    result = module.after_tool_call(ctx, tc.name, result)

                ctx.tool_calls.append({"id": tc.id, "name": tc.name, "args": tc.arguments})
                ctx.tool_results.append({"name": tc.name, "result": result})

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tc.name,
                    "content": str(result),
                })

        ctx.emit_event("max_tool_rounds_reached", {"max_rounds": max_rounds})
        return "[Max tool rounds exceeded — last model response was a tool call]"

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_augmented_prompt(self, ctx: RunContext) -> str:
        if not ctx.retrieved_docs:
            return ctx.user_input

        doc_sections = []
        for i, doc in enumerate(ctx.retrieved_docs, start=1):
            content = doc.get("content", "")
            meta = doc.get("metadata", {})
            source = meta.get("source", f"doc-{i}")
            doc_sections.append(f"[Source {i} — {source}]\n{content}")

        context_block = "\n\n".join(doc_sections)
        return f"{ctx.user_input}\n\n---\nRelevant context from knowledge base:\n\n{context_block}"

    def _build_messages(self, ctx: RunContext) -> list[dict[str, Any]]:
        messages: list[dict[str, Any]] = []
        if ctx.system_prompt:
            messages.append({"role": "system", "content": ctx.system_prompt})
        messages.append({"role": "user", "content": ctx.augmented_prompt or ctx.user_input})
        return messages

    def _build_tool_schemas(self) -> list[dict[str, Any]]:
        if self._tools is None:
            return []
        try:
            return self._tools.to_openai_schema()
        except NotImplementedError:
            return []

    @staticmethod
    def _snapshot(ctx: RunContext) -> dict[str, Any]:
        snap: dict[str, Any] = {f: getattr(ctx, f) for f in _SNAPSHOT_FIELDS}
        snap["retrieved_docs_count"] = len(ctx.retrieved_docs)
        snap["tool_calls_count"] = len(ctx.tool_calls)
        return snap

    @staticmethod
    def _diff(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
        return [
            f"{key} changed"
            for key in before
            if before[key] != after.get(key)
        ]
