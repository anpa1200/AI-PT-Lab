# Architecture

## Overview

Vulnerable AI Lab is a modular, intentionally vulnerable AI security training lab. A user sends a query, the system retrieves context from a knowledge base, calls external tools, and generates a response — and at each step, pluggable vulnerability modules can silently corrupt the pipeline.

```
┌─────────────────────────────────────────────────────────────┐
│  User (Web UI / CLI)                                        │
└───────────────────────────┬─────────────────────────────────┘
                            │  POST /api/v1/run
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  FastAPI app  (app/api/main.py)                             │
│  • routes: /run, /scenarios, /modules, /health              │
│  • builds ScenarioOrchestrator from loaded scenario config  │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  ScenarioOrchestrator  (app/core/orchestrator.py)           │
│                                                             │
│  ① before_prompt hook                                       │
│  ② RAG retrieval ──► ChromaDB (app/rag/pipeline.py)         │
│     • before_retrieval hook                                 │
│     • after_retrieval hook  ◄── injection point             │
│  ③ Build augmented prompt                                   │
│     • after_prompt hook                                     │
│  ④ LLM call (with tool loop)                                │
│     LLMRouter ──► OpenAI / Anthropic / Ollama / Gemini      │
│     For each tool call:                                     │
│       • before_tool_call hook  ◄── validation bypass point  │
│       • ToolExecutor ──► sandboxed handlers                 │
│       • after_tool_call hook                                │
│  ⑤ before_response hook  ◄── output scan point             │
│  ⑥ after_response hook                                      │
│  ⑦ ScoringEngine ──► RunContext.score_result                │
│  ⑧ TelemetryWriter ──► JSONL session log                    │
└─────────────────────────────────────────────────────────────┘
```

All mutable state for a single request lives in a `RunContext` dataclass. Modules are singletons; they never store per-request state in instance variables — they read and write the context instead.

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Synchronous hook chain | Simple, debuggable, no event bus overhead. Hooks run in priority order; the result of one is visible to the next. |
| Per-request `RunContext` | Full isolation between concurrent requests. Modules are safe to share across threads. |
| YAML-first config | Adding a new scenario requires zero Python changes. |
| Stateless modules | Modules never hold mutable state between runs — `ctx.metadata` is the escape hatch for module-private per-request data. |
| ChromaDB embedded | In-process, no separate service. `asyncio.Lock` per collection prevents concurrent write races. |
| Evidence-first scoring | Modules emit structured evidence during the run; the scoring engine aggregates at the end. No LLM-as-judge. |

---

## Components

### Settings (`app/core/settings.py`)

Pydantic `BaseSettings` loaded once at import time. All environment variables are documented in the README. Key settings:

| Setting | Env var | Default |
|---|---|---|
| `openai_api_key` | `OPENAI_API_KEY` | — |
| `anthropic_api_key` | `ANTHROPIC_API_KEY` | — |
| `data_dir` | `LAB_DATA_DIR` | `./data` |
| `log_level` | `LAB_LOG_LEVEL` | `INFO` |
| `seed_on_startup` | `LAB_SEED_ON_STARTUP` | `true` |
| `reset_on_startup` | `LAB_RESET_ON_STARTUP` | `false` |

### Config Loader (`app/core/config_loader.py`)

Loads YAML scenario and provider files. Supports `${ENV_VAR:default}` interpolation so secrets never appear in YAML.

### RunContext (`app/core/context.py`)

The per-request mutable state carrier. All hooks receive the same context object; mutations are visible to later hooks.

| Field | Type | Set by |
|---|---|---|
| `session_id` | `str` (UUID4) | Auto on construction |
| `scenario_id` | `str` | API request |
| `user_input` | `str` | API request |
| `system_prompt` | `str` | Orchestrator (from scenario config) |
| `retrieval_query` | `str` | Orchestrator, or module via `before_retrieval` |
| `retrieved_docs` | `list[dict]` | RAG pipeline; modules via `after_retrieval` |
| `augmented_prompt` | `str` | Orchestrator after retrieval |
| `tool_calls` | `list[dict]` | Orchestrator after each tool round |
| `tool_results` | `list[dict]` | Orchestrator after each tool round |
| `llm_response` | `str` | Orchestrator after LLM call |
| `final_response` | `str` | Orchestrator after `before_response` hook |
| `active_modules` | `list[str]` | Orchestrator at run start |
| `hook_traces` | `list[HookTrace]` | Orchestrator after each mutating hook |
| `telemetry_events` | `list[dict]` | `ctx.emit_event()` calls |
| `score_evidence` | `list[dict]` | Modules during hooks |
| `score_result` | `dict \| None` | ScoringEngine at run end |
| `metadata` | `dict` | Module-private per-request data |

`ctx.emit_event(event_type, data)` appends a timestamped dict to `telemetry_events`. This is the standard way for modules to record what they observed.

### HookTrace (`app/core/context.py`)

Captured automatically by the orchestrator whenever a hook mutates the context.

```python
@dataclass
class HookTrace:
    hook_point: str           # e.g. "after_retrieval"
    module_id: str            # e.g. "indirect_prompt_injection_rag"
    input_snapshot: dict      # snapshot of key fields before the hook
    output_snapshot: dict     # snapshot after the hook
    mutations: list[str]      # human-readable list of what changed
```

### VulnerabilityModule (`app/vulnerabilities/base.py`)

Abstract base class. Every module must implement `module_id`. All hook methods have default no-op implementations so modules only override what they need.

### ModuleRegistry (`app/vulnerabilities/registry.py`)

Singleton registry. `@register` class decorator registers a module class by its `module_id`. `registry.autodiscover()` imports all files under `app/vulnerabilities/modules/` to trigger registration. Called once in the FastAPI lifespan and once at test collection time (`tests/conftest.py`).

### ScenarioOrchestrator (`app/core/orchestrator.py`)

Stateless. One `run(ctx)` call executes the full pipeline for one request:

1. Sets `ctx.active_modules`
2. Applies system prompt from scenario config
3. Fires `before_prompt` hooks
4. If RAG enabled: fires `before_retrieval`, calls `rag.retrieve()`, fires `after_retrieval`
5. Builds `ctx.augmented_prompt`, fires `after_prompt`
6. Calls `_llm_with_tools()` (tool loop, up to `max_tool_rounds`)
7. Fires `before_response`, sets `ctx.final_response = ctx.llm_response`, fires `after_response`
8. Calls `scorer.score(ctx, modules)` → `ctx.score_result`
9. In `finally`: calls `module.cleanup(ctx)` for each module, flushes telemetry

The tool loop fires `before_tool_call` and `after_tool_call` hooks for every tool call in every round. `before_tool_call` receives the args dict and must return it (possibly modified).

### LLM Router (`app/models/router.py`)

Unified interface over multiple providers. Selects the adapter based on `provider_config`. All adapters return `LLMResponse(content, tool_calls)`.

| Adapter | Provider |
|---|---|
| `OpenAIAdapter` | OpenAI API, Azure OpenAI |
| `AnthropicAdapter` | Anthropic API |
| `OllamaAdapter` | Ollama (local) |
| `GeminiAdapter` | Google Gemini |
| `VLLMAdapter` | vLLM / LM Studio |

### RAG Pipeline (`app/rag/pipeline.py`)

Wraps ChromaDB. Each scenario gets its own named collection (e.g. `soc_copilot`). `retrieve(query, ctx, n_results)` returns a list of dicts with `id`, `content`, `metadata`, and `similarity` fields.

Seeding: `RAGPipeline.seed(documents)` upserts documents in batches using cosine-space embeddings. `from_config(scenario_cfg)` is the factory used by the scenario loader. On startup, `_seed_all_scenarios()` in `app/api/main.py` seeds any empty collection.

### Tool Executor (`app/tools/executor.py`)

Registry of sandboxed tool handlers. `from_config(tools_config)` looks up handlers in `app/tools/sandboxed_tools.py` by convention (`handle_{tool_id}`). `execute(tool_name, args, ctx)` calls the handler and emits `tool_execute_start` / `tool_execute_end` events.

`to_openai_schema()` returns the OpenAI function-call schema for all registered tools.

### Scoring Engine (`app/scoring/engine.py`)

Aggregates evidence from two sources:

1. **Module evidence**: each module's `score(ctx) -> list[dict]` is called after the run. Each dict is a scoring item (see [Rule Dict Format](#rule-dict-format)).
2. **YAML rules**: defined in the scenario config under `scoring_rules`. Evaluated by built-in condition evaluators.

YAML condition evaluators:

| Condition key | What it checks |
|---|---|
| `response_matches_pattern` | Regex match in a `RunContext` field (default: `final_response`) |
| `hook_trace_contains` | A `HookTrace` matching `hook_point`, `module_id`, and a substring in `mutations` |
| `tool_call_matches` | A tool call with the given `tool_name` in `ctx.tool_calls` |
| `event_type_present` | An event with the given `event_type` in `ctx.telemetry_events` |

#### Rule Dict Format

```python
{
    "rule_id": "injection_doc_inserted",     # unique within a scenario run
    "description": "Human-readable text",
    "passed": True,                          # True = vulnerability triggered
    "evidence": "What was observed",
    "severity": "critical",                  # critical | high | medium | low | info
    "source": "module",                      # "module" or "yaml_rule"
}
```

The final `score_result` dict:

```python
{
    "total_rules": 6,
    "triggered": 3,
    "critical_triggered": 2,
    "high_triggered": 1,
    "evidence": [...],            # all rule dicts
    "overall_status": "vulnerable",  # or "not_triggered"
}
```

### Telemetry Writer (`app/telemetry/writer.py`)

`flush(ctx)` writes the complete session (all `telemetry_events`, `hook_traces`, and `score_result`) to a JSONL file under `{data_dir}/telemetry/{session_id}.jsonl`. `TelemetryWriter.default()` is a singleton returning the shared writer instance.

### FastAPI App (`app/api/main.py`)

Three route groups:

| Route | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/api/v1/scenarios` | GET | List available scenario IDs |
| `/api/v1/scenarios/{id}` | GET | Scenario metadata |
| `/api/v1/modules` | GET | List registered module IDs |
| `/api/v1/run` | POST | Execute a scenario run |

The lifespan handler calls `registry.autodiscover()` and `_seed_all_scenarios()` on startup.

### CLI (`app/cli/main.py`)

Typer CLI with commands: `run`, `list-scenarios`, `list-modules`, `validate-config`.

---

## Hook Lifecycle

Hooks fire in this order for every request. Each hook point dispatches modules sorted by `priority` (lower = earlier).

```
Request arrives
      │
      ▼
① before_prompt(ctx)
      │  Modules may modify: user_input, system_prompt
      ▼
② before_retrieval(ctx)
      │  Modules may modify: retrieval_query
      ▼
   RAG retrieve → ctx.retrieved_docs
      │
      ▼
③ after_retrieval(ctx)
      │  Modules may modify: retrieved_docs
      │  ← PRIMARY injection point for LLM02 attacks
      ▼
   Build augmented_prompt
      │
      ▼
④ after_prompt(ctx)
      │  Modules may observe: augmented_prompt
      ▼
   LLM call (first round)
      │
      ├─ if tool_calls returned ──►
      │      ⑤ before_tool_call(ctx, tool_name, args) → args
      │           └─ Modules may modify args (or skip validation)
      │      Tool execution
      │      ⑥ after_tool_call(ctx, tool_name, result) → result
      │           └─ Modules may modify result
      │      LLM call (next round) ──► loop back
      │
      ▼ (no more tool calls)
⑦ before_response(ctx)
      │  Modules may observe: llm_response
      │  ← PRIMARY scan point for LLM05/LLM07 attacks
      ▼
   ctx.final_response = ctx.llm_response
      │
      ▼
⑧ after_response(ctx)
      │  Modules may observe or modify: final_response
      ▼
   ScoringEngine.score() — calls module.score(ctx) for each module
      │
      ▼
   module.cleanup(ctx) — always, even on error
      │
      ▼
   TelemetryWriter.flush(ctx)
```

---

## Scenario Config Format

```yaml
# configs/scenarios/my_scenario.yaml
id: my_scenario
name: My Scenario
description: Short description

provider: openai   # refers to configs/providers/openai.yaml
model: gpt-4o-mini

system_prompt: |
  You are an AI assistant. ...

rag_enabled: true
rag_collection: my_scenario   # ChromaDB collection name
rag_n_results: 5

tools:
  - id: search_incidents
  - id: escalate_incident

max_tool_rounds: 5

vulnerability_modules:
  - module_id: indirect_prompt_injection_rag
    injection_probability: 1.0
    injection_position: 0

scoring_rules:
  - rule_id: my_yaml_rule
    description: LLM echoed the injection keyword
    severity: critical
    condition:
      response_matches_pattern:
        field: final_response
        patterns:
          - "(?i)maintenance mode"
```

All keys under a `vulnerability_modules` entry (except `module_id`, `enabled`, and `priority`) are passed as flat config to the module's `on_load()`.

---

## Project Layout

```
app/
  api/          FastAPI routes and lifespan
  cli/          Typer CLI (vai-lab)
  core/         Orchestrator, RunContext, config loader, settings, exceptions
  models/       LLM router and adapters
  rag/          ChromaDB pipeline (seeding, retrieval)
  scoring/      Evidence aggregation and YAML rule evaluators
  telemetry/    JSONL session writer
  tools/        Tool executor, sandboxed handlers, OpenAI schemas
  vulnerabilities/
    base.py     VulnerabilityModule ABC
    registry.py ModuleRegistry + @register decorator
    modules/    Built-in vulnerability modules

configs/
  scenarios/    YAML scenario definitions
  providers/    YAML provider definitions (model, base_url, etc.)

datasets/
  soc_copilot/  Synthetic incidents, threat intel, adversarial doc
  code_assistant/ Synthetic PRs, coding standards, adversarial doc

tests/
  unit/         Module and component unit tests
  integration/  API endpoint tests (FastAPI TestClient)
  scenarios/    Full-pipeline scenario tests (async, mocked LLM/RAG)

docs/           This directory
scripts/        Standalone seed CLI
ui/             Single-page frontend (vanilla JS, no build step)
```
