# Architecture

## Overview

Vulnerable AI Lab is a modular, intentionally vulnerable AI security training lab.

```
User (Web UI / CLI)
        │
        ▼
  Lab API Gateway (FastAPI)
        │
        ▼
  Scenario Orchestrator
   ├── LLM Router → Model Adapters (OpenAI / Anthropic / Ollama / Gemini)
   ├── RAG Pipeline → ChromaDB
   ├── Tool Executor → Sandboxed Tools
   └── Vulnerability Module Engine (hook chain)
        │
        ▼
  Scoring Engine + Telemetry Writer
```

## Key Design Decisions

1. **Synchronous hook chain**: Each hook point calls modules in priority order, passing a mutable `RunContext`. No async event bus.
2. **Per-request isolation**: `RunContext` is instantiated per API request. Modules are singletons; all state lives in context.
3. **YAML-first config**: Scenarios and provider config are YAML files. Adding a new scenario requires zero Python changes.
4. **Stateless plugins**: Vulnerability modules never hold mutable state between runs.
5. **ChromaDB embedded**: In-process, no separate service for MVP.
6. **Evidence-first scoring**: Modules collect evidence into `RunContext`; scoring engine aggregates — no LLM-as-judge.

## Components

| Component | File | Phase |
|-----------|------|-------|
| Settings | `app/core/settings.py` | 0 |
| Config loader | `app/core/config_loader.py` | 0 |
| Run context | `app/core/context.py` | 0 |
| Module base | `app/vulnerabilities/base.py` | 2 |
| Module registry | `app/vulnerabilities/registry.py` | 2 |
| Orchestrator | `app/core/orchestrator.py` | 3 |
| LLM router | `app/models/router.py` | 4 |
| RAG pipeline | `app/rag/pipeline.py` | 5 |
| Tool executor | `app/tools/executor.py` | 6 |
| Vulnerability modules | `app/vulnerabilities/modules/` | 7 |
| Scoring engine | `app/scoring/engine.py` | 8 |
| Telemetry writer | `app/telemetry/writer.py` | 8 |
| FastAPI app | `app/api/main.py` | 9 |
| CLI | `app/cli/main.py` | 10 |
