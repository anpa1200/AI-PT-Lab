# Vulnerable AI Lab

A modular, intentionally vulnerable AI security training lab — like DVWA/WebGoat, but for modern AI applications.

## What It Is

Vulnerable AI Lab simulates realistic AI product architectures (RAG assistants, tool-using agents, SOC copilots) with pluggable vulnerability modules. Each vulnerability is a hook-based module that can modify prompts, retrieval results, tools, memory, or output handling.

## Quick Start

```bash
cp .env.example .env
# Add your OPENAI_API_KEY or configure OLLAMA_BASE_URL for local mode

docker compose up
```

- Web UI: http://localhost:3000
- API: http://localhost:8000
- API docs: http://localhost:8000/docs

## CLI

```bash
pip install -e ".[dev]"

vai-lab run soc_copilot --input "Check IOC 185.220.101.47"
vai-lab list-scenarios
vai-lab list-modules
```

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Writing Modules

See [docs/writing-a-module.md](docs/writing-a-module.md).

## Build Phases

| Phase | What |
|-------|------|
| 0 | Repository skeleton ← **current** |
| 1 | Core data structures and config layer |
| 2 | Vulnerability module system (hook engine) |
| 3 | Scenario orchestrator |
| 4 | LLM router and adapters |
| 5 | RAG pipeline |
| 6 | Tool executor (sandboxed) |
| 7 | MVP vulnerability modules |
| 8 | Scoring engine and telemetry |
| 9 | FastAPI layer |
| 10 | CLI runner |

## Safety

This lab uses **synthetic data only**. No real emails are sent. No real cloud APIs are called. No real credentials are used. All tools are sandboxed.

## License

MIT
