.PHONY: build up down logs shell test seed reset lint

# ── Docker ────────────────────────────────────────────────────────────────────

build:
	docker compose build

up:
	docker compose up -d
	@echo "Backend: http://localhost:8000/docs"
	@echo "UI:      http://localhost:3000"

down:
	docker compose down

logs:
	docker compose logs -f backend

shell:
	docker compose exec backend bash

# Production stack (no dev overrides)
up-prod:
	docker compose -f docker-compose.yml up -d

# ── Database ──────────────────────────────────────────────────────────────────

seed:
	docker compose exec backend python scripts/seed_db.py

seed-reset:
	docker compose exec backend python scripts/seed_db.py --reset

reset:
	docker compose exec backend python scripts/seed_db.py --reset

# ── Testing ───────────────────────────────────────────────────────────────────

test:
	python3.12 -m pytest tests/ -q

test-unit:
	python3.12 -m pytest tests/unit/ -q

test-integration:
	python3.12 -m pytest tests/integration/ -q

test-scenarios:
	python3.12 -m pytest tests/scenarios/ -q

test-verbose:
	python3.12 -m pytest tests/ -v

# ── CLI shortcuts ─────────────────────────────────────────────────────────────

list-scenarios:
	python3.12 -m app.cli.main list-scenarios

list-modules:
	python3.12 -m app.cli.main list-modules

validate:
	python3.12 -m app.cli.main validate-config
