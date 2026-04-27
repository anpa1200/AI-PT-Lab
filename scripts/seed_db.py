#!/usr/bin/env python3
"""
Seed ChromaDB collections for all RAG-enabled scenarios.

Usage:
    python scripts/seed_db.py                    # seed all, skip non-empty
    python scripts/seed_db.py --scenario soc_copilot
    python scripts/seed_db.py --reset            # wipe and re-seed all
    python scripts/seed_db.py --scenario soc_copilot --reset
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Ensure the project root is on sys.path when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config_loader import list_scenarios, load_scenario
from app.rag.pipeline import RAGPipeline

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger("seed_db")


def seed_scenario(scenario_id: str, reset: bool = False) -> int:
    """Seed one scenario. Returns number of documents added."""
    cfg = load_scenario(scenario_id)
    scenario = cfg.get("scenario", cfg)
    rag_cfg = scenario.get("rag", {})

    if not rag_cfg.get("enabled", False):
        logger.info("%-20s  RAG disabled — skipped", scenario_id)
        return 0

    pipeline = RAGPipeline.from_config(rag_cfg)

    if reset:
        pipeline.reset()
        logger.info("%-20s  collection reset", scenario_id)
    elif pipeline.count() > 0:
        logger.info("%-20s  already seeded (%d docs) — use --reset to force", scenario_id, pipeline.count())
        return 0

    seeded = 0
    seed_cfg = scenario.get("seed", {}) or {}
    if seed_cfg.get("incidents"):
        p = Path(seed_cfg["incidents"])
        if p.exists():
            n = pipeline.seed_from_jsonl(p)
            seeded += n
            logger.info("%-20s  +%d docs from %s", scenario_id, n, p)
        else:
            logger.warning("%-20s  seed file not found: %s", scenario_id, p)

    for ds_path in rag_cfg.get("datasets", []):
        p = Path(ds_path)
        if p.is_dir():
            n = pipeline.seed_from_directory(p)
            seeded += n
            logger.info("%-20s  +%d docs from directory %s", scenario_id, n, p)
        elif p.is_file():
            n = pipeline.seed_from_jsonl(p)
            seeded += n
            logger.info("%-20s  +%d docs from %s", scenario_id, n, p)
        else:
            logger.warning("%-20s  dataset path not found: %s", scenario_id, ds_path)

    logger.info("%-20s  total seeded: %d", scenario_id, seeded)
    return seeded


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed ChromaDB for AI Vuln Lab scenarios")
    parser.add_argument("--scenario", metavar="ID", help="Seed only this scenario")
    parser.add_argument("--reset", action="store_true", help="Wipe collection before seeding")
    args = parser.parse_args()

    targets = [args.scenario] if args.scenario else list_scenarios()
    if not targets:
        logger.error("No scenarios found in configs/scenarios/")
        sys.exit(1)

    total = 0
    errors = []
    for scenario_id in targets:
        try:
            total += seed_scenario(scenario_id, reset=args.reset)
        except Exception as exc:
            logger.error("%-20s  FAILED: %s", scenario_id, exc)
            errors.append(scenario_id)

    print(f"\nDone. {total} documents seeded across {len(targets)} scenario(s).")
    if errors:
        print(f"Errors in: {', '.join(errors)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
