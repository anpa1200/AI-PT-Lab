#!/bin/sh
set -e

# Create persistent data directories if they don't exist
mkdir -p "${LAB_DATA_DIR:-/app/data}/chromadb"
mkdir -p "${LAB_DATA_DIR:-/app/data}/telemetry"

exec uvicorn app.api.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 1 \
    --log-level "${LAB_LOG_LEVEL:-info}"
