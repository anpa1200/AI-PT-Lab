FROM python:3.12-slim

WORKDIR /app

# System deps needed by sentence-transformers and chromadb
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps before copying source (better layer caching).
# README.md is required by hatchling during metadata generation.
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir ".[dev]"

COPY . .

RUN chmod +x docker-entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["./docker-entrypoint.sh"]
