from __future__ import annotations

import asyncio
import json
import logging
import uuid
from pathlib import Path
from typing import Any

from app.core.context import RunContext
from app.core.exceptions import RAGError
from app.core.settings import settings

logger = logging.getLogger(__name__)

# Per-collection write lock — ChromaDB embedded is not thread-safe for concurrent writes
_collection_locks: dict[str, asyncio.Lock] = {}


def _get_lock(collection_name: str) -> asyncio.Lock:
    if collection_name not in _collection_locks:
        _collection_locks[collection_name] = asyncio.Lock()
    return _collection_locks[collection_name]


class RAGPipeline:
    def __init__(
        self,
        collection_name: str,
        embedding_model: str = "all-MiniLM-L6-v2",
        top_k: int = 5,
        similarity_threshold: float = 0.5,
    ) -> None:
        self._collection_name = collection_name
        self._top_k = top_k
        self._threshold = similarity_threshold
        self._client = self._build_client()
        self._embedding_fn = self._build_embedding_fn(embedding_model)
        self._collection = self._client.get_or_create_collection(
            name=collection_name,
            embedding_function=self._embedding_fn,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(
            "RAGPipeline ready: collection=%s top_k=%d threshold=%.2f",
            collection_name, top_k, similarity_threshold,
        )

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> RAGPipeline:
        return cls(
            collection_name=config["collection"],
            embedding_model=config.get("embedding_model", "all-MiniLM-L6-v2"),
            top_k=config.get("top_k", 5),
            similarity_threshold=config.get("similarity_threshold", 0.5),
        )

    # ── Seeding ───────────────────────────────────────────────────────────────

    def seed_from_jsonl(self, path: Path) -> int:
        """Load documents from a JSONL file into the collection. Returns count added."""
        docs, ids, metas = [], [], []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("Skipping malformed JSONL line in %s: %s", path, exc)
                continue
            doc_id = str(obj.get("id", uuid.uuid4()))
            docs.append(obj["content"])
            ids.append(doc_id)
            metas.append({k: str(v) for k, v in obj.items() if k not in ("id", "content")})

        if docs:
            self._collection.upsert(documents=docs, ids=ids, metadatas=metas)
            logger.info("Seeded %d documents into collection '%s'", len(docs), self._collection_name)
        return len(docs)

    def seed_from_directory(self, directory: Path, glob: str = "*.jsonl") -> int:
        """Seed all JSONL files in a directory."""
        total = 0
        for path in sorted(directory.glob(glob)):
            total += self.seed_from_jsonl(path)
        return total

    async def add_documents(self, documents: list[dict[str, Any]]) -> None:
        """Add documents at runtime (used by injection modules). Thread-safe."""
        async with _get_lock(self._collection_name):
            docs = [d["content"] for d in documents]
            ids = [str(d.get("id", uuid.uuid4())) for d in documents]
            metas = [
                {k: str(v) for k, v in d.items() if k not in ("id", "content")}
                for d in documents
            ]
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self._collection.upsert(documents=docs, ids=ids, metadatas=metas),
            )

    def delete_documents(self, ids: list[str]) -> None:
        self._collection.delete(ids=ids)

    def reset(self) -> None:
        """Delete and recreate the collection — used by the scenario reset endpoint."""
        self._client.delete_collection(self._collection_name)
        self._collection = self._client.get_or_create_collection(
            name=self._collection_name,
            embedding_function=self._embedding_fn,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("Collection '%s' reset.", self._collection_name)

    def count(self) -> int:
        return self._collection.count()

    # ── Retrieval ─────────────────────────────────────────────────────────────

    async def retrieve(self, query: str, ctx: RunContext) -> list[dict[str, Any]]:
        ctx.emit_event("rag_retrieve_start", {
            "query": query[:200],
            "collection": self._collection_name,
            "top_k": self._top_k,
        })
        logger.debug("RAG retrieve: collection=%s query=%r", self._collection_name, query[:80])

        if self._collection.count() == 0:
            logger.warning("Collection '%s' is empty — no documents seeded yet", self._collection_name)
            ctx.emit_event("rag_retrieve_end", {"doc_count": 0, "warning": "empty_collection"})
            return []

        loop = asyncio.get_event_loop()
        try:
            results = await loop.run_in_executor(
                None,
                lambda: self._collection.query(
                    query_texts=[query],
                    n_results=min(self._top_k, self._collection.count()),
                    include=["documents", "metadatas", "distances"],
                ),
            )
        except Exception as exc:
            raise RAGError(f"ChromaDB query failed: {exc}") from exc

        docs: list[dict[str, Any]] = []
        for content, meta, distance in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            # ChromaDB cosine distance: 0 = identical, 2 = opposite
            # Convert to similarity score in [0, 1]
            similarity = max(0.0, 1.0 - distance)
            if similarity >= self._threshold:
                docs.append({
                    "content": content,
                    "metadata": meta or {},
                    "similarity": round(similarity, 4),
                })

        docs.sort(key=lambda d: d["similarity"], reverse=True)
        ctx.emit_event("rag_retrieve_end", {
            "doc_count": len(docs),
            "collection": self._collection_name,
        })
        logger.debug("RAG retrieved %d docs above threshold %.2f", len(docs), self._threshold)
        return docs

    # ── Internals ─────────────────────────────────────────────────────────────


    @staticmethod
    def _build_client():
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
        except ImportError as exc:
            raise RAGError("chromadb not installed — run: pip install chromadb") from exc

        data_dir = Path(settings.data_dir) / "chromadb"
        data_dir.mkdir(parents=True, exist_ok=True)
        return chromadb.PersistentClient(
            path=str(data_dir),
            settings=ChromaSettings(anonymized_telemetry=False),
        )

    @staticmethod
    def _build_embedding_fn(model_name: str):
        try:
            from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
        except ImportError as exc:
            raise RAGError(
                "sentence-transformers not installed — run: pip install sentence-transformers"
            ) from exc
        return SentenceTransformerEmbeddingFunction(model_name=model_name)


def seed_scenario(pipeline: RAGPipeline, scenario: dict[str, Any]) -> int:
    """
    Seed a RAGPipeline from a scenario's seed + rag.datasets config.

    Shared by startup seeding (main.py) and the /reset API endpoint so the
    logic stays in one place.  Returns the total number of documents seeded.
    """
    seeded = 0
    seed_cfg = scenario.get("seed") or {}
    if seed_cfg.get("incidents"):
        p = Path(seed_cfg["incidents"])
        if p.exists():
            seeded += pipeline.seed_from_jsonl(p)

    for ds_path in scenario.get("rag", {}).get("datasets", []):
        p = Path(ds_path)
        if p.is_dir():
            seeded += pipeline.seed_from_directory(p)
        elif p.is_file():
            seeded += pipeline.seed_from_jsonl(p)

    return seeded
