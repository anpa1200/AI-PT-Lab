from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_INSTRUCTION_RE = re.compile(
    r"\b(always|ignore|override|from now on|system instruction|remember to|never|forget|you must|you should)\b",
    re.IGNORECASE,
)


class MemoryEntry:
    def __init__(
        self,
        key: str,
        value: str,
        trust_level: str = "low",
        provenance: str = "user",
        ttl: int | None = None,
    ) -> None:
        self.key = key
        self.value = value
        self.trust_level = trust_level
        self.provenance = provenance
        self.created_at = time.time()
        self.expires_at = self.created_at + ttl if ttl else None

    def is_expired(self) -> bool:
        return self.expires_at is not None and time.time() > self.expires_at

    def is_instruction_like(self) -> bool:
        return bool(_INSTRUCTION_RE.search(self.value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "trust_level": self.trust_level,
            "provenance": self.provenance,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MemoryEntry:
        entry = cls(
            key=d["key"],
            value=d["value"],
            trust_level=d.get("trust_level", "low"),
            provenance=d.get("provenance", "user"),
        )
        entry.created_at = d.get("created_at", time.time())
        entry.expires_at = d.get("expires_at")
        return entry


class MemoryStore:
    def __init__(self, path: Path | None = None) -> None:
        from app.core.settings import settings
        self._path = path or (Path(settings.data_dir) / "memory.json")
        self._entries: dict[str, MemoryEntry] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                self._entries = {k: MemoryEntry.from_dict(v) for k, v in raw.items()}
            except Exception as exc:
                logger.warning("Failed to load memory store: %s", exc)

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps({k: e.to_dict() for k, e in self._entries.items()}, indent=2),
            encoding="utf-8",
        )

    def write(
        self,
        key: str,
        value: str,
        trust_level: str = "low",
        provenance: str = "user",
        ttl: int | None = None,
    ) -> MemoryEntry:
        entry = MemoryEntry(key, value, trust_level, provenance, ttl)
        self._entries[key] = entry
        self._save()
        logger.info(
            "Memory write: key=%s trust=%s instruction_like=%s",
            key, trust_level, entry.is_instruction_like(),
        )
        return entry

    def read(self, key: str) -> MemoryEntry | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.is_expired():
            del self._entries[key]
            self._save()
            return None
        return entry

    def all_active(self) -> list[MemoryEntry]:
        expired = [k for k, e in self._entries.items() if e.is_expired()]
        for k in expired:
            del self._entries[k]
        if expired:
            self._save()
        return list(self._entries.values())

    def delete(self, key: str) -> None:
        self._entries.pop(key, None)
        self._save()

    def clear(self) -> None:
        self._entries.clear()
        self._save()


_store: MemoryStore | None = None


def get_memory_store() -> MemoryStore:
    global _store
    if _store is None:
        _store = MemoryStore()
    return _store


def reset_memory_store() -> None:
    """Force a fresh store instance — used in tests."""
    global _store
    _store = None
