from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict:
    return {"status": "ok", "version": "0.1.0", "lab": "Vulnerable AI Lab"}
