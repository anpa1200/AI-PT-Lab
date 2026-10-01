from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.core.exceptions import ConfigError
from app.course.catalog import get_course_module, list_course_modules, load_course

router = APIRouter(prefix="/course", tags=["course"])


@router.get("")
async def get_course() -> dict:
    """Return the course identity and syllabus for learner-facing clients."""
    try:
        course = load_course()
    except ConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {
        "id": course["id"],
        "title": course["title"],
        "version": course["version"],
        "status": course.get("status", "draft"),
        "description": course.get("description", ""),
        "evidence_policy": course.get("evidence_policy", {}),
        "learning_loop": course.get("learning_loop", []),
        "modules": list_course_modules(),
    }


@router.get("/modules/{module_id}")
async def get_module(module_id: str) -> dict:
    try:
        course = load_course()
        module = get_course_module(module_id)
    except ConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Course module not found: {module_id}") from exc

    return {"course_id": course["id"], "module": module}
