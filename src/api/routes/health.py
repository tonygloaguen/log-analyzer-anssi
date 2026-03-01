"""
Route GET /health — vérification de l'état des services.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter

from src.api.schemas import HealthResponse

router = APIRouter()

VERSION = "1.0.0"


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Vérifie la disponibilité de tous les services dépendants."""
    services: dict[str, str] = {}

    # Vérifier Ollama
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
    services["ollama"] = await _check_http(f"{ollama_url}/api/version")

    # Vérifier Loki
    loki_url = os.getenv("LOKI_URL", "http://loki:3100")
    services["loki"] = await _check_http(f"{loki_url}/ready")

    overall = "healthy" if all(s == "healthy" for s in services.values()) else "degraded"

    return HealthResponse(
        status=overall,
        version=VERSION,
        services=services,
        timestamp=datetime.now(timezone.utc),
    )


async def _check_http(url: str, timeout: float = 3.0) -> str:
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.get(url)
            return "healthy" if resp.status_code < 400 else "unhealthy"
        except Exception:
            return "unreachable"
