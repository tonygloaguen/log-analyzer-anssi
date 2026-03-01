"""
Collecteur de logs depuis Loki — Interface asynchrone.

Récupère les logs via l'API LogQL de Loki et les transmet
au pipeline LangGraph pour analyse.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")
DEFAULT_LIMIT = 5000


class LokiCollector:
    """Client asynchrone pour l'API Loki."""

    def __init__(self, base_url: str = LOKI_URL, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def query_range(
        self,
        logql_query: str,
        start: datetime,
        end: datetime,
        limit: int = DEFAULT_LIMIT,
    ) -> list[dict[str, Any]]:
        """
        Récupère des logs depuis Loki via une requête LogQL.

        Args:
            logql_query: Requête LogQL (ex: '{job="nginx"}').
            start: Début de la fenêtre temporelle.
            end: Fin de la fenêtre temporelle.
            limit: Nombre maximum de logs à récupérer.

        Returns:
            Liste de logs normalisés (dict).
        """
        params = {
            "query": logql_query,
            "start": str(int(start.timestamp() * 1e9)),
            "end": str(int(end.timestamp() * 1e9)),
            "limit": str(limit),
            "direction": "forward",
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(
                    f"{self.base_url}/loki/api/v1/query_range",
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()
                return self._parse_loki_response(data)

            except httpx.HTTPStatusError as e:
                logger.error("Erreur HTTP Loki (%s): %s", e.response.status_code, e)
                raise
            except httpx.TimeoutException:
                logger.error("Timeout lors de la requête Loki")
                raise

    def _parse_loki_response(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse la réponse JSON de Loki en liste de logs."""
        logs = []
        result = data.get("data", {}).get("result", [])

        for stream in result:
            labels = stream.get("stream", {})
            for ts_ns, line in stream.get("values", []):
                logs.append({
                    "timestamp": int(ts_ns),
                    "message": line,
                    "source": labels.get("job", labels.get("app", "unknown")),
                    "host": labels.get("host", labels.get("hostname", "unknown")),
                    **{k: v for k, v in labels.items() if k not in ("job", "host", "hostname")},
                })

        return logs

    async def get_logs_for_source(
        self,
        source: str,
        time_range: str = "1h",
    ) -> list[dict[str, Any]]:
        """
        Récupère les logs d'une source spécifique.

        Args:
            source: Nom du job Loki (ex: "nginx", "*").
            time_range: Fenêtre temporelle (ex: "1h", "24h", "7d").
        """
        duration_map = {
            "15m": 900, "30m": 1800, "1h": 3600,
            "6h": 21600, "24h": 86400, "7d": 604800,
        }
        seconds = duration_map.get(time_range, 3600)
        end = datetime.now(timezone.utc)
        start = end - timedelta(seconds=seconds)

        if source == "*":
            query = '{job=~".+"}'
        else:
            query = f'{{job="{source}"}}'

        return await self.query_range(query, start, end)

    async def is_healthy(self) -> bool:
        """Vérifie que Loki est opérationnel."""
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                resp = await client.get(f"{self.base_url}/ready")
                return resp.status_code == 200
            except Exception:
                return False
