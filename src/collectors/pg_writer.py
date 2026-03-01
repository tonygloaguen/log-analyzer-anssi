"""
Écrivain PostgreSQL — Stockage structuré des logs et rapports.

Utilise asyncpg pour les insertions asynchrones.
La table audit_trail est utilisée pour la traçabilité ANSSI.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

POSTGRES_DSN = os.getenv(
    "POSTGRES_DSN",
    "postgresql+asyncpg://loguser:password@postgres:5432/log_analyzer",
)


class PostgresWriter:
    """Client asynchrone pour l'écriture en base PostgreSQL."""

    def __init__(self, dsn: str = POSTGRES_DSN) -> None:
        self.dsn = dsn
        self._pool: Any = None

    async def connect(self) -> None:
        """Initialise le pool de connexions asyncpg."""
        import asyncpg
        # Convertir le DSN SQLAlchemy en DSN asyncpg natif
        dsn = self.dsn.replace("postgresql+asyncpg://", "postgresql://")
        self._pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10)
        logger.info("Pool PostgreSQL initialisé")

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    async def insert_log_entry(self, log: dict[str, Any]) -> None:
        """Insère un log normalisé dans la table log_entries."""
        if not self._pool:
            raise RuntimeError("Pool PostgreSQL non initialisé")

        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO log_entries
                    (id, timestamp, source, host, raw_message, normalized_message,
                     severity, tags, metadata, hmac_signature, integrity_verified)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $11)
                ON CONFLICT (id) DO NOTHING
                """,
                log["id"],
                log["timestamp"],
                log["source"],
                log["host"],
                log["raw_message"],
                log.get("normalized_message", ""),
                log["severity"],
                json.dumps(log.get("tags", [])),
                json.dumps(log.get("metadata", {})),
                log.get("hmac_signature", ""),
                log.get("integrity_verified", False),
            )

    async def insert_report(self, report: dict[str, Any]) -> None:
        """Insère un rapport d'analyse en base."""
        if not self._pool:
            raise RuntimeError("Pool PostgreSQL non initialisé")

        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO analysis_reports
                    (id, created_at, source_filter, total_logs_analyzed,
                     overall_risk_score, status, routed_to, escalation_reason,
                     llm_summary, recommendations, audit_trail)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb)
                ON CONFLICT (id) DO NOTHING
                """,
                report["id"],
                report.get("created_at", datetime.now(timezone.utc)),
                report.get("source_filter", "*"),
                report.get("total_logs_analyzed", 0),
                report.get("overall_risk_score", 0.0),
                report.get("status", "pending"),
                report.get("routed_to", ""),
                report.get("escalation_reason", ""),
                report.get("llm_summary", ""),
                json.dumps(report.get("recommendations", [])),
                json.dumps(report.get("audit_trail", [])),
            )

    async def insert_audit_event(self, event: dict[str, Any]) -> None:
        """Insère un événement dans la table d'audit ANSSI."""
        if not self._pool:
            raise RuntimeError("Pool PostgreSQL non initialisé")

        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_trail
                    (event_type, event_timestamp, details, actor)
                VALUES ($1, $2, $3::jsonb, $4)
                """,
                event.get("event", "unknown"),
                datetime.now(timezone.utc),
                json.dumps(event.get("details", {})),
                event.get("actor", "system"),
            )
