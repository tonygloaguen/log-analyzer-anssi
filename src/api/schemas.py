"""
Schémas Pydantic pour l'API FastAPI.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    """Corps de la requête POST /analyze."""

    source: str = Field(default="*", description="Source de logs (nginx, ssh, *)")
    time_range: str = Field(default="1h", description="Fenêtre temporelle (1h, 24h, 7d)")
    analysis_id: str | None = Field(default=None, description="UUID optionnel (généré si absent)")
    raw_logs: list[dict[str, Any]] | None = Field(
        default=None,
        description="Logs bruts à analyser (si absent, récupérés depuis Loki)",
    )

    model_config = {"json_schema_extra": {
        "example": {
            "source": "nginx",
            "time_range": "1h",
        }
    }}


class AnomalyResponse(BaseModel):
    anomaly_type: str
    score: float
    description: str
    affected_count: int


class AnalysisResponse(BaseModel):
    """Réponse de l'endpoint POST /analyze."""

    analysis_id: str
    status: str
    routed_to: str
    overall_risk_score: float
    total_logs_analyzed: int
    anomalies_count: int
    anomalies: list[AnomalyResponse]
    final_severity: str
    llm_summary: str
    recommendations: list[str]
    created_at: datetime
    requires_human_review: bool


class ReportSummary(BaseModel):
    """Résumé d'un rapport pour la liste GET /reports."""

    id: str
    created_at: datetime
    status: str
    overall_risk_score: float
    total_logs_analyzed: int
    anomalies_count: int
    requires_human_review: bool


class HealthResponse(BaseModel):
    """Réponse de GET /health."""

    status: str
    version: str
    services: dict[str, str]
    timestamp: datetime
