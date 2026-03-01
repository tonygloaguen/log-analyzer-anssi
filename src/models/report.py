"""
Modèle de rapport d'analyse généré par le pipeline LangGraph.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ReportStatus(str, Enum):
    PENDING = "pending"
    AUTO_RESOLVED = "auto_resolved"
    ESCALATED = "escalated"
    ACKNOWLEDGED = "acknowledged"


class AnomalyDetail(BaseModel):
    """Détail d'une anomalie détectée."""

    anomaly_type: str
    score: float = Field(ge=0.0, le=1.0)
    description: str
    affected_log_ids: list[str] = Field(default_factory=list)
    llm_analysis: str = ""


class AnalysisReport(BaseModel):
    """Rapport complet produit par le pipeline d'analyse."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    analysis_window_start: datetime
    analysis_window_end: datetime
    source_filter: str = "*"

    # Résultats de l'analyse
    total_logs_analyzed: int = 0
    anomalies_detected: list[AnomalyDetail] = Field(default_factory=list)
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    status: ReportStatus = ReportStatus.PENDING

    # Routing LangGraph
    routed_to: str = ""  # "auto_report" ou "human_escalation"
    escalation_reason: str = ""

    # Recommandations LLM
    llm_summary: str = ""
    recommendations: list[str] = Field(default_factory=list)

    # Traçabilité ANSSI
    pipeline_version: str = "1.0.0"
    analyzed_by: str = "langgraph-pipeline"
    audit_trail: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def requires_human_review(self) -> bool:
        return self.status == ReportStatus.ESCALATED

    def add_audit_event(self, event: str, details: dict[str, Any] | None = None) -> None:
        """Ajoute un événement à la piste d'audit du rapport."""
        self.audit_trail.append({
            "event": event,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {},
        })
