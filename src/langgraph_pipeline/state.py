"""
État partagé du pipeline LangGraph d'analyse de logs.

LogAnalysisState est le TypedDict qui transite entre tous les nœuds
du graphe. Chaque nœud lit et enrichit cet état.
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from langgraph.graph.message import add_messages

from src.models.log_entry import LogEntry, SeverityLevel
from src.models.report import AnomalyDetail, AnalysisReport


class LogAnalysisState(TypedDict, total=False):
    """
    État complet du pipeline d'analyse.

    Flux : normalize → detect_anomalies → classify_severity
           → [auto_report | human_escalation]
    """

    # ── Entrée ──────────────────────────────────────────────
    raw_logs: list[dict[str, Any]]          # Logs bruts depuis Loki/collecteur
    source_filter: str                       # Filtre de source (ex: "nginx", "*")
    time_range: str                          # Fenêtre temporelle (ex: "1h", "24h")
    analysis_id: str                         # UUID de cette analyse

    # ── Après normalize ──────────────────────────────────────
    normalized_logs: list[LogEntry]          # Logs normalisés (modèle interne)
    normalization_errors: list[str]          # Erreurs de normalisation

    # ── Après detect_anomalies ───────────────────────────────
    anomalies: list[AnomalyDetail]           # Anomalies détectées avec scores
    anomaly_count: int
    overall_risk_score: float                # Score agrégé [0.0, 1.0]

    # ── Après classify_severity ──────────────────────────────
    final_severity: SeverityLevel            # Sévérité globale de l'analyse
    llm_analysis: str                        # Analyse textuelle du LLM
    recommendations: list[str]

    # ── Routing conditionnel ─────────────────────────────────
    routing_decision: str                    # "auto_report" | "human_escalation"
    escalation_reason: str

    # ── Rapport final ────────────────────────────────────────
    report: AnalysisReport | None

    # ── Traçabilité ANSSI ────────────────────────────────────
    messages: Annotated[list[Any], add_messages]  # Historique LangGraph
    audit_events: list[dict[str, Any]]
    pipeline_errors: list[str]
