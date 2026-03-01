"""
Conditions de routage conditionnel du pipeline LangGraph.

Le routage est basé sur le score de risque global :
- score < ANOMALY_THRESHOLD → auto_report (traitement automatique)
- score >= ANOMALY_THRESHOLD → human_escalation (intervention humaine)
"""

from __future__ import annotations

import os

from src.langgraph_pipeline.state import LogAnalysisState

# Seuil configurable via variable d'environnement (ANSSI : paramétrable)
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.75"))


def route_by_risk(state: LogAnalysisState) -> str:
    """
    Détermine le prochain nœud selon le score de risque global.

    Returns:
        "human_escalation" si le risque dépasse le seuil,
        "auto_report" sinon.
    """
    overall_score = state.get("overall_risk_score", 0.0)
    final_severity = state.get("final_severity")

    # Escalade automatique si sévérité CRITICAL quelle que soit le score
    from src.models.log_entry import SeverityLevel
    if final_severity == SeverityLevel.CRITICAL:
        return "human_escalation"

    if overall_score >= ANOMALY_THRESHOLD:
        return "human_escalation"

    return "auto_report"
