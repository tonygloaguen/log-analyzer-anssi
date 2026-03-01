"""
Définition du graphe LangGraph pour l'analyse de logs ANSSI.

Structure du pipeline :
    START → normalize → detect_anomalies → classify_severity
                                                  ↓
                              ┌─────────────────────────────────┐
                              │ route_by_risk (conditionnel)     │
                              └─────────────────────────────────┘
                                    ↙                    ↘
                            auto_report          human_escalation
                                    ↘                    ↙
                                          END
"""

from __future__ import annotations

import logging

from langgraph.graph import END, START, StateGraph

from src.langgraph_pipeline.conditions import route_by_risk
from src.langgraph_pipeline.nodes import (
    auto_report,
    classify_severity,
    detect_anomalies,
    human_escalation,
    normalize,
)
from src.langgraph_pipeline.state import LogAnalysisState

logger = logging.getLogger(__name__)


def build_log_analysis_graph() -> StateGraph:
    """
    Construit et compile le graphe LangGraph d'analyse de logs.

    Returns:
        Le graphe compilé prêt à l'exécution.
    """
    graph = StateGraph(LogAnalysisState)

    # ── Ajout des nœuds ──────────────────────────────────────
    graph.add_node("normalize", normalize)
    graph.add_node("detect_anomalies", detect_anomalies)
    graph.add_node("classify_severity", classify_severity)
    graph.add_node("auto_report", auto_report)
    graph.add_node("human_escalation", human_escalation)

    # ── Arêtes séquentielles ─────────────────────────────────
    graph.add_edge(START, "normalize")
    graph.add_edge("normalize", "detect_anomalies")
    graph.add_edge("detect_anomalies", "classify_severity")

    # ── Routage conditionnel après classify_severity ─────────
    graph.add_conditional_edges(
        "classify_severity",
        route_by_risk,
        {
            "auto_report": "auto_report",
            "human_escalation": "human_escalation",
        },
    )

    # ── Terminaison ──────────────────────────────────────────
    graph.add_edge("auto_report", END)
    graph.add_edge("human_escalation", END)

    compiled = graph.compile()
    logger.info("Graphe LangGraph d'analyse de logs compilé avec succès")
    return compiled


# Instance singleton du graphe (chargée au démarrage de l'API)
log_analysis_graph = build_log_analysis_graph()


async def run_analysis(
    raw_logs: list[dict],
    source_filter: str = "*",
    time_range: str = "1h",
    analysis_id: str | None = None,
) -> LogAnalysisState:
    """
    Point d'entrée pour exécuter une analyse de logs.

    Args:
        raw_logs: Liste de logs bruts (format dict Loki/JSON).
        source_filter: Filtre de source (ex: "nginx", "*").
        time_range: Fenêtre temporelle de l'analyse.
        analysis_id: UUID optionnel (généré si absent).

    Returns:
        L'état final du pipeline après exécution.
    """
    import uuid as uuid_mod

    initial_state: LogAnalysisState = {
        "raw_logs": raw_logs,
        "source_filter": source_filter,
        "time_range": time_range,
        "analysis_id": analysis_id or str(uuid_mod.uuid4()),
        "audit_events": [],
        "pipeline_errors": [],
        "messages": [],
    }

    logger.info(
        "Démarrage analyse (id=%s, source=%s, %d logs)",
        initial_state["analysis_id"],
        source_filter,
        len(raw_logs),
    )

    final_state = await log_analysis_graph.ainvoke(initial_state)
    return final_state
