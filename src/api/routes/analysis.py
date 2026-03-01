"""
Routes d'analyse de logs :
- POST /analyze  — déclenche une analyse via le pipeline LangGraph
- GET  /reports  — liste les rapports générés
- GET  /reports/{id} — récupère un rapport spécifique
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Query

from src.api.schemas import AnalysisRequest, AnalysisResponse, AnomalyResponse, ReportSummary
from src.langgraph_pipeline.graph import run_analysis
from src.models.report import AnalysisReport

logger = logging.getLogger(__name__)
router = APIRouter()

# Stockage en mémoire des rapports (en production : PostgreSQL)
_reports_store: dict[str, AnalysisReport] = {}


@router.post("/analyze", response_model=AnalysisResponse)
async def trigger_analysis(request: AnalysisRequest) -> AnalysisResponse:
    """
    Déclenche une analyse de logs via le pipeline LangGraph.

    Si `raw_logs` est fourni, les utilise directement.
    Sinon, récupère les logs depuis Loki pour la fenêtre temporelle demandée.
    """
    logs = request.raw_logs

    if logs is None:
        # Récupérer les logs depuis Loki
        try:
            logs = await _fetch_logs_from_loki(
                source=request.source,
                time_range=request.time_range,
            )
        except Exception as e:
            logger.error("Impossible de récupérer les logs Loki: %s", e)
            raise HTTPException(status_code=503, detail=f"Service Loki indisponible: {e}")

    logger.info(
        "Analyse déclenchée: source=%s, time_range=%s, logs=%d",
        request.source, request.time_range, len(logs),
    )

    try:
        final_state = await run_analysis(
            raw_logs=logs,
            source_filter=request.source,
            time_range=request.time_range,
            analysis_id=request.analysis_id,
        )
    except Exception as e:
        logger.error("Erreur pipeline LangGraph: %s", e)
        raise HTTPException(status_code=500, detail=f"Erreur pipeline d'analyse: {e}")

    report: AnalysisReport | None = final_state.get("report")
    if not report:
        raise HTTPException(status_code=500, detail="Le pipeline n'a pas produit de rapport")

    # Stocker le rapport
    _reports_store[report.id] = report

    # Construire la réponse
    anomaly_responses = [
        AnomalyResponse(
            anomaly_type=a.anomaly_type,
            score=a.score,
            description=a.description,
            affected_count=len(a.affected_log_ids),
        )
        for a in report.anomalies_detected
    ]

    return AnalysisResponse(
        analysis_id=report.id,
        status=report.status.value,
        routed_to=report.routed_to,
        overall_risk_score=report.overall_risk_score,
        total_logs_analyzed=report.total_logs_analyzed,
        anomalies_count=len(report.anomalies_detected),
        anomalies=anomaly_responses,
        final_severity=final_state.get("final_severity", "info").value
        if hasattr(final_state.get("final_severity", "info"), "value")
        else str(final_state.get("final_severity", "info")),
        llm_summary=report.llm_summary,
        recommendations=report.recommendations,
        created_at=report.created_at,
        requires_human_review=report.requires_human_review,
    )


@router.get("/reports", response_model=list[ReportSummary])
async def list_reports(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[ReportSummary]:
    """Liste les rapports d'analyse (du plus récent au plus ancien)."""
    all_reports = sorted(
        _reports_store.values(),
        key=lambda r: r.created_at,
        reverse=True,
    )
    page = all_reports[offset: offset + limit]

    return [
        ReportSummary(
            id=r.id,
            created_at=r.created_at,
            status=r.status.value,
            overall_risk_score=r.overall_risk_score,
            total_logs_analyzed=r.total_logs_analyzed,
            anomalies_count=len(r.anomalies_detected),
            requires_human_review=r.requires_human_review,
        )
        for r in page
    ]


@router.get("/reports/{report_id}", response_model=dict[str, Any])
async def get_report(report_id: str) -> dict[str, Any]:
    """Récupère un rapport d'analyse complet par son ID."""
    report = _reports_store.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Rapport {report_id} introuvable")
    return report.model_dump()


async def _fetch_logs_from_loki(source: str, time_range: str) -> list[dict[str, Any]]:
    """
    Récupère les logs depuis l'API Loki.

    Args:
        source: Source de logs (ex: "nginx", "*").
        time_range: Fenêtre temporelle (ex: "1h", "24h").

    Returns:
        Liste de logs au format dict.
    """
    loki_url = os.getenv("LOKI_URL", "http://loki:3100")

    # Calculer la fenêtre temporelle
    duration_map = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
    seconds = duration_map.get(time_range, 3600)
    end = datetime.now(timezone.utc)
    start = end - timedelta(seconds=seconds)

    # Requête LogQL
    query = '{job=~".+"}'
    if source != "*":
        query = f'{{job="{source}"}}'

    params = {
        "query": query,
        "start": str(int(start.timestamp() * 1e9)),
        "end": str(int(end.timestamp() * 1e9)),
        "limit": "5000",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"{loki_url}/loki/api/v1/query_range", params=params)
        resp.raise_for_status()
        data = resp.json()

    logs = []
    for stream in data.get("data", {}).get("result", []):
        labels = stream.get("stream", {})
        for ts_ns, line in stream.get("values", []):
            logs.append({
                "timestamp": int(ts_ns),
                "message": line,
                "source": labels.get("job", "unknown"),
                "host": labels.get("host", labels.get("hostname", "unknown")),
                **labels,
            })

    return logs
