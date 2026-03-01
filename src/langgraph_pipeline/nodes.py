"""
Nœuds du pipeline LangGraph d'analyse de logs ANSSI.

Pipeline :
    normalize → detect_anomalies → classify_severity
              → [auto_report | human_escalation]

Chaque nœud reçoit et retourne un LogAnalysisState partiel.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from src.langgraph_pipeline.llm_client import OllamaClient
from src.langgraph_pipeline.state import LogAnalysisState
from src.models.log_entry import LogEntry, LogSource, SeverityLevel
from src.models.report import AnalysisReport, AnomalyDetail, ReportStatus

logger = logging.getLogger(__name__)

# Patterns de détection d'anomalies (règles déterministes + LLM pour le contexte)
ANOMALY_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "brute_force_ssh",
        "pattern": r"Failed password for .* from \d+\.\d+\.\d+\.\d+",
        "severity": SeverityLevel.ERROR,
        "base_score": 0.7,
        "description": "Tentative de brute-force SSH détectée",
    },
    {
        "name": "root_login",
        "pattern": r"(Accepted|Failed) password for root",
        "severity": SeverityLevel.CRITICAL,
        "base_score": 0.95,
        "description": "Tentative de connexion root détectée",
    },
    {
        "name": "port_scan",
        "pattern": r"(nmap|masscan|port scan|SYN flood)",
        "severity": SeverityLevel.WARNING,
        "base_score": 0.6,
        "description": "Scan de ports potentiel",
    },
    {
        "name": "sql_injection",
        "pattern": r"(UNION SELECT|DROP TABLE|--\s|;.*SELECT|OR 1=1)",
        "severity": SeverityLevel.CRITICAL,
        "base_score": 0.9,
        "description": "Tentative d'injection SQL",
    },
    {
        "name": "path_traversal",
        "pattern": r"\.\./|\.\.\\|%2e%2e",
        "severity": SeverityLevel.ERROR,
        "base_score": 0.8,
        "description": "Tentative de traversée de répertoire",
    },
    {
        "name": "multiple_403",
        "pattern": r'" 403 ',
        "severity": SeverityLevel.WARNING,
        "base_score": 0.5,
        "description": "Erreurs 403 répétées (accès non autorisés)",
    },
    {
        "name": "privilege_escalation",
        "pattern": r"(sudo|su -|chmod 777|NOPASSWD)",
        "severity": SeverityLevel.ERROR,
        "base_score": 0.75,
        "description": "Tentative d'élévation de privilèges",
    },
]


# ─────────────────────────────────────────────────────────────
# Nœud 1 : normalize
# ─────────────────────────────────────────────────────────────
async def normalize(state: LogAnalysisState) -> dict[str, Any]:
    """
    Normalise les logs bruts vers le modèle interne LogEntry.

    Extrait : timestamp, source, host, message, sévérité initiale.
    Trace les erreurs de normalisation sans bloquer le pipeline.
    """
    raw_logs: list[dict[str, Any]] = state.get("raw_logs", [])
    analysis_id = state.get("analysis_id", str(uuid.uuid4()))
    normalized: list[LogEntry] = []
    errors: list[str] = []

    logger.info("[normalize] Traitement de %d logs bruts (analysis_id=%s)", len(raw_logs), analysis_id)

    for idx, raw in enumerate(raw_logs):
        try:
            entry = _normalize_single(raw, idx)
            normalized.append(entry)
        except Exception as e:
            error_msg = f"Log #{idx} — erreur normalisation: {e}"
            logger.warning(error_msg)
            errors.append(error_msg)

    audit_events = state.get("audit_events", [])
    audit_events.append({
        "node": "normalize",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "logs_in": len(raw_logs),
        "logs_out": len(normalized),
        "errors": len(errors),
    })

    logger.info("[normalize] %d/%d logs normalisés avec succès", len(normalized), len(raw_logs))

    return {
        "normalized_logs": normalized,
        "normalization_errors": errors,
        "audit_events": audit_events,
        "analysis_id": analysis_id,
    }


def _normalize_single(raw: dict[str, Any], idx: int) -> LogEntry:
    """Normalise un log brut en LogEntry."""
    message = raw.get("message", raw.get("log", str(raw)))
    host = raw.get("host", raw.get("hostname", raw.get("labels", {}).get("host", "unknown")))

    # Détection de la source
    source_str = raw.get("source", raw.get("job", "unknown")).lower()
    source = LogSource.UNKNOWN
    for s in LogSource:
        if s.value in source_str:
            source = s
            break

    # Détection de sévérité initiale depuis le message
    severity = _detect_initial_severity(message)

    # Timestamp
    ts_raw = raw.get("timestamp", raw.get("time", raw.get("ts", None)))
    if ts_raw:
        if isinstance(ts_raw, (int, float)):
            # Nanoseconds depuis epoch (format Loki)
            ts = datetime.fromtimestamp(ts_raw / 1e9, tz=timezone.utc)
        else:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
    else:
        ts = datetime.now(timezone.utc)

    return LogEntry(
        timestamp=ts,
        source=source,
        host=str(host),
        raw_message=message,
        normalized_message=message.strip(),
        severity=severity,
        metadata={k: v for k, v in raw.items() if k not in ("message", "log", "timestamp", "time")},
    )


def _detect_initial_severity(message: str) -> SeverityLevel:
    """Détecte la sévérité initiale depuis les mots-clés du message."""
    msg_lower = message.lower()
    if any(k in msg_lower for k in ("critical", "fatal", "emerg", "alert")):
        return SeverityLevel.CRITICAL
    if any(k in msg_lower for k in ("error", "err ", "failed", "failure", "denied")):
        return SeverityLevel.ERROR
    if any(k in msg_lower for k in ("warn", "warning")):
        return SeverityLevel.WARNING
    if any(k in msg_lower for k in ("debug",)):
        return SeverityLevel.DEBUG
    return SeverityLevel.INFO


# ─────────────────────────────────────────────────────────────
# Nœud 2 : detect_anomalies
# ─────────────────────────────────────────────────────────────
async def detect_anomalies(state: LogAnalysisState) -> dict[str, Any]:
    """
    Détecte les anomalies par pattern matching et comptage fréquentiel.

    Utilise des règles déterministes (règles ANSSI + patterns IOC)
    complétées par une analyse de fréquence.
    """
    logs: list[LogEntry] = state.get("normalized_logs", [])
    anomalies: list[AnomalyDetail] = []

    logger.info("[detect_anomalies] Analyse de %d logs normalisés", len(logs))

    # 1. Pattern matching sur chaque log
    pattern_hits: dict[str, list[str]] = {}  # pattern_name → [log_ids]

    for log in logs:
        for pattern_def in ANOMALY_PATTERNS:
            if re.search(pattern_def["pattern"], log.normalized_message, re.IGNORECASE):
                pattern_hits.setdefault(pattern_def["name"], []).append(log.id)

    # 2. Construire les AnomalyDetail
    for pattern_def in ANOMALY_PATTERNS:
        hit_ids = pattern_hits.get(pattern_def["name"], [])
        if not hit_ids:
            continue

        # Score amplifié par la fréquence
        frequency_multiplier = min(1.0, 1.0 + (len(hit_ids) - 1) * 0.05)
        score = min(1.0, pattern_def["base_score"] * frequency_multiplier)

        anomalies.append(AnomalyDetail(
            anomaly_type=pattern_def["name"],
            score=score,
            description=f"{pattern_def['description']} ({len(hit_ids)} occurrences)",
            affected_log_ids=hit_ids,
        ))

    # 3. Anomalie de volume (pic de logs)
    volume_anomaly = _detect_volume_anomaly(logs)
    if volume_anomaly:
        anomalies.append(volume_anomaly)

    # Score global = max des scores individuels (pondéré par le nombre d'anomalies)
    if anomalies:
        max_score = max(a.score for a in anomalies)
        anomaly_factor = min(1.0, len(anomalies) * 0.1)
        overall_score = min(1.0, max_score + anomaly_factor)
    else:
        overall_score = 0.0

    audit_events = state.get("audit_events", [])
    audit_events.append({
        "node": "detect_anomalies",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "anomalies_found": len(anomalies),
        "overall_risk_score": overall_score,
    })

    logger.info(
        "[detect_anomalies] %d anomalies détectées, score global=%.2f",
        len(anomalies), overall_score,
    )

    return {
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "overall_risk_score": overall_score,
        "audit_events": audit_events,
    }


def _detect_volume_anomaly(logs: list[LogEntry]) -> AnomalyDetail | None:
    """Détecte un pic de volume anormal (> 1000 logs par fenêtre)."""
    if len(logs) > 1000:
        score = min(1.0, 0.4 + (len(logs) - 1000) / 5000)
        return AnomalyDetail(
            anomaly_type="volume_spike",
            score=score,
            description=f"Volume de logs anormalement élevé: {len(logs)} entrées",
            affected_log_ids=[],
        )
    return None


# ─────────────────────────────────────────────────────────────
# Nœud 3 : classify_severity
# ─────────────────────────────────────────────────────────────
async def classify_severity(state: LogAnalysisState) -> dict[str, Any]:
    """
    Classifie la sévérité globale et enrichit l'analyse via le LLM local.

    Utilise Ollama/Mistral pour une analyse contextuelle des anomalies.
    """
    anomalies: list[AnomalyDetail] = state.get("anomalies", [])
    logs: list[LogEntry] = state.get("normalized_logs", [])
    overall_score: float = state.get("overall_risk_score", 0.0)

    # Sévérité déterministe basée sur le score
    if overall_score >= 0.9:
        final_severity = SeverityLevel.CRITICAL
    elif overall_score >= 0.7:
        final_severity = SeverityLevel.ERROR
    elif overall_score >= 0.4:
        final_severity = SeverityLevel.WARNING
    elif overall_score > 0.0:
        final_severity = SeverityLevel.INFO
    else:
        final_severity = SeverityLevel.DEBUG

    # Analyse LLM pour enrichissement contextuel
    llm_analysis = ""
    recommendations: list[str] = []

    if anomalies:
        try:
            ollama = OllamaClient()
            if await ollama.is_available():
                log_summary = _build_log_summary(logs, anomalies)
                anomaly_descriptions = [a.description for a in anomalies]
                llm_analysis, recommendations = await ollama.analyze_anomalies(
                    log_summary, anomaly_descriptions
                )
                # Stocker l'analyse LLM dans chaque anomalie
                for anomaly in anomalies:
                    anomaly.llm_analysis = llm_analysis
            else:
                logger.warning("[classify_severity] Ollama non disponible — analyse LLM ignorée")
                llm_analysis = "Service LLM indisponible — analyse déterministe uniquement."
                recommendations = _default_recommendations(final_severity)
        except Exception as e:
            logger.error("[classify_severity] Erreur LLM: %s", e)
            llm_analysis = f"Erreur analyse LLM: {e}"
            recommendations = _default_recommendations(final_severity)
    else:
        llm_analysis = "Aucune anomalie détectée dans cette fenêtre d'analyse."
        recommendations = ["Continuer la surveillance normale."]

    audit_events = state.get("audit_events", [])
    audit_events.append({
        "node": "classify_severity",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "final_severity": final_severity.value,
        "llm_used": bool(llm_analysis and "indisponible" not in llm_analysis),
    })

    logger.info("[classify_severity] Sévérité finale: %s", final_severity.value)

    return {
        "final_severity": final_severity,
        "anomalies": anomalies,
        "llm_analysis": llm_analysis,
        "recommendations": recommendations,
        "audit_events": audit_events,
    }


def _build_log_summary(logs: list[LogEntry], anomalies: list[AnomalyDetail]) -> str:
    """Construit un résumé des logs pour le LLM (sans données sensibles)."""
    sources = list({log.source.value for log in logs})
    hosts = list({log.host for log in logs})[:5]  # Limiter à 5 hôtes
    high_sev = [log for log in logs if log.is_high_severity]

    return (
        f"Fenêtre analysée: {len(logs)} logs\n"
        f"Sources: {', '.join(sources)}\n"
        f"Hôtes concernés: {', '.join(hosts)}\n"
        f"Logs haute sévérité: {len(high_sev)}\n"
        f"Anomalies détectées: {len(anomalies)}\n"
    )


def _default_recommendations(severity: SeverityLevel) -> list[str]:
    """Recommandations par défaut sans LLM."""
    if severity == SeverityLevel.CRITICAL:
        return [
            "Isoler immédiatement les systèmes concernés",
            "Notifier l'équipe CERT/SOC",
            "Conserver les preuves forensiques",
            "Activer le plan de réponse aux incidents",
        ]
    if severity == SeverityLevel.ERROR:
        return [
            "Investiguer les anomalies détectées",
            "Vérifier les accès récents sur les systèmes concernés",
            "Renforcer les règles de filtrage",
        ]
    return ["Surveiller l'évolution de la situation."]


# ─────────────────────────────────────────────────────────────
# Nœud 4a : auto_report
# ─────────────────────────────────────────────────────────────
async def auto_report(state: LogAnalysisState) -> dict[str, Any]:
    """
    Génère un rapport automatique pour les anomalies de faible risque.
    Aucune intervention humaine requise.
    """
    report = _build_report(state, status=ReportStatus.AUTO_RESOLVED, routed_to="auto_report")
    report.add_audit_event("auto_report_generated")

    logger.info("[auto_report] Rapport automatique généré: %s", report.id)

    audit_events = state.get("audit_events", [])
    audit_events.append({
        "node": "auto_report",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "report_id": report.id,
        "status": "auto_resolved",
    })

    return {"report": report, "audit_events": audit_events}


# ─────────────────────────────────────────────────────────────
# Nœud 4b : human_escalation
# ─────────────────────────────────────────────────────────────
async def human_escalation(state: LogAnalysisState) -> dict[str, Any]:
    """
    Escalade vers un analyste humain pour les anomalies à haut risque.
    Conforme ANSSI : les incidents graves nécessitent une validation humaine.
    """
    report = _build_report(state, status=ReportStatus.ESCALATED, routed_to="human_escalation")
    report.escalation_reason = state.get(
        "escalation_reason",
        f"Score de risque élevé: {state.get('overall_risk_score', 0):.2f}"
    )
    report.add_audit_event("human_escalation_triggered", {
        "reason": report.escalation_reason,
        "risk_score": state.get("overall_risk_score", 0),
    })

    logger.warning(
        "[human_escalation] ESCALADE HUMAINE requise — rapport: %s, score: %.2f",
        report.id,
        state.get("overall_risk_score", 0),
    )

    audit_events = state.get("audit_events", [])
    audit_events.append({
        "node": "human_escalation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "report_id": report.id,
        "status": "escalated",
        "reason": report.escalation_reason,
    })

    return {
        "report": report,
        "routing_decision": "human_escalation",
        "audit_events": audit_events,
    }


def _build_report(state: LogAnalysisState, status: ReportStatus, routed_to: str) -> AnalysisReport:
    """Construit le rapport d'analyse depuis l'état final du pipeline."""
    logs: list[LogEntry] = state.get("normalized_logs", [])
    timestamps = [log.timestamp for log in logs] if logs else [datetime.now(timezone.utc)]

    return AnalysisReport(
        analysis_window_start=min(timestamps),
        analysis_window_end=max(timestamps),
        source_filter=state.get("source_filter", "*"),
        total_logs_analyzed=len(logs),
        anomalies_detected=state.get("anomalies", []),
        overall_risk_score=state.get("overall_risk_score", 0.0),
        status=status,
        routed_to=routed_to,
        llm_summary=state.get("llm_analysis", ""),
        recommendations=state.get("recommendations", []),
        audit_trail=state.get("audit_events", []),
    )
