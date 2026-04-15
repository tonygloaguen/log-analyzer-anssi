"""
Nœud LangGraph — Ransomware Behavior Analyst.

Analyse les alertes SIEM via Ollama/granite3.3:8b (LLM local, pas de cloud).
Timeout 30s → fallback règles statiques si Ollama indisponible.
Persiste les analyses dans SQLite (DB_PATH) pour audit NIS2.
Signe chaque analyse avec HMAC-SHA256.

Variables d'environnement :
    OLLAMA_HOST              URL Ollama (défaut : http://localhost:11434).
    OLLAMA_RANSOMWARE_MODEL  Modèle (défaut : granite3.3:8b).
    DB_PATH                  SQLite checkpoint (défaut : /tmp/log_analyzer_checkpoint.db).
    HMAC_SECRET              Clé HMAC (obligatoire).

Référence MITRE ATT&CK :
    T1486  — Data Encrypted for Impact
    T1490  — Inhibit System Recovery
    T1021  — Remote Services (propagation SMB/RDP)
    T1070.004 — File Deletion
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from core.log_integrity import _require_secret, sign_event

logger = logging.getLogger(__name__)

# ─── Constantes ──────────────────────────────────────────────────────────────

_OLLAMA_TIMEOUT_S = 30.0
_DEFAULT_MODEL = "granite3.3:8b"
_DEFAULT_DB_PATH = os.path.join(tempfile.gettempdir(), "log_analyzer_checkpoint.db")

_SYSTEM_PROMPT = (
    "Tu es un analyste SOC ANSSI. Analyse les alertes SIEM suivantes et retourne "
    "UNIQUEMENT un JSON valide sans markdown ni backticks : "
    '{ "verdict": string, "confidence": float 0.0-1.0, '
    '"techniques": [liste MITRE], '
    '"recommended_actions": [liste], '
    '"narrative": string < 150 mots }'
)

_VSS_PATTERNS = re.compile(
    r"vssadmin\s+delete|wmic\s+shadowcopy\s+delete|"
    r"bcdedit\s+/set.*recoveryenabled\s+no|"
    r"wbadmin\s+delete\s+catalog",
    re.IGNORECASE,
)

_ENCRYPTION_PATTERNS = re.compile(
    r"\.(locked|encrypted|enc|crypt|ryuk|conti|ransom|pay2decrypt|"
    r"wncry|wnry|wcry|cerber|locky)\b|"
    r"encrypt.*file|file.*encrypt",
    re.IGNORECASE,
)

_BACKUP_DISRUPTION_PATTERNS = re.compile(
    r"wbadmin|backup.*disable|disable.*backup|"
    r"schtasks.*/delete.*backup|"
    r"net\s+stop.*backup",
    re.IGNORECASE,
)

_LATERAL_MOVEMENT_PATTERNS = re.compile(
    r"\\\\[a-zA-Z0-9_\-\.]+\\(admin\$|c\$|ipc\$)|"
    r"psexec|wmiexec|net\s+use|"
    r"rdp.*connect|mstsc",
    re.IGNORECASE,
)


# ─── Modèle de résultat ───────────────────────────────────────────────────────

@dataclass
class RansomwareIndicators:
    """Indicateurs comportementaux de ransomware détectés dans les alertes.

    Attributes:
        file_encryption_detected: Chiffrement massif de fichiers détecté.
        vss_deletion_detected: Suppression VSS (``vssadmin delete shadows``).
        backup_disruption_detected: Désactivation des sauvegardes.
        lateral_movement_detected: Propagation latérale (SMB/RDP/WMI).
        affected_hosts: Hôtes impliqués.
        ioc_list: IOCs extraits (hashes, IPs, domaines).
        llm_reasoning: Analyse contextuelle du LLM.
        confidence: Score de confiance global (0.0–1.0).
    """

    file_encryption_detected: bool = False
    vss_deletion_detected: bool = False
    backup_disruption_detected: bool = False
    lateral_movement_detected: bool = False
    affected_hosts: list[str] = field(default_factory=list)
    ioc_list: list[str] = field(default_factory=list)
    llm_reasoning: str = ""
    confidence: float = 0.0


# ─── Nœud LangGraph ───────────────────────────────────────────────────────────

async def ransomware_behavior_analyst(state: dict[str, Any]) -> dict[str, Any]:
    """Nœud LangGraph d'analyse comportementale ransomware.

    Consomme ``state["alerts"]`` (list[dict]) et ``state["context"]`` (str).
    Produit ``state["analysis"]`` (dict signé HMAC) et
    ``state["notification_payload"]`` (dict pour AlertDispatcher).

    Args:
        state: État LangGraph courant.

    Returns:
        Mise à jour partielle de l'état LangGraph.
    """
    alerts: list[dict[str, Any]] = state.get("alerts", [])
    context: str = state.get("context", "")

    if not alerts:
        analysis = _build_empty_analysis()
        _persist_analysis(analysis)
        return {
            "analysis": _sign_analysis(analysis),
            "notification_payload": _build_notification_payload(analysis),
        }

    # 1. Pré-détection statique (règles déterministes)
    indicators = _run_static_detection(alerts)

    # 2. Enrichissement LLM (Ollama granite3.3:8b, timeout 30s)
    ollama_host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    model = os.environ.get("OLLAMA_RANSOMWARE_MODEL", _DEFAULT_MODEL)
    llm_result = await _call_ollama(alerts, context, ollama_host, model)

    # 3. Fusion : LLM + règles statiques
    analysis = _merge_results(indicators, llm_result, alerts)

    # 4. Persistance SQLite (checkpoint NIS2)
    _persist_analysis(analysis)

    # 5. Signature HMAC
    signed = _sign_analysis(analysis)

    logger.info(
        "[ransomware_analyst] verdict=%s confidence=%.2f llm_used=%s",
        analysis.get("verdict"),
        analysis.get("confidence", 0.0),
        llm_result.get("_llm_used", False),
    )

    return {
        "analysis": signed,
        "notification_payload": _build_notification_payload(analysis),
    }


# ─── Détection statique ───────────────────────────────────────────────────────

def _run_static_detection(alerts: list[dict[str, Any]]) -> RansomwareIndicators:
    """Règles déterministes sans LLM — fallback et pré-filtrage."""
    indicators = RansomwareIndicators()

    all_messages: list[str] = []
    for alert in alerts:
        msg = str(alert.get("message", "")) + " " + str(alert.get("driver", ""))
        all_messages.append(msg)
        host = alert.get("host", "")
        if host and host not in indicators.affected_hosts:
            indicators.affected_hosts.append(host)

    combined = " ".join(all_messages)
    indicators.vss_deletion_detected = _detect_vss_deletion(all_messages)
    indicators.file_encryption_detected = _detect_mass_encryption(all_messages)
    indicators.backup_disruption_detected = bool(_BACKUP_DISRUPTION_PATTERNS.search(combined))
    indicators.lateral_movement_detected = bool(_LATERAL_MOVEMENT_PATTERNS.search(combined))

    # Score de confiance statique
    factor_count = sum([
        indicators.vss_deletion_detected,
        indicators.file_encryption_detected,
        indicators.backup_disruption_detected,
        indicators.lateral_movement_detected,
    ])
    alert_max_conf = max((a.get("confidence", 0.0) for a in alerts), default=0.0)
    indicators.confidence = min(0.95, alert_max_conf + factor_count * 0.08)

    return indicators


def _detect_vss_deletion(log_messages: list[str]) -> bool:
    """Détecte les commandes de suppression VSS dans les messages de logs.

    Recherche ``vssadmin delete``, ``wmic shadowcopy delete``,
    ``bcdedit /set recoveryenabled no`` et ``wbadmin delete catalog``.

    Args:
        log_messages: Liste de messages de logs normalisés.

    Returns:
        ``True`` si au moins un pattern VSS est trouvé.
    """
    return any(_VSS_PATTERNS.search(msg) for msg in log_messages)


def _detect_mass_encryption(log_messages: list[str]) -> bool:
    """Détecte des indicateurs de chiffrement massif de fichiers.

    Recherche des extensions connues de ransomware (.locked, .wncry…)
    ou des patterns de renommage de fichiers en masse.

    Args:
        log_messages: Liste de messages de logs normalisés.

    Returns:
        ``True`` si un pattern de chiffrement est détecté.
    """
    return any(_ENCRYPTION_PATTERNS.search(msg) for msg in log_messages)


# ─── Appel LLM Ollama ─────────────────────────────────────────────────────────

async def _call_ollama(
    alerts: list[dict[str, Any]],
    context: str,
    ollama_host: str,
    model: str,
) -> dict[str, Any]:
    """Interroge Ollama/granite3.3:8b avec les alertes (timeout 30s).

    Retourne un dict avec les clés : verdict, confidence, techniques,
    recommended_actions, narrative. En cas d'erreur, retourne le fallback statique.

    Args:
        alerts: Liste d'alertes SIEM à analyser.
        context: Contexte additionnel (hôtes, fenêtre temporelle…).
        ollama_host: URL de l'instance Ollama.
        model: Identifiant du modèle à utiliser.

    Returns:
        Dict d'analyse (structure JSON Ollama ou fallback statique).
    """
    # Résumé compact des alertes pour le prompt (sans données sensibles)
    alert_summary = _build_alert_summary(alerts)
    prompt = f"Contexte : {context}\n\nAlertes SIEM :\n{alert_summary}"

    try:
        async with httpx.AsyncClient(timeout=_OLLAMA_TIMEOUT_S) as client:
            resp = await client.post(
                f"{ollama_host}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "system": _SYSTEM_PROMPT,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.1, "num_predict": 512},
                },
            )
            resp.raise_for_status()
            data = resp.json()
            raw_response = data.get("response", "{}")
            result = _parse_llm_response(raw_response)
            result["_llm_used"] = True
            return result
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        logger.warning("[ransomware_analyst] Ollama indisponible (%s) — fallback statique", exc)
    except (httpx.HTTPError, json.JSONDecodeError, KeyError) as exc:
        logger.error("[ransomware_analyst] Erreur réponse Ollama: %s", exc)

    return _static_fallback(alerts)


def _parse_llm_response(raw: str) -> dict[str, Any]:
    """Parse la réponse JSON du LLM en gérant les formats imparfaits."""
    # Ollama avec format=json retourne du JSON pur, mais on sécurise
    cleaned = raw.strip()
    # Retire éventuels backticks si le modèle en génère quand même
    cleaned = re.sub(r"^```json?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        parsed: dict[str, Any] = json.loads(cleaned)
    except json.JSONDecodeError:
        # Tentative de récupération du premier bloc JSON valide
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if m:
            try:
                parsed = json.loads(m.group())
            except json.JSONDecodeError:
                return _empty_llm_result()
        else:
            return _empty_llm_result()

    return {
        "verdict": str(parsed.get("verdict", "ANOMALY")),
        "confidence": float(parsed.get("confidence", 0.5)),
        "techniques": list(parsed.get("techniques", [])),
        "recommended_actions": list(parsed.get("recommended_actions", [])),
        "narrative": str(parsed.get("narrative", ""))[:150],
        "_llm_used": False,
    }


def _static_fallback(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Fallback déterministe quand Ollama est indisponible."""
    max_conf = max((float(a.get("confidence", 0.0)) for a in alerts), default=0.0)
    verdict = "SUSPECTED_RANSOMWARE" if max_conf > 0.7 else "ANOMALY"
    techniques = list({a.get("technique", "") for a in alerts} - {""})
    return {
        "verdict": verdict,
        "confidence": round(max_conf, 4),
        "techniques": techniques,
        "recommended_actions": [
            "Isoler les hôtes concernés",
            "Préserver les preuves forensiques",
            "Notifier le CERT/SOC",
        ],
        "narrative": (
            f"Analyse statique (LLM indisponible). "
            f"Confiance maximale des alertes : {max_conf:.0%}. "
            f"Verdict : {verdict}."
        ),
        "_llm_used": False,
    }


def _empty_llm_result() -> dict[str, Any]:
    return {
        "verdict": "UNKNOWN",
        "confidence": 0.0,
        "techniques": [],
        "recommended_actions": [],
        "narrative": "Réponse LLM invalide ou vide.",
        "_llm_used": False,
    }


# ─── Fusion résultats ─────────────────────────────────────────────────────────

def _merge_results(
    indicators: RansomwareIndicators,
    llm_result: dict[str, Any],
    alerts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Fusionne les indicateurs statiques et le résultat LLM."""
    llm_conf = float(llm_result.get("confidence", 0.0))
    static_conf = indicators.confidence
    # Confiance finale = max(llm, static) — on ne divise pas, on prend le plus alarmant
    final_conf = max(llm_conf, static_conf)
    verdict = llm_result.get("verdict", "ANOMALY")
    if indicators.vss_deletion_detected or indicators.file_encryption_detected:
        if final_conf < 0.7:
            verdict = "SUSPECTED_RANSOMWARE"
            final_conf = max(final_conf, 0.7)

    return {
        "verdict": verdict,
        "confidence": round(final_conf, 4),
        "techniques": llm_result.get("techniques", []),
        "recommended_actions": llm_result.get("recommended_actions", []),
        "narrative": llm_result.get("narrative", ""),
        "static_indicators": {
            "vss_deletion": indicators.vss_deletion_detected,
            "file_encryption": indicators.file_encryption_detected,
            "backup_disruption": indicators.backup_disruption_detected,
            "lateral_movement": indicators.lateral_movement_detected,
        },
        "affected_hosts": indicators.affected_hosts,
        "alert_count": len(alerts),
        "ts": time.time(),
        "_llm_used": llm_result.get("_llm_used", False),
    }


def _build_empty_analysis() -> dict[str, Any]:
    return {
        "verdict": "NO_ALERT",
        "confidence": 0.0,
        "techniques": [],
        "recommended_actions": [],
        "narrative": "Aucune alerte à analyser.",
        "static_indicators": {},
        "affected_hosts": [],
        "alert_count": 0,
        "ts": time.time(),
        "_llm_used": False,
    }


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _build_alert_summary(alerts: list[dict[str, Any]]) -> str:
    """Résumé compact des alertes pour le prompt LLM (sans données sensibles)."""
    lines = []
    for i, alert in enumerate(alerts[:10]):  # limite 10 alertes dans le prompt
        lines.append(
            f"[{i+1}] technique={alert.get('technique', '?')} "
            f"confidence={alert.get('confidence', 0):.2f} "
            f"driver={alert.get('driver', '?')} "
            f"edr_targeted={alert.get('edr_targeted', [])}"
        )
    if len(alerts) > 10:
        lines.append(f"... et {len(alerts) - 10} alertes supplémentaires")
    return "\n".join(lines)


def _sign_analysis(analysis: dict[str, Any]) -> dict[str, Any]:
    """Signe l'analyse avec HMAC-SHA256 (NIS2 Art.21.2.h)."""
    secret = _require_secret()
    # Signature du contenu sans la clé "hmac_signature" elle-même
    body = {k: v for k, v in analysis.items() if k != "hmac_signature"}
    analysis["hmac_signature"] = sign_event(body, secret)
    return analysis


def _build_notification_payload(analysis: dict[str, Any]) -> dict[str, Any]:
    """Construit le payload pour AlertDispatcher.dispatch()."""
    techniques = analysis.get("techniques", [])
    return {
        "verdict": analysis.get("verdict", "UNKNOWN"),
        "confidence": analysis.get("confidence", 0.0),
        "technique": "+".join(techniques) if techniques else "UNKNOWN",
        "narrative": analysis.get("narrative", ""),
        "ts": analysis.get("ts", time.time()),
    }


# ─── Persistance SQLite ───────────────────────────────────────────────────────

def _persist_analysis(analysis: dict[str, Any]) -> None:
    """Persiste l'analyse dans SQLite pour audit et checkpoint NIS2.

    Args:
        analysis: Dict d'analyse (avant signature).
    """
    db_path = os.environ.get("DB_PATH", _DEFAULT_DB_PATH)
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ransomware_analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    verdict TEXT,
                    confidence REAL,
                    payload TEXT NOT NULL,
                    created_at REAL DEFAULT (unixepoch('now'))
                )
            """)
            conn.execute(
                "INSERT INTO ransomware_analyses (ts, verdict, confidence, payload) "
                "VALUES (?, ?, ?, ?)",
                (
                    analysis.get("ts", time.time()),
                    analysis.get("verdict"),
                    analysis.get("confidence"),
                    json.dumps(analysis, default=str),
                ),
            )
    except sqlite3.Error as exc:
        logger.error("[ransomware_analyst] Erreur persistance SQLite (%s): %s", db_path, exc)


async def _enrich_with_llm(
    indicators: RansomwareIndicators,
    log_summary: str,
    ollama_base_url: str = "http://ollama:11434",
) -> str:
    """Enrichit les indicateurs via Ollama/granite3.3:8b.

    Args:
        indicators: Indicateurs pré-détectés à enrichir.
        log_summary: Résumé textuel des logs (sans données personnelles).
        ollama_base_url: URL de l'instance Ollama locale.

    Returns:
        Raisonnement LLM sous forme de texte structuré.
    """
    model = os.environ.get("OLLAMA_RANSOMWARE_MODEL", _DEFAULT_MODEL)
    result = await _call_ollama([], log_summary, ollama_base_url, model)
    indicators.llm_reasoning = result.get("narrative", "")
    return indicators.llm_reasoning
