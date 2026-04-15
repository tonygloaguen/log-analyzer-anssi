"""
Nœud LangGraph — Ransomware Behavior Analyst.

Analyse les séquences comportementales caractéristiques du ransomware :
chiffrement massif de fichiers, suppression de VSS, désactivation des
sauvegardes, propagation latérale via SMB/RDP.

LLM utilisé : Ollama/granite3.3:8b (IBM Granite, modèle local, pas de cloud).

Conformité ANSSI NIS2 Art.21.2.h : détection comportementale des menaces
avancées sans exfiltration de données vers des services tiers.

Référence MITRE ATT&CK :
    T1486  — Data Encrypted for Impact
    T1490  — Inhibit System Recovery
    T1021  — Remote Services (propagation SMB/RDP)
    T1070.004 — File Deletion (nettoyage des traces)

Intégration dans le pipeline LangGraph ::

    graph.add_node("ransomware_analyst", ransomware_behavior_analyst)
    graph.add_edge("detect_anomalies", "ransomware_analyst")

Usage typique ::

    result = await ransomware_behavior_analyst(state)
    # result["ransomware_indicators"] → RansomwareIndicators | None
    # result["ransomware_risk_score"] → float in [0.0, 1.0]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RansomwareIndicators:
    """Ensemble d'indicateurs comportementaux de ransomware.

    Attributes:
        file_encryption_detected: Chiffrement massif de fichiers détecté.
        vss_deletion_detected: Suppression du Volume Shadow Copy détectée
            (commande ``vssadmin delete shadows``).
        backup_disruption_detected: Désactivation des mécanismes de sauvegarde.
        lateral_movement_detected: Propagation latérale (SMB/RDP).
        affected_hosts: Liste des hôtes impliqués.
        ioc_list: Indicateurs de compromission extraits (hashes, IPs, domaines).
        llm_reasoning: Analyse contextuelle produite par granite3.3:8b.
        confidence: Score de confiance global entre 0.0 et 1.0.
    """

    file_encryption_detected: bool = False
    vss_deletion_detected: bool = False
    backup_disruption_detected: bool = False
    lateral_movement_detected: bool = False
    affected_hosts: list[str] = field(default_factory=list)
    ioc_list: list[str] = field(default_factory=list)
    llm_reasoning: str = ""
    confidence: float = 0.0


async def ransomware_behavior_analyst(state: dict[str, Any]) -> dict[str, Any]:
    """Nœud LangGraph d'analyse comportementale ransomware.

    Reçoit l'état courant du pipeline (logs normalisés + anomalies détectées)
    et enrichit l'analyse en recherchant des séquences comportementales de
    ransomware via des règles heuristiques + LLM granite3.3:8b.

    Args:
        state: État LangGraph courant. Clés consommées :
            - ``normalized_logs`` : liste de LogEntry.
            - ``anomalies`` : liste d'AnomalyDetail.
            - ``overall_risk_score`` : float.

    Returns:
        Dictionnaire de mise à jour partielle de l'état. Clés produites :
            - ``ransomware_indicators`` : :class:`RansomwareIndicators` ou ``None``.
            - ``ransomware_risk_score`` : float.
            - ``audit_events`` : liste mise à jour.
    """
    ...


def _detect_vss_deletion(log_messages: list[str]) -> bool:
    """Détecte les commandes de suppression VSS dans les messages de logs.

    Recherche les patterns ``vssadmin delete``, ``wmic shadowcopy delete``
    et ``bcdedit /set {default} recoveryenabled No``.

    Args:
        log_messages: Liste de messages de logs normalisés.

    Returns:
        ``True`` si au moins un pattern VSS est trouvé.
    """
    ...


def _detect_mass_encryption(log_messages: list[str]) -> bool:
    """Détecte un chiffrement massif de fichiers via les extensions connues.

    Recherche des accès en écriture à haute fréquence sur des extensions
    renommées ou non reconnues (indicateur de chiffrement en cours).

    Args:
        log_messages: Liste de messages de logs normalisés.

    Returns:
        ``True`` si un pattern de chiffrement massif est détecté.
    """
    ...


async def _enrich_with_llm(
    indicators: RansomwareIndicators,
    log_summary: str,
    ollama_base_url: str = "http://ollama:11434",
) -> str:
    """Enrichit l'analyse via Ollama/granite3.3:8b.

    Construit un prompt structuré et interroge le modèle local pour
    obtenir une analyse contextuelle et des recommandations de remédiation.

    Args:
        indicators: Indicateurs détectés à enrichir.
        log_summary: Résumé textuel des logs (sans données personnelles).
        ollama_base_url: URL de l'instance Ollama locale.

    Returns:
        Raisonnement LLM sous forme de texte structuré.
    """
    ...
