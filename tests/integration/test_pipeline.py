"""
Tests d'intégration du pipeline LangGraph complet.

Ces tests vérifient l'exécution end-to-end du pipeline
sans appeler les services externes (Ollama mocké).
"""

from __future__ import annotations

import os
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

os.environ.setdefault("HMAC_SECRET_KEY", "integration-test-key-32bytes-min!")
os.environ.setdefault("ANOMALY_THRESHOLD", "0.75")

from src.langgraph_pipeline.graph import run_analysis
from src.models.report import ReportStatus


def make_log(message: str, source: str = "nginx", host: str = "web01") -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": message,
        "source": source,
        "host": host,
    }


@pytest.mark.asyncio
class TestPipelineIntegration:

    @patch("src.langgraph_pipeline.nodes.OllamaClient")
    async def test_clean_logs_produce_auto_report(self, mock_ollama_class):
        """Des logs propres doivent produire un rapport automatique (non escaladé)."""
        mock_client = AsyncMock()
        mock_client.is_available.return_value = False  # Simuler Ollama absent
        mock_ollama_class.return_value = mock_client

        logs = [
            make_log("GET /api/health HTTP/1.1 200 OK"),
            make_log("POST /api/login HTTP/1.1 200 OK"),
            make_log("User alice authenticated successfully"),
        ]

        result = await run_analysis(logs, source_filter="nginx", time_range="1h")

        assert result.get("report") is not None
        report = result["report"]
        assert report.status == ReportStatus.AUTO_RESOLVED
        assert report.overall_risk_score < 0.75

    @patch("src.langgraph_pipeline.nodes.OllamaClient")
    async def test_attack_logs_trigger_escalation(self, mock_ollama_class):
        """Des logs d'attaque doivent déclencher une escalade humaine."""
        mock_client = AsyncMock()
        mock_client.is_available.return_value = True
        mock_client.analyze_anomalies.return_value = (
            "Attaque SSH brute-force détectée depuis 10.0.0.1",
            ["Bloquer l'IP 10.0.0.1", "Vérifier les logs d'authentification"]
        )
        mock_ollama_class.return_value = mock_client

        # Simuler une attaque par force brute
        logs = [
            make_log("Failed password for admin from 10.0.0.1 port 22 ssh2", source="ssh")
            for _ in range(20)
        ] + [
            make_log("Accepted password for root from 10.0.0.1 port 22 ssh2", source="ssh")
        ]

        result = await run_analysis(logs, source_filter="ssh", time_range="15m")

        assert result.get("report") is not None
        report = result["report"]
        assert report.status == ReportStatus.ESCALATED
        assert report.requires_human_review is True

    @patch("src.langgraph_pipeline.nodes.OllamaClient")
    async def test_pipeline_produces_audit_trail(self, mock_ollama_class):
        """Le pipeline doit produire une piste d'audit complète (ANSSI)."""
        mock_client = AsyncMock()
        mock_client.is_available.return_value = False
        mock_ollama_class.return_value = mock_client

        logs = [make_log("Normal log entry")]
        result = await run_analysis(logs)

        audit_events = result.get("audit_events", [])
        node_names = [e["node"] for e in audit_events]

        # Tous les nœuds doivent avoir laissé une trace
        assert "normalize" in node_names
        assert "detect_anomalies" in node_names
        assert "classify_severity" in node_names

    @patch("src.langgraph_pipeline.nodes.OllamaClient")
    async def test_pipeline_with_sql_injection(self, mock_ollama_class):
        """Les tentatives d'injection SQL doivent être détectées."""
        mock_client = AsyncMock()
        mock_client.is_available.return_value = False
        mock_ollama_class.return_value = mock_client

        logs = [
            make_log("GET /api/users?id=1 UNION SELECT username,password FROM users--"),
            make_log("POST /login HTTP/1.1 200"),
        ]

        result = await run_analysis(logs, source_filter="nginx")

        anomalies = result.get("anomalies", [])
        anomaly_types = [a.anomaly_type for a in anomalies]
        assert "sql_injection" in anomaly_types

    @patch("src.langgraph_pipeline.nodes.OllamaClient")
    async def test_pipeline_handles_empty_logs(self, mock_ollama_class):
        """Le pipeline doit gérer gracieusement un lot de logs vide."""
        mock_client = AsyncMock()
        mock_client.is_available.return_value = False
        mock_ollama_class.return_value = mock_client

        result = await run_analysis([], source_filter="*")

        assert result.get("report") is not None
        assert result["report"].total_logs_analyzed == 0
        assert result["report"].overall_risk_score == 0.0

    @patch("src.langgraph_pipeline.nodes.OllamaClient")
    async def test_llm_analysis_stored_in_report(self, mock_ollama_class):
        """L'analyse LLM doit être stockée dans le rapport."""
        expected_analysis = "Comportement suspect détecté."
        expected_recs = ["Action 1", "Action 2"]

        mock_client = AsyncMock()
        mock_client.is_available.return_value = True
        mock_client.analyze_anomalies.return_value = (expected_analysis, expected_recs)
        mock_ollama_class.return_value = mock_client

        logs = [make_log("Accepted password for root from 5.5.5.5 port 22", source="ssh")]
        result = await run_analysis(logs)

        report = result.get("report")
        assert report is not None
        assert report.llm_summary == expected_analysis
        assert report.recommendations == expected_recs
