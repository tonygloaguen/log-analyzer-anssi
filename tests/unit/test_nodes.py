"""
Tests unitaires des nœuds LangGraph.

Teste chaque nœud de manière isolée sans dépendances externes
(Ollama, Loki, PostgreSQL).
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from src.langgraph_pipeline.nodes import (
    auto_report,
    classify_severity,
    detect_anomalies,
    human_escalation,
    normalize,
    _detect_initial_severity,
    _normalize_single,
)
from src.langgraph_pipeline.conditions import route_by_risk
from src.models.log_entry import LogEntry, LogSource, SeverityLevel
from src.models.report import ReportStatus


# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def raw_nginx_log() -> dict:
    return {
        "timestamp": "2024-01-15T10:30:00+00:00",
        "message": '192.168.1.1 - - [15/Jan/2024:10:30:00 +0000] "GET /admin HTTP/1.1" 403 512',
        "source": "nginx",
        "host": "web-server-01",
    }


@pytest.fixture
def raw_ssh_brute_force_log() -> dict:
    return {
        "timestamp": "2024-01-15T10:30:00+00:00",
        "message": "Failed password for admin from 10.0.0.1 port 22 ssh2",
        "source": "ssh",
        "host": "bastion-01",
    }


@pytest.fixture
def raw_critical_log() -> dict:
    return {
        "timestamp": "2024-01-15T10:30:00+00:00",
        "message": "Accepted password for root from 203.0.113.1 port 22 ssh2",
        "source": "ssh",
        "host": "prod-server-01",
    }


@pytest.fixture
def base_state() -> dict:
    return {
        "analysis_id": "test-analysis-001",
        "source_filter": "nginx",
        "time_range": "1h",
        "audit_events": [],
        "pipeline_errors": [],
        "messages": [],
    }


# ─────────────────────────────────────────────────────────────
# Tests : normalize
# ─────────────────────────────────────────────────────────────

class TestNormalizeNode:

    @pytest.mark.asyncio
    async def test_normalize_valid_logs(self, raw_nginx_log, raw_ssh_brute_force_log, base_state):
        state = {**base_state, "raw_logs": [raw_nginx_log, raw_ssh_brute_force_log]}
        result = await normalize(state)

        assert "normalized_logs" in result
        assert len(result["normalized_logs"]) == 2
        assert len(result["normalization_errors"]) == 0

    @pytest.mark.asyncio
    async def test_normalize_single_nginx(self, raw_nginx_log):
        entry = _normalize_single(raw_nginx_log, 0)

        assert isinstance(entry, LogEntry)
        assert entry.source == LogSource.NGINX
        assert entry.host == "web-server-01"
        assert "403" in entry.normalized_message

    @pytest.mark.asyncio
    async def test_normalize_handles_malformed_log(self, base_state):
        malformed = {"garbage": "data", "no_message": True}
        state = {**base_state, "raw_logs": [malformed]}
        result = await normalize(state)

        # Le nœud ne doit pas crasher sur un log malformé
        assert "normalized_logs" in result

    @pytest.mark.asyncio
    async def test_normalize_empty_logs(self, base_state):
        state = {**base_state, "raw_logs": []}
        result = await normalize(state)

        assert result["normalized_logs"] == []
        assert result["normalization_errors"] == []

    @pytest.mark.asyncio
    async def test_normalize_adds_audit_event(self, raw_nginx_log, base_state):
        state = {**base_state, "raw_logs": [raw_nginx_log]}
        result = await normalize(state)

        events = result["audit_events"]
        assert any(e["node"] == "normalize" for e in events)

    def test_detect_initial_severity_critical(self):
        assert _detect_initial_severity("CRITICAL system failure") == SeverityLevel.CRITICAL

    def test_detect_initial_severity_error(self):
        assert _detect_initial_severity("Failed password for user") == SeverityLevel.ERROR

    def test_detect_initial_severity_info_default(self):
        assert _detect_initial_severity("Normal operation log") == SeverityLevel.INFO


# ─────────────────────────────────────────────────────────────
# Tests : detect_anomalies
# ─────────────────────────────────────────────────────────────

class TestDetectAnomaliesNode:

    def _make_log(self, message: str, source: str = "ssh") -> LogEntry:
        return LogEntry(
            timestamp=datetime.now(timezone.utc),
            source=LogSource(source) if source in LogSource._value2member_map_ else LogSource.UNKNOWN,
            host="test-host",
            raw_message=message,
            normalized_message=message,
        )

    @pytest.mark.asyncio
    async def test_detects_ssh_brute_force(self):
        logs = [self._make_log("Failed password for admin from 10.0.0.1 port 22 ssh2")]
        state = {"normalized_logs": logs, "audit_events": []}

        result = await detect_anomalies(state)

        assert result["anomaly_count"] >= 1
        types = [a.anomaly_type for a in result["anomalies"]]
        assert "brute_force_ssh" in types

    @pytest.mark.asyncio
    async def test_detects_root_login(self):
        logs = [self._make_log("Accepted password for root from 1.2.3.4 port 22")]
        state = {"normalized_logs": logs, "audit_events": []}

        result = await detect_anomalies(state)

        types = [a.anomaly_type for a in result["anomalies"]]
        assert "root_login" in types
        # Root login = score très élevé
        root_anomaly = next(a for a in result["anomalies"] if a.anomaly_type == "root_login")
        assert root_anomaly.score >= 0.9

    @pytest.mark.asyncio
    async def test_detects_sql_injection(self):
        logs = [self._make_log("GET /api/users?id=1 UNION SELECT * FROM users")]
        state = {"normalized_logs": logs, "audit_events": []}

        result = await detect_anomalies(state)

        types = [a.anomaly_type for a in result["anomalies"]]
        assert "sql_injection" in types

    @pytest.mark.asyncio
    async def test_no_anomaly_on_clean_logs(self):
        logs = [
            self._make_log("User alice logged in successfully from 192.168.1.10"),
            self._make_log("GET /api/health HTTP/1.1 200 OK"),
        ]
        state = {"normalized_logs": logs, "audit_events": []}

        result = await detect_anomalies(state)

        assert result["anomaly_count"] == 0
        assert result["overall_risk_score"] == 0.0

    @pytest.mark.asyncio
    async def test_frequency_amplifies_score(self):
        # 50 tentatives de brute-force = score plus élevé qu'une seule
        single_log = [self._make_log("Failed password for admin from 10.0.0.1")]
        many_logs = [self._make_log("Failed password for admin from 10.0.0.1")] * 50

        result_single = await detect_anomalies({"normalized_logs": single_log, "audit_events": []})
        result_many = await detect_anomalies({"normalized_logs": many_logs, "audit_events": []})

        score_single = next(
            (a.score for a in result_single["anomalies"] if a.anomaly_type == "brute_force_ssh"), 0
        )
        score_many = next(
            (a.score for a in result_many["anomalies"] if a.anomaly_type == "brute_force_ssh"), 0
        )
        assert score_many >= score_single


# ─────────────────────────────────────────────────────────────
# Tests : conditions de routage
# ─────────────────────────────────────────────────────────────

class TestRouting:

    def test_low_risk_routes_to_auto_report(self):
        state = {"overall_risk_score": 0.3, "final_severity": SeverityLevel.INFO}
        assert route_by_risk(state) == "auto_report"

    def test_high_risk_routes_to_escalation(self):
        state = {"overall_risk_score": 0.85, "final_severity": SeverityLevel.ERROR}
        assert route_by_risk(state) == "human_escalation"

    def test_critical_severity_always_escalates(self):
        # Même avec un score bas, CRITICAL → escalade
        state = {"overall_risk_score": 0.1, "final_severity": SeverityLevel.CRITICAL}
        assert route_by_risk(state) == "human_escalation"

    def test_threshold_boundary(self):
        # Exactement au seuil (0.75) → escalade
        state = {"overall_risk_score": 0.75, "final_severity": SeverityLevel.ERROR}
        assert route_by_risk(state) == "human_escalation"

        # En dessous du seuil → auto
        state = {"overall_risk_score": 0.74, "final_severity": SeverityLevel.ERROR}
        assert route_by_risk(state) == "auto_report"


# ─────────────────────────────────────────────────────────────
# Tests : nœuds terminaux
# ─────────────────────────────────────────────────────────────

class TestTerminalNodes:

    def _base_terminal_state(self) -> dict:
        from src.models.log_entry import LogEntry, LogSource
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            source=LogSource.NGINX,
            host="test",
            raw_message="test",
        )
        return {
            "normalized_logs": [log],
            "anomalies": [],
            "overall_risk_score": 0.2,
            "final_severity": SeverityLevel.INFO,
            "llm_analysis": "Aucune anomalie critique.",
            "recommendations": ["Surveillance normale."],
            "source_filter": "*",
            "audit_events": [],
        }

    @pytest.mark.asyncio
    async def test_auto_report_generates_report(self):
        state = self._base_terminal_state()
        result = await auto_report(state)

        assert result["report"] is not None
        assert result["report"].status == ReportStatus.AUTO_RESOLVED
        assert result["report"].routed_to == "auto_report"

    @pytest.mark.asyncio
    async def test_human_escalation_generates_report(self):
        state = {**self._base_terminal_state(), "overall_risk_score": 0.9}
        result = await human_escalation(state)

        assert result["report"] is not None
        assert result["report"].status == ReportStatus.ESCALATED
        assert result["report"].requires_human_review is True
