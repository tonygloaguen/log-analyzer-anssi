"""
Tests unitaires — ransomware_behavior_analyst.

Couvre :
    1. _run_static_detection  — règles déterministes (VSS, chiffrement, backup, lateral)
    2. _static_fallback        — verdict selon confiance maximale
    3. _parse_llm_response     — parsing JSON brut et markdown-wrappé
    4. _merge_results          — fusion indicateurs statiques + résultat LLM
    5. Helpers                 — _build_empty_analysis, _build_notification_payload,
                                 _build_alert_summary
    6. ransomware_behavior_analyst() async — alertes vides + Ollama mocké

Aucun accès réseau requis — Ollama est mocké via unittest.mock.AsyncMock.

Exécution ::

    pytest tests/test_ransomware_analyst.py -v
"""

from __future__ import annotations

import os
import sqlite3
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("HMAC_SECRET", "test-secret-ransomware-00000000000000000")

from nodes.ransomware_behavior_analyst import (  # noqa: E402
    RansomwareIndicators,
    _build_alert_summary,
    _build_empty_analysis,
    _build_notification_payload,
    _detect_mass_encryption,
    _detect_vss_deletion,
    _merge_results,
    _parse_llm_response,
    _run_static_detection,
    _static_fallback,
    ransomware_behavior_analyst,
)


# ─── Helpers de construction d'alertes ───────────────────────────────────────

def _alert(
    message: str = "",
    confidence: float = 0.5,
    technique: str = "T1068",
    host: str = "PC01",
    driver: str = "RTCore64.sys",
) -> dict:
    return {
        "message": message,
        "confidence": confidence,
        "technique": technique,
        "host": host,
        "driver": driver,
        "edr_targeted": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Détection statique
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectVSSDeletion:
    def test_vssadmin_delete(self) -> None:
        assert _detect_vss_deletion(["vssadmin delete shadows /all /quiet"]) is True

    def test_wmic_shadowcopy(self) -> None:
        assert _detect_vss_deletion(["wmic shadowcopy delete"]) is True

    def test_bcdedit_recovery(self) -> None:
        assert _detect_vss_deletion(["bcdedit /set recoveryenabled no"]) is True

    def test_wbadmin_delete_catalog(self) -> None:
        assert _detect_vss_deletion(["wbadmin delete catalog"]) is True

    def test_clean_message_not_detected(self) -> None:
        assert _detect_vss_deletion(["user logged in successfully"]) is False

    def test_empty_list_returns_false(self) -> None:
        assert _detect_vss_deletion([]) is False


class TestDetectMassEncryption:
    def test_locked_extension(self) -> None:
        assert _detect_mass_encryption(["document.docx.locked created"]) is True

    def test_wncry_extension(self) -> None:
        assert _detect_mass_encryption(["file.wncry renamed"]) is True

    def test_encrypt_file_pattern(self) -> None:
        assert _detect_mass_encryption(["encrypt file operation started"]) is True

    def test_clean_message(self) -> None:
        assert _detect_mass_encryption(["normal backup completed"]) is False


class TestRunStaticDetection:
    def test_vss_detection_from_alert(self) -> None:
        alerts = [_alert(message="vssadmin delete shadows /all")]
        ind = _run_static_detection(alerts)
        assert ind.vss_deletion_detected is True

    def test_encryption_detection_from_alert(self) -> None:
        alerts = [_alert(message="C:\\Users\\victim\\doc.locked")]
        ind = _run_static_detection(alerts)
        assert ind.file_encryption_detected is True

    def test_backup_disruption_detection(self) -> None:
        alerts = [_alert(message="wbadmin delete catalog -quiet")]
        ind = _run_static_detection(alerts)
        assert ind.backup_disruption_detected is True

    def test_lateral_movement_detection(self) -> None:
        alerts = [_alert(message="psexec \\\\192.168.1.2 cmd /c whoami")]
        ind = _run_static_detection(alerts)
        assert ind.lateral_movement_detected is True

    def test_clean_alerts_no_indicators(self) -> None:
        alerts = [_alert(message="login success", confidence=0.2)]
        ind = _run_static_detection(alerts)
        assert not ind.vss_deletion_detected
        assert not ind.file_encryption_detected
        assert not ind.backup_disruption_detected
        assert not ind.lateral_movement_detected

    def test_affected_hosts_deduplicated(self) -> None:
        alerts = [
            _alert(host="PC01"),
            _alert(host="PC02"),
            _alert(host="PC01"),  # doublon
        ]
        ind = _run_static_detection(alerts)
        assert sorted(ind.affected_hosts) == ["PC01", "PC02"]

    def test_confidence_boosted_by_indicators(self) -> None:
        alerts = [
            _alert(
                message="vssadmin delete shadows wbadmin delete catalog doc.locked",
                confidence=0.6,
            )
        ]
        ind = _run_static_detection(alerts)
        # base = 0.6, + 3 indicateurs * 0.08 = 0.84
        assert ind.confidence > 0.6

    def test_empty_alerts_returns_zero_confidence(self) -> None:
        ind = _run_static_detection([])
        assert ind.confidence == 0.0
        assert ind.affected_hosts == []

    def test_driver_field_included_in_message_scan(self) -> None:
        """Le champ driver est concaténé au message pour la détection."""
        alerts = [_alert(message="", driver="vssadmin delete")]
        ind = _run_static_detection(alerts)
        assert ind.vss_deletion_detected is True


# ─────────────────────────────────────────────────────────────────────────────
# Fallback statique
# ─────────────────────────────────────────────────────────────────────────────

class TestStaticFallback:
    def test_high_confidence_returns_suspected_ransomware(self) -> None:
        alerts = [_alert(confidence=0.85)]
        result = _static_fallback(alerts)
        assert result["verdict"] == "SUSPECTED_RANSOMWARE"
        assert result["confidence"] == pytest.approx(0.85)

    def test_low_confidence_returns_anomaly(self) -> None:
        alerts = [_alert(confidence=0.5)]
        result = _static_fallback(alerts)
        assert result["verdict"] == "ANOMALY"

    def test_empty_alerts_returns_anomaly_zero_confidence(self) -> None:
        result = _static_fallback([])
        assert result["verdict"] == "ANOMALY"
        assert result["confidence"] == 0.0

    def test_techniques_extracted_from_alerts(self) -> None:
        alerts = [
            _alert(technique="T1068"),
            _alert(technique="T1562.001"),
        ]
        result = _static_fallback(alerts)
        assert "T1068" in result["techniques"]
        assert "T1562.001" in result["techniques"]

    def test_llm_used_always_false(self) -> None:
        result = _static_fallback([_alert(confidence=0.9)])
        assert result["_llm_used"] is False

    def test_recommended_actions_non_empty(self) -> None:
        result = _static_fallback([_alert()])
        assert len(result["recommended_actions"]) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Parse LLM response
# ─────────────────────────────────────────────────────────────────────────────

class TestParseLLMResponse:
    def test_valid_json(self) -> None:
        raw = (
            '{"verdict": "SUSPECTED_RANSOMWARE", "confidence": 0.9, '
            '"techniques": ["T1486"], "recommended_actions": ["isolate"], '
            '"narrative": "Chiffrement massif détecté."}'
        )
        result = _parse_llm_response(raw)
        assert result["verdict"] == "SUSPECTED_RANSOMWARE"
        assert result["confidence"] == pytest.approx(0.9)
        assert "T1486" in result["techniques"]

    def test_markdown_wrapped_json(self) -> None:
        raw = '```json\n{"verdict": "ANOMALY", "confidence": 0.3, "techniques": [], "recommended_actions": [], "narrative": "ok"}\n```'
        result = _parse_llm_response(raw)
        assert result["verdict"] == "ANOMALY"

    def test_invalid_json_returns_unknown(self) -> None:
        result = _parse_llm_response("this is definitely not JSON !!!")
        assert result["verdict"] == "UNKNOWN"
        assert result["confidence"] == 0.0

    def test_empty_string_returns_unknown(self) -> None:
        result = _parse_llm_response("")
        assert result["verdict"] == "UNKNOWN"

    def test_partial_json_embedded_in_text(self) -> None:
        """Le parser doit extraire le premier bloc JSON valide."""
        raw = 'Some prefix text {"verdict": "ANOMALY", "confidence": 0.4, "techniques": [], "recommended_actions": [], "narrative": "partial"} suffix'
        result = _parse_llm_response(raw)
        assert result["verdict"] == "ANOMALY"

    def test_narrative_truncated_to_150_chars(self) -> None:
        long_narrative = "x" * 300
        raw = f'{{"verdict": "X", "confidence": 0.5, "techniques": [], "recommended_actions": [], "narrative": "{long_narrative}"}}'
        result = _parse_llm_response(raw)
        assert len(result["narrative"]) <= 150


# ─────────────────────────────────────────────────────────────────────────────
# Fusion résultats
# ─────────────────────────────────────────────────────────────────────────────

class TestMergeResults:
    def test_vss_elevates_verdict_to_suspected(self) -> None:
        indicators = RansomwareIndicators(vss_deletion_detected=True, confidence=0.6)
        llm = {
            "verdict": "ANOMALY",
            "confidence": 0.5,
            "techniques": [],
            "recommended_actions": [],
            "narrative": "x",
            "_llm_used": True,
        }
        result = _merge_results(indicators, llm, [_alert()])
        assert result["verdict"] == "SUSPECTED_RANSOMWARE"
        assert result["confidence"] >= 0.7

    def test_high_llm_confidence_takes_precedence(self) -> None:
        indicators = RansomwareIndicators(confidence=0.3)
        llm = {
            "verdict": "CONFIRMED_RANSOMWARE",
            "confidence": 0.95,
            "techniques": ["T1486"],
            "recommended_actions": [],
            "narrative": "x",
            "_llm_used": True,
        }
        result = _merge_results(indicators, llm, [])
        assert result["verdict"] == "CONFIRMED_RANSOMWARE"
        assert result["confidence"] == pytest.approx(0.95)

    def test_static_indicators_included_in_result(self) -> None:
        indicators = RansomwareIndicators(
            vss_deletion_detected=True,
            backup_disruption_detected=True,
        )
        llm = {"verdict": "ANOMALY", "confidence": 0.5, "techniques": [], "recommended_actions": [], "narrative": "", "_llm_used": False}
        result = _merge_results(indicators, llm, [])
        assert result["static_indicators"]["vss_deletion"] is True
        assert result["static_indicators"]["backup_disruption"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Helpers divers
# ─────────────────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_build_empty_analysis(self) -> None:
        result = _build_empty_analysis()
        assert result["verdict"] == "NO_ALERT"
        assert result["confidence"] == 0.0
        assert result["alert_count"] == 0
        assert result["_llm_used"] is False

    def test_build_notification_payload_multi_techniques(self) -> None:
        analysis = {
            "verdict": "SUSPECTED_RANSOMWARE",
            "confidence": 0.9,
            "techniques": ["T1486", "T1490"],
            "narrative": "test",
            "ts": 0.0,
        }
        payload = _build_notification_payload(analysis)
        assert payload["verdict"] == "SUSPECTED_RANSOMWARE"
        assert "T1486" in payload["technique"]
        assert "T1490" in payload["technique"]

    def test_build_notification_payload_no_techniques(self) -> None:
        analysis = {"verdict": "X", "confidence": 0.5, "techniques": [], "narrative": "", "ts": 0.0}
        payload = _build_notification_payload(analysis)
        assert payload["technique"] == "UNKNOWN"

    def test_build_alert_summary_limits_to_10(self) -> None:
        alerts = [_alert(technique=f"T{i}") for i in range(15)]
        summary = _build_alert_summary(alerts)
        assert "et 5 alertes supplémentaires" in summary

    def test_build_alert_summary_empty_list(self) -> None:
        assert _build_alert_summary([]) == ""

    def test_build_alert_summary_exactly_10(self) -> None:
        alerts = [_alert(technique=f"T{i}") for i in range(10)]
        summary = _build_alert_summary(alerts)
        assert "supplémentaires" not in summary


# ─────────────────────────────────────────────────────────────────────────────
# Nœud LangGraph async
# ─────────────────────────────────────────────────────────────────────────────

class TestAsyncNode:
    @pytest.mark.asyncio
    async def test_empty_alerts_returns_no_alert(self, tmp_path: object) -> None:
        """Aucune alerte → NO_ALERT sans appel Ollama."""
        os.environ["DB_PATH"] = str(tmp_path / "test_empty.db")  # type: ignore[operator]
        result = await ransomware_behavior_analyst({"alerts": [], "context": ""})
        assert result["analysis"]["verdict"] == "NO_ALERT"
        assert "hmac_signature" in result["analysis"]
        assert result["notification_payload"]["confidence"] == 0.0

    @pytest.mark.asyncio
    async def test_alerts_with_mocked_ollama_produces_signed_analysis(
        self, tmp_path: object
    ) -> None:
        """Alertes + Ollama mocké → analyse signée HMAC."""
        os.environ["DB_PATH"] = str(tmp_path / "test_mock.db")  # type: ignore[operator]
        mock_llm_result = {
            "verdict": "SUSPECTED_RANSOMWARE",
            "confidence": 0.88,
            "techniques": ["T1068+T1562.001"],
            "recommended_actions": ["Isoler le poste"],
            "narrative": "Driver vulnérable + handle EDR détectés.",
            "_llm_used": True,
        }
        with patch(
            "nodes.ransomware_behavior_analyst._call_ollama",
            new=AsyncMock(return_value=mock_llm_result),
        ):
            alerts = [_alert(confidence=0.85, technique="T1068+T1562.001")]
            result = await ransomware_behavior_analyst({"alerts": alerts, "context": "test"})

        analysis = result["analysis"]
        assert analysis["verdict"] in ("SUSPECTED_RANSOMWARE", "ANOMALY")
        assert "hmac_signature" in analysis
        assert len(analysis["hmac_signature"]) == 64  # HMAC-SHA256 hex 64 chars

    @pytest.mark.asyncio
    async def test_analysis_persisted_to_sqlite(self, tmp_path: object) -> None:
        """L'analyse est persistée dans SQLite (checkpoint NIS2)."""
        db_path = str(tmp_path / "test_persist.db")  # type: ignore[operator]
        os.environ["DB_PATH"] = db_path
        await ransomware_behavior_analyst({"alerts": [], "context": ""})
        with sqlite3.connect(db_path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM ransomware_analyses"
            ).fetchone()[0]
        assert count == 1

    @pytest.mark.asyncio
    async def test_notification_payload_structure(self, tmp_path: object) -> None:
        os.environ["DB_PATH"] = str(tmp_path / "test_notif.db")  # type: ignore[operator]
        result = await ransomware_behavior_analyst({"alerts": [], "context": ""})
        payload = result["notification_payload"]
        assert "verdict" in payload
        assert "confidence" in payload
        assert "technique" in payload
        assert "narrative" in payload
        assert "ts" in payload
