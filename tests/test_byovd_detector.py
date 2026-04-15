"""
Tests unitaires — BYOVDDetector.

Couvre :
    1. test_true_positive   : driver LOLDrivers SHA256 connu + handle EDR
                              dans fenêtre 30s → alerte générée.
    2. test_false_positive  : driver légitime SHA256 absent de loldrivers
                              → aucune alerte.
    3. test_window_boundary : driver à t=0, handle EDR à t=29s (corrélé)
                              et t=31s (hors fenêtre, non corrélé).

Fixtures XML Sysmon utilisées depuis tests/fixtures/ :
    sysmon_byovd_tp.xml  — RTCore64.sys (CVE-2019-16098)
    sysmon_byovd_fp.xml  — disk.sys (Microsoft légitime)

Exécution ::

    pytest tests/test_byovd_detector.py -v
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

# HMAC_SECRET obligatoire avant toute importation qui l'utilise
os.environ.setdefault("HMAC_SECRET", "test-secret-byovd-00000000000000000")

from detectors.byovd_detector import BYOVDDetector  # noqa: E402

# ─── SHA256 des fixtures ──────────────────────────────────────────────────────
# RTCore64.sys — présent dans loldrivers (tp)
_TP_SHA256 = "01aa278b07b58dc46a4d4c8a7f26c44be67b16e0a50e4a4efde92d52a21da9b6"
# disk.sys — absent de loldrivers (fp)
_FP_SHA256 = "b94e35f5c36b4d78e9f0a2c1d3e6b8f4a5c9d2e7f0b1a3c6d8e2f4a7b9c1d3e5"

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ─── Helpers de construction d'événements ────────────────────────────────────

def _make_driver_event(sha256: str, ts: float, host: str = "WORKSTATION-01") -> dict:
    """Construit un événement EventID 6 (driver load) normalisé."""
    return {
        "source": "sysmon_xml",
        "event_id": 6,
        "ts": ts,
        "process_id": 4,
        "image_loaded": f"C:\\Windows\\System32\\drivers\\{sha256[:8]}.sys",
        "sha256": sha256,
        "signed": True,
        "signature": "Micro-Star International",
        "target_image": None,
        "utc_time": "",
        "host": host,
    }


def _make_edr_handle_event(ts: float, edr_proc: str = "MsMpEng.exe") -> dict:
    """Construit un événement EventID 10 (handle EDR) normalisé."""
    return {
        "source": "sysmon_xml",
        "event_id": 10,
        "ts": ts,
        "process_id": 1234,
        "image_loaded": None,
        "sha256": "",
        "signed": True,
        "signature": "",
        "target_image": f"C:\\Program Files\\Windows Defender\\{edr_proc}",
        "utc_time": "",
        "host": "WORKSTATION-01",
    }


def _make_unsigned_process_event(ts: float) -> dict:
    """Construit un événement EventID 1 (process create) non signé."""
    return {
        "source": "sysmon_xml",
        "event_id": 1,
        "ts": ts,
        "process_id": 5678,
        "image_loaded": "C:\\Temp\\malware.exe",
        "sha256": "",
        "signed": False,
        "signature": "",
        "target_image": None,
        "utc_time": "",
        "host": "WORKSTATION-01",
    }


# ─── Fixture : détecteur avec cache mock ─────────────────────────────────────

@pytest.fixture()
def mock_cache_path(tmp_path: Path) -> Path:
    """Crée un cache loldrivers.io minimal en JSON avec RTCore64.sys."""
    loldrivers_data = [
        {
            "Id": "test-rtcore64-uuid",
            "Tags": ["MSI", "Afterburner", "kernel"],
            "KnownVulnerableSamples": [
                {
                    "Filename": "RTCore64.sys",
                    "MD5": "2D8E4F38B36C334D0A32A7324832501D",
                    "SHA1": "1234567890ABCDEF1234567890ABCDEF12345678",
                    "SHA256": _TP_SHA256.upper(),
                }
            ],
            "CVEs": ["CVE-2019-16098"],
            "Category": "vulnerable driver",
        }
    ]
    cache = tmp_path / "loldrivers_cache.json"
    cache.write_text(json.dumps(loldrivers_data), encoding="utf-8")
    return cache


@pytest.fixture()
def detector(mock_cache_path: Path) -> BYOVDDetector:
    """BYOVDDetector avec cache minimal (RTCore64.sys / CVE-2019-16098)."""
    return BYOVDDetector(cache_path=mock_cache_path, risk_threshold=0.6)


@pytest.fixture()
def sysmon_tp_xml() -> str:
    """XML Sysmon vrai positif (RTCore64.sys, EventID 6)."""
    return (FIXTURES_DIR / "sysmon_byovd_tp.xml").read_text(encoding="utf-8")


@pytest.fixture()
def sysmon_fp_xml() -> str:
    """XML Sysmon faux positif (disk.sys, EventID 6)."""
    return (FIXTURES_DIR / "sysmon_byovd_fp.xml").read_text(encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — Vrai positif : driver BYOVD + handle EDR dans la fenêtre 30s
# ─────────────────────────────────────────────────────────────────────────────

class TestTruePositive:
    """Driver LOLDrivers SHA256 connu + handle EDR dans fenêtre 30s → alerte."""

    def test_known_driver_with_edr_handle_generates_alert(
        self, detector: BYOVDDetector
    ) -> None:
        """EventID 6 (BYOVD) + EventID 10 (EDR target) dans 30s → 1 alerte."""
        base_ts = time.time()
        events = [
            _make_driver_event(_TP_SHA256, ts=base_ts),
            _make_edr_handle_event(ts=base_ts + 15.0),  # +15s dans la fenêtre
        ]
        alerts = detector.detect(events)

        assert len(alerts) == 1, f"Attendu 1 alerte, obtenu {len(alerts)}"
        alert = alerts[0]
        assert alert["technique"] == "T1068+T1562.001"
        assert alert["confidence"] > 0.7, "Confidence doit être > 0.7 avec corrélation EDR"
        assert len(alert["edr_targeted"]) >= 1, "edr_targeted doit contenir le processus EDR"
        assert "MsMpEng.exe" in alert["edr_targeted"][0]

    def test_alert_contains_cve_ids(self, detector: BYOVDDetector) -> None:
        """L'alerte doit inclure les CVEs associés au pilote."""
        base_ts = time.time()
        events = [_make_driver_event(_TP_SHA256, ts=base_ts)]
        alerts = detector.detect(events)

        assert alerts, "Au moins une alerte attendue"
        assert "CVE-2019-16098" in alerts[0]["cve_ids"]

    def test_alert_has_hmac_signature(self, detector: BYOVDDetector) -> None:
        """Chaque alerte doit être signée avec HMAC-SHA256."""
        events = [_make_driver_event(_TP_SHA256, ts=time.time())]
        alerts = detector.detect(events)

        assert alerts, "Au moins une alerte attendue"
        sig = alerts[0].get("signature", "")
        assert sig and len(sig) == 64, f"Signature HMAC hex 64 chars attendue, obtenu: {sig!r}"

    def test_ingest_sysmon_xml_then_detect(
        self, detector: BYOVDDetector, tmp_path: Path, sysmon_tp_xml: str
    ) -> None:
        """ingest_sysmon_xml() parse le fichier XML et detect() génère une alerte."""
        xml_file = tmp_path / "sysmon_tp.xml"
        xml_file.write_text(sysmon_tp_xml, encoding="utf-8")

        events = detector.ingest_sysmon_xml(str(xml_file))
        assert len(events) >= 1, "Au moins 1 événement parsé depuis le XML"
        assert events[0]["event_id"] == 6
        assert events[0]["sha256"] == _TP_SHA256

        # Injecter un handle EDR dans la même fenêtre temporelle
        edr_ts = events[0]["ts"] + 10.0
        events.append(_make_edr_handle_event(ts=edr_ts))
        alerts = detector.detect(events)

        assert len(alerts) == 1
        assert alerts[0]["confidence"] > 0.7


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — Faux positif : driver légitime → aucune alerte
# ─────────────────────────────────────────────────────────────────────────────

class TestFalsePositive:
    """Driver légitime (SHA256 absent de loldrivers) → aucune alerte."""

    def test_legitimate_driver_generates_no_alert(
        self, detector: BYOVDDetector
    ) -> None:
        """disk.sys (Microsoft) n'est pas dans loldrivers → 0 alerte."""
        events = [
            _make_driver_event(_FP_SHA256, ts=time.time()),
            _make_edr_handle_event(ts=time.time() + 5.0),  # EDR handle présent
        ]
        alerts = detector.detect(events)

        assert len(alerts) == 0, (
            f"Aucune alerte attendue pour un driver légitime, obtenu {len(alerts)}"
        )

    def test_empty_events_list_generates_no_alert(
        self, detector: BYOVDDetector
    ) -> None:
        """Liste vide → aucune alerte."""
        alerts = detector.detect([])
        assert alerts == []

    def test_only_edr_handle_without_byovd_driver_generates_no_alert(
        self, detector: BYOVDDetector
    ) -> None:
        """EventID 10 seul (sans EventID 6 BYOVD) → aucune alerte."""
        events = [_make_edr_handle_event(ts=time.time())]
        alerts = detector.detect(events)
        assert alerts == []

    def test_ingest_fp_xml_generates_no_alert(
        self, detector: BYOVDDetector, tmp_path: Path, sysmon_fp_xml: str
    ) -> None:
        """ingest_sysmon_xml() sur le fichier FP + detect() → 0 alerte."""
        xml_file = tmp_path / "sysmon_fp.xml"
        xml_file.write_text(sysmon_fp_xml, encoding="utf-8")

        events = detector.ingest_sysmon_xml(str(xml_file))
        assert len(events) >= 1
        assert events[0]["sha256"] == _FP_SHA256

        alerts = detector.detect(events)
        assert len(alerts) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — Limite de fenêtre : t=29s (TP), t=31s (hors fenêtre)
# ─────────────────────────────────────────────────────────────────────────────

class TestWindowBoundary:
    """Corrélation temporelle : fenêtre ±30s stricte."""

    def test_edr_handle_at_29s_is_correlated(
        self, detector: BYOVDDetector
    ) -> None:
        """Handle EDR à t=29s : dans la fenêtre → corrélé, edr_targeted non vide."""
        base_ts = 1_710_000_000.0  # timestamp fixe pour la reproductibilité
        events = [
            _make_driver_event(_TP_SHA256, ts=base_ts),
            _make_edr_handle_event(ts=base_ts + 29.0),  # 29s < seuil 30s → TP
        ]
        alerts = detector.detect(events)

        assert len(alerts) == 1
        alert = alerts[0]
        assert len(alert["edr_targeted"]) >= 1, (
            "À t=29s (dans la fenêtre 30s), edr_targeted doit être non vide"
        )
        assert alert["confidence"] > 0.7, (
            "Confiance doit être > 0.7 (base 0.7 + bonus EDR 0.25)"
        )

    def test_edr_handle_at_31s_is_not_correlated(
        self, detector: BYOVDDetector
    ) -> None:
        """Handle EDR à t=31s : hors fenêtre → non corrélé, edr_targeted vide.

        L'alerte BYOVD est toujours générée (driver dans loldrivers),
        mais la corrélation EDR n'est pas comptabilisée.
        """
        base_ts = 1_710_000_000.0
        events = [
            _make_driver_event(_TP_SHA256, ts=base_ts),
            _make_edr_handle_event(ts=base_ts + 31.0),  # 31s > seuil 30s → hors fenêtre
        ]
        alerts = detector.detect(events)

        # L'alerte BYOVD de base doit toujours être présente (driver vulnérable)
        assert len(alerts) == 1, "L'alerte de base (driver BYOVD) doit être générée"
        alert = alerts[0]
        assert alert["edr_targeted"] == [], (
            "À t=31s (hors fenêtre 30s), edr_targeted doit être vide"
        )
        # Confiance de base seulement (0.7), sans bonus EDR
        assert alert["confidence"] == pytest.approx(0.7, abs=0.01), (
            "Confiance doit être la valeur de base (0.7) sans corrélation EDR"
        )

    def test_both_boundaries_in_sequence(
        self, detector: BYOVDDetector
    ) -> None:
        """Vérification séquentielle : deux batches distincts ne se contaminent pas."""
        base_ts = 1_710_100_000.0

        # Batch 1 : driver + handle à 29s (TP)
        events_tp = [
            _make_driver_event(_TP_SHA256, ts=base_ts),
            _make_edr_handle_event(ts=base_ts + 29.0),
        ]
        alerts_tp = detector.detect(events_tp)
        assert alerts_tp[0]["edr_targeted"], "Batch TP : edr_targeted non vide"

        # Réinitialiser le buffer pour isoler le test suivant
        detector._buffer.clear()

        # Batch 2 : driver + handle à 31s (FP boundary)
        events_fp = [
            _make_driver_event(_TP_SHA256, ts=base_ts + 100.0),
            _make_edr_handle_event(ts=base_ts + 131.0),
        ]
        alerts_fp = detector.detect(events_fp)
        assert alerts_fp[0]["edr_targeted"] == [], "Batch FP boundary : edr_targeted vide"
