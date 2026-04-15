"""
Tests unitaires — BYOVDDetector.

Couvre :
    - Détection vraie positive (pilote vulnérable connu dans loldrivers.io).
    - Détection fausse positive (pilote légitime absent de la base).
    - Parsing des événements Sysmon EventID 6.
    - Gestion du cache loldrivers absent (FileNotFoundError).
    - Corrélation par hash SHA-256 (priorité) vs nom de fichier (repli).

Fixtures utilisées :
    tests/fixtures/sysmon_byovd_tp.xml  — événement Sysmon vrai positif
    tests/fixtures/sysmon_byovd_fp.xml  — événement Sysmon faux positif

Exécution ::

    pytest tests/test_byovd_detector.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from detectors.byovd_detector import BYOVDDetector, BYOVDMatch

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture()
def detector(tmp_path: Path) -> BYOVDDetector:
    """Retourne un BYOVDDetector avec un cache minimal en mémoire."""
    ...


@pytest.fixture()
def sysmon_tp_xml() -> str:
    """Charge le fichier XML vrai positif depuis les fixtures."""
    return (FIXTURES_DIR / "sysmon_byovd_tp.xml").read_text(encoding="utf-8")


@pytest.fixture()
def sysmon_fp_xml() -> str:
    """Charge le fichier XML faux positif depuis les fixtures."""
    return (FIXTURES_DIR / "sysmon_byovd_fp.xml").read_text(encoding="utf-8")


class TestBYOVDDetectorTruePositive:
    """Cas de détection attendue d'un pilote BYOVD connu."""

    @pytest.mark.asyncio()
    async def test_known_driver_is_detected(
        self, detector: BYOVDDetector, sysmon_tp_xml: str
    ) -> None:
        """Un pilote figurant dans loldrivers.io doit générer un BYOVDMatch."""
        ...

    @pytest.mark.asyncio()
    async def test_match_has_nonzero_risk_score(
        self, detector: BYOVDDetector, sysmon_tp_xml: str
    ) -> None:
        """Le score de risque d'une correspondance BYOVD doit être > 0."""
        ...

    @pytest.mark.asyncio()
    async def test_match_contains_cve_ids(
        self, detector: BYOVDDetector, sysmon_tp_xml: str
    ) -> None:
        """Un match vrai positif doit comporter au moins un CVE associé."""
        ...


class TestBYOVDDetectorFalsePositive:
    """Cas où le détecteur ne doit PAS émettre d'alerte."""

    @pytest.mark.asyncio()
    async def test_legitimate_driver_not_detected(
        self, detector: BYOVDDetector, sysmon_fp_xml: str
    ) -> None:
        """Un pilote Microsoft légitime ne doit pas générer de match BYOVD."""
        ...

    @pytest.mark.asyncio()
    async def test_empty_event_returns_no_match(
        self, detector: BYOVDDetector
    ) -> None:
        """Un XML vide ou sans EventID 6 doit retourner une liste vide."""
        ...


class TestBYOVDDetectorEdgeCases:
    """Cas limites et robustesse."""

    def test_missing_cache_raises_file_not_found(self, tmp_path: Path) -> None:
        """Lever FileNotFoundError si le cache loldrivers est absent."""
        ...

    def test_invalid_xml_raises_value_error(
        self, detector: BYOVDDetector
    ) -> None:
        """Lever ValueError si le XML fourni est malformé."""
        ...

    @pytest.mark.asyncio()
    async def test_hash_correlation_takes_priority_over_name(
        self, detector: BYOVDDetector
    ) -> None:
        """La corrélation par hash SHA-256 doit primer sur le nom de fichier."""
        ...
