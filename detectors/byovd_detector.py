"""
BYOVD Correlation Engine — Bring Your Own Vulnerable Driver.

Corrèle les événements Sysmon (EventID 6 — chargement de pilote) avec
la base loldrivers.io pour identifier les pilotes vulnérables connus
utilisés comme vecteur d'escalade de privilèges ou de désactivation EDR.

Conformité ANSSI NIS2 Art.21.2.h : détection des techniques d'évasion défensive.

Référence MITRE ATT&CK :
    T1068  — Exploitation for Privilege Escalation
    T1562.001 — Impair Defenses: Disable or Modify Tools

Flux de données :
    Sysmon XML (EventID 6) → parser → corrélation hash/nom → BYOVDMatch

Usage typique ::

    detector = BYOVDDetector(cache_path=Path("data/loldrivers_cache.json"))
    matches = await detector.analyze_sysmon_events(xml_events)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class BYOVDMatch:
    """Représente une correspondance entre un pilote chargé et la base loldrivers.

    Attributes:
        driver_name: Nom du fichier pilote (ex. ``RTCore64.sys``).
        driver_hash: Hash SHA-256 du pilote.
        cve_ids: Liste des CVE associés au pilote vulnérable.
        risk_score: Score de risque normalisé entre 0.0 et 1.0.
        sysmon_event_id: Identifiant de l'événement Sysmon source.
        is_known_byovd: ``True`` si le pilote figure dans loldrivers.io.
    """

    driver_name: str
    driver_hash: str
    cve_ids: list[str]
    risk_score: float
    sysmon_event_id: str
    is_known_byovd: bool


class BYOVDDetector:
    """Moteur de corrélation BYOVD.

    Charge la base loldrivers.io depuis un cache JSON local et corrèle
    les événements de chargement de pilote Sysmon (EventID 6).

    Args:
        cache_path: Chemin vers le cache JSON loldrivers
                    (``data/loldrivers_cache.json`` par défaut).
        risk_threshold: Score minimal pour émettre une alerte (défaut 0.6).
    """

    def __init__(
        self,
        cache_path: Path = Path("data/loldrivers_cache.json"),
        risk_threshold: float = 0.6,
    ) -> None:
        ...

    async def load_loldrivers_cache(self) -> None:
        """Charge ou recharge le cache loldrivers.io depuis le disque.

        Raises:
            FileNotFoundError: Si le cache n'existe pas encore (lancer
                ``scripts/update_loldrivers.sh`` en premier).
            ValueError: Si le JSON est malformé ou incompatible avec le schéma attendu.
        """
        ...

    async def analyze_sysmon_events(
        self,
        xml_data: str,
    ) -> list[BYOVDMatch]:
        """Analyse un flux d'événements Sysmon XML et retourne les correspondances BYOVD.

        Args:
            xml_data: Contenu XML brut exporté depuis Sysmon / Windows Event Log.

        Returns:
            Liste de :class:`BYOVDMatch` (vide si aucune correspondance).

        Raises:
            ValueError: Si ``xml_data`` n'est pas du XML valide.
        """
        ...

    def _parse_sysmon_event6(self, xml_data: str) -> list[dict[str, Any]]:
        """Extrait les champs pertinents des événements Sysmon EventID 6.

        Args:
            xml_data: XML brut Sysmon.

        Returns:
            Liste de dicts ``{ImageLoaded, Hashes, Signed, Signature}``.
        """
        ...

    def _correlate_with_loldrivers(
        self,
        driver_info: dict[str, Any],
    ) -> BYOVDMatch | None:
        """Cherche une correspondance dans le cache loldrivers pour un pilote donné.

        La corrélation se fait en priorité sur le hash SHA-256,
        avec repli sur le nom de fichier (moins fiable).

        Args:
            driver_info: Dict issu de :meth:`_parse_sysmon_event6`.

        Returns:
            :class:`BYOVDMatch` si correspondance, ``None`` sinon.
        """
        ...
