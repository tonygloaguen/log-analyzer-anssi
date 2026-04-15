"""
Collecteur de logs réseau — Zeek conn.log + fallback tcpdump.

Collecte les métadonnées de flux réseau depuis Zeek (IDS réseau) en mode
principal, avec repli automatique sur tcpdump si Zeek est indisponible.

Les données collectées alimentent le pipeline LangGraph pour la détection
de propagation latérale (T1021) et d'exfiltration (T1041).

Conformité ANSSI :
    - Aucune capture de contenu (payload) : métadonnées de flux uniquement.
    - Horodatage via NTP synchronisé (service ``ntp`` Docker Compose).
    - Rotation et intégrité HMAC via :mod:`core.log_integrity`.

Variables d'environnement :
    ZEEK_LOG_DIR   Répertoire des logs Zeek (défaut ``/var/log/zeek/current``).
    TCPDUMP_IFACE  Interface réseau pour tcpdump fallback (défaut ``eth0``).
    NETWORK_POLL_INTERVAL_S  Intervalle de collecte en secondes (défaut ``30``).

Usage typique ::

    collector = NetworkCollector()
    async for flow_batch in collector.stream_flows():
        await pipeline.ingest(flow_batch)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator


@dataclass
class NetworkFlow:
    """Métadonnées d'un flux réseau normalisé.

    Compatible avec le format Zeek conn.log et le format pcap/tcpdump.

    Attributes:
        timestamp: Horodatage UTC du début du flux.
        src_ip: Adresse IP source.
        dst_ip: Adresse IP destination.
        src_port: Port source.
        dst_port: Port destination.
        proto: Protocole (``tcp``, ``udp``, ``icmp``).
        bytes_sent: Octets envoyés par la source.
        bytes_recv: Octets reçus par la source.
        duration_s: Durée du flux en secondes.
        conn_state: État de connexion Zeek (``S0``, ``SF``, ``REJ``…).
        metadata: Champs supplémentaires Zeek (service, history…).
    """

    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    duration_s: float = 0.0
    conn_state: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


class NetworkCollector:
    """Collecteur de flux réseau avec basculement automatique Zeek → tcpdump.

    Args:
        zeek_log_dir: Répertoire des logs Zeek.
        tcpdump_iface: Interface réseau pour le fallback tcpdump.
        poll_interval_s: Intervalle de scrutation en secondes.
    """

    def __init__(
        self,
        zeek_log_dir: Path = Path("/var/log/zeek/current"),
        tcpdump_iface: str = "eth0",
        poll_interval_s: int = 30,
    ) -> None:
        ...

    async def stream_flows(self) -> AsyncIterator[list[NetworkFlow]]:
        """Génère des batches de flux réseau en continu.

        Tente d'abord de lire depuis Zeek (``conn.log``).
        En cas d'indisponibilité, bascule sur tcpdump avec un avertissement.

        Yields:
            Liste de :class:`NetworkFlow` pour chaque intervalle de collecte.
        """
        ...

    async def _collect_from_zeek(self) -> list[NetworkFlow]:
        """Lit et parse les nouvelles lignes du fichier Zeek ``conn.log``.

        Utilise un curseur de position de fichier pour éviter les doublons
        entre deux cycles de collecte.

        Returns:
            Liste de :class:`NetworkFlow` issus de Zeek.

        Raises:
            FileNotFoundError: Si ``conn.log`` est introuvable.
        """
        ...

    async def _collect_from_tcpdump(self) -> list[NetworkFlow]:
        """Capture des métadonnées réseau via tcpdump (mode fallback).

        Lance ``tcpdump -i {iface} -c 1000 -w -`` en sous-processus et
        parse le flux pcap pour extraire les 5-tuples sans payload.

        Returns:
            Liste de :class:`NetworkFlow` issus de tcpdump.

        Raises:
            RuntimeError: Si tcpdump n'est pas disponible sur le système.
        """
        ...

    @staticmethod
    def _parse_zeek_conn_line(line: str) -> NetworkFlow | None:
        """Parse une ligne TSV du format Zeek conn.log.

        Args:
            line: Ligne brute du fichier conn.log (commentaires ``#`` ignorés).

        Returns:
            :class:`NetworkFlow` si la ligne est valide, ``None`` sinon.
        """
        ...
