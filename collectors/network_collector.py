"""
Collecteur de logs réseau — Zeek conn.log + fallback tcpdump.

Détections embarquées :
    - Beaconing C2 : même (src, dst, port), intervalle < 60s, > 5 connexions.
    - Connexions Tor : port 9001 ou 9030 en destination.
    - DoH suspect : 8.8.8.8:443 ou 1.1.1.1:443 avec volume resp > 1 Mo.

Conformité ANSSI :
    - Métadonnées de flux uniquement (pas de payload).
    - Horodatage NTP via service Docker Compose.

Variables d'environnement :
    ZEEK_LOG_DIR            Répertoire logs Zeek (défaut : /var/log/zeek/current).
    TCPDUMP_IFACE           Interface fallback tcpdump (défaut : eth0).
    NETWORK_POLL_INTERVAL_S Intervalle de collecte en secondes (défaut : 30).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

logger = logging.getLogger(__name__)

# Scapy : import optionnel — graceful degradation si absent
try:
    from scapy.all import IP, TCP, UDP, rdpcap  # type: ignore[import-untyped]
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False

# ─── Seuils de détection ─────────────────────────────────────────────────────
_BEACON_INTERVAL_MAX_S = 60.0      # intervalle max entre connexions (beaconing)
_BEACON_COUNT_MIN = 5              # nb min de connexions pour flag beaconing
_TOR_PORTS = frozenset((9001, 9030))
_DOH_HOSTS = frozenset(("8.8.8.8", "1.1.1.1", "9.9.9.9", "149.112.112.112"))
_DOH_PORT = 443
_DOH_BYTES_THRESHOLD = 1_000_000  # 1 Mo en resp_bytes → suspect


# ─── Modèle de flux réseau ───────────────────────────────────────────────────

@dataclass
class NetworkFlow:
    """Métadonnées d'un flux réseau normalisé (Zeek ou tcpdump).

    Attributes:
        timestamp: Horodatage UTC du début du flux.
        src_ip: Adresse IP source.
        dst_ip: Adresse IP destination.
        src_port: Port source.
        dst_port: Port destination.
        proto: Protocole (``tcp``, ``udp``, ``icmp``).
        bytes_sent: Octets envoyés par la source (orig_bytes Zeek).
        bytes_recv: Octets reçus par la source (resp_bytes Zeek).
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


# ─── Collecteur principal ─────────────────────────────────────────────────────

class NetworkCollector:
    """Collecteur de flux réseau avec basculement automatique Zeek → tcpdump.

    Args:
        zeek_log_dir: Répertoire des logs Zeek.
        tcpdump_iface: Interface réseau pour le fallback tcpdump.
        poll_interval_s: Intervalle de scrutation en secondes.
    """

    def __init__(
        self,
        zeek_log_dir: Path | None = None,
        tcpdump_iface: str | None = None,
        poll_interval_s: int | None = None,
    ) -> None:
        self._zeek_log_dir = Path(
            zeek_log_dir or os.environ.get("ZEEK_LOG_DIR", "/var/log/zeek/current")
        )
        self._tcpdump_iface = tcpdump_iface or os.environ.get("TCPDUMP_IFACE", "eth0")
        self._poll_interval_s = poll_interval_s if poll_interval_s is not None else int(
            os.environ.get("NETWORK_POLL_INTERVAL_S", "30")
        )
        # Curseur de lecture Zeek (évite les doublons entre cycles)
        self._zeek_file_pos: int = 0

    # ─── Stream continu ───────────────────────────────────────────────────────

    async def stream_flows(self) -> AsyncIterator[list[NetworkFlow]]:
        """Génère des batches de flux réseau en continu.

        Tente Zeek d'abord ; bascule sur tcpdump si conn.log est absent.

        Yields:
            Liste de :class:`NetworkFlow` pour chaque intervalle de collecte.
        """
        zeek_conn = self._zeek_log_dir / "conn.log"
        while True:
            if zeek_conn.exists():
                try:
                    flows = await self._collect_from_zeek()
                    yield flows
                except Exception as exc:
                    logger.warning("[NetworkCollector] Zeek error (%s) — fallback tcpdump", exc)
                    flows = await self._collect_from_tcpdump()
                    yield flows
            else:
                logger.warning(
                    "[NetworkCollector] %s introuvable — utilisation de tcpdump",
                    zeek_conn,
                )
                flows = await self._collect_from_tcpdump()
                yield flows
            await asyncio.sleep(self._poll_interval_s)

    async def _collect_from_zeek(self) -> list[NetworkFlow]:
        """Lit les nouvelles lignes de conn.log depuis le dernier curseur.

        Returns:
            Liste de :class:`NetworkFlow` issus de Zeek.
        """
        conn_log = self._zeek_log_dir / "conn.log"
        flows: list[NetworkFlow] = []

        loop = asyncio.get_event_loop()
        content = await loop.run_in_executor(None, conn_log.read_text, "utf-8")
        lines = content.splitlines()
        new_lines = lines[self._zeek_file_pos:]
        self._zeek_file_pos = len(lines)

        for line in new_lines:
            flow = self._parse_zeek_conn_line(line)
            if flow is not None:
                flows.append(flow)
        return flows

    async def _collect_from_tcpdump(self) -> list[NetworkFlow]:
        """Capture des métadonnées réseau via tcpdump (mode fallback).

        Capture 60 secondes ou jusqu'au prochain cycle.
        Parse avec scapy si disponible, sinon retourne liste vide avec log.

        Returns:
            Liste de :class:`NetworkFlow` issus de tcpdump.
        """
        if not _SCAPY_AVAILABLE:
            logger.warning(
                "[NetworkCollector] scapy non installé — tcpdump fallback non disponible. "
                "Installer avec : pip install scapy"
            )
            return []

        pcap_path = Path(tempfile.mktemp(suffix=".pcap", prefix="log_analyzer_"))
        duration = min(self._poll_interval_s, 60)
        try:
            proc = await asyncio.create_subprocess_exec(
                "tcpdump",
                "-i", self._tcpdump_iface,
                "-w", str(pcap_path),
                "--immediate-mode",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.sleep(duration)
            proc.terminate()
            await proc.wait()
        except FileNotFoundError:
            logger.error("[NetworkCollector] tcpdump non trouvé — vérifier l'installation")
            return []
        except Exception as exc:
            logger.error("[NetworkCollector] Erreur tcpdump: %s", exc)
            return []

        if not pcap_path.exists():
            return []

        flows: list[NetworkFlow] = []
        try:
            packets = rdpcap(str(pcap_path))
            now = datetime.now(timezone.utc)
            for pkt in packets:
                if IP not in pkt:
                    continue
                proto = "tcp" if TCP in pkt else "udp" if UDP in pkt else "other"
                src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                flows.append(NetworkFlow(
                    timestamp=now,
                    src_ip=pkt[IP].src,
                    dst_ip=pkt[IP].dst,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=proto,
                    bytes_sent=len(pkt),
                ))
        except Exception as exc:
            logger.error("[NetworkCollector] Erreur parsing pcap: %s", exc)
        finally:
            pcap_path.unlink(missing_ok=True)

        return flows

    @staticmethod
    def _parse_zeek_conn_line(line: str) -> NetworkFlow | None:
        """Parse une ligne TSV du format Zeek conn.log.

        Args:
            line: Ligne brute du fichier conn.log (commentaires ``#`` ignorés).

        Returns:
            :class:`NetworkFlow` si la ligne est valide et non commentaire.
        """
        if not line or line.startswith("#"):
            return None
        fields = line.split("\t")
        # conn.log : ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto
        #            service duration orig_bytes resp_bytes conn_state ...
        if len(fields) < 12:
            return None
        try:
            ts_float = float(fields[0])
            src_ip = fields[2]
            src_port = int(fields[3])
            dst_ip = fields[4]
            dst_port = int(fields[5])
            proto = fields[6]
            duration = float(fields[8]) if fields[8] not in ("-", "") else 0.0
            orig_bytes = int(fields[9]) if fields[9] not in ("-", "") else 0
            resp_bytes = int(fields[10]) if fields[10] not in ("-", "") else 0
            conn_state = fields[11] if len(fields) > 11 else ""
            service = fields[7] if fields[7] not in ("-", "") else ""
        except (ValueError, IndexError):
            return None

        return NetworkFlow(
            timestamp=datetime.fromtimestamp(ts_float, tz=timezone.utc),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            bytes_sent=orig_bytes,
            bytes_recv=resp_bytes,
            duration_s=duration,
            conn_state=conn_state,
            metadata={"service": service, "uid": fields[1] if len(fields) > 1 else ""},
        )

    # ─── Détection des anomalies réseau ──────────────────────────────────────

    def parse_zeek_conn_log(self, path: str) -> list[dict[str, Any]]:
        """Parse conn.log et retourne les alertes réseau détectées.

        Détections :
        - Beaconing C2 : > 5 connexions vers même (dst, port) avec intervalles < 60s.
        - Connexions Tor : port 9001 ou 9030.
        - DoH suspect : 8.8.8.8/1.1.1.1:443 avec resp_bytes > 1 Mo cumulé.

        Args:
            path: Chemin vers le fichier conn.log.

        Returns:
            Liste d'alertes réseau (dicts avec alert_type, IPs, confidence…).
        """
        flows: list[NetworkFlow] = []
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            flow = self._parse_zeek_conn_line(line)
            if flow is not None:
                flows.append(flow)

        alerts: list[dict[str, Any]] = []
        alerts.extend(self._detect_beaconing(flows))
        alerts.extend(self._detect_tor(flows))
        alerts.extend(self._detect_doh(flows))
        return alerts

    def _detect_beaconing(self, flows: list[NetworkFlow]) -> list[dict[str, Any]]:
        """Détecte le beaconing C2 par régularité des intervalles de connexion."""
        # Grouper par (src_ip, dst_ip, dst_port)
        groups: dict[tuple[str, str, int], list[float]] = defaultdict(list)
        for f in flows:
            groups[(f.src_ip, f.dst_ip, f.dst_port)].append(f.timestamp.timestamp())

        alerts = []
        for (src, dst, port), timestamps in groups.items():
            if len(timestamps) < _BEACON_COUNT_MIN:
                continue
            timestamps_sorted = sorted(timestamps)
            intervals = [
                timestamps_sorted[i + 1] - timestamps_sorted[i]
                for i in range(len(timestamps_sorted) - 1)
            ]
            regular_count = sum(1 for iv in intervals if iv < _BEACON_INTERVAL_MAX_S)
            if regular_count >= _BEACON_COUNT_MIN - 1:
                avg_interval = sum(intervals) / len(intervals)
                confidence = min(0.9, 0.5 + (regular_count / len(intervals)) * 0.4)
                alerts.append({
                    "alert_type": "beaconing",
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": port,
                    "connection_count": len(timestamps),
                    "avg_interval_s": round(avg_interval, 1),
                    "ts": timestamps_sorted[0],
                    "confidence": round(confidence, 4),
                    "technique": "T1071",
                })
        return alerts

    def _detect_tor(self, flows: list[NetworkFlow]) -> list[dict[str, Any]]:
        """Détecte les connexions sortantes vers les ports Tor (9001, 9030)."""
        alerts = []
        for f in flows:
            if f.dst_port in _TOR_PORTS:
                alerts.append({
                    "alert_type": "tor_connection",
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "dst_port": f.dst_port,
                    "connection_count": 1,
                    "ts": f.timestamp.timestamp(),
                    "confidence": 0.8,
                    "technique": "T1090.003",
                })
        return alerts

    def _detect_doh(self, flows: list[NetworkFlow]) -> list[dict[str, Any]]:
        """Détecte le DNS over HTTPS suspect (volume élevé vers résolveurs connus)."""
        # Agrège resp_bytes par (src, dst) pour les flux DoH
        doh_volumes: dict[tuple[str, str], int] = defaultdict(int)
        doh_ts: dict[tuple[str, str], float] = {}
        for f in flows:
            if f.dst_ip in _DOH_HOSTS and f.dst_port == _DOH_PORT:
                key = (f.src_ip, f.dst_ip)
                doh_volumes[key] += f.bytes_recv
                doh_ts.setdefault(key, f.timestamp.timestamp())

        alerts = []
        for (src, dst), total_bytes in doh_volumes.items():
            if total_bytes > _DOH_BYTES_THRESHOLD:
                confidence = min(0.85, 0.5 + (total_bytes / _DOH_BYTES_THRESHOLD) * 0.1)
                alerts.append({
                    "alert_type": "doh_suspicious",
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": _DOH_PORT,
                    "resp_bytes_total": total_bytes,
                    "connection_count": 1,
                    "ts": doh_ts.get((src, dst), time.time()),
                    "confidence": round(confidence, 4),
                    "technique": "T1071.004",
                })
        return alerts

    async def capture_tcpdump(
        self, iface: str, duration: int = 60
    ) -> list[dict[str, Any]]:
        """Capture réseau via tcpdump et retourne les flux normalisés.

        Mode fallback si Zeek est absent. Scapy requis pour le parsing.
        Si scapy est absent, retourne une liste vide avec avertissement.

        Args:
            iface: Interface réseau (ex. ``eth0``, ``wlan0``).
            duration: Durée de capture en secondes (défaut 60).

        Returns:
            Liste de dicts de flux réseau (schéma commun avec Zeek).
        """
        flows = await self._collect_from_tcpdump_on_iface(iface, duration)
        return [
            {
                "alert_type": "raw_flow",
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "src_port": f.src_port,
                "dst_port": f.dst_port,
                "proto": f.proto,
                "bytes_sent": f.bytes_sent,
                "ts": f.timestamp.timestamp(),
                "confidence": 0.0,
            }
            for f in flows
        ]

    async def _collect_from_tcpdump_on_iface(
        self, iface: str, duration: int
    ) -> list[NetworkFlow]:
        """Implémentation de la capture tcpdump pour une interface spécifique."""
        if not _SCAPY_AVAILABLE:
            logger.warning("[NetworkCollector] scapy absent — capture tcpdump impossible")
            return []

        pcap_path = Path(tempfile.mktemp(suffix=".pcap", prefix="log_analyzer_net_"))
        try:
            proc = await asyncio.create_subprocess_exec(
                "tcpdump", "-i", iface, "-w", str(pcap_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.sleep(duration)
            proc.terminate()
            await proc.wait()
        except FileNotFoundError:
            logger.error("[NetworkCollector] tcpdump introuvable")
            return []
        except Exception as exc:
            logger.error("[NetworkCollector] Erreur tcpdump: %s", exc)
            return []

        if not pcap_path.exists():
            return []

        flows: list[NetworkFlow] = []
        try:
            packets = rdpcap(str(pcap_path))
            for pkt in packets:
                if IP not in pkt:
                    continue
                proto = "tcp" if TCP in pkt else "udp" if UDP in pkt else "other"
                sp = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                dp = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                flows.append(NetworkFlow(
                    timestamp=datetime.now(timezone.utc),
                    src_ip=pkt[IP].src,
                    dst_ip=pkt[IP].dst,
                    src_port=sp,
                    dst_port=dp,
                    proto=proto,
                    bytes_sent=len(pkt),
                ))
        except Exception as exc:
            logger.error("[NetworkCollector] Erreur parsing pcap: %s", exc)
        finally:
            pcap_path.unlink(missing_ok=True)

        return flows

    def score_composite(
        self,
        network_alerts: list[dict[str, Any]],
        byovd_alerts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Corrèle les alertes réseau avec les alertes BYOVD.

        Croise les timestamps (fenêtre ±120s) et produit un score composite
        amplifiant la confiance quand les deux sources coïncident.

        Args:
            network_alerts: Sortie de :meth:`parse_zeek_conn_log`.
            byovd_alerts: Sortie de :class:`~detectors.byovd_detector.BYOVDDetector.detect`.

        Returns:
            Liste de dicts composites ``{alert_type, network_alert, byovd_alert, score, ts}``.
        """
        _CORRELATION_WINDOW = 120.0
        composites: list[dict[str, Any]] = []

        for net in network_alerts:
            for byovd in byovd_alerts:
                net_ts: float = net.get("ts", 0.0)
                byovd_ts: float = byovd.get("ts", 0.0)
                if abs(net_ts - byovd_ts) > _CORRELATION_WINDOW:
                    continue
                net_conf: float = net.get("confidence", 0.0)
                byovd_conf: float = byovd.get("confidence", 0.0)
                # Score composite = moyenne pondérée + bonus de corrélation
                score = min(1.0, (net_conf + byovd_conf) / 2 + 0.1)
                composites.append({
                    "alert_type": "composite",
                    "network_alert": net,
                    "byovd_alert": byovd,
                    "score": round(score, 4),
                    "ts": min(net_ts, byovd_ts),
                    "techniques": list({
                        net.get("technique", ""),
                        byovd.get("technique", ""),
                    } - {""}),
                })

        return composites
