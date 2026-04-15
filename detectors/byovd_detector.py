"""
BYOVD Correlation Engine — Bring Your Own Vulnerable Driver.

Corrèle les événements Sysmon (EventID 6/10/1) et auditd avec la base
loldrivers.io pour identifier les pilotes vulnérables utilisés comme
vecteur d'escalade de privilèges ou de désactivation d'EDR/AV.

Contraintes RPi 4 :
    - Batch max 50 événements (mémoire limitée).
    - Buffer circulaire ``deque(maxlen=100)`` pour la corrélation inter-batches.

Variables d'environnement :
    LOLDRIVERS_CACHE     Chemin du cache JSON (défaut : data/loldrivers_cache.json).
    LOLDRIVERS_URL       URL de téléchargement (défaut : API loldrivers.io).
    EDR_PROCESS_LIST     Processus EDR/AV ciblés, séparés par virgule.
    HMAC_SECRET          Clé HMAC pour signer les alertes (obligatoire).
    BYOVD_RISK_THRESHOLD Score minimal pour inclure une alerte (défaut : 0.6).

Référence MITRE ATT&CK :
    T1068       — Exploitation for Privilege Escalation
    T1562.001   — Impair Defenses: Disable or Modify Tools
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import defusedxml.ElementTree as ET  # type: ignore[import-untyped]
except ImportError:
    import xml.etree.ElementTree as ET  # type: ignore[assignment]

from core.log_integrity import _require_secret, sign_event

logger = logging.getLogger(__name__)

# ─── Constantes ──────────────────────────────────────────────────────────────

_SYSMON_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_LOLDRIVERS_URL_DEFAULT = "https://www.loldrivers.io/api/drivers.json"
_CACHE_PATH_DEFAULT = "data/loldrivers_cache.json"
_DOWNLOAD_TIMEOUT_S = 10
_CORRELATION_WINDOW_S = 30.0
_BATCH_SIZE = 50
_BUFFER_MAXLEN = 100

_DEFAULT_EDR_PROCESSES = (
    "MsMpEng.exe,bdservicehost.exe,CylanceSvc.exe,SentinelAgent.exe,"
    "cb.exe,csagent.exe,avp.exe,kavfs.exe,mcshield.exe,ekrn.exe"
)


def _local_tag(tag: str) -> str:
    """Retourne le nom local d'un tag XML (sans namespace)."""
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _parse_sysmon_utctime(utc_time: str) -> float:
    """Parse 'YYYY-MM-DD HH:MM:SS.mmm' (UtcTime Sysmon) vers Unix timestamp."""
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(utc_time.strip(), fmt)
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return time.time()


def _parse_system_time(ts_str: str) -> float:
    """Parse 'YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ' (SystemTime Sysmon) vers Unix timestamp."""
    ts_str = ts_str.rstrip("Z")
    if "." in ts_str:
        base, frac = ts_str.split(".", 1)
        frac = frac[:6].ljust(6, "0")
        ts_str = f"{base}.{frac}"
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return time.time()


def _extract_sha256_from_hashes(hashes_str: str) -> str:
    """Extrait le hash SHA256 du champ Hashes Sysmon ('MD5=...,SHA256=...')."""
    for part in hashes_str.split(","):
        part = part.strip()
        if part.upper().startswith("SHA256="):
            return part[7:].lower()
    return ""


# ─── Classe principale ────────────────────────────────────────────────────────

class BYOVDDetector:
    """Moteur de corrélation BYOVD avec buffer circulaire inter-batches.

    Args:
        cache_path: Chemin vers le cache JSON loldrivers.io.
        risk_threshold: Score minimal pour émettre une alerte (0.0–1.0).

    Example::

        detector = BYOVDDetector()
        events = detector.ingest_sysmon_xml("sysmon.xml")
        alerts = detector.detect(events)
    """

    def __init__(
        self,
        cache_path: Path | str | None = None,
        risk_threshold: float | None = None,
    ) -> None:
        self._cache_path = Path(
            cache_path
            or os.environ.get("LOLDRIVERS_CACHE", _CACHE_PATH_DEFAULT)
        )
        self._risk_threshold = risk_threshold if risk_threshold is not None else float(
            os.environ.get("BYOVD_RISK_THRESHOLD", "0.6")
        )
        self._loldrivers_url = os.environ.get("LOLDRIVERS_URL", _LOLDRIVERS_URL_DEFAULT)
        self._edr_processes: list[str] = [
            p.strip().lower()
            for p in os.environ.get("EDR_PROCESS_LIST", _DEFAULT_EDR_PROCESSES).split(",")
            if p.strip()
        ]
        # Lookup dict : sha256_lower → {driver_name, cve_ids}
        self._index: dict[str, dict[str, Any]] = {}
        # Buffer circulaire inter-batches (contrainte RPi mémoire)
        self._buffer: deque[dict[str, Any]] = deque(maxlen=_BUFFER_MAXLEN)
        self._load_cache()

    # ─── Chargement du cache ──────────────────────────────────────────────────

    def _load_cache(self) -> None:
        """Charge le cache loldrivers depuis le disque ; télécharge si absent.

        Fallback : cache vide avec avertissement si le téléchargement échoue.
        """
        if self._cache_path.exists():
            self._index = self._build_index_from_file(self._cache_path)
            logger.info(
                "[BYOVDDetector] Cache chargé : %d SHA256 indexés depuis %s",
                len(self._index),
                self._cache_path,
            )
        else:
            logger.warning(
                "[BYOVDDetector] Cache absent (%s) — tentative de téléchargement depuis %s",
                self._cache_path,
                self._loldrivers_url,
            )
            self._download_cache()

    def _download_cache(self) -> None:
        """Télécharge loldrivers_cache.json depuis loldrivers.io (timeout 10s).

        Fallback sur cache vide si le réseau est indisponible.
        """
        try:
            req = urllib.request.Request(
                self._loldrivers_url,
                headers={"User-Agent": "log-analyzer-anssi/1.0 (ANSSI compliance)"},
            )
            with urllib.request.urlopen(req, timeout=_DOWNLOAD_TIMEOUT_S) as resp:  # noqa: S310  # nosec B310
                data = resp.read()
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache_path.write_bytes(data)
            self._index = self._build_index_from_file(self._cache_path)
            logger.info(
                "[BYOVDDetector] Cache téléchargé : %d SHA256 indexés",
                len(self._index),
            )
        except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError) as exc:
            logger.error(
                "[BYOVDDetector] Téléchargement échoué (%s) — détection BYOVD désactivée. "
                "Lancer scripts/update_loldrivers.sh pour initialiser le cache.",
                exc,
            )
            self._index = {}

    def _build_index_from_file(self, path: Path) -> dict[str, dict[str, Any]]:
        """Construit l'index SHA256 → {driver_name, cve_ids} depuis le JSON."""
        raw = path.read_bytes()
        drivers: list[dict[str, Any]] = json.loads(raw)
        index: dict[str, dict[str, Any]] = {}
        for driver in drivers:
            cves: list[str] = driver.get("CVEs", [])
            for sample in driver.get("KnownVulnerableSamples", []):
                sha256 = sample.get("SHA256", "").lower()
                if sha256:
                    index[sha256] = {
                        "driver_name": sample.get("Filename", "unknown.sys"),
                        "cve_ids": cves,
                        "category": driver.get("Category", ""),
                    }
        return index

    # ─── Ingesteurs de sources ────────────────────────────────────────────────

    def ingest_sysmon_xml(self, path: str) -> list[dict[str, Any]]:
        """Parse un fichier Sysmon XML et normalise les événements.

        Extrait EventID 6 (driver load), EventID 10 (process access),
        EventID 1 (process create). Ignore silencieusement les autres EventID.

        Args:
            path: Chemin vers le fichier XML Sysmon.

        Returns:
            Liste de dicts normalisés (schéma interne unifié).

        Raises:
            FileNotFoundError: Si le fichier est introuvable.
            ValueError: Si le XML est malformé.
        """
        xml_data = Path(path).read_text(encoding="utf-8", errors="replace")
        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError as exc:
            raise ValueError(f"XML Sysmon malformé dans {path}: {exc}") from exc

        ns = _SYSMON_NS
        # Cherche <Event> avec ou sans namespace
        event_elements = root.findall(f".//{{{ns}}}Event") or root.findall(".//Event")

        events: list[dict[str, Any]] = []
        for ev in event_elements:
            parsed = self._parse_sysmon_event(ev, ns)
            if parsed is not None:
                events.append(parsed)
        return events

    def _parse_sysmon_event(
        self, ev: ET.Element, ns: str
    ) -> dict[str, Any] | None:
        """Parse un élément <Event> Sysmon en dict normalisé."""
        def find(tag: str) -> ET.Element | None:
            # NOTE: must use "is not None" — ET elements are falsy when childless
            r = ev.find(f"{{{ns}}}{tag}")
            return r if r is not None else ev.find(tag)

        def find_nested(path: str) -> ET.Element | None:
            ns_path = "/".join(f"{{{ns}}}{p}" for p in path.split("/"))
            r = ev.find(ns_path)
            return r if r is not None else ev.find(path)

        # EventID
        eid_el = find_nested("System/EventID")
        if eid_el is None or not eid_el.text:
            return None
        try:
            event_id = int(eid_el.text.strip())
        except ValueError:
            return None
        if event_id not in (1, 6, 10):
            return None

        # Timestamp (priorité : UtcTime dans EventData, sinon SystemTime)
        time_created = find_nested("System/TimeCreated")
        system_time = _parse_system_time(
            time_created.get("SystemTime", "") if time_created is not None else ""
        )

        # ProcessID depuis Execution[@ProcessID]
        execution = find_nested("System/Execution")
        process_id = int(execution.get("ProcessID", "0")) if execution is not None else 0

        # EventData fields
        data_fields: dict[str, str] = {}
        for data_el in ev.iter():
            local = _local_tag(data_el.tag)
            if local == "Data":
                name = data_el.get("Name", "")
                value = data_el.text or ""
                if name:
                    data_fields[name] = value

        utc_time_str = data_fields.get("UtcTime", "")
        ts = _parse_sysmon_utctime(utc_time_str) if utc_time_str else system_time

        sha256 = _extract_sha256_from_hashes(data_fields.get("Hashes", ""))

        return {
            "source": "sysmon_xml",
            "event_id": event_id,
            "ts": ts,
            "process_id": process_id,
            "image_loaded": data_fields.get("ImageLoaded"),
            "sha256": sha256,
            "signed": data_fields.get("Signed", "false").lower() == "true",
            "signature": data_fields.get("Signature", ""),
            "target_image": data_fields.get("TargetImage"),
            "utc_time": utc_time_str,
            "host": "unknown",
        }

    def ingest_auditd(self, path: str) -> list[dict[str, Any]]:
        """Parse un fichier auditd Linux et normalise les événements.

        Regroupe les enregistrements par serial (msg=audit(ts:serial))
        et extrait les appels système et chemins d'exécutables.

        Args:
            path: Chemin vers le fichier auditd (ex. ``/var/log/audit/audit.log``).

        Returns:
            Liste de dicts normalisés. Schéma : event_id=1 (process),
            image_loaded=chemin, sha256='', signed=False, source='auditd'.

        Raises:
            FileNotFoundError: Si le fichier est introuvable.
        """
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        # Regroupe par serial auditd : audit(ts:serial)
        records: dict[str, dict[str, Any]] = {}
        _audit_re = re.compile(r"audit\((\d+\.\d+):(\d+)\)")
        _kv_re = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

        for line in lines:
            m = _audit_re.search(line)
            if not m:
                continue
            ts_str, serial = m.group(1), m.group(2)
            key = serial
            if key not in records:
                records[key] = {"ts": float(ts_str), "fields": {}, "types": []}
            # Type de record
            type_m = re.match(r"type=(\w+)", line)
            if type_m:
                records[key]["types"].append(type_m.group(1))
            # Clés/valeurs
            for kv in _kv_re.finditer(line):
                k, v = kv.group(1), kv.group(2).strip('"')
                records[key]["fields"][k] = v

        events: list[dict[str, Any]] = []
        for rec in records.values():
            fields = rec["fields"]
            exe = fields.get("exe", fields.get("comm", ""))
            events.append({
                "source": "auditd",
                "event_id": 1,  # assimilé à process create
                "ts": rec["ts"],
                "process_id": int(fields.get("pid", "0")),
                "image_loaded": exe.strip('"') if exe else None,
                "sha256": "",
                "signed": False,
                "signature": "",
                "target_image": None,
                "utc_time": "",
                "host": fields.get("hostname", "unknown"),
                "syscall": fields.get("syscall", ""),
                "argv": [
                    fields.get(f"a{i}", "")
                    for i in range(int(fields.get("argc", "0")))
                ],
            })
        return events

    def ingest_syslog_json(self, path: str) -> list[dict[str, Any]]:
        """Parse un fichier de syslog JSON normalisé (une ligne = un objet JSON).

        Format attendu (NDJSON) ::

            {"ts": 1710461862.0, "host": "server01", "message": "...", ...}

        Args:
            path: Chemin vers le fichier NDJSON.

        Returns:
            Liste de dicts normalisés (event_id inféré depuis le message).

        Raises:
            FileNotFoundError: Si le fichier est introuvable.
        """
        events: list[dict[str, Any]] = []
        for i, line in enumerate(Path(path).read_text(encoding="utf-8", errors="replace").splitlines()):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.debug("[ingest_syslog_json] Ligne %d ignorée (JSON invalide): %s", i, exc)
                continue
            # Timestamp : ts (float), timestamp (str ISO), @timestamp (str)
            ts_raw = obj.get("ts") or obj.get("timestamp") or obj.get("@timestamp")
            ts: float
            if isinstance(ts_raw, (int, float)):
                ts = float(ts_raw)
            elif isinstance(ts_raw, str):
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).timestamp()
                except ValueError:
                    ts = time.time()
            else:
                ts = time.time()
            events.append({
                "source": "syslog_json",
                "event_id": 1,
                "ts": ts,
                "process_id": int(obj.get("pid", 0)),
                "image_loaded": obj.get("exe") or obj.get("program"),
                "sha256": obj.get("sha256", ""),
                "signed": False,
                "signature": "",
                "target_image": None,
                "utc_time": "",
                "host": obj.get("host", obj.get("hostname", "unknown")),
                "message": obj.get("message", ""),
            })
        return events

    # ─── Détection et corrélation ─────────────────────────────────────────────

    def detect(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Corrèle les événements et retourne les alertes BYOVD signées.

        Algorithme :
        1. Traitement en batches de 50 (contrainte mémoire RPi).
        2. Chaque événement est ajouté au buffer circulaire (deque maxlen=100).
        3. Pour chaque EventID 6 avec SHA256 connu dans loldrivers :
           - Cherche EventID 10 ciblant un EDR dans ±30s (buffer + batch courant).
           - Cherche EventID 1 non signé dans la même fenêtre.
           - Calcule le score de confiance composite.
        4. Filtre par ``risk_threshold``.
        5. Signe chaque alerte avec HMAC-SHA256.

        Args:
            events: Liste d'événements normalisés (sortie des ``ingest_*``).

        Returns:
            Liste d'alertes JSON signées. Schéma :
            ``{technique, confidence, driver, edr_targeted, ts, signature}``.
        """
        secret = _require_secret()
        alerts: list[dict[str, Any]] = []

        for batch_start in range(0, max(len(events), 1), _BATCH_SIZE):
            batch = events[batch_start: batch_start + _BATCH_SIZE]
            for ev in batch:
                self._buffer.append(ev)
            alerts.extend(self._correlate_batch(batch, secret))

        return alerts

    def _correlate_batch(
        self, batch: list[dict[str, Any]], secret: bytes
    ) -> list[dict[str, Any]]:
        """Analyse un batch d'événements contre le buffer courant."""
        alerts: list[dict[str, Any]] = []
        seen_drivers: set[str] = set()  # dédup par SHA256 + ts dans ce batch

        for ev in batch:
            if ev.get("event_id") != 6:
                continue
            sha256 = (ev.get("sha256") or "").lower()
            if not sha256 or sha256 not in self._index:
                continue
            dedup_key = f"{sha256}:{ev.get('ts', 0):.0f}"
            if dedup_key in seen_drivers:
                continue
            seen_drivers.add(dedup_key)

            entry = self._index[sha256]
            confidence, edr_targeted = self._check_temporal_correlation(ev)

            if confidence < self._risk_threshold:
                continue

            alert_body: dict[str, Any] = {
                "technique": "T1068+T1562.001",
                "confidence": round(confidence, 4),
                "driver": entry["driver_name"],
                "cve_ids": entry["cve_ids"],
                "sha256": sha256,
                "edr_targeted": edr_targeted,
                "ts": ev.get("ts", time.time()),
                "host": ev.get("host", "unknown"),
                "source": ev.get("source", "unknown"),
            }
            alert_body["signature"] = sign_event(alert_body, secret)
            alerts.append(alert_body)

        return alerts

    def _check_temporal_correlation(
        self, driver_ev: dict[str, Any]
    ) -> tuple[float, list[str]]:
        """Cherche les événements corrélés dans ±30s autour du chargement de pilote.

        Args:
            driver_ev: Événement EventID 6 déjà identifié comme BYOVD.

        Returns:
            Tuple ``(confidence, edr_targeted_list)``.
            confidence : 0.7 (base) + 0.25 si EDR ciblé + 0.05 si non signé.
        """
        driver_ts: float = driver_ev.get("ts", 0.0)
        confidence: float = 0.7  # confiance de base : driver BYOVD seul
        edr_targeted: list[str] = []

        for buffered in self._buffer:
            delta = abs(buffered.get("ts", 0.0) - driver_ts)
            if delta > _CORRELATION_WINDOW_S:
                continue

            ev_id = buffered.get("event_id")

            if ev_id == 10:
                # EventID 10 : process access — cible un EDR ?
                target = (buffered.get("target_image") or "").lower()
                for edr_proc in self._edr_processes:
                    if edr_proc in target and target not in edr_targeted:
                        edr_targeted.append(buffered.get("target_image", target))
                        confidence = min(0.95, confidence + 0.25)
                        break

            elif ev_id == 1 and not buffered.get("signed", True):
                # EventID 1 non signé dans la fenêtre → indicateur supplémentaire
                confidence = min(0.95, confidence + 0.05)

        return confidence, edr_targeted
