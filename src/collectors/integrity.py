"""
Module d'intégrité des fichiers de logs — Conforme ANSSI.

Implémente :
- Signature HMAC-SHA256 de chaque fichier archivé
- Vérification d'intégrité avant lecture
- Rotation quotidienne avec compression gzip
- Rétention configurable (défaut 90 jours)
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import logging
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

LOG_BASE_DIR = Path(os.getenv("LOG_BASE_DIR", "/var/log-analyzer"))
LOG_RETENTION_DAYS = int(os.getenv("LOG_RETENTION_DAYS", "90"))
HMAC_SECRET_KEY = os.getenv("HMAC_SECRET_KEY", "").encode()


def compute_hmac(file_path: Path) -> str:
    """
    Calcule la signature HMAC-SHA256 d'un fichier.

    Args:
        file_path: Chemin vers le fichier à signer.

    Returns:
        Signature hexadécimale HMAC-SHA256.

    Raises:
        ValueError: Si la clé HMAC n'est pas configurée.
        FileNotFoundError: Si le fichier n'existe pas.
    """
    if not HMAC_SECRET_KEY:
        raise ValueError("HMAC_SECRET_KEY non configurée — vérifier les variables d'environnement")

    h = hmac.new(HMAC_SECRET_KEY, digestmod=hashlib.sha256)

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)

    return h.hexdigest()


def verify_hmac(file_path: Path, expected_signature: str) -> bool:
    """
    Vérifie l'intégrité d'un fichier par comparaison HMAC.

    Args:
        file_path: Chemin vers le fichier à vérifier.
        expected_signature: Signature HMAC attendue.

    Returns:
        True si l'intégrité est confirmée, False si le fichier est altéré.
    """
    try:
        actual = compute_hmac(file_path)
        # Comparaison en temps constant (protection timing attack)
        result = hmac.compare_digest(actual, expected_signature)
        if not result:
            logger.warning(
                "INTÉGRITÉ COMPROMISE: %s — signature ne correspond pas",
                file_path,
            )
        return result
    except FileNotFoundError:
        logger.error("Fichier introuvable lors de la vérification HMAC: %s", file_path)
        return False
    except Exception as e:
        logger.error("Erreur vérification HMAC %s: %s", file_path, e)
        return False


def write_signature_file(file_path: Path, signature: str) -> None:
    """Écrit la signature HMAC dans un fichier .hmac adjacent."""
    sig_path = file_path.with_suffix(file_path.suffix + ".hmac")
    sig_path.write_text(f"{signature}  {file_path.name}\n", encoding="utf-8")
    logger.debug("Signature HMAC écrite: %s", sig_path)


def read_signature_file(file_path: Path) -> str | None:
    """Lit la signature HMAC depuis le fichier .hmac adjacent."""
    sig_path = file_path.with_suffix(file_path.suffix + ".hmac")
    if not sig_path.exists():
        return None
    content = sig_path.read_text(encoding="utf-8").strip()
    return content.split()[0] if content else None


def rotate_log_file(log_path: Path) -> Path | None:
    """
    Effectue la rotation d'un fichier de log.

    - Compresse le fichier avec gzip
    - Calcule et stocke sa signature HMAC
    - Retourne le chemin du fichier archivé

    Args:
        log_path: Chemin du fichier de log à archiver.

    Returns:
        Chemin du fichier archivé (.gz) ou None si erreur.
    """
    if not log_path.exists() or log_path.stat().st_size == 0:
        logger.debug("Rotation ignorée: %s (vide ou inexistant)", log_path)
        return None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    archive_dir = LOG_BASE_DIR / "archive" / datetime.now(timezone.utc).strftime("%Y/%m/%d")
    archive_dir.mkdir(parents=True, exist_ok=True)

    gz_path = archive_dir / f"{log_path.stem}-{timestamp}.log.gz"

    try:
        # Compression gzip
        with open(log_path, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        # Signature HMAC du fichier compressé
        signature = compute_hmac(gz_path)
        write_signature_file(gz_path, signature)

        # Vider le fichier source (rotation)
        log_path.write_bytes(b"")

        logger.info(
            "Rotation effectuée: %s → %s (HMAC: %s...)",
            log_path,
            gz_path,
            signature[:16],
        )
        return gz_path

    except Exception as e:
        logger.error("Erreur lors de la rotation de %s: %s", log_path, e)
        if gz_path.exists():
            gz_path.unlink()
        return None


def apply_retention_policy() -> int:
    """
    Supprime les fichiers archivés dépassant la rétention configurée.

    Conforme ANSSI : rétention minimum recommandée = 1 an en production.
    La valeur par défaut (90j) est adaptée aux environnements de dev/test.

    Returns:
        Nombre de fichiers supprimés.
    """
    archive_dir = LOG_BASE_DIR / "archive"
    if not archive_dir.exists():
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(days=LOG_RETENTION_DAYS)
    deleted = 0

    for file_path in archive_dir.rglob("*.log.gz"):
        try:
            mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                # Vérifier l'intégrité avant suppression (audit ANSSI)
                stored_sig = read_signature_file(file_path)
                if stored_sig:
                    is_intact = verify_hmac(file_path, stored_sig)
                    if not is_intact:
                        logger.warning(
                            "ATTENTION: suppression d'un fichier corrompu: %s", file_path
                        )

                # Supprimer fichier et sa signature
                file_path.unlink()
                sig_path = file_path.with_suffix(file_path.suffix + ".hmac")
                if sig_path.exists():
                    sig_path.unlink()

                deleted += 1
                logger.info("Rétention: supprimé %s (âge > %d jours)", file_path, LOG_RETENTION_DAYS)

        except Exception as e:
            logger.error("Erreur rétention pour %s: %s", file_path, e)

    if deleted:
        logger.info("Politique de rétention: %d fichiers supprimés", deleted)

    return deleted


def verify_archive_integrity(archive_dir: Path | None = None) -> dict[str, bool]:
    """
    Vérifie l'intégrité de tous les fichiers archivés.

    Returns:
        Dict {chemin_fichier: intégrité_ok}
    """
    base = archive_dir or (LOG_BASE_DIR / "archive")
    results: dict[str, bool] = {}

    for gz_path in base.rglob("*.log.gz"):
        stored_sig = read_signature_file(gz_path)
        if stored_sig is None:
            logger.warning("Pas de signature HMAC pour: %s", gz_path)
            results[str(gz_path)] = False
        else:
            results[str(gz_path)] = verify_hmac(gz_path, stored_sig)

    ok_count = sum(1 for v in results.values() if v)
    logger.info(
        "Vérification intégrité: %d/%d fichiers intègres",
        ok_count, len(results),
    )
    return results
