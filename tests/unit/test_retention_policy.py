"""
Tests de la politique de rétention et d'audit trail — log-analyzer-anssi.

Vérifie les mécanismes de rétention des logs archivés et les propriétés
de l'audit trail conformes ANSSI.

Contrôles NIS2 : NIS2-LOG-04 (rétention), NIS2-LOG-06 (audit trail)
"""
from __future__ import annotations

import gzip
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# Variables de test
os.environ.setdefault("HMAC_SECRET_KEY", "test-retention-policy-key-32bytes!")
os.environ.setdefault("LOG_BASE_DIR", "/tmp/log-analyzer-retention-test")
os.environ.setdefault("LOG_RETENTION_DAYS", "30")

from src.collectors.integrity import (
    apply_retention_policy,
    compute_hmac,
    read_signature_file,
    rotate_log_file,
    verify_archive_integrity,
    verify_hmac,
    write_signature_file,
)


class TestRetentionPolicy:
    """Tests de la politique de rétention ANSSI."""

    def test_retention_deletes_old_archives(self, tmp_path, monkeypatch):
        """Les archives plus anciennes que LOG_RETENTION_DAYS doivent être supprimées."""
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)
        monkeypatch.setattr(integrity_module, "LOG_RETENTION_DAYS", 30)

        # Créer une archive "ancienne" (> 30 jours)
        archive_dir = tmp_path / "archive" / "2024" / "01" / "01"
        archive_dir.mkdir(parents=True)
        old_archive = archive_dir / "old-20240101-000000.log.gz"

        # Créer un vrai fichier gzip
        with gzip.open(old_archive, "wb") as f:
            f.write(b"old log content")

        sig = compute_hmac(old_archive)
        write_signature_file(old_archive, sig)

        # Dater le fichier à plus de 30 jours
        old_time = (datetime.now(timezone.utc) - timedelta(days=35)).timestamp()
        os.utime(old_archive, (old_time, old_time))

        assert old_archive.exists()

        deleted = apply_retention_policy()

        assert deleted == 1
        assert not old_archive.exists()

    def test_retention_preserves_recent_archives(self, tmp_path, monkeypatch):
        """Les archives récentes (< LOG_RETENTION_DAYS) ne doivent pas être supprimées."""
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)
        monkeypatch.setattr(integrity_module, "LOG_RETENTION_DAYS", 90)

        archive_dir = tmp_path / "archive" / "2024" / "01" / "01"
        archive_dir.mkdir(parents=True)
        recent_archive = archive_dir / "recent-20240101-000000.log.gz"

        with gzip.open(recent_archive, "wb") as f:
            f.write(b"recent log content")

        sig = compute_hmac(recent_archive)
        write_signature_file(recent_archive, sig)
        # Fichier créé maintenant = récent

        deleted = apply_retention_policy()

        assert deleted == 0
        assert recent_archive.exists()

    def test_retention_also_deletes_hmac_file(self, tmp_path, monkeypatch):
        """La suppression d'une archive doit aussi supprimer son fichier .hmac."""
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)
        monkeypatch.setattr(integrity_module, "LOG_RETENTION_DAYS", 30)

        archive_dir = tmp_path / "archive" / "2024" / "01" / "01"
        archive_dir.mkdir(parents=True)
        old_archive = archive_dir / "old-20240101-000000.log.gz"

        with gzip.open(old_archive, "wb") as f:
            f.write(b"content to delete")

        sig = compute_hmac(old_archive)
        write_signature_file(old_archive, sig)

        hmac_file = old_archive.with_suffix(old_archive.suffix + ".hmac")
        assert hmac_file.exists()

        # Vieillir le fichier
        old_time = (datetime.now(timezone.utc) - timedelta(days=35)).timestamp()
        os.utime(old_archive, (old_time, old_time))

        apply_retention_policy()

        assert not old_archive.exists()
        assert not hmac_file.exists(), "Le fichier .hmac doit être supprimé avec l'archive"

    def test_retention_returns_count(self, tmp_path, monkeypatch):
        """apply_retention_policy doit retourner le nombre de fichiers supprimés."""
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)
        monkeypatch.setattr(integrity_module, "LOG_RETENTION_DAYS", 30)

        archive_dir = tmp_path / "archive" / "2024" / "01" / "01"
        archive_dir.mkdir(parents=True)

        # Créer 3 archives anciennes
        for i in range(3):
            gz = archive_dir / f"old-{i}.log.gz"
            with gzip.open(gz, "wb") as f:
                f.write(f"content {i}".encode())
            sig = compute_hmac(gz)
            write_signature_file(gz, sig)
            old_time = (datetime.now(timezone.utc) - timedelta(days=35)).timestamp()
            os.utime(gz, (old_time, old_time))

        deleted = apply_retention_policy()
        assert deleted == 3

    def test_empty_archive_dir_returns_zero(self, tmp_path, monkeypatch):
        """Pas d'erreur si le répertoire d'archive est vide."""
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)

        deleted = apply_retention_policy()
        assert deleted == 0


class TestArchiveIntegrity:
    """Tests de la vérification d'intégrité des archives."""

    def test_verify_all_valid_archives(self, tmp_path, monkeypatch):
        """Toutes les archives avec HMAC valide doivent passer la vérification."""
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)

        archive_dir = tmp_path / "archive"
        archive_dir.mkdir()

        # Créer 2 archives signées
        archives = []
        for i in range(2):
            gz = archive_dir / f"valid-{i}.log.gz"
            with gzip.open(gz, "wb") as f:
                f.write(f"valid content {i}".encode())
            sig = compute_hmac(gz)
            write_signature_file(gz, sig)
            archives.append(gz)

        results = verify_archive_integrity(archive_dir)

        assert len(results) == 2
        assert all(results.values()), "Toutes les archives valides doivent passer"

    def test_detects_tampered_archive(self, tmp_path, monkeypatch):
        """Une archive modifiée après signature doit être détectée comme corrompue."""
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)

        archive_dir = tmp_path / "archive"
        archive_dir.mkdir()

        gz = archive_dir / "tampered.log.gz"
        with gzip.open(gz, "wb") as f:
            f.write(b"original content")

        sig = compute_hmac(gz)
        write_signature_file(gz, sig)

        # Falsifier l'archive après signature
        gz.write_bytes(b"FALSIFIED CONTENT")

        results = verify_archive_integrity(archive_dir)

        assert str(gz) in results
        assert results[str(gz)] is False, "L'archive falsifiée doit être détectée"

    def test_missing_hmac_file_flagged(self, tmp_path, monkeypatch):
        """Une archive sans fichier .hmac doit être marquée comme non vérifiable."""
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)

        archive_dir = tmp_path / "archive"
        archive_dir.mkdir()

        gz = archive_dir / "no_sig.log.gz"
        with gzip.open(gz, "wb") as f:
            f.write(b"unsigned content")
        # Pas de fichier .hmac créé

        results = verify_archive_integrity(archive_dir)

        assert str(gz) in results
        assert results[str(gz)] is False, "Archive sans HMAC doit être marquée False"


class TestRotationWithIntegrity:
    """Tests de la rotation avec vérification d'intégrité post-rotation."""

    def test_rotated_file_passes_integrity_check(self, tmp_path, monkeypatch):
        """Un fichier rotaté doit passer la vérification d'intégrité complète."""
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)

        log_file = tmp_path / "test.log"
        log_file.write_text("2024-01-15 INFO Security log entry\n", encoding="utf-8")

        gz_path = rotate_log_file(log_file)

        assert gz_path is not None

        # Vérification complète via verify_archive_integrity
        archive_dir = gz_path.parent
        while archive_dir != tmp_path / "archive" and archive_dir != tmp_path:
            archive_dir = archive_dir.parent
        archive_dir = tmp_path / "archive"

        results = verify_archive_integrity(archive_dir)
        assert all(results.values()), (
            "Les archives fraîchement créées doivent toutes passer l'intégrité"
        )

    def test_rotation_audit_log_not_empty_after_rotate(self, tmp_path, monkeypatch):
        """Après rotation, le fichier source doit être vide (rotation correcte)."""
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)

        log_file = tmp_path / "security.log"
        log_file.write_text(
            "Event: user_login\nEvent: sudo_attempt\n",
            encoding="utf-8",
        )
        original_size = log_file.stat().st_size

        assert original_size > 0

        rotate_log_file(log_file)

        assert log_file.stat().st_size == 0, (
            "Le fichier source doit être vidé après rotation (ANSSI)"
        )
