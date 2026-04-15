"""
Tests unitaires du module d'intégrité HMAC.

Vérifie la conformité ANSSI : signature, vérification, rotation, rétention.
"""

from __future__ import annotations

import gzip
import os
from pathlib import Path

import pytest

# Fixer la clé HMAC pour les tests
os.environ.setdefault("HMAC_SECRET_KEY", "test-secret-key-for-unit-tests-32bytes!")
os.environ.setdefault("LOG_BASE_DIR", "/tmp/log-analyzer-test")
os.environ.setdefault("LOG_RETENTION_DAYS", "7")

from src.collectors.integrity import (
    compute_hmac,
    read_signature_file,
    rotate_log_file,
    verify_hmac,
    write_signature_file,
)


@pytest.fixture
def temp_log_file(tmp_path: Path) -> Path:
    """Crée un fichier de log temporaire pour les tests."""
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "2024-01-15T10:30:00 INFO User logged in\n"
        "2024-01-15T10:31:00 ERROR Failed authentication\n",
        encoding="utf-8",
    )
    return log_file


class TestHmacComputation:

    def test_compute_hmac_returns_hex_string(self, temp_log_file):
        sig = compute_hmac(temp_log_file)
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA-256 = 64 caractères hex

    def test_same_file_same_signature(self, temp_log_file):
        sig1 = compute_hmac(temp_log_file)
        sig2 = compute_hmac(temp_log_file)
        assert sig1 == sig2

    def test_modified_file_different_signature(self, temp_log_file):
        sig1 = compute_hmac(temp_log_file)
        temp_log_file.write_text("modified content", encoding="utf-8")
        sig2 = compute_hmac(temp_log_file)
        assert sig1 != sig2

    def test_compute_hmac_raises_without_key(self, temp_log_file, monkeypatch):
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "HMAC_SECRET_KEY", b"")
        with pytest.raises(ValueError, match="HMAC_SECRET_KEY"):
            compute_hmac(temp_log_file)

    def test_compute_hmac_raises_on_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            compute_hmac(tmp_path / "nonexistent.log")


class TestHmacVerification:

    def test_verify_valid_signature(self, temp_log_file):
        sig = compute_hmac(temp_log_file)
        assert verify_hmac(temp_log_file, sig) is True

    def test_verify_detects_tampered_file(self, temp_log_file):
        sig = compute_hmac(temp_log_file)
        # Falsifier le fichier après signature
        with open(temp_log_file, "a") as f:
            f.write("INJECTED MALICIOUS CONTENT\n")
        assert verify_hmac(temp_log_file, sig) is False

    def test_verify_detects_wrong_signature(self, temp_log_file):
        assert verify_hmac(temp_log_file, "a" * 64) is False

    def test_verify_missing_file_returns_false(self, tmp_path):
        assert verify_hmac(tmp_path / "missing.log", "a" * 64) is False


class TestSignatureFile:

    def test_write_and_read_signature(self, temp_log_file):
        sig = compute_hmac(temp_log_file)
        write_signature_file(temp_log_file, sig)
        read_sig = read_signature_file(temp_log_file)
        assert read_sig == sig

    def test_read_missing_signature_returns_none(self, tmp_path):
        result = read_signature_file(tmp_path / "no_sig.log")
        assert result is None


class TestLogRotation:

    def test_rotate_creates_gz_file(self, temp_log_file, tmp_path, monkeypatch):
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)

        gz_path = rotate_log_file(temp_log_file)

        assert gz_path is not None
        assert gz_path.suffix == ".gz"
        assert gz_path.exists()

    def test_rotate_creates_hmac_file(self, temp_log_file, tmp_path, monkeypatch):
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)

        gz_path = rotate_log_file(temp_log_file)

        assert gz_path is not None
        hmac_path = gz_path.with_suffix(gz_path.suffix + ".hmac")
        assert hmac_path.exists()

    def test_rotate_empties_source_file(self, temp_log_file, tmp_path, monkeypatch):
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)

        rotate_log_file(temp_log_file)

        assert temp_log_file.stat().st_size == 0

    def test_rotate_gz_content_is_valid(self, temp_log_file, tmp_path, monkeypatch):
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)
        original = temp_log_file.read_bytes()

        gz_path = rotate_log_file(temp_log_file)

        assert gz_path is not None
        with gzip.open(gz_path, "rb") as f:
            content = f.read()
        assert content == original

    def test_rotate_skips_empty_file(self, tmp_path):
        empty_file = tmp_path / "empty.log"
        empty_file.write_bytes(b"")

        result = rotate_log_file(empty_file)

        assert result is None

    def test_rotated_gz_signature_is_valid(self, temp_log_file, tmp_path, monkeypatch):
        import src.collectors.integrity as integrity_module
        monkeypatch.setattr(integrity_module, "LOG_BASE_DIR", tmp_path)

        gz_path = rotate_log_file(temp_log_file)

        assert gz_path is not None
        stored_sig = read_signature_file(gz_path)
        assert stored_sig is not None
        assert verify_hmac(gz_path, stored_sig) is True
