"""
Tests de validation de configuration au démarrage — log-analyzer-anssi.

Vérifie que l'API FastAPI refuse de démarrer sans les variables obligatoires,
et que les variables invalides sont correctement rejetées.

Contrôle NIS2 : NIS2-SEC-01 (validation configuration au boot)
"""
from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient


class TestStartupConfigValidation:
    """Tests de validation des variables d'environnement au démarrage."""

    def test_missing_hmac_key_raises_on_startup(self, monkeypatch):
        """L'API doit refuser de démarrer si HMAC_SECRET_KEY est absent."""
        monkeypatch.delenv("HMAC_SECRET_KEY", raising=False)
        monkeypatch.setenv("POSTGRES_DSN", "postgresql+asyncpg://test:test@localhost/test")
        monkeypatch.setenv("LOKI_URL", "http://loki-test:3100")

        # Réimporter l'app pour déclencher le cycle de vie
        from importlib import reload
        import src.api.main as main_module
        reload(main_module)

        with pytest.raises(Exception):
            with TestClient(main_module.app, raise_server_exceptions=True):
                pass

    def test_missing_postgres_dsn_raises_on_startup(self, monkeypatch):
        """L'API doit refuser de démarrer si POSTGRES_DSN est absent."""
        monkeypatch.setenv("HMAC_SECRET_KEY", "a-valid-hmac-key-that-is-long-enough-32c")
        monkeypatch.delenv("POSTGRES_DSN", raising=False)
        monkeypatch.setenv("LOKI_URL", "http://loki-test:3100")

        from importlib import reload
        import src.api.main as main_module
        reload(main_module)

        with pytest.raises(Exception):
            with TestClient(main_module.app, raise_server_exceptions=True):
                pass

    def test_missing_loki_url_raises_on_startup(self, monkeypatch):
        """L'API doit refuser de démarrer si LOKI_URL est absent."""
        monkeypatch.setenv("HMAC_SECRET_KEY", "a-valid-hmac-key-that-is-long-enough-32c")
        monkeypatch.setenv("POSTGRES_DSN", "postgresql+asyncpg://test:test@localhost/test")
        monkeypatch.delenv("LOKI_URL", raising=False)

        from importlib import reload
        import src.api.main as main_module
        reload(main_module)

        with pytest.raises(Exception):
            with TestClient(main_module.app, raise_server_exceptions=True):
                pass

    def test_short_hmac_key_raises_on_startup(self, monkeypatch):
        """L'API doit refuser une clé HMAC trop courte (< 32 caractères)."""
        monkeypatch.setenv("HMAC_SECRET_KEY", "too-short")
        monkeypatch.setenv("POSTGRES_DSN", "postgresql+asyncpg://test:test@localhost/test")
        monkeypatch.setenv("LOKI_URL", "http://loki-test:3100")

        from importlib import reload
        import src.api.main as main_module
        reload(main_module)

        with pytest.raises(Exception):
            with TestClient(main_module.app, raise_server_exceptions=True):
                pass

    def test_valid_config_starts_successfully(self, monkeypatch):
        """L'API doit démarrer normalement avec une configuration valide."""
        monkeypatch.setenv("HMAC_SECRET_KEY", "a-valid-hmac-key-that-is-long-enough-32c")
        monkeypatch.setenv("POSTGRES_DSN", "postgresql+asyncpg://test:test@localhost/test")
        monkeypatch.setenv("LOKI_URL", "http://loki-test:3100")
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://ollama-test:11434")

        from importlib import reload
        import src.api.main as main_module
        reload(main_module)

        # Ne doit pas lever d'exception
        with TestClient(main_module.app, raise_server_exceptions=False) as client:
            response = client.get("/health")
            assert response.status_code == 200


class TestEnvExample:
    """Tests de complétude du fichier .env.example."""

    def test_env_example_exists(self):
        """Le fichier .env.example doit exister (NIS2-SEC-04)."""
        repo_root = os.path.join(os.path.dirname(__file__), "..", "..")
        env_example = os.path.join(repo_root, ".env.example")
        assert os.path.exists(env_example), ".env.example manquant — contrôle NIS2-SEC-04"

    def test_env_example_contains_required_vars(self):
        """Le .env.example doit documenter toutes les variables obligatoires."""
        repo_root = os.path.join(os.path.dirname(__file__), "..", "..")
        env_example = os.path.join(repo_root, ".env.example")

        if not os.path.exists(env_example):
            pytest.skip(".env.example absent")

        content = open(env_example, encoding="utf-8").read()

        required_vars = [
            "HMAC_SECRET_KEY",
            "POSTGRES_PASSWORD",
            "LOG_RETENTION_DAYS",
            "OLLAMA_BASE_URL",
            "LOKI_URL",
            "ANOMALY_THRESHOLD",
            "GRAFANA_PASSWORD",
        ]

        for var in required_vars:
            assert var in content, f"Variable {var} absente de .env.example"

    def test_env_example_mentions_anssi_retention(self):
        """Le .env.example doit mentionner la recommandation ANSSI sur la rétention."""
        repo_root = os.path.join(os.path.dirname(__file__), "..", "..")
        env_example = os.path.join(repo_root, ".env.example")

        if not os.path.exists(env_example):
            pytest.skip(".env.example absent")

        content = open(env_example, encoding="utf-8").read()
        # La recommandation ANSSI (1 an = 365j) doit être documentée
        assert "365" in content, (
            "La recommandation ANSSI de 365j de rétention doit être documentée dans .env.example"
        )


class TestCheckEnvVarsScript:
    """Tests du script check_env_vars.py."""

    def test_script_exists(self):
        """Le script de vérification des variables doit exister."""
        repo_root = os.path.join(os.path.dirname(__file__), "..", "..")
        script = os.path.join(repo_root, "scripts", "compliance", "check_env_vars.py")
        assert os.path.exists(script), "scripts/compliance/check_env_vars.py manquant"

    def test_script_accepts_env_example(self, tmp_path):
        """Le script doit accepter le .env.example sans erreur."""
        import subprocess
        repo_root = os.path.join(os.path.dirname(__file__), "..", "..")
        script = os.path.join(repo_root, "scripts", "compliance", "check_env_vars.py")
        env_example = os.path.join(repo_root, ".env.example")

        if not os.path.exists(env_example):
            pytest.skip(".env.example absent")

        result = subprocess.run(
            ["python3", script, "--env-file", env_example, "--check-example"],
            capture_output=True,
            text=True,
            cwd=repo_root,
        )
        # En mode --check-example, le script ne doit pas échouer sur des valeurs "changeme"
        assert result.returncode == 0, f"Script a échoué: {result.stdout}\n{result.stderr}"
