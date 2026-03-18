#!/usr/bin/env python3
"""
Vérification des variables d'environnement critiques — log-analyzer-anssi.

Contrôle NIS2 : NIS2-SEC-01, NIS2-SEC-02, NIS2-SEC-03, NIS2-SEC-04

Usage :
    python scripts/compliance/check_env_vars.py
    python scripts/compliance/check_env_vars.py --env-file .env.local
    python scripts/compliance/check_env_vars.py --env-file .env.example --check-example
    python scripts/compliance/check_env_vars.py --json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Définition des variables à vérifier
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_VARS: list[dict[str, Any]] = [
    {
        "name": "HMAC_SECRET_KEY",
        "description": "Clé HMAC pour la signature des archives de logs",
        "required": True,
        "min_length": 32,
        "forbidden_values": ["changeme", "secret", "password", "test"],
        "nis2_control": "NIS2-SEC-03",
    },
    {
        "name": "POSTGRES_PASSWORD",
        "description": "Mot de passe PostgreSQL",
        "required": True,
        "min_length": 12,
        "forbidden_values": ["changeme", "password", "postgres", "admin"],
        "nis2_control": "NIS2-SEC-02",
    },
    {
        "name": "GRAFANA_PASSWORD",
        "description": "Mot de passe administrateur Grafana",
        "required": True,
        "min_length": 8,
        "forbidden_values": ["admin", "grafana", "password", "changeme"],
        "nis2_control": "NIS2-SEC-01",
    },
]

OPTIONAL_VARS: list[dict[str, Any]] = [
    {
        "name": "LOG_RETENTION_DAYS",
        "description": "Rétention des logs (ANSSI : 365j minimum en production)",
        "required": False,
        "recommended_min": 365,
        "nis2_control": "NIS2-LOG-04",
    },
    {
        "name": "ANOMALY_THRESHOLD",
        "description": "Seuil de score pour escalade humaine [0.0–1.0]",
        "required": False,
        "nis2_control": "NIS2-DET-04",
    },
    {
        "name": "LOKI_URL",
        "description": "URL du service Loki",
        "required": False,
        "nis2_control": "NIS2-LOG-01",
    },
    {
        "name": "OLLAMA_BASE_URL",
        "description": "URL du service Ollama (LLM local)",
        "required": False,
        "nis2_control": "NIS2-DET-03",
    },
    {
        "name": "ALERT_WEBHOOK_URL",
        "description": "Webhook de notification pour les escalades",
        "required": False,
        "nis2_control": "NIS2-INC-02",
    },
]


def load_env_file(env_file: Path) -> dict[str, str]:
    """Charge un fichier .env et retourne un dictionnaire."""
    env_vars: dict[str, str] = {}
    if not env_file.exists():
        return env_vars

    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            # Enlever les commentaires inline et les guillemets
            value = value.split("#")[0].strip().strip('"').strip("'")
            env_vars[key.strip()] = value

    return env_vars


def check_var(
    var_def: dict[str, Any],
    env_vars: dict[str, str],
    check_example: bool = False,
) -> dict[str, Any]:
    """Vérifie une variable et retourne le résultat."""
    name = var_def["name"]
    value = env_vars.get(name) or os.environ.get(name, "")

    result: dict[str, Any] = {
        "name": name,
        "description": var_def["description"],
        "nis2_control": var_def.get("nis2_control", ""),
        "present": bool(value),
        "warnings": [],
        "errors": [],
    }

    if not value:
        if var_def.get("required"):
            result["errors"].append(f"Variable obligatoire manquante")
        return result

    # En mode --check-example, on ne valide pas les valeurs "changeme"
    if check_example:
        result["status"] = "example_ok"
        return result

    # Vérification longueur minimale
    min_len = var_def.get("min_length", 0)
    if min_len and len(value) < min_len:
        result["errors"].append(
            f"Trop courte: {len(value)} caractères (minimum {min_len})"
        )

    # Vérification des valeurs interdites
    for forbidden in var_def.get("forbidden_values", []):
        if forbidden.lower() in value.lower():
            result["errors"].append(
                f"Valeur non sécurisée détectée (contient '{forbidden}')"
            )

    # Vérification valeur numérique recommandée
    recommended_min = var_def.get("recommended_min")
    if recommended_min and value.isdigit():
        if int(value) < recommended_min:
            result["warnings"].append(
                f"Valeur {value} inférieure au minimum recommandé ({recommended_min})"
                f" — ANSSI recommande {recommended_min}+ en production"
            )

    return result


def run_checks(
    env_file: Path | None = None,
    check_example: bool = False,
    output_json: bool = False,
) -> int:
    """Exécute tous les contrôles et affiche le résultat."""
    env_vars: dict[str, str] = {}

    if env_file:
        env_vars = load_env_file(env_file)
        if not env_file.exists():
            print(f"ERREUR: Fichier {env_file} introuvable", file=sys.stderr)
            return 1

    all_results: list[dict[str, Any]] = []
    errors_count = 0
    warnings_count = 0

    for var_def in REQUIRED_VARS + OPTIONAL_VARS:
        result = check_var(var_def, env_vars, check_example=check_example)
        all_results.append(result)
        errors_count += len(result["errors"])
        warnings_count += len(result["warnings"])

    if output_json:
        print(json.dumps({
            "results": all_results,
            "summary": {
                "total": len(all_results),
                "errors": errors_count,
                "warnings": warnings_count,
                "status": "FAIL" if errors_count > 0 else "PASS",
            }
        }, indent=2, ensure_ascii=False))
        return 1 if errors_count > 0 else 0

    # Affichage texte
    print("=" * 70)
    print("VÉRIFICATION DES VARIABLES D'ENVIRONNEMENT — log-analyzer-anssi")
    print("=" * 70)

    if env_file:
        print(f"Fichier : {env_file}")
    else:
        print("Source : variables d'environnement système")

    print()

    for result in all_results:
        if result["errors"]:
            status = "✗ ERREUR"
        elif result["warnings"]:
            status = "⚠ WARNING"
        elif result["present"]:
            status = "✓ OK"
        else:
            status = "- ABSENT (optionnel)"

        print(f"{status:<15} {result['name']:<30} [{result['nis2_control']}]")

        for err in result["errors"]:
            print(f"              → ERREUR: {err}")
        for warn in result["warnings"]:
            print(f"              → WARNING: {warn}")

    print()
    print("-" * 70)
    print(f"Résultat : {errors_count} erreur(s), {warnings_count} avertissement(s)")

    if errors_count == 0:
        print("STATUT : PASS ✓")
    else:
        print("STATUT : FAIL ✗")

    return 1 if errors_count > 0 else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Vérification des variables d'environnement critiques"
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Chemin vers le fichier .env à vérifier (ex: .env.local)",
    )
    parser.add_argument(
        "--check-example",
        action="store_true",
        help="Mode vérification du .env.example (ne valide pas les valeurs)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sortie au format JSON",
    )
    args = parser.parse_args()

    exit_code = run_checks(
        env_file=args.env_file,
        check_example=args.check_example,
        output_json=args.json,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
