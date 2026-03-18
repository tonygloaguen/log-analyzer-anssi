#!/usr/bin/env python3
"""
Validation de la configuration locale — log-analyzer-anssi.

Vérifie que l'environnement local est correctement configuré pour :
- La sécurité (secrets, TLS, rétention)
- La conformité ANSSI (partition dédiée, NTP, séparation des rôles)
- Le développement (tests, linter, dépendances)

Usage :
    python scripts/compliance/validate_local_config.py
    python scripts/compliance/validate_local_config.py --strict
    python scripts/compliance/validate_local_config.py --json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).parent.parent.parent


def check(name: str, ok: bool, detail: str = "", critical: bool = True) -> dict[str, Any]:
    return {
        "name": name,
        "status": "PASS" if ok else ("FAIL" if critical else "WARN"),
        "detail": detail,
        "critical": critical,
    }


def run_checks(strict: bool = False) -> list[dict[str, Any]]:
    results = []

    # ── Fichiers obligatoires ────────────────────────────────────────────────
    results.append(check(
        ".env.example présent",
        (REPO_ROOT / ".env.example").exists(),
        "Fichier de référence des variables d'environnement",
    ))

    results.append(check(
        "docker-compose.yml présent",
        (REPO_ROOT / "docker-compose.yml").exists(),
        "Orchestration Docker",
    ))

    results.append(check(
        "scripts/gen_certs.sh présent",
        (REPO_ROOT / "scripts" / "gen_certs.sh").exists(),
        "Script de génération des certificats TLS",
    ))

    results.append(check(
        "docs/nis2/ présente",
        (REPO_ROOT / "docs" / "nis2").is_dir(),
        "Documentation NIS2 obligatoire",
        critical=False,
    ))

    results.append(check(
        "nis2-control-matrix.csv présente",
        (REPO_ROOT / "docs" / "nis2" / "nis2-control-matrix.csv").exists(),
        "Matrice de contrôles NIS2",
        critical=False,
    ))

    # ── Variables d'environnement ────────────────────────────────────────────
    hmac_key = os.environ.get("HMAC_SECRET_KEY", "")
    results.append(check(
        "HMAC_SECRET_KEY définie",
        bool(hmac_key),
        "Variable obligatoire pour l'intégrité des logs",
    ))

    if hmac_key:
        results.append(check(
            "HMAC_SECRET_KEY longueur >= 32",
            len(hmac_key) >= 32,
            f"Longueur actuelle : {len(hmac_key)} (minimum 32)",
        ))

    retention = os.environ.get("LOG_RETENTION_DAYS", "90")
    try:
        retention_int = int(retention)
        results.append(check(
            "LOG_RETENTION_DAYS >= 90",
            retention_int >= 90,
            f"Valeur actuelle : {retention_int}j (ANSSI recommande 365j en prod)",
            critical=False,
        ))
        if strict:
            results.append(check(
                "LOG_RETENTION_DAYS >= 365 (mode strict)",
                retention_int >= 365,
                f"Valeur actuelle : {retention_int}j — ANSSI min. 1 an en production",
                critical=True,
            ))
    except ValueError:
        results.append(check(
            "LOG_RETENTION_DAYS valeur numérique",
            False,
            f"Valeur non numérique: {retention}",
        ))

    # ── Outils de développement ──────────────────────────────────────────────
    results.append(check(
        "Docker disponible",
        shutil.which("docker") is not None,
        "Docker requis pour l'environnement complet",
        critical=False,
    ))

    results.append(check(
        "Python 3.11+ disponible",
        sys.version_info >= (3, 11),
        f"Version actuelle : {sys.version_info.major}.{sys.version_info.minor}",
    ))

    results.append(check(
        "openssl disponible",
        shutil.which("openssl") is not None,
        "Requis pour la génération des certificats TLS",
        critical=False,
    ))

    # ── Fichiers de sécurité ─────────────────────────────────────────────────
    env_local = REPO_ROOT / ".env.local"
    results.append(check(
        ".env.local non commité (gitignore)",
        _check_gitignored(env_local),
        ".env.local ne doit pas être dans git",
        critical=False,
    ))

    certs_dir = REPO_ROOT / "certs"
    if certs_dir.exists():
        key_files = list(certs_dir.glob("*.key"))
        if key_files:
            all_restricted = all(
                oct(f.stat().st_mode)[-3:] in ("600", "400")
                for f in key_files
            )
            results.append(check(
                "Permissions clés TLS restrictives (600)",
                all_restricted,
                f"Clés trouvées : {[f.name for f in key_files]}",
            ))

    # ── Tests ────────────────────────────────────────────────────────────────
    pytest_ini = REPO_ROOT / "pytest.ini"
    if pytest_ini.exists():
        content = pytest_ini.read_text()
        results.append(check(
            "pytest --cov-fail-under configuré",
            "cov-fail-under" in content,
            "Seuil de couverture minimum imposé",
            critical=False,
        ))

    results.append(check(
        ".github/workflows/ci.yml présent",
        (REPO_ROOT / ".github" / "workflows" / "ci.yml").exists(),
        "Pipeline CI/CD DevSecOps",
        critical=False,
    ))

    return results


def _check_gitignored(path: Path) -> bool:
    """Vérifie qu'un fichier est bien gitignorié."""
    if not path.exists():
        return True  # Fichier absent = pas de risque
    try:
        result = subprocess.run(
            ["git", "check-ignore", "-q", str(path)],
            cwd=REPO_ROOT,
            capture_output=True,
        )
        return result.returncode == 0
    except Exception:
        return True  # En cas d'erreur git, on ne bloque pas


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validation de la configuration locale log-analyzer-anssi"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Mode strict : appliquer les critères de production (LOG_RETENTION_DAYS >= 365)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sortie au format JSON",
    )
    args = parser.parse_args()

    results = run_checks(strict=args.strict)

    failures = [r for r in results if r["status"] == "FAIL"]
    warnings = [r for r in results if r["status"] == "WARN"]
    passes = [r for r in results if r["status"] == "PASS"]

    if args.json:
        print(json.dumps({
            "results": results,
            "summary": {
                "total": len(results),
                "pass": len(passes),
                "fail": len(failures),
                "warn": len(warnings),
                "status": "FAIL" if failures else "PASS",
            }
        }, indent=2, ensure_ascii=False))
        sys.exit(1 if failures else 0)

    print("=" * 70)
    print("VALIDATION CONFIGURATION LOCALE — log-analyzer-anssi")
    if args.strict:
        print("Mode : STRICT (critères production)")
    print("=" * 70)
    print()

    for r in results:
        icon = {"PASS": "✓", "FAIL": "✗", "WARN": "⚠"}.get(r["status"], "?")
        print(f"  {icon} [{r['status']:<4}] {r['name']}")
        if r["detail"] and r["status"] != "PASS":
            print(f"          {r['detail']}")

    print()
    print("-" * 70)
    print(f"Résultat : {len(passes)} OK, {len(failures)} erreur(s), {len(warnings)} avertissement(s)")

    if failures:
        print("\nERREURS À CORRIGER :")
        for r in failures:
            print(f"  → {r['name']}: {r['detail']}")
        print("\nSTATUT : FAIL ✗")
        sys.exit(1)
    else:
        print("\nSTATUT : PASS ✓")


if __name__ == "__main__":
    main()
