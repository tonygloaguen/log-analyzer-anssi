#!/usr/bin/env python3
"""
Inventaire des contrôles de sécurité présents dans le repo — log-analyzer-anssi.

Lit la matrice de contrôles NIS2 et vérifie que les fichiers de preuve existent.
Produit un rapport JSON ou texte des contrôles avec leur statut vérifié.

Contrôle NIS2 : NIS2-CI-01 (auditabilité du dépôt)

Usage :
    python scripts/compliance/inventory_controls.py
    python scripts/compliance/inventory_controls.py --json
    python scripts/compliance/inventory_controls.py --filter covered
    python scripts/compliance/inventory_controls.py --filter missing
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
MATRIX_FILE = REPO_ROOT / "docs" / "nis2" / "nis2-control-matrix.csv"


def check_evidence_files(evidence_str: str) -> tuple[list[str], list[str]]:
    """
    Vérifie que les fichiers de preuve listés existent dans le repo.
    Retourne (fichiers_trouvés, fichiers_manquants).
    """
    if not evidence_str.strip():
        return [], []

    found = []
    missing = []

    for file_ref in evidence_str.split():
        # Séparer le fichier du numéro de ligne éventuel (ex: src/foo.py:42)
        file_path_str = file_ref.split(":")[0]
        full_path = REPO_ROOT / file_path_str

        if full_path.exists():
            found.append(file_ref)
        else:
            missing.append(file_ref)

    return found, missing


def load_control_matrix() -> list[dict[str, str]]:
    """Charge la matrice de contrôles depuis le CSV."""
    if not MATRIX_FILE.exists():
        print(f"ERREUR: Matrice de contrôles introuvable: {MATRIX_FILE}", file=sys.stderr)
        sys.exit(1)

    controls = []
    with open(MATRIX_FILE, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            controls.append(row)

    return controls


def build_inventory(controls: list[dict[str, str]]) -> list[dict]:
    """Construit l'inventaire avec vérification des fichiers de preuve."""
    inventory = []

    for ctrl in controls:
        evidence_files = ctrl.get("evidence_files", "")
        code_refs = ctrl.get("code_refs", "")
        all_evidence = f"{evidence_files} {code_refs}".strip()

        found, missing = check_evidence_files(all_evidence)

        entry = {
            "control_id": ctrl["control_id"],
            "domaine": ctrl["domaine"],
            "objectif": ctrl["objectif"],
            "repo_status": ctrl["repo_status"],
            "priority": ctrl["priority"],
            "evidence_declared": found + missing,
            "evidence_verified": found,
            "evidence_missing": missing,
            "evidence_complete": len(missing) == 0 and len(found) > 0,
            "notes": ctrl.get("notes", ""),
        }
        inventory.append(entry)

    return inventory


def print_summary(inventory: list[dict]) -> None:
    """Affiche un résumé de l'inventaire."""
    total = len(inventory)
    covered = sum(1 for c in inventory if c["repo_status"] == "covered")
    partial = sum(1 for c in inventory if c["repo_status"] == "partial")
    missing = sum(1 for c in inventory if c["repo_status"] == "missing")
    evidence_ok = sum(1 for c in inventory if c["evidence_complete"])
    evidence_broken = sum(
        1 for c in inventory
        if c["evidence_declared"] and not c["evidence_complete"]
    )

    print("=" * 70)
    print("INVENTAIRE DES CONTRÔLES NIS2 — log-analyzer-anssi")
    print("=" * 70)
    print()

    # Par domaine
    domains: dict[str, list[dict]] = {}
    for ctrl in inventory:
        d = ctrl["domaine"]
        domains.setdefault(d, []).append(ctrl)

    for domain, ctrls in sorted(domains.items()):
        print(f"── {domain} ──")
        for ctrl in ctrls:
            status_icon = {"covered": "✓", "partial": "◑", "missing": "✗"}.get(
                ctrl["repo_status"], "?"
            )
            evidence_icon = "📎" if ctrl["evidence_complete"] else ("⚠" if ctrl["evidence_missing"] else "")
            print(
                f"  {status_icon} {ctrl['control_id']:<20} {ctrl['repo_status']:<8} "
                f"[{ctrl['priority']}] {evidence_icon}"
            )
            if ctrl["evidence_missing"]:
                for f in ctrl["evidence_missing"]:
                    print(f"      ⚠ Fichier de preuve introuvable: {f}")
        print()

    print("-" * 70)
    print(f"Total contrôles     : {total}")
    print(f"  Couverts (covered) : {covered} ({covered*100//total if total else 0}%)")
    print(f"  Partiels (partial) : {partial} ({partial*100//total if total else 0}%)")
    print(f"  Manquants (missing): {missing} ({missing*100//total if total else 0}%)")
    print()
    print(f"Preuves vérifiées   : {evidence_ok}/{total}")
    if evidence_broken > 0:
        print(f"Preuves brisées     : {evidence_broken} (fichiers référencés mais absents)")
    print()

    p1_missing = [c for c in inventory if c["priority"] == "P1" and c["repo_status"] == "missing"]
    if p1_missing:
        print(f"ALERTES P1 ({len(p1_missing)} contrôles manquants critiques) :")
        for ctrl in p1_missing:
            print(f"  → {ctrl['control_id']}: {ctrl['objectif']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inventaire des contrôles de sécurité NIS2 du dépôt"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sortie au format JSON",
    )
    parser.add_argument(
        "--filter",
        choices=["covered", "partial", "missing"],
        help="Filtrer par statut",
    )
    args = parser.parse_args()

    controls = load_control_matrix()
    inventory = build_inventory(controls)

    if args.filter:
        inventory = [c for c in inventory if c["repo_status"] == args.filter]

    if args.json:
        summary = {
            "total": len(controls),
            "covered": sum(1 for c in inventory if c["repo_status"] == "covered"),
            "partial": sum(1 for c in inventory if c["repo_status"] == "partial"),
            "missing": sum(1 for c in inventory if c["repo_status"] == "missing"),
        }
        print(json.dumps({"summary": summary, "controls": inventory}, indent=2, ensure_ascii=False))
        return

    print_summary(inventory)


if __name__ == "__main__":
    main()
