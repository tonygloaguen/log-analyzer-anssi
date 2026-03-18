#!/usr/bin/env python3
"""
Générateur de rapport de couverture NIS2 — log-analyzer-anssi.

Produit un rapport Markdown lisible depuis la matrice de contrôles.
Utilisable pour la démonstration, l'audit et le portefeuille VAE.

Usage :
    python scripts/compliance/generate_nis2_coverage_report.py
    python scripts/compliance/generate_nis2_coverage_report.py --output docs/nis2/coverage-report.md
    python scripts/compliance/generate_nis2_coverage_report.py --json
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
MATRIX_FILE = REPO_ROOT / "docs" / "nis2" / "nis2-control-matrix.csv"

NIS2_THEMES = {
    "Journalisation": "Journalisation / détection / traçabilité",
    "Détection": "Détection d'anomalies",
    "Incidents": "Gestion des incidents",
    "Transport": "Sécurité des transports (TLS)",
    "Secrets": "Contrôle d'accès et gestion des secrets",
    "Réseau": "Séparation réseau",
    "Containers": "Sécurité des conteneurs",
    "Temps": "Synchronisation temporelle",
    "Base de données": "Sécurité de la base de données",
    "Supply chain": "Sécurité de la chaîne d'approvisionnement",
    "CI/CD": "Pipeline DevSecOps",
    "Sauvegarde": "Continuité et sauvegarde",
}

STATUS_LABEL = {
    "covered": "✅ Couvert",
    "partial": "⚠️ Partiel",
    "missing": "❌ Manquant",
}

PRIORITY_LABEL = {
    "P1": "🔴 Critique",
    "P2": "🟡 Important",
    "P3": "🟢 Souhaitable",
}


def load_matrix() -> list[dict[str, str]]:
    if not MATRIX_FILE.exists():
        print(f"ERREUR: {MATRIX_FILE} introuvable", file=sys.stderr)
        sys.exit(1)
    with open(MATRIX_FILE, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def compute_coverage(controls: list[dict[str, str]]) -> dict[str, dict]:
    """Calcule la couverture par domaine."""
    by_domain: dict[str, list[dict[str, str]]] = {}
    for ctrl in controls:
        d = ctrl["domaine"]
        by_domain.setdefault(d, []).append(ctrl)

    coverage: dict[str, dict] = {}
    for domain, ctrls in by_domain.items():
        total = len(ctrls)
        covered = sum(1 for c in ctrls if c["repo_status"] == "covered")
        partial = sum(1 for c in ctrls if c["repo_status"] == "partial")
        missing = sum(1 for c in ctrls if c["repo_status"] == "missing")

        # Score : covered=1, partial=0.5, missing=0
        score = (covered + partial * 0.5) / total if total else 0
        pct = int(score * 100)

        bar_filled = int(score * 10)
        bar = "█" * bar_filled + "░" * (10 - bar_filled)

        coverage[domain] = {
            "total": total,
            "covered": covered,
            "partial": partial,
            "missing": missing,
            "score": score,
            "pct": pct,
            "bar": bar,
            "theme": NIS2_THEMES.get(domain, domain),
        }

    return coverage


def generate_markdown(controls: list[dict[str, str]]) -> str:
    coverage = compute_coverage(controls)
    today = date.today().isoformat()

    total_controls = len(controls)
    total_covered = sum(1 for c in controls if c["repo_status"] == "covered")
    total_partial = sum(1 for c in controls if c["repo_status"] == "partial")
    total_missing = sum(1 for c in controls if c["repo_status"] == "missing")
    global_score = int((total_covered + total_partial * 0.5) / total_controls * 100) if total_controls else 0

    lines = [
        f"# Rapport de couverture NIS2 — log-analyzer-anssi",
        f"",
        f"> Généré le {today}",
        f"> **Note** : démonstrateur technique — aucun contrôle n'est certifié conforme NIS2.",
        f"",
        f"## Résumé global",
        f"",
        f"| Indicateur | Valeur |",
        f"|---|---|",
        f"| Contrôles totaux analysés | {total_controls} |",
        f"| Couverts (covered) | {total_covered} ({total_covered*100//total_controls if total_controls else 0}%) |",
        f"| Partiels (partial) | {total_partial} ({total_partial*100//total_controls if total_controls else 0}%) |",
        f"| Manquants (missing) | {total_missing} ({total_missing*100//total_controls if total_controls else 0}%) |",
        f"| Score global estimé | **{global_score}%** |",
        f"",
        f"## Couverture par domaine",
        f"",
    ]

    for domain, cov in sorted(coverage.items(), key=lambda x: -x[1]["score"]):
        lines.append(
            f"| {cov['theme']:<45} | `{cov['bar']}` | {cov['pct']:>3}% | "
            f"{cov['covered']}/{cov['total']} couverts |"
        )

    # En-tête tableau couverture
    lines.insert(
        lines.index("## Couverture par domaine") + 2,
        "| Domaine NIS2 | Progression | % | Contrôles |",
    )
    lines.insert(
        lines.index("| Domaine NIS2 | Progression | % | Contrôles |") + 1,
        "|---|---|---|---|",
    )

    lines += [
        "",
        "## Contrôles par priorité",
        "",
        "### 🔴 P1 — Critiques (à traiter en priorité)",
        "",
        "| ID | Domaine | Objectif | Statut |",
        "|---|---|---|---|",
    ]

    for ctrl in controls:
        if ctrl["priority"] == "P1":
            status = STATUS_LABEL.get(ctrl["repo_status"], ctrl["repo_status"])
            lines.append(
                f"| `{ctrl['control_id']}` | {ctrl['domaine']} | {ctrl['objectif']} | {status} |"
            )

    lines += [
        "",
        "### 🟡 P2 — Importants",
        "",
        "| ID | Domaine | Objectif | Statut |",
        "|---|---|---|---|",
    ]

    for ctrl in controls:
        if ctrl["priority"] == "P2":
            status = STATUS_LABEL.get(ctrl["repo_status"], ctrl["repo_status"])
            lines.append(
                f"| `{ctrl['control_id']}` | {ctrl['domaine']} | {ctrl['objectif']} | {status} |"
            )

    lines += [
        "",
        "### 🟢 P3 — Souhaitables",
        "",
        "| ID | Domaine | Objectif | Statut |",
        "|---|---|---|---|",
    ]

    for ctrl in controls:
        if ctrl["priority"] == "P3":
            status = STATUS_LABEL.get(ctrl["repo_status"], ctrl["repo_status"])
            lines.append(
                f"| `{ctrl['control_id']}` | {ctrl['domaine']} | {ctrl['objectif']} | {status} |"
            )

    lines += [
        "",
        "## Actions immédiates recommandées (P1 manquants)",
        "",
    ]

    p1_missing = [c for c in controls if c["priority"] == "P1" and c["repo_status"] == "missing"]
    if p1_missing:
        for ctrl in p1_missing:
            lines.append(f"- **{ctrl['control_id']}** — {ctrl['objectif']}: {ctrl['remediation']}")
    else:
        lines.append("✅ Aucun contrôle P1 manquant.")

    lines += [
        "",
        "---",
        f"*Rapport généré par `scripts/compliance/generate_nis2_coverage_report.py`*",
        f"*Matrice source : `docs/nis2/nis2-control-matrix.csv`*",
    ]

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Génère un rapport de couverture NIS2 depuis la matrice de contrôles"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Fichier de sortie Markdown (défaut : stdout)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sortie au format JSON",
    )
    args = parser.parse_args()

    controls = load_matrix()

    if args.json:
        coverage = compute_coverage(controls)
        print(json.dumps(coverage, indent=2, ensure_ascii=False))
        return

    report = generate_markdown(controls)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
        print(f"Rapport généré : {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
