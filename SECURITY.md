# Politique de sécurité — log-analyzer-anssi

## Versions supportées

Ce projet est un **démonstrateur technique** (non un produit en production certifié).
Seule la branche `main` / branche de développement active est maintenue.

| Branche | Maintenue |
|---|---|
| `main` | Oui |
| Autres branches | Non |

---

## Signaler une vulnérabilité

### Canal de signalement

Ouvrir une **issue GitHub privée** (Security Advisory) :
`Dépôt GitHub → Security → Report a vulnerability`

> Ne pas ouvrir une issue publique pour une vulnérabilité non divulguée.

### Informations à inclure

1. Description de la vulnérabilité (type, composant affecté)
2. Étapes pour reproduire le problème
3. Impact estimé (confidentialité, intégrité, disponibilité)
4. Version ou commit concerné
5. Preuve de concept si disponible (optionnel)

### Délai de traitement

| Étape | Délai |
|---|---|
| Accusé de réception | 48h |
| Évaluation initiale (CVSS estimé) | 7 jours |
| Correctif ou plan d'action | 30 jours (critique : 15 jours) |
| Publication du correctif | Après validation |

---

## Périmètre de sécurité

### Dans le périmètre

- Pipeline d'analyse LangGraph (`src/langgraph_pipeline/`)
- API FastAPI (`src/api/`)
- Mécanisme d'intégrité HMAC (`src/collectors/integrity.py`)
- Configuration Docker Compose et Fluent Bit
- Scripts de conformité (`scripts/compliance/`)

### Hors périmètre

- Services tiers (Ollama, Loki, Grafana, PostgreSQL) — reporter directement aux mainteneurs
- Vulnérabilités requérant un accès physique au serveur
- Attaques par déni de service (DoS) volumétrique
- Issues de sécurité dans les dépendances Python — utiliser `pip-audit` et reporter en amont

---

## Mesures de sécurité en place

Voir [`docs/nis2/nis2-control-matrix.csv`](docs/nis2/nis2-control-matrix.csv) pour
la liste complète des contrôles implémentés.

Mesures principales :

- **Intégrité des logs** : HMAC-SHA256 sur chaque archive (`src/collectors/integrity.py`)
- **Transport chiffré** : mTLS Fluent Bit → Loki (`config/fluent-bit.conf`)
- **Secrets obligatoires** : variables vérifiées au démarrage (`src/api/main.py`)
- **Pas de LLM cloud** : Ollama local uniquement — aucune donnée externe
- **Audit trail** : chaque action tracée en base PostgreSQL

---

## Divulgation responsable

Ce projet suit le principe de **divulgation coordonnée** :

1. Le signalement est reçu et accusé de réception dans les 48h
2. La vulnérabilité est évaluée et un correctif est développé
3. Le correctif est publié avec les notes de version
4. La vulnérabilité est divulguée publiquement 90 jours après le signalement
   (ou plus tôt si le correctif est disponible)

---

*Contrôle NIS2 : NIS2-SC-03 — Politique de divulgation des vulnérabilités*
