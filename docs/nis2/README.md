# NIS2 / ANSSI — Documentation de conformité

## Positionnement du projet

`log-analyzer-anssi` est un **démonstrateur technique** d'un système de journalisation
de sécurité conçu en cohérence avec :

- La **Directive NIS2** (UE 2022/2555) — applicable depuis octobre 2024
- Le **Guide ANSSI** « Recommandations de sécurité pour l'architecture d'un système
  de journalisation » (2022)

> **Avertissement important**
> Ce projet est un démonstrateur à vocation pédagogique et portfolio. Il ne constitue
> pas un produit certifié, ni une implémentation complète de la directive NIS2.
> Aucun contrôle ne doit être déclaré "conforme NIS2" sans preuve dans le code,
> la configuration, les tests ou la documentation de ce dépôt.

---

## Hypothèses structurantes

| Hypothèse | Valeur retenue |
|---|---|
| Type d'entité | Entité importante (NIS2 Art. 3) — démonstrateur |
| Périmètre système | Système de journalisation et détection d'anomalies |
| Environnement cible | Déploiement on-premise, 100% local, sans cloud obligatoire |
| Niveau de maturité visé | Niveau 2 — défense active (ANSSI PRIS) |
| Statut LLM | Local uniquement (Ollama/Mistral 7B) — aucune donnée externe |

---

## Périmètre couvert par ce dépôt

### Ce qui est démontré techniquement

| Domaine NIS2 | Mécanisme implémenté | Fichier(s) de preuve |
|---|---|---|
| Journalisation | Pipeline LangGraph + structlog JSON | `src/langgraph_pipeline/nodes.py`, `src/api/main.py` |
| Intégrité des logs | HMAC-SHA256 sur archives gzip | `src/collectors/integrity.py` |
| Transport chiffré | mTLS Fluent Bit → Loki | `config/fluent-bit.conf`, `scripts/gen_certs.sh` |
| Détection d'anomalies | 7 patterns IOC + score de risque | `src/langgraph_pipeline/nodes.py:27-77` |
| Escalade incidents | Routage conditionnel auto/humain | `src/langgraph_pipeline/conditions.py` |
| Traçabilité | `audit_trail` PostgreSQL + `audit_events` pipeline | `scripts/init_db.sql:61-73` |
| Séparation des rôles | Réseaux Docker isolés (collect/analyze/storage) | `docker-compose.yml:17-30` |
| Synchronisation temporelle | Service NTP dédié | `docker-compose.yml:48-62` |
| Rétention configurable | `LOG_RETENTION_DAYS` (défaut 90j) | `src/collectors/integrity.py:151-196` |
| Secrets obligatoires | Validation au démarrage FastAPI | `src/api/main.py:55-59` |
| Container non-root | `appuser` dans Dockerfile | `Dockerfile:32-35` |

### Ce qui est partiellement couvert

| Domaine NIS2 | Lacune identifiée | Priorité |
|---|---|---|
| Supply chain | Pas de SBOM, scan images Trivy absent, images non pinnées par digest | P1 |
| CI/CD DevSecOps | Pipeline GitHub Actions présent mais sans scan SAST/DAST | P1 |
| Backup / continuité | Pas de script de sauvegarde PostgreSQL | P2 |
| Gestion des vulnérabilités | `pip-audit` configuré mais non automatisé en CI | P2 |
| Contrôle d'accès API | Authentification API absente (JWT non implémenté) | P2 |
| Notification incidents | Webhook/email pour escalades non implémenté | P3 |

### Ce qui est hors périmètre (à cadrer / valider)

| Domaine NIS2 | Statut |
|---|---|
| Gouvernance formelle (RACI, comité sécurité) | Non démontrable dans ce dépôt |
| Gestion des risques (registre EBIOS RM) | Non démontrable dans ce dépôt |
| Plan de continuité d'activité (PCA/PRA) | Non démontrable dans ce dépôt |
| Tests d'intrusion | Non applicable dans ce contexte |
| Déclaration d'incident ANSSI (72h) | Processus organisationnel — hors code |
| Certification ISO 27001 | Non applicable — démonstrateur |

---

## Utilisation de cette documentation

```
docs/nis2/
├── README.md                      ← Ce fichier — vue d'ensemble et hypothèses
├── nis2-gap-analysis.md           ← Analyse structurée des écarts par thème
├── nis2-implementation-plan.md    ← Plan en 5 phases avec critères d'acceptation
└── nis2-control-matrix.csv        ← Matrice des contrôles (covered/partial/missing)
```

### Pour un audit / démonstration

1. Lire ce README pour comprendre le positionnement et les hypothèses
2. Consulter `nis2-control-matrix.csv` pour la vue synthétique des contrôles
3. Consulter `nis2-gap-analysis.md` pour l'analyse détaillée des écarts
4. Utiliser `scripts/compliance/` pour collecter les preuves automatiquement

### Pour contribuer

Voir les règles dans `CLAUDE.md` section "Règles de contribution NIS2/DevSecOps".
Toute mesure déclarée "NIS2" doit pointer vers : **code + config + test + doc**.

---

## Références normatives

| Référence | Titre |
|---|---|
| UE 2022/2555 | Directive NIS2 |
| ANSSI — 2022 | Guide de recommandations de sécurité pour l'architecture d'un système de journalisation |
| ANSSI — PRIS | Prestataires de Réponse aux Incidents de Sécurité |
| CIS Controls v8 | Center for Internet Security — Controls |
| ISO/IEC 27001:2022 | Systèmes de management de la sécurité de l'information |
