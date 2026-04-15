# log-analyzer-anssi

SIEM léger de détection BYOVD/ransomware pour Raspberry Pi 4 (ARM64).
Conforme ANSSI · NIS2 Art.21 · LLM 100% local (granite3.3:8b via Ollama).

---

## Architecture

```
Sysmon XML / auditd / Zeek conn.log
          │
          ▼
┌─────────────────────────────────────────────────────┐
│  collectors/                                        │
│  ├── BYOVDDetector   ← loldrivers.io (SHA256)       │
│  │   EventID 6 (driver load) + EventID 10 (EDR)     │
│  └── NetworkCollector ← Zeek / tcpdump              │
│      beaconing · Tor · DoH                          │
└──────────────┬──────────────────────────────────────┘
               │  alerts[]
               ▼
┌─────────────────────────────────────────────────────┐
│  nodes/ransomware_behavior_analyst (LangGraph)       │
│  httpx → Ollama granite3.3:8b  (timeout 30s)        │
│  fallback statique si Ollama KO                     │
│  SQLite checkpoint · HMAC-SHA256 signature          │
└──────────────┬──────────────────────────────────────┘
               │  notification_payload
               ▼
┌─────────────────────────────────────────────────────┐
│  notifiers/AlertDispatcher                          │
│  ntfy (push) → email SMTP (fallback)                │
│  rate limit : 1 alerte / 5 min / technique          │
└─────────────────────────────────────────────────────┘
               │
               ▼
         Raspberry Pi 4 — ARM64
         ntfy :8080 · ollama :11434
```

---

## Couverture MITRE ATT&CK

| Technique | ID | Détecteur |
|---|---|---|
| Exploit Public-Facing App / priv-esc | T1068 | BYOVDDetector (EventID 6) |
| Impair Defenses — Disable/Mod Tools | T1562.001 | BYOVDDetector (EventID 10) |
| Command & Scripting Interpreter | T1059 | ransomware_behavior_analyst |
| Data Encrypted for Impact | T1486 | ransomware_behavior_analyst |
| Inhibit System Recovery | T1490 | ransomware_behavior_analyst |
| Lateral Tool Transfer | T1021 | ransomware_behavior_analyst |
| Application Layer Protocol | T1071 | NetworkCollector (beaconing) |
| Proxy — Tor | T1090.003 | NetworkCollector (ports 9001/9030) |
| DNS over HTTPS | T1071.004 | NetworkCollector (DoH suspicion) |

---

## Conformité NIS2 / ANSSI

| Exigence | Implémentation |
|---|---|
| NIS2 Art.21.2.h — intégrité journaux | HMAC-SHA256 sur chaque événement (`core/log_integrity.py`) |
| LLM local uniquement | Ollama sur le RPi — aucune donnée cloud |
| Pas de secret au build | `HMAC_SECRET` obligatoire à runtime, aucun default |
| Signature des alertes | `sign_event()` sur chaque alerte avant dispatch |
| Rétention configurable | `LOG_RETENTION_DAYS` (min 365j ANSSI prod) |
| Isolation réseau | Docker Compose sans exposition de ports internes |
| Mise à jour des IoC | `scripts/update_loldrivers.sh` (cron hebdomadaire) |
| Audit trail | SQLite checkpoint chaque analyse (table `ransomware_analyses`) |

---

## Déploiement Raspberry Pi 4

### Prérequis

- Raspberry Pi 4 (4 Go RAM minimum)
- Raspberry Pi OS 64-bit (Bookworm)
- Docker 24+ et Docker Compose v2 installés
- SSH configuré : `gloaguen@192.168.1.31`

### 1. Swap 4 Go (requis pour granite3.3:8b)

```bash
sudo dphys-swapfile swapoff
sudo sed -i 's/CONF_SWAPSIZE=.*/CONF_SWAPSIZE=4096/' /etc/dphys-swapfile
sudo dphys-swapfile setup && sudo dphys-swapfile swapon
free -h  # vérifier : Swap ~4G
```

### 2. Variables d'environnement

```bash
cp .env.example .env
# Renseigner obligatoirement :
#   HMAC_SECRET   → openssl rand -hex 32
#   NTFY_TOPIC    → nom de topic privé
#   SMTP_*        → si notification email requise
```

### 3. Premier démarrage

```bash
# Depuis la machine de développement :
make deploy-rpi

# Ou manuellement sur le RPi :
cd /opt/log-analyzer-anssi
docker compose up -d
docker compose exec ollama ollama pull granite3.3:8b  # ~5 Go, ~15 min
```

### 4. Vérification

```bash
# État des services
docker compose ps

# Santé Ollama
curl http://192.168.1.31:11434/api/version

# Test ntfy
curl -d "Test SIEM" http://192.168.1.31:8080/log-analyzer-alerts
```

### 5. Mise à jour hebdomadaire LOLDrivers (cron)

```bash
# Ajouter au crontab du RPi :
0 3 * * 0 /opt/log-analyzer-anssi/scripts/update_loldrivers.sh \
    >> /var/log/loldrivers-update.log 2>&1
```

---

## Commandes Make

| Commande | Description |
|---|---|
| `make run` | Démarrer les services Docker Compose |
| `make stop` | Arrêter les services |
| `make test` | Tous les tests + couverture HTML |
| `make test-unit` | Tests unitaires uniquement |
| `make lint` | Vérification style ruff |
| `make typecheck` | mypy --strict |
| `make update-loldrivers` | Mettre à jour le cache loldrivers.io |
| `make deploy-rpi` | Déployer sur gloaguen@192.168.1.31 |
| `make clean` | Supprimer artefacts (htmlcov, caches) |

---

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `HMAC_SECRET` | *obligatoire* | Clé HMAC-SHA256 — `openssl rand -hex 32` |
| `OLLAMA_BASE_URL` | `http://ollama:11434` | URL Ollama local |
| `OLLAMA_MODEL` | `granite3.3:8b` | Modèle LLM analyst |
| `LOLDRIVERS_CACHE` | `/app/data/loldrivers_cache.json` | Cache LOLDrivers |
| `BYOVD_RISK_THRESHOLD` | `0.6` | Seuil alerte BYOVD |
| `NTFY_URL` | `http://ntfy:8080` | URL ntfy auto-hébergé |
| `NTFY_TOPIC` | `log-analyzer-alerts` | Topic ntfy |
| `NTFY_TOKEN` | — | Bearer token ntfy (optionnel) |
| `ALERT_MIN_SCORE` | `0.6` | Score minimal pour notifier |
| `NOTIFIER_CHANNELS` | `ntfy,email` | Ordre des canaux (priorité gauche) |
| `SMTP_HOST` | — | Serveur SMTP (fallback email) |
| `ALERT_EMAIL_TO` | — | Destinataires email (virgule) |
| `ZEEK_LOG_DIR` | `/var/log/zeek/current` | Logs Zeek (conn.log) |
| `TCPDUMP_IFACE` | `eth0` | Interface tcpdump fallback |
| `LOG_RETENTION_DAYS` | `365` | Rétention archives (ANSSI min) |

---

## Structure du projet

```
log-analyzer-anssi/
├── core/
│   └── log_integrity.py        # HMAC-SHA256, hash chaining NIS2
├── detectors/
│   └── byovd_detector.py       # T1068+T1562.001, loldrivers.io
├── collectors/
│   └── network_collector.py    # Zeek, beaconing, Tor, DoH
├── nodes/
│   └── ransomware_behavior_analyst.py  # LangGraph, Ollama, SQLite
├── notifiers/
│   └── alert_dispatcher.py     # ntfy + SMTP, rate limiting
├── scripts/
│   └── update_loldrivers.sh    # Cron hebdomadaire IoC
├── tests/
│   ├── fixtures/               # XML Sysmon (TP/FP), Zeek TSV
│   └── test_byovd_detector.py  # 11 tests (TP×4, FP×4, boundary×3)
├── data/                       # Cache LOLDrivers, SQLite DB
├── .github/workflows/
│   ├── ci.yml                  # lint + test ≥80% + security
│   ├── build-check.yml         # Docker buildx ARM64 + SBOM syft
│   └── deploy-notify.yml       # ntfy notification on main push
├── docker-compose.yml          # siem + ntfy + ollama (ARM64)
├── Dockerfile                  # python:3.11-slim-bookworm
├── Makefile                    # run/test/lint/deploy-rpi
└── .env.example                # Template variables (copier → .env)
```

---

## Licence

MIT — Voir `LICENSE`
