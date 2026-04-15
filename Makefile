# Makefile — log-analyzer-anssi
# Cibles : run, test, update-loldrivers, incident-report, lint, deploy-rpi
#
# Prérequis : Docker Compose v2, Python 3.11+, make, curl, jq
# Copier .env.example → .env.local avant le premier lancement.

.DEFAULT_GOAL := help
.PHONY: run stop test test-unit test-integration update-loldrivers \
        incident-report lint typecheck deploy-rpi clean help

# ─── Variables ───────────────────────────────────────────────────────────────
ENV_FILE      ?= .env.local
COMPOSE       := docker compose --env-file $(ENV_FILE)
PYTHON        := python3
PYTEST        := pytest
MYPY          := mypy
REPORT_DIR    := reports
RPI_HOST      ?= pi@raspberrypi.local
RPI_DEST      ?= /opt/log-analyzer-anssi

# ─── Couleurs terminal ───────────────────────────────────────────────────────
BOLD  := \033[1m
RESET := \033[0m
GREEN := \033[32m
CYAN  := \033[36m

# ─────────────────────────────────────────────────────────────────────────────
## run : Démarrer tous les services Docker Compose
# ─────────────────────────────────────────────────────────────────────────────
run: $(ENV_FILE)
	@echo "$(BOLD)$(GREEN)▶ Démarrage des services...$(RESET)"
	$(COMPOSE) up -d
	@echo "$(CYAN)API disponible sur http://localhost:8000/docs$(RESET)"
	@echo "$(CYAN)Grafana disponible sur http://localhost:3000$(RESET)"

## stop : Arrêter tous les services Docker Compose
stop:
	@echo "$(BOLD)▶ Arrêt des services...$(RESET)"
	$(COMPOSE) down

# ─────────────────────────────────────────────────────────────────────────────
## test : Lancer tous les tests (unit + integration) avec couverture
# ─────────────────────────────────────────────────────────────────────────────
test:
	@echo "$(BOLD)▶ Lancement de la suite de tests complète...$(RESET)"
	$(PYTEST) tests/ --cov=src --cov=detectors --cov=nodes --cov=collectors \
	    --cov=notifiers --cov=core \
	    --cov-report=html:htmlcov --cov-report=term-missing \
	    -v

## test-unit : Tests unitaires uniquement
test-unit:
	@echo "$(BOLD)▶ Tests unitaires...$(RESET)"
	$(PYTEST) tests/unit/ tests/test_byovd_detector.py -v

## test-integration : Tests d'intégration uniquement (Ollama mocké)
test-integration:
	@echo "$(BOLD)▶ Tests d'intégration...$(RESET)"
	$(PYTEST) tests/integration/ -v

# ─────────────────────────────────────────────────────────────────────────────
## update-loldrivers : Mettre à jour le cache loldrivers.io
# ─────────────────────────────────────────────────────────────────────────────
update-loldrivers:
	@echo "$(BOLD)▶ Mise à jour du cache loldrivers.io...$(RESET)"
	@if [ -f $(ENV_FILE) ]; then \
	    export $$(grep -v '^#' $(ENV_FILE) | xargs) 2>/dev/null || true; \
	fi
	./scripts/update_loldrivers.sh
	@echo "$(GREEN)Cache mis à jour : data/loldrivers_cache.json$(RESET)"

# ─────────────────────────────────────────────────────────────────────────────
## incident-report : Générer un rapport d'incident depuis le dernier run
# ─────────────────────────────────────────────────────────────────────────────
incident-report:
	@echo "$(BOLD)▶ Génération du rapport d'incident...$(RESET)"
	@mkdir -p $(REPORT_DIR)
	@REPORT_FILE=$(REPORT_DIR)/incident-$$(date -u +%Y%m%d-%H%M%S).json; \
	curl -sf http://localhost:8000/reports?limit=1 \
	    | python3 -m json.tool > "$$REPORT_FILE" && \
	echo "$(GREEN)Rapport généré : $$REPORT_FILE$(RESET)" || \
	echo "$(BOLD)Erreur : API indisponible (lancer 'make run' d'abord)$(RESET)"

# ─────────────────────────────────────────────────────────────────────────────
## lint : Vérification du style de code (ruff)
# ─────────────────────────────────────────────────────────────────────────────
lint:
	@echo "$(BOLD)▶ Linting (ruff)...$(RESET)"
	$(PYTHON) -m ruff check src/ detectors/ nodes/ collectors/ notifiers/ core/ tests/

## typecheck : Vérification des types (mypy strict)
typecheck:
	@echo "$(BOLD)▶ Vérification des types (mypy --strict)...$(RESET)"
	$(MYPY) src/ detectors/ nodes/ collectors/ notifiers/ core/ --strict

# ─────────────────────────────────────────────────────────────────────────────
## deploy-rpi : Déploiement sur Raspberry Pi (rsync + docker compose)
# ─────────────────────────────────────────────────────────────────────────────
deploy-rpi:
	@echo "$(BOLD)▶ Déploiement sur $(RPI_HOST):$(RPI_DEST)$(RESET)"
	rsync -avz --exclude='.git' --exclude='htmlcov' --exclude='*.pyc' \
	    --exclude='.env.local' --exclude='data/loldrivers_cache.json' \
	    ./ $(RPI_HOST):$(RPI_DEST)/
	ssh $(RPI_HOST) "cd $(RPI_DEST) && docker compose --env-file .env.local up -d --build"
	@echo "$(GREEN)Déploiement terminé.$(RESET)"

# ─────────────────────────────────────────────────────────────────────────────
## clean : Supprimer les artefacts générés (htmlcov, rapports, caches Python)
# ─────────────────────────────────────────────────────────────────────────────
clean:
	@echo "$(BOLD)▶ Nettoyage des artefacts...$(RESET)"
	rm -rf htmlcov/ .coverage $(REPORT_DIR)/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
## help : Afficher l'aide
# ─────────────────────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "$(BOLD)log-analyzer-anssi — Cibles disponibles :$(RESET)"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  make /' | column -t -s ':'
	@echo ""

# ─── Garde-fou : vérifier que .env.local existe ──────────────────────────────
$(ENV_FILE):
	@echo "$(BOLD)Erreur : $(ENV_FILE) introuvable.$(RESET)"
	@echo "  Copier .env.example → $(ENV_FILE) et renseigner les valeurs."
	@exit 1
