"""
Application FastAPI principale — log-analyzer-anssi.

Endpoints :
    GET  /health          — état des services
    POST /analyze         — déclencher une analyse
    GET  /reports         — lister les rapports
    GET  /reports/{id}    — récupérer un rapport
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import analysis, health

# ── Logging structuré (ANSSI : logs d'audit exploitables) ────
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifecycle : initialisation et nettoyage de l'application."""
    logger.info("Démarrage log-analyzer-anssi API", version="1.0.0")

    # Vérifier que les variables critiques sont définies
    required_env = ["HMAC_SECRET_KEY"]
    missing = [v for v in required_env if not os.getenv(v)]
    if missing:
        logger.error("Variables d'environnement manquantes", missing=missing)
        raise RuntimeError(f"Variables obligatoires non définies: {missing}")

    logger.info(
        "Configuration chargée",
        loki_url=os.getenv("LOKI_URL"),
        ollama_url=os.getenv("OLLAMA_BASE_URL"),
        retention_days=os.getenv("LOG_RETENTION_DAYS", "90"),
        anomaly_threshold=os.getenv("ANOMALY_THRESHOLD", "0.75"),
    )

    yield

    logger.info("Arrêt log-analyzer-anssi API")


app = FastAPI(
    title="log-analyzer-anssi",
    description=(
        "Système d'analyse de logs conforme ANSSI avec pipeline LangGraph. "
        "Détection d'anomalies, classification de sévérité, et escalade intelligente."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS (restreint en production) ───────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# ── Routes ────────────────────────────────────────────────────
app.include_router(health.router, tags=["Health"])
app.include_router(analysis.router, tags=["Analysis"])
