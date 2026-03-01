# Dockerfile — log-analyzer-anssi
# Build multi-stage : base → api

FROM python:3.11-slim AS base

LABEL maintainer="log-analyzer-anssi"
LABEL description="ANSSI-compliant log analysis system with LangGraph"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ─────────────────────
# Stage : API FastAPI
# ─────────────────────
FROM base AS api

COPY src/ ./src/

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
RUN mkdir -p /var/log-analyzer && chown appuser:appgroup /var/log-analyzer

USER appuser

EXPOSE 8000

CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
