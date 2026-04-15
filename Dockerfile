# Dockerfile — log-analyzer-anssi
# Cible : Raspberry Pi 4 ARM64 (python:3.11-slim-bookworm)
# Conformité ANSSI : USER nobody, pas de secret au build, cache LOLDrivers pré-chargé

FROM python:3.11-slim-bookworm

LABEL maintainer="log-analyzer-anssi"
LABEL description="SIEM BYOVD/ransomware — ANSSI NIS2 Art.21 — ARM64"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dépendances système : libxml2 (parsing Sysmon XML), curl (loldrivers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dépendances Python (couche mise en cache séparément)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pré-chargement du cache LOLDrivers (réduit le cold-start)
RUN mkdir -p /app/data && \
    curl -fsSL --tlsv1.2 --max-time 60 --retry 3 --retry-delay 5 \
        https://www.loldrivers.io/api/drivers.json \
        -o /app/data/loldrivers_cache.json \
    || echo "[Dockerfile] LOLDrivers non disponible au build — téléchargement différé au runtime"

# Copie des sources
COPY detectors/ ./detectors/
COPY collectors/ ./collectors/
COPY nodes/ ./nodes/
COPY notifiers/ ./notifiers/
COPY core/ ./core/
COPY scripts/ ./scripts/

# Répertoires runtime
RUN mkdir -p /app/logs /app/data && \
    chown -R nobody:nogroup /app/logs /app/data

USER nobody

EXPOSE 8000

ENTRYPOINT ["python", "-m", "app"]
