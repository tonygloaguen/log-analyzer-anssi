-- ─────────────────────────────────────────────────────────────────────────────
-- Initialisation PostgreSQL — log-analyzer-anssi
-- Extensions : pgvector pour la recherche sémantique
-- ─────────────────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vector";

-- ── Table principale des logs normalisés ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS log_entries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp           TIMESTAMPTZ NOT NULL,
    source              VARCHAR(64) NOT NULL DEFAULT 'unknown',
    host                VARCHAR(255) NOT NULL DEFAULT 'unknown',
    raw_message         TEXT NOT NULL,
    normalized_message  TEXT NOT NULL DEFAULT '',
    severity            VARCHAR(16) NOT NULL DEFAULT 'info',
    tags                JSONB DEFAULT '[]',
    metadata            JSONB DEFAULT '{}',
    hmac_signature      VARCHAR(64) DEFAULT '',
    integrity_verified  BOOLEAN DEFAULT FALSE,
    collected_at        TIMESTAMPTZ DEFAULT NOW(),

    -- Vecteur d'embedding pour recherche sémantique (pgvector)
    embedding           vector(384)
);

-- Index pour les requêtes fréquentes
CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_log_entries_source ON log_entries (source);
CREATE INDEX IF NOT EXISTS idx_log_entries_severity ON log_entries (severity);
CREATE INDEX IF NOT EXISTS idx_log_entries_host ON log_entries (host);

-- Index vectoriel (IVFFlat pour recherche approximative rapide)
CREATE INDEX IF NOT EXISTS idx_log_entries_embedding
    ON log_entries USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- ── Table des rapports d'analyse ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS analysis_reports (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    analysis_window_start   TIMESTAMPTZ,
    analysis_window_end     TIMESTAMPTZ,
    source_filter           VARCHAR(64) DEFAULT '*',
    total_logs_analyzed     INTEGER DEFAULT 0,
    overall_risk_score      DOUBLE PRECISION DEFAULT 0.0,
    status                  VARCHAR(32) NOT NULL DEFAULT 'pending',
    routed_to               VARCHAR(32) DEFAULT '',
    escalation_reason       TEXT DEFAULT '',
    llm_summary             TEXT DEFAULT '',
    recommendations         JSONB DEFAULT '[]',
    audit_trail             JSONB DEFAULT '[]',
    pipeline_version        VARCHAR(16) DEFAULT '1.0.0'
);

CREATE INDEX IF NOT EXISTS idx_reports_created_at ON analysis_reports (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_status ON analysis_reports (status);

-- ── Table d'audit ANSSI (immuable — pas de UPDATE/DELETE) ────────────────────
CREATE TABLE IF NOT EXISTS audit_trail (
    id              BIGSERIAL PRIMARY KEY,
    event_type      VARCHAR(64) NOT NULL,
    event_timestamp TIMESTAMPTZ DEFAULT NOW(),
    details         JSONB DEFAULT '{}',
    actor           VARCHAR(128) DEFAULT 'system',
    report_id       UUID REFERENCES analysis_reports(id) ON DELETE SET NULL
);

-- L'audit trail ne doit pas être modifiable
-- En production : utiliser des Row Level Security policies
CREATE INDEX IF NOT EXISTS idx_audit_trail_timestamp ON audit_trail (event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_trail_event ON audit_trail (event_type);

-- ── Table des anomalies détectées ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS anomaly_details (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id       UUID REFERENCES analysis_reports(id) ON DELETE CASCADE,
    anomaly_type    VARCHAR(64) NOT NULL,
    score           DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 1),
    description     TEXT DEFAULT '',
    llm_analysis    TEXT DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anomalies_report ON anomaly_details (report_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_type ON anomaly_details (anomaly_type);

-- ── Vue pour le dashboard Grafana ────────────────────────────────────────────
CREATE OR REPLACE VIEW v_security_summary AS
SELECT
    date_trunc('hour', created_at) AS hour,
    COUNT(*) AS total_reports,
    AVG(overall_risk_score) AS avg_risk_score,
    MAX(overall_risk_score) AS max_risk_score,
    SUM(CASE WHEN status = 'escalated' THEN 1 ELSE 0 END) AS escalations,
    SUM(total_logs_analyzed) AS total_logs
FROM analysis_reports
GROUP BY date_trunc('hour', created_at)
ORDER BY hour DESC;

-- Confirmation
DO $$
BEGIN
    RAISE NOTICE 'Base log_analyzer initialisée avec succès (pgvector activé)';
END $$;
