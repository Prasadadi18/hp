-- postgres/init/01_schema.sql
-- HPE audit database schema.
-- Runs automatically on first postgres container startup.
-- Vault's dynamic service users get SELECT/INSERT/UPDATE on these tables.

CREATE TABLE IF NOT EXISTS hpe_audit_logs (
    id           SERIAL PRIMARY KEY,
    event_id     VARCHAR(64)  NOT NULL,
    timestamp    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    user_id      VARCHAR(32),
    action       VARCHAR(64),
    threat_score FLOAT,
    is_threat    BOOLEAN      DEFAULT FALSE,
    source_ip    VARCHAR(45),
    details      JSONB
);

CREATE TABLE IF NOT EXISTS hpe_credential_rotations (
    id             SERIAL PRIMARY KEY,
    rotation_id    VARCHAR(64)  NOT NULL,
    timestamp      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    rotation_type  VARCHAR(32)  NOT NULL,  -- 'user' or 'infrastructure'
    target         VARCHAR(128) NOT NULL,  -- user_id or service name
    trigger_score  FLOAT,
    lease_id       VARCHAR(256),           -- Vault lease ID for infra rotations
    lease_duration INTEGER,               -- seconds
    success        BOOLEAN      DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS hpe_infra_leases (
    id         SERIAL PRIMARY KEY,
    service    VARCHAR(64)  NOT NULL,  -- 'elasticsearch', 'kafka', 'database'
    lease_id   VARCHAR(256) NOT NULL,
    username   VARCHAR(128),
    issued_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked    BOOLEAN      DEFAULT FALSE,
    revoked_at TIMESTAMPTZ
);

-- Grant vault-root full control so Vault can CREATE/DROP dynamic service users
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "vault-root";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "vault-root";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON TABLES TO "vault-root";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT ALL ON SEQUENCES TO "vault-root";

CREATE TABLE IF NOT EXISTS hpe_admin_alerts (
    alert_id VARCHAR(64) PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64),
    threat_score FLOAT,
    threat_action VARCHAR(32),
    xgb_score FLOAT,
    lgb_score FLOAT,
    ensemble_score FLOAT,
    threshold FLOAT,
    status VARCHAR(32) DEFAULT 'pending',
    event_data JSONB,
    pipeline_stages JSONB,
    source_geo JSONB,
    destination_geo JSONB,
    total_latency_ms FLOAT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    admin_notes TEXT,
    rotation_result JSONB
);

CREATE TABLE IF NOT EXISTS hpe_admin_stats (
    id SERIAL PRIMARY KEY,
    total_alerts_created INT DEFAULT 0,
    total_approved INT DEFAULT 0,
    total_rejected INT DEFAULT 0,
    total_auto_allowed INT DEFAULT 0
);
INSERT INTO hpe_admin_stats (id, total_alerts_created, total_approved, total_rejected, total_auto_allowed) VALUES (1, 0, 0, 0, 0) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS hpe_admin_audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    action VARCHAR(32),
    alert_id VARCHAR(64),
    user_id VARCHAR(64),
    threat_score FLOAT,
    admin_notes TEXT
);

CREATE TABLE IF NOT EXISTS hpe_threat_metrics (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    total_events INT DEFAULT 0,
    blocked_events INT DEFAULT 0,
    monitored_events INT DEFAULT 0,
    allowed_events INT DEFAULT 0,
    avg_latency FLOAT DEFAULT 0,
    high_risk_users JSONB
);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "vault-root";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "vault-root";