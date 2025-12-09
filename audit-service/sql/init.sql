-- ============================================================================
-- Audit Log Service - Database Initialization Script
-- ============================================================================
-- This script creates all necessary tables, indexes, and configurations
-- for the audit log system.

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;    -- For encryption functions
CREATE EXTENSION IF NOT EXISTS pg_trgm;     -- For trigram-based text search

-- ============================================================================
-- 1. MAIN TABLE: audit_events
-- ============================================================================
-- This is the core table storing all audit events.
-- Features:
--   - Append-only (no UPDATE/DELETE allowed)
--   - Partitioned by month for performance
--   - JSONB for flexible event data
--   - Hash chaining for tamper detection

CREATE TABLE IF NOT EXISTS audit_events (
    -- === IDENTITY FIELDS ===
    id BIGSERIAL,                              -- Auto-increment ID
    service_id TEXT NOT NULL,                  -- Publisher service identifier
    event_type TEXT NOT NULL,                  -- Event category/type
    
    -- === PAYLOAD ===
    event_data JSONB NOT NULL,                 -- Structured event data (auto-compressed via TOAST)
    event_canonical TEXT NOT NULL,             -- Canonical form for signature verification
    
    -- === CRYPTOGRAPHIC PROOF ===
    event_hash BYTEA NOT NULL,                 -- SHA-256 of event_canonical
    signature BYTEA NOT NULL,                  -- Digital signature (Ed25519 or RSA-PSS)
    public_key_id TEXT NOT NULL,               -- Reference to key used for signing
    chain_hash BYTEA NOT NULL,                 -- Hash chain: SHA256(prev_chain || event_hash || service_id)
    
    -- === VERIFICATION STATUS ===
    verified BOOLEAN NOT NULL DEFAULT false,   -- Gateway verified signature?
    
    -- === TIMESTAMPS ===
    timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT now(),  -- Event timestamp (from publisher)
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),    -- When gateway received it
    
    -- === CONSTRAINTS ===
    PRIMARY KEY (id, timestamp_utc)            -- Composite key for partitioning
) PARTITION BY RANGE (timestamp_utc);

-- Create initial partitions (current month + next month)
DO $$
DECLARE
    current_year INT := EXTRACT(YEAR FROM CURRENT_DATE);
    current_month INT := EXTRACT(MONTH FROM CURRENT_DATE);
    next_year INT;
    next_month INT;
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    -- Current month partition
    start_date := DATE_TRUNC('month', CURRENT_DATE);
    end_date := start_date + INTERVAL '1 month';
    partition_name := 'audit_events_' || TO_CHAR(start_date, 'YYYY_MM');
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_events 
         FOR VALUES FROM (%L) TO (%L)',
        partition_name, start_date, end_date
    );
    
    -- Next month partition
    start_date := end_date;
    end_date := start_date + INTERVAL '1 month';
    partition_name := 'audit_events_' || TO_CHAR(start_date, 'YYYY_MM');
    
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_events 
         FOR VALUES FROM (%L) TO (%L)',
        partition_name, start_date, end_date
    );
END $$;

-- Indexes for audit_events
CREATE INDEX IF NOT EXISTS idx_audit_service_time 
    ON audit_events(service_id, timestamp_utc DESC);

CREATE INDEX IF NOT EXISTS idx_audit_event_type 
    ON audit_events(event_type, timestamp_utc DESC);

CREATE INDEX IF NOT EXISTS idx_audit_event_hash 
    ON audit_events USING hash(event_hash);

CREATE INDEX IF NOT EXISTS idx_audit_chain_hash 
    ON audit_events(chain_hash);

CREATE INDEX IF NOT EXISTS idx_audit_public_key 
    ON audit_events(public_key_id, timestamp_utc DESC);

-- JSONB index for querying event_data
CREATE INDEX IF NOT EXISTS idx_audit_event_data_gin 
    ON audit_events USING gin(event_data jsonb_path_ops);

-- Full-text search index
CREATE INDEX IF NOT EXISTS idx_audit_event_text 
    ON audit_events USING gin(to_tsvector('english', event_canonical));

-- ============================================================================
-- 2. TABLE: key_registry
-- ============================================================================
-- Stores public keys for signature verification.

CREATE TABLE IF NOT EXISTS key_registry (
    public_key_id TEXT PRIMARY KEY,            -- Unique key identifier (e.g., "service-a:v1")
    service_id TEXT NOT NULL,                  -- Owning service
    
    -- Key data
    public_key_pem TEXT NOT NULL,              -- PEM-encoded public key
    algorithm TEXT NOT NULL CHECK (algorithm IN ('ed25519', 'rsa-pss', 'rsa-pkcs1v15')),
    
    -- Approval workflow
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewed_by TEXT,                          -- Admin who approved/rejected
    reviewed_at TIMESTAMPTZ,                   -- When reviewed
    rejection_reason TEXT,                     -- Reason if rejected
    
    -- Lifecycle
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT NOT NULL,                  -- Service that requested (self-registration)
    rotated_to TEXT REFERENCES key_registry(public_key_id),  -- Points to replacement key
    disabled_at TIMESTAMPTZ,                   -- When key was disabled/revoked
    
    -- Metadata
    metadata JSONB                             -- Additional key metadata
);

-- Index for finding active keys by service (approved only)
CREATE INDEX IF NOT EXISTS idx_key_service_active 
    ON key_registry(service_id) 
    WHERE status = 'approved' AND disabled_at IS NULL AND rotated_to IS NULL;

-- Index for pending key requests
CREATE INDEX IF NOT EXISTS idx_key_pending 
    ON key_registry(created_at DESC) 
    WHERE status = 'pending';

-- ============================================================================
-- 3. TABLE: chain_state
-- ============================================================================
-- Tracks the current chain hash for each service.

CREATE TABLE IF NOT EXISTS chain_state (
    service_id TEXT PRIMARY KEY,
    last_chain_hash BYTEA NOT NULL,            -- Current chain head
    last_event_id BIGINT NOT NULL,             -- ID of last event
    last_updated TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 4. TABLE: admin_audit
-- ============================================================================
-- Meta-audit table for tracking administrative actions.

CREATE TABLE IF NOT EXISTS admin_audit (
    id BIGSERIAL PRIMARY KEY,
    action TEXT NOT NULL,                      -- Action performed
    actor TEXT NOT NULL,                       -- Who performed it
    target_resource TEXT,                      -- What was affected
    details JSONB,                             -- Additional details
    timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    signature BYTEA NOT NULL                   -- Admin key signature
);

CREATE INDEX IF NOT EXISTS idx_admin_actor 
    ON admin_audit(actor, timestamp_utc DESC);

CREATE INDEX IF NOT EXISTS idx_admin_action 
    ON admin_audit(action, timestamp_utc DESC);

-- ============================================================================
-- 5. MATERIALIZED VIEW: event_stats_hourly
-- ============================================================================
-- Pre-aggregated statistics for dashboard queries.

CREATE MATERIALIZED VIEW IF NOT EXISTS event_stats_hourly AS
SELECT 
    date_trunc('hour', timestamp_utc) as hour,
    service_id,
    event_type,
    count(*) as event_count,
    count(*) FILTER (WHERE NOT verified) as failed_count
FROM audit_events
GROUP BY 1, 2, 3;

CREATE UNIQUE INDEX IF NOT EXISTS idx_stats_hourly_pk 
    ON event_stats_hourly (hour, service_id, event_type);

-- ============================================================================
-- 6. RULES: Prevent UPDATE/DELETE on audit_events
-- ============================================================================
-- Enforce append-only behavior.

CREATE OR REPLACE RULE no_update_audit_events AS 
    ON UPDATE TO audit_events 
    DO INSTEAD NOTHING;

CREATE OR REPLACE RULE no_delete_audit_events AS 
    ON DELETE TO audit_events 
    DO INSTEAD NOTHING;

-- ============================================================================
-- 7. DATABASE ROLES AND PERMISSIONS
-- ============================================================================

-- API role (used by the application)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_api_role') THEN
        CREATE ROLE audit_api_role;
    END IF;
END $$;

GRANT CONNECT ON DATABASE audit_db TO audit_api_role;
GRANT USAGE ON SCHEMA public TO audit_api_role;
GRANT INSERT ON audit_events TO audit_api_role;
GRANT SELECT ON key_registry TO audit_api_role;
GRANT SELECT, INSERT, UPDATE ON chain_state TO audit_api_role;
GRANT INSERT ON admin_audit TO audit_api_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO audit_api_role;

-- Read-only role (for analytics/dashboards)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'audit_readonly') THEN
        CREATE ROLE audit_readonly;
    END IF;
END $$;

GRANT CONNECT ON DATABASE audit_db TO audit_readonly;
GRANT USAGE ON SCHEMA public TO audit_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO audit_readonly;

-- ============================================================================
-- 8. COMMENTS
-- ============================================================================

COMMENT ON TABLE audit_events IS 'Main audit log table - append-only, partitioned by month';
COMMENT ON TABLE key_registry IS 'Public key registry for signature verification';
COMMENT ON TABLE chain_state IS 'Tracks hash chain state per service';
COMMENT ON TABLE admin_audit IS 'Meta-audit trail for administrative actions';
COMMENT ON MATERIALIZED VIEW event_stats_hourly IS 'Hourly aggregated statistics for dashboards';

-- Done!
SELECT 'Audit Log database initialized successfully' as status;
