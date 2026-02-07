-- Audit Events Table
-- Stores all SQL proxy request audit logs with indexes for common queries

CREATE TABLE IF NOT EXISTS audit_events (
    event_id UUID PRIMARY KEY,
    sequence_num BIGSERIAL,

    -- Timestamps
    received_at TIMESTAMP NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Request context
    user_id VARCHAR(100) NOT NULL,
    source_ip INET,
    session_id VARCHAR(100),
    database_name VARCHAR(100),

    -- Query information
    sql_text TEXT NOT NULL,
    fingerprint_hash BIGINT NOT NULL,
    normalized_query TEXT,
    statement_type VARCHAR(50),

    -- Tables and columns accessed
    tables TEXT[],
    columns TEXT[],
    columns_filtered TEXT[],

    -- Policy decision
    decision VARCHAR(20) NOT NULL,
    matched_rule VARCHAR(200),
    rule_specificity INTEGER,
    block_reason TEXT,

    -- Execution results
    execution_attempted BOOLEAN DEFAULT false,
    execution_success BOOLEAN DEFAULT false,
    error_code VARCHAR(50),
    error_message TEXT,
    rows_affected BIGINT,
    rows_returned BIGINT,

    -- Classification
    detected_classifications TEXT[],
    has_pii BOOLEAN DEFAULT false,

    -- Performance metrics (in microseconds)
    total_duration_us BIGINT,
    proxy_overhead_us BIGINT,
    parse_time_us BIGINT,
    policy_time_us BIGINT,
    execution_time_us BIGINT,
    classification_time_us BIGINT,

    -- Rate limiting
    rate_limited BOOLEAN DEFAULT false,
    rate_limit_level VARCHAR(50),

    -- Circuit breaker
    circuit_breaker_tripped BOOLEAN DEFAULT false,

    -- Cache
    cache_hit BOOLEAN DEFAULT false,

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for common query patterns

-- Find all events for a specific user
CREATE INDEX idx_audit_user_time ON audit_events(user_id, timestamp DESC);

-- Find all denied requests
CREATE INDEX idx_audit_decision_time ON audit_events(decision, timestamp DESC);

-- Find all PII access
CREATE INDEX idx_audit_has_pii_time ON audit_events(has_pii, timestamp DESC) WHERE has_pii = true;

-- Find events by table access (GIN index for array containment)
CREATE INDEX idx_audit_tables ON audit_events USING GIN(tables);

-- Find events by query fingerprint (same query shape)
CREATE INDEX idx_audit_fingerprint_time ON audit_events(fingerprint_hash, timestamp DESC);

-- Find events by statement type
CREATE INDEX idx_audit_statement_type ON audit_events(statement_type);

-- Find rate limited requests
CREATE INDEX idx_audit_rate_limited ON audit_events(rate_limited, timestamp DESC) WHERE rate_limited = true;

-- Find failed executions
CREATE INDEX idx_audit_exec_failed ON audit_events(execution_attempted, execution_success, timestamp DESC)
    WHERE execution_attempted = true AND execution_success = false;

-- Sequence number for detecting lost events
CREATE INDEX idx_audit_sequence ON audit_events(sequence_num);

-- Performance analysis - slow queries
CREATE INDEX idx_audit_slow_queries ON audit_events(total_duration_us DESC, timestamp DESC);

-- Create proxy user with appropriate permissions
DO $$
BEGIN
    -- Create user if it doesn't exist
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = 'proxy_user') THEN
        CREATE USER proxy_user WITH PASSWORD 'secure_password';
    END IF;
END
$$;

-- Grant permissions to proxy user
GRANT SELECT, INSERT, UPDATE, DELETE ON customers, orders, order_items TO proxy_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO proxy_user;

-- Grant read-only access to sensitive_data (will be controlled by proxy policies)
GRANT SELECT ON sensitive_data TO proxy_user;

-- Grant full access to audit_events table
GRANT SELECT, INSERT ON audit_events TO proxy_user;
GRANT USAGE, SELECT ON SEQUENCE audit_events_sequence_num_seq TO proxy_user;

-- Grant schema usage
GRANT USAGE ON SCHEMA public TO proxy_user;

-- Comment the tables for documentation
COMMENT ON TABLE audit_events IS 'SQL Proxy audit log - every request is recorded here';
COMMENT ON COLUMN audit_events.fingerprint_hash IS 'xxHash64 of normalized query for grouping similar queries';
COMMENT ON COLUMN audit_events.proxy_overhead_us IS 'Time spent in proxy (excluding DB execution)';
COMMENT ON COLUMN audit_events.cache_hit IS 'Whether parse cache was hit (significant perf indicator)';
COMMENT ON COLUMN audit_events.sequence_num IS 'Monotonic counter for detecting lost events (gaps indicate problems)';
