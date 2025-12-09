-- ============================================================================
-- Audit Log Service - Database Functions and Triggers
-- ============================================================================

-- ============================================================================
-- 1. NOTIFY TRIGGER: Publish new events for async processing
-- ============================================================================

CREATE OR REPLACE FUNCTION notify_new_audit_event()
RETURNS TRIGGER AS $$
BEGIN
    -- Send notification with basic event info
    PERFORM pg_notify('audit_events', json_build_object(
        'id', NEW.id,
        'service_id', NEW.service_id,
        'event_type', NEW.event_type,
        'timestamp', NEW.timestamp_utc
    )::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach trigger (only if not exists)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger 
        WHERE tgname = 'trigger_notify_audit_event'
    ) THEN
        CREATE TRIGGER trigger_notify_audit_event
        AFTER INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION notify_new_audit_event();
    END IF;
END $$;

-- ============================================================================
-- 2. PARTITION MANAGEMENT: Auto-create future partitions
-- ============================================================================

CREATE OR REPLACE FUNCTION create_audit_partition_for_month(target_date DATE)
RETURNS TEXT AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    start_date := DATE_TRUNC('month', target_date);
    end_date := start_date + INTERVAL '1 month';
    partition_name := 'audit_events_' || TO_CHAR(start_date, 'YYYY_MM');
    
    -- Check if partition already exists
    IF EXISTS (
        SELECT 1 FROM pg_class 
        WHERE relname = partition_name
    ) THEN
        RETURN 'Partition ' || partition_name || ' already exists';
    END IF;
    
    -- Create partition
    EXECUTE format(
        'CREATE TABLE %I PARTITION OF audit_events 
         FOR VALUES FROM (%L) TO (%L)',
        partition_name, start_date, end_date
    );
    
    -- Log creation
    INSERT INTO admin_audit (action, actor, target_resource, details, signature)
    VALUES (
        'create_partition',
        'system',
        partition_name,
        json_build_object('start_date', start_date, 'end_date', end_date),
        '\x00'::bytea
    );
    
    RETURN 'Created partition: ' || partition_name;
END;
$$ LANGUAGE plpgsql;

-- Function to ensure partitions exist for next N months
CREATE OR REPLACE FUNCTION ensure_future_partitions(months_ahead INT DEFAULT 3)
RETURNS TABLE(partition_name TEXT, status TEXT) AS $$
DECLARE
    target_date DATE;
    i INT;
BEGIN
    FOR i IN 0..months_ahead LOOP
        target_date := DATE_TRUNC('month', CURRENT_DATE) + (i || ' months')::INTERVAL;
        partition_name := 'audit_events_' || TO_CHAR(target_date, 'YYYY_MM');
        status := create_audit_partition_for_month(target_date);
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 3. CHAIN VERIFICATION: Verify hash chain integrity
-- ============================================================================

CREATE OR REPLACE FUNCTION verify_chain_integrity(
    p_service_id TEXT,
    p_limit INT DEFAULT 10000
)
RETURNS TABLE(
    is_valid BOOLEAN,
    events_checked INT,
    first_invalid_id BIGINT,
    error_message TEXT
) AS $$
DECLARE
    prev_chain_hash BYTEA := '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea;
    expected_hash BYTEA;
    event_record RECORD;
    checked_count INT := 0;
BEGIN
    FOR event_record IN
        SELECT id, event_hash, chain_hash
        FROM audit_events
        WHERE service_id = p_service_id
        ORDER BY id ASC
        LIMIT p_limit
    LOOP
        checked_count := checked_count + 1;
        
        -- Compute expected chain hash
        expected_hash := digest(
            prev_chain_hash || event_record.event_hash || p_service_id::bytea,
            'sha256'
        );
        
        -- Compare with stored chain hash
        IF expected_hash != event_record.chain_hash THEN
            is_valid := false;
            events_checked := checked_count;
            first_invalid_id := event_record.id;
            error_message := 'Chain hash mismatch at event ID ' || event_record.id;
            RETURN NEXT;
            RETURN;
        END IF;
        
        prev_chain_hash := event_record.chain_hash;
    END LOOP;
    
    is_valid := true;
    events_checked := checked_count;
    first_invalid_id := NULL;
    error_message := NULL;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 4. STATISTICS REFRESH
-- ============================================================================

CREATE OR REPLACE FUNCTION refresh_event_stats()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY event_stats_hourly;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 5. CLEANUP OLD PARTITIONS (Optional - for data retention)
-- ============================================================================

CREATE OR REPLACE FUNCTION drop_old_partitions(months_to_keep INT DEFAULT 24)
RETURNS TABLE(partition_name TEXT, status TEXT) AS $$
DECLARE
    cutoff_date DATE;
    part_record RECORD;
BEGIN
    cutoff_date := DATE_TRUNC('month', CURRENT_DATE) - (months_to_keep || ' months')::INTERVAL;
    
    FOR part_record IN
        SELECT c.relname as name
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'audit_events'
        ORDER BY c.relname
    LOOP
        -- Extract date from partition name (format: audit_events_YYYY_MM)
        DECLARE
            part_date DATE;
        BEGIN
            part_date := TO_DATE(
                SUBSTRING(part_record.name FROM 'audit_events_(\d{4}_\d{2})'),
                'YYYY_MM'
            );
            
            IF part_date < cutoff_date THEN
                -- Archive before dropping (optional)
                -- EXECUTE format('COPY %I TO ''/archive/%I.csv'' CSV', part_record.name, part_record.name);
                
                EXECUTE format('DROP TABLE %I', part_record.name);
                
                partition_name := part_record.name;
                status := 'dropped';
                RETURN NEXT;
                
                -- Log action
                INSERT INTO admin_audit (action, actor, target_resource, details, signature)
                VALUES (
                    'drop_partition',
                    'system',
                    part_record.name,
                    json_build_object('cutoff_date', cutoff_date),
                    '\x00'::bytea
                );
            END IF;
        EXCEPTION WHEN OTHERS THEN
            partition_name := part_record.name;
            status := 'error: ' || SQLERRM;
            RETURN NEXT;
        END;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 6. SUSPICIOUS ACTIVITY DETECTION
-- ============================================================================

CREATE OR REPLACE VIEW suspicious_activity AS
SELECT 
    service_id,
    count(*) as failed_attempts,
    count(DISTINCT public_key_id) as unique_keys_used,
    min(timestamp_utc) as first_attempt,
    max(timestamp_utc) as last_attempt
FROM audit_events
WHERE NOT verified
  AND timestamp_utc > now() - interval '1 hour'
GROUP BY service_id
HAVING count(*) > 100;

-- Function to check and alert on suspicious activity
CREATE OR REPLACE FUNCTION check_suspicious_activity()
RETURNS TABLE(
    service_id TEXT,
    failed_attempts BIGINT,
    unique_keys_used BIGINT
) AS $$
BEGIN
    RETURN QUERY SELECT s.service_id, s.failed_attempts, s.unique_keys_used
    FROM suspicious_activity s;
    
    -- Notify if any suspicious activity found
    IF EXISTS (SELECT 1 FROM suspicious_activity) THEN
        PERFORM pg_notify('security_alert', 
            (SELECT json_agg(row_to_json(s)) FROM suspicious_activity s)::text
        );
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 7. SEARCH HELPERS
-- ============================================================================

-- Function to search events with flexible criteria
CREATE OR REPLACE FUNCTION search_audit_events(
    p_service_id TEXT DEFAULT NULL,
    p_event_type TEXT DEFAULT NULL,
    p_search_text TEXT DEFAULT NULL,
    p_start_time TIMESTAMPTZ DEFAULT NULL,
    p_end_time TIMESTAMPTZ DEFAULT NULL,
    p_limit INT DEFAULT 100,
    p_offset INT DEFAULT 0
)
RETURNS TABLE(
    id BIGINT,
    service_id TEXT,
    event_type TEXT,
    event_data JSONB,
    verified BOOLEAN,
    timestamp_utc TIMESTAMPTZ,
    rank REAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        e.id,
        e.service_id,
        e.event_type,
        e.event_data,
        e.verified,
        e.timestamp_utc,
        CASE 
            WHEN p_search_text IS NOT NULL THEN
                ts_rank(to_tsvector('english', e.event_canonical), plainto_tsquery('english', p_search_text))
            ELSE 0::REAL
        END as rank
    FROM audit_events e
    WHERE 
        (p_service_id IS NULL OR e.service_id = p_service_id)
        AND (p_event_type IS NULL OR e.event_type = p_event_type)
        AND (p_start_time IS NULL OR e.timestamp_utc >= p_start_time)
        AND (p_end_time IS NULL OR e.timestamp_utc <= p_end_time)
        AND (p_search_text IS NULL OR 
             to_tsvector('english', e.event_canonical) @@ plainto_tsquery('english', p_search_text))
    ORDER BY 
        CASE WHEN p_search_text IS NOT NULL THEN rank ELSE 0 END DESC,
        e.timestamp_utc DESC
    LIMIT p_limit
    OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 8. SCHEDULED JOBS (requires pg_cron extension)
-- ============================================================================
-- Note: pg_cron needs to be installed and configured separately

-- Uncomment these if pg_cron is available:
/*
-- Refresh stats every hour
SELECT cron.schedule('refresh-stats-hourly', '0 * * * *', 
    'SELECT refresh_event_stats()');

-- Create future partitions daily
SELECT cron.schedule('create-partitions-daily', '0 0 * * *', 
    'SELECT * FROM ensure_future_partitions(3)');

-- Check suspicious activity every 5 minutes
SELECT cron.schedule('check-security', '*/5 * * * *', 
    'SELECT * FROM check_suspicious_activity()');

-- Clean up old partitions monthly (if data retention is enabled)
-- SELECT cron.schedule('cleanup-partitions', '0 0 1 * *', 
--     'SELECT * FROM drop_old_partitions(24)');
*/

-- ============================================================================
-- Done!
-- ============================================================================
SELECT 'Audit Log functions and triggers initialized successfully' as status;
