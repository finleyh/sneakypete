-- Trino's PostgreSQL connector doesn't support the native INET type and
-- silently drops any column using it (SELECT src_ip errors with
-- COLUMN_NOT_FOUND) rather than mapping it to something queryable. These
-- views re-expose src_ip as text so it's visible through Trino; query them
-- instead of the base tables when working from Trino.

CREATE OR REPLACE VIEW events_trino AS
    SELECT id, ts, source, event_type, host(src_ip) AS src_ip, src_port, dst_port,
           username, password, success, session_id, raw, extra, created_at
    FROM events;

CREATE OR REPLACE VIEW js_events_trino AS
    SELECT id, ts, host(src_ip) AS src_ip, src_port, kind, user_agent, raw, data, created_at
    FROM js_events;
