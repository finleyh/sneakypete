-- Unified event schema for all honeypot services (sip, ami, magnusbilling, ssh)

CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    source      TEXT NOT NULL,              -- 'sip' | 'ami' | 'magnusbilling' | 'ssh'
    event_type  TEXT NOT NULL,              -- 'connection' | 'auth_attempt' | 'probe' | 'command' | 'session_close' | ...
    src_ip      INET NOT NULL,
    src_port    INTEGER,
    dst_port    INTEGER,
    username    TEXT,
    password    TEXT,
    success     BOOLEAN,
    session_id  TEXT,
    raw         TEXT,                       -- raw line/payload as received
    extra       JSONB NOT NULL DEFAULT '{}'::jsonb,  -- protocol-specific structured fields
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_ts       ON events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip   ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_source   ON events (source);
CREATE INDEX IF NOT EXISTS idx_events_session  ON events (session_id);
CREATE INDEX IF NOT EXISTS idx_events_extra    ON events USING GIN (extra);
