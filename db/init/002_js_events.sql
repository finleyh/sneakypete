-- Client-side telemetry from the magnusbilling-honeypot boot page's JS shim
-- (page-load timing, login round-trip time). Kept separate from `events`:
-- this is connection-quality signal about the browser session itself, not
-- an attacker action, and has a different, JS-defined shape per `kind`.

CREATE TABLE IF NOT EXISTS js_events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    src_ip      INET NOT NULL,
    src_port    INTEGER,
    kind        TEXT NOT NULL,              -- 'page_load' | 'login_rtt'
    user_agent  TEXT,
    raw         TEXT,                       -- raw JSON body as received, pre-parse
    data        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_js_events_ts     ON js_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_js_events_src_ip ON js_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_js_events_kind   ON js_events (kind);
CREATE INDEX IF NOT EXISTS idx_js_events_data   ON js_events USING GIN (data);
