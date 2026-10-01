-- credential_attempts was a thin view over events (WHERE event_type =
-- 'auth_attempt') with no independent writer and no Trino-usable src_ip
-- column of its own. Query events/events_trino directly instead.

DROP VIEW IF EXISTS credential_attempts;
