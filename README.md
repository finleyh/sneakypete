# voip-honeypot

Docker Compose stack: SIP + AMI + web login decoys, plus a Cowrie SSH
honeypot, all logging into one Postgres `events` table.

## Services / ports

| Service | Port |
|---|---|
| `sip-honeypot` | 5060/udp, bound to `BIND_IP` (default all interfaces) |
| `ami-honeypot` | 5038/tcp, bound to `BIND_IP` (default all interfaces) |
| `magnusbilling-honeypot` | 80/tcp, bound to `BIND_IP` (default all interfaces) |
| `cowrie` (SSH) | 22/tcp, bound to `BIND_IP` (default all interfaces) |
| `ssh-log-shipper` | — (no listener, ships Cowrie's log into Postgres) |
| `postgres` | 5432/tcp, bound only to `TAILSCALE_IP` |

## Event schema

See [db/init/001_schema.sql](db/init/001_schema.sql). One `events` table for
all services: `source`, `event_type`, `src_ip`, `username`, `password`,
`success`, `session_id`, `raw`, plus a `extra` JSONB column for
protocol-specific fields.

**Querying from Trino**: Trino's PostgreSQL connector doesn't support the
native `INET` type `src_ip` uses, and silently drops that column instead of
erroring. Query [`events_trino`](db/init/003_trino_ip_views.sql) /
`js_events_trino` from Trino instead of `events`/`js_events` directly — same
columns, with `src_ip` cast to text.

## Setup

```bash
cp .env.example .env
```

Edit `.env`:
- `PG_PASSWORD` — set a real secret.
- `TAILSCALE_IP` — this host's tailnet IP (`tailscale ip -4`). Postgres binds
  only to this address.
- `BIND_IP` — optional. IP the honeypot listeners (sip/ami/magnusbilling/
  cowrie) bind to; defaults to `0.0.0.0` (all interfaces) if unset. Set this
  to pin the decoys to one interface on a multi-homed host.

```bash
docker compose up -d --build
```

## Operational notes

- Every honeypot listener binds its real port on all interfaces by default
  (override with `BIND_IP` to pin to one interface). Only Postgres is
  restricted to the tailnet — don't expose 5432 publicly.
- Per-IP rate limiting ([common/ratelimit.py](common/ratelimit.py)) caps
  attempts/connections per source IP and temporarily bans noisy scanners.
  In-memory per-process only, not shared across restarts.
- SIP is UDP: like any UDP service, source IPs aren't verifiable, so it
  carries some inherent reflection/amplification risk. Responses are kept
  small and rate-limited.
- SIP auth attempts are logged as raw Digest fields (realm/nonce/response),
  not plaintext — crack offline (e.g. hashcat mode 5500) if needed. AMI logs
  plaintext credentials directly; the web login's `password` field is
  whatever the client sent, which for a real MagnusBilling client is an
  uppercase SHA1 hash, not plaintext (see below).
- `magnusbilling-honeypot` serves an unmodified copy of MagnusBilling's real
  boot page and replicates its actual `index.php/authentication/login`
  request/response contract (client-side `SHA1(password)`, exact failure
  JSON) instead of a generic fake login form — see
  [services/magnusbilling-honeypot/NOTICE.md](services/magnusbilling-honeypot/NOTICE.md)
  for where each piece came from.
- Containers run as non-root with `cap_drop: ALL`, `no-new-privileges`, and
  read-only root filesystems, except Cowrie (needs to persist session/
  download data).
- No TLS/443 configured.

## Verifying a deployment

```bash
docker compose exec postgres psql -U "$PG_USER" -d "$PG_DATABASE" \
  -c "SELECT ts, source, event_type, host(src_ip), username, password FROM events ORDER BY ts DESC LIMIT 20;"
```
