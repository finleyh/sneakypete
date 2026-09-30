import json
import logging
import os

import asyncpg

logger = logging.getLogger("honeypot.db")

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            host=os.environ["PG_HOST"],
            port=int(os.environ.get("PG_PORT", "5432")),
            user=os.environ["PG_USER"],
            password=os.environ["PG_PASSWORD"],
            database=os.environ["PG_DATABASE"],
            min_size=1,
            max_size=int(os.environ.get("PG_POOL_MAX", "5")),
        )
    return _pool


async def log_event(
    *,
    source: str,
    event_type: str,
    src_ip: str,
    src_port: int | None = None,
    dst_port: int | None = None,
    username: str | None = None,
    password: str | None = None,
    success: bool | None = None,
    session_id: str | None = None,
    raw: str | None = None,
    extra: dict | None = None,
) -> None:
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO events
                    (source, event_type, src_ip, src_port, dst_port,
                     username, password, success, session_id, raw, extra)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
                """,
                source, event_type, src_ip, src_port, dst_port,
                username, password, success, session_id, raw,
                json.dumps(extra or {}),
            )
    except Exception:
        logger.exception("failed to write event to postgres (source=%s type=%s)", source, event_type)


async def log_js_event(
    *,
    src_ip: str,
    kind: str,
    src_port: int | None = None,
    user_agent: str | None = None,
    raw: str | None = None,
    data: dict | None = None,
) -> None:
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO js_events (src_ip, src_port, kind, user_agent, raw, data)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                """,
                src_ip, src_port, kind, user_agent, raw, json.dumps(data or {}),
            )
    except Exception:
        logger.exception("failed to write js_event to postgres (kind=%s)", kind)
