from __future__ import annotations

import asyncio
import logging
import os
import sys

sys.path.insert(0, "/app/common")

from db import log_event  # noqa: E402
from ratelimit import PerIpLimiter  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("honeypot.ami")

AMI_PORT = int(os.environ.get("AMI_PORT", "5038"))
BANNER = os.environ.get("AMI_VERSION_BANNER", "Asterisk Call Manager/8.4.0")
READ_TIMEOUT = 30.0
MAX_FAILED_LOGINS = 3
MAX_ACTIONS_PER_CONN = 10

limiter = PerIpLimiter(max_attempts=30, window_seconds=60.0, ban_seconds=300.0, max_concurrent_per_ip=3)


def parse_packet(block: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in block.split("\r\n"):
        if not line.strip() or ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip().lower()] = value.strip()
    return fields


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)

    if not limiter.allow_connection(ip):
        writer.close()
        return

    limiter.connection_opened(ip)
    await log_event(source="ami", event_type="connection", src_ip=ip, src_port=port, dst_port=AMI_PORT)

    failed_logins = 0
    actions_handled = 0
    buf = ""

    try:
        writer.write(f"{BANNER}\r\n".encode())
        await writer.drain()

        while actions_handled < MAX_ACTIONS_PER_CONN:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=READ_TIMEOUT)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break

            buf += chunk.decode("utf-8", errors="replace")
            while "\r\n\r\n" in buf:
                block, buf = buf.split("\r\n\r\n", 1)
                actions_handled += 1
                fields = parse_packet(block)
                action = (fields.get("action") or "").lower()

                if action == "login":
                    username = fields.get("username")
                    secret = fields.get("secret")
                    await log_event(
                        source="ami", event_type="auth_attempt", src_ip=ip, src_port=port, dst_port=AMI_PORT,
                        username=username, password=secret, success=False, raw=block,
                        extra={"actionid": fields.get("actionid")},
                    )
                    writer.write(b"Response: Error\r\nMessage: Authentication failed\r\n\r\n")
                    await writer.drain()
                    failed_logins += 1
                    if failed_logins >= MAX_FAILED_LOGINS:
                        await writer.drain()
                        writer.close()
                        return
                else:
                    await log_event(
                        source="ami", event_type="probe", src_ip=ip, src_port=port, dst_port=AMI_PORT,
                        raw=block, extra={"action": fields.get("action")},
                    )
                    writer.write(b"Response: Error\r\nMessage: Authentication required\r\n\r\n")
                    await writer.drain()

                if actions_handled >= MAX_ACTIONS_PER_CONN:
                    break
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception:
        logger.exception("error handling AMI connection from %s:%s", ip, port)
    finally:
        limiter.connection_closed(ip)
        try:
            writer.close()
        except Exception:
            pass


async def main() -> None:
    server = await asyncio.start_server(handle_client, "0.0.0.0", AMI_PORT)
    logger.info("AMI honeypot listening on TCP 0.0.0.0:%s (banner=%r)", AMI_PORT, BANNER)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
