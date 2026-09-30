from __future__ import annotations

import asyncio
import json
import logging
import os
import sys

sys.path.insert(0, "/app/common")

from db import log_event  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("honeypot.ssh-shipper")

LOG_PATH = os.environ.get("COWRIE_JSON_LOG", "/cowrie-logs/cowrie.json")
SSH_EXTERNAL_PORT = int(os.environ.get("SSH_EXTERNAL_PORT", "22"))
POLL_SECONDS = 1.0

# eventid -> (event_type, needs auth fields)
AUTH_EVENTS = {"cowrie.login.success": True, "cowrie.login.failed": False}


async def handle_line(line: str) -> None:
    line = line.strip()
    if not line:
        return
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return

    eventid = rec.get("eventid", "")
    src_ip = rec.get("src_ip")
    if not src_ip:
        return
    session_id = rec.get("session")

    if eventid == "cowrie.session.connect":
        await log_event(
            source="ssh", event_type="connection", src_ip=src_ip,
            src_port=rec.get("src_port"), dst_port=SSH_EXTERNAL_PORT,
            session_id=session_id, extra={"eventid": eventid},
        )
    elif eventid in AUTH_EVENTS:
        await log_event(
            source="ssh", event_type="auth_attempt", src_ip=src_ip,
            dst_port=SSH_EXTERNAL_PORT, session_id=session_id,
            username=rec.get("username"), password=rec.get("password"),
            success=AUTH_EVENTS[eventid], extra={"eventid": eventid},
        )
    elif eventid == "cowrie.command.input":
        await log_event(
            source="ssh", event_type="command", src_ip=src_ip,
            dst_port=SSH_EXTERNAL_PORT, session_id=session_id,
            raw=rec.get("input"), extra={"eventid": eventid},
        )
    elif eventid == "cowrie.session.closed":
        await log_event(
            source="ssh", event_type="session_close", src_ip=src_ip,
            dst_port=SSH_EXTERNAL_PORT, session_id=session_id,
            extra={"eventid": eventid, "duration": rec.get("duration")},
        )
    elif eventid == "cowrie.session.file_download":
        await log_event(
            source="ssh", event_type="file_download", src_ip=src_ip,
            dst_port=SSH_EXTERNAL_PORT, session_id=session_id,
            extra={"eventid": eventid, "url": rec.get("url"), "shasum": rec.get("shasum")},
        )
    else:
        await log_event(
            source="ssh", event_type="probe", src_ip=src_ip,
            dst_port=SSH_EXTERNAL_PORT, session_id=session_id,
            raw=line, extra={"eventid": eventid},
        )


async def tail_file(path: str) -> None:
    while not os.path.exists(path):
        logger.info("waiting for cowrie log file to appear at %s", path)
        await asyncio.sleep(POLL_SECONDS)

    f = open(path, "r")
    f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    logger.info("tailing %s", path)

    while True:
        line = f.readline()
        if line:
            await handle_line(line)
            continue

        await asyncio.sleep(POLL_SECONDS)

        try:
            current_inode = os.stat(path).st_ino
        except FileNotFoundError:
            continue

        if current_inode != inode:
            logger.info("log file rotated, reopening")
            f.close()
            f = open(path, "r")
            inode = os.fstat(f.fileno()).st_ino


async def main() -> None:
    await tail_file(LOG_PATH)


if __name__ == "__main__":
    asyncio.run(main())
