from __future__ import annotations

import asyncio
import logging
import os
import sys
import time

sys.path.insert(0, "/app/common")

from db import log_event  # noqa: E402
from ratelimit import PerIpLimiter  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("honeypot.ami")

AMI_PORT = int(os.environ.get("AMI_PORT", "5038"))
BANNER = os.environ.get("AMI_VERSION_BANNER", "Asterisk Call Manager/8.4.0")
ASTERISK_BANNER = os.environ.get("ASTERISK_VERSION_BANNER", "Asterisk PBX 18.9.0")
READ_TIMEOUT = 30.0
MAX_FAILED_LOGINS = 3
MAX_ACTIONS_PER_CONN = 10
MAX_AUTHENTICATED_ACTIONS = 40

limiter = PerIpLimiter(max_attempts=30, window_seconds=60.0, ban_seconds=300.0, max_concurrent_per_ip=3)

# Real-world AMI default credentials attackers actually try -- most notably
# admin/amp111, FreePBX's long-infamous default manager.conf secret. Only
# these succeed; everything else is still rejected like before. Override
# with AMI_DEFAULT_CREDS="user1:pass1,user2:pass2" (comma-separated pairs).
def _load_default_creds() -> set[tuple[str, str]]:
    raw = os.environ.get("AMI_DEFAULT_CREDS")
    if raw:
        pairs = set()
        for item in raw.split(","):
            if ":" in item:
                u, _, p = item.partition(":")
                pairs.add((u.strip(), p.strip()))
        return pairs
    return {
        ("admin", "amp111"),
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "asterisk"),
    }


DEFAULT_CREDS = _load_default_creds()

# A small fake PBX topology so Originate/SIPpeers etc. have something
# plausible to reference -- real-looking enough to pull an attacker into
# actually attempting toll fraud rather than disconnecting immediately.
# Each connection gets its own mutable copy (see session_peers in
# handle_client) so a peer/extension added via UpdateConfig shows up in that
# same session's later SIPpeers/Command output, without leaking across
# sessions or needing real persistence.
BASE_PEERS = [
    {"name": "100", "ip": "-none-", "status": "Unmonitored"},
    {"name": "101", "ip": "-none-", "status": "Unmonitored"},
    {"name": "6002", "ip": "-none-", "status": "Unmonitored"},
]


def parse_packet(block: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in block.split("\r\n"):
        if not line.strip() or ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip().lower()] = value.strip()
    return fields


def _actionid_suffix(fields: dict[str, str]) -> bytes:
    actionid = fields.get("actionid")
    return f"ActionID: {actionid}\r\n".encode() if actionid else b""


def handle_originate(fields: dict[str, str], peers: list[dict[str, str]]) -> bytes:
    resp = b"Response: Success\r\n" + _actionid_suffix(fields) + b"Message: Originate successfully queued\r\n\r\n"
    return resp


def handle_command(fields: dict[str, str], peers: list[dict[str, str]]) -> bytes:
    command = (fields.get("command") or "").strip().lower()
    if command in ("core show version", "show version"):
        output = ASTERISK_BANNER
    elif command in ("sip show peers", "pjsip show endpoints"):
        output = "\n".join(f"{p['name']}  {p['ip']}  {p['status']}" for p in peers)
    else:
        output = ""
    body = f"Response: Follows\r\n".encode() + _actionid_suffix(fields)
    body += b"Privilege: Command\r\n"
    if output:
        body += output.encode() + b"\r\n"
    body += b"--END COMMAND--\r\n\r\n"
    return body


def handle_sippeers(fields: dict[str, str], peers: list[dict[str, str]]) -> bytes:
    body = b"Response: Success\r\n" + _actionid_suffix(fields) + b"Message: Peer status list will follow\r\n\r\n"
    for peer in peers:
        body += (
            b"Event: PeerEntry\r\n"
            + _actionid_suffix(fields)
            + b"Channeltype: SIP\r\n"
            + f"ObjectName: {peer['name']}\r\n".encode()
            + b"ChanObjectType: peer\r\n"
            + f"IPaddress: {peer['ip']}\r\n".encode()
            + b"IPport: 0\r\n"
            + b"Dynamic: yes\r\n"
            + f"Status: {peer['status']}\r\n".encode()
            + b"\r\n"
        )
    body += (
        b"Event: PeerlistComplete\r\n"
        + _actionid_suffix(fields)
        + b"EventList: Complete\r\n"
        + f"ListItems: {len(peers)}\r\n\r\n".encode()
    )
    return body


def handle_coreshowchannels(fields: dict[str, str], peers: list[dict[str, str]]) -> bytes:
    # No simulated calls are ever actually active, so this is always empty --
    # which happens to be the realistic answer for a box nobody's routing
    # real traffic through yet.
    return (
        b"Response: Success\r\n"
        + _actionid_suffix(fields)
        + b"Message: Channels will follow\r\n\r\n"
        + b"Event: CoreShowChannelsComplete\r\n"
        + _actionid_suffix(fields)
        + b"EventList: Complete\r\n"
        + b"ListItems: 0\r\n\r\n"
    )


def handle_status(fields: dict[str, str], peers: list[dict[str, str]]) -> bytes:
    return (
        b"Response: Success\r\n"
        + _actionid_suffix(fields)
        + b"Message: Status will follow\r\n\r\n"
        + b"Event: StatusComplete\r\n"
        + _actionid_suffix(fields)
        + b"Items: 0\r\n\r\n"
    )


def handle_updateconfig(fields: dict[str, str], peers: list[dict[str, str]]) -> bytes:
    # Real AMI UpdateConfig takes numbered Action-NNNNNN/Cat-NNNNNN/
    # Var-NNNNNN/Value-NNNNNN tuples to add/modify config file sections --
    # this is the actual mechanism attackers use to plant a backdoor
    # peer/extension. We don't write any real config, but we do add the
    # category name to this session's fake peer list, so a follow-up
    # SIPpeers/Command genuinely reflects whatever they just "added".
    existing = {p["name"] for p in peers}
    for key, value in fields.items():
        if key.startswith("cat-") and value and value not in existing:
            peers.append({"name": value, "ip": "-none-", "status": "Unmonitored"})
            existing.add(value)
    return (
        b"Response: Success\r\n"
        + _actionid_suffix(fields)
        + b"Message: The requested update was successful\r\n\r\n"
    )


def handle_ping(fields: dict[str, str], peers: list[dict[str, str]]) -> bytes:
    return (
        b"Response: Success\r\n"
        + _actionid_suffix(fields)
        + b"Ping: Pong\r\n"
        + f"Timestamp: {time.time():.6f}\r\n\r\n".encode()
    )


def handle_corestatus(fields: dict[str, str], peers: list[dict[str, str]]) -> bytes:
    return (
        b"Response: Success\r\n"
        + _actionid_suffix(fields)
        + f"CoreStartupTime: {ASTERISK_BANNER}\r\n".encode()
        + b"CoreReloadTime: 00:00:00\r\n"
        + b"CoreCurrentCalls: 0\r\n\r\n"
    )


# Action name (lowercased) -> handler. Anything authenticated but not listed
# here still gets a generic plausible success below, rather than an error --
# the goal is to keep the session going so we see what they try next, not to
# faithfully implement the whole AMI action set. Every handler takes
# (fields, session_peers) even if it ignores one of them, so dispatch below
# stays uniform.
AUTHENTICATED_HANDLERS = {
    "originate": handle_originate,
    "command": handle_command,
    "sippeers": handle_sippeers,
    "pjsipshowendpoints": handle_sippeers,
    "ping": handle_ping,
    "corestatus": handle_corestatus,
    "coreshowchannels": handle_coreshowchannels,
    "status": handle_status,
    "updateconfig": handle_updateconfig,
}


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
    authenticated = False
    session_peers = list(BASE_PEERS)
    buf = ""

    try:
        writer.write(f"{BANNER}\r\n".encode())
        await writer.drain()

        while True:
            action_cap = MAX_AUTHENTICATED_ACTIONS if authenticated else MAX_ACTIONS_PER_CONN
            if actions_handled >= action_cap:
                break
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

                if action == "login" and not authenticated:
                    username = fields.get("username")
                    secret = fields.get("secret")
                    success = (username, secret) in DEFAULT_CREDS
                    await log_event(
                        source="ami", event_type="auth_attempt", src_ip=ip, src_port=port, dst_port=AMI_PORT,
                        username=username, password=secret, success=success, raw=block,
                        extra={"actionid": fields.get("actionid")},
                    )
                    if success:
                        authenticated = True
                        writer.write(b"Response: Success\r\n" + _actionid_suffix(fields) + b"Message: Authentication accepted\r\n\r\n")
                        await writer.drain()
                    else:
                        writer.write(b"Response: Error\r\n" + _actionid_suffix(fields) + b"Message: Authentication failed\r\n\r\n")
                        await writer.drain()
                        failed_logins += 1
                        if failed_logins >= MAX_FAILED_LOGINS:
                            writer.close()
                            return
                elif authenticated:
                    await log_event(
                        source="ami", event_type="session_action", src_ip=ip, src_port=port, dst_port=AMI_PORT,
                        raw=block, extra={"action": fields.get("action"), "fields": fields},
                    )
                    if action == "logoff":
                        writer.write(b"Response: Goodbye\r\n" + _actionid_suffix(fields) + b"Message: Thanks for all the fish.\r\n\r\n")
                        await writer.drain()
                        writer.close()
                        return
                    handler = AUTHENTICATED_HANDLERS.get(action)
                    if handler:
                        writer.write(handler(fields, session_peers))
                    else:
                        writer.write(b"Response: Success\r\n" + _actionid_suffix(fields) + b"Message: Action completed\r\n\r\n")
                    await writer.drain()
                else:
                    await log_event(
                        source="ami", event_type="probe", src_ip=ip, src_port=port, dst_port=AMI_PORT,
                        raw=block, extra={"action": fields.get("action")},
                    )
                    writer.write(b"Response: Error\r\nMessage: Authentication required\r\n\r\n")
                    await writer.drain()

                action_cap = MAX_AUTHENTICATED_ACTIONS if authenticated else MAX_ACTIONS_PER_CONN
                if actions_handled >= action_cap:
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
