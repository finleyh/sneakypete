from __future__ import annotations

import asyncio
import logging
import os
import secrets
import sys

sys.path.insert(0, "/app/common")

from db import log_event  # noqa: E402
from ratelimit import PerIpLimiter  # noqa: E402
from sip_parser import parse_authorization, parse_sip_request  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("honeypot.sip")

SIP_PORT = int(os.environ.get("SIP_PORT", "5060"))
SERVER_BANNER = os.environ.get("ASTERISK_VERSION_BANNER", "Asterisk PBX 18.9.0")
REALM = os.environ.get("SIP_REALM", "asterisk")

limiter = PerIpLimiter(max_attempts=30, window_seconds=60.0, ban_seconds=300.0)

# Methods we at least acknowledge, mirroring a default Asterisk chan_pjsip/chan_sip install.
ALLOWED_METHODS = "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, REGISTER"


def _new_nonce() -> str:
    return secrets.token_hex(16)


def _new_tag() -> str:
    return secrets.token_hex(8)


def _build_response(status_line: str, req, *, extra_headers: list[str] | None = None, body: str = "") -> bytes:
    via = req.header("via") or ""
    from_hdr = req.header("from") or ""
    to_hdr = req.header("to") or ""
    if "tag=" not in to_hdr:
        to_hdr = f"{to_hdr};tag={_new_tag()}"
    call_id = req.header("call-id") or ""
    cseq = req.header("cseq") or ""

    lines = [
        f"SIP/2.0 {status_line}",
        f"Via: {via}",
        f"From: {from_hdr}",
        f"To: {to_hdr}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq}",
        f"Server: {SERVER_BANNER}",
    ]
    if extra_headers:
        lines.extend(extra_headers)
    lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    lines.append(body)
    return ("\r\n".join(lines)).encode("utf-8")


class SipProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        ip, port = addr
        if not limiter.allow_connection(ip):
            return
        asyncio.ensure_future(self._handle(data, ip, port))

    async def _handle(self, data: bytes, ip: str, port: int) -> None:
        req = parse_sip_request(data)
        if req is None:
            return

        try:
            if req.method == "OPTIONS":
                await self._handle_options(req, ip, port)
            elif req.method == "REGISTER":
                await self._handle_register(req, ip, port)
            elif req.method == "INVITE":
                await self._handle_invite(req, ip, port)
            elif req.method == "ACK":
                # No response expected for ACK; just log it.
                await log_event(
                    source="sip", event_type="probe", src_ip=ip, src_port=port, dst_port=SIP_PORT,
                    raw=req.raw, extra={"method": req.method, "user_agent": req.header("user-agent")},
                )
            else:
                await self._handle_other(req, ip, port)
        except Exception:
            logger.exception("error handling SIP request from %s:%s", ip, port)

    async def _handle_options(self, req, ip: str, port: int) -> None:
        resp = _build_response(
            "200 OK", req,
            extra_headers=[f"Allow: {ALLOWED_METHODS}", "Accept: application/sdp"],
        )
        self.transport.sendto(resp, (ip, port))
        await log_event(
            source="sip", event_type="probe", src_ip=ip, src_port=port, dst_port=SIP_PORT,
            raw=req.raw, extra={"method": "OPTIONS", "user_agent": req.header("user-agent")},
        )

    async def _challenge_or_log_attempt(self, req, ip: str, port: int) -> bool:
        """Shared REGISTER/INVITE auth flow. Returns True if this was a completed
        (challenged) auth attempt that should now be rejected."""
        auth_header = req.header("authorization") or req.header("proxy-authorization")
        if not auth_header:
            nonce = _new_nonce()
            resp = _build_response(
                "401 Unauthorized", req,
                extra_headers=[f'WWW-Authenticate: Digest algorithm=MD5, realm="{REALM}", nonce="{nonce}", qop="auth"'],
            )
            self.transport.sendto(resp, (ip, port))
            await log_event(
                source="sip", event_type="connection", src_ip=ip, src_port=port, dst_port=SIP_PORT,
                raw=req.raw, extra={"method": req.method, "user_agent": req.header("user-agent"), "stage": "challenge_issued"},
            )
            return False

        fields = parse_authorization(auth_header)
        username = fields.get("username")
        await log_event(
            source="sip", event_type="auth_attempt", src_ip=ip, src_port=port, dst_port=SIP_PORT,
            username=username, success=False, raw=req.raw,
            extra={
                "method": req.method,
                "user_agent": req.header("user-agent"),
                "realm": fields.get("realm"),
                "nonce": fields.get("nonce"),
                "uri": fields.get("uri"),
                "response": fields.get("response"),
                "algorithm": fields.get("algorithm"),
                "cnonce": fields.get("cnonce"),
                "nc": fields.get("nc"),
                "qop": fields.get("qop"),
            },
        )
        return True

    async def _handle_register(self, req, ip: str, port: int) -> None:
        rejected = await self._challenge_or_log_attempt(req, ip, port)
        if rejected:
            resp = _build_response("403 Forbidden", req)
            self.transport.sendto(resp, (ip, port))

    async def _handle_invite(self, req, ip: str, port: int) -> None:
        rejected = await self._challenge_or_log_attempt(req, ip, port)
        if rejected:
            resp = _build_response("403 Forbidden", req)
            self.transport.sendto(resp, (ip, port))

    async def _handle_other(self, req, ip: str, port: int) -> None:
        resp = _build_response("200 OK", req)
        self.transport.sendto(resp, (ip, port))
        await log_event(
            source="sip", event_type="probe", src_ip=ip, src_port=port, dst_port=SIP_PORT,
            raw=req.raw, extra={"method": req.method, "user_agent": req.header("user-agent")},
        )


async def main() -> None:
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        SipProtocol, local_addr=("0.0.0.0", SIP_PORT)
    )
    logger.info("SIP honeypot listening on UDP 0.0.0.0:%s (banner=%r)", SIP_PORT, SERVER_BANNER)
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(main())
