from __future__ import annotations

import asyncio
import datetime
import logging
import os
import socket
import ssl
import sys

sys.path.insert(0, "/app/common")

from db import log_event  # noqa: E402
from ja4 import ClientHelloError, ja4, parse_client_hello, tls_version_name  # noqa: E402
from ratelimit import PerIpLimiter  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("honeypot.tls")

# TLS front for magnusbilling-honeypot. Terminates HTTPS on 443 with a
# self-signed cert (the way most real VoIP boxes run), but first peeks each
# raw ClientHello to compute its JA4 fingerprint, then proxies plain HTTP/1.1
# to the decoy with the real client IP/port and the JA4 carried in one
# X-Honeypot-Conn header. The decoy only trusts that header from inside the
# docker network, and strips any copy a client sends.

TLS_PORT = int(os.environ.get("TLS_PORT", "443"))
BACKEND_HOST = os.environ.get("BACKEND_HOST", "magnusbilling-honeypot")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "80"))
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
CERT_CN = os.environ.get("TLS_CERT_CN", "magnusbilling")
APACHE_BANNER = os.environ.get("APACHE_VERSION_BANNER", "Apache/2.4.41 (Ubuntu)")
PEEK_TIMEOUT = 5.0
HANDSHAKE_TIMEOUT = 10.0
IDLE_TIMEOUT = 30.0
MAX_HELLO = 65536
CONN_HEADER = b"X-Honeypot-Conn"

limiter = PerIpLimiter(max_attempts=60, window_seconds=60.0, ban_seconds=300.0, max_concurrent_per_ip=8)

# What Apache httpd actually says when you speak plain HTTP to its TLS port.
PLAINTEXT_400 = (
    "HTTP/1.1 400 Bad Request\r\n"
    f"Server: {APACHE_BANNER}\r\n"
    "Content-Type: text/html; charset=iso-8859-1\r\n"
    "Connection: close\r\n"
    "\r\n"
    '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
    "<html><head>\n<title>400 Bad Request</title>\n</head><body>\n"
    "<h1>Bad Request</h1>\n<p>Your browser sent a request that this server could not understand.<br />\n"
    "Reason: You're speaking plain HTTP to an SSL-enabled server port.<br />\n"
    "Instead use the HTTPS scheme to access this URL, please.<br />\n</p>\n<hr>\n"
    f"<address>{APACHE_BANNER} Server at {CERT_CN} Port {TLS_PORT}</address>\n</body></html>\n"
).encode()


class NotTLS(Exception):
    def __init__(self, data: bytes) -> None:
        super().__init__("not TLS")
        self.data = data


def ensure_cert() -> tuple[str, str]:
    # Mimics Ubuntu's default ssl-cert-snakeoil: self-signed RSA-2048, CN =
    # hostname, 10-year validity. Persisted in a volume so the cert (and its
    # fingerprint, which scanners record) stays stable across restarts like
    # a real box's would.
    cert_path = os.path.join(CERT_DIR, "cert.pem")
    key_path = os.path.join(CERT_DIR, "key.pem")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CERT_CN)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(CERT_CN)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    os.makedirs(CERT_DIR, exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    logger.info("generated self-signed cert CN=%s in %s", CERT_CN, CERT_DIR)
    return cert_path, key_path


async def peek_client_hello(loop: asyncio.AbstractEventLoop, sock: socket.socket) -> bytes:
    # MSG_PEEK leaves the bytes in the kernel buffer for the TLS layer to
    # consume afterwards, so we get the raw ClientHello without having to
    # splice it back into the SSL object ourselves.
    deadline = loop.time() + PEEK_TIMEOUT
    seen = 0
    while True:
        try:
            data = sock.recv(MAX_HELLO, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            data = b""
        if data:
            if data[0] != 0x16:
                raise NotTLS(data)
            try:
                parse_client_hello(data)
                return data
            except ClientHelloError as e:
                if not str(e).startswith("truncated") or len(data) >= MAX_HELLO:
                    raise
        if loop.time() >= deadline:
            raise asyncio.TimeoutError
        if len(data) == seen:
            await asyncio.sleep(0.02)
        seen = len(data)


def _conn_header_value(ip: str, port: int, fp: str, fp_raw: str) -> bytes:
    return f"ip={ip};port={port};proto=https;ja4={fp};ja4_r={fp_raw}".encode()


async def proxy(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, conn_header: bytes) -> None:
    backend_reader, backend_writer = await asyncio.open_connection(BACKEND_HOST, BACKEND_PORT)

    async def pump_responses() -> None:
        try:
            while True:
                chunk = await backend_reader.read(65536)
                if not chunk:
                    break
                client_writer.write(chunk)
                await client_writer.drain()
        except Exception:
            pass
        finally:
            try:
                client_writer.close()
            except Exception:
                pass

    pump = asyncio.create_task(pump_responses())
    try:
        while True:
            head = await asyncio.wait_for(client_reader.readuntil(b"\r\n\r\n"), IDLE_TIMEOUT)
            lines = head.split(b"\r\n")
            request_line = lines[0]
            headers = [h for h in lines[1:] if h and not h.lower().startswith(CONN_HEADER.lower() + b":")]

            content_length = 0
            chunked = False
            for h in headers:
                name, _, value = h.partition(b":")
                name, value = name.strip().lower(), value.strip()
                if name == b"content-length":
                    try:
                        content_length = int(value)
                    except ValueError:
                        content_length = 0
                elif name == b"transfer-encoding" and b"chunked" in value.lower():
                    chunked = True

            backend_writer.write(b"\r\n".join([request_line, *headers, CONN_HEADER + b": " + conn_header]) + b"\r\n\r\n")
            if chunked:
                while True:
                    size_line = await client_reader.readuntil(b"\r\n")
                    backend_writer.write(size_line)
                    size = int(size_line.split(b";")[0].strip() or b"0", 16)
                    backend_writer.write(await client_reader.readexactly(size + 2))
                    if size == 0:
                        break
            else:
                remaining = content_length
                while remaining > 0:
                    chunk = await client_reader.read(min(65536, remaining))
                    if not chunk:
                        raise ConnectionError("client closed mid-body")
                    backend_writer.write(chunk)
                    remaining -= len(chunk)
            await backend_writer.drain()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError, ConnectionError, ValueError):
        pass
    finally:
        pump.cancel()
        try:
            backend_writer.close()
        except Exception:
            pass


async def handle(loop: asyncio.AbstractEventLoop, ctx: ssl.SSLContext, sock: socket.socket, addr: tuple) -> None:
    ip, port = addr[0], addr[1]
    if not limiter.allow_connection(ip):
        sock.close()
        return
    limiter.connection_opened(ip)
    sock.setblocking(False)
    sock_owned = True
    base = dict(source="magnusbilling", src_ip=ip, src_port=port, dst_port=TLS_PORT)

    try:
        try:
            raw = await peek_client_hello(loop, sock)
        except NotTLS as e:
            await log_event(
                **base, event_type="probe", raw=e.data[:512].decode("latin-1"),
                extra={"scheme": "https", "note": "plain HTTP on the TLS port"},
            )
            await loop.sock_sendall(sock, PLAINTEXT_400)
            return
        except asyncio.TimeoutError:
            await log_event(**base, event_type="connection", extra={"scheme": "https", "note": "no ClientHello before timeout"})
            return

        try:
            hello = parse_client_hello(raw)
            fp, fp_raw = ja4(hello)
        except ClientHelloError as e:
            await log_event(
                **base, event_type="probe", raw=raw[:512].decode("latin-1"),
                extra={"scheme": "https", "note": f"unparseable ClientHello: {e}"},
            )
            return

        meta = {
            "scheme": "https",
            "ja4": fp,
            "ja4_r": fp_raw,
            "tls_version": tls_version_name(hello),
            "sni": hello["sni"],
            "alpn": [a.decode("latin-1") for a in hello["alpn"]],
        }

        reader = asyncio.StreamReader(limit=65536)
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            transport, _ = await loop.connect_accepted_socket(
                lambda: protocol, sock, ssl=ctx, ssl_handshake_timeout=HANDSHAKE_TIMEOUT,
            )
        except Exception as e:
            await log_event(**base, event_type="tls_handshake", extra={**meta, "handshake": f"failed: {type(e).__name__}: {e}"[:300]})
            return
        sock_owned = False

        ssl_obj = transport.get_extra_info("ssl_object")
        await log_event(**base, event_type="tls_handshake", extra={
            **meta,
            "handshake": "ok",
            "negotiated": ssl_obj.version() if ssl_obj else None,
            "cipher": ssl_obj.cipher()[0] if ssl_obj and ssl_obj.cipher() else None,
        })

        writer = asyncio.StreamWriter(transport, protocol, reader, loop)
        try:
            await proxy(reader, writer, _conn_header_value(ip, port, fp, fp_raw))
        finally:
            try:
                writer.close()
            except Exception:
                pass
    except Exception:
        logger.exception("error handling TLS connection from %s:%s", ip, port)
    finally:
        limiter.connection_closed(ip)
        if sock_owned:
            try:
                sock.close()
            except Exception:
                pass


async def main() -> None:
    cert_path, key_path = ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.set_alpn_protocols(["http/1.1"])

    loop = asyncio.get_running_loop()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", TLS_PORT))
    srv.listen(128)
    srv.setblocking(False)
    logger.info("TLS front listening on 0.0.0.0:%s -> %s:%s (cert CN=%s)", TLS_PORT, BACKEND_HOST, BACKEND_PORT, CERT_CN)
    while True:
        sock, addr = await loop.sock_accept(srv)
        asyncio.create_task(handle(loop, ctx, sock, addr))


if __name__ == "__main__":
    asyncio.run(main())
