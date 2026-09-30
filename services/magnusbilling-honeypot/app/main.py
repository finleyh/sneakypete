from __future__ import annotations

import logging
import os
import sys

sys.path.insert(0, "/app/common")

from db import log_event  # noqa: E402

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.templating import Jinja2Templates

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("honeypot.web")

VERSION_BANNER = os.environ.get("MAGNUSBILLING_VERSION_BANNER", "MagnusBilling 7.3.0")
PHP_BANNER = os.environ.get("PHP_VERSION_BANNER", "PHP/7.4.33")
APACHE_BANNER = os.environ.get("APACHE_VERSION_BANNER", "Apache/2.4.41 (Ubuntu)")

templates = Jinja2Templates(directory="/app/app/templates")

USERNAME_FIELDS = ("username", "user", "login")
PASSWORD_FIELDS = ("password", "pass", "pwd")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def log_request(request: Request, event_type: str, **extra_fields) -> None:
    await log_event(
        source="magnusbilling",
        event_type=event_type,
        src_ip=client_ip(request),
        src_port=request.client.port if request.client else None,
        dst_port=int(os.environ.get("WEB_PORT", "80")),
        raw=f"{request.method} {request.url.path}?{request.url.query}",
        extra={
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query),
            "user_agent": request.headers.get("user-agent"),
            **extra_fields,
        },
    )


async def index(request: Request) -> Response:
    return RedirectResponse(url="/index.php")


async def login_page(request: Request) -> Response:
    error = None

    if request.method == "POST":
        form = await request.form()
        username = next((form.get(f) for f in USERNAME_FIELDS if form.get(f)), None)
        password = next((form.get(f) for f in PASSWORD_FIELDS if form.get(f)), None)

        await log_event(
            source="magnusbilling", event_type="auth_attempt",
            src_ip=client_ip(request), src_port=request.client.port if request.client else None,
            dst_port=int(os.environ.get("WEB_PORT", "80")),
            username=str(username) if username is not None else None,
            password=str(password) if password is not None else None,
            success=False,
            raw=f"POST {request.url.path}",
            extra={"user_agent": request.headers.get("user-agent")},
        )
        error = "Invalid username or password"
    else:
        await log_request(request, "probe")

    resp = templates.TemplateResponse(
        request, "login.html",
        {"error": error, "version": VERSION_BANNER},
    )
    resp.headers["Server"] = APACHE_BANNER
    resp.headers["X-Powered-By"] = PHP_BANNER
    return resp


async def catch_all(request: Request) -> Response:
    await log_request(request, "probe")
    resp = Response(status_code=404, content="Not Found")
    resp.headers["Server"] = APACHE_BANNER
    resp.headers["X-Powered-By"] = PHP_BANNER
    return resp


routes = [
    Route("/", index, methods=["GET"]),
    Route("/index.php", login_page, methods=["GET", "POST"]),
    Route("/{path:path}", catch_all, methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]),
]

app = Starlette(routes=routes)
