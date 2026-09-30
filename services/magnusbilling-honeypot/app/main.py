from __future__ import annotations

import logging
import os
import sys

sys.path.insert(0, "/app/common")

from db import log_event  # noqa: E402

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("honeypot.web")

PHP_BANNER = os.environ.get("PHP_VERSION_BANNER", "PHP/7.4.33")
APACHE_BANNER = os.environ.get("APACHE_VERSION_BANNER", "Apache/2.4.41 (Ubuntu)")

STATIC_DIR = "/app/app/static"
INDEX_HTML_PATH = f"{STATIC_DIR}/index.html"

# Minimal stand-in for what the real `index.php`, loaded as <script src="index.php">
# on the boot page, would emit: it just needs to define the globals the inline
# bootstrap script in index.html reads (theme/captcha/branding config), so that
# script doesn't throw before it gets to the (already-404ing) app bundle load.
INDEX_PHP_BOOTSTRAP_JS = """
window.reCaptchaKey = '';
window.agentTitle = false;
window.agentId = false;
window.backgroundColor = '#0b1220';
window.theme = 'blue-dark';
window.wallpaper = 'wallpaper1';
window.colorMenu = 'dark';
window.lang = 'en';
window.show_signup_button = true;
"""


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def with_banners(resp: Response) -> Response:
    resp.headers["Server"] = APACHE_BANNER
    resp.headers["X-Powered-By"] = PHP_BANNER
    return resp


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
    await log_request(request, "probe")
    resp = FileResponse(INDEX_HTML_PATH, media_type="text/html")
    return with_banners(resp)


async def index_php_bootstrap(request: Request) -> Response:
    await log_request(request, "probe")
    resp = Response(content=INDEX_PHP_BOOTSTRAP_JS, media_type="application/javascript")
    return with_banners(resp)


async def init_css(request: Request) -> Response:
    await log_request(request, "probe")
    resp = FileResponse(f"{STATIC_DIR}/resources/init.css", media_type="text/css")
    return with_banners(resp)


async def locale_js(request: Request) -> Response:
    await log_request(request, "probe")
    resp = FileResponse(f"{STATIC_DIR}/locale.js", media_type="application/javascript")
    return with_banners(resp)


async def bootstrap_js(request: Request) -> Response:
    await log_request(request, "probe")
    resp = FileResponse(f"{STATIC_DIR}/bootstrap.js", media_type="application/javascript")
    return with_banners(resp)


async def authentication_login(request: Request) -> Response:
    # Mirrors the real AJAX call made by classic/src/view/main/LoginController.js:
    # Ext.Ajax.request({ url: 'index.php/authentication/login', params: { user, password: SHA1(password), key } })
    params = dict(request.query_params)
    if request.method == "POST":
        try:
            form = await request.form()
            params.update({k: v for k, v in form.items()})
        except Exception:
            pass

    username = params.get("user")
    password = params.get("password")  # the real client sends uppercase SHA1(password), not plaintext
    captcha_key = params.get("key")

    await log_event(
        source="magnusbilling", event_type="auth_attempt",
        src_ip=client_ip(request), src_port=request.client.port if request.client else None,
        dst_port=int(os.environ.get("WEB_PORT", "80")),
        username=username, password=password, success=False,
        raw=f"{request.method} {request.url.path}?{request.url.query}",
        extra={
            "user_agent": request.headers.get("user-agent"),
            "endpoint": "authentication/login",
            "captcha_key_present": bool(captcha_key),
            "password_field_note": "real client sends uppercase SHA1(password), not plaintext",
        },
    )

    # Exact response shape/text of AuthenticationController::actionLogin()'s invalid-login branch.
    resp = JSONResponse({"success": False, "msg": "Username and password combination is invalid"})
    return with_banners(resp)


async def catch_all(request: Request) -> Response:
    await log_request(request, "probe")
    resp = Response(status_code=404, content="Not Found")
    return with_banners(resp)


routes = [
    Route("/", index, methods=["GET"]),
    Route("/index.php", index_php_bootstrap, methods=["GET"]),
    Route("/resources/init.css", init_css, methods=["GET"]),
    Route("/locale.js", locale_js, methods=["GET"]),
    Route("/bootstrap.js", bootstrap_js, methods=["GET"]),
    Route("/index.php/authentication/login", authentication_login, methods=["GET", "POST"]),
    Route("/{path:path}", catch_all, methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]),
]

app = Starlette(routes=routes)
