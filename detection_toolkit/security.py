"""Request safety for a single-user local app.

``canonical_origin``, ``request_origin_is_allowed``, ``csrf_token``,
``security_error`` and ``enforce_csrf_and_same_origin`` are copied from the
installed app.py, minus the login and the configurable origin allowlist.
There is no login, but the session-bound CSRF token stays: a local app without
it would accept form posts from any web page the user happens to open.

``add_security_headers`` is stricter than the installed one: the edition has
no inline scripts or styles, so the CSP drops 'unsafe-inline' and the unused
CDN allowance.
"""
from __future__ import annotations

import secrets
from typing import Optional, Set
from urllib.parse import urlsplit

from flask import Flask, Response, g, jsonify, render_template, request, session
from flask.globals import request_ctx


def canonical_origin(value: str) -> Optional[str]:
    """Return a normalized web origin, or None when the value is not an origin."""
    try:
        parsed = urlsplit((value or "").strip())
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except (TypeError, ValueError):
        return None

    if (
        scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None

    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 80 if scheme == "http" else 443
    port_suffix = f":{port}" if port is not None and port != default_port else ""
    return f"{scheme}://{host}{port_suffix}"


def request_origin_is_allowed(value: Optional[str], request_origin: Optional[str], allowed_origins: Set[str]) -> bool:
    """Validate a non-opaque Origin after the synchronizer CSRF check passes."""
    raw_origin = (value or "").strip()
    if not raw_origin or raw_origin.lower() == "null":
        # An opaque Origin falls back to the synchronizer token, which already matched.
        return True
    supplied_origin = canonical_origin(raw_origin)
    accepted_origins = allowed_origins or {candidate for candidate in (request_origin,) if candidate}
    return bool(supplied_origin and supplied_origin in accepted_origins)


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def security_error(message: str, status: int):
    if request.path.startswith("/api/"):
        return jsonify({"error": message}), status
    if request_ctx.url_adapter is None:
        return Response(message, status=status, content_type="text/plain; charset=utf-8")
    if not hasattr(g, "selection"):
        g.selection = {}
    return render_template("error.html", status=status, message=message), status


def enforce_csrf_and_same_origin():
    if request.method in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return None

    fetch_site = (request.headers.get("Sec-Fetch-Site") or "").lower()
    if fetch_site == "cross-site":
        return security_error("Cross-site request blocked", 403)

    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token") or ""
    expected = session.get("csrf_token") or ""
    if not supplied or not expected or not secrets.compare_digest(supplied, expected):
        return security_error("The form's security token is missing or out of date. Reload the page and try again.", 403)

    raw_origin = request.headers.get("Origin")
    if raw_origin:
        request_origin = canonical_origin(request.host_url)
        if not request_origin_is_allowed(raw_origin, request_origin, set()):
            return security_error("Cross-origin request blocked", 403)
    return None


CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "base-uri 'none'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-src 'none'; "
    "worker-src 'none'; "
    "manifest-src 'self'"
)


def add_security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    if not request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


def init_app(app: Flask) -> None:
    app.before_request(enforce_csrf_and_same_origin)
    app.after_request(add_security_headers)
    app.jinja_env.globals["csrf_token"] = csrf_token
