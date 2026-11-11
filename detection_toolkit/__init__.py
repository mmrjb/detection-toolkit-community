"""Detection Toolkit v0.1: a standalone, local edition with six views and bundled demo data.

``create_app`` builds the Flask app. Creating the app never creates or changes
the database; run ``python -m detection_toolkit init-db`` once first.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import click
from flask import Flask, Response, g, jsonify, make_response, render_template, request
from flask.globals import request_ctx
from werkzeug.exceptions import SecurityError

from .config import APP_NAME, APP_VERSION, load_secret_key, load_settings

ERROR_MESSAGES = {
    400: "The request could not be read.",
    403: "This request was blocked.",
    404: "That page does not exist.",
    405: "That action is not allowed on this page.",
    413: "The submitted form is too large. Paste one rule of up to 256 KiB.",
    500: "Something went wrong. The details are in the server log.",
}
EXEMPT_ENDPOINTS = {"static", "main.healthz"}


def create_app(test_config: Optional[Dict[str, Any]] = None) -> Flask:
    app = Flask(__name__)
    app.config.update(load_settings())
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = load_secret_key(app.config)
    logging.basicConfig(level=getattr(logging, str(app.config.get("DTK_LOG_LEVEL", "INFO")), logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    from . import attack, security, views
    from .db import is_busy_error, schema_state

    security.init_app(app)

    @app.before_request
    def require_initialized_database():
        if request.endpoint in EXEMPT_ENDPOINTS or request_ctx.url_adapter is None:
            return None  # static files, health check, or a request Flask could not route (handled below)
        state = schema_state(app.config["DTK_DB_PATH"])
        if state == "busy":
            return render_error(503, "The database is busy. Try again in a moment.")
        if state != "ok":
            return render_template("not_initialized.html", state=state, minimal=True,
                                   db_path=app.config["DTK_DB_PATH"]), 503
        views.load_selection()
        return None

    app.register_blueprint(views.bp)
    app.jinja_env.globals.update(ctx_url=views.ctx_url, app_name=APP_NAME, app_version=APP_VERSION,
                                 technique_url=attack.technique_url)

    def render_error(status: int, message: Optional[str] = None):
        text = message or ERROR_MESSAGES.get(status, ERROR_MESSAGES[500])
        if request.path.startswith("/api/") or request.endpoint == "main.healthz":
            return jsonify({"error": text}), status
        if request_ctx.url_adapter is None:  # no URL building possible, e.g. an untrusted Host header
            return Response(text, status=status, mimetype="text/plain")
        if not hasattr(g, "selection"):
            g.selection = {}
        return render_template("error.html", status=status, message=text), status

    for code in (400, 403, 404, 413):
        app.register_error_handler(code, lambda exc, code=code: render_error(code))

    @app.errorhandler(405)
    def method_not_allowed(exc):
        response = make_response(render_error(405))
        for key, value in exc.get_headers():
            if key.lower() == "allow":
                response.headers[key] = value
        return response

    @app.errorhandler(SecurityError)
    def untrusted_host(exc):
        return Response("This host name is not allowed. Browse with a name listed in DTK_TRUSTED_HOSTS "
                        "(default: 127.0.0.1 or localhost), or add the name you use to DTK_TRUSTED_HOSTS.",
                        status=400, mimetype="text/plain")

    @app.errorhandler(500)
    def internal_error(exc):
        original = getattr(exc, "original_exception", None) or exc
        if is_busy_error(original):
            return render_error(503, "The database is busy. Try again in a moment.")
        app.logger.error("Unhandled error on %s %s", request.method, request.path, exc_info=original)
        return render_error(500)

    @app.cli.command("init-db")
    @click.option("--reset", is_flag=True, help="Rebuild an existing database (deletes your rule plans).")
    def init_db_command(reset: bool) -> None:
        """Create the database from the bundled demo data."""
        from .cli import run_init_db
        raise SystemExit(run_init_db(app.config, reset=reset))

    return app
