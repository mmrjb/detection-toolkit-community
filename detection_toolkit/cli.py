"""Command line: ``python -m detection_toolkit {init-db,serve,check-config}``."""
from __future__ import annotations

import argparse
import ipaddress
import sys
from typing import Any, Dict, List, Optional

from .config import APP_NAME, APP_VERSION, load_settings, parse_port


def run_init_db(settings: Dict[str, Any], reset: bool = False) -> int:
    from .db import init_database
    try:
        summary = init_database(settings, reset=reset)
    except FileExistsError as exc:
        print(f"init-db: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError) as exc:
        print(f"init-db failed: {exc}", file=sys.stderr)
        return 1
    print(f"{APP_NAME} {APP_VERSION}: database ready at {summary['database']}")
    for key in ("rules", "data_sources", "event_types", "technique_requirements", "threat_reports",
                "demo_events", "plans"):
        print(f"  {key.replace('_', ' ')}: {summary.get(key, 0)}")
    if summary.get("secret_key_file_created"):
        print(f"  secret key written to {settings['DTK_SECRET_KEY_FILE']} (mode 0600)")
    return 0


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def run_serve(settings: Dict[str, Any], host: Optional[str], port: Optional[str]) -> int:
    from . import create_app
    from .db import schema_state

    host = host or settings["DTK_HOST"]
    try:
        port_number = parse_port(port) if port is not None else settings["DTK_PORT"]
    except ValueError as exc:
        print(f"serve: {exc}", file=sys.stderr)
        return 2
    state = schema_state(settings["DTK_DB_PATH"])
    if state == "busy":
        print(f"serve: the database at {settings['DTK_DB_PATH']} is locked by another process. Try again.", file=sys.stderr)
        return 1
    if state != "ok":
        print(f"serve: the database at {settings['DTK_DB_PATH']} is {state}. "
              "Run `python -m detection_toolkit init-db` first.", file=sys.stderr)
        return 1
    if not _is_loopback(host):
        print(f"warning: binding to {host} exposes this demo beyond this machine. It has no login. "
              "Add the host name you will browse with to DTK_TRUSTED_HOSTS.", file=sys.stderr)
    try:
        app = create_app()
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    browse_host = f"[{host}]" if ":" in host else host
    trusted = settings["TRUSTED_HOSTS"]
    if trusted is not None and browse_host not in trusted and not (host in ("0.0.0.0", "::") and "localhost" in trusted):
        print(f"warning: {browse_host} is not in DTK_TRUSTED_HOSTS ({', '.join(trusted)}); requests that use it "
              "will be refused. Browse with a listed name or add it.", file=sys.stderr)
    print(f"{APP_NAME} {APP_VERSION} on http://{browse_host}:{port_number}/  (Ctrl+C to stop)")
    app.run(host=host, port=port_number, debug=False, use_reloader=False)
    return 0


def run_check_config(settings: Dict[str, Any]) -> int:
    from .config import secret_key_source
    from .db import schema_state
    for key in ("DTK_DATA_DIR", "DTK_DB_PATH", "DTK_SECRET_KEY_FILE", "DTK_HOST", "DTK_PORT", "TRUSTED_HOSTS",
                "DTK_LOG_LEVEL"):
        print(f"{key} = {settings[key]}")
    print(f"database state = {schema_state(settings['DTK_DB_PATH'])}")
    try:
        print(f"secret key = {secret_key_source(settings)}")  # the key itself is never printed
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m detection_toolkit", description=f"{APP_NAME} {APP_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init-db", help="create the SQLite database from the bundled demo data")
    init.add_argument("--reset", action="store_true", help="rebuild an existing database (deletes your rule plans)")
    serve = sub.add_parser("serve", help="start the local web server")
    serve.add_argument("--host", help="bind address (default: DTK_HOST or 127.0.0.1)")
    serve.add_argument("--port", help="port (default: DTK_PORT or 5000)")
    sub.add_parser("check-config", help="print the resolved settings and the database state")
    args = parser.parse_args(argv)
    try:
        settings = load_settings()
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.command == "init-db":
        return run_init_db(settings, reset=args.reset)
    if args.command == "serve":
        return run_serve(settings, args.host, args.port)
    return run_check_config(settings)
