"""Configuration for the standalone Detection Toolkit edition.

Every setting comes from a ``DTK_*`` environment variable with a safe local
default. Paths resolve from this project directory, never from another
installation, so the edition can be moved or copied as a unit.
"""
from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional

APP_NAME = "Detection Toolkit"
APP_VERSION = "0.1.0"
SCHEMA_VERSION = 1

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent
SEED_DIR = PACKAGE_DIR / "seed"
SCHEMA_FILE = PACKAGE_DIR / "schema.sql"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
DEFAULT_TRUSTED_HOSTS = "127.0.0.1,localhost"
MIN_SECRET_KEY_LENGTH = 32

logger = logging.getLogger("detection_toolkit")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _resolve(value: str, base: Path) -> Path:
    path = Path(value).expanduser()
    return (path if path.is_absolute() else base / path).resolve()


def parse_port(value: Any) -> int:
    text = str(value).strip()
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise ValueError(f"DTK_PORT must be a whole number between 1 and 65535 (got {value!r}).")
    return int(text)


def parse_trusted_hosts(value: str) -> Optional[List[str]]:
    """Comma-separated host names; '*' disables the Host header check."""
    text = (value or DEFAULT_TRUSTED_HOSTS).strip()
    if text == "*":
        return None
    hosts = [part.strip() for part in text.split(",") if part.strip()]
    return hosts or None


def load_settings() -> Dict[str, Any]:
    """Resolved settings. Reading them never creates files or directories."""
    data_dir = _resolve(_env("DTK_DATA_DIR") or "data", PROJECT_ROOT)
    db_path = _resolve(_env("DTK_DB_PATH") or "detection_toolkit.sqlite3", data_dir)
    return {
        "DTK_DATA_DIR": str(data_dir),
        "DTK_DB_PATH": str(db_path),
        "DTK_SECRET_KEY_FILE": str(data_dir / "secret_key"),
        "DTK_HOST": _env("DTK_HOST") or DEFAULT_HOST,
        "DTK_PORT": parse_port(_env("DTK_PORT") or DEFAULT_PORT),
        "TRUSTED_HOSTS": parse_trusted_hosts(_env("DTK_TRUSTED_HOSTS")),
        "DTK_LOG_LEVEL": (_env("DTK_LOG_LEVEL") or "INFO").upper(),
        "MAX_CONTENT_LENGTH": 1024 * 1024,
        "MAX_FORM_MEMORY_SIZE": 1024 * 1024,
        "SESSION_COOKIE_NAME": "dtk_public_session",
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Strict",
        "SESSION_COOKIE_SECURE": False,  # plain HTTP on the loopback interface
        "TEMPLATES_AUTO_RELOAD": False,
    }


def load_secret_key(settings: Dict[str, Any]) -> str:
    """DTK_SECRET_KEY, else the file written by init-db, else a per-process key.

    A per-process key only means that open forms stop working after a restart;
    the demo keeps no login sessions.
    """
    value = _env("DTK_SECRET_KEY")
    if value:
        if len(value) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(f"DTK_SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters.")
        return value
    path = Path(settings["DTK_SECRET_KEY_FILE"])
    try:
        stored = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        stored = ""
    except OSError as exc:
        logger.warning("Could not read %s (%s); using a per-process secret key.", path, exc)
        stored = ""
    if len(stored) >= MIN_SECRET_KEY_LENGTH:
        return stored
    logger.warning("No secret key file at %s; using a per-process key. Run init-db to create one.", path)
    return secrets.token_hex(32)


def secret_key_source(settings: Dict[str, Any]) -> str:
    """Where the secret key comes from, without revealing it. Raises ValueError for a bad DTK_SECRET_KEY."""
    value = _env("DTK_SECRET_KEY")
    if value:
        if len(value) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(f"DTK_SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters.")
        return "DTK_SECRET_KEY"
    path = Path(settings["DTK_SECRET_KEY_FILE"])
    try:
        stored = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return "per-process key (run init-db to create the key file)"
    except OSError:
        return "per-process key (the key file is not readable)"
    if len(stored) >= MIN_SECRET_KEY_LENGTH:
        return f"file {path}"
    return "per-process key (the key file is shorter than 32 characters)"


def write_secret_key_file(path: Path) -> bool:
    """Create the secret key file with mode 0600. Returns False if it already exists."""
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(secrets.token_hex(32) + "\n")
    return True
