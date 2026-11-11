"""SQLite access and one-time initialization.

``ManagedConnection``, ``connect`` and ``is_busy_error`` are copied from the
installed Detection Toolkit (services/sqlite_conn.py): foreign keys on, an
explicit busy timeout, ``sqlite3.Row`` rows, and a context manager that
commits (or rolls back) and then always closes.

Nothing here runs on import. The database is created only by
``init_database`` (``python -m detection_toolkit init-db``).
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional, Union

from flask import current_app

from .config import SCHEMA_FILE, SCHEMA_VERSION, write_secret_key_file

DEFAULT_TIMEOUT = 30.0


class ManagedConnection(sqlite3.Connection):
    """sqlite3 connection whose context manager also closes it."""

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


def connect(
    path: Union[str, Path],
    *,
    readonly: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    row_factory: Optional[Any] = sqlite3.Row,
) -> ManagedConnection:
    """Open the database with FK enforcement and an explicit busy timeout.

    ``readonly`` opens ``file:...?mode=ro`` so the connection can never take
    the write lock. ``row_factory=None`` keeps plain tuples.
    """
    target = str(path)
    if readonly:
        conn = sqlite3.connect(Path(target).resolve().as_uri() + "?mode=ro", uri=True,
                               timeout=timeout, factory=ManagedConnection)
    else:
        conn = sqlite3.connect(target, timeout=timeout, factory=ManagedConnection)
    try:
        conn.row_factory = row_factory
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(f"PRAGMA busy_timeout = {max(0, int(timeout * 1000))}")
    except BaseException:
        conn.close()
        raise
    return conn


def is_busy_error(exc: BaseException) -> bool:
    """True for SQLITE_BUSY / SQLITE_LOCKED surfaced as OperationalError."""
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    code = getattr(exc, "sqlite_errorcode", None)
    if code is not None and (code & 0xFF) in (5, 6):  # SQLITE_BUSY, SQLITE_LOCKED
        return True
    text = str(exc).lower()
    return "database is locked" in text or "database is busy" in text or "database table is locked" in text


def db() -> ManagedConnection:
    """A connection to the configured database: ``with db() as conn: ...``."""
    return connect(current_app.config["DTK_DB_PATH"])


def schema_state(path: Union[str, Path]) -> str:
    """'ok', 'missing' (no file), 'outdated' (wrong user_version), 'busy' (locked, try again) or 'unreadable'."""
    target = Path(path)
    if not target.is_file():
        return "missing"
    try:
        with connect(target, readonly=True, timeout=5.0, row_factory=None) as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
    except sqlite3.Error as exc:
        return "busy" if is_busy_error(exc) else "unreadable"
    return "ok" if version == SCHEMA_VERSION else "outdated"


def init_database(settings: Dict[str, Any], reset: bool = False) -> Dict[str, Any]:
    """Create the data directory, build a fresh database from the bundled seed and swap it in.

    The new database is built in a temporary file next to the target and moved
    into place with ``os.replace`` only after every seed row has loaded, so a
    failed run never leaves a half-initialized database behind. An existing
    database is replaced only when ``reset`` is true.
    """
    from . import seed  # local import: seed pulls in YAML parsing only when needed

    data_dir = Path(settings["DTK_DATA_DIR"])
    target = Path(settings["DTK_DB_PATH"])
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.exists() and not reset:
        raise FileExistsError(
            f"{target} already exists. Re-run with --reset to rebuild it from the bundled demo data "
            "(this deletes every rule plan you created).")
    temporary = target.with_name(target.name + ".init-tmp")
    if temporary.exists():
        temporary.unlink()
    try:
        with connect(temporary) as conn:
            conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
            summary = seed.load_all(conn)
            conn.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except BaseException:
        if temporary.exists():
            temporary.unlink()
        raise
    created_key = write_secret_key_file(Path(settings["DTK_SECRET_KEY_FILE"]))
    summary.update({"database": str(target), "secret_key_file_created": created_key})
    return summary
