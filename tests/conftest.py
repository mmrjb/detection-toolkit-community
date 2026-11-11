"""Fixtures: every test gets its own data directory and a freshly initialized demo database."""
import pytest

from detection_toolkit import create_app
from detection_toolkit.db import init_database
from detection_toolkit.seed import rule_uid

POWERSHELL_RULE = rule_uid("dtk-demo", "win_proc_creation_powershell_encoded_command.yml")
SCHTASKS_RULE = rule_uid("dtk-demo", "win_proc_creation_schtasks_user_writable_path.yml")


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("DTK_DATA_DIR", str(tmp_path / "data"))
    for name in ("DTK_DB_PATH", "DTK_SECRET_KEY", "DTK_TRUSTED_HOSTS", "DTK_PORT", "DTK_HOST"):
        monkeypatch.delenv(name, raising=False)
    application = create_app({"TESTING": True, "SECRET_KEY": "test-secret-key-for-pytest-only-0123456789"})
    init_database(application.config)
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def csrf(client):
    client.get("/plans/new")
    with client.session_transaction() as session:
        return session["csrf_token"]
