import os
import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

import pytest

from app.store import MemoryStore

REF_TIME = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
DEFAULT_DSN = "postgresql://triage:triage_dev_password@localhost:5432/triage"


def _test_database(base_dsn: str) -> str:
    """Return a DSN for `<db>_test`, creating that database if needed.

    Tests run in their own database so they can never touch real data, such as the shared
    retrieval corpus or alerts ingested by hand.
    """
    import psycopg
    from psycopg import sql

    parts = urlsplit(base_dsn)
    test_name = parts.path.lstrip("/") + "_test"
    with psycopg.connect(base_dsn, connect_timeout=2, autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (test_name,)).fetchone()
        if not exists:
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(test_name)))
    return urlunsplit(parts._replace(path="/" + test_name))


@pytest.fixture(scope="session")
def pg_dsn():
    """DSN of a reachable, migrated test database. Skips locally if there is none; fails in CI."""
    import psycopg

    from app.migrate import migrate

    explicit = os.environ.get("TEST_DATABASE_URL")
    base = explicit or os.environ.get("DATABASE_URL") or DEFAULT_DSN
    try:
        dsn = explicit or _test_database(base)
        psycopg.connect(dsn, connect_timeout=2).close()
    except psycopg.OperationalError as exc:
        if os.environ.get("CI"):
            pytest.fail(f"Postgres must be reachable in CI: {exc}")
        pytest.skip("Postgres not reachable; run `docker compose up -d db`")
    migrate(dsn)
    yield dsn
    # Remove the rows this run created (test tenants are named t-<hex>).
    with psycopg.connect(dsn) as conn:
        conn.execute("DELETE FROM alerts WHERE tenant_id LIKE 't-%'")
        conn.execute("DELETE FROM corpus_chunks WHERE tenant_id LIKE 't-%'")


@pytest.fixture(params=["memory", "postgres"])
def store(request):
    """The same store contract tests run against both implementations."""
    if request.param == "memory":
        return MemoryStore()
    from app.pg_store import PostgresStore

    return PostgresStore(request.getfixturevalue("pg_dsn"))


@pytest.fixture
def tenant() -> str:
    """A fresh tenant per test, so tests never see each other's rows in a shared database."""
    return f"t-{uuid.uuid4().hex[:12]}"


def sysmon(ts: str = "2026-11-01 10:00:00.000", **overrides):
    """A Sysmon process-create record, with overrides."""
    record = {
        "EventID": 1,
        "UtcTime": ts,
        "Computer": "WS01.corp.local",
        "User": "CORP\\alice",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile -File C:\\scripts\\patch.ps1",
        "ProcessId": 4242,
        "ProcessGuid": "{8f3c1c2e-5d1a-4c1b-9b6e-1a2b3c4d5e6f}",
    }
    record.update(overrides)
    return record
