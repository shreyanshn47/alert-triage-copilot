"""Minimal SQL migration runner.

Applies app/migrations/NNN_name.sql files in order, once each, and records them in
schema_migrations. This is the answer to "init.sql only runs on an empty volume": schema
changes become new numbered files that run against the live database.
"""

from importlib import resources

import psycopg

_LOCK_KEY = 727_001  # arbitrary constant; one migrator at a time across API replicas


def migrate(dsn: str) -> list[str]:
    """Apply pending migrations. Returns the versions applied by this call."""
    directory = resources.files("app").joinpath("migrations")
    sql_files = (f for f in directory.iterdir() if f.name.endswith(".sql"))
    files = sorted(sql_files, key=lambda f: f.name)
    applied: list[str] = []
    with psycopg.connect(dsn) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_KEY,))
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        done = {r[0] for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
        for f in files:
            if f.name in done:
                continue
            conn.execute(f.read_text(encoding="utf-8"))
            conn.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (f.name,))
            applied.append(f.name)
    return applied
