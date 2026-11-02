"""FastAPI dependencies. Tests replace get_store via app.dependency_overrides."""

import os
from functools import lru_cache
from typing import Annotated

from fastapi import Header, HTTPException

from app.pg_store import PostgresStore
from app.store import AlertStore


@lru_cache
def _postgres_store(dsn: str) -> PostgresStore:
    return PostgresStore(dsn)


def get_store() -> AlertStore:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise HTTPException(status_code=503, detail="DATABASE_URL is not configured")
    return _postgres_store(dsn)


# Stand-in for authentication. In a real deployment the tenant comes from the API key or
# token, never from a header the client chooses.
TenantId = Annotated[
    str,
    Header(alias="X-Tenant-ID", pattern=r"^[A-Za-z0-9_-]{1,64}$"),
]
