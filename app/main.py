import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException

from app.deps import TenantId, get_store
from app.ingest import ingest
from app.migrate import migrate
from app.schemas import Alert, IngestRequest, IngestResponse
from app.store import AlertStore


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    dsn = os.environ.get("DATABASE_URL")
    if dsn:
        migrate(dsn)
    yield


app = FastAPI(title="Alert Triage Copilot", version="0.2.0", lifespan=lifespan)

Store = Annotated[AlertStore, Depends(get_store)]


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness check. Later steps can extend this with a DB ping."""
    return {"status": "ok"}


@app.post("/alerts", response_model=IngestResponse)
def post_alerts(body: IngestRequest, tenant_id: TenantId, store: Store) -> IngestResponse:
    """Ingest a batch of raw alerts. Bad records are rejected individually in the response."""
    return ingest(store, tenant_id, body.source, body.records)


@app.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: UUID, tenant_id: TenantId, store: Store) -> Alert:
    alert = store.get(tenant_id, alert_id)
    if alert is None:
        # 404 for other tenants' alerts too, so existence is not revealed across tenants.
        raise HTTPException(status_code=404, detail="alert not found")
    return alert
