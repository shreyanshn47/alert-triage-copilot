"""Ingest service: parse, fingerprint, store. No HTTP in here, so it is easy to test."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from app.fingerprint import fingerprint
from app.parsers import PARSERS, ParseError
from app.schemas import Alert, IngestResponse, IngestResult
from app.store import AlertStore

GROUP_WINDOW = timedelta(minutes=10)


def ingest(
    store: AlertStore,
    tenant_id: str,
    source: str,
    records: list[Any],
    now: datetime | None = None,
) -> IngestResponse:
    """Ingest a batch. A bad record is rejected on its own and never blocks the others."""
    parser = PARSERS[source]
    now = now or datetime.now(UTC)
    results: list[IngestResult] = []

    for index, record in enumerate(records):
        try:
            parsed = parser(record, now)
        except ParseError as exc:
            results.append(IngestResult(index=index, status="rejected", error=str(exc)))
            continue

        fp = fingerprint(
            tenant_id,
            parsed.host,
            parsed.user,
            parsed.process,
            parsed.command_line,
            parsed.event_type,
        )
        alert = Alert(id=uuid4(), tenant_id=tenant_id, fingerprint=fp, **parsed.model_dump())
        stored, new_group = store.add_alert(alert, GROUP_WINDOW)
        results.append(
            IngestResult(
                index=index,
                status="ingested",
                id=stored.id,
                group_id=stored.group_id,
                new_group=new_group,
                fingerprint=fp,
            )
        )

    ingested = sum(r.status == "ingested" for r in results)
    return IngestResponse(ingested=ingested, rejected=len(results) - ingested, results=results)
