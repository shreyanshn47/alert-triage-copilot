"""retrieve(alert, tenant): the context an LLM gets for one alert."""

import re
from pathlib import PurePath

from app.retrieval.embed import EmbedderLike
from app.retrieval.store import ChunkStore, Hit
from app.schemas import ParsedAlert

__all__ = ["Hit", "query_text", "retrieve"]

_SID = re.compile(r"S-1-5-21(?:-\d+){3,4}", re.IGNORECASE)


def query_text(alert: ParsedAlert) -> str:
    """The text we embed for an alert.

    Includes what the alert DID (event type, process, command or detail). Leaves out host,
    user and timestamps: they differ per environment and say nothing about the technique.
    """
    process = PurePath((alert.process or "").replace("\\", "/")).name
    parts = [f"event: {alert.event_type}"]
    if process:
        parts.append(f"process: {process}")
    if alert.command_line:
        # A Windows SID (S-1-5-21-...) identifies one machine's account, not a behaviour.
        details = _SID.sub("<sid>", alert.command_line[:600])
        parts.append(f"details: {details}")
    return "; ".join(parts)


def retrieve(
    alert: ParsedAlert,
    tenant_id: str,
    store: ChunkStore,
    embedder: EmbedderLike,
    k: int = 5,
    sources: list[str] | None = None,
) -> list[Hit]:
    """Top-k chunks for an alert, from the shared corpus plus this tenant's own chunks only."""
    if not tenant_id:
        raise ValueError("tenant_id is required")
    return store.search(tenant_id, embedder.embed_query(query_text(alert)), k, sources)
