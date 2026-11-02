"""Data shapes shared by parsers, stores and the API."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


class ParsedAlert(BaseModel):
    """What a parser extracts from one raw record. No tenant, id or group yet."""

    source: str
    timestamp: datetime  # always timezone-aware UTC
    host: str | None = None
    user: str | None = None
    process: str | None = None
    command_line: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    event_type: str
    raw: dict[str, Any]


class Alert(ParsedAlert):
    """A normalized alert as stored. group_id is assigned by the store."""

    id: UUID
    tenant_id: str
    fingerprint: str
    group_id: UUID | None = None


class IngestRequest(BaseModel):
    source: Literal["sysmon_json", "syslog"]
    records: list[Any] = Field(min_length=1, max_length=1000)


class IngestResult(BaseModel):
    index: int
    status: Literal["ingested", "rejected"]
    id: UUID | None = None
    group_id: UUID | None = None
    new_group: bool | None = None
    fingerprint: str | None = None
    error: str | None = None


class IngestResponse(BaseModel):
    ingested: int
    rejected: int
    results: list[IngestResult]
