"""Alert storage interface and the in-memory implementation.

Grouping lives inside add_alert so that finding a group and inserting into it happen
atomically. The Postgres store implements the same contract; tests/test_stores.py runs the
same cases against both so they cannot drift apart.

Grouping rule: an alert joins an existing group for the same (tenant, fingerprint) when its
timestamp is within `window` of that group's earliest alert. Otherwise it starts a new group.
Anchoring at the earliest alert keeps a group bounded to one window, where chaining from the
latest alert would let a steady beacon grow one group forever.
"""

import threading
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from app.schemas import Alert


class AlertStore(Protocol):
    def add_alert(self, alert: Alert, window: timedelta) -> tuple[Alert, bool]:
        """Store the alert, assign its group_id, return (stored alert, started_new_group)."""
        ...

    def get(self, tenant_id: str, alert_id: UUID) -> Alert | None:
        """Fetch one alert. Returns None for unknown ids and for other tenants' alerts."""
        ...


class MemoryStore:
    def __init__(self) -> None:
        self._alerts: dict[UUID, Alert] = {}
        self._lock = threading.Lock()

    def _find_group(
        self, tenant_id: str, fingerprint: str, ts: datetime, window: timedelta
    ) -> UUID | None:
        earliest: dict[UUID, datetime] = {}
        for a in self._alerts.values():
            if a.tenant_id == tenant_id and a.fingerprint == fingerprint and a.group_id:
                if a.group_id not in earliest or a.timestamp < earliest[a.group_id]:
                    earliest[a.group_id] = a.timestamp
        candidates = [(first, gid) for gid, first in earliest.items() if abs(ts - first) <= window]
        return max(candidates)[1] if candidates else None

    def add_alert(self, alert: Alert, window: timedelta) -> tuple[Alert, bool]:
        with self._lock:
            group_id = self._find_group(alert.tenant_id, alert.fingerprint, alert.timestamp, window)
            new_group = group_id is None
            stored = alert.model_copy(update={"group_id": group_id or uuid4()})
            self._alerts[stored.id] = stored
            return stored, new_group

    def get(self, tenant_id: str, alert_id: UUID) -> Alert | None:
        alert = self._alerts.get(alert_id)
        if alert is None or alert.tenant_id != tenant_id:
            return None
        return alert
