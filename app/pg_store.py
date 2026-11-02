"""PostgreSQL alert store (psycopg 3, plain SQL).

One connection per call for now. A pool is the first thing to add if this becomes a hot path.
"""

from datetime import timedelta
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.schemas import Alert

_FIND_GROUP = """
SELECT group_id
FROM alerts
WHERE tenant_id = %(tenant)s AND fingerprint = %(fp)s
GROUP BY group_id
HAVING abs(extract(epoch FROM (%(ts)s::timestamptz - min(timestamp)))) <= %(window)s
ORDER BY min(timestamp) DESC
LIMIT 1
"""

_INSERT = """
INSERT INTO alerts (id, tenant_id, source, timestamp, host, user_name, process, command_line,
                    src_ip, dst_ip, event_type, raw, fingerprint, group_id)
VALUES (%(id)s, %(tenant)s, %(source)s, %(ts)s, %(host)s, %(user)s, %(process)s,
        %(command_line)s, %(src_ip)s, %(dst_ip)s, %(event_type)s, %(raw)s, %(fp)s, %(group_id)s)
"""

_SELECT = """
SELECT id, tenant_id, source, timestamp, host, user_name AS "user", process, command_line,
       src_ip, dst_ip, event_type, raw, fingerprint, group_id
FROM alerts
WHERE tenant_id = %s AND id = %s
"""


class PostgresStore:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def add_alert(self, alert: Alert, window: timedelta) -> tuple[Alert, bool]:
        # `with connect()` commits on success and rolls back on error. The transaction-scoped
        # advisory lock serializes concurrent inserts of the same (tenant, fingerprint), so two
        # identical alerts arriving together cannot both decide to start a new group.
        with psycopg.connect(self._dsn) as conn:
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"{alert.tenant_id}:{alert.fingerprint}",),
            )
            row = conn.execute(
                _FIND_GROUP,
                {
                    "tenant": alert.tenant_id,
                    "fp": alert.fingerprint,
                    "ts": alert.timestamp,
                    "window": window.total_seconds(),
                },
            ).fetchone()
            new_group = row is None
            group_id = uuid4() if row is None else row[0]
            conn.execute(
                _INSERT,
                {
                    "id": alert.id,
                    "tenant": alert.tenant_id,
                    "source": alert.source,
                    "ts": alert.timestamp,
                    "host": alert.host,
                    "user": alert.user,
                    "process": alert.process,
                    "command_line": alert.command_line,
                    "src_ip": alert.src_ip,
                    "dst_ip": alert.dst_ip,
                    "event_type": alert.event_type,
                    "raw": Jsonb(alert.raw),
                    "fp": alert.fingerprint,
                    "group_id": group_id,
                },
            )
        return alert.model_copy(update={"group_id": group_id}), new_group

    def get(self, tenant_id: str, alert_id: UUID) -> Alert | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as conn:
            row = conn.execute(_SELECT, (tenant_id, alert_id)).fetchone()
        return Alert(**row) if row else None
