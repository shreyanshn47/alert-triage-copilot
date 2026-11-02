-- Alerts: one row per ingested alert. group_id is shared by duplicates (same fingerprint
-- inside the grouping window). Every query filters on tenant_id.
CREATE TABLE alerts (
    id           uuid PRIMARY KEY,
    tenant_id    text        NOT NULL,
    source       text        NOT NULL,
    timestamp    timestamptz NOT NULL,
    host         text,
    user_name    text,
    process      text,
    command_line text,
    src_ip       text,
    dst_ip       text,
    event_type   text        NOT NULL,
    raw          jsonb       NOT NULL,
    fingerprint  text        NOT NULL,
    group_id     uuid        NOT NULL,
    received_at  timestamptz NOT NULL DEFAULT now()
);

-- Serves the grouping lookup: tenant + fingerprint, then time.
CREATE INDEX alerts_tenant_fingerprint_ts ON alerts (tenant_id, fingerprint, timestamp);
-- Serves "all members of a group" for a tenant.
CREATE INDEX alerts_tenant_group ON alerts (tenant_id, group_id);
