"""Parser for Sysmon / Windows event JSON, one flat object per event.

Field names follow Sysmon and the public OTRF datasets. A few aliases are accepted
because the datasets are not consistent about them.
"""

from datetime import datetime
from typing import Any

from app.parsers.base import ParseError, clean, clean_ip, parse_timestamp
from app.schemas import ParsedAlert

# Only the event ids that matter for the six techniques in PLAN.md; others become event_<id>.
EVENT_TYPES = {
    1: "process_create",  # T1059.001, T1053.005
    3: "network_connect",
    10: "process_access",  # T1003.001 (LSASS access)
    11: "file_create",
    13: "registry_set",  # T1547.001
    4624: "logon_success",
    4625: "logon_failure",  # T1110
    4698: "scheduled_task_created",  # T1053.005
    5140: "network_share_access",  # T1021.002
}

_TIME_KEYS = ("UtcTime", "EventTime", "@timestamp", "TimeCreated")
_HOST_KEYS = ("Computer", "Hostname", "host")
_USER_KEYS = ("User", "TargetUserName", "SubjectUserName")
_PROCESS_KEYS = ("Image", "NewProcessName", "ProcessName")
_SRC_IP_KEYS = ("SourceIp", "IpAddress")
_DST_IP_KEYS = ("DestinationIp",)


def _first(record: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = clean(record.get(key))
        if value is not None:
            return value
    return None


def _first_ip(record: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = clean_ip(record.get(key))
        if value is not None:
            return value
    return None


def parse_sysmon_json(record: Any, ref_time: datetime) -> ParsedAlert:
    if not isinstance(record, dict):
        raise ParseError("record must be a JSON object")

    raw_id = record.get("EventID")
    if isinstance(raw_id, bool) or raw_id is None:
        raise ParseError("missing or invalid EventID")
    try:
        event_id = int(raw_id)
    except (TypeError, ValueError) as exc:
        raise ParseError("missing or invalid EventID") from exc

    return ParsedAlert(
        source="sysmon_json",
        timestamp=parse_timestamp(_first(record, _TIME_KEYS)),
        host=_first(record, _HOST_KEYS),
        user=_first(record, _USER_KEYS),
        process=_first(record, _PROCESS_KEYS),
        command_line=clean(record.get("CommandLine")),
        src_ip=_first_ip(record, _SRC_IP_KEYS),
        dst_ip=_first_ip(record, _DST_IP_KEYS),
        event_type=EVENT_TYPES.get(event_id, f"event_{event_id}"),
        raw=record,
    )
