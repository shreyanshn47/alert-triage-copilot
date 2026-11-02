"""Parser for generic syslog lines (RFC 3164 style, or ISO-8601 timestamp)."""

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from app.parsers.base import ParseError, clean, clean_ip, parse_timestamp
from app.schemas import ParsedAlert

_LINE = re.compile(
    r"""^(?:<(?P<pri>\d{1,3})>)?
        (?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+
        (?P<host>\S+)\s+
        (?P<tag>[^\s:\[]+)(?:\[\d+\])?:\s*
        (?P<msg>.*)$""",
    re.VERBOSE,
)
_FAILED = re.compile(r"Failed \w+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_ACCEPTED = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>\S+)")


def _rfc3164_time(text: str, ref_time: datetime) -> datetime:
    """RFC 3164 has no year: use the reference year, or last year if that is in the future."""
    text = " ".join(text.split())
    try:
        parsed = datetime.strptime(f"{text} {ref_time.year}", "%b %d %H:%M:%S %Y").replace(
            tzinfo=UTC
        )
        if parsed - ref_time > timedelta(days=1):
            parsed = parsed.replace(year=ref_time.year - 1)
    except ValueError as exc:
        raise ParseError(f"unparseable timestamp: {text[:40]!r}") from exc
    return parsed


def parse_syslog(record: Any, ref_time: datetime) -> ParsedAlert:
    if not isinstance(record, str):
        raise ParseError("syslog record must be a string")
    line = record.strip()
    if not line:
        raise ParseError("empty syslog line")
    match = _LINE.match(line)
    if match is None:
        raise ParseError("not a recognizable syslog line")

    ts_text = match["ts"]
    timestamp = parse_timestamp(ts_text) if "T" in ts_text else _rfc3164_time(ts_text, ref_time)

    message = match["msg"]
    event_type, user, src_ip = "syslog", None, None
    if m := _FAILED.search(message):
        event_type, user, src_ip = "auth_failure", m["user"], clean_ip(m["ip"])
    elif m := _ACCEPTED.search(message):
        event_type, user, src_ip = "auth_success", m["user"], clean_ip(m["ip"])

    return ParsedAlert(
        source="syslog",
        timestamp=timestamp,
        host=clean(match["host"]),
        user=clean(user),
        process=clean(match["tag"]),  # PID dropped: it changes on every restart
        command_line=clean(message),
        src_ip=src_ip,
        event_type=event_type,
        raw={"line": line[:8192]},
    )
