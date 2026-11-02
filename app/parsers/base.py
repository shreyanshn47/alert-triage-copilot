"""Helpers shared by the parsers. Everything here treats input as untrusted."""

import ipaddress
from datetime import UTC, datetime
from typing import Any

MAX_FIELD_LEN = 4096


class ParseError(ValueError):
    """A record could not be turned into an alert. The message is returned to the caller."""


def clean(value: Any) -> str | None:
    """Strip, treat empty and Windows' "-" placeholder as missing, cap the length."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "-":
        return None
    return text[:MAX_FIELD_LEN]


def clean_ip(value: Any) -> str | None:
    """Return a canonical IP string, or None if the value is not a valid IP.

    An invalid IP drops the field, not the alert; the original stays in `raw`.
    """
    text = clean(value)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def parse_timestamp(value: Any) -> datetime:
    """Parse an ISO-8601 style timestamp to timezone-aware UTC. Naive means UTC."""
    text = clean(value)
    if text is None:
        raise ParseError("missing timestamp")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ParseError(f"unparseable timestamp: {text[:40]!r}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
