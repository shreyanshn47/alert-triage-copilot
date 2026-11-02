"""Dedup fingerprint.

Two alerts that describe the same behaviour on the same host by the same user should hash
the same, even though their timestamps, process ids and random identifiers differ. Time is
not part of the hash. Time decides grouping (see the stores), not identity.
"""

import hashlib
import json
import re

# Applied to the lower-cased command line, in this order (timestamps first so the digit
# rule below does not eat their pieces).
_EPHEMERAL = [
    (re.compile(r"\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?z?"), "<ts>"),
    (re.compile(r"\b\d{1,2}:\d{2}:\d{2}\b"), "<time>"),
    (
        re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?"),
        "<guid>",
    ),
    (re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{8,}\b"), "<hex>"),
    (re.compile(r"\bpid[=: ]\s*\d+"), "pid=<n>"),
    (re.compile(r"\d{5,}"), "<n>"),  # ids, and ephemeral ports (32768 and up)
]


def normalize_command_line(command_line: str | None) -> str:
    if not command_line:
        return ""
    text = command_line.lower()
    for pattern, replacement in _EPHEMERAL:
        text = pattern.sub(replacement, text)
    return " ".join(text.split())


def _norm(value: str | None) -> str:
    return " ".join((value or "").lower().split())


def fingerprint(
    tenant_id: str,
    host: str | None,
    user: str | None,
    process: str | None,
    command_line: str | None,
    event_type: str | None,
) -> str:
    parts = [
        tenant_id,
        _norm(host),
        _norm(user),
        _norm(process).replace("\\", "/"),
        normalize_command_line(command_line),
        _norm(event_type),
    ]
    # JSON encoding keeps field boundaries unambiguous, so a separator character inside one
    # field cannot make two different alerts hash the same.
    payload = json.dumps(parts, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()
