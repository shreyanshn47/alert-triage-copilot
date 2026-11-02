from collections.abc import Callable
from datetime import datetime
from typing import Any

from app.parsers.base import ParseError
from app.parsers.syslog import parse_syslog
from app.parsers.sysmon import parse_sysmon_json
from app.schemas import ParsedAlert

Parser = Callable[[Any, datetime], ParsedAlert]

PARSERS: dict[str, Parser] = {
    "sysmon_json": parse_sysmon_json,
    "syslog": parse_syslog,
}

__all__ = ["PARSERS", "ParseError", "Parser"]
