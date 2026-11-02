"""Readers that turn raw dataset files into flat event dicts (the shape app/parsers/sysmon.py takes).

Both readers stream line by line and never extract archives to disk. The Splunk reader pulls
fields out of the event XML with regular expressions, so untrusted XML never reaches an XML
parser (no entity expansion, no DTDs).
"""

import html
import json
import re
import zipfile
from collections.abc import Iterator
from pathlib import Path

MAX_LINE = 1_000_000  # skip absurdly long lines instead of processing them

_EID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
_COMPUTER = re.compile(r"<Computer>([^<]*)</Computer>")
_CHANNEL = re.compile(r"<Channel>([^<]*)</Channel>")
_TIME = re.compile(r"<TimeCreated SystemTime='([^']+)'")
_DATA = re.compile(r"<Data Name='([^']*)'>([^<]*)</Data>")


def read_otrf(zip_path: Path) -> Iterator[dict]:
    """Yield events from the first member of an OTRF Security-Datasets zip (JSON lines)."""
    with zipfile.ZipFile(zip_path) as zf:
        member = zf.infolist()[0]
        with zf.open(member) as fh:
            for line in fh:
                if len(line) > MAX_LINE:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if isinstance(event, dict):
                    yield event


def read_splunk_xml(path: Path) -> Iterator[dict]:
    """Yield events from a Splunk attack_data XmlWinEventLog file (one event per line)."""
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if len(line) > MAX_LINE or "<Event" not in line:
                continue
            eid = _EID.search(line)
            if eid is None:
                continue
            event: dict = {"EventID": int(eid.group(1))}
            for key, pattern in (("Computer", _COMPUTER), ("Channel", _CHANNEL), ("TimeCreated", _TIME)):
                match = pattern.search(line)
                if match:
                    event[key] = html.unescape(match.group(1))
            for name, value in _DATA.findall(line):
                event[name] = html.unescape(value)
            yield event
