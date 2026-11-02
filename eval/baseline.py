"""Rules-only baseline: hand-written indicator rules, no model, no retrieval.

Each rule is the kind of simple check a detection engineer writes first: a tool name plus a
suspicious argument or path. It returns "malicious" with the rule's technique, or "benign".
It never returns needs_human.

Read the results with one caveat in mind: these rules were written by the same author who built the
labeled sets, so they are an illustration of what simple rules achieve here, not an independent
benchmark. They were written before any test-set result existed and are not changed afterwards.
"""

import re
from collections.abc import Callable

from app.schemas import ParsedAlert

SUSPICIOUS_PATH = ("\\users\\public\\", "\\temp\\", "\\appdata\\", "\\programdata\\", "\\downloads\\")
TRUSTED_SOURCE_PREFIX = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\windows defender\\",
)
DUMP_ACCESS = ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff", "0x1400")
PS_MARKERS = re.compile(
    r"\s-(enc|encodedcommand|ec)\b|-w(indowstyle)?\s+hidden|downloadstring|downloadfile|invoke-expression|\biex\b"
    r"|frombase64string|-ep\s+bypass|-executionpolicy\s+bypass|net\.webclient|invoke-webrequest|\biwr\b"
)


def _text(a: ParsedAlert) -> str:
    return (a.command_line or "").lower()


def _proc(a: ParsedAlert) -> str:
    return (a.process or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def _has_suspicious_path(text: str) -> bool:
    return any(p in text for p in SUSPICIOUS_PATH)


def powershell(a: ParsedAlert) -> bool:
    return _proc(a) in {"powershell.exe", "pwsh.exe"} and bool(PS_MARKERS.search(_text(a)))


def scheduled_task(a: ParsedAlert) -> bool:
    text = _text(a)
    if a.event_type == "scheduled_task_created":
        return not text.startswith("scheduled task \\microsoft\\windows\\")
    if _proc(a) == "schtasks.exe" and "/create" in text:
        return _has_suspicious_path(text) or "cmd /c" in text or "powershell" in text or PS_MARKERS.search(text) is not None
    return False


def run_key(a: ParsedAlert) -> bool:
    text = _text(a)
    if "currentversion\\run" not in text:
        return False
    if a.event_type == "registry_set":
        value = text.split(" = ", 1)[1] if " = " in text else ""
        return _has_suspicious_path(value) or any(s in value for s in ("powershell", "cmd /c", "wscript", "mshta", "rundll32"))
    return _proc(a) in {"reg.exe", "powershell.exe", "cmd.exe", "wscript.exe"}


def lsass(a: ParsedAlert) -> bool:
    text = _text(a)
    if a.event_type == "process_access" and "lsass.exe" in text:
        source = text.split(" accessed ", 1)[0]
        mask = text.rsplit("access=", 1)[-1].strip()
        return mask in DUMP_ACCESS and not source.startswith(TRUSTED_SOURCE_PREFIX)
    return any(k in text for k in ("procdump", "comsvcs", "minidump", "sekurlsa", "mimikatz", "createdump"))


def smb(a: ParsedAlert) -> bool:
    text = _text(a)
    if a.event_type == "network_share_access":
        if "svcctl" in text or "psexesvc" in text:
            return True
        admin_share = re.search(r"share \\\\\*\\(c|d|admin)\$", text) is not None
        return admin_share and re.search(r" file .*\.(exe|dll|bat|ps1|scr)$", text) is not None
    return bool(re.search(r"\bpsexec\b|\bsc(\.exe)?\s+\\\\\S+\s+create\b|copy\s+\S+\s+\\\\\S+\\(c|admin)\$|net(\.exe)?\s+use\s+\\\\\S+.*/user:", text))


def brute_force(a: ParsedAlert) -> bool:
    """A failed logon raised by a program running from a user-writable folder."""
    return a.event_type == "logon_failure" and _has_suspicious_path((a.process or "").lower() + "\\")


RULES: list[tuple[str, Callable[[ParsedAlert], bool]]] = [
    ("T1003.001", lsass),
    ("T1059.001", powershell),
    ("T1053.005", scheduled_task),
    ("T1547.001", run_key),
    ("T1021.002", smb),
    ("T1110", brute_force),
]


def predict(alert: ParsedAlert) -> tuple[str, str | None]:
    """Return (verdict, technique). The first matching rule wins."""
    for technique, rule in RULES:
        if rule(alert):
            return "malicious", technique
    return "benign", None
