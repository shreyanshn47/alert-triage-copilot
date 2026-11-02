from datetime import UTC, datetime

import pytest

from app.parsers import PARSERS, ParseError
from app.parsers.base import MAX_FIELD_LEN
from tests.conftest import REF_TIME, sysmon

parse_sysmon = PARSERS["sysmon_json"]
parse_syslog = PARSERS["syslog"]


# ---- Sysmon JSON ------------------------------------------------------------------------


def test_sysmon_process_create_maps_fields():
    a = parse_sysmon(sysmon(), REF_TIME)
    assert a.source == "sysmon_json"
    assert a.event_type == "process_create"
    assert a.host == "WS01.corp.local"
    assert a.user == "CORP\\alice"
    assert a.process.endswith("powershell.exe")
    assert a.timestamp == datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
    assert a.raw["EventID"] == 1


def test_sysmon_network_connect_extracts_ips():
    rec = sysmon(EventID=3, SourceIp="10.0.0.5", DestinationIp="203.0.113.9")
    a = parse_sysmon(rec, REF_TIME)
    assert (a.event_type, a.src_ip, a.dst_ip) == ("network_connect", "10.0.0.5", "203.0.113.9")


def test_sysmon_failed_logon_uses_security_log_field_names():
    rec = {
        "EventID": 4625,
        "EventTime": "2026-11-01T10:00:00Z",
        "Hostname": "dc01",
        "TargetUserName": "admin",
        "IpAddress": "-",
    }
    a = parse_sysmon(rec, REF_TIME)
    assert (a.event_type, a.host, a.user, a.src_ip) == ("logon_failure", "dc01", "admin", None)


@pytest.mark.parametrize(
    "extra, expected",
    [
        (
            {"EventID": 10, "SourceImage": "C:\\x\\a.exe", "TargetImage": "C:\\Windows\\lsass.exe",
             "GrantedAccess": "0x1010", "CommandLine": None},
            "C:\\x\\a.exe accessed C:\\Windows\\lsass.exe access=0x1010",
        ),
        (
            {"EventID": 13, "TargetObject": "HKCU\\Software\\Run\\Updater", "Details": "x.exe",
             "CommandLine": None},
            "registry HKCU\\Software\\Run\\Updater = x.exe",
        ),
        (
            {"EventID": 5145, "ShareName": "\\\\*\\C$", "RelativeTargetName": "ProgramData\\g.exe",
             "CommandLine": None},
            "share \\\\*\\C$ file ProgramData\\g.exe",
        ),
        ({"EventID": 4698, "TaskName": "\\Evil", "CommandLine": None}, "scheduled task \\Evil"),
    ],
)
def test_events_without_a_command_line_get_a_detail_string(extra, expected):
    assert parse_sysmon(sysmon(**extra), REF_TIME).command_line == expected


@pytest.mark.parametrize(
    "event_id, expected",
    [(1, "process_create"), (4688, "process_create"), (5140, "network_share_access"), (5145, "network_share_access")],
)
def test_equivalent_events_from_different_logs_get_the_same_event_type(event_id, expected):
    """Security-log and Sysmon events that mean the same thing must not look different to the model."""
    assert parse_sysmon(sysmon(EventID=event_id), REF_TIME).event_type == expected


def test_a_real_command_line_is_never_replaced_by_the_detail():
    rec = sysmon(EventID=10, TargetImage="lsass.exe", CommandLine="mimikatz.exe")
    assert parse_sysmon(rec, REF_TIME).command_line == "mimikatz.exe"


def test_sysmon_unknown_event_id_is_kept_not_rejected():
    assert parse_sysmon(sysmon(EventID=999), REF_TIME).event_type == "event_999"


def test_sysmon_timestamp_with_offset_is_converted_to_utc():
    a = parse_sysmon(sysmon(ts="2026-11-01T12:00:00+02:00"), REF_TIME)
    assert a.timestamp == datetime(2026, 11, 1, 10, 0, tzinfo=UTC)


def test_sysmon_invalid_ip_drops_the_field_not_the_alert():
    a = parse_sysmon(sysmon(EventID=3, SourceIp="not-an-ip"), REF_TIME)
    assert a.src_ip is None


def test_sysmon_overlong_field_is_truncated():
    a = parse_sysmon(sysmon(CommandLine="A" * (MAX_FIELD_LEN * 3)), REF_TIME)
    assert len(a.command_line) == MAX_FIELD_LEN


@pytest.mark.parametrize(
    "record, message",
    [
        ("a string", "JSON object"),
        (None, "JSON object"),
        ([1, 2], "JSON object"),
        ({}, "EventID"),
        ({"EventID": True, "UtcTime": "2026-11-01 10:00:00"}, "EventID"),
        ({"EventID": "abc", "UtcTime": "2026-11-01 10:00:00"}, "EventID"),
        ({"EventID": 1}, "missing timestamp"),
        ({"EventID": 1, "UtcTime": "yesterday-ish"}, "unparseable timestamp"),
    ],
)
def test_sysmon_malformed_records_are_rejected(record, message):
    with pytest.raises(ParseError, match=message):
        parse_sysmon(record, REF_TIME)


# ---- Syslog -----------------------------------------------------------------------------

FAILED = "<38>Nov  1 10:00:05 web01 sshd[1234]: Failed password for invalid user admin from 198.51.100.7 port 51234 ssh2"


def test_syslog_failed_password_becomes_auth_failure():
    a = parse_syslog(FAILED, REF_TIME)
    assert (a.event_type, a.host, a.process, a.user, a.src_ip) == (
        "auth_failure",
        "web01",
        "sshd",
        "admin",
        "198.51.100.7",
    )
    assert a.timestamp == datetime(2026, 11, 1, 10, 0, 5, tzinfo=UTC)
    assert a.raw == {"line": FAILED}


def test_syslog_accepted_login():
    line = "Nov 1 10:01:00 web01 sshd[99]: Accepted publickey for deploy from 10.0.0.8 port 40000 ssh2"
    a = parse_syslog(line, REF_TIME)
    assert (a.event_type, a.user, a.src_ip) == ("auth_success", "deploy", "10.0.0.8")


def test_syslog_other_message_is_generic_and_priority_is_optional():
    a = parse_syslog("Nov  1 10:02:00 web01 cron[7]: (root) CMD (/usr/bin/backup.sh)", REF_TIME)
    assert (a.event_type, a.process, a.user) == ("syslog", "cron", None)
    assert a.command_line == "(root) CMD (/usr/bin/backup.sh)"


def test_syslog_iso_timestamp_with_zone():
    a = parse_syslog("2026-11-01T10:00:00+00:00 web01 app: started", REF_TIME)
    assert a.timestamp == datetime(2026, 11, 1, 10, 0, tzinfo=UTC)


def test_syslog_year_rolls_back_when_line_would_be_in_the_future():
    ref = datetime(2027, 1, 1, 0, 30, tzinfo=UTC)
    a = parse_syslog("Dec 31 23:59:00 web01 app: tick", ref)
    assert a.timestamp == datetime(2026, 12, 31, 23, 59, tzinfo=UTC)


@pytest.mark.parametrize(
    "record, message",
    [
        ("", "empty"),
        ("   ", "empty"),
        ("complete garbage", "recognizable"),
        ("Nov  1 10:00:05 onlyhost", "recognizable"),
        ("Feb 30 10:00:05 web01 app: hi", "unparseable timestamp"),
        (123, "must be a string"),
        ({"line": "x"}, "must be a string"),
    ],
)
def test_syslog_malformed_records_are_rejected(record, message):
    with pytest.raises(ParseError, match=message):
        parse_syslog(record, REF_TIME)
