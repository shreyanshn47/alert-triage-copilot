"""Generate synthetic benign alerts that resemble the six attack techniques.

The data is made up by this script (fixed seed), so it carries no license or confidentiality
issues. Each group imitates routine activity that a naive detector would flag.

Usage: python data/make_benign.py   ->   data/labeled/benign.jsonl
"""

import json
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root, for `app`
from app.fingerprint import fingerprint  # noqa: E402
from app.parsers.sysmon import parse_sysmon_json  # noqa: E402

SEED = 20261102
PER_GROUP = 10
DEV_PER_GROUP = 3
OUT = Path(__file__).resolve().parent / "labeled" / "benign.jsonl"

HOSTS = ["WS-ACCT-014", "WS-HR-007", "SRV-FILE-01", "SRV-APP-03", "WS-ENG-122", "SRV-BKP-02", "WS-OPS-031"]
USERS = ["CORP\\jsmith", "CORP\\mpatel", "CORP\\alee", "CORP\\rgarcia", "CORP\\tnguyen", "CORP\\kwong"]
ADMINS = ["CORP\\svc-patch", "CORP\\adm-ops", "CORP\\adm-it2"]
SYSTEM = "NT AUTHORITY\\SYSTEM"
PSH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
BASE_TIME = datetime(2026, 10, 12, 8, 0, tzinfo=UTC)


def stamp(rng: random.Random) -> str:
    t = BASE_TIME + timedelta(minutes=rng.randrange(0, 60 * 24 * 14))
    return t.strftime("%Y-%m-%d %H:%M:%S.") + f"{rng.randrange(1000):03d}"


def admin_powershell(rng):
    script = rng.choice(["Install-Updates.ps1", "Get-Inventory.ps1", "Rotate-Logs.ps1", "Check-Disk.ps1",
                         "Sync-AD-Groups.ps1", "Export-Report.ps1"])
    flags = rng.choice(["-NoProfile -ExecutionPolicy RemoteSigned", "-NoProfile", "-NonInteractive -NoLogo"])
    return {"EventID": 1, "Image": PSH, "User": rng.choice(ADMINS),
            "CommandLine": f"powershell.exe {flags} -File D:\\IT\\scripts\\{script}",
            "ParentImage": "C:\\Windows\\System32\\taskeng.exe"}


def legit_schtask(rng):
    name = rng.choice(["Backup\\Nightly", "Maintenance\\DiskCleanup", "Reports\\WeeklySales", "IT\\PatchScan",
                       "Sync\\FileShare", "Monitoring\\HealthCheck"])
    action = rng.choice(["C:\\Program Files\\BackupAgent\\run.exe", "C:\\IT\\tools\\cleanup.cmd",
                         "C:\\IT\\tools\\healthcheck.exe", "D:\\Reports\\export.bat"])
    when = rng.choice(["/SC DAILY /ST 02:00", "/SC WEEKLY /D SUN /ST 03:30", "/SC DAILY /ST 23:15"])
    return {"EventID": 1, "Image": "C:\\Windows\\System32\\schtasks.exe", "User": rng.choice(ADMINS),
            "CommandLine": f'schtasks.exe /Create /TN "{name}" /TR "{action}" {when} /RU SYSTEM',
            "ParentImage": "C:\\Windows\\System32\\cmd.exe"}


def backup_smb(rng):
    share = rng.choice(["\\\\*\\D$", "\\\\*\\E$", "\\\\*\\ADMIN$", "\\\\*\\C$"])
    rel = rng.choice(["Backups\\daily\\full.vhdx", "Shares\\Finance\\q3.xlsx", "Windows\\Temp\\sccm_pkg.exe",
                      "Data\\archive\\2026-10.bak", "Windows\\CCM\\inbox\\update.msi"])
    return {"EventID": 5145, "Channel": "Security", "SubjectUserName": rng.choice(["svc-backup", "svc-sccm"]),
            "IpAddress": f"10.20.{rng.randrange(1, 5)}.{rng.randrange(10, 250)}",
            "ShareName": share, "RelativeTargetName": rel}


def mistyped_or_scanned_logon(rng):
    if rng.random() < 0.6:  # a person mistyping a password
        user = rng.choice(["jsmith", "mpatel", "alee", "rgarcia", "tnguyen", "kwong"])
        return {"EventID": 4625, "Channel": "Security", "TargetUserName": user, "SubjectUserName": "-",
                "IpAddress": f"10.20.{rng.randrange(1, 5)}.{rng.randrange(10, 250)}",
                "ProcessName": "C:\\Windows\\System32\\winlogon.exe"}
    return {"EventID": 4625, "Channel": "Security", "TargetUserName": "svc-nessus", "SubjectUserName": "-",
            "IpAddress": "10.20.9.50", "ProcessName": "-"}  # authenticated vulnerability scanner


def installer_autostart(rng):
    app, exe = rng.choice([("OneDrive", "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background"),
                           ("Teams", "C:\\Users\\Public\\Teams\\Update.exe --processStart Teams.exe"),
                           ("Zoom", "C:\\Program Files\\Zoom\\bin\\Zoom.exe --autostart"),
                           ("SecurityHealth", "C:\\Windows\\System32\\SecurityHealthSystray.exe"),
                           ("Slack", "C:\\Program Files\\Slack\\slack.exe --startup")])
    installer = rng.choice(["C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\OneDriveSetup.exe",
                            "C:\\Program Files\\Common Files\\Update\\setup.exe"])
    return {"EventID": 13, "Image": installer, "User": SYSTEM,
            "TargetObject": f"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{app}",
            "Details": exe}


def security_agent_lsass(rng):
    src, access = rng.choice([("C:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe", "0x1010"),
                              ("C:\\Program Files\\CrowdStrike\\CSFalconService.exe", "0x1410"),
                              ("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe", "0x1010"),
                              ("C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe", "0x1010"),
                              ("C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "0x1410")])
    return {"EventID": 10, "SourceImage": src, "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": access, "User": SYSTEM}


GROUPS = [
    ("T1059.001", admin_powershell),
    ("T1053.005", legit_schtask),
    ("T1021.002", backup_smb),
    ("T1110", mistyped_or_scanned_logon),
    ("T1547.001", installer_autostart),
    ("T1003.001", security_agent_lsass),
]


def main() -> int:
    rng = random.Random(SEED)
    rows = []
    seen: set[str] = set()  # fingerprints, so no two benign alerts describe the same behaviour
    for lookalike, make in GROUPS:
        for i in range(PER_GROUP):
            for _ in range(200):
                record = make(rng)
                record.setdefault("Channel", "Microsoft-Windows-Sysmon/Operational")
                record["UtcTime"] = stamp(rng)
                record["Computer"] = rng.choice(HOSTS) + ".corp.example"
                a = parse_sysmon_json(record, BASE_TIME)
                fp = fingerprint("lab", a.host, a.user, a.process, a.command_line, a.event_type)
                if fp not in seen:
                    seen.add(fp)
                    break
            else:
                raise SystemExit(f"could not draw a distinct {lookalike} alert; widen the options")
            rows.append({
                "id": f"ben-{lookalike}-{i + 1:02d}",
                "label": "benign",
                "technique": None,
                "lookalike_of": lookalike,
                "split": "dev" if i < DEV_PER_GROUP else "test",
                "dataset": "synthetic:make_benign.py",
                "source": "synthetic",
                "record": record,
            })
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"wrote {len(rows)} benign rows to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
