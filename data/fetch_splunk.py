"""Download Splunk attack_data log files used for malicious alerts.

Source: https://github.com/splunk/attack_data (Apache-2.0, see DATA_SOURCES.md).
The repo stores logs in Git LFS, so files come from media.githubusercontent.com. Files land
in data/raw/splunk/ (git-ignored); SHA-256 values are pinned in data/splunk_checksums.json.

Usage: python data/fetch_splunk.py
"""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

MEDIA = "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/"
RAW_DIR = Path(__file__).parent / "raw" / "splunk"
CHECKSUMS = Path(__file__).parent / "splunk_checksums.json"
MAX_BYTES = 60 * 1024 * 1024

# (technique, folder, file). The label is the technique folder the dataset is filed under.
FILES = [
    ("T1059.001", "encoded_powershell", "windows-sysmon.log"),
    ("T1059.001", "obfuscated_powershell", "windows-sysmon.log"),
    ("T1059.001", "powershell_execution_policy", "windows-sysmon.log"),
    ("T1059.001", "hidden_powershell", "windows-security.log"),
    ("T1053.005", "schtasks", "windows-sysmon.log"),
    ("T1053.005", "schtasks", "windows-security.log"),
    ("T1053.005", "schtask_system", "windows-sysmon.log"),
    ("T1053.005", "lateral_movement", "windows-sysmon.log"),
    ("T1547.001", "atomic_red_team", "windows-sysmon.log"),
    ("T1547.001", "atomic_red_team", "windows-security.log"),
    ("T1003.001", "atomic_red_team", "windows-sysmon.log"),
    ("T1003.001", "atomic_red_team", "createdump_windows-sysmon.log"),
]


def local_name(technique: str, folder: str, name: str) -> str:
    return f"{technique}__{folder}__{name}"


def main() -> int:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    pinned = json.loads(CHECKSUMS.read_text()) if CHECKSUMS.exists() else {}
    changed = False
    for technique, folder, name in FILES:
        key = local_name(technique, folder, name)
        dest = RAW_DIR / key
        if not dest.exists():
            url = f"{MEDIA}{technique}/{folder}/{name}"
            with urllib.request.urlopen(url, timeout=180) as resp:
                data = resp.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise SystemExit(f"{key} is larger than {MAX_BYTES} bytes; refusing")
            if data.startswith(b"version https://git-lfs"):
                raise SystemExit(f"{key} came back as an LFS pointer, not data")
            dest.write_bytes(data)
        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        if key in pinned and pinned[key] != digest:
            print(f"CHECKSUM MISMATCH {key}", file=sys.stderr)
            return 1
        if key not in pinned:
            pinned[key] = digest
            changed = True
        print(f"{technique:10} {folder[:28]:28} {name[:30]:30} {dest.stat().st_size / 1e6:6.2f} MB")
    if changed:
        CHECKSUMS.write_text(json.dumps(pinned, indent=2, sort_keys=True) + "\n")
        print(f"pinned new checksums in {CHECKSUMS.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
