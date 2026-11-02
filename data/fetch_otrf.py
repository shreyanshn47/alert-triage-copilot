"""Download the OTRF Security-Datasets (Mordor) files used for malicious alerts.

Source: https://github.com/OTRF/Security-Datasets (MIT license, see DATA_SOURCES.md).
Files land in data/raw/otrf/ (git-ignored). Each file's SHA-256 is pinned in
data/otrf_checksums.json: the first fetch records it, later fetches must match, so a changed
upstream file is noticed instead of silently changing the labeled set.

Usage: python data/fetch_otrf.py
"""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
RAW_DIR = Path(__file__).parent / "raw" / "otrf"
CHECKSUMS = Path(__file__).parent / "otrf_checksums.json"
MAX_BYTES = 200 * 1024 * 1024  # refuse anything larger than this

# technique -> datasets. The label is the dataset's own ATT&CK mapping from its OTRF metadata.
DATASETS = {
    "T1059.001": [
        ("SDWIN-201102041306", "datasets/atomic/windows/execution/host/psh_powershell_httplistener.zip"),
    ],
    "T1003.001": [
        ("SDWIN-190518202151", "datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip"),
        ("SDWIN-201018195009", "datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip"),
        ("SDWIN-191027055035", "datasets/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip"),
    ],
    "T1021.002": [
        ("SDWIN-190518210125", "datasets/atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip"),
        ("SDWIN-200806015757", "datasets/atomic/windows/lateral_movement/host/covenant_copy_smb_CreateRequest.zip"),
    ],
    "T1053.005": [
        ("SDWIN-190319024742", "datasets/atomic/windows/persistence/host/empire_schtasks_creation_standard_user.zip"),
        ("SDWIN-201219070027", "datasets/atomic/windows/lateral_movement/host/schtask_create.zip"),
    ],
    "T1547.001": [
        ("SDWIN-190319023812", "datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip"),
        ("SDWIN-200722001847", "datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_elevated_user.zip"),
    ],
    "T1110": [  # OTRF maps this one to T1110.003 (password spraying)
        ("SDWIN-201022042947", "datasets/atomic/windows/lateral_movement/host/purplesharp_ad_playbook_I.zip"),
    ],
}


def local_path(url_path: str) -> Path:
    return RAW_DIR / Path(url_path).name


def fetch(url_path: str) -> bytes:
    with urllib.request.urlopen(BASE + url_path, timeout=120) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise SystemExit(f"{url_path} is larger than {MAX_BYTES} bytes; refusing")
    return data


def main() -> int:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    pinned = json.loads(CHECKSUMS.read_text()) if CHECKSUMS.exists() else {}
    changed = False
    for technique, items in DATASETS.items():
        for dataset_id, url_path in items:
            dest = local_path(url_path)
            if not dest.exists():
                dest.write_bytes(fetch(url_path))
            digest = hashlib.sha256(dest.read_bytes()).hexdigest()
            if dataset_id in pinned and pinned[dataset_id] != digest:
                print(f"CHECKSUM MISMATCH {dataset_id} {dest.name}", file=sys.stderr)
                return 1
            if dataset_id not in pinned:
                pinned[dataset_id] = digest
                changed = True
            print(f"{technique:10} {dataset_id} {dest.stat().st_size / 1e6:7.1f} MB {digest[:12]}")
    if changed:
        CHECKSUMS.write_text(json.dumps(pinned, indent=2, sort_keys=True) + "\n")
        print(f"pinned new checksums in {CHECKSUMS.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
