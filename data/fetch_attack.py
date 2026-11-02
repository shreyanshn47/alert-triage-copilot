"""Download the MITRE ATT&CK Enterprise STIX bundle (pinned release) into data/raw/attack/.

ATT&CK is (c) The MITRE Corporation, free to use if the copyright notice and license are
reproduced (see DATA_SOURCES.md). The release and its SHA-256 are pinned below.

Usage: python data/fetch_attack.py
"""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

VERSION = "20.0"
URL = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-{VERSION}.json"
DEST = Path(__file__).parent / "raw" / "attack" / f"enterprise-attack-{VERSION}.json"
CHECKSUMS = Path(__file__).parent / "attack_checksums.json"
MAX_BYTES = 150 * 1024 * 1024


def main() -> int:
    DEST.parent.mkdir(parents=True, exist_ok=True)
    if not DEST.exists():
        with urllib.request.urlopen(URL, timeout=180) as resp:
            data = resp.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise SystemExit("ATT&CK bundle is larger than expected; refusing")
        DEST.write_bytes(data)
    digest = hashlib.sha256(DEST.read_bytes()).hexdigest()
    pinned = json.loads(CHECKSUMS.read_text()) if CHECKSUMS.exists() else {}
    if pinned.get(VERSION, digest) != digest:
        print("CHECKSUM MISMATCH for ATT&CK", VERSION, file=sys.stderr)
        return 1
    if VERSION not in pinned:
        CHECKSUMS.write_text(json.dumps({VERSION: digest}, indent=2) + "\n")
    print(f"ATT&CK {VERSION}: {DEST.stat().st_size / 1e6:.1f} MB sha256 {digest[:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
