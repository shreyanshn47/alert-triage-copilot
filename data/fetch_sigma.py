"""Fetch SigmaHQ rules at a pinned commit into data/raw/sigma/.

SigmaHQ rules are under the Detection Rule License (DRL) 1.1, which requires attribution
(see DATA_SOURCES.md). The first run records the commit in data/sigma_commit.txt; later runs
fetch exactly that commit.

Usage: python data/fetch_sigma.py
"""

import subprocess
from pathlib import Path

REPO = "https://github.com/SigmaHQ/sigma.git"
DEST = Path(__file__).parent / "raw" / "sigma"
PIN = Path(__file__).parent / "sigma_commit.txt"


def git(*args: str, cwd: Path | None = None) -> str:
    # core.longpaths: some Sigma rule paths exceed the legacy Windows path limit.
    cmd = ["git", "-c", "core.longpaths=true", *args]
    result = subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def main() -> int:
    if (DEST / ".git").exists():
        head = git("rev-parse", "HEAD", cwd=DEST)
        if not PIN.exists():
            PIN.write_text(head + "\n")
        print(f"sigma already at {head[:12]}")
        return 0
    DEST.parent.mkdir(parents=True, exist_ok=True)
    if PIN.exists():
        sha = PIN.read_text().strip()
        DEST.mkdir(exist_ok=True)
        git("init", "-q", cwd=DEST)
        git("remote", "add", "origin", REPO, cwd=DEST)
        git("fetch", "-q", "--depth", "1", "origin", sha, cwd=DEST)
        git("checkout", "-q", "FETCH_HEAD", cwd=DEST)
    else:
        git("clone", "-q", "--depth", "1", REPO, str(DEST))
        PIN.write_text(git("rev-parse", "HEAD", cwd=DEST) + "\n")
    print(f"sigma at {git('rev-parse', 'HEAD', cwd=DEST)[:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
