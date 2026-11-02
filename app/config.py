"""Tiny .env loader for command-line scripts (the API gets its environment from Docker/the shell)."""

import os
from pathlib import Path


def load_dotenv(start: Path | None = None) -> Path | None:
    """Load the nearest .env at or above `start` into os.environ, without overriding anything set.

    Searches a few levels up so scripts run from a git worktree still find the project's .env.
    Returns the file used. Values are never printed or logged.
    """
    here = (start or Path(__file__).resolve().parent).resolve()
    for directory in [here, *list(here.parents)[:5]]:
        candidate = directory / ".env"
        if candidate.is_file():
            for line in candidate.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip().strip('"').strip("'")
                if key and value and not os.environ.get(key):
                    os.environ[key] = value
            return candidate
    return None
