"""Build the shared retrieval corpus: chunk ATT&CK and Sigma, embed, store in pgvector.

Usage: python -m app.retrieval.index        (needs DATABASE_URL, the data/fetch_*.py downloads,
                                             and the `retrieval` extra installed)
Safe to re-run: it replaces the shared corpus in one transaction.
"""

import os
from pathlib import Path

from app.migrate import migrate
from app.retrieval.corpus import load_attack, load_sigma
from app.retrieval.embed import Embedder
from app.retrieval.store import ChunkStore

RAW = Path(__file__).resolve().parents[2] / "data" / "raw"
ATTACK_FILE = RAW / "attack" / "enterprise-attack-20.0.json"
SIGMA_DIR = RAW / "sigma"


def main() -> int:
    dsn = os.environ["DATABASE_URL"]
    migrate(dsn)
    chunks = load_attack(ATTACK_FILE) + load_sigma(SIGMA_DIR)
    by_source = {s: sum(c.source == s for c in chunks) for s in ("attack", "sigma")}
    print(f"chunks: {by_source}")
    vectors = Embedder().embed_docs([c.content for c in chunks])
    stored = ChunkStore(dsn).replace_public(chunks, vectors)
    print(f"stored {stored} chunks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
