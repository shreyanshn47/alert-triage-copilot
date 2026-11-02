"""pgvector storage and search for corpus chunks."""

from dataclasses import dataclass

from psycopg.rows import dict_row

from app.db import get_pool
from app.retrieval.corpus import Chunk

PUBLIC = "public"

_INSERT = """
INSERT INTO corpus_chunks (tenant_id, source, ref, technique_ids, chunk_index, content, embedding)
VALUES (%s, %s, %s, %s, %s, %s, %s::vector)
"""

_SEARCH = """
SELECT source, ref, technique_ids, chunk_index, content,
       1 - (embedding <=> %(q)s::vector) AS score
FROM corpus_chunks
WHERE tenant_id = ANY(%(tenants)s)
  AND (%(sources)s::text[] IS NULL OR source = ANY(%(sources)s::text[]))
ORDER BY embedding <=> %(q)s::vector
LIMIT %(k)s
"""


@dataclass
class Hit:
    source: str
    ref: str
    technique_ids: list[str]
    chunk_index: int
    content: str
    score: float


def vector_literal(vector: list[float]) -> str:
    return "[" + ",".join(f"{x:.7f}" for x in vector) + "]"


class ChunkStore:
    def __init__(self, dsn: str) -> None:
        self._pool = get_pool(dsn)

    def replace_public(self, chunks: list[Chunk], vectors: list[list[float]]) -> int:
        """Replace the shared corpus in one transaction, so a failed rebuild changes nothing."""
        if len(chunks) != len(vectors):
            raise ValueError("one vector per chunk is required")
        with self._pool.connection() as conn:
            conn.execute("DELETE FROM corpus_chunks WHERE tenant_id = %s", (PUBLIC,))
            for chunk, vector in zip(chunks, vectors, strict=True):
                conn.execute(
                    _INSERT,
                    (PUBLIC, chunk.source, chunk.ref, chunk.technique_ids, chunk.chunk_index,
                     chunk.content, vector_literal(vector)),
                )
        return len(chunks)

    def add_tenant_chunks(self, tenant_id: str, chunks: list[Chunk], vectors: list[list[float]]) -> int:
        """Add a tenant's own chunks (for example its past cases). Never writes to the shared corpus."""
        if not tenant_id or tenant_id == PUBLIC:
            raise ValueError("a tenant id other than 'public' is required")
        with self._pool.connection() as conn:
            for chunk, vector in zip(chunks, vectors, strict=True):
                conn.execute(
                    _INSERT,
                    (tenant_id, chunk.source, chunk.ref, chunk.technique_ids, chunk.chunk_index,
                     chunk.content, vector_literal(vector)),
                )
        return len(chunks)

    def search(self, tenant_id: str, vector: list[float], k: int, sources: list[str] | None) -> list[Hit]:
        params = {"q": vector_literal(vector), "tenants": [PUBLIC, tenant_id], "k": k, "sources": sources}
        with self._pool.connection() as conn:
            rows = conn.cursor(row_factory=dict_row).execute(_SEARCH, params).fetchall()
        return [Hit(**row) for row in rows]

    def count(self) -> int:
        with self._pool.connection() as conn:
            return conn.execute("SELECT count(*) FROM corpus_chunks WHERE tenant_id = %s", (PUBLIC,)).fetchone()[0]
