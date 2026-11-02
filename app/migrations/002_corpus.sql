-- Retrieval corpus: chunks of ATT&CK technique text and Sigma rules, with embeddings.
-- tenant_id is 'public' for the shared corpus. A tenant's own notes would carry its tenant_id,
-- and every search filters on ('public', caller's tenant).
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE corpus_chunks (
    id            bigserial PRIMARY KEY,
    tenant_id     text    NOT NULL,
    source        text    NOT NULL,          -- 'attack' | 'sigma' | 'note'
    ref           text    NOT NULL,          -- technique id, or rule title
    technique_ids text[]  NOT NULL,
    chunk_index   integer NOT NULL,
    content       text    NOT NULL,
    embedding     vector(384) NOT NULL,      -- BAAI/bge-small-en-v1.5, L2-normalized
    UNIQUE (tenant_id, source, ref, chunk_index)
);

CREATE INDEX corpus_chunks_tenant ON corpus_chunks (tenant_id);
-- Approximate nearest-neighbour index (cosine). With a tenant filter the planner may ignore it
-- and scan, which is exact; at this corpus size either is instant.
CREATE INDEX corpus_chunks_embedding ON corpus_chunks USING hnsw (embedding vector_cosine_ops);
