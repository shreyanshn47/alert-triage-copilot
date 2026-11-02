"""pgvector storage, search and the tenant filter. Uses a fake embedder: no model download."""

import hashlib
import random

import pytest

from app.parsers.sysmon import parse_sysmon_json
from app.retrieval import query_text, retrieve
from app.retrieval.corpus import Chunk
from app.retrieval.embed import DIMENSIONS
from app.retrieval.store import ChunkStore
from tests.conftest import REF_TIME, sysmon


class FakeEmbedder:
    """Same text -> same unit vector; different texts are (almost surely) far apart."""

    def _vec(self, text: str) -> list[float]:
        rng = random.Random(int(hashlib.sha256(text.encode()).hexdigest(), 16))
        v = [rng.gauss(0, 1) for _ in range(DIMENSIONS)]
        norm = sum(x * x for x in v) ** 0.5
        return [x / norm for x in v]

    def embed_docs(self, texts):
        return [self._vec(t) for t in texts]

    def embed_query(self, text):
        return self._vec(text)


@pytest.fixture
def chunks_store(pg_dsn):
    return ChunkStore(pg_dsn)


def chunk(ref, text, source="note", technique="T1003.001"):
    return Chunk(source, ref, [technique], 0, text)


def test_a_tenant_never_retrieves_another_tenants_chunks(chunks_store, tenant):
    other = f"t-other-{tenant[2:]}"
    embedder = FakeEmbedder()
    secret = chunk("secret-case", "tenant A private incident notes")
    chunks_store.add_tenant_chunks(tenant, [secret], embedder.embed_docs([secret.content]))
    query = embedder.embed_query("tenant A private incident notes")  # exact match to the secret

    own = chunks_store.search(tenant, query, 50, None)
    foreign = chunks_store.search(other, query, 50, None)

    assert own and own[0].ref == "secret-case"  # the owner sees it, as the best match
    assert all(h.ref != "secret-case" for h in foreign)  # another tenant never does


def test_public_corpus_is_visible_to_every_tenant_and_tenant_rows_are_not_public(chunks_store, tenant):
    embedder = FakeEmbedder()
    pub = chunk("T9999.test", "shared public technique text", source="attack", technique="T9999")
    chunks_store.replace_public([pub], embedder.embed_docs([pub.content]))
    try:
        hits = chunks_store.search(tenant, embedder.embed_query(pub.content), 5, None)
        assert hits[0].ref == "T9999.test"
        assert chunks_store.count() == 1
    finally:
        chunks_store.replace_public([], [])  # leave the shared corpus empty for the next test


def test_writing_as_the_public_tenant_through_the_tenant_api_is_refused(chunks_store):
    c = chunk("x", "text")
    for bad in ("public", ""):
        with pytest.raises(ValueError):
            chunks_store.add_tenant_chunks(bad, [c], [[0.0] * DIMENSIONS])


def test_source_filter(chunks_store, tenant):
    embedder = FakeEmbedder()
    a = chunk("T1.a", "same words", source="attack", technique="T1003.001")
    s = chunk("rule", "same words", source="sigma", technique="T1003.001")
    chunks_store.add_tenant_chunks(tenant, [a, s], embedder.embed_docs([a.content, s.content]))
    q = embedder.embed_query("same words")
    assert {h.source for h in chunks_store.search(tenant, q, 10, ["sigma"])} == {"sigma"}
    assert {h.source for h in chunks_store.search(tenant, q, 10, ["attack"])} == {"attack"}


def test_retrieve_requires_a_tenant(chunks_store):
    alert = parse_sysmon_json(sysmon(), REF_TIME)
    with pytest.raises(ValueError):
        retrieve(alert, "", chunks_store, FakeEmbedder())


def test_query_text_masks_windows_sids():
    rec = sysmon(EventID=13, CommandLine=None,
                 TargetObject="HKU\\S-1-5-21-3125456671-949036322-3048627137-1104\\Software\\Run\\Updater")
    text = query_text(parse_sysmon_json(rec, REF_TIME))
    assert "<sid>" in text and "3125456671" not in text and "Run\\Updater" in text


def test_query_text_describes_the_behaviour_not_the_environment():
    alert = parse_sysmon_json(sysmon(), REF_TIME)
    text = query_text(alert)
    assert "process_create" in text and "powershell.exe" in text and "patch.ps1" in text
    assert "WS01" not in text and "alice" not in text and "2026" not in text
