"""Local embedding model (BAAI/bge-small-en-v1.5, 384 dimensions, runs on CPU)."""

from typing import Protocol

MODEL_NAME = "BAAI/bge-small-en-v1.5"
DIMENSIONS = 384
# BGE models retrieve better when the query (not the documents) carries this instruction.
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "


class EmbedderLike(Protocol):
    def embed_docs(self, texts: list[str]) -> list[list[float]]: ...
    def embed_query(self, text: str) -> list[float]: ...


class Embedder:
    """Loads the model on first use, so importing this module stays cheap."""

    def __init__(self, model_name: str = MODEL_NAME) -> None:
        self._name = model_name
        self._model = None

    def _load(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer  # heavy import, keep local

            self._model = SentenceTransformer(self._name, device="cpu")
        return self._model

    def embed_docs(self, texts: list[str]) -> list[list[float]]:
        vectors = self._load().encode(texts, batch_size=32, normalize_embeddings=True)
        return [v.tolist() for v in vectors]

    def embed_query(self, text: str) -> list[float]:
        vector = self._load().encode(QUERY_PREFIX + text, normalize_embeddings=True)
        return vector.tolist()
