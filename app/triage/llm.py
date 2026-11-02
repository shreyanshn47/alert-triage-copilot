"""The LLM call: one function, an on-disk cache, and a cost estimate.

Every result is cached on disk under a hash of everything that shapes the answer (model, effort,
system prompt, messages, max_tokens), so a repeated run costs nothing and returns the same text.
The cache holds model output only: no API key or request headers are ever written to it.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

DEFAULT_MODEL = "claude-haiku-5-5"
DEFAULT_EFFORT = "low"
DEFAULT_MAX_TOKENS = 4000  # thinking tokens count against this, so leave room beyond the answer
CACHE_DIR = Path(os.environ.get("TRIAGE_CACHE_DIR", ".cache/llm"))

# USD per million tokens (input, output), from Anthropic's published first-party prices as of
# 2026-10. Haiku 5.5 is priced higher for prompts over 100K tokens; ours are far below that.
# Check https://platform.claude.com/docs/en/about-claude/pricing before trusting a total.
PRICES: dict[str, tuple[float, float]] = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00),
}


@dataclass
class LLMResult:
    text: str
    stop_reason: str | None
    input_tokens: int
    output_tokens: int
    cached: bool
    model: str


class LLM(Protocol):
    model: str

    def complete(self, system: str, messages: list[dict], max_tokens: int = DEFAULT_MAX_TOKENS) -> LLMResult: ...


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float | None:
    price = PRICES.get(model)
    if price is None:
        return None
    return (input_tokens * price[0] + output_tokens * price[1]) / 1_000_000


class AnthropicLLM:
    def __init__(
        self,
        model: str | None = None,
        effort: str | None = None,
        cache_dir: Path | None = None,
        client: Any = None,
    ) -> None:
        self.model = model or os.environ.get("TRIAGE_MODEL") or DEFAULT_MODEL
        self.effort = effort or os.environ.get("TRIAGE_EFFORT") or DEFAULT_EFFORT
        self.cache_dir = cache_dir or CACHE_DIR
        self._client = client

    def _api(self) -> Any:
        if self._client is None:
            import anthropic  # imported here so tests and cached re-runs need no key

            self._client = anthropic.Anthropic()
        return self._client

    def _key(self, system: str, messages: list[dict], max_tokens: int) -> str:
        payload = {"model": self.model, "effort": self.effort, "system": system,
                   "messages": messages, "max_tokens": max_tokens}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True).encode()).hexdigest()

    def complete(self, system: str, messages: list[dict], max_tokens: int = DEFAULT_MAX_TOKENS) -> LLMResult:
        path = self.cache_dir / f"{self._key(system, messages, max_tokens)}.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return LLMResult(data["text"], data["stop_reason"], data["input_tokens"],
                             data["output_tokens"], True, self.model)

        # No temperature/top_p: Claude Haiku 5.5 rejects non-default sampling values.
        response = self._api().messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
            output_config={"effort": self.effort},
        )
        text = "".join(block.text for block in response.content if block.type == "text")
        record = {
            "text": text,
            "stop_reason": response.stop_reason,
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
        }
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record), encoding="utf-8")
        tmp.replace(path)  # atomic: a crash never leaves a half-written cache entry
        return LLMResult(text, record["stop_reason"], record["input_tokens"],
                         record["output_tokens"], False, self.model)
