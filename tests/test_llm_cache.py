import json
from types import SimpleNamespace

import pytest

from app.triage.llm import AnthropicLLM, estimate_cost


class FakeClient:
    """Stands in for anthropic.Anthropic: counts calls, records the arguments."""

    def __init__(self):
        self.calls = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(
            content=[SimpleNamespace(type="thinking", thinking="", text=None),
                     SimpleNamespace(type="text", text='{"ok": true}')],
            stop_reason="end_turn",
            usage=SimpleNamespace(input_tokens=1200, output_tokens=80),
        )


@pytest.fixture
def llm(tmp_path):
    client = FakeClient()
    return AnthropicLLM(model="claude-haiku-5-5", effort="low", cache_dir=tmp_path / "cache", client=client), client


MSGS = [{"role": "user", "content": "hello"}]


def test_second_identical_call_is_served_from_disk_and_is_free(llm):
    model, client = llm
    first = model.complete("sys", MSGS)
    second = model.complete("sys", MSGS)
    assert len(client.calls) == 1
    assert (first.cached, second.cached) == (False, True)
    assert second.text == first.text == '{"ok": true}'
    assert (second.input_tokens, second.output_tokens) == (1200, 80)


def test_any_change_to_the_input_is_a_cache_miss(llm):
    model, client = llm
    model.complete("sys", MSGS)
    model.complete("sys changed", MSGS)
    model.complete("sys", [{"role": "user", "content": "hello!"}])
    model.complete("sys", MSGS, max_tokens=999)
    AnthropicLLM(model="claude-sonnet-5-5", effort="low", cache_dir=model.cache_dir, client=client).complete("sys", MSGS)
    AnthropicLLM(model="claude-haiku-5-5", effort="high", cache_dir=model.cache_dir, client=client).complete("sys", MSGS)
    assert len(client.calls) == 6


def test_only_text_blocks_are_returned_and_thinking_is_ignored(llm):
    model, _ = llm
    assert model.complete("sys", MSGS).text == '{"ok": true}'


def test_request_has_effort_and_no_sampling_parameters(llm):
    model, client = llm
    model.complete("sys", MSGS)
    sent = client.calls[0]
    assert sent["output_config"] == {"effort": "low"} and sent["model"] == "claude-haiku-5-5"
    assert not {"temperature", "top_p", "top_k"} & set(sent)  # Haiku 5.5 rejects non-default sampling


def test_cache_files_hold_only_model_output(llm):
    model, _ = llm
    model.complete("sys", MSGS)
    (path,) = list(model.cache_dir.glob("*.json"))
    assert set(json.loads(path.read_text())) == {"text", "stop_reason", "input_tokens", "output_tokens"}
    assert not list(model.cache_dir.glob("*.tmp"))


def test_cost_estimate_uses_per_million_prices():
    assert estimate_cost("claude-haiku-5-5", 1_000_000, 1_000_000) == pytest.approx(0.60)
    assert estimate_cost("claude-sonnet-5-5", 1_000_000, 0) == pytest.approx(2.00)
    assert estimate_cost("some-unpriced-model", 10, 10) is None
