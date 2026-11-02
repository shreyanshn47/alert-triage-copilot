"""Triage: retrieve context, ask the model, then check its answer in code.

The prompt asks for good behaviour; this module enforces it. Whatever the model says, the result
that leaves here has valid structure, cites only what it was given, and falls back to
needs_human instead of guessing. Nothing in here acts on a verdict: it only recommends one.
"""

import json
import re
from typing import Any

from pydantic import ValidationError

from app.retrieval import retrieve
from app.retrieval.embed import EmbedderLike
from app.retrieval.store import Hit
from app.schemas import ParsedAlert
from app.triage.llm import LLM, estimate_cost
from app.triage.prompt import SYSTEM_PROMPT, alert_fields, build_user_message, retry_message
from app.triage.schema import RetrievedRef, TriageResult, Usage, Verdict

DEFAULT_THRESHOLD = 0.6  # below this the verdict becomes needs_human. Tune on dev only.
MAX_ATTEMPTS = 2  # the first try plus one retry


def _fallback(reason: str) -> Verdict:
    return Verdict(
        verdict="needs_human",
        technique_id=None,
        confidence=0.0,
        evidence=[],
        rationale=f"Automated triage gave no usable answer ({reason[:600]}). A human should review this alert.",
    )


def _extract_json(text: str) -> Any:
    """Parse the model's reply. Tolerates a code fence or stray words around one JSON object."""
    text = text.strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(text[start : end + 1])


def _norm(value: str) -> str:
    return " ".join(value.lower().split())


class _Sources:
    """What the model was allowed to cite, and the text behind each citation."""

    def __init__(self, fields: dict[str, str], hits: list[Hit]) -> None:
        self.fields = fields
        self.attack = {tid.upper(): h.content for h in hits if h.source == "attack" for tid in h.technique_ids}
        self.sigma = {h.ref: h.content for h in hits if h.source == "sigma"}

    def text_for(self, source: str, ref: str) -> str | None:
        ref = ref.strip()
        if source == "alert_field":
            return self.fields.get(ref)
        if source == "attack":
            return self.attack.get(ref.upper())
        return self.sigma.get(ref)


def check_rules(verdict: Verdict, sources: _Sources) -> list[str]:
    """Rules the code enforces whatever the prompt says. Returns the problems found."""
    problems = []
    if verdict.verdict == "malicious" and not verdict.evidence:
        problems.append('verdict "malicious" requires at least one evidence item')
    for ev in verdict.evidence:
        if sources.text_for(ev.source, ev.ref) is None:
            problems.append(f'evidence ref "{ev.ref}" (source "{ev.source}") is not in the context or alert')
    return problems


def _parse_and_check(text: str, sources: _Sources) -> tuple[Verdict | None, list[str]]:
    try:
        verdict = Verdict.model_validate(_extract_json(text))
    except json.JSONDecodeError:
        return None, ["the reply was not valid JSON"]
    except ValidationError as exc:
        return None, [f"{'.'.join(map(str, e['loc'])) or 'reply'}: {e['msg']}" for e in exc.errors()[:6]]
    problems = check_rules(verdict, sources)
    return (None, problems) if problems else (verdict, [])


def _quote_support(verdict: Verdict, sources: _Sources) -> tuple[int, int]:
    """How many evidence quotes appear verbatim (ignoring case and spacing) in what they cite."""
    ok = 0
    for ev in verdict.evidence:
        source_text = sources.text_for(ev.source, ev.ref)
        if source_text is not None and _norm(ev.quote) in _norm(source_text):
            ok += 1
    return ok, len(verdict.evidence)


def triage(
    alert: ParsedAlert,
    tenant_id: str,
    llm: LLM,
    store: Any = None,
    embedder: EmbedderLike | None = None,
    *,
    use_retrieval: bool = True,
    threshold: float = DEFAULT_THRESHOLD,
    k: int = 5,
) -> TriageResult:
    hits = retrieve(alert, tenant_id, store, embedder, k=k) if use_retrieval else []
    sources = _Sources(alert_fields(alert), hits)
    messages: list[dict] = [{"role": "user", "content": build_user_message(alert, hits)}]
    usage = Usage()
    live_in = live_out = 0

    verdict: Verdict | None = None
    reason: str | None = None
    status = "ok"
    for attempt in range(MAX_ATTEMPTS):
        result = llm.complete(SYSTEM_PROMPT, messages)
        usage.calls += 1
        if result.cached:
            usage.cached_calls += 1
        else:
            live_in += result.input_tokens
            live_out += result.output_tokens

        if result.stop_reason == "refusal":
            reason = "model_refused"
            break
        if result.stop_reason == "max_tokens":
            problems = ["the reply was cut off before the JSON was complete"]
        else:
            verdict, problems = _parse_and_check(result.text, sources)
        if verdict is not None:
            status = "ok" if attempt == 0 else "retried"
            break
        reason = "invalid_output: " + "; ".join(problems)
        if attempt + 1 < MAX_ATTEMPTS:
            messages += [{"role": "assistant", "content": result.text or "(empty)"},
                         {"role": "user", "content": retry_message(problems)}]

    usage.input_tokens, usage.output_tokens = live_in, live_out
    usage.cost_usd = estimate_cost(llm.model, live_in, live_out)

    model_verdict = None
    if verdict is None:
        status = "fallback"
        final = _fallback(reason or "unknown")
    else:
        reason = None
        final = verdict
        if verdict.verdict != "needs_human" and verdict.confidence < threshold:
            model_verdict = verdict.verdict
            reason = f"confidence {verdict.confidence:.2f} is below the {threshold:.2f} threshold"
            final = verdict.model_copy(update={"verdict": "needs_human", "technique_id": None})

    verified, total = _quote_support(final, sources)
    return TriageResult(
        verdict=final,
        status=status,
        reason=reason,
        model_verdict=model_verdict,
        model=llm.model,
        retrieved=[RetrievedRef(source=h.source, ref=h.ref, technique_ids=h.technique_ids, score=round(h.score, 4))
                   for h in hits],
        quotes_verified=verified,
        quotes_total=total,
        usage=usage,
    )
