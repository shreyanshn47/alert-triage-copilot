"""The verdict the model must return, and the result the service hands back."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["attack", "sigma", "alert_field"]
    ref: str = Field(min_length=1, max_length=300)  # technique id | rule title | field name
    quote: str = Field(min_length=1, max_length=500)


class Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # unknown keys are an invalid answer, not ignored

    verdict: Literal["malicious", "benign", "needs_human"]
    technique_id: str | None = Field(default=None, pattern=r"^T\d{4}(\.\d{3})?$")
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = Field(max_length=8)
    rationale: str = Field(min_length=1, max_length=1200)


class RetrievedRef(BaseModel):
    source: str
    ref: str
    technique_ids: list[str]
    score: float


class Usage(BaseModel):
    calls: int = 0  # LLM calls made for this alert, cached or not
    cached_calls: int = 0
    input_tokens: int = 0  # live (billed) calls only
    output_tokens: int = 0
    cost_usd: float | None = None  # estimate for live calls; None when the model has no price entry


class TriageResult(BaseModel):
    """What POST /alerts/{id}/triage returns. A recommendation only: nothing acts on it."""

    verdict: Verdict
    status: Literal["ok", "retried", "fallback"]  # first-try valid | valid after one retry | gave up
    reason: str | None = None  # why the verdict was replaced by needs_human, when it was
    model_verdict: str | None = None  # what the model itself said, if that was overridden
    model: str
    retrieved: list[RetrievedRef] = []
    quotes_verified: int = 0  # evidence quotes found verbatim in their cited source
    quotes_total: int = 0
    usage: Usage = Usage()
