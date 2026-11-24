"""Typed public API envelopes and bounded request bodies."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ApiError(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: Literal[
        "unauthorized",
        "forbidden",
        "not_found",
        "invalid_input",
        "rate_limited",
        "stale_evidence",
        "unavailable",
        "conflict",
        "timeout",
        "policy_denied",
        "insufficient_data",
        "stale",
    ]
    message: str
    trace_id: str | None = None


class ApiErrorEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: ApiError


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["ok"]
    uptime_seconds: float
    build_version: str


class MeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: str
    active_tenant: str
    roles: list[str]
    auth_method: str
    identity_mode: Literal["development_fixture", "external"]


class ApiEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[dict[str, Any]] = Field(default_factory=list)
    total_count: int = 0
    page: int = 1
    page_size: int = 25
    evidence_ids: list[str] = Field(default_factory=list)
    manifest_ids: list[str] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)
    data_as_of: datetime | None = None
    freshness: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    trace_id: str | None = None
    policy_version: str = "fleet-policy-v1"
    data_sha256: list[str] = Field(default_factory=list)
    graph_version: str = "not_applicable"
    prompt_version: str = "not_applicable"
    model_version: str = "not_applicable"
    error: ApiError | None = None


class AgentRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    question: str = Field(min_length=1, max_length=2000)
    conversation_id: str | None = Field(default=None, max_length=128)
    input_history: str = Field(default="", max_length=8000)


class AgentRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str
    answer: dict[str, Any]
    trace: list[dict[str, Any]] = Field(default_factory=list)
    step_events: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)
    versions: dict[str, Any]
    evidence_ids: list[str] = Field(default_factory=list)
    manifest_ids: list[str] = Field(default_factory=list)
    coverage: list[dict[str, Any]] = Field(default_factory=list)
    data_as_of: datetime | None = None
    freshness: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    trace_id: str
    trace_persisted: bool = False


class ProposalAuditResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_id: int
    proposal_hash: str
    status: str
    events: list[dict[str, Any]]
    trace_id: str | None = None
