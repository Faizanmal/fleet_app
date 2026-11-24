"""Structured planner and answer contracts for the fleet agent."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

READ_TOOL_NAMES = frozenset(
    {
        "list_devices",
        "get_device_snapshot",
        "query_compliance",
        "list_software",
        "get_device_history",
        "compute_fleet_trends",
        "rank_fleet_insights",
        "resolve_evidence",
        "get_policy_thresholds",
        "get_action_preconditions",
    }
)


class PlannedToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    tool_name: str = Field(min_length=1, max_length=80)
    arguments: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def allowlisted(self) -> PlannedToolCall:
        if self.tool_name not in READ_TOOL_NAMES:
            raise ValueError("planner may select only allowlisted read tools")
        if "tenant_id" in self.arguments:
            raise ValueError("tenant scope is supplied by trusted server context")
        return self


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    text: str = Field(min_length=1, max_length=1200)
    evidence_ids: list[str] = Field(default_factory=list, max_length=100)
    manifest_ids: list[str] = Field(default_factory=list, max_length=100)


class AgentAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    text: str = Field(min_length=1, max_length=4000)
    claims: list[Claim] = Field(default_factory=list, max_length=30)
    abstained: bool = False
    gaps: list[str] = Field(default_factory=list, max_length=30)


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    steps: list[PlannedToolCall] = Field(default_factory=list, max_length=4)
    answer: AgentAnswer | None = None

    @model_validator(mode="after")
    def has_work(self) -> Plan:
        if not self.steps and self.answer is None:
            raise ValueError("plan must contain read steps or a structured answer")
        if self.steps and self.answer is not None:
            raise ValueError("a plan either requests tools or returns an answer")
        return self
