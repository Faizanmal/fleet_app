"""Typed action proposal, policy, decision and execution schemas."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ActionKind = Literal[
    "create_upgrade_order",
    "open_remediation_ticket",
    "flag_device_for_replacement",
    "notify_employee",
]
ActionMode = Literal["SANDBOX_SIMULATION", "REAL_EXTERNAL"]
ProposalStatus = Literal[
    "DRAFT",
    "PENDING_APPROVAL",
    "APPROVED",
    "EXECUTING",
    "EXECUTED",
    "REJECTED",
    "EXPIRED",
    "BLOCKED",
    "FAILED",
]
DecisionKind = Literal["approve", "reject"]


class ProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    action_kind: ActionKind
    target_id: str = Field(min_length=1, max_length=255)
    payload: dict[str, Any] = Field(min_length=1, max_length=12)
    evidence_manifest_ids: list[str] = Field(min_length=1, max_length=20)
    mode: ActionMode = "SANDBOX_SIMULATION"

    @field_validator("target_id")
    @classmethod
    def safe_target_id(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", value):
            raise ValueError("invalid target identifier")
        return value

    @field_validator("evidence_manifest_ids")
    @classmethod
    def unique_manifests(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)) or any(
            not re.fullmatch(r"man_[0-9a-f]{64}", value) for value in values
        ):
            raise ValueError("invalid or duplicate evidence manifest identifier")
        return values

    @model_validator(mode="after")
    def action_payload_shape(self) -> ProposalRequest:
        allowed_keys = {
            "create_upgrade_order": {"component", "spec"},
            "open_remediation_ticket": {"check_id", "note"},
            "flag_device_for_replacement": {"reason"},
            "notify_employee": {"message"},
        }[self.action_kind]
        if set(self.payload) != allowed_keys:
            raise ValueError("payload fields do not match action kind")
        for key in ("spec", "note", "reason", "message"):
            if key in self.payload:
                value = self.payload[key]
                if not isinstance(value, str) or not 1 <= len(value.strip()) <= 500:
                    raise ValueError(f"{key} must contain 1–500 characters")
                if any(ord(character) < 32 for character in value):
                    raise ValueError(f"{key} contains control characters")
                if re.search(r"(?:https?://|www\.|\b\S+@\S+\b|-----BEGIN .*KEY-----)", value, re.I):
                    raise ValueError(f"{key} contains unsupported contact, URL, or secret content")
        if "component" in self.payload and self.payload["component"] not in {
            "memory",
            "storage_capacity",
            "battery",
        }:
            raise ValueError("unsupported upgrade component")
        if "check_id" in self.payload and (
            not isinstance(self.payload["check_id"], str)
            or not 1 <= len(self.payload["check_id"]) <= 255
        ):
            raise ValueError("invalid check_id")
        return self


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    decision: DecisionKind
    proposal_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    allowed: bool
    code: str
    message: str
    policy_version: str
    facts: dict[str, Any] = Field(default_factory=dict)


class ProposalDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    tenant_key: str
    actor_id: str
    target_type: Literal["device", "employee"]
    target_id: str
    action_kind: ActionKind
    payload: dict[str, Any]
    evidence_manifest_ids: list[str]
    policy_facts: dict[str, Any]
    data_as_of: datetime
    expires_at: datetime
    mode: ActionMode
    graph_version: str
    policy_version: str
    prompt_version: str
    model_version: str


class ProposalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_id: int
    proposal_hash: str
    status: ProposalStatus
    mode: ActionMode
    proposal: ProposalDocument
    policy_decision: PolicyDecision
    approval_summary: str
    trace_id: str | None = None


class DecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_id: int
    status: ProposalStatus
    decision: DecisionKind
    actor_id: str
    actor_role: Literal["approver", "admin"]
    proposal_hash: str
    workflow_status: str
    trace_id: str | None = None


class ExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    proposal_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ExecutionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_id: int
    execution_id: str
    action_version: str
    status: str
    simulation_mode: Literal["SANDBOX_SIMULATION"]
    result: dict[str, Any]
    repeated: bool = False
    trace_id: str | None = None


class AuditChainVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_key: str
    valid: bool
    events_verified: int
    head_hash: str
    limitation: str
