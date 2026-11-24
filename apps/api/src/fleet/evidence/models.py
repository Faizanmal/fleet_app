"""Typed, deterministic evidence ledger contracts."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class EvidencePointer(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: int
    dataset_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_id: int
    device_id: str
    collected_at: datetime
    field_path: str
    field_value_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_id: str = Field(pattern=r"^ev_[0-9a-f]{64}$")


class AggregateManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: int
    query_version: str
    query_type: str
    filters: dict[str, Any]
    as_of: datetime
    selection_rule: str
    matched_snapshot_refs: tuple[dict[str, Any], ...]
    excluded_refs: tuple[dict[str, Any], ...]
    numerator: Decimal | int | None
    denominator: Decimal | int | None
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    query_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    threshold_version: str
    latest_observed_at: datetime | None
    coverage: dict[str, int | None]
    manifest_id: str = Field(pattern=r"^man_[0-9a-f]{64}$")


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_type: Literal["count", "ratio", "percent", "list_ids", "field_value"]
    value: Any
    unit: str | None = None
    scope: str
    as_of: datetime
    evidence_ids: tuple[str, ...] = ()
    query_manifest_id: str | None = None
    method: str
    coverage: dict[str, int | None]
    limitations: tuple[str, ...] = ()
    policy_version: str
