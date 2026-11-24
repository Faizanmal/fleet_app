"""Typed, injection-safe inputs and auditable query-result envelopes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fleet.domain.metrics import ThresholdResult

T = TypeVar("T")


class NumericRange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    minimum: Decimal | None = None
    maximum: Decimal | None = None

    @model_validator(mode="after")
    def ordered_range(self) -> NumericRange:
        if any(
            value is not None and not value.is_finite() for value in (self.minimum, self.maximum)
        ):
            raise ValueError("range bounds must be finite")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("minimum must be less than or equal to maximum")
        return self


class SnapshotFilters(BaseModel):
    """Equality/range filters only; no caller-provided operators or SQL fragments."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    platform: str | None = None
    device_id: str | None = None
    model: str | None = None
    employee_id: str | None = None
    compliance_status: str | None = None
    compliance_severity: str | None = None
    compliance_check: str | None = None
    os_major: NumericRange | None = None
    disk_free_percent: NumericRange | None = None
    disk_free_percent_below: Decimal | None = None
    disk_free_percent_above: Decimal | None = None
    ram_utilization: NumericRange | None = None
    collected_at: tuple[datetime | None, datetime | None] | None = None
    sort_by: Literal[
        "device_id",
        "collected_at",
        "platform",
        "model",
        "employee_id",
        "disk_free_percent",
        "ram_utilization",
    ] = "device_id"
    sort_direction: Literal["asc", "desc"] = "asc"
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0)

    @field_validator("platform")
    @classmethod
    def normalize_platform(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.casefold()
        aliases = {"macos": "darwin", "darwin": "darwin", "windows": "win32", "win32": "win32"}
        if normalized not in aliases:
            raise ValueError("platform must be macOS/Darwin or Windows/win32")
        return aliases[normalized]

    @model_validator(mode="after")
    def validate_ranges(self) -> SnapshotFilters:
        if self.disk_free_percent:
            for value in (self.disk_free_percent.minimum, self.disk_free_percent.maximum):
                if value is not None and not Decimal(0) <= value <= Decimal(100):
                    raise ValueError("disk free percent range must be between 0 and 100")
        for value in (self.disk_free_percent_below, self.disk_free_percent_above):
            if value is not None and (
                not value.is_finite() or not Decimal(0) <= value <= Decimal(100)
            ):
                raise ValueError("disk free percent threshold must be finite and between 0 and 100")
        if self.ram_utilization:
            for value in (self.ram_utilization.minimum, self.ram_utilization.maximum):
                if value is not None and not Decimal(0) <= value <= Decimal(1):
                    raise ValueError("RAM utilization range must be between 0 and 1")
        if self.os_major:
            for value in (self.os_major.minimum, self.os_major.maximum):
                if value is not None and (
                    not value.is_finite() or value < 0 or value != value.to_integral_value()
                ):
                    raise ValueError("OS major version bounds must be nonnegative integers")
        if self.collected_at:
            start, end = self.collected_at
            if start and (start.tzinfo is None or start.utcoffset() is None):
                raise ValueError("collected_at range timestamps must be timezone-aware")
            if end and (end.tzinfo is None or end.utcoffset() is None):
                raise ValueError("collected_at range timestamps must be timezone-aware")
            if start and end and start > end:
                raise ValueError("collected_at range start must not exceed end")
        return self


class ThresholdSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    metric: Literal["disk_free_percent", "ram_utilization"]
    operator: Literal["lt", "lte", "gt", "gte"]
    threshold: Decimal
    threshold_source: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_bounds(self) -> ThresholdSpec:
        maximum = Decimal(100) if self.metric == "disk_free_percent" else Decimal(1)
        if not self.threshold.is_finite() or not Decimal(0) <= self.threshold <= maximum:
            raise ValueError(f"threshold for {self.metric} must be between 0 and {maximum}")
        return self


@dataclass(frozen=True)
class QueryScope:
    tenant_id: int
    tenant_key: str


@dataclass(frozen=True)
class SourceRowReference:
    snapshot_id: int
    device_id: str
    collected_at: datetime
    source_path: str
    source_line_number: int
    source_row_sha256: str
    data_sha256: str


@dataclass(frozen=True)
class QueryResult(Generic[T]):  # noqa: UP046 - retain Python 3.11 compatibility
    items: tuple[T, ...]
    scope: QueryScope
    filters: dict[str, object]
    numerator: int | Decimal | None
    denominator: int | Decimal | None
    excluded_count: int
    as_of: datetime
    data_as_of: datetime | None
    policy_threshold_source: str | None
    source_row_references: tuple[SourceRowReference, ...]
    data_sha256: tuple[str, ...]
    policy_version: str
    graph_version: str = "not_applicable"
    prompt_version: str = "not_applicable"
    model_version: str = "not_applicable"
    total_count: int = 0
    query_manifest_id: str | None = None


@dataclass(frozen=True)
class SnapshotView:
    snapshot_id: int
    tenant_id: int
    device_id: str
    employee_id: str
    collected_at: datetime
    os_platform: str
    os_product_name: str
    product_version: str | None
    model: str | None
    primary_disk_mount: str | None
    primary_disk_available_bytes: int | None
    primary_disk_size_bytes: int | None
    disk_free_percent: Decimal | None
    disk_free_valid: bool
    disk_free_exclusion_reason: str | None
    used_memory_bytes: int | None
    total_memory_bytes: int | None
    ram_utilization: Decimal | None
    ram_valid: bool
    ram_exclusion_reason: str | None
    battery: dict | None
    compliance: tuple[dict[str, str], ...]
    source: SourceRowReference


@dataclass(frozen=True)
class DeviceReading:
    snapshot_id: int
    device_id: str
    collected_at: datetime
    disk_free_percent: Decimal | None
    ram_utilization: Decimal | None
    validity_mask: dict[str, bool]
    exclusions: tuple[str, ...]
    source: SourceRowReference


@dataclass(frozen=True)
class ThresholdCoverage:
    spec: ThresholdSpec
    results: tuple[ThresholdResult, ...]
    passed_count: int
    failed_count: int
    unknown_count: int
    denominator: int


@dataclass(frozen=True)
class DeviceTimeWindow:
    device_id: str
    readings: tuple[DeviceReading, ...]
    first_observed_at: datetime | None
    last_observed_at: datetime | None
    snapshot_count: int
    disk_valid_count: int
    ram_valid_count: int
    excluded_reading_count: int
    exclusion_counts: dict[str, int]
    threshold_coverages: tuple[ThresholdCoverage, ...]


def normalize_as_of(as_of: datetime) -> datetime:
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError("as_of must be timezone-aware")
    return as_of.astimezone(UTC)
