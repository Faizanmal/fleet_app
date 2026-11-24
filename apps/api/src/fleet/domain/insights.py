"""Pure deterministic fleet insight detectors and transparent risk ranking."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fleet.domain.metrics import (
    is_primary_mount,
    parse_macos_major,
    primary_disk_free_percent,
    ram_utilization,
)
from fleet.domain.query import SourceRowReference

InsightKind = Literal[
    "persistent_low_storage",
    "sustained_ram_pressure",
    "battery_service_condition",
    "compliance_drift",
    "high_severity_compliance_failure",
    "os_obsolescence",
    "telemetry_blind_spot",
]
SeverityHeuristic = Literal["critical", "warning", "info", "unknown"]


class InsightPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_version: str = "fleet-risk-v1"
    storage_warning_percent: Decimal = Decimal("20")
    storage_critical_percent: Decimal = Decimal("10")
    storage_min_low_count: int = Field(default=7, ge=1, le=10)
    storage_window: int = Field(default=10, ge=1, le=30)
    storage_min_observed_days: int = Field(default=7, ge=1, le=10)
    ram_threshold: Decimal = Decimal("0.85")
    ram_min_count: int = Field(default=7, ge=1, le=10)
    ram_window: int = Field(default=10, ge=1, le=30)
    ram_min_coverage: float = Field(default=0.7, ge=0, le=1)
    macos_min_major: int = Field(default=15, ge=1)
    windows_min_major: int = Field(default=11, ge=1)
    telemetry_sla: timedelta = timedelta(days=7)
    weights: dict[str, float] = Field(
        default_factory=lambda: {
            "persistent_low_storage": 1.0,
            "sustained_ram_pressure": 0.8,
            "battery_service_condition": 0.6,
            "compliance_drift": 0.8,
            "high_severity_compliance_failure": 1.0,
            "os_obsolescence": 0.7,
            "telemetry_blind_spot": 0.7,
        }
    )

    @model_validator(mode="after")
    def compatible_windows(self) -> InsightPolicy:
        if self.storage_min_low_count > self.storage_window:
            raise ValueError("storage_min_low_count cannot exceed storage_window")
        if self.storage_min_observed_days > self.storage_window:
            raise ValueError("storage_min_observed_days cannot exceed storage_window")
        if self.ram_min_count > self.ram_window:
            raise ValueError("ram_min_count cannot exceed ram_window")
        return self

    @field_validator("weights")
    @classmethod
    def bounded_weights(cls, value: dict[str, float]) -> dict[str, float]:
        if any(
            not Decimal(str(weight)).is_finite() or not 0 <= weight <= 1
            for weight in value.values()
        ):
            raise ValueError("risk weights must be finite values between zero and one")
        return value

    @field_validator("storage_warning_percent", "storage_critical_percent")
    @classmethod
    def percent_bounds(cls, value: Decimal) -> Decimal:
        if not value.is_finite() or not Decimal(0) <= value <= Decimal(100):
            raise ValueError("storage thresholds must be between zero and 100")
        return value

    @field_validator("ram_threshold")
    @classmethod
    def utilization_bounds(cls, value: Decimal) -> Decimal:
        if not value.is_finite() or not Decimal(0) <= value <= Decimal(1):
            raise ValueError("RAM threshold must be between zero and one")
        return value


class InsightObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    tenant: str
    device_id: str
    snapshot_id: int
    collected_at: datetime
    os_platform: str
    os_product_version: str | None = None
    disk_free_percent: Decimal | None = None
    disk_valid: bool = False
    disk_available_bytes: int | None = None
    disk_size_bytes: int | None = None
    ram_utilization: Decimal | None = None
    ram_valid: bool = False
    ram_used_bytes: int | None = None
    ram_total_bytes: int | None = None
    battery: dict[str, Any] | None = None
    compliance: tuple[dict[str, str], ...] = ()
    source: SourceRowReference
    field_paths: dict[str, str] = Field(default_factory=dict)


class InsightCoverage(BaseModel):
    eligible: int
    observed: int
    unknown: int
    fraction: float
    observed_days: int = 0


class SupportingReading(BaseModel):
    snapshot_id: int
    collected_at: datetime
    metric: str
    value: Any
    source_path: str
    source_row_sha256: str
    data_sha256: str
    evidence_id: str | None = None
    derived_value: Any | None = None
    calculation: str | None = None


class Insight(BaseModel):
    kind: InsightKind
    tenant: str
    device_ids: list[str]
    severity_heuristic: SeverityHeuristic
    headline: str
    numerator: int | Decimal | None = None
    denominator: int | Decimal | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    latest_observed_at: datetime | None = None
    coverage: InsightCoverage
    policy_version: str
    evidence_manifest: dict[str, Any] = Field(default_factory=dict)
    supporting_readings: list[SupportingReading] = Field(default_factory=list)
    explanation: str
    limitations: list[str] = Field(default_factory=list)
    suggested_action_kinds: list[str] = Field(default_factory=list)
    risk_score: float = 0
    risk_weights: dict[str, float] = Field(default_factory=dict)


class InsufficientSeries(BaseModel):
    device_id: str
    detector: Literal[
        "persistent_low_storage", "sustained_ram_pressure", "battery_service_condition"
    ]
    reason: str
    eligible: int
    observed: int
    coverage: float


class InsightRun(BaseModel):
    tenant: str
    as_of: datetime
    latest_observed_at: datetime | None = None
    policy_version: str
    graph_version: str = "not_applicable"
    prompt_version: str = "not_applicable"
    model_version: str = "not_applicable"
    total_devices: int
    insights: list[Insight]
    insufficient_data: list[InsufficientSeries]
    source_data_sha256: list[str]
    high_severity_compliance_failures: int


def observation_from_snapshot(snapshot: Any, tenant: str) -> InsightObservation:
    """Normalize a DB row or source-shaped record into source-backed metrics."""
    raw = snapshot.raw_json
    os_data = raw.get("os") or {}
    memory = raw.get("memory") or {}
    disk_items = raw.get("disk_volumes") or []
    disk_metric = primary_disk_free_percent(os_data.get("platform"), disk_items)
    ram_metric = ram_utilization(memory.get("used_memory_bytes"), memory.get("total_memory_bytes"))
    paths: dict[str, str] = {
        "os_version": "$.os.product_version",
        "ram_used": "$.memory.used_memory_bytes",
        "ram_total": "$.memory.total_memory_bytes",
        "battery_condition": "$.battery.condition",
        "battery_percentage": "$.battery.percentage",
        "battery_cycles": "$.battery.cycle_count",
    }
    matches = [
        (index, volume)
        for index, volume in enumerate(disk_items)
        if is_primary_mount(os_data.get("platform"), volume.get("mount_point"))
    ]
    if len(matches) == 1:
        index, _ = matches[0]
        paths["disk_available"] = f"$.disk_volumes[{index}].available_bytes"
        paths["disk_size"] = f"$.disk_volumes[{index}].size_bytes"
    for key in ("condition", "percentage", "cycle_count", "full_charge_capacity"):
        paths[f"battery_{key}"] = f"$.battery.{key}"
    for index, check in enumerate(raw.get("compliance_results") or []):
        check_id = str(check.get("check_id", ""))
        paths[f"compliance_status:{check_id}"] = f"$.compliance_results[{index}].status"
        paths[f"compliance_severity:{check_id}"] = f"$.compliance_results[{index}].severity"
    source = (
        snapshot.source
        if hasattr(snapshot, "source")
        else SourceRowReference(
            snapshot_id=int(snapshot.id),
            device_id=snapshot.device_id,
            collected_at=snapshot.collected_at,
            source_path=snapshot.source_path,
            source_line_number=snapshot.source_line_number,
            source_row_sha256=snapshot.source_row_sha256,
            data_sha256=snapshot.data_sha256,
        )
    )
    compliance = tuple(
        {
            "check_id": str(row.get("check_id", "")),
            "status": str(row.get("status", "")),
            "severity": str(row.get("severity", "")),
        }
        for row in (raw.get("compliance_results") or [])
    )
    return InsightObservation(
        tenant=tenant,
        device_id=snapshot.device_id,
        snapshot_id=int(snapshot.id),
        collected_at=snapshot.collected_at,
        os_platform=os_data.get("platform", getattr(snapshot, "os_platform", "unknown")),
        os_product_version=os_data.get("product_version"),
        disk_free_percent=disk_metric.value,
        disk_valid=disk_metric.valid,
        disk_available_bytes=(int(matches[0][1]["available_bytes"]) if len(matches) == 1 else None),
        disk_size_bytes=int(matches[0][1]["size_bytes"]) if len(matches) == 1 else None,
        ram_utilization=ram_metric.value,
        ram_valid=ram_metric.valid,
        ram_used_bytes=memory.get("used_memory_bytes"),
        ram_total_bytes=memory.get("total_memory_bytes"),
        battery=raw.get("battery"),
        compliance=compliance,
        source=source,
        field_paths=paths,
    )


def detect_insights(
    observations: list[InsightObservation],
    *,
    tenant: str,
    as_of: datetime,
    device_last_seen: dict[str, datetime] | None = None,
    policy: InsightPolicy | None = None,
) -> tuple[list[Insight], list[InsufficientSeries]]:
    """Run fixed rules on tenant-filtered observations no newer than the cutoff."""
    rules = policy or InsightPolicy()
    if as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError("as_of must be timezone-aware")
    cutoff = as_of.astimezone(UTC)
    scoped = sorted(
        (o for o in observations if o.tenant == tenant and o.collected_at <= cutoff),
        key=lambda o: (o.device_id, o.collected_at, o.snapshot_id),
    )
    by_device: dict[str, list[InsightObservation]] = defaultdict(list)
    for observation in scoped:
        by_device[observation.device_id].append(observation)
    result: list[Insight] = []
    insufficient: list[InsufficientSeries] = []
    all_devices = sorted(set(by_device) | set(device_last_seen or {}))
    for device_id in all_devices:
        series = by_device.get(device_id, [])
        _detect_storage(tenant, device_id, series, cutoff, rules, result, insufficient)
        _detect_ram(tenant, device_id, series, cutoff, rules, result, insufficient)
        _detect_battery(tenant, device_id, series, cutoff, rules, result, insufficient)
        _detect_compliance(tenant, device_id, series, cutoff, rules, result)
        _detect_os(tenant, device_id, series, cutoff, rules, result)
        _detect_blind_spot(
            tenant,
            device_id,
            series,
            cutoff,
            rules,
            result,
            (device_last_seen or {}).get(device_id),
        )
    _rank(
        result,
        total_devices=len(set((device_last_seen or {}).keys()) | set(by_device)),
        policy=rules,
    )
    return result, insufficient


def _coverage(eligible: int, observed: int, days: int = 0) -> InsightCoverage:
    return InsightCoverage(
        eligible=eligible,
        observed=observed,
        unknown=max(eligible - observed, 0),
        fraction=observed / eligible if eligible else 0.0,
        observed_days=days,
    )


def _readings(rows: list[InsightObservation], metric: str, value_getter) -> list[SupportingReading]:
    result = []
    for row in rows:
        value = value_getter(row)
        paths = row.field_paths
        path = paths.get(metric, "$.collected_at")
        if metric == "disk_free_percent":
            for label, raw_value in (
                ("disk_available", row.disk_available_bytes),
                ("disk_size", row.disk_size_bytes),
            ):
                source_path = paths.get(label)
                if source_path and raw_value is not None:
                    result.append(
                        SupportingReading(
                            snapshot_id=row.snapshot_id,
                            collected_at=row.collected_at,
                            metric=label,
                            value=raw_value,
                            source_path=source_path,
                            source_row_sha256=row.source.source_row_sha256,
                            data_sha256=row.source.data_sha256,
                            derived_value=row.disk_free_percent,
                            calculation="available_bytes / size_bytes * 100; ROUND_HALF_UP to 0.01",
                        )
                    )
            continue
        elif metric == "ram_utilization":
            for label, raw_value in (
                ("ram_used", row.ram_used_bytes),
                ("ram_total", row.ram_total_bytes),
            ):
                source_path = paths[label]
                if raw_value is None:
                    continue
                result.append(
                    SupportingReading(
                        snapshot_id=row.snapshot_id,
                        collected_at=row.collected_at,
                        metric=label,
                        value=raw_value,
                        source_path=source_path,
                        source_row_sha256=row.source.source_row_sha256,
                        data_sha256=row.source.data_sha256,
                        derived_value=row.ram_utilization,
                        calculation="used_memory_bytes / total_memory_bytes",
                    )
                )
            continue
        elif metric == "battery_condition":
            value = row.battery.get("condition") if row.battery else None
            path = paths["battery_condition"]
        elif metric == "os_version":
            value = row.os_product_version
            path = paths["os_version"]
        elif metric.startswith("compliance_status:"):
            path = paths.get(metric, "$.collected_at")
        result.append(
            SupportingReading(
                snapshot_id=row.snapshot_id,
                collected_at=row.collected_at,
                metric=metric,
                value=value,
                source_path=path,
                source_row_sha256=row.source.source_row_sha256,
                data_sha256=row.source.data_sha256,
            )
        )
    return result


def _insight(
    kind: InsightKind,
    tenant: str,
    device: str,
    rows: list[InsightObservation],
    *,
    severity: SeverityHeuristic,
    headline: str,
    numerator: int | Decimal | None,
    denominator: int | Decimal | None,
    policy: InsightPolicy,
    explanation: str,
    limitations: list[str],
    action: str,
    metric: str,
    value_getter,
    eligible: int | None = None,
    observed: int | None = None,
    days: int = 0,
) -> Insight:
    chronological = sorted(rows, key=lambda row: (row.collected_at, row.snapshot_id))
    count = len(chronological)
    support = _readings(chronological, metric, value_getter)
    obs = observed if observed is not None else count
    denom = eligible if eligible is not None else count
    return Insight(
        kind=kind,
        tenant=tenant,
        device_ids=[device],
        severity_heuristic=severity,
        headline=headline,
        numerator=numerator,
        denominator=denominator,
        window_start=chronological[0].collected_at if chronological else None,
        window_end=chronological[-1].collected_at if chronological else None,
        latest_observed_at=chronological[-1].collected_at if chronological else None,
        coverage=_coverage(denom, obs, days),
        policy_version=policy.policy_version,
        supporting_readings=support,
        explanation=explanation,
        limitations=limitations,
        suggested_action_kinds=[action],
    )


def _detect_storage(tenant, device, series, cutoff, policy, result, insufficient):
    eligible = [row for row in series if row.disk_valid and row.disk_free_percent is not None][
        -policy.storage_window :
    ]
    if len(eligible) < policy.storage_window:
        insufficient.append(
            InsufficientSeries(
                device_id=device,
                detector="persistent_low_storage",
                reason="fewer than configured eligible readings",
                eligible=policy.storage_window,
                observed=len(eligible),
                coverage=len(eligible) / policy.storage_window,
            )
        )
        return
    days = len({row.collected_at.date() for row in eligible})
    low = [row for row in eligible if row.disk_free_percent < policy.storage_warning_percent]
    if len(low) < policy.storage_min_low_count or days < policy.storage_min_observed_days:
        return
    latest = eligible[-1]
    critical = latest.disk_free_percent < policy.storage_critical_percent
    result.append(
        _insight(
            "persistent_low_storage",
            tenant,
            device,
            eligible,
            severity="critical" if critical else "warning",
            headline="Primary storage is persistently low",
            numerator=len(low),
            denominator=len(eligible),
            policy=policy,
            explanation=(
                f"{len(low)} of {len(eligible)} eligible readings are below "
                f"{policy.storage_warning_percent}% across {days} observed days. "
                "This is a policy heuristic, not a reported compliance severity."
            ),
            limitations=[
                "Disk free space does not establish cause or user impact.",
                "Critical is a heuristic based on latest primary free space below "
                f"{policy.storage_critical_percent}%.",
            ],
            action="review_storage_capacity",
            metric="disk_free_percent",
            value_getter=lambda row: row.disk_free_percent,
            eligible=policy.storage_window,
            observed=len(eligible),
            days=days,
        )
    )


def _detect_ram(tenant, device, series, cutoff, policy, result, insufficient):
    window = series[-policy.ram_window :]
    valid = [row for row in window if row.ram_valid and row.ram_utilization is not None]
    coverage = len(valid) / policy.ram_window
    if coverage < policy.ram_min_coverage or len(valid) < policy.ram_min_count:
        insufficient.append(
            InsufficientSeries(
                device_id=device,
                detector="sustained_ram_pressure",
                reason="metric coverage below configured minimum",
                eligible=policy.ram_window,
                observed=len(valid),
                coverage=coverage,
            )
        )
        return
    high = [row for row in valid if row.ram_utilization >= policy.ram_threshold]
    if len(high) < policy.ram_min_count:
        return
    result.append(
        _insight(
            "sustained_ram_pressure",
            tenant,
            device,
            window,
            severity="warning",
            headline="Repeated high RAM utilization observed",
            numerator=len(high),
            denominator=policy.ram_window,
            policy=policy,
            explanation=(
                f"RAM utilization met or exceeded {policy.ram_threshold:.0%} on "
                f"{len(high)} of {len(valid)} observed readings in the latest "
                f"{policy.ram_window} observations."
            ),
            limitations=["RAM is a proxy, not proof of application performance or its cause."],
            action="review_memory_capacity",
            metric="ram_utilization",
            value_getter=lambda row: row.ram_utilization,
            eligible=policy.ram_window,
            observed=len(valid),
        )
    )


def _detect_battery(tenant, device, series, cutoff, policy, result, insufficient):
    if not series or series[-1].battery is None or series[-1].battery.get("condition") is None:
        insufficient.append(
            InsufficientSeries(
                device_id=device,
                detector="battery_service_condition",
                reason="latest battery condition is missing; condition is unknown",
                eligible=1,
                observed=0,
                coverage=0.0,
            )
        )
        return
    battery_rows = [row for row in series if row.battery is not None]
    if not battery_rows:
        return
    latest = series[-1]
    if latest.battery.get("condition") != "Service Recommended":
        return
    recent = battery_rows[-10:]
    detail = [
        {
            "at": row.collected_at,
            **{
                field: row.battery[field]
                for field in ("percentage", "cycle_count", "full_charge_capacity")
                if row.battery.get(field) is not None
            },
        }
        for row in recent
        if any(
            row.battery.get(field) is not None
            for field in ("percentage", "cycle_count", "full_charge_capacity")
        )
    ]
    insight = _insight(
        "battery_service_condition",
        tenant,
        device,
        recent,
        severity="warning",
        headline="Battery condition reports Service Recommended",
        numerator=1,
        denominator=1,
        policy=policy,
        explanation=(
            "The latest observed battery condition is exactly 'Service Recommended'. "
            "Charge percentage and cycle counts are observations only."
        ),
        limitations=[
            "No battery health percentage is derived from charge percentage.",
            "Missing battery observations are unknown, not normal.",
        ],
        action="review_battery_service",
        metric="battery_condition",
        value_getter=lambda row: row.battery.get("condition") if row.battery else None,
    )
    if detail:
        insight.explanation += f" Recent observed trajectory: {detail}."
    for row in recent:
        for field in ("percentage", "cycle_count", "full_charge_capacity"):
            value = row.battery.get(field) if row.battery else None
            if value is None:
                continue
            insight.supporting_readings.append(
                SupportingReading(
                    snapshot_id=row.snapshot_id,
                    collected_at=row.collected_at,
                    metric=f"battery_{field}",
                    value=value,
                    source_path=row.field_paths[f"battery_{field}"],
                    source_row_sha256=row.source.source_row_sha256,
                    data_sha256=row.source.data_sha256,
                )
            )
    result.append(insight)


def _detect_compliance(tenant, device, series, cutoff, policy, result):
    checks: dict[str, list[tuple[InsightObservation, dict[str, str]]]] = defaultdict(list)
    for row in series:
        for check in row.compliance:
            checks[check["check_id"]].append((row, check))
    for check_id, values in sorted(checks.items()):
        ordered = sorted(values, key=lambda item: (item[0].collected_at, item[0].snapshot_id))
        for (previous_row, previous), (current_row, current) in zip(
            ordered, ordered[1:], strict=False
        ):
            if previous["status"].casefold() == "pass" and current["status"].casefold() == "fail":
                result.append(
                    _insight(
                        "compliance_drift",
                        tenant,
                        device,
                        [previous_row, current_row],
                        severity="warning",
                        headline=f"Compliance check {check_id} changed from pass to fail",
                        numerator=1,
                        denominator=2,
                        policy=policy,
                        explanation=(
                            f"Source observations show check {check_id} pass at "
                            f"{previous_row.collected_at.isoformat()} and fail at "
                            f"{current_row.collected_at.isoformat()}; source severity is "
                            f"{current['severity']!r}."
                        ),
                        limitations=[
                            "The transition does not establish a cause.",
                            "Source severity is retained separately from this risk heuristic.",
                        ],
                        action="review_compliance_check",
                        metric=f"compliance_status:{check_id}",
                        value_getter=lambda row, selected_check=check_id: next(
                            item["status"]
                            for item in row.compliance
                            if item["check_id"] == selected_check
                        ),
                    )
                )
        latest_by_check = ordered[-1][1] if ordered else None
        if (
            latest_by_check
            and latest_by_check["status"].casefold() == "fail"
            and latest_by_check["severity"].casefold() == "high"
        ):
            row, check = ordered[-1]
            result.append(
                _insight(
                    "high_severity_compliance_failure",
                    tenant,
                    device,
                    [row],
                    severity="warning",
                    headline=f"Source reports high-severity compliance failure: {check_id}",
                    numerator=1,
                    denominator=1,
                    policy=policy,
                    explanation=(
                        "The latest observed source result is "
                        f"status={check['status']!r}, severity={check['severity']!r}."
                    ),
                    limitations=["Source severity is separate from heuristic risk labels."],
                    action="review_compliance_failure",
                    metric=f"compliance_status:{check_id}",
                    value_getter=lambda source_row, selected_check=check_id: next(
                        item["status"]
                        for item in source_row.compliance
                        if item["check_id"] == selected_check
                    ),
                )
            )


def _detect_os(tenant, device, series, cutoff, policy, result):
    if not series:
        return
    latest = series[-1]
    major = parse_macos_major(latest.os_platform, latest.os_product_version)
    family = latest.os_platform.casefold()
    if major is not None and major < policy.macos_min_major:
        minimum = policy.macos_min_major
        family_name = "macOS"
    elif family in {"win32", "windows"} and latest.os_product_version:
        match = re.match(r"^\s*(\d+)", latest.os_product_version)
        major = int(match.group(1)) if match else None
        if major is None or major >= policy.windows_min_major:
            return
        minimum = policy.windows_min_major
        family_name = "Windows"
    else:
        return
    result.append(
        _insight(
            "os_obsolescence",
            tenant,
            device,
            [latest],
            severity="warning",
            headline=f"{family_name} major version {major} is below policy rule {minimum}",
            numerator=major,
            denominator=minimum,
            policy=policy,
            explanation=(
                f"Numeric {family_name} major version {major} is below configured "
                f"policy minimum {minimum}."
            ),
            limitations=[
                "This version filter is not necessarily a current vulnerability assessment.",
                "The comparison uses only the configured numeric major-version rule.",
            ],
            action="review_os_upgrade",
            metric="os_version",
            value_getter=lambda row: row.os_product_version,
        )
    )


def _detect_blind_spot(tenant, device, series, cutoff, policy, result, last_seen):
    if not series:
        severity: SeverityHeuristic = "unknown"
        age = None
        reason = "No telemetry series is available; freshness is unknown, not healthy."
    else:
        latest_at = series[-1].collected_at
        age = cutoff - latest_at
        if age <= policy.telemetry_sla:
            return
        severity = "warning"
        reason = (
            f"Latest telemetry is stale by {age.days} days against a "
            f"{policy.telemetry_sla.days}-day service expectation."
        )
    result.append(
        _insight(
            "telemetry_blind_spot",
            tenant,
            device,
            series[-1:] if series else [],
            severity=severity,
            headline="Telemetry freshness is unknown" if age is None else "Telemetry is stale",
            numerator=age.days if age is not None else None,
            denominator=policy.telemetry_sla.days,
            policy=policy,
            explanation=reason,
            limitations=["Stale or absent telemetry does not imply a healthy or failed device."],
            action="check_telemetry_reporting",
            metric="collected_at",
            value_getter=lambda row: row.collected_at,
        )
    )


def _rank(insights: list[Insight], *, total_devices: int, policy: InsightPolicy) -> None:
    for insight in insights:
        persistence = (
            min(max(float(insight.numerator / insight.denominator), 0.0), 1.0)
            if isinstance(insight.numerator, (int, Decimal))
            and isinstance(insight.denominator, (int, Decimal))
            and insight.denominator
            else 1.0
        )
        scope = len(set(insight.device_ids)) / max(total_devices, 1)
        confidence = insight.coverage.fraction
        weight = policy.weights.get(insight.kind, 0.5)
        insight.risk_weights = {
            "signal_weight": weight,
            "persistence": persistence,
            "scope": scope,
            "confidence": confidence,
        }
        insight.risk_score = round(weight * persistence * scope * confidence * 100, 4)
    insights.sort(
        key=lambda item: (
            -item.risk_score,
            item.kind,
            item.device_ids,
            item.window_end or datetime.min.replace(tzinfo=UTC),
        )
    )
