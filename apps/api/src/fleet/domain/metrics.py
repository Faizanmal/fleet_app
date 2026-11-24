"""Pure telemetry metrics with explicit invalid-data semantics."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal

PRIMARY_DISK_OS = frozenset({"darwin", "macos", "win32", "windows"})
PERCENT_QUANTUM = Decimal("0.01")


@dataclass(frozen=True)
class MetricValue:
    value: Decimal | None
    numerator: int | None
    denominator: int | None
    valid: bool
    reason: str | None = None


@dataclass(frozen=True)
class BatteryObservation:
    percentage: int | None
    condition: str | None
    cycle_count: int | None
    full_charge_capacity: int | None
    known: bool


@dataclass(frozen=True)
class ThresholdResult:
    result: bool | None
    metric: str
    operator: Literal["lt", "lte", "gt", "gte"]
    threshold: Decimal
    threshold_source: str
    reason: str | None = None


def parse_macos_major(platform: str | None, product_version: str | None) -> int | None:
    """Parse a numeric major only for macOS/Darwin records."""
    if not platform or platform.strip().casefold() not in {"darwin", "macos"}:
        return None
    if not product_version:
        return None
    match = re.match(r"^\s*(\d+)(?:\.|$)", product_version)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _field(volume: Any, key: str) -> Any:
    if isinstance(volume, Mapping):
        return volume.get(key)
    return getattr(volume, key, None)


def is_primary_mount(platform: str | None, mount_point: str | None) -> bool:
    if not platform or not isinstance(mount_point, str):
        return False
    os_name = platform.strip().casefold()
    mount = mount_point.strip()
    if os_name in {"darwin", "macos"}:
        return mount == "/"
    if os_name in {"win32", "windows"}:
        normalized = mount.replace("/", "\\").rstrip("\\").casefold()
        return normalized == "c:"
    return False


def select_primary_disk(platform: str | None, volumes: Sequence[Any] | None) -> Any | None:
    """Return the unique platform primary volume; ambiguity and absence are unknown."""
    if not volumes:
        return None
    matches = [v for v in volumes if is_primary_mount(platform, _field(v, "mount_point"))]
    return matches[0] if len(matches) == 1 else None


def disk_free_percent(available_bytes: Any, size_bytes: Any) -> MetricValue:
    if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes <= 0:
        return MetricValue(None, None, None, False, "invalid_or_zero_size")
    if not isinstance(available_bytes, int) or isinstance(available_bytes, bool):
        return MetricValue(None, None, size_bytes, False, "invalid_available_bytes")
    if available_bytes < 0 or available_bytes > size_bytes:
        return MetricValue(None, available_bytes, size_bytes, False, "available_out_of_range")
    try:
        value = (Decimal(available_bytes) * 100 / Decimal(size_bytes)).quantize(
            PERCENT_QUANTUM, rounding=ROUND_HALF_UP
        )
    except (InvalidOperation, ZeroDivisionError):
        return MetricValue(None, available_bytes, size_bytes, False, "invalid_ratio")
    return MetricValue(value, available_bytes, size_bytes, True)


def primary_disk_free_percent(platform: str | None, volumes: Sequence[Any] | None) -> MetricValue:
    volume = select_primary_disk(platform, volumes)
    if volume is None:
        return MetricValue(None, None, None, False, "primary_volume_missing_or_ambiguous")
    return disk_free_percent(_field(volume, "available_bytes"), _field(volume, "size_bytes"))


def ram_utilization(used_memory_bytes: Any, total_memory_bytes: Any) -> MetricValue:
    if not isinstance(total_memory_bytes, int) or isinstance(total_memory_bytes, bool):
        return MetricValue(None, None, None, False, "invalid_total_memory")
    if total_memory_bytes <= 0:
        return MetricValue(
            None,
            used_memory_bytes if isinstance(used_memory_bytes, int) else None,
            total_memory_bytes,
            False,
            "zero_or_negative_total_memory",
        )
    if not isinstance(used_memory_bytes, int) or isinstance(used_memory_bytes, bool):
        return MetricValue(None, None, total_memory_bytes, False, "invalid_used_memory")
    if used_memory_bytes < 0 or used_memory_bytes > total_memory_bytes:
        return MetricValue(None, used_memory_bytes, total_memory_bytes, False, "used_out_of_range")
    return MetricValue(
        Decimal(used_memory_bytes) / Decimal(total_memory_bytes),
        used_memory_bytes,
        total_memory_bytes,
        True,
    )


def high_severity_compliance_failure(status: str | None, severity: str | None) -> bool:
    return bool(
        isinstance(status, str)
        and isinstance(severity, str)
        and status.strip().casefold() == "fail"
        and severity.strip().casefold() == "high"
    )


def battery_observation(battery: Mapping[str, Any] | None) -> BatteryObservation:
    if battery is None:
        return BatteryObservation(None, None, None, None, False)
    return BatteryObservation(
        percentage=battery.get("percentage"),
        condition=battery.get("condition"),
        cycle_count=battery.get("cycle_count"),
        full_charge_capacity=battery.get("full_charge_capacity"),
        known=True,
    )


def evaluate_threshold(
    value: Decimal | None,
    *,
    metric: str,
    operator: Literal["lt", "lte", "gt", "gte"],
    threshold: Decimal,
    threshold_source: str,
) -> ThresholdResult:
    if value is None:
        return ThresholdResult(
            None, metric, operator, threshold, threshold_source, "metric_unknown"
        )
    result = {
        "lt": value < threshold,
        "lte": value <= threshold,
        "gt": value > threshold,
        "gte": value >= threshold,
    }[operator]
    return ThresholdResult(result, metric, operator, threshold, threshold_source)


def ratio_summary(values: Sequence[MetricValue]) -> tuple[Decimal | None, int, int, int]:
    """Return pooled ratio, summed numerator, summed denominator, excluded observations."""
    valid = [v for v in values if v.valid and v.numerator is not None and v.denominator]
    numerator = sum(v.numerator for v in valid if v.numerator is not None)
    denominator = sum(v.denominator for v in valid if v.denominator is not None)
    ratio = Decimal(numerator) / Decimal(denominator) if denominator else None
    return ratio, numerator, denominator, len(values) - len(valid)
