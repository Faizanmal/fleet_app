from __future__ import annotations

import random
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from fleet.domain.latest import select_latest_observations
from fleet.domain.metrics import (
    disk_free_percent,
    evaluate_threshold,
    high_severity_compliance_failure,
    parse_macos_major,
    primary_disk_free_percent,
    ram_utilization,
    select_primary_disk,
)
from fleet.domain.query import NumericRange, SnapshotFilters, normalize_as_of


def test_windows_primary_mount_accepts_c_drive_spellings_and_never_falls_back():
    assert select_primary_disk("win32", [{"mount_point": "C:\\"}]) is not None
    assert select_primary_disk("windows", [{"mount_point": "c:"}]) is not None
    assert select_primary_disk("win32", [{"mount_point": "D:\\"}]) is None
    assert select_primary_disk("darwin", [{"mount_point": "/System/Data"}]) is None
    assert select_primary_disk("darwin", [{"mount_point": "/"}]) is not None
    assert select_primary_disk("win32", [{"mount_point": "C:\\"}, {"mount_point": "C:"}]) is None


def test_disk_metric_rounding_invalid_denominators_and_bounds():
    assert disk_free_percent(259, 10_000).value == Decimal("2.59")
    assert disk_free_percent(200, 10_000).value == Decimal("2.00")
    assert disk_free_percent(0, 1).value == Decimal("0.00")
    assert disk_free_percent(1, 0).valid is False
    assert disk_free_percent(11, 10).valid is False
    assert (
        primary_disk_free_percent(
            "windows", [{"mount_point": "D:\\", "size_bytes": 10, "available_bytes": 5}]
        ).value
        is None
    )


def test_ram_metric_has_explicit_zero_missing_and_invalid_semantics():
    assert ram_utilization(0, 8).value == Decimal(0)
    assert ram_utilization(4, 8).value == Decimal("0.5")
    assert ram_utilization(1, 0).valid is False
    assert ram_utilization(None, 8).reason == "invalid_used_memory"
    assert ram_utilization(9, 8).valid is False


def test_macos_major_parser_is_numeric_platform_restricted_and_unknown_safe():
    assert parse_macos_major("darwin", "14.10") == 14
    assert parse_macos_major("macOS", "9.9") == 9
    assert parse_macos_major("win32", "14.5") is None
    assert parse_macos_major("darwin", "unknown") is None
    assert parse_macos_major("darwin", None) is None
    assert (parse_macos_major("darwin", "14.10") or 0) < 15
    assert not (parse_macos_major("darwin", "15.0") or 0) < 15


def test_high_severity_failure_is_exact_status_and_severity_pair():
    assert high_severity_compliance_failure("FAIL", "High") is True
    assert high_severity_compliance_failure("fail", "medium") is False
    assert high_severity_compliance_failure("pass", "high") is False
    assert high_severity_compliance_failure(None, "high") is False


def test_latest_selection_applies_tenant_as_of_and_duplicate_timestamp_tie_break():
    rows = [
        {"company_id": "acme", "device_id": "d1", "collected_at": "2026-01-01T00:00:00Z", "id": 1},
        {
            "company_id": "acme",
            "device_id": "d1",
            "collected_at": "2026-01-01T00:00:00+00:00",
            "id": 2,
        },
        {"company_id": "other", "device_id": "d1", "collected_at": "2026-01-01T00:00:00Z", "id": 3},
        {"company_id": "acme", "device_id": "d2", "collected_at": "2026-01-02T00:00:00Z", "id": 4},
    ]
    chosen = select_latest_observations(rows, datetime(2026, 1, 1, 12, tzinfo=UTC))
    assert [(r["company_id"], r["device_id"], r["id"]) for r in chosen] == [
        ("acme", "d1", 2),
        ("other", "d1", 3),
    ]
    assert select_latest_observations(rows, datetime(2025, 1, 1, tzinfo=UTC)) == ()


def test_future_snapshot_is_excluded_at_as_of_cutoff():
    rows = [
        {"company_id": "acme", "device_id": "d1", "collected_at": "2026-01-01T00:00:00Z", "id": 1},
        {"company_id": "acme", "device_id": "d1", "collected_at": "2026-01-03T00:00:00Z", "id": 2},
    ]
    chosen = select_latest_observations(rows, datetime(2026, 1, 2, tzinfo=UTC))
    assert [(row["id"], row["collected_at"]) for row in chosen] == [(1, "2026-01-01T00:00:00Z")]


def test_timezone_normalization_and_as_of_require_offsets():
    assert normalize_as_of(datetime.fromisoformat("2026-01-01T05:30:00+05:30")) == datetime(
        2026, 1, 1, tzinfo=UTC
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        normalize_as_of(datetime(2026, 1, 1))


def test_filters_are_closed_typed_and_reject_operator_injection():
    assert SnapshotFilters(platform="Windows").platform == "win32"
    assert SnapshotFilters(os_major=NumericRange(maximum=Decimal(14))).os_major.maximum == 14
    with pytest.raises(ValidationError):
        SnapshotFilters.model_validate({"tenant_id": "globex-002"})
    with pytest.raises(ValidationError):
        SnapshotFilters.model_validate({"model": {"$ne": ""}})
    with pytest.raises(ValidationError):
        NumericRange(minimum=Decimal(15), maximum=Decimal(10))


def test_seeded_property_checks_metric_bounds_and_monotonicity():
    rng = random.Random(40204)
    for _ in range(2_000):
        size = rng.randint(1, 2**63 - 1)
        available = rng.randint(0, size)
        metric = disk_free_percent(available, size)
        assert metric.valid and metric.value is not None
        assert Decimal(0) <= metric.value <= Decimal(100)
        assert metric.numerator == available and metric.denominator == size

        total = rng.randint(1, 2**63 - 1)
        used = rng.randint(0, total)
        utilization = ram_utilization(used, total)
        assert utilization.valid and utilization.value is not None
        assert Decimal(0) <= utilization.value <= Decimal(1)

        threshold = Decimal("20")
        evaluation = evaluate_threshold(
            metric.value,
            metric="disk_free_percent",
            operator="lt",
            threshold=threshold,
            threshold_source="test-policy",
        )
        assert evaluation.result is (metric.value < threshold)


def test_threshold_unknown_is_not_false():
    result = evaluate_threshold(
        None,
        metric="ram_utilization",
        operator="gt",
        threshold=Decimal("0.8"),
        threshold_source="policy-v1",
    )
    assert result.result is None
    assert result.reason == "metric_unknown"
