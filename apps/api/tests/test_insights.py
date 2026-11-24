from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

import pytest

from fleet.core.identity import Membership, Principal, RequestContext
from fleet.domain.insights import (
    InsightObservation,
    InsightPolicy,
    detect_insights,
)
from fleet.domain.query import SourceRowReference

ROOT = Path(__file__).resolve().parents[3]
BASE = datetime(2026, 1, 1, tzinfo=UTC)


def observation(
    index: int,
    *,
    device: str = "d1",
    tenant: str = "tenant-a",
    disk: str | None = "8.00",
    ram: str | None = "0.90",
    battery=None,
    compliance=(),
    platform="darwin",
    version="14.5",
) -> InsightObservation:
    at = BASE + timedelta(days=index)
    source = SourceRowReference(
        snapshot_id=index + 1,
        device_id=device,
        collected_at=at,
        source_path="dataset.ndjson",
        source_line_number=index + 1,
        source_row_sha256=f"{index + 1:064x}",
        data_sha256="a" * 64,
    )
    return InsightObservation(
        tenant=tenant,
        device_id=device,
        snapshot_id=index + 1,
        collected_at=at,
        os_platform=platform,
        os_product_version=version,
        disk_free_percent=Decimal(disk) if disk is not None else None,
        disk_valid=disk is not None,
        disk_available_bytes=100 if disk is not None else None,
        disk_size_bytes=1000 if disk is not None else None,
        ram_utilization=Decimal(ram) if ram is not None else None,
        ram_valid=ram is not None,
        ram_used_bytes=900 if ram is not None else None,
        ram_total_bytes=1000 if ram is not None else None,
        battery=battery,
        compliance=tuple(compliance),
        source=source,
        field_paths={
            "disk_available": "$.disk_volumes[0].available_bytes",
            "disk_size": "$.disk_volumes[0].size_bytes",
            "ram_used": "$.memory.used_memory_bytes",
            "ram_total": "$.memory.total_memory_bytes",
            "battery_condition": "$.battery.condition",
            "battery_percentage": "$.battery.percentage",
            "battery_cycle_count": "$.battery.cycle_count",
            "battery_full_charge_capacity": "$.battery.full_charge_capacity",
            "os_version": "$.os.product_version",
            "compliance_status:encryption": "$.compliance_results[0].status",
        },
    )


def find(result, kind):
    return next((item for item in result if item.kind == kind), None)


def test_storage_detector_uses_latest_ten_days_and_critical_is_heuristic():
    rows = [observation(i) for i in range(10)]
    insights, insufficient = detect_insights(rows, tenant="tenant-a", as_of=rows[-1].collected_at)
    hit = find(insights, "persistent_low_storage")
    assert hit is not None
    assert (hit.numerator, hit.denominator, hit.coverage.observed_days) == (10, 10, 10)
    assert hit.severity_heuristic == "critical"
    assert "policy heuristic" in hit.explanation
    assert "high-severity compliance" not in hit.kind
    assert not any(
        item.detector in {"persistent_low_storage", "sustained_ram_pressure"}
        for item in insufficient
    )


def test_storage_cutoff_and_threshold_sensitivity_change_signal_reproducibly():
    rows = [observation(i, disk="15.00" if i < 7 else "35.00") for i in range(10)]
    base, _ = detect_insights(rows, tenant="tenant-a", as_of=rows[-1].collected_at)
    higher_policy, _ = detect_insights(
        rows,
        tenant="tenant-a",
        as_of=rows[-1].collected_at,
        policy=InsightPolicy(storage_warning_percent=Decimal("50")),
    )
    assert find(base, "persistent_low_storage").numerator == 7
    assert find(higher_policy, "persistent_low_storage").numerator == 10
    assert (
        find(higher_policy, "persistent_low_storage").risk_score
        > find(base, "persistent_low_storage").risk_score
    )
    extra = [observation(i, disk="80.00") for i in range(10, 14)]
    later, _ = detect_insights(rows + extra, tenant="tenant-a", as_of=extra[-1].collected_at)
    assert find(later, "persistent_low_storage") is None


def test_ram_coverage_and_threshold_are_explicit_and_monotone():
    rows = [observation(i, disk=None, ram="0.90" if i < 8 else "0.70") for i in range(10)]
    insights, insufficient = detect_insights(rows, tenant="tenant-a", as_of=rows[-1].collected_at)
    assert find(insights, "sustained_ram_pressure").numerator == 8
    assert not any(item.detector == "sustained_ram_pressure" for item in insufficient)
    strict, _ = detect_insights(
        rows,
        tenant="tenant-a",
        as_of=rows[-1].collected_at,
        policy=InsightPolicy(ram_threshold=Decimal("0.95")),
    )
    assert find(strict, "sustained_ram_pressure") is None


def test_insufficient_series_is_reported_not_converted_to_normal():
    rows = [observation(i, disk=None, ram=None, battery=None) for i in range(6)]
    insights, insufficient = detect_insights(rows, tenant="tenant-a", as_of=rows[-1].collected_at)
    assert find(insights, "sustained_ram_pressure") is None
    assert find(insights, "battery_service_condition") is None
    assert {item.detector for item in insufficient} == {
        "persistent_low_storage",
        "sustained_ram_pressure",
        "battery_service_condition",
    }
    assert next(
        item for item in insufficient if item.detector == "battery_service_condition"
    ).reason.endswith("unknown")


def test_configured_minimum_coverage_and_telemetry_staleness_are_explicit():
    rows = [observation(i, disk=None, ram="0.9" if i < 7 else None) for i in range(10)]
    high_coverage, insufficient = detect_insights(
        rows,
        tenant="tenant-a",
        as_of=rows[-1].collected_at,
        policy=InsightPolicy(ram_min_coverage=0.8),
    )
    assert find(high_coverage, "sustained_ram_pressure") is None
    assert any(item.detector == "sustained_ram_pressure" for item in insufficient)
    stale_cutoff = rows[-1].collected_at + timedelta(days=9)
    stale, _ = detect_insights(rows, tenant="tenant-a", as_of=stale_cutoff)
    assert find(stale, "telemetry_blind_spot").severity_heuristic == "warning"
    fresh, _ = detect_insights(rows, tenant="tenant-a", as_of=rows[-1].collected_at)
    assert find(fresh, "telemetry_blind_spot") is None


def test_request_context_rejects_cross_tenant_insight_scope_before_database_access():
    principal = Principal(
        "user-a", (Membership("tenant-a", frozenset({"viewer"})),), "tenant-a", "test"
    )
    with pytest.raises(ValueError, match="authorized, resolved tenant"):
        RequestContext(session=object(), principal=principal, tenant_id=2, tenant_key="tenant-b")


def test_battery_service_uses_exact_observation_and_does_not_infer_health():
    rows = [
        observation(i, disk=None, ram=None, battery={"condition": "Normal", "percentage": 20})
        for i in range(9)
    ]
    rows.append(
        observation(
            9,
            disk=None,
            ram=None,
            battery={"condition": "Service Recommended", "percentage": 52, "cycle_count": 700},
        )
    )
    insights, _ = detect_insights(rows, tenant="tenant-a", as_of=rows[-1].collected_at)
    hit = find(insights, "battery_service_condition")
    assert hit is not None
    assert "health percentage" in " ".join(hit.limitations)
    assert hit.supporting_readings
    missing_latest, _ = detect_insights(
        rows[:-1] + [observation(10, disk=None, ram=None, battery=None)],
        tenant="tenant-a",
        as_of=BASE + timedelta(days=10),
    )
    assert find(missing_latest, "battery_service_condition") is None
    no_condition, insufficient = detect_insights(
        [observation(0, disk=None, ram=None, battery={"percentage": 70})],
        tenant="tenant-a",
        as_of=BASE,
    )
    assert find(no_condition, "battery_service_condition") is None
    assert any(item.detector == "battery_service_condition" for item in insufficient)


def test_compliance_drift_and_source_high_failure_are_separate():
    rows = [
        observation(
            0,
            disk=None,
            ram=None,
            compliance=({"check_id": "encryption", "status": "pass", "severity": "high"},),
        ),
        observation(
            1,
            disk=None,
            ram=None,
            compliance=({"check_id": "encryption", "status": "fail", "severity": "medium"},),
        ),
    ]
    insights, _ = detect_insights(rows, tenant="tenant-a", as_of=rows[-1].collected_at)
    drift = find(insights, "compliance_drift")
    assert drift is not None and drift.numerator == 1
    assert find(insights, "high_severity_compliance_failure") is None
    high_rows = rows[:-1] + [
        observation(
            1,
            disk=None,
            ram=None,
            compliance=({"check_id": "encryption", "status": "fail", "severity": "high"},),
        )
    ]
    high, _ = detect_insights(high_rows, tenant="tenant-a", as_of=high_rows[-1].collected_at)
    assert find(high, "high_severity_compliance_failure") is not None


def test_os_version_is_numeric_and_platform_scoped():
    rows = [observation(0, disk=None, ram=None, platform="darwin", version="14.10")]
    insights, _ = detect_insights(rows, tenant="tenant-a", as_of=rows[0].collected_at)
    assert find(insights, "os_obsolescence") is not None
    windows, _ = detect_insights(
        [observation(0, disk=None, ram=None, platform="win32", version="10 22H2")],
        tenant="tenant-a",
        as_of=rows[0].collected_at,
    )
    assert find(windows, "os_obsolescence") is not None
    windows_current, _ = detect_insights(
        [observation(0, disk=None, ram=None, platform="win32", version="11 23H2")],
        tenant="tenant-a",
        as_of=rows[0].collected_at,
    )
    assert find(windows_current, "os_obsolescence") is None


def test_property_threshold_monotonicity_for_storage_and_ram():
    import random

    rng = random.Random(61107)
    as_of = BASE + timedelta(days=9)
    for _ in range(100):
        disk_values = [Decimal(rng.randrange(0, 100)) for _ in range(10)]
        ram_values = [Decimal(rng.randrange(0, 101)) / 100 for _ in range(10)]
        disk_rows = [observation(i, disk=str(disk_values[i]), ram=None) for i in range(10)]
        ram_rows = [observation(i, disk=None, ram=str(ram_values[i])) for i in range(10)]
        disk20, _ = detect_insights(
            disk_rows,
            tenant="tenant-a",
            as_of=as_of,
            policy=InsightPolicy(storage_warning_percent=Decimal("20")),
        )
        disk30, _ = detect_insights(
            disk_rows,
            tenant="tenant-a",
            as_of=as_of,
            policy=InsightPolicy(storage_warning_percent=Decimal("30")),
        )
        if find(disk20, "persistent_low_storage"):
            assert find(disk30, "persistent_low_storage") is not None
            assert (
                find(disk30, "persistent_low_storage").numerator
                >= find(disk20, "persistent_low_storage").numerator
            )
        ram80, _ = detect_insights(
            ram_rows,
            tenant="tenant-a",
            as_of=as_of,
            policy=InsightPolicy(ram_threshold=Decimal("0.80")),
        )
        ram90, _ = detect_insights(
            ram_rows,
            tenant="tenant-a",
            as_of=as_of,
            policy=InsightPolicy(ram_threshold=Decimal("0.90")),
        )
        if find(ram90, "sustained_ram_pressure"):
            assert find(ram80, "sustained_ram_pressure") is not None
            assert (
                find(ram80, "sustained_ram_pressure").numerator
                >= find(ram90, "sustained_ram_pressure").numerator
            )


def test_tenant_filter_and_transparent_ranking_weights():
    rows = [observation(i) for i in range(10)] + [
        observation(i, device="d2", tenant="tenant-b") for i in range(10)
    ]
    insights, _ = detect_insights(rows, tenant="tenant-a", as_of=rows[9].collected_at)
    assert all(item.tenant == "tenant-a" and item.device_ids == ["d1"] for item in insights)
    hit = find(insights, "persistent_low_storage")
    assert hit.risk_weights == {
        "signal_weight": 1.0,
        "persistence": 1.0,
        "scope": 1.0,
        "confidence": 1.0,
    }
    assert hit.risk_score == 100


def test_source_dataset_has_zero_high_severity_failures_and_emits_verifiable_example_data():
    source_path = ROOT / "data" / "device-telemetry-dataset.ndjson"
    source_bytes = source_path.read_bytes()
    raw_lines = source_bytes.splitlines()
    rows = [json.loads(line) for line in raw_lines]
    high_failures = [
        check
        for row in rows
        for check in row["compliance_results"]
        if check["status"].casefold() == "fail" and check["severity"].casefold() == "high"
    ]
    assert high_failures == []
    report = json.loads((ROOT / "reports" / "insight_examples.json").read_text(encoding="utf-8"))
    assert report["high_severity_compliance_failures"] == 0
    assert 2 <= len(report["examples"]) <= 3
    assert hashlib.sha256(source_bytes).hexdigest() == report["dataset_sha256"]
    for index, example in enumerate(report["examples"], start=1):
        individual = json.loads(
            (ROOT / "reports" / f"insight_example_{index:02d}.json").read_text(encoding="utf-8")
        )
        assert individual["insight"]["kind"] == example["kind"]
        assert individual["dataset_sha256"] == report["dataset_sha256"]

    def resolve(row, path):
        value = row
        for key, index in re.findall(r"\.([A-Za-z_][A-Za-z0-9_]*)|\[([0-9]+)\]", path[1:]):
            value = value[key] if key else value[int(index)]
        return value

    for example in report["examples"]:
        assert example["suggested_actions_executed"] is False
        assert example["device_ids"]
        for reading in example["supporting_readings"]:
            line_no = reading["snapshot_id"]
            raw_line = raw_lines[line_no - 1]
            row = rows[line_no - 1]
            assert row["device_id"] in example["device_ids"]
            assert hashlib.sha256(raw_line).hexdigest() == reading["source_row_sha256"]
            assert resolve(row, reading["source_path"]) == reading["value"]
            if reading["metric"] in {"disk_available", "disk_size"}:
                volume = resolve(row, reading["source_path"].rsplit(".", 1)[0] + ".available_bytes")
                size = resolve(row, reading["source_path"].rsplit(".", 1)[0] + ".size_bytes")
                expected = (Decimal(volume) * 100 / Decimal(size)).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )
                assert Decimal(reading["derived_value"]) == expected
            if reading["metric"] in {"ram_used", "ram_total"}:
                used = resolve(row, "$.memory.used_memory_bytes")
                total = resolve(row, "$.memory.total_memory_bytes")
                assert Decimal(reading["derived_value"]) == Decimal(used) / Decimal(total)
        assert example["evidence_manifest"]["database_manifest_id"] is None
