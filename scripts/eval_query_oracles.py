"""Recompute and exactly compare frozen deterministic-query data oracles."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from fleet.domain.latest import select_latest_observations
from fleet.domain.metrics import (
    high_severity_compliance_failure,
    parse_macos_major,
    primary_disk_free_percent,
    select_primary_disk,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data" / "device-telemetry-dataset.ndjson"
GOLDEN = ROOT / "evals" / "golden" / "phase04_query_oracles.json"
EXPECTED_SHA256 = "fb0ee31ffeeb731b919fc4d5124098c9c5b68cf3fba35eed5092a9f73655c4de"


def compute_oracles() -> dict:
    source_bytes = SOURCE.read_bytes()
    data_sha = hashlib.sha256(source_bytes).hexdigest()
    if data_sha != EXPECTED_SHA256:
        raise SystemExit(f"source hash mismatch: got {data_sha}, expected {EXPECTED_SHA256}")
    rows = []
    for line_number, line in enumerate(source_bytes.splitlines(), start=1):
        row = json.loads(line)
        row["line_number"] = line_number
        rows.append(row)
    latest = select_latest_observations(rows, datetime.max.replace(tzinfo=UTC))
    by_company: dict[str, list[dict]] = {}
    for row in latest:
        by_company.setdefault(row["company_id"], []).append(row)

    older_devices: dict[str, list[str]] = {}
    for company, snapshots in sorted(by_company.items()):
        older_devices[company] = sorted(
            row["device_id"]
            for row in snapshots
            if (major := parse_macos_major(row["os"]["platform"], row["os"]["product_version"]))
            is not None
            and major < 15
        )

    acme = by_company["acme-001"]
    low_disk = []
    for row in acme:
        volume = select_primary_disk(row["os"]["platform"], row["disk_volumes"])
        metric = primary_disk_free_percent(row["os"]["platform"], row["disk_volumes"])
        if metric.valid and metric.value is not None and metric.value < Decimal(20):
            low_disk.append(
                {
                    "device_id": row["device_id"],
                    "mount_point": volume["mount_point"],
                    "free_percent": format(metric.value, ".2f"),
                }
            )
    low_disk.sort(key=lambda item: item["device_id"])

    screen_failures = [
        compliance
        for row in acme
        for compliance in row["compliance_results"]
        if compliance["check_id"].casefold() == "screen_lock"
        and compliance["status"].casefold() == "fail"
    ]
    all_latest_compliance = [
        compliance for row in latest for compliance in row["compliance_results"]
    ]
    data_as_of = {
        company: _utc_z(max(_parse_time(row["collected_at"]) for row in snapshots))
        for company, snapshots in sorted(by_company.items())
    }
    return {
        "data_sha256": data_sha,
        "latest_inventory_by_tenant": {
            company: len(snapshots) for company, snapshots in sorted(by_company.items())
        },
        "latest_macos_major_below_15": {
            "count": sum(len(devices) for devices in older_devices.values()),
            "devices_by_tenant": older_devices,
        },
        "acme_primary_disk_free_below_20_percent": low_disk,
        "acme_screen_lock_failures": {
            "count": len(screen_failures),
            "severity_counts": dict(
                sorted(Counter(c["severity"].casefold() for c in screen_failures).items())
            ),
        },
        "latest_high_severity_compliance_failures_all_tenants": sum(
            high_severity_compliance_failure(c["status"], c["severity"])
            for c in all_latest_compliance
        ),
        "acme_battery_service_recommended": sum(
            row.get("battery") is not None
            and isinstance(row["battery"].get("condition"), str)
            and row["battery"]["condition"].casefold() == "service recommended"
            for row in acme
        ),
        "data_as_of_by_tenant": data_as_of,
    }


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _utc_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def main() -> int:
    actual = compute_oracles()
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    if actual != expected:
        print("Query oracle mismatch")
        print("Expected:")
        print(json.dumps(expected, indent=2, sort_keys=True))
        print("Actual:")
        print(json.dumps(actual, indent=2, sort_keys=True))
        return 1
    print(f"PASS: exact query oracle match ({actual['data_sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
