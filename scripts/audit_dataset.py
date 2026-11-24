"""Inspect NDJSON shape, field missingness, and dataset-specific invariants."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

CATEGORY_PATHS = {
    "os.platform",
    "os.product_name",
    "os.architecture",
    "os.kernel_name",
    "battery.condition",
    "battery.charging_status",
    "disk_volumes[].mount_point",
    "disk_volumes[].file_system",
    "compliance_results[].status",
    "compliance_results[].severity",
    "network[].family",
    "network[].internal",
}


def collect(
    value: Any,
    prefix: str,
    counts: dict[str, Counter],
    samples: dict[str, list[Any]],
    object_counts: Counter[str],
    property_counts: Counter[str],
    array_lengths: dict[str, Counter],
    numeric_values: dict[str, list[int]],
    category_values: dict[str, Counter],
) -> None:
    path = prefix or "$"
    kind = "null" if value is None else type(value).__name__
    counts[path][kind] += 1
    if type(value) is int:
        numeric_values[path].append(value)
    if path in CATEGORY_PATHS and (isinstance(value, str) or type(value) is bool):
        category_values[path][str(value)] += 1
    if len(samples[path]) < 4 and not isinstance(value, (dict, list)):
        samples[path].append(value)
    if isinstance(value, dict):
        object_counts[path] += 1
        for key, child in value.items():
            child_path = f"{prefix}.{key}" if prefix else key
            property_counts[child_path] += 1
            if isinstance(child, list):
                array_lengths[child_path][len(child)] += 1
            collect(
                child,
                child_path,
                counts,
                samples,
                object_counts,
                property_counts,
                array_lengths,
                numeric_values,
                category_values,
            )
    elif isinstance(value, list):
        for child in value:
            collect(
                child,
                f"{prefix}[]",
                counts,
                samples,
                object_counts,
                property_counts,
                array_lengths,
                numeric_values,
                category_values,
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    raw = args.source.read_bytes()
    lines = raw.splitlines()
    records: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    row_hashes: list[str] = []
    counts: dict[str, Counter] = defaultdict(Counter)
    samples: dict[str, list[Any]] = defaultdict(list)
    object_counts: Counter[str] = Counter()
    property_counts: Counter[str] = Counter()
    array_lengths: dict[str, Counter] = defaultdict(Counter)
    numeric_values: dict[str, list[int]] = defaultdict(list)
    category_values: dict[str, Counter] = defaultdict(Counter)
    top_level_keys: Counter[str] = Counter()
    timestamps: list[datetime] = []
    company_devices: set[tuple[str, str]] = set()
    company_employees: set[tuple[str, str]] = set()
    devices_by_company: dict[str, set[str]] = defaultdict(set)
    snapshots_by_company: Counter[str] = Counter()
    snapshots_by_device: Counter[tuple[str, str]] = Counter()
    byte_observations = Counter()
    compliance_high_fails = 0
    battery_missing = network_missing = 0

    for line_number, line in enumerate(lines, start=1):
        row_hashes.append(hashlib.sha256(line).hexdigest())
        try:
            row = json.loads(line)
            if not isinstance(row, dict):
                raise TypeError("NDJSON line must contain a JSON object")
        except (json.JSONDecodeError, TypeError) as error:
            errors.append({"line": line_number, "error": str(error)})
            continue
        records.append(row)
        top_level_keys.update(row.keys())
        collect(
            row,
            "",
            counts,
            samples,
            object_counts,
            property_counts,
            array_lengths,
            numeric_values,
            category_values,
        )
        company_id = row.get("company_id")
        device_id = row.get("device_id")
        employee_id = row.get("employee_id")
        if isinstance(company_id, str) and isinstance(device_id, str):
            company_devices.add((company_id, device_id))
            devices_by_company[company_id].add(device_id)
            snapshots_by_company[company_id] += 1
            snapshots_by_device[(company_id, device_id)] += 1
        if isinstance(company_id, str) and isinstance(employee_id, str):
            company_employees.add((company_id, employee_id))
        if "battery" not in row:
            battery_missing += 1
        if "network" not in row:
            network_missing += 1
        collected = row.get("collected_at")
        try:
            parsed = datetime.fromisoformat(collected.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("timestamp has no UTC offset")
            timestamps.append(parsed)
        except (AttributeError, ValueError) as error:
            errors.append({"line": line_number, "error": f"invalid collected_at: {error}"})
        for volume in row.get("disk_volumes") or []:
            size = volume.get("size_bytes")
            available = volume.get("available_bytes")
            if isinstance(size, int):
                byte_observations["size_zero"] += size == 0
                byte_observations["size_negative"] += size < 0
            if isinstance(size, int) and isinstance(available, int):
                byte_observations["available_negative"] += available < 0
                byte_observations["available_gt_size"] += available > size
        for result in row.get("compliance_results") or []:
            compliance_high_fails += (
                result.get("status") == "fail" and result.get("severity") == "high"
            )

    field_stats = {}
    for path, type_counts in sorted(counts.items()):
        values = sum(type_counts.values())
        parent = path.rsplit(".", 1)[0] if "." in path else "$"
        missing = (
            object_counts[parent] - property_counts[path]
            if path != "$" and not path.endswith("[]")
            else None
        )
        field_stats[path] = {
            "occurrences": values,
            "missing_from_parent_objects": missing,
            "types": dict(type_counts),
            "sample_values": samples[path],
        }

    report = {
        "source": str(args.source),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "line_count": len(lines),
        "valid_object_count": len(records),
        "invalid_line_count": len(errors),
        "invalid_lines": errors,
        "top_level_keys": dict(sorted(top_level_keys.items())),
        "field_occurrences": field_stats,
        "object_counts_by_path": dict(sorted(object_counts.items())),
        "array_length_distributions": {
            path: dict(sorted(lengths.items())) for path, lengths in sorted(array_lengths.items())
        },
        "numeric_ranges": {
            path: {"count": len(values), "min": min(values), "max": max(values)}
            for path, values in sorted(numeric_values.items())
        },
        "category_counts": {
            path: dict(sorted(values.items())) for path, values in sorted(category_values.items())
        },
        "missingness": {
            "records_without_battery_key": battery_missing,
            "records_without_network_key": network_missing,
            "records_with_battery_null": counts["battery"].get("null", 0),
            "records_with_network_null": counts["network"].get("null", 0),
        },
        "dataset_counts": {
            "companies": len(devices_by_company),
            "devices": len(company_devices),
            "snapshots_by_company": dict(sorted(snapshots_by_company.items())),
            "devices_by_company": {
                key: len(value) for key, value in sorted(devices_by_company.items())
            },
            "snapshot_counts_per_company_device": dict(
                sorted(
                    (f"{company}/{device}", count)
                    for (company, device), count in snapshots_by_device.items()
                )
            ),
            "company_employee_associations": len(company_employees),
        },
        "timestamp_range": {
            "first": min(timestamps).isoformat() if timestamps else None,
            "last": max(timestamps).isoformat() if timestamps else None,
        },
        "disk_byte_edge_counts": dict(byte_observations),
        "compliance_high_fails": compliance_high_fails,
        "row_sha256": row_hashes,
    }
    output = json.dumps(report, indent=2, default=str)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
