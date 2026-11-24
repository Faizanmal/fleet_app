"""Create a source-audited Acme evidence example without inventing DB IDs."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

from fleet.domain.latest import select_latest_observations
from fleet.domain.metrics import primary_disk_free_percent, select_primary_disk

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data" / "device-telemetry-dataset.ndjson"
OUTPUT = ROOT / "reports" / "evidence_example.json"


def main() -> int:
    content = SOURCE.read_bytes()
    data_hash = hashlib.sha256(content).hexdigest()
    lines = content.splitlines()
    source_rows = []
    for line_number, line in enumerate(lines, start=1):
        row = json.loads(line)
        row["line_number"] = line_number
        row["source_row_sha256"] = hashlib.sha256(line).hexdigest()
        source_rows.append(row)
    latest = select_latest_observations(source_rows, datetime.max.replace(tzinfo=UTC))
    acme = [row for row in latest if row["company_id"] == "acme-001"]
    matches = []
    excluded = []
    unknown = 0
    for row in acme:
        volume = select_primary_disk(row["os"]["platform"], row["disk_volumes"])
        metric = primary_disk_free_percent(row["os"]["platform"], row["disk_volumes"])
        reference = {
            "device_id": row["device_id"],
            "source_line_number": row["line_number"],
            "source_row_sha256": row["source_row_sha256"],
            "collected_at": datetime.fromisoformat(row["collected_at"].replace("Z", "+00:00"))
            .astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        if not metric.valid or metric.value is None or volume is None:
            unknown += 1
            excluded.append({**reference, "exclusion": metric.reason or "primary_disk_unknown"})
        elif metric.value < Decimal(20):
            matches.append(
                {
                    **reference,
                    "field_path": (
                        f"$.disk_volumes[{row['disk_volumes'].index(volume)}].available_bytes"
                    ),
                    "available_bytes": volume["available_bytes"],
                    "size_bytes": volume["size_bytes"],
                    "mount_point": volume["mount_point"],
                    "free_percent": format(metric.value, ".2f"),
                }
            )
        else:
            excluded.append({**reference, "exclusion": "disk_free_percent_not_below_20"})
    latest_observed = (
        max(datetime.fromisoformat(row["collected_at"].replace("Z", "+00:00")) for row in acme)
        .astimezone(UTC)
        .isoformat()
        .replace("+00:00", "Z")
    )
    report = {
        "status": "source-audited; DB-generated snapshot/evidence IDs pending PostgreSQL import",
        "data_sha256": data_hash,
        "graph_version": "not_applicable",
        "prompt_version": "not_applicable",
        "model_version": "not_applicable",
        "claim": {
            "claim_type": "count",
            "value": len(matches),
            "unit": "devices with primary disk free below 20 percent",
            "scope": "tenant:acme-001 latest inventory",
            "as_of": "2026-06-12T11:00:00Z",
            "evidence_ids": [],
            "query_manifest_id": None,
            "method": "primary_disk_free_percent_lt_20-v1",
            "coverage": {
                "eligible": len(acme),
                "observed": len(acme),
                "unknown": unknown,
                "window_days": None,
            },
            "limitations": [
                "Free-space percentage is available_bytes / size_bytes, rounded to two decimals.",
                "The source rows and hashes are verified; persisted evidence IDs require "
                "PostgreSQL import.",
            ],
            "policy_version": "policy-v1",
        },
        "query_manifest": {
            "query_type": "latest_snapshots",
            "query_version": "deterministic-query-v1",
            "filters": {"tenant": "acme-001", "primary_disk_free_percent": {"lt": "20.00"}},
            "selection_rule": (
                "latest per device within tenant at or before as_of; collected_at DESC, "
                "snapshot ID DESC"
            ),
            "numerator": len(matches),
            "denominator": len(acme),
            "source_hash": data_hash,
            "latest_observed_at": latest_observed,
            "matched_source_snapshots": matches,
            "excluded_references": excluded,
            "coverage": {
                "eligible": len(acme),
                "observed": len(acme),
                "unknown": unknown,
                "window_days": None,
            },
        },
    }
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)}: {len(matches)} matches / {len(acme)} eligible")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
