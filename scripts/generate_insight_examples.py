"""Generate source-row-verifiable insight examples without fabricating DB evidence IDs."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from fleet.domain.insights import detect_insights, observation_from_snapshot

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data" / "device-telemetry-dataset.ndjson"
OUTPUT = ROOT / "reports" / "insight_examples.json"
EXAMPLE_PATTERN = "insight_example_{index:02d}.json"


def main() -> None:
    source_bytes = SOURCE.read_bytes()
    dataset_hash = hashlib.sha256(source_bytes).hexdigest()
    observations = []
    source_rows = []
    for line_number, raw_line in enumerate(source_bytes.splitlines(), start=1):
        row = json.loads(raw_line)
        source_rows.append(row)
        snapshot = SimpleNamespace(
            raw_json=row,
            id=line_number,
            device_id=row["device_id"],
            collected_at=datetime.fromisoformat(row["collected_at"].replace("Z", "+00:00")),
            source_path="data/device-telemetry-dataset.ndjson",
            source_line_number=line_number,
            source_row_sha256=hashlib.sha256(raw_line).hexdigest(),
            data_sha256=dataset_hash,
        )
        observations.append(observation_from_snapshot(snapshot, row["company_id"]))

    cutoff = max(item.collected_at for item in observations)
    selected = []
    # Prefer distinct detector types and use the first stable tenant/device match.
    kinds = [
        "persistent_low_storage",
        "battery_service_condition",
        "compliance_drift",
        "os_obsolescence",
        "sustained_ram_pressure",
    ]
    for kind in kinds:
        for tenant in sorted({item.tenant for item in observations}):
            insights, _ = detect_insights(observations, tenant=tenant, as_of=cutoff)
            match = next((item for item in insights if item.kind == kind), None)
            if match is not None:
                payload = match.model_dump(mode="json")
                payload["evidence_manifest"] = {
                    "database_manifest_id": None,
                    "dataset_sha256": dataset_hash,
                    "source_path": "data/device-telemetry-dataset.ndjson",
                    "source_line_numbers": sorted(
                        {reading.snapshot_id for reading in match.supporting_readings}
                    ),
                    "verification_note": (
                        "snapshot_id is the NDJSON line number in this offline report; "
                        "database evidence IDs are intentionally not fabricated"
                    ),
                }
                payload["suggested_actions_executed"] = False
                selected.append(payload)
                break
        if len(selected) >= 3:
            break
    high_failures = sum(
        check["status"].casefold() == "fail" and check["severity"].casefold() == "high"
        for row in source_rows
        for check in row["compliance_results"]
    )
    report = {
        "report_type": "source_audited_insight_examples",
        "as_of": cutoff.isoformat(),
        "policy_version": "fleet-risk-v1",
        "dataset_sha256": dataset_hash,
        "high_severity_compliance_failures": high_failures,
        "examples": selected,
        "note": (
            "Offline source examples with field-level references. Database aggregate "
            "manifest and persisted evidence IDs require an imported PostgreSQL dataset."
        ),
    }
    OUTPUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for index, example in enumerate(selected, start=1):
        example_report = {
            "report_type": "source_audited_insight_example",
            "as_of": cutoff.isoformat(),
            "policy_version": "fleet-risk-v1",
            "graph_version": "not_applicable",
            "prompt_version": "not_applicable",
            "model_version": "not_applicable",
            "dataset_sha256": dataset_hash,
            "high_severity_compliance_failures": high_failures,
            "insight": example,
        }
        (ROOT / "reports" / EXAMPLE_PATTERN.format(index=index)).write_text(
            json.dumps(example_report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(f"wrote {len(selected)} examples to {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
