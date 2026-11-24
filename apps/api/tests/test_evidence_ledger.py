from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

from fleet.actions.service import AUDIT_SENTINEL, _event_digest, verify_audit_events
from fleet.domain.latest import select_latest_observations
from fleet.evidence.ledger import _path_value, canonical_json, make_pointer, stable_hash

ROOT = Path(__file__).resolve().parents[3]


def test_audit_chain_verifier_detects_a_modified_local_event():
    event = SimpleNamespace(
        previous_hash=AUDIT_SENTINEL,
        tenant_id=7,
        actor_id="actor",
        event_type="proposal_approved",
        entity_type="proposal",
        entity_id="12",
        details_json={"trace_id": "trace-safe"},
        created_at=datetime(2026, 11, 23, tzinfo=UTC),
    )
    event.event_hash = _event_digest(
        previous_hash=event.previous_hash,
        tenant_id=event.tenant_id,
        actor_id=event.actor_id,
        event_type=event.event_type,
        entity_type=event.entity_type,
        entity_id=event.entity_id,
        details=event.details_json,
        created_at=event.created_at,
    )
    assert verify_audit_events([event], event.event_hash) == (True, 1, event.event_hash)
    tampered = SimpleNamespace(**event.__dict__)
    tampered.details_json = {"trace_id": "trace-tampered"}
    assert verify_audit_events([tampered], event.event_hash)[0] is False


def _snapshot():
    return SimpleNamespace(
        tenant_id=1,
        data_sha256="a" * 64,
        id=42,
        device_id="device-1",
        collected_at=datetime(2026, 6, 1, tzinfo=UTC),
        raw_json={
            "device_id": "device-1",
            "collected_at": "2026-06-01T00:00:00Z",
            "os": {"platform": "darwin"},
            "disk_volumes": [{"available_bytes": 259, "size_bytes": 10000}],
        },
    )


def test_pointer_identity_is_canonical_and_changes_with_field_or_value():
    snapshot = _snapshot()
    first = make_pointer(snapshot, "$.disk_volumes[0].available_bytes")
    again = make_pointer(snapshot, "$.disk_volumes[0].available_bytes")
    other = make_pointer(snapshot, "$.disk_volumes[0].size_bytes")
    assert first == again
    assert first.evidence_id.startswith("ev_") and len(first.evidence_id) == 67
    assert first.evidence_id != other.evidence_id
    assert first.field_value_hash == stable_hash(259)
    snapshot.raw_json["disk_volumes"][0]["available_bytes"] = 258
    assert (
        make_pointer(snapshot, "$.disk_volumes[0].available_bytes").evidence_id != first.evidence_id
    )


def test_paths_are_exact_and_never_evaluate_arbitrary_expressions():
    assert _path_value(_snapshot().raw_json, "$.disk_volumes[0].available_bytes") == 259
    for path in ("$.unknown", "$.__class__", "$.disk_volumes[*]", "$.__import__('os')"):
        with pytest.raises((ValueError, KeyError)):
            _path_value(_snapshot().raw_json, path)


def test_canonical_json_is_order_independent_and_stable():
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})


def test_sample_report_refs_resolve_to_real_source_rows_and_whole_tenant_count():
    report = json.loads((ROOT / "reports" / "evidence_example.json").read_text(encoding="utf-8"))
    source = (ROOT / "data" / "device-telemetry-dataset.ndjson").read_bytes()
    rows = [json.loads(line) for line in source.splitlines()]
    latest = select_latest_observations(rows, datetime.max.replace(tzinfo=UTC))
    assert (
        sum(row["company_id"] == "acme-001" for row in latest)
        == report["claim"]["coverage"]["eligible"]
    )
    assert report["claim"]["value"] == 2
    assert len(report["query_manifest"]["matched_source_snapshots"]) == 2
    for reference in report["query_manifest"]["matched_source_snapshots"]:
        line = source.splitlines()[reference["source_line_number"] - 1]
        row = json.loads(line)
        assert hashlib.sha256(line).hexdigest() == reference["source_row_sha256"]
        assert row["device_id"] == reference["device_id"]
        assert row["company_id"] == "acme-001"
        assert row["collected_at"].replace("+00:00", "Z") == reference["collected_at"].replace(
            "+00:00", "Z"
        )
        volume = next(
            volume
            for volume in row["disk_volumes"]
            if volume["mount_point"] == reference["mount_point"]
        )
        assert row["disk_volumes"].index(volume) == 0
        assert volume["available_bytes"] == reference["available_bytes"]
        assert volume["size_bytes"] == reference["size_bytes"]
        free_percent = Decimal(volume["available_bytes"]) / Decimal(volume["size_bytes"]) * 100
        assert free_percent.quantize(Decimal("0.01")) == Decimal(reference["free_percent"])
