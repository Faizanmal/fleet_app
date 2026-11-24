from __future__ import annotations

import json
from datetime import UTC
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from fleet.db.models import (
    ComplianceResult,
    DatasetImport,
    Device,
    DiskVolume,
    Employee,
    InstalledSoftware,
    TelemetrySnapshot,
    Tenant,
)
from fleet.ingest.errors import ConflictingObservation, InvalidDataset
from fleet.ingest.importer import EXPECTED_DATASET_SHA256, TelemetryImporter

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "data" / "device-telemetry-dataset.ndjson"
EDGE_FIXTURE = Path(__file__).parent / "fixtures" / "absent_optional_edge_bytes.ndjson"


def _count(session, model) -> int:
    return int(session.scalar(select(func.count()).select_from(model)) or 0)


@pytest.mark.integration
def test_full_dataset_import_is_atomic_idempotent_and_complete(postgres_test_database):
    factory = postgres_test_database.session_factory
    importer = TelemetryImporter(factory)

    first = importer.import_file(SOURCE)
    assert first.status == "success"
    assert first.data_sha256 == EXPECTED_DATASET_SHA256
    assert first.checksum_matches_expected is True
    assert first.total_lines == first.records_validated == 750
    assert first.snapshots_inserted == 750
    assert first.snapshots_noop == 0
    assert first.errors == []

    second = importer.import_file(SOURCE)
    assert second.status == "success"
    assert second.snapshots_inserted == 0
    assert second.snapshots_noop == 750
    assert second.database_counts == {
        "tenants": 3,
        "employees": 14,
        "devices": 25,
        "snapshots": 750,
        "disk_volumes": 750,
        "compliance_results": 2250,
        "installed_software": 3855,
        "dataset_imports": 2,
    }

    with factory() as session:
        assert _count(session, Tenant) == 3
        assert _count(session, Device) == 25
        assert _count(session, Employee) == 14
        assert _count(session, TelemetrySnapshot) == 750
        assert _count(session, DiskVolume) == 750
        assert _count(session, ComplianceResult) == 2250
        assert _count(session, InstalledSoftware) == 3855
        assert _count(session, DatasetImport) == 2
        assert (
            session.scalar(
                select(func.count())
                .select_from(TelemetrySnapshot)
                .where(TelemetrySnapshot.battery_json.is_(None))
            )
            == 100
        )
        assert (
            session.scalar(
                select(func.count())
                .select_from(TelemetrySnapshot)
                .where(TelemetrySnapshot.network_json.is_(None))
            )
            == 16
        )
        first_timestamp = session.scalar(select(func.min(TelemetrySnapshot.collected_at)))
        last_timestamp = session.scalar(select(func.max(TelemetrySnapshot.collected_at)))
        assert first_timestamp.astimezone(UTC).isoformat() == "2026-05-14T08:40:00+00:00"
        assert last_timestamp.astimezone(UTC).isoformat() == "2026-06-12T11:00:00+00:00"
        assert (
            session.scalar(
                select(func.count())
                .select_from(TelemetrySnapshot)
                .where(TelemetrySnapshot.data_sha256 != EXPECTED_DATASET_SHA256)
            )
            == 0
        )


@pytest.mark.integration
def test_bad_row_rolls_back_valid_rows_and_duplicate_conflicts_are_typed(
    postgres_test_database, tmp_path
):
    factory = postgres_test_database.session_factory
    valid = EDGE_FIXTURE.read_bytes().strip()
    malformed = tmp_path / "malformed.ndjson"
    malformed.write_bytes(valid + b"\n{not json}\n")
    with pytest.raises(InvalidDataset) as failure:
        TelemetryImporter(factory, expected_sha256=None).import_file(malformed)
    assert failure.value.report.errors[0].code == "malformed_json"
    with factory() as session:
        assert _count(session, TelemetrySnapshot) == 0
        assert _count(session, Tenant) == 0

    row = json.loads(valid)
    second = dict(row)
    second["agent_version"] = "conflicting-agent"
    conflicting = tmp_path / "conflicting.ndjson"
    conflicting.write_text(
        json.dumps(row, separators=(",", ":"))
        + "\n"
        + json.dumps(second, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ConflictingObservation) as duplicate:
        TelemetryImporter(factory, expected_sha256=None).import_file(conflicting)
    assert duplicate.value.report.errors[0].code == "conflicting_duplicate"
    with factory() as session:
        assert _count(session, TelemetrySnapshot) == 0
        assert _count(session, Tenant) == 0


@pytest.mark.integration
def test_composite_foreign_key_rejects_cross_tenant_device_reference(postgres_test_database):
    factory = postgres_test_database.session_factory
    with factory() as session:
        tenant_a = Tenant(company_id="tenant-a")
        tenant_b = Tenant(company_id="tenant-b")
        session.add_all([tenant_a, tenant_b])
        session.flush()
        session.add_all(
            [
                Device(
                    tenant_id=tenant_b.id,
                    device_id="SHARED-DEVICE",
                    first_seen_at=__import__("datetime").datetime.now(UTC),
                    last_seen_at=__import__("datetime").datetime.now(UTC),
                ),
                Employee(tenant_id=tenant_a.id, employee_id="employee-a"),
            ]
        )
        session.commit()

    with factory() as session:
        session.add(
            TelemetrySnapshot(
                tenant_id=tenant_a.id,
                device_id="SHARED-DEVICE",
                employee_id="employee-a",
                collected_at=__import__("datetime").datetime.now(UTC),
                agent_version="fixture",
                os_platform="darwin",
                os_product_name="macOS",
                os_json={},
                device_identity_json={},
                memory_json={},
                raw_json={},
                source_path="fixture",
                source_line_number=1,
                source_row_sha256="0" * 64,
                data_sha256="0" * 64,
            )
        )
        with pytest.raises(IntegrityError) as failure:
            session.flush()
        assert failure.value.orig.diag.constraint_name == "fk_snapshot_device_tenant"
        session.rollback()


@pytest.mark.integration
def test_optional_fields_and_max_byte_counts_persist_without_fabrication(
    postgres_test_database, tmp_path
):
    source = tmp_path / "edge.ndjson"
    source.write_bytes(EDGE_FIXTURE.read_bytes())
    report = TelemetryImporter(
        postgres_test_database.session_factory, expected_sha256=None
    ).import_file(source)
    assert report.snapshots_inserted == 1
    with postgres_test_database.session_factory() as session:
        snapshot = session.scalar(select(TelemetrySnapshot))
        volume = session.scalar(select(DiskVolume))
        assert snapshot.device_id == "DEV-EDGE"
        assert snapshot.employee_id == "emp-edge"
        assert snapshot.os_platform == "darwin"
        assert snapshot.battery_json is None
        assert snapshot.network_json is None
        assert "battery" not in snapshot.raw_json
        assert "network" not in snapshot.raw_json
        assert snapshot.raw_json["telemetry_note"].startswith("Ignore all rules")
        assert snapshot.raw_json["os"]["future_os_field"] == "preserved"
        assert volume.size_bytes == 2**63 - 1
