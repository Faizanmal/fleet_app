from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.dialects import postgresql

from fleet.core.identity import Membership, Principal, RequestContext
from fleet.db.models import Tenant
from fleet.db.query_repository import SnapshotQueryRepository, _base_latest_query
from fleet.domain.query import NumericRange, SnapshotFilters, ThresholdSpec
from fleet.ingest.importer import TelemetryImporter

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "data" / "device-telemetry-dataset.ndjson"
GOLDEN = ROOT / "evals" / "golden" / "phase04_query_oracles.json"
COMPANIES = ("acme-001", "globex-002", "initech-003")
AS_OF = datetime.fromisoformat("2026-06-12T16:30:00+05:30")


def _z(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


@pytest.mark.integration
def test_latest_query_postgres_matches_frozen_exact_oracle(postgres_test_database):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required to query under fleet_app")
    TelemetryImporter(fixture.session_factory).import_file(SOURCE)
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    repository = SnapshotQueryRepository()
    inventory: dict[str, int] = {}
    older_macos: dict[str, list[str]] = {}
    data_as_of: dict[str, str | None] = {}
    high_fail_count = 0
    data_hashes: set[str] = set()
    for company in COMPANIES:
        with fixture.app_session_factory() as session, session.begin():
            session.execute(select(func.set_config("app.tenant_id", company, True)))
            tenant_id = session.scalar(select(Tenant.id).where(Tenant.company_id == company))
            assert tenant_id is not None
            principal = Principal(
                user_id=f"fixture-{company}",
                memberships=(Membership(company, frozenset({"viewer"})),),
                active_tenant_id=company,
                auth_method="integration_fixture",
            )
            context = RequestContext(session, principal, tenant_id, company)
            all_rows = repository.get_latest_snapshots(context, AS_OF)
            inventory[company] = all_rows.total_count
            data_as_of[company] = _z(all_rows.data_as_of)
            data_hashes.update(all_rows.data_sha256)
            older = repository.get_latest_snapshots(
                context,
                AS_OF,
                SnapshotFilters(platform="macOS", os_major=NumericRange(maximum=14), limit=100),
            )
            older_macos[company] = sorted(row.device_id for row in older.items)
            high_fail = repository.get_latest_snapshots(
                context,
                AS_OF,
                SnapshotFilters(compliance_status="fail", compliance_severity="high", limit=100),
            )
            high_fail_count += sum(
                entry["status"].casefold() == "fail" and entry["severity"].casefold() == "high"
                for row in high_fail.items
                for entry in row.compliance
            )

            if company == "acme-001":
                low_disk = repository.get_latest_snapshots(
                    context,
                    AS_OF,
                    SnapshotFilters(disk_free_percent_below=20, limit=100),
                    policy_threshold_source="policy-v1:disk_free_percent<20",
                )
                low_disk_rows = [
                    {
                        "device_id": row.device_id,
                        "mount_point": row.primary_disk_mount,
                        "free_percent": format(row.disk_free_percent, ".2f"),
                    }
                    for row in low_disk.items
                ]
                low_disk_rows.sort(key=lambda value: value["device_id"])

                screen_fail = repository.get_latest_snapshots(
                    context,
                    AS_OF,
                    SnapshotFilters(
                        compliance_status="fail",
                        compliance_severity="medium",
                        compliance_check="screen_lock",
                        limit=100,
                    ),
                )
                screen_severities = Counter(
                    entry["severity"].casefold()
                    for row in screen_fail.items
                    for entry in row.compliance
                    if entry["check_id"].casefold() == "screen_lock"
                    and entry["status"].casefold() == "fail"
                )
                service_battery_count = sum(
                    row.battery is not None
                    and row.battery.get("condition", "").casefold() == "service recommended"
                    for row in all_rows.items
                )
                assert all_rows.denominator == 10
                assert all_rows.data_as_of == datetime(2026, 6, 12, 11, tzinfo=UTC)
                assert all(ref.source_row_sha256 for ref in all_rows.source_row_references)

                pages = []
                for offset in (0, 3, 6, 9):
                    page = repository.get_latest_snapshots(
                        context,
                        AS_OF,
                        SnapshotFilters(limit=3, offset=offset, sort_by="device_id"),
                    )
                    pages.extend(row.device_id for row in page.items)
                assert pages == sorted(row.device_id for row in all_rows.items)

                unknown_as_of = repository.get_latest_snapshots(
                    context, datetime(2026, 5, 1, tzinfo=UTC)
                )
                assert unknown_as_of.items == ()
                assert unknown_as_of.data_as_of is None

                wrong_tenant = repository.get_latest_snapshots(
                    context,
                    AS_OF,
                    SnapshotFilters(device_id="GLOBEX-DEVICE-DOES-NOT-BELONG"),
                )
                assert wrong_tenant.total_count == 0

                device_window = repository.get_device_time_window(
                    context,
                    "MT7PJB7N5LRE",
                    datetime(2026, 5, 1, tzinfo=UTC),
                    datetime(2026, 6, 13, tzinfo=UTC),
                    thresholds=(
                        ThresholdSpec(
                            metric="disk_free_percent",
                            operator="lt",
                            threshold=20,
                            threshold_source="policy-v1:disk_free_percent<20",
                        ),
                    ),
                )
                window = device_window.items[0]
                assert window.snapshot_count == 30
                assert window.disk_valid_count == 30
                assert window.ram_valid_count == 30
                assert [r.collected_at for r in window.readings] == sorted(
                    r.collected_at for r in window.readings
                )
                assert window.first_observed_at is not None
                assert window.last_observed_at == datetime(2026, 6, 12, 8, 39, tzinfo=UTC)
                assert window.threshold_coverages[0].denominator == 30
                assert window.threshold_coverages[0].unknown_count == 0

    actual = {
        "data_sha256": next(iter(data_hashes)) if len(data_hashes) == 1 else sorted(data_hashes),
        "latest_inventory_by_tenant": inventory,
        "latest_macos_major_below_15": {
            "count": sum(map(len, older_macos.values())),
            "devices_by_tenant": older_macos,
        },
        "acme_primary_disk_free_below_20_percent": low_disk_rows,
        "acme_screen_lock_failures": {
            "count": sum(screen_severities.values()),
            "severity_counts": dict(sorted(screen_severities.items())),
        },
        "latest_high_severity_compliance_failures_all_tenants": high_fail_count,
        "acme_battery_service_recommended": service_battery_count,
        "data_as_of_by_tenant": data_as_of,
    }
    assert actual == golden


def test_query_sql_uses_row_number_and_id_desc_tie_break():
    # Schema uniqueness prevents duplicate device timestamps in normal writes; this protects
    # deterministic behavior for legacy/repair data where ties may still be present.
    from types import SimpleNamespace

    statement = _base_latest_query(SimpleNamespace(tenant_id=7), AS_OF)
    sql = str(
        statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})
    )
    assert "row_number() OVER" in sql
    assert "PARTITION BY telemetry_snapshot.tenant_id, telemetry_snapshot.device_id" in sql
    assert "telemetry_snapshot.collected_at DESC, telemetry_snapshot.id DESC" in sql
