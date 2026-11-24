from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select

from fleet.core.identity import Membership, Principal, RequestContext
from fleet.db.models import (
    AggregateManifestRecord,
    EvidencePointerRecord,
    TelemetrySnapshot,
    Tenant,
)
from fleet.db.query_repository import SnapshotQueryRepository
from fleet.domain.query import SnapshotFilters
from fleet.evidence.ledger import resolve_evidence, verify_claim
from fleet.evidence.models import Claim
from fleet.ingest.importer import TelemetryImporter

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "data" / "device-telemetry-dataset.ndjson"
AS_OF = datetime.fromisoformat("2026-06-12T16:30:00+05:30")


def _context(session, tenant_key: str) -> RequestContext:
    session.execute(select(func.set_config("app.tenant_id", tenant_key, True)))
    tenant_id = session.scalar(select(Tenant.id).where(Tenant.company_id == tenant_key))
    assert tenant_id is not None
    principal = Principal(
        user_id=f"test-{tenant_key}",
        memberships=(Membership(tenant_key, frozenset({"viewer"})),),
        active_tenant_id=tenant_key,
        auth_method="test",
    )
    return RequestContext(session, principal, tenant_id, tenant_key)


@pytest.mark.integration
def test_evidence_ledger_tenant_tamper_and_claim_checks(postgres_test_database):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required to query under fleet_app")
    TelemetryImporter(fixture.session_factory).import_file(SOURCE)
    with fixture.app_session_factory() as session, session.begin():
        session.execute(select(func.set_config("app.tenant_id", "acme-001", True)))
        context = _context(session, "acme-001")
        result = SnapshotQueryRepository().get_latest_snapshots(
            context, AS_OF, SnapshotFilters(disk_free_percent_below=20)
        )
        assert result.total_count == 2
        assert result.query_manifest_id
        manifest = session.scalar(
            select(AggregateManifestRecord).where(
                AggregateManifestRecord.tenant_id == context.tenant_id,
                AggregateManifestRecord.manifest_id == result.query_manifest_id,
            )
        )
        assert manifest is not None
        data = manifest.manifest_json
        claim = Claim(
            claim_type="count",
            value=2,
            unit="devices",
            scope="tenant:acme-001",
            as_of=AS_OF.astimezone(UTC),
            query_manifest_id=result.query_manifest_id,
            method="matched_snapshot_count-v1",
            coverage=data["coverage"],
            policy_version="policy-v1",
        )
        assert verify_claim(context, claim)
        assert not verify_claim(context, claim.model_copy(update={"policy_version": "policy-v0"}))
        pointer_id = session.scalar(
            select(EvidencePointerRecord.evidence_id)
            .where(EvidencePointerRecord.tenant_id == context.tenant_id)
            .limit(1)
        )
        assert pointer_id and resolve_evidence(context, pointer_id)
        foreign = _context(session, "globex-002")
        assert resolve_evidence(foreign, pointer_id) is None
        assert not verify_claim(foreign, claim)
        session.execute(select(func.set_config("app.tenant_id", "acme-001", True)))
        assert not verify_claim(context, claim.model_copy(update={"value": 3}))
        assert resolve_evidence(context, "ev_fake") is None
        empty = SnapshotQueryRepository().get_latest_snapshots(
            context, AS_OF, SnapshotFilters(device_id="no-such-device")
        )
        assert empty.total_count == 0 and empty.denominator == 10
        assert empty.query_manifest_id
        empty_row = session.scalar(
            select(AggregateManifestRecord).where(
                AggregateManifestRecord.tenant_id == context.tenant_id,
                AggregateManifestRecord.manifest_id == empty.query_manifest_id,
            )
        )
        assert empty_row is not None
        empty_coverage = empty_row.manifest_json["coverage"]
        assert empty_coverage["eligible"] == empty_coverage["observed"] == 10
        zero_claim = Claim(
            claim_type="count",
            value=0,
            scope="tenant:acme-001",
            as_of=AS_OF.astimezone(UTC),
            query_manifest_id=empty.query_manifest_id,
            method="matched_snapshot_count-v1",
            coverage=empty_coverage,
            policy_version="policy-v1",
        )
        assert verify_claim(context, zero_claim)

    with fixture.session_factory() as session, session.begin():
        row = session.scalar(select(AggregateManifestRecord).limit(1))
        assert row is not None
        original = row.manifest_json
        row.manifest_json = {**original, "numerator": 999}
        session.flush()
    with fixture.app_session_factory() as session, session.begin():
        session.execute(select(func.set_config("app.tenant_id", "acme-001", True)))
        context = _context(session, "acme-001")
        tampered = session.scalar(select(AggregateManifestRecord).limit(1))
        assert tampered is not None
        claim = Claim(
            claim_type="count",
            value=2,
            scope="tenant:acme-001",
            as_of=AS_OF,
            query_manifest_id=tampered.manifest_id,
            method="matched_snapshot_count-v1",
            coverage=tampered.manifest_json["coverage"],
            policy_version="policy-v1",
        )
        assert not verify_claim(context, claim)


@pytest.mark.integration
def test_changed_source_field_invalidates_evidence_pointer(postgres_test_database):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required to query under fleet_app")
    TelemetryImporter(fixture.session_factory).import_file(SOURCE)
    with fixture.app_session_factory() as session, session.begin():
        session.execute(select(func.set_config("app.tenant_id", "acme-001", True)))
        context = _context(session, "acme-001")
        SnapshotQueryRepository().get_latest_snapshots(context, AS_OF)
        pointer_id = session.scalar(
            select(EvidencePointerRecord.evidence_id)
            .where(EvidencePointerRecord.tenant_id == context.tenant_id)
            .limit(1)
        )
        assert pointer_id
    with fixture.session_factory() as session, session.begin():
        pointer = session.scalar(
            select(EvidencePointerRecord).where(EvidencePointerRecord.evidence_id == pointer_id)
        )
        assert pointer is not None
        acme_id = session.scalar(select(Tenant.id).where(Tenant.company_id == "acme-001"))
        snapshot = session.scalar(
            select(TelemetrySnapshot).where(
                TelemetrySnapshot.tenant_id == acme_id,
                TelemetrySnapshot.id == pointer.snapshot_id,
            )
        )
        assert snapshot is not None
        changed = dict(snapshot.raw_json)
        changed["device_id"] = "changed-after-ingestion"
        snapshot.raw_json = changed
    with fixture.app_session_factory() as session, session.begin():
        session.execute(select(func.set_config("app.tenant_id", "acme-001", True)))
        context = _context(session, "acme-001")
        with pytest.raises(RuntimeError, match="field changed"):
            resolve_evidence(context, pointer_id)
