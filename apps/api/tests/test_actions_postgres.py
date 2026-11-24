from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from fleet.actions.schemas import DecisionRequest, ProposalRequest
from fleet.actions.service import (
    ActionConflict,
    ActionNotFound,
    create_proposal,
    decide_proposal,
    execute_proposal,
    verify_audit_chain,
)
from fleet.core.identity import Membership, Principal, RequestContext
from fleet.db.models import (
    ActionExecution,
    Approval,
    Device,
    Employee,
    Proposal,
    TelemetrySnapshot,
    Tenant,
)
from fleet.domain.query import SourceRowReference
from fleet.evidence.ledger import capture_manifest

pytestmark = pytest.mark.integration


def _principal(tenant: str, user: str, *roles: str) -> Principal:
    return Principal(
        user_id=user,
        memberships=(Membership(tenant, frozenset(roles)),),
        active_tenant_id=tenant,
        auth_method="action-integration-test",
    )


def _context(session, tenant_id: int, tenant_key: str, user: str, *roles: str) -> RequestContext:
    session.execute(select(func.set_config("app.tenant_id", tenant_key, True)))
    return RequestContext(
        session=session,
        principal=_principal(tenant_key, user, *roles),
        tenant_id=tenant_id,
        tenant_key=tenant_key,
        clock=lambda: datetime(2026, 6, 13, 12, tzinfo=UTC),
    )


def _seed_source(fixture, tenant_key="acme-001"):
    token = uuid4().hex[:10].upper()
    device_id = f"ACT-{token}"
    employee_id = f"EMP-{token}"
    observed_at = datetime(2026, 6, 12, 10, tzinfo=UTC)
    source_hash = "f" * 64
    row_hash = "a" * 64
    with fixture.session_factory() as session, session.begin():
        context = _context(session, 1, tenant_key, "seed", "admin")
        tenant = session.scalar(select(Tenant).where(Tenant.company_id == tenant_key))
        if tenant is None:
            tenant = Tenant(company_id=tenant_key)
            session.add(tenant)
            session.flush()
        context = _context(session, tenant.id, tenant_key, "seed", "admin")
        employee = Employee(tenant_id=tenant.id, employee_id=employee_id)
        device = Device(
            tenant_id=tenant.id,
            device_id=device_id,
            first_seen_at=observed_at,
            last_seen_at=observed_at,
        )
        session.add_all([employee, device])
        session.flush()
        snapshot = TelemetrySnapshot(
            tenant_id=tenant.id,
            device_id=device_id,
            employee_id=employee_id,
            collected_at=observed_at,
            agent_version="action-test",
            os_platform="darwin",
            os_product_name="macOS",
            os_json={"product_version": "15.0"},
            device_identity_json={"model_name": "Test Mac"},
            memory_json={"total_memory_bytes": 16_000_000_000, "used_memory_bytes": 8_000_000_000},
            battery_json=None,
            network_json=None,
            raw_json={
                "device_id": device_id,
                "collected_at": observed_at.isoformat(),
                "os": {
                    "platform": "darwin",
                    "product_name": "macOS",
                    "product_version": "15.0",
                },
            },
            source_path="actions_fixture.ndjson",
            source_line_number=1,
            source_row_sha256=row_hash,
            data_sha256=source_hash,
        )
        session.add(snapshot)
        session.flush()
        reference = SourceRowReference(
            snapshot_id=snapshot.id,
            device_id=device_id,
            collected_at=observed_at,
            source_path=snapshot.source_path,
            source_line_number=snapshot.source_line_number,
            source_row_sha256=row_hash,
            data_sha256=source_hash,
        )
        manifest = capture_manifest(
            context,
            query_type="latest_snapshots",
            filters={"device_id": device_id},
            as_of=observed_at,
            matched_refs=(reference,),
            excluded_refs=(),
            numerator=1,
            denominator=1,
            eligible=1,
            observed=1,
            unknown=0,
            policy_version="fleet-policy-v1",
        )
        tenant_id = tenant.id
    return tenant_id, device_id, manifest.manifest_id


def _request(device_id: str, manifest_id: str) -> ProposalRequest:
    return ProposalRequest(
        action_kind="create_upgrade_order",
        target_id=device_id,
        payload={"component": "memory", "spec": "Add 16 GB memory module"},
        evidence_manifest_ids=[manifest_id],
        mode="SANDBOX_SIMULATION",
    )


def _create(fixture, tenant_id, device_id, manifest_id, tenant_key="acme-001"):
    with fixture.app_session_factory() as session, session.begin():
        context = _context(session, tenant_id, tenant_key, "requester", "operator")
        result = create_proposal(context, _request(device_id, manifest_id))
        assert result.status == "PENDING_APPROVAL"
        return result.proposal_id, result.proposal_hash


def test_restart_approval_resume_execute_retry_and_hash_chain(postgres_test_database):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required for non-owner action RLS checks")
    tenant_id, device_id, manifest_id = _seed_source(fixture)
    proposal_id, proposal_hash = _create(fixture, tenant_id, device_id, manifest_id)

    # A fresh session/saver simulates process restart between interrupt and decision.
    with fixture.app_session_factory() as session, session.begin():
        context = _context(session, tenant_id, "acme-001", "approver", "approver")
        response = decide_proposal(
            context,
            proposal_id,
            DecisionRequest(decision="approve", proposal_hash=proposal_hash),
        )
        assert response.status == "APPROVED"
        assert response.workflow_status == "APPROVED"

    with fixture.app_session_factory() as session, session.begin():
        context = _context(session, tenant_id, "acme-001", "approver", "approver")
        with pytest.raises(ActionConflict):
            decide_proposal(
                context,
                proposal_id,
                DecisionRequest(decision="approve", proposal_hash=proposal_hash),
            )

    with fixture.app_session_factory() as session, session.begin():
        context = _context(session, tenant_id, "acme-001", "operator", "operator")
        first = execute_proposal(context, proposal_id)
        second = execute_proposal(context, proposal_id)
        assert first.status == second.status == "EXECUTED"
        assert second.repeated is True
        count = session.scalar(
            select(func.count(ActionExecution.id)).where(
                ActionExecution.tenant_id == tenant_id,
                ActionExecution.proposal_id == proposal_id,
            )
        )
        assert count == 1
        assert first.result["simulated"] is True
        assert "no external system" in first.result["message"].lower()

    with fixture.app_session_factory() as session, session.begin():
        context = _context(session, tenant_id, "acme-001", "auditor", "admin")
        verification = verify_audit_chain(context)
        print(
            "ACTION_AUDIT_CHAIN", json.dumps(verification.model_dump(mode="json"), sort_keys=True)
        )
        assert verification.valid
        assert verification.events_verified >= 5


def test_concurrent_approval_has_one_cas_winner(postgres_test_database):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required for concurrent action checks")
    tenant_id, device_id, manifest_id = _seed_source(fixture)
    proposal_id, proposal_hash = _create(fixture, tenant_id, device_id, manifest_id)

    def approve_once(_index):
        try:
            with fixture.app_session_factory() as session, session.begin():
                context = _context(session, tenant_id, "acme-001", "approver", "approver")
                decide_proposal(
                    context,
                    proposal_id,
                    DecisionRequest(decision="approve", proposal_hash=proposal_hash),
                )
                return "approved"
        except ActionConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(approve_once, range(2)))
    assert sorted(outcomes) == ["approved", "conflict"]
    with fixture.app_session_factory() as session, session.begin():
        _context(session, tenant_id, "acme-001", "auditor", "admin")
        count = session.scalar(
            select(func.count(Approval.id)).where(
                Approval.tenant_id == tenant_id,
                Approval.proposal_id == proposal_id,
            )
        )
        assert count == 1


def test_foreign_proposal_and_high_severity_ticket_without_failure_are_denied(
    postgres_test_database,
):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required for action scope checks")
    tenant_id, device_id, manifest_id = _seed_source(fixture)
    with fixture.app_session_factory() as session, session.begin():
        context = _context(session, tenant_id, "acme-001", "viewer", "viewer")
        with pytest.raises(ActionNotFound):
            decide_proposal(
                context,
                999999999,
                DecisionRequest(decision="approve", proposal_hash="a" * 64),
            )

    with fixture.app_session_factory() as session, session.begin():
        context = _context(session, tenant_id, "acme-001", "requester", "operator")
        result = create_proposal(
            context,
            ProposalRequest(
                action_kind="open_remediation_ticket",
                target_id=device_id,
                payload={"check_id": "high-check", "note": "Investigate source failure"},
                evidence_manifest_ids=[manifest_id],
            ),
        )
        assert result.allowed is False
        assert result.code == "no_contrary_evidence"


def test_viewer_cannot_propose_and_operator_cannot_approve(postgres_test_database):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required for action authorization checks")
    tenant_id, device_id, manifest_id = _seed_source(fixture)
    with fixture.app_session_factory() as session, session.begin():
        context = _context(session, tenant_id, "acme-001", "viewer", "viewer")
        with pytest.raises(PermissionError):
            create_proposal(context, _request(device_id, manifest_id))
    proposal_id, proposal_hash = _create(fixture, tenant_id, device_id, manifest_id)
    with fixture.app_session_factory() as session, session.begin():
        context = _context(session, tenant_id, "acme-001", "operator", "operator")
        with pytest.raises(PermissionError):
            decide_proposal(
                context,
                proposal_id,
                DecisionRequest(decision="approve", proposal_hash=proposal_hash),
            )


def test_requester_separation_expiry_and_rejection_are_terminal(postgres_test_database):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required for action transition checks")
    tenant_id, device_id, manifest_id = _seed_source(fixture)

    with fixture.app_session_factory() as session, session.begin():
        both = _context(session, tenant_id, "acme-001", "same-actor", "operator", "approver")
        proposal = create_proposal(both, _request(device_id, manifest_id))
        with pytest.raises(PermissionError, match="different actors"):
            decide_proposal(
                both,
                proposal.proposal_id,
                DecisionRequest(decision="approve", proposal_hash=proposal.proposal_hash),
            )

    reject_id, reject_hash = _create(fixture, tenant_id, device_id, manifest_id)
    with fixture.app_session_factory() as session, session.begin():
        context = _context(session, tenant_id, "acme-001", "approver", "approver")
        rejected = decide_proposal(
            context, reject_id, DecisionRequest(decision="reject", proposal_hash=reject_hash)
        )
        assert rejected.status == "REJECTED"
        with pytest.raises(ActionConflict):
            execute_proposal(
                _context(session, tenant_id, "acme-001", "operator", "operator"), reject_id
            )

    expired_id, expired_hash = _create(fixture, tenant_id, device_id, manifest_id)
    with fixture.app_session_factory() as session, session.begin():
        context = _context(session, tenant_id, "acme-001", "approver", "approver")
        context = RequestContext(
            session=session,
            principal=context.principal,
            tenant_id=tenant_id,
            tenant_key="acme-001",
            clock=lambda: datetime(2026, 6, 15, tzinfo=UTC),
        )
        with pytest.raises(ActionConflict, match="expired"):
            decide_proposal(
                context,
                expired_id,
                DecisionRequest(decision="approve", proposal_hash=expired_hash),
            )
        row = session.scalar(
            select(Proposal).where(Proposal.tenant_id == tenant_id, Proposal.id == expired_id)
        )
        assert row.status == "EXPIRED"


def test_foreign_tenant_proposal_is_opaque_not_found(postgres_test_database):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required for tenant isolation checks")
    acme_tenant, _, _ = _seed_source(fixture, "acme-001")
    globex_tenant, device_id, manifest_id = _seed_source(fixture, "globex-002")
    foreign_id, foreign_hash = _create(
        fixture, globex_tenant, device_id, manifest_id, tenant_key="globex-002"
    )
    with fixture.app_session_factory() as session, session.begin():
        acme = _context(session, acme_tenant, "acme-001", "acme-approver", "approver")
        with pytest.raises(ActionNotFound):
            decide_proposal(
                acme,
                foreign_id,
                DecisionRequest(decision="approve", proposal_hash=foreign_hash),
            )
