from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from fleet.api.auth import DEMO_PRINCIPALS
from fleet.core.identity import (
    AuthorizationDenied,
    Membership,
    Principal,
    RequestContext,
    authorize,
    verify_approved_proposal_hash,
)
from fleet.db.models import (
    ActionExecution,
    Approval,
    AuditEvent,
    Device,
    Employee,
    Evidence,
    EvidencePointerRecord,
    GraphRun,
    Proposal,
    TelemetrySnapshot,
    Tenant,
)
from fleet.db.repositories import TenantRecordRepository
from fleet.settings import Settings


def test_demo_tokens_are_fixed_server_principals_for_each_company_and_role():
    for company in ("acme-001", "globex-002", "initech-003"):
        for role in ("viewer", "operator", "approver"):
            principal = DEMO_PRINCIPALS[f"demo-{company}-{role}"]
            assert principal.membership_for(company).roles == {role}


def test_demo_auth_cannot_be_enabled_in_production():
    with pytest.raises(ValueError, match="cannot be enabled in production"):
        Settings(database_url="postgresql://unused", demo_auth_mode=True, app_env="production")


def test_request_context_rejects_unverified_tenant():
    principal = Principal(
        user_id="u1",
        memberships=(Membership("acme-001", frozenset({"viewer"})),),
        active_tenant_id="acme-001",
        auth_method="test",
    )
    with pytest.raises(ValueError, match="authorized"):
        RequestContext(None, principal, 2, "globex-002")


@pytest.mark.parametrize(
    ("role", "allowed", "denied"),
    [
        ("viewer", "read", "draft_proposal"),
        ("operator", "draft_proposal", "approve"),
        ("approver", "approve", "draft_proposal"),
    ],
)
def test_transition_capabilities_are_checked_for_active_membership(role, allowed, denied):
    principal = Principal(
        user_id="fixture",
        memberships=(Membership("acme-001", frozenset({role})),),
        active_tenant_id="acme-001",
        auth_method="test",
    )
    authorize(principal, "acme-001", allowed)
    with pytest.raises(AuthorizationDenied):
        authorize(principal, "acme-001", denied)
    if role == "viewer":
        with pytest.raises(AuthorizationDenied):
            authorize(principal, "acme-001", "approve")
    with pytest.raises(AuthorizationDenied):
        authorize(principal, "globex-002", allowed)


def test_execution_is_bound_to_exact_approved_proposal_hash():
    verify_approved_proposal_hash("abc123", "abc123")
    with pytest.raises(AuthorizationDenied, match="hash does not match"):
        verify_approved_proposal_hash("abc123", "different")


@pytest.mark.integration
def test_api_ignores_tenant_claims_and_returns_opaque_foreign_not_found(
    postgres_test_database, monkeypatch
):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required to test API under the non-owner app role")
    now = datetime.now(UTC)
    nonce = uuid4().hex[:10].upper()
    own_device_id = f"ACME-API-{nonce}"
    foreign_device_id = f"GLOBEX-API-{nonce}"
    with fixture.session_factory() as session, session.begin():
        acme = session.scalar(select(Tenant).where(Tenant.company_id == "acme-001"))
        globex = session.scalar(select(Tenant).where(Tenant.company_id == "globex-002"))
        if acme is None:
            acme = Tenant(company_id="acme-001")
            session.add(acme)
        if globex is None:
            globex = Tenant(company_id="globex-002")
            session.add(globex)
        session.flush()
        emp = Employee(tenant_id=acme.id, employee_id=f"EMP-{nonce}")
        session.add(emp)
        session.flush()
        session.add_all(
            [
                Device(
                    tenant_id=acme.id, device_id=own_device_id, first_seen_at=now, last_seen_at=now
                ),
                Device(
                    tenant_id=globex.id,
                    device_id=foreign_device_id,
                    first_seen_at=now,
                    last_seen_at=now,
                ),
                TelemetrySnapshot(
                    tenant_id=acme.id,
                    device_id=own_device_id,
                    employee_id=emp.employee_id,
                    collected_at=now,
                    agent_version="fixture",
                    os_platform="darwin",
                    os_product_name="macOS",
                    os_json={"product_version": "15.0"},
                    device_identity_json={"model_name": "MacBook Pro"},
                    memory_json={
                        "total_memory_bytes": 16000000000,
                        "used_memory_bytes": 8000000000,
                    },
                    battery_json=None,
                    network_json=None,
                    raw_json={"device_id": own_device_id, "collected_at": now.isoformat()},
                    source_path="fixture",
                    source_line_number=1,
                    source_row_sha256="0" * 64,
                    data_sha256="0" * 64,
                ),
            ]
        )

    from fleet.api import context, main
    from fleet.settings import get_settings

    settings = Settings(
        database_url="postgresql://app_role",
        demo_auth_mode=True,
        app_env="test",
    )
    monkeypatch.setattr(context, "_session_factory", lambda _url: fixture.app_session_factory)
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "check_database", lambda _url: None)
    main.app.dependency_overrides[get_settings] = lambda: settings
    try:
        with TestClient(main.app) as client:
            headers = {"Authorization": "Bearer demo-acme-viewer"}
            own = client.get(f"/api/v1/fleet/devices/{own_device_id}", headers=headers)
            foreign = client.get(f"/api/v1/fleet/devices/{foreign_device_id}", headers=headers)
            forged_claim = client.get(
                f"/api/v1/fleet/devices/{foreign_device_id}?tenant_id=globex-002",
                headers={**headers, "X-Tenant-ID": "globex-002"},
            )
            forged_body = client.request(
                "GET",
                f"/api/v1/fleet/devices/{foreign_device_id}",
                headers=headers,
                json={"tenant_id": "globex-002"},
            )
            forged_scope = client.get(
                f"/api/v1/fleet/devices/{foreign_device_id}",
                headers={**headers, "X-Active-Tenant": "globex-002"},
            )
        assert own.status_code == 200
        for resp in (foreign, forged_claim, forged_body, forged_scope):
            assert resp.status_code == 404
            data = resp.json()
            assert (
                data.get("detail") == "Not found"
                or data.get("error", {}).get("code") == "not_found"
            )
    finally:
        main.app.dependency_overrides.clear()
        with fixture.session_factory() as session, session.begin():
            session.query(EvidencePointerRecord).delete(synchronize_session=False)
            session.query(TelemetrySnapshot).filter(
                TelemetrySnapshot.device_id.in_((own_device_id, foreign_device_id))
            ).delete(synchronize_session=False)
            session.query(Device).filter(
                Device.device_id.in_((own_device_id, foreign_device_id))
            ).delete(synchronize_session=False)


@pytest.mark.integration
def test_forced_rls_select_insert_and_connection_scope_reset(postgres_test_database):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required for non-owner RLS verification")
    now = datetime.now(UTC)
    suffix = uuid4().hex
    tenant_a_key, tenant_b_key = f"rls-a-{suffix}", f"rls-b-{suffix}"
    with fixture.session_factory() as session, session.begin():
        acme = Tenant(company_id=tenant_a_key)
        globex = Tenant(company_id=tenant_b_key)
        session.add_all([acme, globex])
        session.flush()
        acme_id, globex_id = acme.id, globex.id
        session.add_all(
            [
                Device(
                    tenant_id=acme_id, device_id="A-DEVICE", first_seen_at=now, last_seen_at=now
                ),
                Device(
                    tenant_id=globex_id, device_id="B-DEVICE", first_seen_at=now, last_seen_at=now
                ),
            ]
        )

    engine = fixture.app_session_factory.kw["bind"]
    with engine.connect() as connection:
        assert connection.scalar(select(func.current_user())) == "fleet_app"
        role_flags = connection.execute(
            text(
                "SELECT rolsuper, rolbypassrls, EXISTS ("
                "SELECT 1 FROM pg_class WHERE relowner = (SELECT oid FROM pg_roles "
                "WHERE rolname = current_user) AND relname = 'tenant') "
                "FROM pg_roles WHERE rolname = current_user"
            )
        ).one()
        assert role_flags == (False, False, False)
        assert connection.scalar(select(func.current_setting("app.tenant_id", True))) is None
        connection.commit()
        for tenant, visible_device in (
            (tenant_a_key, "A-DEVICE"),
            (tenant_b_key, "B-DEVICE"),
            (tenant_a_key, "A-DEVICE"),
        ):
            with connection.begin():
                connection.execute(select(func.set_config("app.tenant_id", tenant, True)))
                found = connection.scalars(select(Device.device_id)).all()
                assert found == [visible_device]
        with connection.begin():
            assert connection.scalars(select(Device.device_id)).all() == []

        with connection.begin():
            connection.execute(select(func.set_config("app.tenant_id", tenant_a_key, True)))
            connection.execute(
                Device.__table__.insert().values(
                    tenant_id=acme_id,
                    device_id="A-INSERTED",
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
        with pytest.raises(DBAPIError):
            with connection.begin():
                connection.execute(select(func.set_config("app.tenant_id", tenant_a_key, True)))
                connection.execute(
                    Device.__table__.insert().values(
                        tenant_id=globex_id,
                        device_id="FORGED-INSERT",
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                )


@pytest.mark.integration
def test_run_thread_trace_evidence_proposal_approval_execution_audit_and_snapshot_ids_are_scoped(
    postgres_test_database,
):
    fixture = postgres_test_database
    if fixture.app_session_factory is None:
        pytest.skip("TEST_DATABASE_APP_URL is required for non-owner repository verification")
    suffix = uuid4().hex
    tenant_a_key, tenant_b_key = f"scope-a-{suffix}", f"scope-b-{suffix}"
    with fixture.session_factory() as session, session.begin():
        tenant_a, tenant_b = Tenant(company_id=tenant_a_key), Tenant(company_id=tenant_b_key)
        session.add_all([tenant_a, tenant_b])
        session.flush()
        ids = {tenant_a_key: tenant_a.id, tenant_b_key: tenant_b.id}
        runs = {
            key: GraphRun(
                tenant_id=ids[key],
                thread_id=f"thread-{key}",
                trace_id=f"trace-{key}",
                user_id="fixture",
                data_sha256="0" * 64,
                policy_version="p1",
                graph_version="g1",
                prompt_version="pr1",
                model_version="m1",
            )
            for key in (tenant_a_key, tenant_b_key)
        }
        session.add_all(runs.values())
        session.flush()
        records = {}
        for key in (tenant_a_key, tenant_b_key):
            run = runs[key]
            evidence = Evidence(
                tenant_id=ids[key], run_id=run.id, data_sha256="0" * 64, evidence_json={}
            )
            proposal = Proposal(
                tenant_id=ids[key],
                run_id=run.id,
                requested_by="operator",
                proposal_hash="a" * 64,
                data_sha256="0" * 64,
                policy_version="p1",
                graph_version="g1",
                prompt_version="pr1",
                model_version="m1",
                proposal_json={},
                expires_at=datetime.now(UTC) + timedelta(days=1),
                workflow_thread_id=f"t{ids[key]}-{uuid4().hex}",
            )
            session.add_all([evidence, proposal])
            session.flush()
            approval = Approval(
                tenant_id=ids[key],
                proposal_id=proposal.id,
                approver_id="approver",
                approver_role="approver",
                decision="approve",
                proposal_hash=proposal.proposal_hash,
            )
            execution = ActionExecution(
                tenant_id=ids[key],
                proposal_id=proposal.id,
                execution_id=f"exec-{key}",
                proposal_hash=proposal.proposal_hash,
                status="sandboxed",
            )
            audit = AuditEvent(
                tenant_id=ids[key],
                run_id=run.id,
                actor_id="fixture",
                event_type="test",
                entity_type="run",
                entity_id=str(run.id),
                details_json={},
            )
            device = Device(
                tenant_id=ids[key],
                device_id=f"DEVICE-{key}",
                first_seen_at=datetime.now(UTC),
                last_seen_at=datetime.now(UTC),
            )
            employee = Employee(tenant_id=ids[key], employee_id=f"employee-{key}")
            session.add_all([approval, execution, audit, device, employee])
            session.flush()
            snapshot = TelemetrySnapshot(
                tenant_id=ids[key],
                device_id=device.device_id,
                employee_id=employee.employee_id,
                collected_at=datetime.now(UTC),
                agent_version="fixture",
                os_platform="darwin",
                os_product_name="macos",
                os_json={},
                device_identity_json={},
                memory_json={},
                raw_json={},
                source_path="fixture",
                source_line_number=1,
                source_row_sha256="0" * 64,
                data_sha256="0" * 64,
            )
            session.add(snapshot)
            session.flush()
            records[key] = {
                "run": run.id,
                "thread": run.thread_id,
                "trace": run.trace_id,
                "evidence": evidence.id,
                "proposal": proposal.id,
                "approval": approval.id,
                "execution": execution.id,
                "execution_id": execution.execution_id,
                "audit": audit.id,
                "snapshot": snapshot.id,
            }

    principal = Principal(
        user_id="fixture-scope",
        memberships=(Membership(tenant_a_key, frozenset({"viewer"})),),
        active_tenant_id=tenant_a_key,
        auth_method="test",
    )
    factory = fixture.app_session_factory
    with factory() as session, session.begin():
        session.execute(select(func.set_config("app.tenant_id", tenant_a_key, True)))
        context = RequestContext(session, principal, ids[tenant_a_key], tenant_a_key)
        repository = TenantRecordRepository()
        for kind in ("run", "evidence", "proposal", "approval", "execution", "audit", "snapshot"):
            assert getattr(repository, kind)(context, records[tenant_b_key][kind]) is None
        assert repository.thread(context, records[tenant_b_key]["thread"]) is None
        assert repository.trace(context, records[tenant_b_key]["trace"]) is None
        assert (
            repository.execution_by_public_id(context, records[tenant_b_key]["execution_id"])
            is None
        )
        assert repository.run(context, records[tenant_a_key]["run"]) is not None
