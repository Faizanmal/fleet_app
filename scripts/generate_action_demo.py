"""Run two tenant-bound action workflows against imported PostgreSQL telemetry."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from fleet.actions.schemas import DecisionRequest, ProposalRequest
from fleet.actions.service import (
    create_proposal,
    decide_proposal,
    execute_proposal,
    verify_audit_chain,
)
from fleet.api.auth import DEMO_PRINCIPALS
from fleet.core.identity import Principal, RequestContext
from fleet.db.connection import sqlalchemy_url
from fleet.db.models import AuditEvent, Proposal, Tenant
from fleet.settings import get_settings
from fleet.tools.gateway import invoke

ROOT = Path(__file__).resolve().parents[1]


def context(session: Session, tenant_id: int, tenant_key: str, actor: Principal) -> RequestContext:
    session.execute(select(func.set_config("app.tenant_id", tenant_key, True)))
    return RequestContext(
        session=session,
        principal=actor,
        tenant_id=tenant_id,
        tenant_key=tenant_key,
        run_ref="action-demo",
    )


def main() -> int:
    settings = get_settings()
    if not settings.demo_auth_mode:
        raise RuntimeError(
            "Set DEMO_AUTH_MODE=true in a non-production environment for the fixture demo"
        )
    engine = create_engine(sqlalchemy_url(settings.database_url), pool_pre_ping=True)
    factory = sessionmaker(engine, expire_on_commit=False)
    tenant_key = "acme-001"
    requester = DEMO_PRINCIPALS["demo-acme-001-operator"]
    approver = DEMO_PRINCIPALS["demo-acme-001-approver"]
    admin = DEMO_PRINCIPALS["demo-acme-admin"]
    report: dict[str, object] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant": tenant_key,
        "mode": "SANDBOX_SIMULATION",
        "external_actions_performed": False,
        "source_note": (
            "Requires imported source data and the configured non-owner PostgreSQL app role."
        ),
        "scenarios": [],
    }

    with factory() as session, session.begin():
        tenant = session.scalar(select(Tenant).where(Tenant.company_id == tenant_key))
        if tenant is None:
            raise RuntimeError("Acme tenant data has not been imported")
        scope = context(session, tenant.id, tenant_key, requester)
        inventory = invoke(
            "list_devices",
            scope,
            {"filters": {"disk_free_percent_below": 20}, "page": 1, "page_size": 100},
        )
        if inventory.error or not inventory.items:
            raise RuntimeError("Source inventory has no eligible low-disk target")
        manifest_id = inventory.metadata.get("manifest_id")
        if not manifest_id:
            raise RuntimeError("Inventory query did not persist an evidence manifest")
        target_id = inventory.items[0]["device_id"]
        tenant_id = tenant.id
        report["data_sha256"] = inventory.data_sha256
        report["data_as_of"] = inventory.data_as_of.isoformat() if inventory.data_as_of else None

    scenarios = []
    for decision in ("reject", "approve"):
        with factory() as session, session.begin():
            scope = context(session, tenant_id, tenant_key, requester)
            proposal = create_proposal(
                scope,
                ProposalRequest(
                    action_kind="create_upgrade_order",
                    target_id=target_id,
                    payload={"component": "memory", "spec": "Add 16 GB memory module"},
                    evidence_manifest_ids=[manifest_id],
                    mode="SANDBOX_SIMULATION",
                ),
            )
            if not hasattr(proposal, "proposal_id"):
                raise RuntimeError(
                    f"Proposal policy denied action: {proposal.model_dump(mode='json')}"
                )
            proposal_id, proposal_hash = proposal.proposal_id, proposal.proposal_hash

        with factory() as session, session.begin():
            scope = context(session, tenant_id, tenant_key, approver)
            decision_result = decide_proposal(
                scope,
                proposal_id,
                DecisionRequest(decision=decision, proposal_hash=proposal_hash),
            )

        execution_result = None
        if decision == "approve":
            with factory() as session, session.begin():
                scope = context(session, tenant_id, tenant_key, requester)
                execution_result = execute_proposal(scope, proposal_id).model_dump(mode="json")

        with factory() as session, session.begin():
            scope = context(session, tenant_id, tenant_key, admin)
            persisted = session.scalar(
                select(Proposal).where(
                    Proposal.tenant_id == tenant_id,
                    Proposal.id == proposal_id,
                )
            )
            events = session.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.tenant_id == tenant_id,
                    AuditEvent.entity_type == "proposal",
                    AuditEvent.entity_id == str(proposal_id),
                )
                .order_by(AuditEvent.id.asc())
            ).all()
            chain = verify_audit_chain(scope)
            scenario = {
                "proposal_id": proposal_id,
                "proposal_hash": proposal_hash,
                "proposal": persisted.proposal_json,
                "final_status": persisted.status,
                "status_transition": [
                    {
                        "event": event.event_type,
                        "from": event.details_json.get("from"),
                        "to": event.details_json.get("to"),
                        "actor_id": event.actor_id,
                        "actor_role": event.details_json.get("actor_role"),
                    }
                    for event in events
                ],
                "decision": decision_result.model_dump(mode="json"),
                "execution": execution_result,
                "audit_chain_valid": chain.valid,
            }
            scenarios.append(scenario)
    report["scenarios"] = scenarios
    with factory() as session, session.begin():
        scope = context(session, tenant_id, tenant_key, admin)
        report["audit_chain_verification"] = verify_audit_chain(scope).model_dump(mode="json")
    destination = ROOT / "reports" / "action_demo.json"
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {destination}")
    print(json.dumps(report["audit_chain_verification"], sort_keys=True))
    engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
