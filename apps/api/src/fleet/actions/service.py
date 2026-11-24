"""Durable proposal policy, state transitions, approvals, simulation and audit chain."""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from fleet.agent.graph import GRAPH_VERSION, MODEL_VERSION, PROMPT_VERSION
from fleet.core.identity import AuthorizationDenied, RequestContext, authorize
from fleet.db.models import (
    ActionExecution,
    ActionOutbox,
    AggregateManifestRecord,
    Approval,
    AuditChainHead,
    AuditEvent,
    ComplianceResult,
    Device,
    Employee,
    GraphRun,
    Proposal,
    TelemetrySnapshot,
)
from fleet.evidence.ledger import _manifest_refs_resolvable, stable_hash
from fleet.evidence.models import AggregateManifest

from .schemas import (
    AuditChainVerification,
    DecisionRequest,
    DecisionResponse,
    ExecutionResponse,
    PolicyDecision,
    ProposalDocument,
    ProposalRequest,
    ProposalResponse,
    ProposalStatus,
)

POLICY_VERSION = "fleet-action-policy-v1"
SANDBOX_ACTION_VERSION = "sandbox-sim-v1"
AUDIT_SENTINEL = "0" * 64
MAX_EVIDENCE_AGE = timedelta(days=7)
PROPOSAL_TTL = timedelta(hours=24)

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "DRAFT": frozenset({"PENDING_APPROVAL", "BLOCKED", "EXPIRED"}),
    "PENDING_APPROVAL": frozenset({"APPROVED", "REJECTED", "EXPIRED", "BLOCKED"}),
    "APPROVED": frozenset({"EXECUTING", "EXPIRED", "BLOCKED"}),
    "EXECUTING": frozenset({"EXECUTED", "FAILED"}),
    "EXECUTED": frozenset(),
    "REJECTED": frozenset(),
    "EXPIRED": frozenset(),
    "BLOCKED": frozenset(),
    "FAILED": frozenset(),
}


class ActionNotFound(LookupError):
    """Opaque missing/foreign proposal, target, or evidence response."""


class ActionConflict(RuntimeError):
    """The requested transition is stale or not legal in the current state."""


def _now(context: RequestContext) -> datetime:
    value = context.clock()
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("request clock must be timezone-aware")
    return value.astimezone(UTC)


def _canonical_row_hash(proposal: Proposal) -> str:
    return stable_hash(proposal.proposal_json)


def _verified_manifests(
    context: RequestContext, manifest_ids: list[str]
) -> list[AggregateManifest] | None:
    manifests = []
    for manifest_id in manifest_ids:
        row = context.session.scalar(
            select(AggregateManifestRecord).where(
                AggregateManifestRecord.tenant_id == context.tenant_id,
                AggregateManifestRecord.manifest_id == manifest_id,
            )
        )
        if row is None:
            return None
        try:
            if stable_hash(row.manifest_json) != row.manifest_hash:
                return None
            manifest = AggregateManifest.model_validate(row.manifest_json)
            payload = manifest.model_dump(mode="python")
            payload.pop("query_fingerprint")
            payload.pop("manifest_id")
            if (
                manifest.tenant_id != context.tenant_id
                or manifest.manifest_id != manifest_id
                or manifest.manifest_id != "man_" + manifest.query_fingerprint
                or stable_hash(payload) != manifest.query_fingerprint
                or not _manifest_refs_resolvable(context, manifest)
            ):
                return None
        except Exception:
            return None
        manifests.append(manifest)
    if len({manifest.source_hash for manifest in manifests}) != 1:
        return None
    return manifests


def _target(context: RequestContext, request: ProposalRequest) -> tuple[str, Any] | None:
    if request.action_kind == "notify_employee":
        employee = context.session.scalar(
            select(Employee.employee_id).where(
                Employee.tenant_id == context.tenant_id,
                Employee.employee_id == request.target_id,
            )
        )
        return ("employee", employee) if employee else None
    device = context.session.scalar(
        select(Device.device_id).where(
            Device.tenant_id == context.tenant_id, Device.device_id == request.target_id
        )
    )
    return ("device", device) if device else None


def evaluate_proposal_policy(
    context: RequestContext,
    request: ProposalRequest,
    manifests: list[AggregateManifest],
    *,
    policy_version: str = POLICY_VERSION,
    real_external_adapter_enabled: bool = False,
) -> tuple[PolicyDecision, datetime | None, str | None]:
    """Run deterministic policy after integrity, tenant and target-scope validation."""
    observed_at = _target_data_as_of(manifests, request.target_id)
    facts: dict[str, Any] = {
        "evidence_manifest_count": len(manifests),
        "target_scope_match": False,
        "evidence_latest_observed_at": observed_at.isoformat() if observed_at else None,
        "simulation_mode": request.mode,
        "adapter_enabled": real_external_adapter_enabled,
    }
    eligible = sum(int(manifest.coverage.get("eligible") or 0) for manifest in manifests)
    observed = sum(int(manifest.coverage.get("observed") or 0) for manifest in manifests)
    unknown = sum(int(manifest.coverage.get("unknown") or 0) for manifest in manifests)
    coverage_fraction = observed / eligible if eligible else 0.0
    facts["coverage"] = {
        "eligible": eligible,
        "observed": observed,
        "unknown": unknown,
        "fraction": coverage_fraction,
    }
    target_match = any(
        request.target_id in {str(ref.get("device_id")) for ref in manifest.matched_snapshot_refs}
        or (
            request.action_kind == "notify_employee"
            and manifest.filters.get("employee_id") == request.target_id
        )
        for manifest in manifests
    )
    facts["target_scope_match"] = target_match
    code = "allowed"
    message = "Evidence, target scope and policy checks passed."
    allowed = True

    if any(manifest.tenant_id != context.tenant_id for manifest in manifests):
        allowed, code, message = (
            False,
            "evidence_scope_mismatch",
            "Evidence does not belong to the active tenant.",
        )
    elif policy_version != POLICY_VERSION:
        allowed, code, message = (
            False,
            "policy_version_mismatch",
            "Unsupported action policy version.",
        )
    elif eligible == 0 or coverage_fraction < 0.7:
        allowed, code, message = (
            False,
            "insufficient_coverage",
            "Evidence coverage is below the 70% action threshold.",
        )
    elif observed_at is None:
        allowed, code, message = False, "insufficient_data", "Evidence has no observed timestamp."
    elif not target_match:
        allowed, code, message = (
            False,
            "evidence_scope_mismatch",
            "Evidence does not cover the requested target.",
        )
    elif request.action_kind == "flag_device_for_replacement":
        allowed, code, message = (
            False,
            "action_forbidden",
            "Device replacement is not an approved action in this policy.",
        )
    elif request.action_kind == "create_upgrade_order" and (
        request.payload.get("component") == "storage_capacity"
        and re.search(r"\breplac", str(request.payload.get("spec", "")), re.I)
    ):
        allowed, code, message = (
            False,
            "action_forbidden",
            "Disk replacement is not supported by the action policy.",
        )
    elif request.action_kind == "open_remediation_ticket":
        current_fail = _has_source_failure(
            context,
            request.target_id,
            str(request.payload.get("check_id", "")),
            manifests,
        )
        facts["contrary_source_failure_exists"] = current_fail
        if not current_fail:
            allowed, code, message = (
                False,
                "no_contrary_evidence",
                "No matching source failure exists; a remediation ticket is not supported.",
            )
    elif request.action_kind == "notify_employee" and request.mode == "REAL_EXTERNAL":
        allowed, code, message = (
            False,
            "adapter_disabled",
            "External notification adapter is disabled.",
        )

    if allowed and request.mode == "REAL_EXTERNAL":
        age = _now(context) - observed_at
        facts["evidence_age_seconds"] = max(age.total_seconds(), 0)
        if not real_external_adapter_enabled:
            allowed, code, message = (
                False,
                "adapter_disabled",
                "REAL_EXTERNAL execution is disabled.",
            )
        elif age > MAX_EVIDENCE_AGE:
            allowed, code, message = (
                False,
                "stale_evidence",
                "REAL_EXTERNAL evidence is older than seven days.",
            )
    elif request.mode == "SANDBOX_SIMULATION":
        facts["historical_data"] = (_now(context) - observed_at) > MAX_EVIDENCE_AGE

    return (
        PolicyDecision(
            allowed=allowed, code=code, message=message, policy_version=policy_version, facts=facts
        ),
        observed_at,
        next((manifest.source_hash for manifest in manifests), None),
    )


def _has_source_failure(
    context: RequestContext,
    device_id: str,
    check_id: str,
    manifests: list[AggregateManifest],
) -> bool:
    snapshot_ids = {
        int(ref["snapshot_id"])
        for manifest in manifests
        for ref in manifest.matched_snapshot_refs
        if str(ref.get("device_id")) == device_id
    }
    if not snapshot_ids:
        return False
    row = context.session.scalar(
        select(ComplianceResult.id)
        .join(
            TelemetrySnapshot,
            (TelemetrySnapshot.id == ComplianceResult.snapshot_id)
            & (TelemetrySnapshot.tenant_id == ComplianceResult.tenant_id),
        )
        .where(
            ComplianceResult.tenant_id == context.tenant_id,
            ComplianceResult.snapshot_id.in_(snapshot_ids),
            ComplianceResult.check_id == check_id,
            func.lower(ComplianceResult.status) == "fail",
            func.lower(ComplianceResult.severity) == "high",
        )
        .limit(1)
    )
    return row is not None


def create_proposal(
    context: RequestContext,
    request: ProposalRequest,
    *,
    policy_version: str = POLICY_VERSION,
    graph_version: str = GRAPH_VERSION,
    prompt_version: str = PROMPT_VERSION,
    model_version: str = MODEL_VERSION,
    real_external_adapter_enabled: bool = False,
    idempotency_key: str | None = None,
) -> ProposalResponse | PolicyDecision:
    authorize(context.principal, context.tenant_key, "draft_proposal")
    if idempotency_key is not None:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", idempotency_key):
            raise ValueError("invalid idempotency key")
        prior = context.session.scalar(
            select(Proposal).where(
                Proposal.tenant_id == context.tenant_id,
                Proposal.requested_by == context.principal.user_id,
                Proposal.idempotency_key == idempotency_key,
            )
        )
        if prior is not None:
            prior_document = _verify_document(context, prior)
            expected_payload = {
                key: value.strip() if isinstance(value, str) else value
                for key, value in request.payload.items()
            }
            if (
                prior_document.target_id != request.target_id
                or prior_document.action_kind != request.action_kind
                or prior_document.payload != expected_payload
                or prior_document.evidence_manifest_ids != request.evidence_manifest_ids
                or prior_document.mode != request.mode
            ):
                raise ActionConflict("Idempotency key was already used for another proposal")
            return ProposalResponse(
                proposal_id=prior.id,
                proposal_hash=prior.proposal_hash,
                status=prior.status,
                mode=prior_document.mode,
                proposal=prior_document,
                policy_decision=PolicyDecision(
                    allowed=True,
                    code="idempotent_replay",
                    message="Returned the existing immutable proposal.",
                    policy_version=prior.policy_version,
                    facts=prior_document.policy_facts,
                ),
                approval_summary=(
                    f"{prior_document.mode} — {prior_document.action_kind} for "
                    f"{prior_document.target_type} {prior_document.target_id}; "
                    "existing proposal returned; no second proposal was created."
                ),
                trace_id=context.run_ref,
            )
    target = _target(context, request)
    if target is None:
        raise ActionNotFound("Target not found")
    manifests = _verified_manifests(context, request.evidence_manifest_ids)
    if not manifests:
        raise ActionNotFound("Evidence not found")
    decision, observed_at, source_hash = evaluate_proposal_policy(
        context,
        request,
        manifests,
        policy_version=policy_version,
        real_external_adapter_enabled=real_external_adapter_enabled,
    )
    if not decision.allowed:
        _append_audit(
            context,
            event_type="policy_decision_denied",
            entity_type="action_request",
            entity_id=uuid.uuid4().hex,
            details={"code": decision.code, "policy_version": policy_version},
        )
        return decision
    if observed_at is None or source_hash is None:
        return PolicyDecision(
            allowed=False,
            code="insufficient_data",
            message="Evidence provenance is incomplete.",
            policy_version=policy_version,
        )

    now = _now(context)
    payload = {
        key: value.strip() if isinstance(value, str) else value
        for key, value in request.payload.items()
    }
    doc = ProposalDocument(
        tenant_key=context.tenant_key,
        actor_id=context.principal.user_id,
        target_type=target[0],
        target_id=request.target_id,
        action_kind=request.action_kind,
        payload=payload,
        evidence_manifest_ids=request.evidence_manifest_ids,
        policy_facts=decision.facts,
        data_as_of=observed_at,
        expires_at=now + PROPOSAL_TTL,
        mode=request.mode,
        graph_version=graph_version,
        policy_version=policy_version,
        prompt_version=prompt_version,
        model_version=model_version,
    )
    doc_json = doc.model_dump(mode="json")
    proposal_hash = stable_hash(doc_json)
    thread_id = f"t{context.tenant_id}-{uuid.uuid4().hex}"
    run = GraphRun(
        tenant_id=context.tenant_id,
        thread_id=f"action-{uuid.uuid4().hex}",
        trace_id=uuid.uuid4().hex,
        user_id=context.principal.user_id,
        data_sha256=source_hash,
        policy_version=policy_version,
        graph_version=graph_version,
        prompt_version=prompt_version,
        model_version=model_version,
    )
    context.session.add(run)
    context.session.flush()
    proposal = Proposal(
        tenant_id=context.tenant_id,
        run_id=run.id,
        requested_by=context.principal.user_id,
        proposal_hash=proposal_hash,
        status="DRAFT",
        data_sha256=source_hash,
        policy_version=policy_version,
        graph_version=graph_version,
        prompt_version=prompt_version,
        model_version=model_version,
        proposal_json=doc_json,
        expires_at=doc.expires_at,
        workflow_thread_id=thread_id,
        idempotency_key=idempotency_key,
    )
    context.session.add(proposal)
    context.session.flush()
    _append_audit(
        context,
        event_type="proposal_drafted",
        entity_type="proposal",
        entity_id=str(proposal.id),
        details={
            "proposal_hash": proposal_hash,
            "action_kind": request.action_kind,
            "target_ref_hash": _hash_id(request.target_id),
        },
        run_id=run.id,
    )
    _transition(context, proposal, "PENDING_APPROVAL", actor_id=context.principal.user_id)
    from .workflow import start_approval_interrupt

    start_approval_interrupt(context, proposal)
    summary = (
        f"{request.mode} — {request.action_kind} for {target[0]} {request.target_id}; "
        f"payload={payload}; evidence={request.evidence_manifest_ids}; data as of "
        f"{observed_at.isoformat()}. Approval does not execute this operation."
    )
    return ProposalResponse(
        proposal_id=proposal.id,
        proposal_hash=proposal_hash,
        status="PENDING_APPROVAL",
        mode=request.mode,
        proposal=doc,
        policy_decision=decision,
        approval_summary=summary,
        trace_id=context.run_ref,
    )


def decide_proposal(
    context: RequestContext,
    proposal_id: int,
    request: DecisionRequest,
    *,
    separate_requester_approver: bool = True,
    current_policy_version: str = POLICY_VERSION,
) -> DecisionResponse:
    proposal = _locked_proposal(context, proposal_id)
    if proposal is None:
        raise ActionNotFound("Proposal not found")
    capability = "approve" if request.decision == "approve" else "reject"
    authorize(context.principal, context.tenant_key, capability)
    if proposal.status != "PENDING_APPROVAL":
        raise ActionConflict("Proposal is not pending approval")
    try:
        _verify_document(context, proposal)
    except ActionConflict:
        _block_after_integrity_failure(context, proposal)
        raise
    now = _now(context)
    if proposal.expires_at <= now:
        _transition(context, proposal, "EXPIRED", actor_id=context.principal.user_id)
        raise ActionConflict("Proposal expired")
    if proposal.policy_version != current_policy_version:
        _transition(context, proposal, "BLOCKED", actor_id=context.principal.user_id)
        raise ActionConflict("Proposal policy version is stale")
    if separate_requester_approver and proposal.requested_by == context.principal.user_id:
        raise AuthorizationDenied("Requester and approver must be different actors")
    if request.proposal_hash != proposal.proposal_hash:
        raise ActionConflict("Proposal hash does not match")
    _revalidate_freshness(context, proposal)
    approval = Approval(
        tenant_id=context.tenant_id,
        proposal_id=proposal.id,
        approver_id=context.principal.user_id,
        approver_role="admin" if "admin" in context.principal.roles else "approver",
        decision=request.decision,
        proposal_hash=proposal.proposal_hash,
        created_at=now,
    )
    context.session.add(approval)
    context.session.flush()
    next_status = "APPROVED" if request.decision == "approve" else "REJECTED"
    _transition(
        context,
        proposal,
        next_status,
        actor_id=context.principal.user_id,
        details={
            "decision": request.decision,
            "proposal_hash": proposal.proposal_hash,
            "actor_role": "admin" if "admin" in context.principal.roles else "approver",
        },
        event_type="proposal_approved" if request.decision == "approve" else "proposal_rejected",
    )
    from .workflow import resume_after_decision

    workflow = resume_after_decision(context, proposal)
    return DecisionResponse(
        proposal_id=proposal.id,
        status=next_status,
        decision=request.decision,
        actor_id=context.principal.user_id,
        actor_role="admin" if "admin" in context.principal.roles else "approver",
        proposal_hash=proposal.proposal_hash,
        workflow_status=workflow.get("status", next_status),
        trace_id=context.run_ref,
    )


def execute_proposal(
    context: RequestContext,
    proposal_id: int,
    *,
    sandbox_adapter=None,
) -> ExecutionResponse:
    proposal = _locked_proposal(context, proposal_id)
    if proposal is None:
        raise ActionNotFound("Proposal not found")
    authorize(context.principal, context.tenant_key, "draft_proposal")
    existing = context.session.scalar(
        select(ActionExecution).where(
            ActionExecution.tenant_id == context.tenant_id,
            ActionExecution.proposal_id == proposal.id,
            ActionExecution.action_version == SANDBOX_ACTION_VERSION,
        )
    )
    if existing is not None and existing.status == "EXECUTED":
        _append_audit(
            context,
            event_type="execution_idempotent_replay",
            entity_type="proposal",
            entity_id=str(proposal.id),
            details={
                "execution_id": existing.execution_id,
                "action_version": existing.action_version,
            },
            run_id=proposal.run_id,
        )
        return ExecutionResponse(
            proposal_id=proposal.id,
            execution_id=existing.execution_id,
            action_version=existing.action_version,
            status=existing.status,
            simulation_mode="SANDBOX_SIMULATION",
            result=existing.result_json or {},
            repeated=True,
            trace_id=context.run_ref,
        )
    if proposal.status != "APPROVED":
        raise ActionConflict("Only an approved proposal may execute")
    approval = context.session.scalar(
        select(Approval).where(
            Approval.tenant_id == context.tenant_id,
            Approval.proposal_id == proposal.id,
            Approval.proposal_hash == proposal.proposal_hash,
            Approval.decision == "approve",
        )
    )
    if approval is None:
        _block_after_integrity_failure(context, proposal)
        raise ActionConflict("A separate authenticated approval record is required")
    try:
        document = _verify_document(context, proposal)
    except ActionConflict:
        _block_after_integrity_failure(context, proposal)
        raise
    if document.mode != "SANDBOX_SIMULATION":
        _transition(context, proposal, "BLOCKED", actor_id=context.principal.user_id)
        raise ActionConflict("REAL_EXTERNAL execution is disabled")
    if proposal.expires_at <= _now(context):
        _transition(context, proposal, "EXPIRED", actor_id=context.principal.user_id)
        raise ActionConflict("Proposal expired")
    _revalidate_freshness(context, proposal)
    _transition(context, proposal, "EXECUTING", actor_id=context.principal.user_id)
    execution_id = f"{proposal.id}:{SANDBOX_ACTION_VERSION}"
    execution = ActionExecution(
        tenant_id=context.tenant_id,
        proposal_id=proposal.id,
        execution_id=execution_id,
        proposal_hash=proposal.proposal_hash,
        status="EXECUTING",
        action_version=SANDBOX_ACTION_VERSION,
    )
    context.session.add(execution)
    context.session.flush()
    _append_audit(
        context,
        event_type="execution_started",
        entity_type="proposal",
        entity_id=str(proposal.id),
        details={"execution_id": execution_id, "action_version": SANDBOX_ACTION_VERSION},
        run_id=proposal.run_id,
    )
    # Sandbox adapter has a DB-only simulated effect. No connector/network client is called.
    adapter = sandbox_adapter or _sandbox_simulate
    try:
        result = adapter(document, proposal)
    except Exception as exc:
        result = {"simulated": True, "failed": True, "error_type": type(exc).__name__}
        execution.status = "FAILED"
        execution.result_json = result
        _transition(context, proposal, "FAILED", actor_id=context.principal.user_id)
        _append_audit(
            context,
            event_type="execution_failed",
            entity_type="proposal",
            entity_id=str(proposal.id),
            details={"execution_id": execution_id, "error_type": type(exc).__name__},
            run_id=proposal.run_id,
        )
        return ExecutionResponse(
            proposal_id=proposal.id,
            execution_id=execution_id,
            action_version=SANDBOX_ACTION_VERSION,
            status="FAILED",
            simulation_mode="SANDBOX_SIMULATION",
            result=result,
            trace_id=context.run_ref,
        )
    execution.status = "EXECUTED"
    execution.result_json = result
    _transition(context, proposal, "EXECUTED", actor_id=context.principal.user_id)
    _append_audit(
        context,
        event_type="execution_succeeded",
        entity_type="proposal",
        entity_id=str(proposal.id),
        details={"execution_id": execution_id, "action_version": SANDBOX_ACTION_VERSION},
        run_id=proposal.run_id,
    )
    return ExecutionResponse(
        proposal_id=proposal.id,
        execution_id=execution_id,
        action_version=SANDBOX_ACTION_VERSION,
        status="EXECUTED",
        simulation_mode="SANDBOX_SIMULATION",
        result=result,
        trace_id=context.run_ref,
    )


def _sandbox_simulate(document: ProposalDocument, proposal: Proposal) -> dict[str, Any]:
    """Record a simulated result; this function has no network or provider client."""
    return {
        "simulated": True,
        "mode": "SANDBOX_SIMULATION",
        "action_kind": document.action_kind,
        "target_ref_hash": _hash_id(document.target_id),
        "proposal_hash": proposal.proposal_hash,
        "message": "Simulation recorded. No external system was contacted.",
    }


class ExternalActionOutbox:
    """Future connector boundary: stage idempotent intent; never sends network requests."""

    @staticmethod
    def idempotency_key(tenant_id: int, proposal_id: int, action_version: str) -> str:
        return stable_hash(
            {
                "tenant_id": tenant_id,
                "proposal_id": proposal_id,
                "action_version": action_version,
            }
        )

    def stage(
        self, context: RequestContext, proposal_id: int, *, adapter_enabled: bool = False
    ) -> ActionOutbox:
        if not adapter_enabled:
            raise ActionConflict("REAL_EXTERNAL adapter is disabled")
        authorize(context.principal, context.tenant_key, "draft_proposal")
        proposal = _locked_proposal(context, proposal_id)
        if proposal is None:
            raise ActionNotFound("Proposal not found")
        if proposal.status != "APPROVED":
            raise ActionConflict("Only approved proposals can enter the outbox")
        document = _verify_document(context, proposal)
        if document.mode != "REAL_EXTERNAL":
            raise ActionConflict("Sandbox work must never enter the external outbox")
        _revalidate_freshness(context, proposal, real_external_adapter_enabled=True)
        action_version = "provider-v1"
        key = self.idempotency_key(context.tenant_id, proposal.id, action_version)
        existing = context.session.scalar(
            select(ActionOutbox).where(
                ActionOutbox.tenant_id == context.tenant_id,
                ActionOutbox.proposal_id == proposal.id,
                ActionOutbox.action_version == action_version,
            )
        )
        if existing is not None:
            if existing.provider_idempotency_key != key:
                raise ActionConflict("Outbox idempotency key mismatch")
            return existing
        payload = document.model_dump(mode="json")
        entry = ActionOutbox(
            tenant_id=context.tenant_id,
            proposal_id=proposal.id,
            action_version=action_version,
            provider_idempotency_key=key,
            payload_hash=proposal.proposal_hash,
            payload_json=payload,
            status="PENDING",
        )
        context.session.add(entry)
        context.session.flush()
        _append_audit(
            context,
            event_type="external_outbox_staged",
            entity_type="proposal",
            entity_id=str(proposal.id),
            details={"action_version": action_version, "provider_idempotency_key": key},
            run_id=proposal.run_id,
        )
        return entry

    def reconcile(
        self,
        context: RequestContext,
        outbox_id: int,
        *,
        provider_reference: str,
        result: dict[str, Any],
        success: bool,
    ) -> ActionOutbox:
        """Record a signed-in connector reconciliation result; this method calls no provider."""
        authorize(context.principal, context.tenant_key, "audit")
        if not 1 <= len(provider_reference) <= 255 or len(result) > 20:
            raise ValueError("invalid reconciliation record")
        entry = context.session.scalar(
            select(ActionOutbox)
            .where(ActionOutbox.tenant_id == context.tenant_id, ActionOutbox.id == outbox_id)
            .with_for_update()
        )
        if entry is None:
            raise ActionNotFound("Outbox entry not found")
        if entry.status == "RECONCILED":
            return entry
        if entry.status not in {"PENDING", "SENT"}:
            raise ActionConflict("Outbox entry is not reconcilable")
        sanitized = {
            key: value
            for key, value in result.items()
            if key.casefold() not in {"email", "message", "token", "secret", "password", "payload"}
            and isinstance(value, (str, int, float, bool, type(None)))
        }
        entry.provider_reference = provider_reference
        entry.reconciliation_json = sanitized
        entry.status = "RECONCILED" if success else "FAILED"
        _append_audit(
            context,
            event_type="external_outbox_reconciled" if success else "external_outbox_failed",
            entity_type="proposal",
            entity_id=str(entry.proposal_id),
            details={"action_version": entry.action_version, "status": entry.status},
        )
        context.session.flush()
        return entry


def _locked_proposal(context: RequestContext, proposal_id: int) -> Proposal | None:
    return context.session.scalar(
        select(Proposal)
        .where(Proposal.tenant_id == context.tenant_id, Proposal.id == proposal_id)
        .with_for_update()
    )


def _verify_document(context: RequestContext, proposal: Proposal) -> ProposalDocument:
    if _canonical_row_hash(proposal) != proposal.proposal_hash:
        raise ActionConflict("Proposal payload hash mismatch")
    try:
        document = ProposalDocument.model_validate(proposal.proposal_json)
    except Exception as exc:
        raise ActionConflict("Proposal document is invalid") from exc
    if (
        document.tenant_key != context.tenant_key
        or document.actor_id != proposal.requested_by
        or document.policy_version != proposal.policy_version
        or document.graph_version != proposal.graph_version
        or document.prompt_version != proposal.prompt_version
        or document.model_version != proposal.model_version
    ):
        raise ActionConflict("Proposal tenant scope mismatch")
    return document


def _block_after_integrity_failure(context: RequestContext, proposal: Proposal) -> None:
    if "BLOCKED" in ALLOWED_TRANSITIONS.get(proposal.status, frozenset()):
        _transition(
            context,
            proposal,
            "BLOCKED",
            actor_id=context.principal.user_id,
            details={"code": "proposal_integrity_failure"},
        )


def _revalidate_freshness(
    context: RequestContext,
    proposal: Proposal,
    *,
    real_external_adapter_enabled: bool = False,
) -> None:
    document = _verify_document(context, proposal)
    manifests = _verified_manifests(context, document.evidence_manifest_ids)
    if not manifests:
        _transition(context, proposal, "BLOCKED", actor_id=context.principal.user_id)
        raise ActionConflict("Evidence is stale or no longer resolvable")
    current_data_as_of = _target_data_as_of(manifests, document.target_id)
    if current_data_as_of != document.data_as_of:
        _transition(context, proposal, "BLOCKED", actor_id=context.principal.user_id)
        raise ActionConflict("Target evidence freshness changed after proposal")
    if document.mode == "REAL_EXTERNAL":
        latest_target_data = context.session.scalar(
            select(func.max(TelemetrySnapshot.collected_at)).where(
                TelemetrySnapshot.tenant_id == context.tenant_id,
                (
                    TelemetrySnapshot.employee_id == document.target_id
                    if document.target_type == "employee"
                    else TelemetrySnapshot.device_id == document.target_id
                ),
            )
        )
        if latest_target_data != document.data_as_of:
            _transition(context, proposal, "BLOCKED", actor_id=context.principal.user_id)
            raise ActionConflict("REAL_EXTERNAL target data changed after proposal")
    target = ProposalRequest.model_validate(
        {
            "action_kind": document.action_kind,
            "target_id": document.target_id,
            "payload": document.payload,
            "evidence_manifest_ids": document.evidence_manifest_ids,
            "mode": document.mode,
        }
    )
    decision, _, _ = evaluate_proposal_policy(
        context,
        target,
        manifests,
        real_external_adapter_enabled=real_external_adapter_enabled,
    )
    if not decision.allowed:
        _transition(context, proposal, "BLOCKED", actor_id=context.principal.user_id)
        raise ActionConflict("Action policy no longer permits this proposal")


def _target_data_as_of(manifests: list[AggregateManifest], target_id: str) -> datetime | None:
    timestamps = []
    for manifest in manifests:
        for reference in manifest.matched_snapshot_refs + manifest.excluded_refs:
            if str(reference.get("device_id")) == target_id:
                stamp = reference.get("collected_at")
                if isinstance(stamp, datetime):
                    timestamps.append(stamp)
                elif isinstance(stamp, str):
                    timestamps.append(datetime.fromisoformat(stamp.replace("Z", "+00:00")))
    if timestamps:
        return max(timestamps)
    return max(
        (manifest.latest_observed_at for manifest in manifests if manifest.latest_observed_at),
        default=None,
    )


def _transition(
    context: RequestContext,
    proposal: Proposal,
    next_status: ProposalStatus,
    *,
    actor_id: str,
    details: dict[str, Any] | None = None,
    event_type: str | None = None,
) -> None:
    current = proposal.status
    if next_status not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise ActionConflict(f"Illegal proposal transition {current} -> {next_status}")
    changed = context.session.execute(
        update(Proposal)
        .where(
            Proposal.tenant_id == context.tenant_id,
            Proposal.id == proposal.id,
            Proposal.status == current,
            Proposal.proposal_hash == proposal.proposal_hash,
        )
        .values(status=next_status)
    )
    if changed.rowcount != 1:
        raise ActionConflict("Proposal transition lost compare-and-swap")
    proposal.status = next_status
    _append_audit(
        context,
        event_type=event_type or f"proposal_{next_status.casefold()}",
        entity_type="proposal",
        entity_id=str(proposal.id),
        details={"from": current, "to": next_status, **(details or {})},
        actor_id=actor_id,
        run_id=proposal.run_id,
    )


def _hash_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _event_digest(
    *,
    previous_hash: str,
    tenant_id: int,
    actor_id: str,
    event_type: str,
    entity_type: str,
    entity_id: str,
    details: dict[str, Any],
    created_at: datetime,
) -> str:
    return stable_hash(
        {
            "previous_hash": previous_hash,
            "tenant_id": tenant_id,
            "actor_id": actor_id,
            "event_type": event_type,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "details_json": details,
            "created_at": created_at,
        }
    )


def _append_audit(
    context: RequestContext,
    *,
    event_type: str,
    entity_type: str,
    entity_id: str,
    details: dict[str, Any],
    actor_id: str | None = None,
    run_id: int | None = None,
) -> AuditEvent:
    actor = actor_id or context.principal.user_id
    # Lock an upserted per-tenant head to serialize concurrent append operations.
    context.session.execute(
        pg_insert(AuditChainHead)
        .values(tenant_id=context.tenant_id, last_event_id=None, last_hash=AUDIT_SENTINEL)
        .on_conflict_do_nothing(index_elements=["tenant_id"])
    )
    head = context.session.scalar(
        select(AuditChainHead)
        .where(AuditChainHead.tenant_id == context.tenant_id)
        .with_for_update()
    )
    if head is None:
        raise RuntimeError("audit chain head could not be locked")
    timestamp = _now(context)
    previous_hash = head.last_hash
    details_json = {**details, "trace_id": details.get("trace_id", context.run_ref)}
    event = AuditEvent(
        tenant_id=context.tenant_id,
        run_id=run_id,
        actor_id=actor,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        details_json=details_json,
        previous_hash=previous_hash,
        created_at=timestamp,
    )
    event.event_hash = _event_digest(
        previous_hash=previous_hash,
        tenant_id=context.tenant_id,
        actor_id=actor,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details_json,
        created_at=timestamp,
    )
    context.session.add(event)
    context.session.flush()
    head.last_event_id = event.id
    head.last_hash = event.event_hash
    context.session.flush()
    return event


def verify_audit_chain(context: RequestContext) -> AuditChainVerification:
    authorize(context.principal, context.tenant_key, "audit")
    events = context.session.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.tenant_id == context.tenant_id,
            AuditEvent.event_hash.is_not(None),
        )
        .order_by(AuditEvent.id.asc())
    ).all()
    head = context.session.scalar(
        select(AuditChainHead).where(AuditChainHead.tenant_id == context.tenant_id)
    )
    valid, verified_count, previous_hash = verify_audit_events(
        events, head.last_hash if head else AUDIT_SENTINEL
    )
    return AuditChainVerification(
        tenant_key=context.tenant_key,
        valid=valid,
        events_verified=verified_count,
        head_hash=previous_hash,
        limitation=(
            "Hash chaining detects edits/reordering only relative to a trusted saved head; "
            "a privileged database owner can rewrite the entire chain, and legacy unchained "
            "events are excluded."
        ),
    )


def verify_audit_events(events, saved_head: str) -> tuple[bool, int, str]:
    """Verify ordered event digests against a separately stored head value."""
    previous_hash = AUDIT_SENTINEL
    for index, event in enumerate(events):
        if event.previous_hash != previous_hash:
            return False, index, previous_hash
        computed = _event_digest(
            previous_hash=event.previous_hash,
            tenant_id=event.tenant_id,
            actor_id=event.actor_id,
            event_type=event.event_type,
            entity_type=event.entity_type,
            entity_id=event.entity_id,
            details=event.details_json,
            created_at=event.created_at,
        )
        if computed != event.event_hash:
            return False, index, previous_hash
        previous_hash = event.event_hash
    return saved_head == previous_hash, len(events), previous_hash
