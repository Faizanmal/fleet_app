from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from fleet.actions.schemas import ProposalRequest
from fleet.actions.service import (
    ALLOWED_TRANSITIONS,
    ActionConflict,
    _verify_document,
    evaluate_proposal_policy,
)
from fleet.core.identity import Membership, Principal, RequestContext
from fleet.evidence.models import AggregateManifest


class NoSourceRows:
    def scalar(self, *_args, **_kwargs):
        return None


def context():
    now = datetime(2026, 11, 22, tzinfo=UTC)
    principal = Principal(
        user_id="operator-1",
        memberships=(Membership("acme-001", frozenset({"operator"})),),
        active_tenant_id="acme-001",
        auth_method="test",
    )
    return RequestContext(
        session=NoSourceRows(),  # policy branch uses only scalar() for compliance checks
        principal=principal,
        tenant_id=1,
        tenant_key="acme-001",
        clock=lambda: now,
    )


def manifest(*, tenant_id=1, coverage=None):
    observed = datetime(2026, 6, 12, tzinfo=UTC)
    return AggregateManifest(
        tenant_id=tenant_id,
        query_version="deterministic-query-v1",
        query_type="latest_snapshots",
        filters={},
        as_of=observed,
        selection_rule="latest",
        matched_snapshot_refs=({"device_id": "DEVICE-1", "snapshot_id": 1},),
        excluded_refs=(),
        numerator=1,
        denominator=1,
        source_hash="f" * 64,
        query_fingerprint="a" * 64,
        threshold_version="fleet-policy-v1",
        latest_observed_at=observed,
        coverage=coverage or {"eligible": 10, "observed": 10, "unknown": 0},
        manifest_id="man_" + "a" * 64,
    )


def upgrade_request(mode="SANDBOX_SIMULATION"):
    return ProposalRequest(
        action_kind="create_upgrade_order",
        target_id="DEVICE-1",
        payload={"component": "memory", "spec": "Add 16 GB memory module"},
        evidence_manifest_ids=["man_" + "a" * 64],
        mode=mode,
    )


def test_legal_transition_table_has_only_documented_edges_and_terminal_states():
    assert ALLOWED_TRANSITIONS["DRAFT"] == {"PENDING_APPROVAL", "BLOCKED", "EXPIRED"}
    assert ALLOWED_TRANSITIONS["PENDING_APPROVAL"] == {
        "APPROVED",
        "REJECTED",
        "EXPIRED",
        "BLOCKED",
    }
    assert ALLOWED_TRANSITIONS["APPROVED"] == {"EXECUTING", "EXPIRED", "BLOCKED"}
    assert ALLOWED_TRANSITIONS["EXECUTING"] == {"EXECUTED", "FAILED"}
    for terminal in ("EXECUTED", "REJECTED", "EXPIRED", "BLOCKED", "FAILED"):
        assert ALLOWED_TRANSITIONS[terminal] == frozenset()


def test_historical_evidence_allowed_only_as_labeled_simulation():
    decision, observed_at, _source_hash = evaluate_proposal_policy(
        context(), upgrade_request(), [manifest()]
    )
    assert decision.allowed
    assert decision.facts["historical_data"] is True
    assert decision.facts["coverage"]["fraction"] == 1
    assert observed_at == manifest().latest_observed_at


def test_real_external_is_denied_by_default_and_stale_source_is_recorded():
    decision, _observed_at, _source_hash = evaluate_proposal_policy(
        context(), upgrade_request("REAL_EXTERNAL"), [manifest()]
    )
    assert decision.allowed is False
    assert decision.code == "adapter_disabled"


def test_replacement_and_insufficient_coverage_are_denied():
    replacement = ProposalRequest(
        action_kind="flag_device_for_replacement",
        target_id="DEVICE-1",
        payload={"reason": "Replace drive"},
        evidence_manifest_ids=["man_" + "a" * 64],
    )
    denied, *_ = evaluate_proposal_policy(context(), replacement, [manifest()])
    assert denied.code == "action_forbidden"

    low_coverage, *_ = evaluate_proposal_policy(
        context(),
        upgrade_request(),
        [manifest(coverage={"eligible": 10, "observed": 6, "unknown": 4})],
    )
    assert low_coverage.code == "insufficient_coverage"

    foreign, *_ = evaluate_proposal_policy(context(), upgrade_request(), [manifest(tenant_id=2)])
    assert foreign.code == "evidence_scope_mismatch"


def test_high_severity_ticket_requires_real_source_failure():
    request = ProposalRequest(
        action_kind="open_remediation_ticket",
        target_id="DEVICE-1",
        payload={"check_id": "disk-encryption", "note": "Review source check"},
        evidence_manifest_ids=["man_" + "a" * 64],
    )
    decision, *_ = evaluate_proposal_policy(context(), request, [manifest()])
    assert decision.allowed is False
    assert decision.code == "no_contrary_evidence"
    assert decision.facts["contrary_source_failure_exists"] is False


@pytest.mark.parametrize(
    "payload",
    [
        {"component": "disk", "spec": "replace disk"},
        {"component": "memory", "spec": "https://bad.invalid"},
        {"component": "memory", "spec": "operator@example.org"},
        {"component": "memory", "spec": "x" * 501},
        {"component": "memory", "spec": "safe", "tenant_id": 2},
    ],
)
def test_payload_is_typed_bounded_and_closed(payload):
    with pytest.raises(ValueError):
        ProposalRequest(
            action_kind="create_upgrade_order",
            target_id="DEVICE-1",
            payload=payload,
            evidence_manifest_ids=["man_" + "a" * 64],
        )


def test_decision_payload_does_not_accept_client_approval_boolean():
    from fleet.actions.schemas import DecisionRequest

    with pytest.raises(ValueError):
        DecisionRequest(decision="approve", proposal_hash="a" * 64, approved=True)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("target_id", "OTHER-DEVICE"),
        ("payload", {"component": "memory", "spec": "Add 32 GB instead"}),
        ("tenant_key", "globex-002"),
        ("actor_id", "other-actor"),
        ("evidence_manifest_ids", ["man_" + "b" * 64]),
        ("data_as_of", "2026-01-01T00:00:00Z"),
        ("expires_at", "2027-01-01T00:00:00Z"),
    ],
)
def test_any_immutable_document_alteration_fails_hash_check(field, replacement):
    from fleet.evidence.ledger import stable_hash

    original = {
        "tenant_key": "acme-001",
        "actor_id": "operator-1",
        "target_type": "device",
        "target_id": "DEVICE-1",
        "action_kind": "create_upgrade_order",
        "payload": {"component": "memory", "spec": "Add 16 GB memory module"},
        "evidence_manifest_ids": ["man_" + "a" * 64],
        "policy_facts": {},
        "data_as_of": "2026-06-12T00:00:00Z",
        "expires_at": "2026-06-13T00:00:00Z",
        "mode": "SANDBOX_SIMULATION",
        "graph_version": "g1",
        "policy_version": "fleet-action-policy-v1",
        "prompt_version": "p1",
        "model_version": "fixture-v1",
    }
    tampered = {**original, field: replacement}
    row = SimpleNamespace(proposal_json=tampered, proposal_hash=stable_hash(original))
    with pytest.raises(ActionConflict, match="hash mismatch"):
        _verify_document(context(), row)
