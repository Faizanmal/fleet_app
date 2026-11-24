from __future__ import annotations

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from fleet.api.auth import get_principal, require_role
from fleet.api.main import _error, app, health
from fleet.api.schemas import AgentRunRequest
from fleet.core.identity import Membership, Principal
from fleet.settings import Settings


def test_health_handler_is_database_independent():
    response = health()
    assert response["status"] == "ok"
    assert "build_version" in response


def test_viewer_role_dependency_denies_write_capability_before_context_creation():
    viewer = Principal(
        user_id="fixture-viewer",
        memberships=(Membership("acme-001", frozenset({"viewer"})),),
        active_tenant_id="acme-001",
        auth_method="test",
    )
    with pytest.raises(HTTPException) as error:
        require_role("operator")(viewer, "acme-001")
    assert error.value.status_code == 403


def test_missing_bearer_is_401_and_error_envelope_is_typed():
    with pytest.raises(HTTPException) as error:
        get_principal(None, Settings(database_url="postgresql://unused", demo_auth_mode=False))
    assert error.value.status_code == 401
    response = _error(401, "unauthorized", "Unauthorized")
    assert response.status_code == 401
    assert (
        response.body
        == b'{"error":{"code":"unauthorized","message":"Unauthorized","trace_id":null}}'
    )


def test_openapi_exposes_typed_phase_ten_routes_and_polling_not_sse():
    paths = app.openapi()["paths"]
    for path in (
        "/api/v1/health",
        "/api/v1/me",
        "/api/v1/fleet/summary",
        "/api/v1/devices",
        "/api/v1/devices/{device_id}",
        "/api/v1/devices/{device_id}/history",
        "/api/v1/compliance",
        "/api/v1/insights",
        "/api/v1/agent/runs",
        "/api/v1/agent/runs/{run_id}",
        "/api/v1/agent/runs/{run_id}/events",
        "/api/v1/evidence/{evidence_id}",
        "/api/v1/actions/proposals",
        "/api/v1/actions/proposals/{proposal_id}/decision",
        "/api/v1/actions/proposals/{proposal_id}/execute",
        "/api/v1/actions/proposals/{proposal_id}/audit",
        "/api/v1/audit",
        "/api/v1/evaluations/latest",
    ):
        assert path in paths
    assert "get" in paths["/api/v1/actions/proposals"]
    assert "text/event-stream" not in str(paths)
    assert "post" in paths["/api/v1/actions/proposals/{proposal_id}/execute"]
    assert "AgentRunRequest" in str(paths["/api/v1/agent/runs"]["post"])


def test_write_contracts_require_proposal_hash_or_idempotency_key():
    paths = app.openapi()["paths"]
    proposal_post = paths["/api/v1/actions/proposals"]["post"]
    assert "Idempotency-Key" in str(proposal_post["parameters"])
    decision_schema = paths["/api/v1/actions/proposals/{proposal_id}/decision"]["post"]
    assert "DecisionRequest" in str(decision_schema["requestBody"])
    run_post = paths["/api/v1/agent/runs"]["post"]
    assert "Idempotency-Key" in str(run_post["parameters"])


def test_execution_contract_requires_hash_bound_sandbox_confirmation(monkeypatch):
    from types import SimpleNamespace

    from fleet.actions.schemas import ExecutionRequest, ExecutionResponse
    from fleet.api import main

    proposal_hash = "a" * 64
    fake_context = SimpleNamespace(
        tenant_id=1,
        session=SimpleNamespace(
            scalar=lambda _statement: SimpleNamespace(proposal_hash=proposal_hash)
        ),
    )
    principal = Principal(
        user_id="fixture-operator",
        memberships=(Membership("acme-001", frozenset({"operator"})),),
        active_tenant_id="acme-001",
        auth_method="test",
    )
    called = []
    monkeypatch.setattr(
        main,
        "execute_proposal",
        lambda _context, proposal_id: (
            called.append(proposal_id)
            or ExecutionResponse(
                proposal_id=proposal_id,
                execution_id=f"{proposal_id}:sandbox-v1",
                action_version="sandbox-v1",
                status="EXECUTED",
                simulation_mode="SANDBOX_SIMULATION",
                result={"simulated": True},
            )
        ),
    )
    mismatch = main.post_action_execution(
        7, ExecutionRequest(proposal_hash="b" * 64), principal, fake_context
    )
    success = main.post_action_execution(
        7, ExecutionRequest(proposal_hash=proposal_hash), principal, fake_context
    )
    assert mismatch.status_code == 409
    assert success["simulation_mode"] == "SANDBOX_SIMULATION"
    assert called == [7]


def test_agent_body_rejects_tenant_injection_and_unknown_fields():
    with pytest.raises(ValidationError):
        AgentRunRequest.model_validate({"question": "hello", "tenant_id": "globex-002"})
