"""FastAPI application entry point."""

import hashlib
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from fleet.actions.checkpointer import TenantPostgresSaver
from fleet.actions.schemas import (
    DecisionRequest,
    DecisionResponse,
    ExecutionRequest,
    ExecutionResponse,
    PolicyDecision,
    ProposalRequest,
    ProposalResponse,
)
from fleet.actions.service import (
    ActionConflict,
    ActionNotFound,
    _append_audit,
    create_proposal,
    decide_proposal,
    execute_proposal,
    verify_audit_chain,
)
from fleet.agent.graph import build_agent_graph
from fleet.agent.provider import create_planner
from fleet.agent.replay import replay_run
from fleet.api.auth import require_role
from fleet.api.context import get_tenant_context as get_request_context
from fleet.api.schemas import (
    AgentRunRequest,
    AgentRunResponse,
    ApiEnvelope,
    ApiError,
    ApiErrorEnvelope,
    HealthResponse,
    MeResponse,
    ProposalAuditResponse,
)
from fleet.core.identity import AuthorizationDenied, Principal, RequestContext
from fleet.db.connection import check_database
from fleet.db.models import (
    ActionExecution,
    AgentStepEvent,
    AggregateManifestRecord,
    Approval,
    AuditEvent,
    GraphRun,
    Proposal,
    TelemetrySnapshot,
)
from fleet.evidence.ledger import make_pointer, persist_pointer, resolve_evidence, verify_claim
from fleet.evidence.models import Claim
from fleet.logging_config import configure_logging
from fleet.observability import configure_telemetry, span
from fleet.settings import get_settings
from fleet.tools.gateway import QueryResult
from fleet.tools.gateway import invoke as invoke_tool

logger = logging.getLogger(__name__)
started_at = time.monotonic()


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    configure_telemetry()
    if settings.app_env != "test":
        check_database(settings.database_url)
    logger.info("application_started", extra={"build_version": settings.build_version})
    yield


app = FastAPI(
    title="Rayda Fleet Intelligence API",
    version="0.1.0",
    lifespan=lifespan,
    responses={
        status: {"model": ApiErrorEnvelope, "description": label}
        for status, label in {
            401: "Authentication required",
            403: "Role or policy denied",
            404: "Not found in the active tenant",
            409: "Conflict, stale evidence, or idempotency key reuse",
            413: "Request body exceeds the configured limit",
            422: "Invalid request",
            429: "Rate limited by the deployment gateway",
            503: "Database, model, or service unavailable",
        }.items()
    },
)
cors_origins = [
    origin.strip()
    for origin in os.getenv("API_CORS_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]
if not cors_origins or "*" in cors_origins:
    raise RuntimeError("API_CORS_ORIGINS must be a non-empty exact origin allowlist")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Active-Tenant",
        "Idempotency-Key",
        "X-Request-ID",
    ],
)


class SecurityHeadersMiddleware:
    """Pure ASGI wrapper avoids threadpool/streaming ambiguity from BaseHTTPMiddleware."""

    def __init__(self, application):
        self.application = application

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.application(scope, receive, send)
            return
        scope.setdefault("state", {})["trace_id"] = uuid4().hex
        headers = dict(scope.get("headers", []))
        raw_length = headers.get(b"content-length", b"")
        if raw_length.isdigit() and int(raw_length) > 65_536:
            await self._send_too_large(scope, send)
            return

        total_bytes = 0
        response_started = False

        async def limited_receive():
            nonlocal total_bytes
            message = await receive()
            if message["type"] == "http.request":
                total_bytes += len(message.get("body", b""))
                if total_bytes > 65_536:
                    raise _RequestBodyTooLarge
            return message

        async def send_with_headers(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
                outgoing = list(message.get("headers", []))
                outgoing.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"cache-control", b"no-store"),
                        (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
                        (b"x-request-id", scope["state"]["trace_id"].encode()),
                    ]
                )
                message = {**message, "headers": outgoing}
            await send(message)

        try:
            with span(
                "http.server",
                {
                    "http.request.method": scope.get("method", ""),
                    "fleet.request.id": scope["state"]["trace_id"],
                },
            ) as request_span:

                async def traced_send(message):
                    if message["type"] == "http.response.start":
                        request_span.set_attribute("http.response.status_code", message["status"])
                    await send_with_headers(message)

                await self.application(scope, limited_receive, traced_send)
        except _RequestBodyTooLarge:
            if not response_started:
                await self._send_too_large(scope, send)

    @staticmethod
    async def _send_too_large(scope, send):
        body = (
            b'{"error":{"code":"invalid_input",'
            b'"message":"Request body too large","trace_id":"'
            + scope["state"]["trace_id"].encode()
            + b'"}}'
        )
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"x-request-id", scope["state"]["trace_id"].encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class _RequestBodyTooLarge(Exception):
    pass


app.add_middleware(SecurityHeadersMiddleware)


def _error(status_code: int, code: str, message: str, trace_id: str | None = None):
    return JSONResponse(
        status_code=status_code,
        content={"error": ApiError(code=code, message=message, trace_id=trace_id).model_dump()},
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return _error(422, "invalid_input", "Request validation failed", request.state.trace_id)


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    status_codes = {
        401: ("unauthorized", "Unauthorized"),
        403: ("forbidden", "Forbidden"),
        404: ("not_found", "Not found"),
        409: ("conflict", "Conflict"),
        429: ("rate_limited", "Rate limited"),
    }
    code, message = status_codes.get(exc.status_code, ("unavailable", "Request unavailable"))
    return _error(exc.status_code, code, message, request.state.trace_id)


@app.exception_handler(OperationalError)
async def database_unavailable_handler(request: Request, exc: OperationalError):
    logger.warning("database_unavailable", extra={"request_id": request.state.trace_id})
    return _error(503, "unavailable", "Database unavailable", request.state.trace_id)


@app.exception_handler(IntegrityError)
async def integrity_error_handler(request: Request, exc: IntegrityError):
    return _error(
        409,
        "conflict",
        "Request conflicts with an existing record",
        request.state.trace_id,
    )


@app.exception_handler(_RequestBodyTooLarge)
async def body_too_large_handler(request: Request, exc: _RequestBodyTooLarge):
    return _error(413, "invalid_input", "Request body too large", request.state.trace_id)


@app.exception_handler(SQLAlchemyError)
async def database_error_handler(request: Request, exc: SQLAlchemyError):
    logger.warning(
        "database_request_failed",
        extra={"request_id": request.state.trace_id, "error_type": type(exc).__name__},
    )
    return _error(503, "unavailable", "Database request failed", request.state.trace_id)


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    logger.error(
        "request_failed_safely",
        extra={"request_id": request.state.trace_id, "error_type": type(exc).__name__},
    )
    return _error(503, "unavailable", "Request unavailable", request.state.trace_id)


class EvidencePointerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_id: int = Field(gt=0)
    field_path: str = Field(min_length=2, max_length=512)


class ProposalLookupResponse(BaseModel):
    proposal_id: int
    proposal_hash: str
    status: str
    proposal: dict[str, Any]
    approvals: list[dict[str, Any]]
    execution: dict[str, Any] | None = None


@app.get("/api/v1/health", response_model=HealthResponse)
def health() -> dict[str, Any]:
    settings = get_settings()
    return {
        "status": "ok",
        "uptime_seconds": round(time.monotonic() - started_at, 3),
        "build_version": settings.build_version,
    }


@app.get("/api/v1/ready")
def readiness() -> dict[str, str]:
    """Check the request-role database path and forced RLS before advertising readiness."""
    try:
        check_database(get_settings().database_url)
    except Exception as error:
        logger.warning("readiness_database_unavailable", extra={"error_type": type(error).__name__})
        raise HTTPException(status_code=503, detail="Database is not ready") from None
    return {"status": "ready", "graph": "available"}


@app.get("/api/v1/me", response_model=MeResponse)
async def me(
    principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    active_tenant: str | None = Header(default=None, alias="X-Active-Tenant"),
) -> dict[str, Any]:
    tenant_key = active_tenant or principal.active_tenant_id
    membership = principal.membership_for(tenant_key)
    return {
        "user_id": principal.user_id,
        "active_tenant": tenant_key,
        "roles": sorted(membership.roles) if membership else [],
        "auth_method": principal.auth_method,
        "identity_mode": (
            "development_fixture" if principal.auth_method == "demo_fixture_token" else "external"
        ),
    }


@app.get("/api/v1/fleet/devices/{device_id}", include_in_schema=False)
@app.get("/api/v1/devices/{device_id}", response_model=ApiEnvelope)
def get_device(
    device_id: str,
    request: Request,
    as_of: datetime | None = None,
    fields: list[str] | None = Query(default=None, max_length=50),
    _principal: Principal = Depends(require_role("viewer", "operator", "approver")),
    context: RequestContext = Depends(get_request_context),
) -> dict[str, Any]:
    return _run_tool(
        "get_device_snapshot",
        context,
        {
            "device_id": device_id,
            "as_of": as_of,
            "fields": fields,
        },
        request,
    )


@app.post("/api/v1/evidence/pointers")
def create_evidence_pointer(
    request: EvidencePointerRequest,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
) -> dict[str, Any]:
    snapshot = context.session.scalar(
        select(TelemetrySnapshot).where(
            TelemetrySnapshot.tenant_id == context.tenant_id,
            TelemetrySnapshot.id == request.snapshot_id,
        )
    )
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Not found")
    try:
        pointer = persist_pointer(context, make_pointer(snapshot, request.field_path))
    except (ValueError, IndexError, KeyError, TypeError):
        raise HTTPException(status_code=422, detail="Unsupported evidence field") from None
    _append_audit(
        context,
        event_type="evidence_pointer_created",
        entity_type="evidence",
        entity_id=pointer.evidence_id,
        details={"snapshot_id": snapshot.id, "field_path": request.field_path},
    )
    return pointer.model_dump(mode="json")


@app.get("/api/v1/evidence/{evidence_id}")
def get_evidence(
    evidence_id: str,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
) -> dict[str, Any]:
    result = resolve_evidence(context, evidence_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Not found")
    return result


@app.get("/api/v1/evidence/manifests/{manifest_id}")
def get_evidence_manifest(
    manifest_id: str,
    offset: int = 0,
    limit: int = 100,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
) -> dict[str, Any]:
    if offset < 0 or not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail="Invalid page")
    row = context.session.scalar(
        select(AggregateManifestRecord).where(
            AggregateManifestRecord.tenant_id == context.tenant_id,
            AggregateManifestRecord.manifest_id == manifest_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    manifest = row.manifest_json
    matched = manifest["matched_snapshot_refs"]
    excluded = manifest["excluded_refs"]
    refs = matched + excluded
    return {
        "manifest_id": manifest_id,
        "manifest_hash": row.manifest_hash,
        "query_type": manifest["query_type"],
        "query_fingerprint": manifest["query_fingerprint"],
        "coverage": manifest["coverage"],
        "latest_observed_at": manifest["latest_observed_at"],
        "data_as_of": manifest["as_of"],
        "total_references": len(refs),
        "references": refs[offset : offset + limit],
        "offset": offset,
        "limit": limit,
    }


@app.post("/api/v1/evidence/verify-claim")
def verify_evidence_claim(
    claim: Claim,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
) -> dict[str, Any]:
    try:
        accepted = verify_claim(context, claim)
    except (ValueError, RuntimeError):
        accepted = False
    return {"accepted": accepted, "policy_version": claim.policy_version}


@app.post("/api/v1/actions/proposals", response_model=ProposalResponse)
def post_action_proposal(
    request: ProposalRequest,
    _principal: Principal = Depends(require_role("operator", "admin")),
    context: RequestContext = Depends(get_request_context),
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=8, max_length=128),
):
    try:
        result = create_proposal(context, request, idempotency_key=idempotency_key)
    except ActionNotFound:
        return _error(404, "not_found", "Not found")
    except AuthorizationDenied:
        return _error(403, "forbidden", "Forbidden")
    except ActionConflict as exc:
        return _error(409, "conflict", str(exc))
    if isinstance(result, PolicyDecision):
        return JSONResponse(
            status_code=409,
            content={
                "error": ApiError(code="policy_denied", message=result.message).model_dump(),
                "policy_decision": result.model_dump(mode="json"),
            },
        )
    return result.model_dump(mode="json")


@app.get("/api/v1/actions/proposals", response_model=ApiEnvelope)
def list_action_proposals(
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=25, ge=1, le=100),
    status: str | None = Query(default=None, max_length=32),
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    statement = select(Proposal).where(Proposal.tenant_id == context.tenant_id)
    if status:
        if status not in {
            "DRAFT",
            "PENDING_APPROVAL",
            "APPROVED",
            "EXECUTING",
            "EXECUTED",
            "REJECTED",
            "EXPIRED",
            "BLOCKED",
            "FAILED",
        }:
            raise HTTPException(status_code=422, detail="Invalid proposal status")
        statement = statement.where(Proposal.status == status)
    count = context.session.scalar(select(func.count()).select_from(statement.subquery())) or 0
    rows = context.session.scalars(
        statement.order_by(Proposal.created_at.desc(), Proposal.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {
        "items": [
            {
                "proposal_id": row.id,
                "proposal_hash": row.proposal_hash,
                "status": row.status,
                "proposal": row.proposal_json,
                "created_at": row.created_at,
            }
            for row in rows
        ],
        "total_count": count,
        "page": page,
        "page_size": page_size,
        "coverage": {"eligible": count, "observed": len(rows), "unknown": 0},
        "limitations": ["Proposal list is tenant-scoped; foreign IDs are not enumerable."],
        "data_as_of": max((row.created_at for row in rows if row.created_at), default=None),
        "policy_version": get_settings().policy_version,
    }


@app.get("/api/v1/actions/proposals/{proposal_id}", response_model=ProposalLookupResponse)
def get_action_proposal(
    proposal_id: int,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    proposal = context.session.scalar(
        select(Proposal).where(
            Proposal.tenant_id == context.tenant_id,
            Proposal.id == proposal_id,
        )
    )
    if proposal is None:
        return _error(404, "not_found", "Not found")
    approvals = context.session.scalars(
        select(Approval)
        .where(
            Approval.tenant_id == context.tenant_id,
            Approval.proposal_id == proposal.id,
        )
        .order_by(Approval.id.asc())
    ).all()
    execution = context.session.scalar(
        select(ActionExecution)
        .where(
            ActionExecution.tenant_id == context.tenant_id,
            ActionExecution.proposal_id == proposal.id,
        )
        .order_by(ActionExecution.id.desc())
        .limit(1)
    )
    return {
        "proposal_id": proposal.id,
        "proposal_hash": proposal.proposal_hash,
        "status": proposal.status,
        "proposal": proposal.proposal_json,
        "approvals": [
            {
                "actor_id": approval.approver_id,
                "actor_role": approval.approver_role,
                "decision": approval.decision,
                "proposal_hash": approval.proposal_hash,
                "decided_at": approval.created_at,
            }
            for approval in approvals
        ],
        "execution": (
            {
                "execution_id": execution.execution_id,
                "status": execution.status,
                "action_version": execution.action_version,
                "result": execution.result_json,
            }
            if execution
            else None
        ),
    }


@app.post("/api/v1/actions/proposals/{proposal_id}/decision", response_model=DecisionResponse)
def post_action_decision(
    proposal_id: int,
    request: DecisionRequest,
    _principal: Principal = Depends(require_role("approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    settings = get_settings()
    try:
        result = decide_proposal(
            context,
            proposal_id,
            request,
            separate_requester_approver=settings.separate_requester_approver,
        )
        return result.model_dump(mode="json")
    except ActionNotFound:
        return _error(404, "not_found", "Not found")
    except AuthorizationDenied:
        return _error(403, "forbidden", "Forbidden")
    except ActionConflict as exc:
        return _error(409, "conflict", str(exc))


@app.post("/api/v1/actions/proposals/{proposal_id}/execute", response_model=ExecutionResponse)
def post_action_execution(
    proposal_id: int,
    request: ExecutionRequest,
    _principal: Principal = Depends(require_role("operator", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    """Execute the approved sandbox simulation after an explicit hash confirmation."""
    proposal = context.session.scalar(
        select(Proposal).where(
            Proposal.tenant_id == context.tenant_id,
            Proposal.id == proposal_id,
        )
    )
    if proposal is None:
        return _error(404, "not_found", "Not found")
    if proposal.proposal_hash != request.proposal_hash:
        return _error(409, "conflict", "Proposal hash changed; reload and review the proposal")
    try:
        result = execute_proposal(context, proposal_id)
    except ActionNotFound:
        return _error(404, "not_found", "Not found")
    except AuthorizationDenied:
        return _error(403, "forbidden", "Forbidden")
    except ActionConflict as exc:
        return _error(409, "conflict", str(exc))
    return result.model_dump(mode="json")


@app.get("/api/v1/actions/audit-chain")
def get_action_audit_chain(
    _principal: Principal = Depends(require_role("admin")),
    context: RequestContext = Depends(get_request_context),
):
    result = verify_audit_chain(context).model_dump(mode="json")
    return {
        **result,
        "trace_id": context.run_ref,
        "chain_root": "0" * 64,
        "tamper_detection": (
            "modified or reordered events are checked against the stored tenant head"
        ),
        "independent_signature": False,
    }


def _public_result(result: QueryResult, trace_id: str | None = None) -> dict[str, Any]:
    metadata = result.metadata
    manifest_ids = {metadata["manifest_id"]} if metadata.get("manifest_id") else set()

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "manifest_id" and isinstance(child, str):
                    manifest_ids.add(child)
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(result.items)
    return {
        "items": result.items,
        "total_count": result.total_count,
        "page": result.page,
        "page_size": result.page_size,
        "evidence_ids": result.evidence_ids,
        "manifest_ids": sorted(manifest_ids),
        "coverage": metadata.get("coverage_summary", result.coverage.model_dump(mode="json")),
        "data_as_of": result.data_as_of or result.as_of,
        "freshness": {
            "latest_observed_at": metadata.get("latest_observed_at"),
            "historical": metadata.get("historical", False),
        },
        "limitations": metadata.get("limitations", []),
        "policy_version": result.policy_version,
        "data_sha256": result.data_sha256,
        "graph_version": result.graph_version,
        "prompt_version": result.prompt_version,
        "model_version": result.model_version,
        "trace_id": trace_id or uuid4().hex,
        "error": result.error.model_dump(mode="json") if result.error else None,
    }


def _run_tool(name: str, context: RequestContext, arguments: dict[str, Any], request: Request):
    result = invoke_tool(name, context, arguments)
    if result.error and result.error.code == "not_found":
        raise HTTPException(status_code=404, detail="Not found")
    if result.error and result.error.code == "policy_denied":
        raise HTTPException(status_code=403, detail="Forbidden")
    if result.error and result.error.code == "invalid_input":
        raise HTTPException(status_code=422, detail="Invalid query")
    if not result.metadata.get("limitations"):
        defaults = {
            "list_devices": [
                "Latest observation per device at or before as_of; missing metrics remain unknown."
            ],
            "get_device_snapshot": [
                "Snapshot is the latest observation at or before as_of; missing fields "
                "remain unknown."
            ],
            "query_compliance": [
                "Coverage describes observed compliance rows; missing checks are unknown."
            ],
            "get_device_history": ["History is bounded to the requested metric and time window."],
            "rank_fleet_insights": [
                "Insight severity is heuristic; suggested actions are not executed."
            ],
        }
        result.metadata["limitations"] = defaults.get(name, [])
    return _public_result(result, request.state.trace_id)


@app.get("/api/v1/devices", response_model=ApiEnvelope)
def list_devices_api(
    request: Request,
    platform: str | None = None,
    model: str | None = Query(default=None, max_length=255),
    disk_free_percent_below: float | None = Query(default=None, ge=0, le=100),
    as_of: datetime | None = None,
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=25, ge=1, le=100),
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    filters = {
        key: value
        for key, value in {
            "platform": platform,
            "model": model,
            "disk_free_percent_below": disk_free_percent_below,
        }.items()
        if value is not None
    }
    return _run_tool(
        "list_devices",
        context,
        {
            "filters": filters,
            "as_of": as_of,
            "page": page,
            "page_size": page_size,
        },
        request,
    )


@app.get("/api/v1/devices/{device_id}/history", response_model=ApiEnvelope)
def device_history_api(
    device_id: str,
    request: Request,
    metric: str = Query(..., pattern="^(disk_free_percent|ram_utilization)$"),
    start: datetime = Query(...),
    end: datetime = Query(...),
    resolution: str = Query(default="raw", pattern="^(raw|daily|weekly)$"),
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    return _run_tool(
        "get_device_history",
        context,
        {
            "device_id": device_id,
            "metric": metric,
            "start": start,
            "end": end,
            "resolution": resolution,
        },
        request,
    )


@app.get("/api/v1/compliance", response_model=ApiEnvelope)
def compliance_api(
    request: Request,
    status: str | None = Query(default=None, max_length=128),
    severity: str | None = Query(default=None, max_length=128),
    check_id: str | None = Query(default=None, max_length=255),
    as_of: datetime | None = None,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    return _run_tool(
        "query_compliance",
        context,
        {
            "status": status,
            "severity": severity,
            "check_id": check_id,
            "as_of": as_of,
        },
        request,
    )


@app.get("/api/v1/insights", response_model=ApiEnvelope)
def insights_api(
    request: Request,
    as_of: datetime | None = None,
    policy_version: str = Query(default="fleet-policy-v1", max_length=128),
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    return _run_tool(
        "rank_fleet_insights",
        context,
        {
            "as_of": as_of,
            "policy_version": policy_version,
        },
        request,
    )


@app.get("/api/v1/fleet/summary", response_model=ApiEnvelope)
def fleet_summary_api(
    request: Request,
    as_of: datetime | None = None,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    inventory = invoke_tool("list_devices", context, {"as_of": as_of, "page": 1, "page_size": 100})
    compliance = invoke_tool(
        "query_compliance", context, {"as_of": as_of, "status": "fail", "severity": "high"}
    )
    insights = invoke_tool(
        "rank_fleet_insights", context, {"as_of": as_of, "policy_version": "fleet-policy-v1"}
    )
    result = QueryResult(
        items=[
            {
                "inventory_count": inventory.total_count,
                "observed_high_severity_fail_count": compliance.total_count,
                "insight_count": insights.total_count,
                "inventory": inventory.items,
                "insights": insights.items,
            }
        ],
        total_count=1,
        as_of=as_of,
        data_as_of=max(
            (
                value
                for value in (inventory.data_as_of, compliance.data_as_of, insights.data_as_of)
                if value
            ),
            default=None,
        ),
        coverage=inventory.coverage,
        evidence_ids=sorted(
            set(inventory.evidence_ids + compliance.evidence_ids + insights.evidence_ids)
        ),
        metadata={
            "manifest_id": inventory.metadata.get("manifest_id"),
            "limitations": [
                "High-severity failures count only observed compliance rows; missing checks "
                "are unknown.",
                "Insight severity is heuristic and suggested actions are not executed.",
            ],
            "coverage_summary": {
                "inventory": inventory.coverage.model_dump(mode="json"),
                "observed_high_severity_compliance": compliance.coverage.model_dump(mode="json"),
                "insights": insights.coverage.model_dump(mode="json"),
            },
        },
        data_sha256=sorted(
            set(inventory.data_sha256 + compliance.data_sha256 + insights.data_sha256)
        ),
        policy_version="fleet-policy-v1",
    )
    return _public_result(result, request.state.trace_id)


@app.post("/api/v1/agent/runs", response_model=AgentRunResponse)
def create_agent_run(
    body: AgentRunRequest,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
    idempotency_key: str = Header(..., alias="Idempotency-Key", min_length=8, max_length=128),
):
    if any(ord(char) < 33 for char in idempotency_key):
        raise HTTPException(status_code=422, detail="Invalid idempotency key")
    # Derive a tenant/principal-bound opaque run reference from the key. Existing
    # keys are rejected rather than rerunning a write and duplicating its trace.
    public_run_id = hashlib.sha256(
        f"{context.tenant_id}:{context.principal.user_id}:{idempotency_key}".encode()
    ).hexdigest()
    existing = context.session.scalar(
        select(GraphRun).where(
            GraphRun.tenant_id == context.tenant_id,
            GraphRun.user_id == context.principal.user_id,
            GraphRun.trace_id == public_run_id,
        )
    )
    if existing:
        raise HTTPException(status_code=409, detail="Idempotency key already used")
    planner = create_planner(get_settings())
    session = build_agent_graph(context, planner, checkpointer=TenantPostgresSaver(context))
    result = session.invoke(
        body.question,
        conversation_id=body.conversation_id,
        input_history=body.input_history,
        trace_id=public_run_id,
    )
    if result.get("errors") and result["errors"][0].get("code") == "unavailable":
        raise HTTPException(status_code=503, detail="Agent run unavailable")
    if not result.get("run_id"):
        raise HTTPException(status_code=503, detail="Agent run did not complete safely")
    run = context.session.scalar(
        select(GraphRun).where(
            GraphRun.tenant_id == context.tenant_id,
            GraphRun.trace_id == result["run_id"],
        )
    )
    if run is None:
        result["trace_persisted"] = False
        if (
            "Trace persistence was unavailable; this read-only run is not retrievable later."
            not in result["limitations"]
        ):
            result["limitations"].append(
                "Trace persistence was unavailable; this read-only run is not retrievable later."
            )
        return result
    # Bind the derived public reference to the stored trace for safe retry detection.
    run.trace_id = public_run_id
    result["run_id"] = public_run_id
    result["trace_id"] = public_run_id
    return result


@app.get("/api/v1/agent/runs/{run_id}")
def get_agent_run(
    run_id: str,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    run_query = select(GraphRun).where(
        GraphRun.tenant_id == context.tenant_id,
        GraphRun.trace_id == run_id,
    )
    if "admin" not in context.principal.roles:
        run_query = run_query.where(GraphRun.user_id == context.principal.user_id)
    run = context.session.scalar(run_query)
    if run is None:
        raise HTTPException(status_code=404, detail="Not found")
    audit = context.session.scalar(
        select(AuditEvent).where(
            AuditEvent.tenant_id == context.tenant_id,
            AuditEvent.run_id == run.id,
            AuditEvent.event_type == "agent_run_trace",
        )
    )
    step_events = context.session.scalars(
        select(AgentStepEvent)
        .where(AgentStepEvent.tenant_id == context.tenant_id, AgentStepEvent.run_id == run.id)
        .order_by(AgentStepEvent.step_index)
    ).all()
    return {
        "run_id": run_id,
        "status": "completed",
        "operations": audit.details_json.get("operations", []) if audit else [],
        "step_events": [
            {
                "step_index": item.step_index,
                "node": item.node,
                "event": item.event_json,
                "previous_hash": item.previous_hash,
                "event_hash": item.event_hash,
                "elapsed_ms": item.elapsed_ms,
            }
            for item in step_events
        ],
        "replay_available": bool(step_events),
        "evidence_ids": audit.details_json.get("evidence_ids", []) if audit else [],
        "manifest_ids": audit.details_json.get("evidence_manifest_ids", []) if audit else [],
        "coverage": audit.details_json.get("coverage", []) if audit else [],
        "data_as_of": audit.details_json.get("data_as_of") if audit else None,
        "freshness": (
            audit.details_json.get("freshness", {"classification": "unknown"})
            if audit
            else {"classification": "unknown"}
        ),
        "limitations": (
            (audit.details_json.get("limitations", []) if audit else [])
            + ["Run output is a sanitized operation trace; no private reasoning is stored."]
        ),
        "trace_id": run_id,
        "data_sha256": run.data_sha256,
        "policy_version": run.policy_version,
        "graph_version": run.graph_version,
        "prompt_version": run.prompt_version,
        "model_version": run.model_version,
    }


@app.get("/api/v1/agent/runs/{run_id}/events")
def get_agent_run_events(
    run_id: str,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    # JSON polling is deliberate: this synchronous run path does not yet have a
    # durable event cursor suitable for reliable SSE reconnect semantics.
    snapshot = get_agent_run(run_id, _principal, context)
    return {
        "run_id": run_id,
        "status": snapshot["status"],
        "events": snapshot["step_events"],
        "operations": snapshot["operations"],
        "poll_after_seconds": 2,
        "streaming": False,
    }


@app.get("/api/v1/agent/runs/{run_id}/replay")
def replay_agent_run(
    run_id: str,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    try:
        return replay_run(context, run_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Not found") from None


@app.get("/api/v1/observability/summary")
def observability_summary(
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    """Return sampled, tenant-scoped metrics without identifiers or source strings."""
    since = datetime.now(UTC) - timedelta(days=7)
    events = context.session.scalars(
        select(AgentStepEvent.event_json)
        .where(
            AgentStepEvent.tenant_id == context.tenant_id,
            AgentStepEvent.created_at >= since,
        )
        .order_by(AgentStepEvent.created_at.desc())
        .limit(10_000)
    ).all()
    audit_types = context.session.scalars(
        select(AuditEvent.event_type)
        .where(AuditEvent.tenant_id == context.tenant_id, AuditEvent.created_at >= since)
        .limit(10_000)
    ).all()
    action_rows = context.session.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.tenant_id == context.tenant_id,
            AuditEvent.created_at >= since,
            AuditEvent.event_type.in_(
                {
                    "proposal_approved",
                    "proposal_rejected",
                    "execution_started",
                    "execution_succeeded",
                    "execution_failed",
                    "execution_idempotent_replay",
                }
            ),
        )
        .order_by(AuditEvent.id.desc())
        .limit(50)
    ).all()
    tools = [event for event in events if event.get("node") == "tool"]
    plans = [event for event in events if event.get("node") == "plan"]
    assessments = [event for event in events if event.get("node") == "assessment"]
    run_ids = {event.get("trace_id") for event in events if event.get("trace_id")}
    tool_names: dict[str, int] = {}
    for event in tools:
        name = event.get("tool_name", "unknown")
        tool_names[name] = tool_names.get(name, 0) + 1
    latest = context.session.scalar(
        select(func.max(TelemetrySnapshot.collected_at)).where(
            TelemetrySnapshot.tenant_id == context.tenant_id
        )
    )
    report_path = Path(__file__).resolve().parents[5] / "reports" / "eval_security.json"
    test_rate = None
    test_report_status = None
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            suite = report["suite"]
            total = suite["passed"] + suite["failed"] + suite["skipped"]
            test_rate = suite["passed"] / total if total else None
            test_report_status = report.get("release_gate_status")
        except (OSError, KeyError, ValueError, TypeError):
            test_rate = None
    now = datetime.now(UTC)
    return {
        "trace_id": context.run_ref,
        "window_days": 7,
        "sampled": True,
        "sample_limit": 10_000,
        "metrics": {
            "query_count": len(tools),
            "precision": _latest_eval_metric("claim_support_precision"),
            "refusal_ratio": (
                sum(e.get("decision") == "abstained" for e in assessments) / len(assessments)
                if assessments
                else None
            ),
            "tools_per_question": len(tools) / len(run_ids) if run_ids else None,
            "tool_counts": tool_names,
            "graph_loop_iterations": sum(int(e.get("iteration", 0)) for e in plans),
            "policy_denials": sum(e.get("decision") == "policy_denied" for e in events),
            "approval_count": audit_types.count("proposal_approved"),
            "execution_count": audit_types.count("execution_succeeded"),
            "execution_idempotent_replays": audit_types.count("execution_idempotent_replay"),
            "latest_observation_age_hours": (
                (now - latest).total_seconds() / 3600 if latest else None
            ),
            "test_pass_rate": test_rate,
        },
        "recent_action_traces": [
            {
                "event_type": row.event_type,
                "proposal_id": row.entity_id,
                "trace_id": row.details_json.get("trace_id"),
                "created_at": row.created_at,
                "execution_id": row.details_json.get("execution_id"),
                "simulation_label": (
                    "SANDBOX_SIMULATION"
                    if row.event_type
                    in {"execution_started", "execution_succeeded", "execution_failed"}
                    else None
                ),
            }
            for row in action_rows
        ],
        "test_report": report_path.name if report_path.is_file() else None,
        "test_gate_status": test_report_status,
        "limitations": [
            "Runtime counts include recorded agent graph steps in this tenant only; read-only "
            "non-agent API queries are not counted.",
            "A null ratio means no denominator was observed in this window.",
            "Execution attempts rolled back with a failed transaction are absent from committed "
            "audit rows.",
        ],
    }


def _latest_eval_metric(name: str):
    path = Path(__file__).resolve().parents[5] / "reports" / "eval_security.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))["metrics"][name].get("value")
    except (OSError, KeyError, ValueError, TypeError):
        return None


@app.get("/api/v1/actions/proposals/{proposal_id}/audit", response_model=ProposalAuditResponse)
def get_proposal_audit(
    proposal_id: int,
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    proposal = context.session.scalar(
        select(Proposal).where(
            Proposal.tenant_id == context.tenant_id,
            Proposal.id == proposal_id,
        )
    )
    if proposal is None:
        raise HTTPException(status_code=404, detail="Not found")
    events = context.session.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.tenant_id == context.tenant_id,
            AuditEvent.entity_type == "proposal",
            AuditEvent.entity_id == str(proposal_id),
        )
        .order_by(AuditEvent.id)
    ).all()
    return {
        "proposal_id": proposal_id,
        "proposal_hash": proposal.proposal_hash,
        "status": proposal.status,
        "trace_id": context.run_ref,
        "events": [
            {
                "event_type": event.event_type,
                "created_at": event.created_at,
                "details": event.details_json,
                "event_hash": event.event_hash,
            }
            for event in events
        ],
    }


@app.get("/api/v1/audit")
def list_audit_events(
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=25, ge=1, le=100),
    _principal: Principal = Depends(require_role("admin")),
    context: RequestContext = Depends(get_request_context),
):
    rows = context.session.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.tenant_id == context.tenant_id,
        )
        .order_by(AuditEvent.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {
        "items": [
            {
                "event_id": row.id,
                "run_id": row.run_id,
                "event_type": row.event_type,
                "entity_type": row.entity_type,
                "entity_id": row.entity_id,
                "details": row.details_json,
                "created_at": row.created_at,
                "event_hash": row.event_hash,
            }
            for row in rows
        ],
        "page": page,
        "page_size": page_size,
    }


@app.get("/api/v1/evaluations/latest")
def latest_evaluation(
    _principal: Principal = Depends(require_role("viewer", "operator", "approver", "admin")),
    context: RequestContext = Depends(get_request_context),
):
    # This is a checked-in deterministic oracle, not a claim that live DB evaluation ran.
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[5] / "evals" / "golden" / "phase04_query_oracles.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="No evaluation report")
    raw = json.loads(path.read_text(encoding="utf-8"))
    tenant_key = context.tenant_key
    filtered = {
        "data_sha256": raw["data_sha256"],
        "data_as_of": raw["data_as_of_by_tenant"].get(tenant_key),
        "latest_inventory_count": raw["latest_inventory_by_tenant"].get(tenant_key),
        "older_macos_devices": raw["latest_macos_major_below_15"]["devices_by_tenant"].get(
            tenant_key, []
        ),
    }
    if tenant_key == "acme-001":
        filtered.update(
            {
                "primary_disk_free_below_20_percent": raw[
                    "acme_primary_disk_free_below_20_percent"
                ],
                "battery_service_recommended": raw["acme_battery_service_recommended"],
                "screen_lock_failures": raw["acme_screen_lock_failures"],
            }
        )
    return {
        "status": "checked_in_oracle",
        "tenant": tenant_key,
        "limitations": [
            "This is a source-derived offline oracle, not live database evaluation.",
            "Cross-tenant aggregate findings are omitted from this tenant-scoped response.",
        ],
        "result": filtered,
    }
