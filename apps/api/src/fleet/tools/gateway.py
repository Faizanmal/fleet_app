"""Closed, typed and tenant-scoped tool gateway for direct and LangGraph calls."""

from __future__ import annotations

import logging
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import func, select

from fleet.core.identity import AuthorizationDenied, RequestContext, authorize
from fleet.db.models import ComplianceResult, Employee, InstalledSoftware, TelemetrySnapshot
from fleet.db.query_repository import SnapshotQueryRepository, _view_rows
from fleet.db.repositories import DeviceRepository
from fleet.domain.insights import InsightPolicy
from fleet.domain.query import SnapshotFilters, SourceRowReference
from fleet.evidence.ledger import capture_manifest
from fleet.evidence.ledger import resolve_evidence as resolve_one
from fleet.evidence.models import EvidencePointer
from fleet.insights.engine import InsightDataLimitExceeded, run_insights
from fleet.observability import opaque_tenant_id

log = logging.getLogger(__name__)
MAX_WINDOW = timedelta(days=366)
MAX_HISTORY_POINTS = 500
MAX_TREND_POINTS = 5_000
MAX_CALLS = 8


class ToolError(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: Literal[
        "not_found",
        "insufficient_data",
        "policy_denied",
        "timeout",
        "invalid_input",
        "stale",
        "unavailable",
    ]
    message: str


class Coverage(BaseModel):
    eligible: int = 0
    observed: int = 0
    unknown: int = 0
    fraction: float = 0.0


class PolicyDecision(BaseModel):
    allowed: bool
    policy_version: str
    reason: str


class QueryResult(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    total_count: int = 0
    page: int = 1
    page_size: int = 25
    as_of: datetime | None = None
    data_as_of: datetime | None = None
    coverage: Coverage = Field(default_factory=Coverage)
    evidence_ids: list[str] = Field(default_factory=list)
    evidence_pointers: list[EvidencePointer] = Field(default_factory=list)
    insufficient_data: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    data_sha256: list[str] = Field(default_factory=list)
    policy_version: str = "policy-v1"
    graph_version: str = "not_applicable"
    prompt_version: str = "not_applicable"
    model_version: str = "not_applicable"
    policy_decision: PolicyDecision | None = None
    error: ToolError | None = None


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @model_validator(mode="after")
    def aware_dates(self):
        for value in self.__dict__.values():
            if isinstance(value, datetime) and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError("timestamps must be timezone-aware")
        return self


class ListDevices(Input):
    filters: dict[str, Any] = Field(default_factory=dict)
    as_of: datetime | None = None
    page: int = Field(default=1, ge=1, le=10_000)
    page_size: int = Field(default=25, ge=1, le=100)


class Snapshot(Input):
    device_id: str = Field(min_length=1, max_length=255)
    as_of: datetime | None = None
    fields: list[str] | None = None


class Compliance(Input):
    status: str | None = None
    severity: str | None = None
    check_id: str | None = None
    as_of: datetime | None = None


class Software(Input):
    name: str = Field(min_length=1, max_length=512)
    version_constraint: str | None = Field(default=None, max_length=128)
    as_of: datetime | None = None


class History(Input):
    device_id: str = Field(min_length=1, max_length=255)
    metric: Literal["disk_free_percent", "ram_utilization"]
    start: datetime
    end: datetime
    resolution: Literal["raw", "daily", "weekly"] = "raw"


class Trends(Input):
    metric: Literal["disk_free_percent", "ram_utilization"]
    start: datetime
    end: datetime
    threshold_policy: str = Field(default="fleet-policy-v1", max_length=128)
    min_coverage: float = Field(default=0.7, ge=0, le=1)


class Policy(Input):
    as_of: datetime | None = None
    policy_version: str = Field(default="fleet-policy-v1", max_length=128)


class Resolve(Input):
    evidence_ids: list[str] = Field(min_length=1, max_length=100)

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("duplicate evidence identifiers are not allowed")
        if any(not re.fullmatch(r"ev_[0-9a-f]{64}", value) for value in values):
            raise ValueError("invalid evidence identifier")
        return values


class Precondition(Input):
    action_type: str = Field(min_length=1, max_length=100)
    target_id: str = Field(min_length=1, max_length=255)


class Upgrade(Input):
    device_id: str = Field(min_length=1, max_length=255)
    component: str = Field(min_length=1, max_length=128)
    spec: str = Field(min_length=1, max_length=500)

    @field_validator("spec")
    @classmethod
    def plain_spec(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value):
            raise ValueError("control characters are not allowed")
        return value


class Ticket(Input):
    device_id: str = Field(min_length=1, max_length=255)
    check_id: str = Field(min_length=1, max_length=255)
    note: str = Field(min_length=1, max_length=500)

    @field_validator("note")
    @classmethod
    def plain_note(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value):
            raise ValueError("control characters are not allowed")
        return value


class Replacement(Input):
    device_id: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("reason")
    @classmethod
    def plain_reason(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value):
            raise ValueError("control characters are not allowed")
        return value


class Notify(Input):
    employee_id: str = Field(min_length=1, max_length=255)
    message: str = Field(min_length=1, max_length=500)

    @field_validator("message")
    @classmethod
    def plain_message(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value):
            raise ValueError("control characters are not allowed")
        return value


def _authorize(context: RequestContext) -> None:
    if not isinstance(context, RequestContext):
        raise ValueError("trusted RequestContext required")
    authorize(context.principal, context.tenant_key, "read")


def _now(context: RequestContext | None = None) -> datetime:
    return context.clock() if context else datetime.now(UTC)


def _safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        sensitive = {
            "employee_id",
            "email",
            "user_id",
            "tenant_id",
            "device_id",
            "name",
            "hostname",
            "app_title",
            "software_name",
            "target_id",
            "message",
            "note",
            "spec",
            "reason",
            "access_token",
            "token",
            "secret",
            "password",
            "authorization",
            "api_key",
            "client_secret",
            "credential",
            "headers",
        }
        return {k: _safe(v) for k, v in value.items() if k.casefold() not in sensitive}
    if isinstance(value, (list, tuple)):
        return [_safe(v) for v in value]
    return value


def _redact_args(value: dict[str, Any]) -> dict[str, Any]:
    private = {
        "employee_id",
        "email",
        "user_id",
        "message",
        "note",
        "spec",
        "reason",
        "device_id",
        "name",
        "hostname",
        "app_title",
        "software_name",
        "target_id",
        "access_token",
        "token",
        "secret",
        "password",
        "authorization",
        "api_key",
        "client_secret",
        "credential",
        "headers",
    }
    return {k: "[REDACTED]" if k.casefold() in private else _safe(v) for k, v in value.items()}


def _trace(
    name: str, start: float, ok: bool, ctx: RequestContext, args: dict[str, Any], ids: list[str]
) -> None:
    log.info(
        "tool_call",
        extra={
            "tool": name,
            "duration_ms": round((time.monotonic() - start) * 1000, 2),
            "success": ok,
            "evidence_ids": ids[:100],
            "tenant_run_ref": f"tenant:{opaque_tenant_id(ctx.tenant_key)}/run:{ctx.run_ref}",
            "arguments": _redact_args(args),
        },
    )


def invoke(name: str, context: RequestContext, arguments: dict[str, Any]) -> QueryResult:
    """Invoke one catalogued tool. Unknown names are rejected without interpretation."""
    start = time.monotonic()
    ids: list[str] = []
    ok = False
    catalog = {
        "list_devices": (ListDevices, _list_devices),
        "get_device_snapshot": (Snapshot, _snapshot),
        "query_compliance": (Compliance, _compliance),
        "list_software": (Software, _software),
        "get_device_history": (History, _history),
        "compute_fleet_trends": (Trends, _trends),
        "rank_fleet_insights": (Policy, _insights),
        "resolve_evidence": (Resolve, _resolve),
        "get_policy_thresholds": (Policy, _thresholds),
        "get_action_preconditions": (Precondition, _preconditions),
        "create_upgrade_order": (Upgrade, _proposal),
        "open_remediation_ticket": (Ticket, _proposal),
        "flag_device_for_replacement": (Replacement, _proposal),
        "notify_employee": (Notify, _proposal),
    }
    try:
        if name not in catalog:
            return QueryResult(
                error=ToolError(code="invalid_input", message="Tool is not allowlisted")
            )
        schema, handler = catalog[name]
        data = schema.model_validate(arguments)
        _authorize(context)
        result = handler(context, data)
        # Source-derived strings are always labeled as untrusted telemetry, including
        # software names and compliance text that may contain prompt-like instructions.
        if name not in {"get_policy_thresholds", "get_action_preconditions"}:
            result.items = [
                {**item, "content_classification": "untrusted_telemetry_data"}
                for item in result.items
            ]
        if name == "get_policy_thresholds" and isinstance(data, Policy):
            result.policy_version = data.policy_version
        ok = result.error is None
        ids = result.evidence_ids
        return result
    except ValidationError:
        return QueryResult(
            error=ToolError(code="invalid_input", message="Arguments do not match tool schema")
        )
    except AuthorizationDenied:
        return QueryResult(
            error=ToolError(code="policy_denied", message="Read capability required")
        )
    except TimeoutError:
        return QueryResult(error=ToolError(code="timeout", message="Tool call timed out"))
    except (ValueError, TypeError):
        return QueryResult(
            error=ToolError(code="invalid_input", message="Invalid or unsupported request")
        )
    except Exception:
        log.error("tool_call_failed", extra={"tool": name})
        return QueryResult(error=ToolError(code="unavailable", message="Tool unavailable"))
    finally:
        if isinstance(context, RequestContext):
            _trace(name, start, ok, context, arguments, ids)


def _cutoff(value: datetime | None, context: RequestContext | None = None) -> datetime:
    cutoff = value or _now(context)
    if cutoff.tzinfo is None or cutoff.utcoffset() is None:
        raise ValueError("timezone required")
    return cutoff.astimezone(UTC)


def _list_devices(c: RequestContext, a: ListDevices) -> QueryResult:
    filters = SnapshotFilters.model_validate(
        {**a.filters, "limit": a.page_size, "offset": (a.page - 1) * a.page_size}
    )
    q = SnapshotQueryRepository().get_latest_snapshots(c, _cutoff(a.as_of, c), filters)
    items = [
        {
            "device_id": v.device_id,
            "platform": v.os_platform,
            "product_version": v.product_version,
            "model": v.model,
            "collected_at": v.collected_at,
            "primary_disk_mount": v.primary_disk_mount,
            "disk_free_percent": v.disk_free_percent,
            "ram_utilization": v.ram_utilization,
            "battery_condition": (v.battery or {}).get("condition"),
            "battery_cycle_count": (v.battery or {}).get("cycle_count"),
            "snapshot_id": v.snapshot_id,
        }
        for v in q.items
    ]
    return QueryResult(
        items=items,
        total_count=q.total_count,
        page=a.page,
        page_size=a.page_size,
        as_of=q.as_of,
        data_as_of=q.data_as_of,
        metadata={"manifest_id": getattr(q, "query_manifest_id", None)},
        coverage=Coverage(
            eligible=int(getattr(q, "denominator", 0) or 0),
            observed=int(getattr(q, "denominator", 0) or 0),
            unknown=0,
            fraction=1.0 if getattr(q, "denominator", None) else 0.0,
        ),
        data_sha256=list(q.data_sha256),
        policy_version=q.policy_version,
    )


def _snapshot(c: RequestContext, a: Snapshot) -> QueryResult:
    q = SnapshotQueryRepository().get_latest_snapshots(
        c, _cutoff(a.as_of, c), SnapshotFilters(device_id=a.device_id, limit=1)
    )
    if not q.items:
        return QueryResult(error=ToolError(code="not_found", message="Device not found"))
    v = q.items[0]
    fields = set(
        a.fields
        or [
            "platform",
            "model",
            "product_version",
            "primary_disk_mount",
            "disk_free_percent",
            "ram_utilization",
            "battery",
            "compliance",
            "collected_at",
        ]
    )
    allowed = {
        "platform": v.os_platform,
        "model": v.model,
        "product_version": v.product_version,
        "primary_disk_mount": v.primary_disk_mount,
        "disk_free_percent": v.disk_free_percent,
        "ram_utilization": v.ram_utilization,
        "battery": v.battery,
        "compliance": list(v.compliance),
        "collected_at": v.collected_at,
    }
    if not fields <= allowed.keys():
        raise ValueError("unsupported field")
    return QueryResult(
        items=[
            {
                "device_id": v.device_id,
                "snapshot_id": v.snapshot_id,
                **{f: allowed[f] for f in fields},
            }
        ],
        total_count=1,
        as_of=q.as_of,
        data_as_of=q.data_as_of,
        metadata={"manifest_id": getattr(q, "query_manifest_id", None)},
        coverage=Coverage(eligible=1, observed=1, unknown=0, fraction=1.0),
        data_sha256=list(q.data_sha256),
        policy_version=q.policy_version,
    )


def _compliance(c: RequestContext, a: Compliance) -> QueryResult:
    cutoff = _cutoff(a.as_of, c)
    stmt = (
        select(
            ComplianceResult,
            TelemetrySnapshot.device_id,
            TelemetrySnapshot.collected_at,
            TelemetrySnapshot.data_sha256,
            TelemetrySnapshot.id,
            TelemetrySnapshot.source_path,
            TelemetrySnapshot.source_line_number,
            TelemetrySnapshot.source_row_sha256,
        )
        .join(
            TelemetrySnapshot,
            (TelemetrySnapshot.id == ComplianceResult.snapshot_id)
            & (TelemetrySnapshot.tenant_id == ComplianceResult.tenant_id),
        )
        .where(ComplianceResult.tenant_id == c.tenant_id)
    )
    stmt = stmt.where(TelemetrySnapshot.collected_at <= cutoff)
    rows = c.session.execute(
        stmt.order_by(
            TelemetrySnapshot.device_id, TelemetrySnapshot.collected_at.desc(), ComplianceResult.id
        ).limit(2001)
    ).all()
    if len(rows) > 2000:
        return QueryResult(
            error=ToolError(code="insufficient_data", message="Compliance result cap exceeded")
        )
    selected = [
        row
        for row in rows
        if (a.status is None or row[0].status.casefold() == a.status.casefold())
        and (a.severity is None or row[0].severity.casefold() == a.severity.casefold())
        and (a.check_id is None or row[0].check_id == a.check_id)
    ]

    def source_ref(row: Any) -> SourceRowReference:
        (
            _record,
            device_id,
            collected_at,
            data_hash,
            snapshot_id,
            source_path,
            line_number,
            row_hash,
        ) = row
        return SourceRowReference(
            snapshot_id=snapshot_id,
            device_id=device_id,
            collected_at=collected_at,
            source_path=source_path,
            source_line_number=line_number,
            source_row_sha256=row_hash,
            data_sha256=data_hash,
        )

    matched_by_id = {row[4]: source_ref(row) for row in selected}
    all_by_id = {row[4]: source_ref(row) for row in rows}
    manifest = capture_manifest(
        c,
        query_type="compliance_observations",
        filters={"status": a.status, "severity": a.severity, "check_id": a.check_id},
        as_of=cutoff,
        matched_refs=tuple(matched_by_id[key] for key in sorted(matched_by_id)),
        excluded_refs=tuple(all_by_id[key] for key in sorted(set(all_by_id) - set(matched_by_id))),
        numerator=len(selected),
        denominator=len(rows),
        eligible=len(rows),
        observed=len(rows),
        unknown=0,
        policy_version="policy-v1",
    )
    return QueryResult(
        items=[
            {
                "device_id": d,
                "status": r.status,
                "severity": r.severity,
                "check_id": r.check_id,
                "collected_at": t,
            }
            for r, d, t, _data_hash, *_rest in selected
        ],
        total_count=len(selected),
        as_of=cutoff,
        data_as_of=max((row[2] for row in rows), default=None),
        data_sha256=sorted({row[3] for row in rows}),
        metadata={
            "manifest_id": manifest.manifest_id,
            "coverage_scope": "observed compliance rows",
        },
        coverage=Coverage(
            eligible=len(rows), observed=len(rows), unknown=0, fraction=1.0 if rows else 0.0
        ),
    )


def _software(c: RequestContext, a: Software) -> QueryResult:
    cutoff = _cutoff(a.as_of, c)
    stmt = (
        select(
            InstalledSoftware,
            TelemetrySnapshot.device_id,
            TelemetrySnapshot.collected_at,
            TelemetrySnapshot.data_sha256,
        )
        .join(
            TelemetrySnapshot,
            (TelemetrySnapshot.id == InstalledSoftware.snapshot_id)
            & (TelemetrySnapshot.tenant_id == InstalledSoftware.tenant_id),
        )
        .where(
            InstalledSoftware.tenant_id == c.tenant_id,
            func.lower(InstalledSoftware.name) == a.name.casefold(),
        )
    )
    stmt = stmt.where(TelemetrySnapshot.collected_at <= cutoff)
    if a.version_constraint:
        if not re.fullmatch(r"(==|!=|>=|<=|>|<)\s*[\w.+-]{1,100}", a.version_constraint):
            raise ValueError("invalid version constraint")
        op, ver = re.match(r"(==|!=|>=|<=|>|<)\s*(.*)", a.version_constraint).groups()
        stmt = stmt.where(
            {
                "==": InstalledSoftware.version == ver,
                "!=": InstalledSoftware.version != ver,
                ">=": InstalledSoftware.version >= ver,
                "<=": InstalledSoftware.version <= ver,
                ">": InstalledSoftware.version > ver,
                "<": InstalledSoftware.version < ver,
            }[op]
        )
    rows = c.session.execute(
        stmt.order_by(
            TelemetrySnapshot.device_id,
            TelemetrySnapshot.collected_at.desc(),
            InstalledSoftware.id,
        ).limit(1001)
    ).all()
    if len(rows) > 1000:
        return QueryResult(
            error=ToolError(code="insufficient_data", message="Software result cap exceeded")
        )
    return QueryResult(
        items=[
            {
                "device_id": d,
                "name": r.name,
                "version": r.version,
                "publisher": r.publisher,
                "collected_at": t,
            }
            for r, d, t, _data_hash in rows
        ],
        total_count=len(rows),
        as_of=cutoff,
        data_as_of=max((t for _r, _d, t, _hash in rows), default=None),
        data_sha256=sorted({data_hash for _r, _d, _t, data_hash in rows}),
    )


def _history(c: RequestContext, a: History) -> QueryResult:
    start, end = _cutoff(a.start, c), _cutoff(a.end, c)
    if end < start or end - start > MAX_WINDOW:
        raise ValueError("time range exceeds cap")
    if DeviceRepository().get(c, a.device_id) is None:
        return QueryResult(error=ToolError(code="not_found", message="Device not found"))
    q = SnapshotQueryRepository().get_device_time_window(
        c, a.device_id, start, end, max_points=MAX_HISTORY_POINTS
    )
    reads = list(q.items[0].readings) if q.items else []
    if len(reads) > MAX_HISTORY_POINTS:
        return QueryResult(
            error=ToolError(
                code="insufficient_data", message=f"History exceeds {MAX_HISTORY_POINTS} point cap"
            )
        )
    points = [
        {
            "device_id": r.device_id,
            "collected_at": r.collected_at,
            "value": getattr(r, a.metric),
            "valid": r.validity_mask[a.metric],
        }
        for r in reads
    ]
    if a.resolution != "raw":
        buckets: dict[datetime, list[dict[str, Any]]] = {}
        for point in points:
            stamp = point["collected_at"]
            day = stamp.date()
            if a.resolution == "weekly":
                day = day - timedelta(days=day.weekday())
            bucket = datetime.combine(day, datetime.min.time(), tzinfo=UTC)
            buckets.setdefault(bucket, []).append(point)
        points = [
            {
                "device_id": a.device_id,
                "collected_at": bucket,
                "value": (
                    sum(float(p["value"]) for p in values if p["value"] is not None)
                    / sum(p["value"] is not None for p in values)
                    if any(p["value"] is not None for p in values)
                    else None
                ),
                "valid": any(p["value"] is not None for p in values),
                "count": len(values),
            }
            for bucket, values in sorted(buckets.items())
        ]
    return QueryResult(
        items=points,
        total_count=len(points),
        as_of=end,
        data_as_of=q.data_as_of,
        data_sha256=list(q.data_sha256),
        policy_version=q.policy_version,
    )


def _trends(c: RequestContext, a: Trends) -> QueryResult:
    if a.threshold_policy != "fleet-policy-v1":
        return QueryResult(
            error=ToolError(code="policy_denied", message="Unknown threshold policy")
        )
    start, end = _cutoff(a.start, c), _cutoff(a.end, c)
    if end < start or end - start > MAX_WINDOW:
        raise ValueError("time range exceeds cap")
    snapshots = tuple(
        c.session.scalars(
            select(TelemetrySnapshot)
            .where(
                TelemetrySnapshot.tenant_id == c.tenant_id,
                TelemetrySnapshot.collected_at >= start,
                TelemetrySnapshot.collected_at <= end,
            )
            .order_by(
                TelemetrySnapshot.collected_at.asc(),
                TelemetrySnapshot.device_id.asc(),
                TelemetrySnapshot.id.asc(),
            )
            .limit(MAX_TREND_POINTS + 1)
        ).all()
    )
    if len(snapshots) > MAX_TREND_POINTS:
        return QueryResult(
            error=ToolError(
                code="insufficient_data",
                message=f"Trend range exceeds {MAX_TREND_POINTS} observation cost cap",
            )
        )
    views = _view_rows(c, snapshots)
    values = [(view, getattr(view, a.metric)) for view in views]
    count = sum(value is not None for _, value in values)
    cov = count / max(len(values), 1)
    weekly: dict[datetime, list[float]] = {}
    for view, value in values:
        if value is None:
            continue
        day = view.collected_at.date()
        monday = day - timedelta(days=day.weekday())
        bucket = datetime.combine(monday, datetime.min.time(), tzinfo=UTC)
        weekly.setdefault(bucket, []).append(float(value))
    data_hashes = sorted({view.source.data_sha256 for view in views})
    return QueryResult(
        items=[
            {
                "metric": a.metric,
                "week_start": bucket,
                "observation_count": len(points),
                "mean": sum(points) / len(points),
            }
            for bucket, points in sorted(weekly.items())
        ],
        total_count=len(values),
        as_of=end,
        data_as_of=max((view.collected_at for view in views), default=None),
        data_sha256=data_hashes,
        coverage=Coverage(
            eligible=len(values), observed=count, unknown=len(values) - count, fraction=cov
        ),
        error=(
            ToolError(code="insufficient_data", message="Coverage below requested minimum")
            if not values or cov < a.min_coverage
            else None
        ),
        policy_version=a.threshold_policy,
    )


def _insights(c: RequestContext, a: Policy) -> QueryResult:
    if a.policy_version != "fleet-policy-v1":
        return QueryResult(error=ToolError(code="policy_denied", message="Unknown policy version"))
    try:
        report = run_insights(
            c,
            as_of=a.as_of,
            policy=InsightPolicy(policy_version=a.policy_version),
        )
    except InsightDataLimitExceeded as exc:
        return QueryResult(error=ToolError(code="insufficient_data", message=str(exc)))
    insufficient = [item.model_dump(mode="json") for item in report.insufficient_data]
    return QueryResult(
        items=[insight.model_dump(mode="json") for insight in report.insights],
        insufficient_data=insufficient,
        total_count=len(report.insights),
        as_of=report.as_of,
        data_as_of=report.latest_observed_at,
        data_sha256=report.source_data_sha256,
        policy_version=report.policy_version,
        graph_version=report.graph_version,
        prompt_version=report.prompt_version,
        model_version=report.model_version,
        metadata={
            "tenant": report.tenant,
            "total_devices": report.total_devices,
            "high_severity_compliance_failures": report.high_severity_compliance_failures,
        },
    )


def _resolve(c: RequestContext, a: Resolve) -> QueryResult:
    items = []
    for eid in a.evidence_ids:
        try:
            result = resolve_one(c, eid)
        except (RuntimeError, ValueError):
            return QueryResult(
                error=ToolError(code="stale", message="Evidence changed or failed integrity check")
            )
        if result is None:
            return QueryResult(error=ToolError(code="not_found", message="Evidence not found"))
        items.append(_safe(result))
    pointers = [
        EvidencePointer.model_validate(
            {k: item[k] for k in EvidencePointer.model_fields if k in item}
        )
        for item in items
    ]
    return QueryResult(
        items=items, total_count=len(items), evidence_ids=a.evidence_ids, evidence_pointers=pointers
    )


def _thresholds(c: RequestContext, a: Policy) -> QueryResult:
    if a.policy_version != "fleet-policy-v1":
        return QueryResult(error=ToolError(code="policy_denied", message="Unknown policy version"))
    policy = InsightPolicy(policy_version=a.policy_version)
    values = {
        "persistent_low_storage": {
            "warning_percent_below": str(policy.storage_warning_percent),
            "critical_latest_percent_below": str(policy.storage_critical_percent),
            "minimum_low_readings": policy.storage_min_low_count,
            "window": policy.storage_window,
            "minimum_observed_days": policy.storage_min_observed_days,
        },
        "sustained_ram_pressure": {
            "utilization_at_least": str(policy.ram_threshold),
            "minimum_readings": policy.ram_min_count,
            "window": policy.ram_window,
            "minimum_coverage": policy.ram_min_coverage,
        },
        "os_obsolescence": {
            "macos_minimum_major": policy.macos_min_major,
            "windows_minimum_major": policy.windows_min_major,
        },
        "telemetry_blind_spot": {
            "stale_after_days": policy.telemetry_sla.days,
        },
        "risk_weights": policy.weights,
    }
    return QueryResult(
        items=[{"policy_version": a.policy_version, "thresholds": values}],
        policy_decision=PolicyDecision(
            allowed=True, policy_version=a.policy_version, reason="static fleet policy"
        ),
    )


def _preconditions(c: RequestContext, a: Precondition) -> QueryResult:
    if a.action_type not in {"upgrade", "remediation", "replacement", "notification"}:
        raise ValueError("unknown action type")
    if a.action_type == "notification":
        exists = c.session.scalar(
            select(Employee.employee_id).where(
                Employee.tenant_id == c.tenant_id, Employee.employee_id == a.target_id
            )
        )
    else:
        exists = DeviceRepository().get(c, a.target_id)
    if not exists:
        return QueryResult(error=ToolError(code="not_found", message="Target not found"))
    return QueryResult(
        items=[
            {
                "action_type": a.action_type,
                "target_id": a.target_id,
                "preconditions": [
                    "target exists in active tenant",
                    "evidence is current",
                    "human approval required",
                ],
                "executable": False,
            }
        ],
        policy_decision=PolicyDecision(
            allowed=False,
            policy_version="fleet-policy-v1",
            reason="proposal-only tools; execution unavailable",
        ),
    )


def _proposal(c: RequestContext, a: BaseModel) -> QueryResult:
    authorize(c.principal, c.tenant_key, "draft_proposal")
    if isinstance(a, Notify):
        target = c.session.scalar(
            select(Employee.employee_id).where(
                Employee.tenant_id == c.tenant_id, Employee.employee_id == a.employee_id
            )
        )
    else:
        target = DeviceRepository().get(c, a.device_id)
    if not target:
        return QueryResult(error=ToolError(code="not_found", message="Target not found"))
    if isinstance(a, Ticket):
        found_check = c.session.scalar(
            select(ComplianceResult.id)
            .join(
                TelemetrySnapshot,
                (TelemetrySnapshot.id == ComplianceResult.snapshot_id)
                & (TelemetrySnapshot.tenant_id == ComplianceResult.tenant_id),
            )
            .where(
                ComplianceResult.tenant_id == c.tenant_id,
                TelemetrySnapshot.device_id == a.device_id,
                ComplianceResult.check_id == a.check_id,
            )
            .limit(1)
        )
        if found_check is None:
            return QueryResult(error=ToolError(code="not_found", message="Target check not found"))
    return QueryResult(
        error=ToolError(code="unavailable", message="PROPOSAL_NOT_YET_IMPLEMENTED"),
        policy_decision=PolicyDecision(
            allowed=False,
            policy_version="fleet-policy-v1",
            reason="No external action is performed",
        ),
    )


TOOL_DESCRIPTIONS = {
    "list_devices": "Read latest-per-device inventory with closed filters and stable paging.",
    "get_device_snapshot": "Read one device's latest snapshot and selected allowlisted fields.",
    "query_compliance": "Read compliance observations filtered by status, severity, or check.",
    "list_software": "Find installed software by exact name and simple version comparison.",
    "get_device_history": "Read bounded raw metric observations for one device and time range.",
    "compute_fleet_trends": "Summarize bounded fleet metric coverage over a time interval.",
    "rank_fleet_insights": (
        "Rank deterministic historical findings; heuristic signals and actions are never executed."
    ),
    "resolve_evidence": "Verify tenant-owned pointers; source text remains untrusted data.",
    "get_policy_thresholds": "Read configured fleet threshold values for a policy version.",
    "get_action_preconditions": "Check non-executable prerequisites for a proposed action.",
    "create_upgrade_order": "Draft-only proposal stub; never submits or executes an upgrade order.",
    "open_remediation_ticket": "Draft-only proposal stub; never opens an external ticket.",
    "flag_device_for_replacement": "Draft-only proposal stub; never changes device status.",
    "notify_employee": "Draft-only proposal stub; never sends a message.",
}


def langgraph_tools(context: RequestContext):
    """Return only fixed LangChain tools; context is captured from trusted server state."""
    from langchain_core.tools import StructuredTool

    schemas = {
        "list_devices": ListDevices,
        "get_device_snapshot": Snapshot,
        "query_compliance": Compliance,
        "list_software": Software,
        "get_device_history": History,
        "compute_fleet_trends": Trends,
        "rank_fleet_insights": Policy,
        "resolve_evidence": Resolve,
        "get_policy_thresholds": Policy,
        "get_action_preconditions": Precondition,
        "create_upgrade_order": Upgrade,
        "open_remediation_ticket": Ticket,
        "flag_device_for_replacement": Replacement,
        "notify_employee": Notify,
    }
    calls = {"count": 0}

    def bind(name: str):
        def call(**kwargs):
            if calls["count"] >= MAX_CALLS:
                return QueryResult(
                    error=ToolError(code="policy_denied", message="Tool call budget exhausted")
                ).model_dump(mode="json")
            calls["count"] += 1
            return invoke(name, context, kwargs).model_dump(mode="json")

        return call

    return [
        StructuredTool.from_function(
            name=n, description=TOOL_DESCRIPTIONS[n], args_schema=s, func=bind(n)
        )
        for n, s in schemas.items()
    ]
