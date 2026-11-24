"""Tenant-scoped historical insight loading and evidence persistence."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from fleet.core.identity import RequestContext, authorize
from fleet.db.models import Device, TelemetrySnapshot
from fleet.domain.insights import (
    Insight,
    InsightPolicy,
    InsightRun,
    detect_insights,
    observation_from_snapshot,
)
from fleet.evidence.ledger import capture_manifest, make_pointer, persist_pointer

MAX_INSIGHT_SNAPSHOTS = 10_000
MAX_INSIGHTS_PER_RUN = 200


class InsightDataLimitExceeded(ValueError):
    """Raised instead of returning a silently truncated historical analysis."""


def run_insights(
    context: RequestContext,
    *,
    as_of: datetime | None = None,
    policy: InsightPolicy | None = None,
) -> InsightRun:
    """Compute all supported detectors for the trusted active tenant and persist evidence."""
    if not isinstance(context, RequestContext):
        raise ValueError("trusted RequestContext required")
    authorize(context.principal, context.tenant_key, "read")
    # Roll back all insight manifests/pointers if any source pointer cannot be verified.
    with context.session.begin_nested():
        return _run_insights(context, as_of=as_of, policy=policy)


def _run_insights(
    context: RequestContext,
    *,
    as_of: datetime | None,
    policy: InsightPolicy | None,
) -> InsightRun:
    if not isinstance(context, RequestContext):
        raise ValueError("trusted RequestContext required")
    authorize(context.principal, context.tenant_key, "read")
    cutoff = as_of or context.clock()
    if cutoff.tzinfo is None or cutoff.utcoffset() is None:
        raise ValueError("as_of must be timezone-aware")
    cutoff = cutoff.astimezone(UTC)
    snapshots = tuple(
        context.session.scalars(
            select(TelemetrySnapshot)
            .where(
                TelemetrySnapshot.tenant_id == context.tenant_id,
                TelemetrySnapshot.collected_at <= cutoff,
            )
            .order_by(
                TelemetrySnapshot.device_id.asc(),
                TelemetrySnapshot.collected_at.asc(),
                TelemetrySnapshot.id.asc(),
            )
            .limit(MAX_INSIGHT_SNAPSHOTS + 1)
        ).all()
    )
    if len(snapshots) > MAX_INSIGHT_SNAPSHOTS:
        raise InsightDataLimitExceeded(
            f"Insight range exceeds {MAX_INSIGHT_SNAPSHOTS} snapshot cost cap"
        )
    devices = context.session.scalars(
        select(Device)
        .where(
            Device.tenant_id == context.tenant_id,
            Device.first_seen_at <= cutoff,
        )
        .order_by(Device.device_id.asc())
        .limit(MAX_INSIGHT_SNAPSHOTS + 1)
    ).all()
    if len(devices) > MAX_INSIGHT_SNAPSHOTS:
        raise InsightDataLimitExceeded(
            f"Insight scope exceeds {MAX_INSIGHT_SNAPSHOTS} device cost cap"
        )
    observations = [
        observation_from_snapshot(snapshot, context.tenant_key) for snapshot in snapshots
    ]
    first_seen = {device.device_id: device.first_seen_at for device in devices}
    rules = policy or InsightPolicy()
    insights, insufficient = detect_insights(
        observations,
        tenant=context.tenant_key,
        as_of=cutoff,
        device_last_seen=first_seen,
        policy=rules,
    )
    if len(insights) > MAX_INSIGHTS_PER_RUN:
        raise InsightDataLimitExceeded(
            f"Insight result exceeds {MAX_INSIGHTS_PER_RUN} manifest cost cap"
        )
    snapshots_by_id = {snapshot.id: snapshot for snapshot in snapshots}
    source_hashes = sorted({snapshot.data_sha256 for snapshot in snapshots})
    for insight in insights:
        _persist_insight_evidence(context, insight, snapshots_by_id, cutoff)
    return InsightRun(
        tenant=context.tenant_key,
        as_of=cutoff,
        latest_observed_at=max((item.collected_at for item in observations), default=None),
        policy_version=rules.policy_version,
        total_devices=len(devices),
        insights=insights,
        insufficient_data=insufficient,
        source_data_sha256=source_hashes,
        high_severity_compliance_failures=sum(
            insight.kind == "high_severity_compliance_failure" for insight in insights
        ),
    )


def _persist_insight_evidence(
    context: RequestContext,
    insight: Insight,
    snapshots_by_id: dict[int, TelemetrySnapshot],
    cutoff: datetime,
) -> None:
    support_ids = sorted({reading.snapshot_id for reading in insight.supporting_readings})
    references = tuple(_source_ref(snapshots_by_id[snapshot_id]) for snapshot_id in support_ids)
    manifest = capture_manifest(
        context,
        query_type=f"insight:{insight.kind}",
        filters={
            "device_ids": insight.device_ids,
            "window_start": insight.window_start.isoformat() if insight.window_start else None,
            "window_end": insight.window_end.isoformat() if insight.window_end else None,
        },
        as_of=cutoff,
        matched_refs=references,
        excluded_refs=(),
        numerator=insight.numerator,
        denominator=insight.denominator,
        eligible=insight.coverage.eligible,
        observed=insight.coverage.observed,
        unknown=insight.coverage.unknown,
        policy_version=insight.policy_version,
    )
    evidence_ids: list[str] = []
    for reading in insight.supporting_readings:
        snapshot = snapshots_by_id.get(reading.snapshot_id)
        if snapshot is None:
            raise RuntimeError("insight supporting snapshot disappeared")
        try:
            pointer = persist_pointer(context, make_pointer(snapshot, reading.source_path))
        except (ValueError, IndexError, KeyError, TypeError):
            raise RuntimeError("insight evidence field could not be resolved") from None
        reading.evidence_id = pointer.evidence_id
        evidence_ids.append(pointer.evidence_id)
    insight.evidence_manifest = {
        "manifest_id": manifest.manifest_id,
        "query_fingerprint": manifest.query_fingerprint,
        "source_hash": manifest.source_hash,
        "supporting_snapshot_ids": support_ids,
        "evidence_ids": sorted(set(evidence_ids)),
    }


def _source_ref(snapshot: TelemetrySnapshot):
    from fleet.db.query_repository import _source

    return _source(snapshot)
