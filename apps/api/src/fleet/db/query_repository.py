"""PostgreSQL deterministic query implementations, always constrained to RequestContext."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import Numeric, and_, case, cast, func, or_, select

from fleet.core.identity import MissingRequestContext, RequestContext
from fleet.db.models import ComplianceResult, DiskVolume, TelemetrySnapshot
from fleet.domain.metrics import (
    evaluate_threshold,
    is_primary_mount,
    primary_disk_free_percent,
    ram_utilization,
)
from fleet.domain.query import (
    DeviceReading,
    DeviceTimeWindow,
    QueryResult,
    QueryScope,
    SnapshotFilters,
    SnapshotView,
    SourceRowReference,
    ThresholdCoverage,
    ThresholdSpec,
    normalize_as_of,
)
from fleet.evidence.ledger import capture_manifest
from fleet.ingest.schemas import normalize_device_id, normalize_tenant_or_employee_id


def _require_context(context: RequestContext) -> None:
    if not isinstance(context, RequestContext):
        raise MissingRequestContext("A trusted RequestContext is required")


def _source(snapshot: TelemetrySnapshot) -> SourceRowReference:
    return SourceRowReference(
        snapshot_id=snapshot.id,
        device_id=snapshot.device_id,
        collected_at=snapshot.collected_at,
        source_path=snapshot.source_path,
        source_line_number=snapshot.source_line_number,
        source_row_sha256=snapshot.source_row_sha256,
        data_sha256=snapshot.data_sha256,
    )


def _json_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def _model_name(snapshot: TelemetrySnapshot) -> str | None:
    value = snapshot.device_identity_json.get("model_name")
    return value if isinstance(value, str) else None


def _product_version(snapshot: TelemetrySnapshot) -> str | None:
    value = snapshot.os_json.get("product_version")
    return value if isinstance(value, str) else None


def _primary_mount_condition(snapshot: TelemetrySnapshot):
    mount = func.trim(DiskVolume.mount_point)
    windows_mount = func.upper(func.rtrim(func.replace(mount, "/", "\\"), "\\"))
    return or_(
        and_(snapshot.os_platform.in_(("darwin", "macos")), mount == "/"),
        and_(snapshot.os_platform.in_(("win32", "windows")), windows_mount == "C:"),
    )


def _disk_percent_expression(snapshot: TelemetrySnapshot):
    raw_percent = func.round(
        cast(DiskVolume.available_bytes, Numeric) * 100 / cast(DiskVolume.size_bytes, Numeric),
        2,
    )
    return (
        select(
            case(
                (func.count(DiskVolume.id) == 1, func.max(raw_percent)),
                else_=None,
            )
        )
        .where(
            DiskVolume.tenant_id == snapshot.tenant_id,
            DiskVolume.snapshot_id == snapshot.id,
            _primary_mount_condition(snapshot),
        )
        .correlate(snapshot)
        .scalar_subquery()
    )


def _ram_ratio_expression(snapshot: TelemetrySnapshot):
    memory = snapshot.memory_json
    used = cast(memory["used_memory_bytes"].as_string(), Numeric)
    total = cast(memory["total_memory_bytes"].as_string(), Numeric)
    return case((and_(total > 0, used >= 0, used <= total), used / total), else_=None)


def _version_major_expression(snapshot: TelemetrySnapshot):
    version = snapshot.os_json["product_version"].as_string()
    extracted = func.substring(version, r"^\s*(\d+)(?:\.|$)")
    return case(
        (
            and_(snapshot.os_platform.in_(("darwin", "macos")), version.op("~")(r"^\s*\d+")),
            cast(extracted, Numeric),
        ),
        else_=None,
    )


def _base_latest_query(context: RequestContext, as_of: datetime):
    ranked = (
        select(
            TelemetrySnapshot.id.label("snapshot_id"),
            TelemetrySnapshot.tenant_id.label("tenant_id"),
            TelemetrySnapshot.device_id.label("device_id"),
            TelemetrySnapshot.collected_at.label("collected_at"),
            func.row_number()
            .over(
                partition_by=(TelemetrySnapshot.tenant_id, TelemetrySnapshot.device_id),
                order_by=(TelemetrySnapshot.collected_at.desc(), TelemetrySnapshot.id.desc()),
            )
            .label("row_number"),
        )
        .where(
            TelemetrySnapshot.tenant_id == context.tenant_id,
            TelemetrySnapshot.collected_at <= as_of,
        )
        .cte("ranked_snapshots")
    )
    return (
        select(TelemetrySnapshot)
        .join(ranked, ranked.c.snapshot_id == TelemetrySnapshot.id)
        .where(
            ranked.c.row_number == 1,
            TelemetrySnapshot.tenant_id == context.tenant_id,
        )
    )


def _apply_filters(query, context: RequestContext, filters: SnapshotFilters):
    snapshot = TelemetrySnapshot
    if filters.platform:
        query = query.where(snapshot.os_platform == filters.platform)
    if filters.device_id:
        query = query.where(snapshot.device_id == normalize_device_id(filters.device_id))
    if filters.model:
        query = query.where(
            func.lower(snapshot.device_identity_json["model_name"].as_string())
            == filters.model.casefold()
        )
    if filters.employee_id:
        query = query.where(
            snapshot.employee_id == normalize_tenant_or_employee_id(filters.employee_id)
        )
    if filters.collected_at:
        start, end = filters.collected_at
        if start:
            query = query.where(snapshot.collected_at >= start)
        if end:
            query = query.where(snapshot.collected_at <= end)
    if filters.os_major:
        major = _version_major_expression(snapshot)
        if filters.os_major.minimum is not None:
            query = query.where(major >= filters.os_major.minimum)
        if filters.os_major.maximum is not None:
            query = query.where(major <= filters.os_major.maximum)

    if filters.disk_free_percent:
        disk = _disk_percent_expression(snapshot)
        if filters.disk_free_percent.minimum is not None:
            query = query.where(disk >= filters.disk_free_percent.minimum)
        if filters.disk_free_percent.maximum is not None:
            query = query.where(disk <= filters.disk_free_percent.maximum)
    if filters.disk_free_percent_below is not None:
        query = query.where(_disk_percent_expression(snapshot) < filters.disk_free_percent_below)
    if filters.disk_free_percent_above is not None:
        query = query.where(_disk_percent_expression(snapshot) > filters.disk_free_percent_above)
    if filters.ram_utilization:
        ram = _ram_ratio_expression(snapshot)
        if filters.ram_utilization.minimum is not None:
            query = query.where(ram >= filters.ram_utilization.minimum)
        if filters.ram_utilization.maximum is not None:
            query = query.where(ram <= filters.ram_utilization.maximum)

    if any(
        value is not None
        for value in (
            filters.compliance_status,
            filters.compliance_severity,
            filters.compliance_check,
        )
    ):
        compliance = select(ComplianceResult.id).where(
            ComplianceResult.tenant_id == context.tenant_id,
            ComplianceResult.tenant_id == snapshot.tenant_id,
            ComplianceResult.snapshot_id == snapshot.id,
        )
        if filters.compliance_status is not None:
            compliance = compliance.where(
                func.lower(ComplianceResult.status) == filters.compliance_status.casefold()
            )
        if filters.compliance_severity is not None:
            compliance = compliance.where(
                func.lower(ComplianceResult.severity) == filters.compliance_severity.casefold()
            )
        if filters.compliance_check is not None:
            compliance = compliance.where(
                func.lower(ComplianceResult.check_id) == filters.compliance_check.casefold()
            )
        query = query.where(compliance.exists())
    return query


def _ordering(query, filters: SnapshotFilters):
    expressions = {
        "device_id": TelemetrySnapshot.device_id,
        "collected_at": TelemetrySnapshot.collected_at,
        "platform": TelemetrySnapshot.os_platform,
        "model": func.lower(TelemetrySnapshot.device_identity_json["model_name"].as_string()),
        "employee_id": TelemetrySnapshot.employee_id,
        "disk_free_percent": _disk_percent_expression(TelemetrySnapshot),
        "ram_utilization": _ram_ratio_expression(TelemetrySnapshot),
    }
    first = expressions[filters.sort_by]
    first = first.desc() if filters.sort_direction == "desc" else first.asc()
    return query.order_by(first, TelemetrySnapshot.device_id.asc(), TelemetrySnapshot.id.asc())


def _view_rows(
    context: RequestContext, snapshots: Sequence[TelemetrySnapshot]
) -> tuple[SnapshotView, ...]:
    if not snapshots:
        return ()
    snapshot_ids = [snapshot.id for snapshot in snapshots]
    tenant_id = context.tenant_id
    volumes: dict[int, list[DiskVolume]] = defaultdict(list)
    for volume in context.session.scalars(
        select(DiskVolume).where(
            DiskVolume.tenant_id == tenant_id,
            DiskVolume.snapshot_id.in_(snapshot_ids),
        )
    ):
        volumes[volume.snapshot_id].append(volume)
    compliances: dict[int, list[ComplianceResult]] = defaultdict(list)
    for result in context.session.scalars(
        select(ComplianceResult).where(
            ComplianceResult.tenant_id == tenant_id,
            ComplianceResult.snapshot_id.in_(snapshot_ids),
        )
    ):
        compliances[result.snapshot_id].append(result)
    result_views = []
    for snapshot in snapshots:
        primary = next(
            (
                volume
                for volume in volumes[snapshot.id]
                if is_primary_mount(snapshot.os_platform, volume.mount_point)
            ),
            None,
        )
        primary_metric = primary_disk_free_percent(snapshot.os_platform, volumes[snapshot.id])
        used = _json_int(snapshot.memory_json.get("used_memory_bytes"))
        total = _json_int(snapshot.memory_json.get("total_memory_bytes"))
        ram_metric = ram_utilization(used, total)
        result_views.append(
            SnapshotView(
                snapshot_id=snapshot.id,
                tenant_id=snapshot.tenant_id,
                device_id=snapshot.device_id,
                employee_id=snapshot.employee_id,
                collected_at=snapshot.collected_at,
                os_platform=snapshot.os_platform,
                os_product_name=snapshot.os_product_name,
                product_version=_product_version(snapshot),
                model=_model_name(snapshot),
                primary_disk_mount=primary.mount_point if primary else None,
                primary_disk_available_bytes=primary.available_bytes if primary else None,
                primary_disk_size_bytes=primary.size_bytes if primary else None,
                disk_free_percent=primary_metric.value,
                disk_free_valid=primary_metric.valid,
                disk_free_exclusion_reason=primary_metric.reason,
                used_memory_bytes=used,
                total_memory_bytes=total,
                ram_utilization=ram_metric.value,
                ram_valid=ram_metric.valid,
                ram_exclusion_reason=ram_metric.reason,
                battery=snapshot.battery_json,
                compliance=tuple(
                    {"check_id": c.check_id, "status": c.status, "severity": c.severity}
                    for c in compliances[snapshot.id]
                ),
                source=_source(snapshot),
            )
        )
    return tuple(result_views)


class SnapshotQueryRepository:
    def get_latest_snapshots(
        self,
        context: RequestContext,
        as_of: datetime,
        filters: SnapshotFilters | None = None,
        *,
        policy_version: str = "policy-v1",
        policy_threshold_source: str | None = None,
    ) -> QueryResult[SnapshotView]:
        _require_context(context)
        cutoff = normalize_as_of(as_of)
        selected_filters = filters or SnapshotFilters()
        latest_query = _base_latest_query(context, cutoff)
        scope_total = (
            context.session.scalar(
                select(func.count()).select_from(latest_query.order_by(None).subquery())
            )
            or 0
        )
        latest_scope = latest_query.order_by(None).subquery()
        data_as_of = context.session.scalar(
            select(func.max(latest_scope.c.collected_at)).select_from(latest_scope)
        )
        filtered = _apply_filters(latest_query, context, selected_filters)
        total_count = int(
            context.session.scalar(
                select(func.count()).select_from(filtered.order_by(None).subquery())
            )
            or 0
        )
        ordered = (
            _ordering(filtered, selected_filters)
            .limit(selected_filters.limit)
            .offset(selected_filters.offset)
        )
        snapshots = tuple(context.session.scalars(ordered).all())
        views = _view_rows(context, snapshots)
        refs = tuple(view.source for view in views)
        eligible_snapshots = tuple(context.session.scalars(latest_query.order_by(None)).all())
        eligible_views = _view_rows(context, eligible_snapshots)
        # Let SQL define matches instead of duplicating its filters in Python.
        all_matched = tuple(context.session.scalars(filtered.order_by(None)).all())
        matched_ids = {snapshot.id for snapshot in all_matched}
        eligible_by_id = {view.snapshot_id: view for view in eligible_views}
        all_refs = {view.snapshot_id: view.source for view in eligible_views}
        matched_refs = tuple(all_refs[snapshot_id] for snapshot_id in sorted(matched_ids))
        excluded_refs = tuple(
            all_refs[snapshot_id] for snapshot_id in sorted(set(all_refs) - matched_ids)
        )
        unknown_count = sum(
            (
                selected_filters.disk_free_percent is not None
                or selected_filters.disk_free_percent_below is not None
            )
            and not eligible_by_id[snapshot_id].disk_free_valid
            or selected_filters.ram_utilization is not None
            and not eligible_by_id[snapshot_id].ram_valid
            for snapshot_id in all_refs
            if snapshot_id not in matched_ids
        )
        manifest = capture_manifest(
            context,
            query_type="latest_snapshots",
            filters=selected_filters.model_dump(mode="json"),
            as_of=cutoff,
            matched_refs=matched_refs,
            excluded_refs=excluded_refs,
            numerator=total_count,
            denominator=int(scope_total),
            eligible=int(scope_total),
            observed=len(eligible_snapshots),
            unknown=int(unknown_count),
            policy_version=policy_version,
        )
        data_hashes = tuple(sorted({ref.data_sha256 for ref in refs}))
        return QueryResult(
            items=views,
            scope=QueryScope(context.tenant_id, context.tenant_key),
            filters=selected_filters.model_dump(mode="json"),
            numerator=total_count,
            denominator=int(scope_total),
            excluded_count=max(int(scope_total) - total_count, 0),
            as_of=cutoff,
            data_as_of=data_as_of,
            policy_threshold_source=policy_threshold_source,
            source_row_references=refs,
            data_sha256=data_hashes,
            policy_version=policy_version,
            total_count=total_count,
            query_manifest_id=manifest.manifest_id,
        )

    def get_device_time_window(
        self,
        context: RequestContext,
        device_id: str,
        start: datetime,
        end: datetime,
        thresholds: Sequence[ThresholdSpec] = (),
        *,
        policy_version: str = "policy-v1",
        max_points: int | None = None,
    ) -> QueryResult[DeviceTimeWindow]:
        _require_context(context)
        start_utc, end_utc = normalize_as_of(start), normalize_as_of(end)
        if start_utc > end_utc:
            raise ValueError("time window start must not exceed end")
        snapshot_query = (
            select(TelemetrySnapshot)
            .where(
                TelemetrySnapshot.tenant_id == context.tenant_id,
                TelemetrySnapshot.device_id == device_id,
                TelemetrySnapshot.collected_at >= start_utc,
                TelemetrySnapshot.collected_at <= end_utc,
            )
            .order_by(TelemetrySnapshot.collected_at.asc(), TelemetrySnapshot.id.asc())
        )
        if max_points is not None:
            if max_points < 1:
                raise ValueError("max_points must be positive")
            snapshot_query = snapshot_query.limit(max_points + 1)
        snapshots = tuple(context.session.scalars(snapshot_query).all())
        views = _view_rows(context, snapshots)
        readings: list[DeviceReading] = []
        exclusions: Counter[str] = Counter()
        for view in views:
            reasons = tuple(
                reason
                for reason in (view.disk_free_exclusion_reason, view.ram_exclusion_reason)
                if reason
            )
            exclusions.update(reasons)
            readings.append(
                DeviceReading(
                    snapshot_id=view.snapshot_id,
                    device_id=view.device_id,
                    collected_at=view.collected_at,
                    disk_free_percent=view.disk_free_percent,
                    ram_utilization=view.ram_utilization,
                    validity_mask={
                        "disk_free_percent": view.disk_free_valid,
                        "ram_utilization": view.ram_valid,
                    },
                    exclusions=reasons,
                    source=view.source,
                )
            )
        coverage: list[ThresholdCoverage] = []
        for spec in thresholds:
            results = tuple(
                evaluate_threshold(
                    getattr(reading, spec.metric),
                    metric=spec.metric,
                    operator=spec.operator,
                    threshold=spec.threshold,
                    threshold_source=spec.threshold_source,
                )
                for reading in readings
            )
            coverage.append(
                ThresholdCoverage(
                    spec=spec,
                    results=results,
                    passed_count=sum(r.result is True for r in results),
                    failed_count=sum(r.result is False for r in results),
                    unknown_count=sum(r.result is None for r in results),
                    denominator=len(results),
                )
            )
        window = DeviceTimeWindow(
            device_id=device_id,
            readings=tuple(readings),
            first_observed_at=readings[0].collected_at if readings else None,
            last_observed_at=readings[-1].collected_at if readings else None,
            snapshot_count=len(readings),
            disk_valid_count=sum(r.validity_mask["disk_free_percent"] for r in readings),
            ram_valid_count=sum(r.validity_mask["ram_utilization"] for r in readings),
            excluded_reading_count=sum(bool(r.exclusions) for r in readings),
            exclusion_counts=dict(sorted(exclusions.items())),
            threshold_coverages=tuple(coverage),
        )
        refs = tuple(r.source for r in readings)
        hashes = tuple(sorted({ref.data_sha256 for ref in refs}))
        return QueryResult(
            items=(window,),
            scope=QueryScope(context.tenant_id, context.tenant_key),
            filters={
                "device_id": device_id,
                "start": start_utc.isoformat(),
                "end": end_utc.isoformat(),
            },
            numerator=len(readings),
            denominator=len(readings),
            excluded_count=window.excluded_reading_count,
            as_of=end_utc,
            data_as_of=window.last_observed_at,
            policy_threshold_source=(
                ",".join(sorted({t.threshold_source for t in thresholds})) or None
            ),
            source_row_references=refs,
            data_sha256=hashes,
            policy_version=policy_version,
            total_count=len(readings),
        )
