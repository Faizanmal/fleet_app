"""Canonical evidence identity, tenant-scoped persistence, and verification."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import select

from fleet.core.identity import MissingRequestContext, RequestContext
from fleet.db.models import AggregateManifestRecord, EvidencePointerRecord, TelemetrySnapshot
from fleet.domain.query import SourceRowReference, normalize_as_of
from fleet.evidence.models import AggregateManifest, Claim, EvidencePointer

QUERY_VERSION = "deterministic-query-v1"
SELECTION_RULE = "row_number(partition tenant_id,device_id order collected_at desc,id desc)"
ALLOWED_PATH = re.compile(r"^\$(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\])+$")
ALLOWED_ROOTS = {
    "os",
    "device_identity",
    "memory",
    "disk_volumes",
    "installed_software",
    "compliance_results",
    "battery",
    "network",
    "agent_version",
    "collected_at",
    "device_id",
    "employee_id",
}


def canonical_json(value: Any) -> str:
    def encode(obj: Any) -> Any:
        if isinstance(obj, (datetime,)):
            return obj.isoformat()
        if isinstance(obj, Decimal):
            return format(obj, "f")
        if hasattr(obj, "model_dump"):
            return obj.model_dump(mode="json")
        raise TypeError(f"not canonically serializable: {type(obj).__name__}")

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=encode,
    )


def stable_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _path_value(source: dict[str, Any], path: str) -> Any:
    if not ALLOWED_PATH.fullmatch(path):
        raise ValueError("field_path is not a supported JSONPath-like path")
    parts = re.findall(r"\.([A-Za-z_][A-Za-z0-9_]*)|\[([0-9]+)\]", path[1:])
    root = parts[0][0]
    if root not in ALLOWED_ROOTS:
        raise ValueError("field_path root is not an allowed telemetry field")
    value: Any = source
    for key, index in parts:
        if index:
            try:
                value = value[int(index)]
            except (IndexError, TypeError, KeyError):
                return None
        else:
            if not isinstance(value, dict) or key not in value:
                return None
            value = value[key]
    return value


def make_pointer(snapshot: TelemetrySnapshot, field_path: str) -> EvidencePointer:
    source = snapshot.raw_json
    value_hash = stable_hash(_path_value(source, field_path))
    identity = {
        "tenant_id": snapshot.tenant_id,
        "dataset_sha256": snapshot.data_sha256,
        "snapshot_id": snapshot.id,
        "field_path": field_path,
        "field_value_hash": value_hash,
    }
    return EvidencePointer(
        **identity,
        device_id=snapshot.device_id,
        collected_at=snapshot.collected_at,
        evidence_id="ev_" + stable_hash(identity),
    )


def persist_pointer(context: RequestContext, pointer: EvidencePointer) -> EvidencePointer:
    _require_context(context)
    if pointer.tenant_id != context.tenant_id:
        raise PermissionError("evidence pointer tenant mismatch")
    payload = pointer.model_dump(mode="json")
    existing = context.session.scalar(
        select(EvidencePointerRecord).where(
            EvidencePointerRecord.tenant_id == context.tenant_id,
            EvidencePointerRecord.evidence_id == pointer.evidence_id,
        )
    )
    if existing is not None:
        if existing.pointer_json != payload:
            raise RuntimeError("SHA-256 evidence identity collision")
        return pointer
    context.session.add(
        EvidencePointerRecord(
            tenant_id=pointer.tenant_id,
            snapshot_id=pointer.snapshot_id,
            evidence_id=pointer.evidence_id,
            dataset_sha256=pointer.dataset_sha256,
            device_id=pointer.device_id,
            collected_at=pointer.collected_at,
            field_path=pointer.field_path,
            field_value_hash=pointer.field_value_hash,
            pointer_json=payload,
        )
    )
    context.session.flush()
    return pointer


def capture_manifest(
    context: RequestContext,
    *,
    query_type: str,
    filters: dict[str, Any],
    as_of: datetime,
    matched_refs: tuple[SourceRowReference, ...],
    excluded_refs: tuple[SourceRowReference, ...],
    numerator: Decimal | int | None,
    denominator: Decimal | int | None,
    eligible: int,
    observed: int,
    unknown: int,
    policy_version: str,
) -> AggregateManifest:
    _require_context(context)
    cutoff = normalize_as_of(as_of)
    all_refs = matched_refs + excluded_refs
    if any(ref.data_sha256 != all_refs[0].data_sha256 for ref in all_refs) if all_refs else False:
        raise ValueError("a manifest cannot mix source dataset hashes")
    source_hash = (
        all_refs[0].data_sha256 if all_refs else stable_hash({"empty_scope": context.tenant_key})
    )
    matched = tuple(_ref_json(ref) for ref in matched_refs)
    excluded = tuple(_ref_json(ref) for ref in excluded_refs)
    latest = max((ref for ref in all_refs), key=lambda ref: ref.collected_at, default=None)
    window_days: int | None = None
    if filters.get("start") and filters.get("end"):
        start = datetime.fromisoformat(str(filters["start"]))
        end = datetime.fromisoformat(str(filters["end"]))
        window_days = max(0, math.ceil((end - start).total_seconds() / 86400))
    payload = {
        "tenant_id": context.tenant_id,
        "query_version": QUERY_VERSION,
        "query_type": query_type,
        "filters": filters,
        "as_of": cutoff,
        "selection_rule": SELECTION_RULE,
        "matched_snapshot_refs": matched,
        "excluded_refs": excluded,
        "numerator": numerator,
        "denominator": denominator,
        "source_hash": source_hash,
        "threshold_version": policy_version,
        "latest_observed_at": latest.collected_at if latest else None,
        "coverage": {
            "eligible": eligible,
            "observed": observed,
            "unknown": unknown,
            "window_days": window_days,
        },
    }
    fingerprint = stable_hash(payload)
    manifest = AggregateManifest(
        **payload,
        query_fingerprint=fingerprint,
        manifest_id="man_" + fingerprint,
    )
    serialized = manifest.model_dump(mode="json")
    row = context.session.scalar(
        select(AggregateManifestRecord).where(
            AggregateManifestRecord.tenant_id == context.tenant_id,
            AggregateManifestRecord.manifest_id == manifest.manifest_id,
        )
    )
    digest = stable_hash(serialized)
    if row:
        if row.manifest_hash != digest or row.manifest_json != serialized:
            raise RuntimeError("SHA-256 manifest identity collision")
    else:
        context.session.add(
            AggregateManifestRecord(
                tenant_id=context.tenant_id,
                manifest_id=manifest.manifest_id,
                manifest_hash=digest,
                manifest_json=serialized,
            )
        )
        context.session.flush()
    # Every repository aggregate read materializes stable field pointers for its source rows.
    for ref in all_refs:
        snapshot = context.session.scalar(
            select(TelemetrySnapshot).where(
                TelemetrySnapshot.tenant_id == context.tenant_id,
                TelemetrySnapshot.id == ref.snapshot_id,
            )
        )
        if snapshot is not None and isinstance(snapshot.raw_json, dict):
            for field_path in ("$.device_id", "$.collected_at", "$.os.platform"):
                val = _path_value(snapshot.raw_json, field_path)
                if val is not None:
                    persist_pointer(context, make_pointer(snapshot, field_path))
    return manifest


def resolve_evidence(context: RequestContext, evidence_id: str) -> dict[str, Any] | None:
    _require_context(context)
    row = context.session.scalar(
        select(EvidencePointerRecord).where(
            EvidencePointerRecord.tenant_id == context.tenant_id,
            EvidencePointerRecord.evidence_id == evidence_id,
        )
    )
    if row is None:
        return None
    snapshot = context.session.scalar(
        select(TelemetrySnapshot).where(
            TelemetrySnapshot.tenant_id == context.tenant_id,
            TelemetrySnapshot.id == row.snapshot_id,
        )
    )
    if snapshot is None or snapshot.data_sha256 != row.dataset_sha256:
        raise RuntimeError("evidence source snapshot is missing or changed")
    if snapshot.device_id != row.device_id or snapshot.collected_at != row.collected_at:
        raise RuntimeError("evidence snapshot identity changed")
    value = _path_value(snapshot.raw_json, row.field_path)
    if stable_hash(value) != row.field_value_hash:
        raise RuntimeError("evidence source field changed after ingestion")
    if make_pointer(snapshot, row.field_path).evidence_id != row.evidence_id:
        raise RuntimeError("evidence pointer identity failed verification")
    return {
        **row.pointer_json,
        "field_value": value,
        "content_classification": "untrusted_telemetry_data",
        "calculation": "source field value; no derived calculation",
    }


def verify_claim(context: RequestContext, claim: Claim) -> bool:
    _require_context(context)
    if claim.policy_version != "policy-v1":
        return False
    if claim.claim_type == "field_value":
        if len(claim.evidence_ids) != 1:
            return False
        evidence = resolve_evidence(context, claim.evidence_ids[0])
        return evidence is not None and evidence["field_value"] == claim.value
    if not claim.query_manifest_id:
        return False
    row = context.session.scalar(
        select(AggregateManifestRecord).where(
            AggregateManifestRecord.tenant_id == context.tenant_id,
            AggregateManifestRecord.manifest_id == claim.query_manifest_id,
        )
    )
    if row is None or stable_hash(row.manifest_json) != row.manifest_hash:
        return False
    manifest = AggregateManifest.model_validate(row.manifest_json)
    if manifest.tenant_id != context.tenant_id or claim.as_of != manifest.as_of:
        return False
    manifest_payload = manifest.model_dump(mode="python")
    manifest_payload.pop("query_fingerprint")
    manifest_payload.pop("manifest_id")
    if (
        stable_hash(manifest_payload) != manifest.query_fingerprint
        or manifest.manifest_id != "man_" + manifest.query_fingerprint
        or not _manifest_refs_resolvable(context, manifest)
    ):
        return False
    if claim.coverage != manifest.coverage:
        return False
    if claim.claim_type == "count" and claim.method == "matched_snapshot_count-v1":
        expected = len(manifest.matched_snapshot_refs)
        if (
            claim.value != expected
            or manifest.numerator != expected
            or manifest.coverage.get("observed") != manifest.coverage.get("eligible")
            or manifest.coverage.get("eligible", 0) == 0
        ):
            return False
        filters = manifest.filters
        if expected == 0 and str(filters.get("compliance_status", "")).casefold() == "fail":
            if (
                str(filters.get("compliance_severity", "")).casefold() == "high"
                and manifest.coverage.get("unknown") != 0
            ):
                return False
        return True
    if claim.claim_type == "list_ids" and claim.method == "matched_device_ids-v1":
        expected_ids = sorted({str(ref["device_id"]) for ref in manifest.matched_snapshot_refs})
        return claim.value == expected_ids
    required_method = "manifest_ratio-v1" if claim.claim_type == "ratio" else "manifest_percent-v1"
    if claim.claim_type in {"ratio", "percent"} and claim.method == required_method:
        if manifest.denominator in (None, 0) or manifest.numerator is None:
            return False
        numerator = Decimal(str(manifest.numerator))
        denominator = Decimal(str(manifest.denominator))
        expected = numerator / denominator
        if claim.claim_type == "percent":
            expected *= 100
        try:
            return Decimal(str(claim.value)) == expected
        except Exception:
            return False
    return False


def _require_context(context: RequestContext) -> None:
    if not isinstance(context, RequestContext):
        raise MissingRequestContext("A trusted RequestContext is required")


def _ref_json(ref: SourceRowReference) -> dict[str, Any]:
    return {
        "snapshot_id": ref.snapshot_id,
        "device_id": ref.device_id,
        "collected_at": ref.collected_at.isoformat(),
        "data_sha256": ref.data_sha256,
        "source_path": ref.source_path,
        "source_line_number": ref.source_line_number,
        "source_row_sha256": ref.source_row_sha256,
    }


def _manifest_refs_resolvable(context: RequestContext, manifest: AggregateManifest) -> bool:
    references = manifest.matched_snapshot_refs + manifest.excluded_refs
    if not references:
        return manifest.coverage.get("eligible", 0) == 0
    snapshot_ids = [int(ref["snapshot_id"]) for ref in references]
    snapshots = context.session.scalars(
        select(TelemetrySnapshot).where(
            TelemetrySnapshot.tenant_id == context.tenant_id,
            TelemetrySnapshot.id.in_(snapshot_ids),
        )
    ).all()
    by_id = {snapshot.id: snapshot for snapshot in snapshots}
    if len(by_id) != len(set(snapshot_ids)):
        return False
    return all(
        (snapshot := by_id[int(ref["snapshot_id"])]).tenant_id == manifest.tenant_id
        and snapshot.device_id == ref["device_id"]
        and snapshot.data_sha256 == ref["data_sha256"] == manifest.source_hash
        and snapshot.source_path == ref["source_path"]
        and snapshot.source_line_number == ref["source_line_number"]
        and snapshot.source_row_sha256 == ref["source_row_sha256"]
        and snapshot.collected_at.isoformat() == ref["collected_at"]
        for ref in references
    )
