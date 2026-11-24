"""Privacy-preserving deterministic replay of persisted tool-fact transcripts."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from fleet.core.identity import RequestContext, authorize
from fleet.db.models import AgentStepEvent, AuditEvent, GraphRun
from fleet.evidence.ledger import stable_hash

CHAIN_ROOT = "0" * 64


def event_digest(*, previous_hash: str, row: AgentStepEvent) -> str:
    return stable_hash(
        {
            "previous_hash": previous_hash,
            "tenant_id": row.tenant_id,
            "run_id": row.run_id,
            "trace_id": row.trace_id,
            "step_index": row.step_index,
            "node": row.node,
            "event_json": row.event_json,
        }
    )


def replay_transcript(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Project only verifiable tool facts; narrative and private prompt are never replayed."""
    facts = [
        {
            "iteration": event.get("iteration"),
            "tool": event.get("tool_name"),
            "decision": event.get("decision"),
            "result": event.get("result_summary"),
            "evidence_ids": event.get("evidence_ids", []),
        }
        for event in events
        if event.get("node") == "tool"
    ]
    return {"facts": facts, "facts_sha256": stable_hash(facts), "tool_count": len(facts)}


def replay_run(context: RequestContext, run_id: str) -> dict[str, Any]:
    authorize(context.principal, context.tenant_key, "read")
    query = select(GraphRun).where(
        GraphRun.tenant_id == context.tenant_id,
        GraphRun.trace_id == run_id,
    )
    if "admin" not in context.principal.roles:
        query = query.where(GraphRun.user_id == context.principal.user_id)
    run = context.session.scalar(query)
    if run is None:
        raise LookupError("Run not found")
    rows = context.session.scalars(
        select(AgentStepEvent)
        .where(AgentStepEvent.tenant_id == context.tenant_id, AgentStepEvent.run_id == run.id)
        .order_by(AgentStepEvent.step_index)
    ).all()
    expected_head = CHAIN_ROOT
    valid = True
    for index, row in enumerate(rows):
        if row.step_index != index or row.previous_hash != expected_head:
            valid = False
            break
        digest = event_digest(previous_hash=expected_head, row=row)
        if digest != row.event_hash or row.trace_id != run_id:
            valid = False
            break
        if (
            row.event_json.get("policy_version") != run.policy_version
            or row.event_json.get("graph_version") != run.graph_version
            or row.event_json.get("model_version") != run.model_version
        ):
            valid = False
            break
        expected_head = digest
    audit = context.session.scalar(
        select(AuditEvent).where(
            AuditEvent.tenant_id == context.tenant_id,
            AuditEvent.run_id == run.id,
            AuditEvent.event_type == "agent_run_trace",
        )
    )
    if audit is None or audit.details_json.get("step_event_head") != expected_head:
        valid = False
    projection = replay_transcript([row.event_json for row in rows])
    dataset_versions = sorted(
        {
            version
            for row in rows
            for version in row.event_json.get("result_summary", {}).get("data_sha256", [])
        }
    )
    if audit and audit.details_json.get("step_event_count") != len(rows):
        valid = False
    expected_dataset_version = (
        dataset_versions[0]
        if len(dataset_versions) == 1
        else stable_hash(dataset_versions or {"empty_scope": context.tenant_key})
    )
    if expected_dataset_version != run.data_sha256:
        valid = False
    return {
        "run_id": run_id,
        "trace_id": run_id,
        "replay_mode": "offline_fixture_tool_fact_transcript",
        "transcript_valid": valid,
        "tool_facts_deterministic": valid,
        "tool_count": projection["tool_count"],
        "tool_facts_sha256": projection["facts_sha256"],
        "tool_facts": projection["facts"],
        "dataset_version_sha256": run.data_sha256,
        "source_dataset_versions_sha256": dataset_versions,
        "policy_version": run.policy_version,
        "graph_version": run.graph_version,
        "model_version": run.model_version,
        "provider_calls_available": False,
        "narrative_regenerated": False,
        "limitations": [
            "Replay verifies and reprojects persisted sanitized tool facts; it does not rerun a "
            "live database query.",
            "The raw prompt and source strings are not retained, so the original answer narrative "
            "is not regenerated.",
            "Exact provider calls, tokens, and cost are unavailable unless a provider adapter "
            "recorded authentic metadata.",
        ],
    }
