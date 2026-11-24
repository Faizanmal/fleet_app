"""Persistent, authenticated proposal approval interrupt workflow."""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt
from sqlalchemy import select

from fleet.core.identity import RequestContext, authorize
from fleet.db.models import Approval, Proposal

from .checkpointer import TenantPostgresSaver


class ApprovalState(TypedDict, total=False):
    proposal_id: int
    proposal_hash: str
    summary: str
    tenant_id: int
    decision: str
    decision_actor_id: str
    decision_at: str
    status: str


def build_approval_graph(context: RequestContext, checkpointer: Any):
    """Compile the review graph; resumed payload is ignored in favor of DB approval."""
    authorize(context.principal, context.tenant_key, "read")

    def approval_node(state: ApprovalState) -> dict[str, Any]:
        if state.get("tenant_id") != context.tenant_id:
            return {"status": "BLOCKED", "decision": "tenant_mismatch"}
        # Resume is a signal only. The separate authenticated Approval row is authoritative.
        interrupt(
            {
                "proposal_id": state["proposal_id"],
                "proposal_hash": state["proposal_hash"],
                "summary": state["summary"],
            }
        )
        approval = context.session.scalar(
            select(Approval).where(
                Approval.tenant_id == context.tenant_id,
                Approval.proposal_id == state["proposal_id"],
                Approval.proposal_hash == state["proposal_hash"],
            )
        )
        proposal = context.session.scalar(
            select(Proposal).where(
                Proposal.tenant_id == context.tenant_id,
                Proposal.id == state["proposal_id"],
                Proposal.proposal_hash == state["proposal_hash"],
            )
        )
        if approval is None or proposal is None:
            return {"status": "PENDING_APPROVAL", "decision": "unrecorded_resume_ignored"}
        return {
            "status": proposal.status,
            "decision": approval.decision,
            "decision_actor_id": approval.approver_id,
            "decision_at": approval.created_at.isoformat() if approval.created_at else None,
        }

    builder = StateGraph(ApprovalState)
    builder.add_node("approval", approval_node)
    builder.add_edge(START, "approval")
    builder.add_edge("approval", END)
    return builder.compile(checkpointer=checkpointer)


def start_approval_interrupt(context: RequestContext, proposal: Proposal) -> dict[str, Any]:
    saver = TenantPostgresSaver(context)
    graph = build_approval_graph(context, saver)
    return graph.invoke(
        {
            "proposal_id": proposal.id,
            "proposal_hash": proposal.proposal_hash,
            "summary": _approval_summary(proposal.proposal_json),
            "tenant_id": context.tenant_id,
        },
        config={"configurable": {"thread_id": proposal.workflow_thread_id}},
    )


def resume_after_decision(context: RequestContext, proposal: Proposal) -> dict[str, Any]:
    """Only the server calls this after persisting an authenticated approval record."""
    authorize(context.principal, context.tenant_key, "read")
    record = context.session.scalar(
        select(Approval).where(
            Approval.tenant_id == context.tenant_id,
            Approval.proposal_id == proposal.id,
            Approval.proposal_hash == proposal.proposal_hash,
        )
    )
    if record is None:
        raise PermissionError("separate authenticated decision record required")
    saver = TenantPostgresSaver(context)
    graph = build_approval_graph(context, saver)
    return graph.invoke(
        Command(resume={"approval_record_id": record.id}),
        config={"configurable": {"thread_id": proposal.workflow_thread_id}},
    )


def _approval_summary(document: dict[str, Any]) -> str:
    return (
        f"{document['mode']} — {document['action_kind']} for "
        f"{document['target_type']} {document['target_id']}; payload={document['payload']}; "
        f"evidence={document['evidence_manifest_ids']}; data as of {document['data_as_of']}; "
        "This approval does not execute the operation."
    )
