"""Tenant-scoped repositories. Callers must supply authenticated RequestContext."""

from sqlalchemy import select

from fleet.core.identity import MissingRequestContext, RequestContext
from fleet.db.models import (
    ActionExecution,
    Approval,
    AuditEvent,
    Device,
    Evidence,
    GraphRun,
    Proposal,
    TelemetrySnapshot,
)


class DeviceRepository:
    def get(self, context: RequestContext, device_id: str) -> Device | None:
        if not isinstance(context, RequestContext):
            raise MissingRequestContext("A trusted RequestContext is required")
        return context.session.scalar(
            select(Device).where(
                Device.tenant_id == context.tenant_id, Device.device_id == device_id
            )
        )


class TenantRecordRepository:
    """Opaque, tenant-filtered lookups for IDs exposed in APIs, graphs, and traces."""

    @staticmethod
    def _get(context: RequestContext, model, record_id: int):
        if not isinstance(context, RequestContext):
            raise MissingRequestContext("A trusted RequestContext is required")
        return context.session.scalar(
            select(model).where(model.tenant_id == context.tenant_id, model.id == record_id)
        )

    def run(self, context: RequestContext, run_id: int) -> GraphRun | None:
        return self._get(context, GraphRun, run_id)

    def thread(self, context: RequestContext, thread_id: str) -> GraphRun | None:
        if not isinstance(context, RequestContext):
            raise MissingRequestContext("A trusted RequestContext is required")
        return context.session.scalar(
            select(GraphRun).where(
                GraphRun.tenant_id == context.tenant_id, GraphRun.thread_id == thread_id
            )
        )

    def trace(self, context: RequestContext, trace_id: str) -> GraphRun | None:
        if not isinstance(context, RequestContext):
            raise MissingRequestContext("A trusted RequestContext is required")
        return context.session.scalar(
            select(GraphRun).where(
                GraphRun.tenant_id == context.tenant_id, GraphRun.trace_id == trace_id
            )
        )

    def evidence(self, context: RequestContext, evidence_id: int) -> Evidence | None:
        return self._get(context, Evidence, evidence_id)

    def proposal(self, context: RequestContext, proposal_id: int) -> Proposal | None:
        return self._get(context, Proposal, proposal_id)

    def approval(self, context: RequestContext, approval_id: int) -> Approval | None:
        return self._get(context, Approval, approval_id)

    def execution(
        self, context: RequestContext, execution_record_id: int
    ) -> ActionExecution | None:
        return self._get(context, ActionExecution, execution_record_id)

    def execution_by_public_id(
        self, context: RequestContext, execution_id: str
    ) -> ActionExecution | None:
        if not isinstance(context, RequestContext):
            raise MissingRequestContext("A trusted RequestContext is required")
        return context.session.scalar(
            select(ActionExecution).where(
                ActionExecution.tenant_id == context.tenant_id,
                ActionExecution.execution_id == execution_id,
            )
        )

    def audit_event(self, context: RequestContext, event_id: int) -> AuditEvent | None:
        return self._get(context, AuditEvent, event_id)

    def audit(self, context: RequestContext, event_id: int) -> AuditEvent | None:
        return self.audit_event(context, event_id)

    def snapshot(self, context: RequestContext, snapshot_id: int) -> TelemetrySnapshot | None:
        return self._get(context, TelemetrySnapshot, snapshot_id)
