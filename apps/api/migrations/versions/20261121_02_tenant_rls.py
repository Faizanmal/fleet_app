"""Enforce tenant isolation with forced PostgreSQL RLS."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261121_02"
down_revision = "20261121_01"
branch_labels = None
depends_on = None

TENANT_TABLES = (
    "tenant",
    "employee",
    "device",
    "telemetry_snapshot",
    "disk_volume",
    "compliance_result",
    "installed_software",
    "graph_run",
    "evidence",
    "proposal",
    "approval",
    "action_execution",
    "audit_event",
)


def upgrade() -> None:
    op.create_table(
        "graph_run",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("thread_id", sa.String(255), nullable=False),
        sa.Column("trace_id", sa.String(255), nullable=True),
        sa.Column("user_id", sa.String(255), nullable=False),
        sa.Column("data_sha256", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.String(128), nullable=False),
        sa.Column("graph_version", sa.String(128), nullable=False),
        sa.Column("prompt_version", sa.String(128), nullable=False),
        sa.Column("model_version", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_graph_run_tenant_id"),
        sa.UniqueConstraint("tenant_id", "thread_id", name="uq_graph_run_tenant_thread"),
        sa.UniqueConstraint("tenant_id", "trace_id", name="uq_graph_run_tenant_trace"),
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("run_id", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_id", sa.BigInteger(), nullable=True),
        sa.Column("data_sha256", sa.String(64), nullable=False),
        sa.Column("evidence_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["tenant_id", "run_id"],
            ["graph_run.tenant_id", "graph_run.id"],
            name="fk_evidence_run_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["telemetry_snapshot.tenant_id", "telemetry_snapshot.id"],
            name="fk_evidence_snapshot_tenant",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_evidence_tenant_id"),
    )
    op.create_table(
        "proposal",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("run_id", sa.BigInteger(), nullable=False),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("proposal_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="draft"),
        sa.Column("data_sha256", sa.String(64), nullable=False),
        sa.Column("policy_version", sa.String(128), nullable=False),
        sa.Column("graph_version", sa.String(128), nullable=False),
        sa.Column("prompt_version", sa.String(128), nullable=False),
        sa.Column("model_version", sa.String(255), nullable=False),
        sa.Column("proposal_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["tenant_id", "run_id"],
            ["graph_run.tenant_id", "graph_run.id"],
            name="fk_proposal_run_tenant",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_proposal_tenant_id"),
    )
    op.create_table(
        "approval",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("proposal_id", sa.BigInteger(), nullable=False),
        sa.Column("approver_id", sa.String(255), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("proposal_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal.tenant_id", "proposal.id"],
            name="fk_approval_proposal_tenant",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_approval_tenant_id"),
    )
    op.create_table(
        "action_execution",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("proposal_id", sa.BigInteger(), nullable=False),
        sa.Column("execution_id", sa.String(255), nullable=False),
        sa.Column("proposal_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal.tenant_id", "proposal.id"],
            name="fk_action_execution_proposal_tenant",
        ),
        sa.UniqueConstraint("tenant_id", "execution_id", name="uq_action_execution_tenant_id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_action_execution_tenant_pk"),
    )
    op.create_table(
        "audit_event",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("run_id", sa.BigInteger(), nullable=True),
        sa.Column("actor_id", sa.String(255), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("entity_type", sa.String(128), nullable=False),
        sa.Column("entity_id", sa.String(255), nullable=False),
        sa.Column("details_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["tenant_id", "run_id"],
            ["graph_run.tenant_id", "graph_run.id"],
            name="fk_audit_run_tenant",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_audit_event_tenant_id"),
    )

    for table in TENANT_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        if table == "tenant":
            predicate = "company_id = current_setting('app.tenant_id', true)"
        else:
            predicate = (
                "tenant_id = (SELECT t.id FROM tenant AS t "
                "WHERE t.company_id = current_setting('app.tenant_id', true))"
            )
        op.execute(
            f'CREATE POLICY tenant_isolation ON "{table}" '
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )

    # Request paths use fleet_app; migrations use the separate fleet owner role.
    op.execute("GRANT SELECT ON tenant TO fleet_app")
    for table in TENANT_TABLES[1:]:
        if table in {"approval", "audit_event"}:
            op.execute(f'GRANT SELECT, INSERT ON "{table}" TO fleet_app')
        else:
            op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{table}" TO fleet_app')
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO fleet_app")

    # Batch ingest crosses tenant boundaries by design and has no request-facing credentials.
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON tenant, employee, device TO fleet_ingest")
    for table in TENANT_TABLES[3:]:
        op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{table}" TO fleet_ingest')
    op.execute("GRANT SELECT, INSERT ON dataset_import TO fleet_ingest")
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO fleet_ingest")


def downgrade() -> None:
    for table in reversed(TENANT_TABLES):
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
    op.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM fleet_app")
    op.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM fleet_ingest")
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fleet_app")
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fleet_ingest")
    op.drop_table("audit_event")
    op.drop_table("action_execution")
    op.drop_table("approval")
    op.drop_table("proposal")
    op.drop_table("evidence")
    op.drop_table("graph_run")
