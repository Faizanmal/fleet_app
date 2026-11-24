"""Persist tenant-scoped, privacy-filtered graph step events."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261123_06"
down_revision = "20261122_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_step_event",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("run_id", sa.BigInteger(), nullable=False),
        sa.Column("trace_id", sa.String(255), nullable=False),
        sa.Column("step_index", sa.Integer(), nullable=False),
        sa.Column("node", sa.String(64), nullable=False),
        sa.Column("event_json", postgresql.JSONB(), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("elapsed_ms", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["tenant_id", "run_id"],
            ["graph_run.tenant_id", "graph_run.id"],
            name="fk_agent_step_run_tenant",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "run_id", "step_index", name="uq_agent_step_order"),
    )
    op.create_index("ix_agent_step_tenant_trace", "agent_step_event", ["tenant_id", "trace_id"])
    op.execute("ALTER TABLE agent_step_event ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE agent_step_event FORCE ROW LEVEL SECURITY")
    predicate = (
        "tenant_id = (SELECT t.id FROM tenant AS t WHERE "
        "t.company_id = current_setting('app.tenant_id', true))"
    )
    op.execute(
        f"CREATE POLICY tenant_isolation ON agent_step_event "
        f"USING ({predicate}) WITH CHECK ({predicate})"
    )
    op.execute("GRANT SELECT, INSERT, DELETE ON agent_step_event TO fleet_app")
    op.execute("GRANT SELECT, INSERT ON agent_step_event TO fleet_ingest")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE agent_step_event_id_seq TO fleet_app, fleet_ingest")


def downgrade() -> None:
    op.drop_index("ix_agent_step_tenant_trace", table_name="agent_step_event")
    op.drop_table("agent_step_event")
