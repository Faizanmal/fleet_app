"""Add immutable action proposals, idempotent simulation, audit chain and LangGraph checkpoints."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261122_04"
down_revision = "20261122_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE proposal SET status = upper(status)")
    op.drop_constraint("ck_proposal_status", "proposal", type_="check", if_exists=True)
    op.create_check_constraint(
        "ck_proposal_status",
        "proposal",
        "status IN ('DRAFT','PENDING_APPROVAL','APPROVED','EXECUTING','EXECUTED',"
        "'REJECTED','EXPIRED','BLOCKED','FAILED')",
    )
    op.add_column(
        "proposal",
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now() + interval '1 day'"),
        ),
    )
    op.add_column(
        "proposal",
        sa.Column("workflow_thread_id", sa.String(255), nullable=True),
    )
    op.execute("UPDATE proposal SET workflow_thread_id = 'legacy-' || id::text")
    op.alter_column("proposal", "workflow_thread_id", nullable=False)
    op.create_unique_constraint("uq_proposal_workflow_thread", "proposal", ["workflow_thread_id"])

    op.execute("UPDATE approval SET decision='approve' WHERE decision='approved'")
    op.execute("UPDATE approval SET decision='reject' WHERE decision='rejected'")
    op.add_column(
        "approval",
        sa.Column("approver_role", sa.String(32), nullable=False, server_default="legacy"),
    )
    op.create_unique_constraint("uq_approval_once", "approval", ["tenant_id", "proposal_id"])
    op.create_check_constraint(
        "ck_approval_decision", "approval", "decision IN ('approve','reject')"
    )
    op.create_check_constraint(
        "ck_approval_role", "approval", "approver_role IN ('approver','admin','legacy')"
    )

    op.add_column(
        "action_execution",
        sa.Column("action_version", sa.String(64), nullable=True, server_default="legacy-v1"),
    )
    op.add_column("action_execution", sa.Column("result_json", postgresql.JSONB(), nullable=True))
    op.alter_column("action_execution", "action_version", nullable=False)
    op.create_unique_constraint(
        "uq_action_execution_version",
        "action_execution",
        ["tenant_id", "proposal_id", "action_version"],
    )

    op.add_column("audit_event", sa.Column("previous_hash", sa.String(64), nullable=True))
    op.add_column("audit_event", sa.Column("event_hash", sa.String(64), nullable=True))
    op.create_table(
        "audit_chain_head",
        sa.Column("tenant_id", sa.BigInteger(), primary_key=True),
        sa.Column("last_event_id", sa.BigInteger(), nullable=True),
        sa.Column("last_hash", sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
    )
    op.execute(
        "INSERT INTO audit_chain_head (tenant_id, last_hash) SELECT id, "
        "'0000000000000000000000000000000000000000000000000000000000000000' FROM tenant"
    )

    op.create_table(
        "graph_checkpoint",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("thread_id", sa.String(255), nullable=False),
        sa.Column("checkpoint_ns", sa.String(255), nullable=False, server_default=""),
        sa.Column("checkpoint_id", sa.String(255), nullable=False),
        sa.Column("parent_checkpoint_id", sa.String(255), nullable=True),
        sa.Column("checkpoint_data", postgresql.JSONB(), nullable=False),
        sa.Column("metadata_data", postgresql.JSONB(), nullable=False),
        sa.Column(
            "pending_writes",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
        sa.UniqueConstraint(
            "tenant_id",
            "thread_id",
            "checkpoint_ns",
            "checkpoint_id",
            name="uq_checkpoint_tenant_thread_id",
        ),
    )
    op.create_table(
        "action_outbox",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("proposal_id", sa.BigInteger(), nullable=False),
        sa.Column("action_version", sa.String(64), nullable=False),
        sa.Column("provider_idempotency_key", sa.String(255), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("provider_reference", sa.String(255), nullable=True),
        sa.Column("reconciliation_json", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.CheckConstraint(
            "status IN ('PENDING','SENT','RECONCILED','FAILED')", name="ck_action_outbox_status"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "proposal_id"],
            ["proposal.tenant_id", "proposal.id"],
            name="fk_action_outbox_proposal_tenant",
        ),
        sa.UniqueConstraint(
            "tenant_id", "proposal_id", "action_version", name="uq_action_outbox_version"
        ),
        sa.UniqueConstraint(
            "tenant_id", "provider_idempotency_key", name="uq_action_outbox_idempotency"
        ),
    )

    for table in ("audit_chain_head", "graph_checkpoint", "action_outbox"):
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        predicate = (
            "tenant_id = (SELECT t.id FROM tenant AS t WHERE "
            "t.company_id = current_setting('app.tenant_id', true))"
        )
        op.execute(
            f'CREATE POLICY tenant_isolation ON "{table}" USING ({predicate}) '
            f"WITH CHECK ({predicate})"
        )
    op.execute("GRANT SELECT, INSERT, UPDATE ON audit_chain_head TO fleet_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON graph_checkpoint TO fleet_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON action_outbox TO fleet_app")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON "
        "audit_chain_head, graph_checkpoint, action_outbox TO fleet_ingest"
    )
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO fleet_app, fleet_ingest")

    op.execute("""
        CREATE FUNCTION reject_proposal_payload_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF ROW(OLD.tenant_id, OLD.run_id, OLD.requested_by, OLD.proposal_hash,
                   OLD.data_sha256, OLD.policy_version, OLD.graph_version, OLD.prompt_version,
                   OLD.model_version, OLD.proposal_json, OLD.expires_at, OLD.workflow_thread_id)
               IS DISTINCT FROM
               ROW(NEW.tenant_id, NEW.run_id, NEW.requested_by, NEW.proposal_hash,
                   NEW.data_sha256, NEW.policy_version, NEW.graph_version, NEW.prompt_version,
                   NEW.model_version, NEW.proposal_json, NEW.expires_at, NEW.workflow_thread_id)
            THEN RAISE EXCEPTION 'proposal document is immutable'; END IF;
            RETURN NEW;
        END;
        $$
    """)
    op.execute(
        "CREATE TRIGGER proposal_payload_immutable BEFORE UPDATE ON proposal "
        "FOR EACH ROW EXECUTE FUNCTION reject_proposal_payload_mutation()"
    )
    op.execute("""
        CREATE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'audit events are append-only'; END;
        $$
    """)
    op.execute(
        "CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_event "
        "FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation()"
    )


def downgrade() -> None:
    op.execute('DROP TRIGGER IF EXISTS audit_append_only ON "audit_event"')
    op.execute("DROP FUNCTION IF EXISTS reject_audit_mutation()")
    op.execute('DROP TRIGGER IF EXISTS proposal_payload_immutable ON "proposal"')
    op.execute("DROP FUNCTION IF EXISTS reject_proposal_payload_mutation()")
    op.execute(
        "REVOKE ALL ON action_outbox, graph_checkpoint, audit_chain_head "
        "FROM fleet_app, fleet_ingest"
    )
    op.execute('DROP POLICY IF EXISTS tenant_isolation ON "action_outbox"')
    op.execute('DROP POLICY IF EXISTS tenant_isolation ON "graph_checkpoint"')
    op.execute('DROP POLICY IF EXISTS tenant_isolation ON "audit_chain_head"')
    op.drop_table("graph_checkpoint")
    op.drop_table("audit_chain_head")
    op.drop_table("action_outbox")
    op.drop_column("audit_event", "event_hash")
    op.drop_column("audit_event", "previous_hash")
    op.drop_constraint("uq_action_execution_version", "action_execution", type_="unique")
    op.drop_column("action_execution", "result_json")
    op.drop_column("action_execution", "action_version")
    op.drop_constraint("ck_approval_decision", "approval", type_="check")
    op.drop_constraint("ck_approval_role", "approval", type_="check")
    op.drop_constraint("uq_approval_once", "approval", type_="unique")
    op.drop_column("approval", "approver_role")
    op.drop_constraint("uq_proposal_workflow_thread", "proposal", type_="unique")
    op.drop_column("proposal", "workflow_thread_id")
    op.drop_column("proposal", "expires_at")
    op.drop_constraint("ck_proposal_status", "proposal", type_="check")
