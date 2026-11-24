"""Add immutable, tenant-scoped evidence pointers and aggregate manifests."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261122_03"
down_revision = "20261121_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence_pointer",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_id", sa.BigInteger(), nullable=False),
        sa.Column("evidence_id", sa.String(67), nullable=False),
        sa.Column("dataset_sha256", sa.String(64), nullable=False),
        sa.Column("device_id", sa.String(255), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("field_path", sa.Text(), nullable=False),
        sa.Column("field_value_hash", sa.String(64), nullable=False),
        sa.Column("pointer_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["telemetry_snapshot.tenant_id", "telemetry_snapshot.id"],
            name="fk_evidence_pointer_snapshot_tenant",
        ),
        sa.UniqueConstraint("tenant_id", "evidence_id", name="uq_evidence_pointer_tenant_id"),
    )
    op.create_table(
        "aggregate_manifest",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("manifest_id", sa.String(68), nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("manifest_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "manifest_id", name="uq_manifest_tenant_id"),
    )
    for table in ("evidence_pointer", "aggregate_manifest"):
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
        policy = (
            "tenant_id = (SELECT t.id FROM tenant AS t WHERE "
            "t.company_id = current_setting('app.tenant_id', true))"
        )
        op.execute(
            f'CREATE POLICY tenant_isolation ON "{table}" USING ({policy}) WITH CHECK ({policy})'
        )
        op.execute(f'GRANT SELECT, INSERT ON "{table}" TO fleet_app')
        op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{table}" TO fleet_ingest')
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO fleet_app, fleet_ingest")
    op.execute("""
        CREATE FUNCTION reject_evidence_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'evidence ledger rows are immutable'; END;
        $$
    """)
    for table in ("evidence_pointer", "aggregate_manifest"):
        op.execute(
            f'CREATE TRIGGER immutable_ledger BEFORE UPDATE OR DELETE ON "{table}" '
            "FOR EACH ROW EXECUTE FUNCTION reject_evidence_mutation()"
        )


def downgrade() -> None:
    for table in ("aggregate_manifest", "evidence_pointer"):
        op.execute(f'DROP TRIGGER IF EXISTS immutable_ledger ON "{table}"')
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
        op.drop_table(table)
    op.execute("DROP FUNCTION IF EXISTS reject_evidence_mutation()")
