"""Create tenant-scoped telemetry ingestion schema."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20261121_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("company_id", sa.String(255), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_table(
        "employee",
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("employee_id", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("tenant_id", "employee_id"),
    )
    op.create_table(
        "device",
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("device_id", sa.String(255), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenant.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("tenant_id", "device_id"),
    )
    op.create_table(
        "telemetry_snapshot",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("device_id", sa.String(255), nullable=False),
        sa.Column("employee_id", sa.String(255), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_version", sa.String(255), nullable=False),
        sa.Column("os_platform", sa.String(128), nullable=False),
        sa.Column("os_product_name", sa.String(255), nullable=False),
        sa.Column("os_json", postgresql.JSONB(), nullable=False),
        sa.Column("device_identity_json", postgresql.JSONB(), nullable=False),
        sa.Column("memory_json", postgresql.JSONB(), nullable=False),
        sa.Column("battery_json", postgresql.JSONB(), nullable=True),
        sa.Column("network_json", postgresql.JSONB(), nullable=True),
        sa.Column("raw_json", postgresql.JSONB(), nullable=False),
        sa.Column("source_path", sa.Text(), nullable=False),
        sa.Column("source_line_number", sa.Integer(), nullable=False),
        sa.Column("source_row_sha256", sa.String(64), nullable=False),
        sa.Column("data_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(
            ["tenant_id", "device_id"],
            ["device.tenant_id", "device.device_id"],
            name="fk_snapshot_device_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "employee_id"],
            ["employee.tenant_id", "employee.employee_id"],
            name="fk_snapshot_employee_tenant",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "device_id", "collected_at", name="uq_snapshot_tenant_device_collected"
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_snapshot_tenant_id"),
    )
    op.create_table(
        "disk_volume",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_id", sa.BigInteger(), nullable=False),
        sa.Column("volume_name", sa.String(512), nullable=False),
        sa.Column("file_system", sa.String(255), nullable=False),
        sa.Column("mount_point", sa.String(1024), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("available_bytes", sa.BigInteger(), nullable=False),
        sa.Column("encrypted", sa.Boolean(), nullable=False),
        sa.CheckConstraint("size_bytes > 0", name="ck_disk_volume_size_positive"),
        sa.CheckConstraint(
            "available_bytes >= 0 AND available_bytes <= size_bytes",
            name="ck_disk_volume_available_in_range",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["telemetry_snapshot.tenant_id", "telemetry_snapshot.id"],
            name="fk_disk_volume_snapshot_tenant",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "compliance_result",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_id", sa.BigInteger(), nullable=False),
        sa.Column("check_id", sa.String(255), nullable=False),
        sa.Column("status", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(128), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["telemetry_snapshot.tenant_id", "telemetry_snapshot.id"],
            name="fk_compliance_result_snapshot_tenant",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "installed_software",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("tenant_id", sa.BigInteger(), nullable=False),
        sa.Column("snapshot_id", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("version", sa.String(255), nullable=False),
        sa.Column("publisher", sa.String(512), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["telemetry_snapshot.tenant_id", "telemetry_snapshot.id"],
            name="fk_installed_software_snapshot_tenant",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "dataset_import",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("data_sha256", sa.String(64), nullable=False),
        sa.Column("dataset_version", sa.String(128), nullable=False),
        sa.Column("source_path", sa.Text(), nullable=False),
        sa.Column("source_line_count", sa.Integer(), nullable=False),
        sa.Column("records_validated", sa.Integer(), nullable=False),
        sa.Column("snapshots_inserted", sa.Integer(), nullable=False),
        sa.Column("snapshots_noop", sa.Integer(), nullable=False),
        sa.Column("error_count", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.String(128), nullable=False),
        sa.Column("graph_version", sa.String(128), nullable=False),
        sa.Column("prompt_version", sa.String(128), nullable=False),
        sa.Column("model_version", sa.String(255), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dataset_import_data_sha256", "dataset_import", ["data_sha256"])


def downgrade() -> None:
    op.drop_index("ix_dataset_import_data_sha256", table_name="dataset_import")
    op.drop_table("dataset_import")
    op.drop_table("installed_software")
    op.drop_table("compliance_result")
    op.drop_table("disk_volume")
    op.drop_table("telemetry_snapshot")
    op.drop_table("device")
    op.drop_table("employee")
    op.drop_table("tenant")
