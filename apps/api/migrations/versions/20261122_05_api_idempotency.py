"""Add actor-scoped idempotency keys for proposal and agent-run writes."""

import sqlalchemy as sa
from alembic import op

revision = "20261122_05"
down_revision = "20261122_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("proposal", sa.Column("idempotency_key", sa.String(128), nullable=True))
    op.create_unique_constraint(
        "uq_proposal_idempotency", "proposal", ["tenant_id", "requested_by", "idempotency_key"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_proposal_idempotency", "proposal", type_="unique")
    op.drop_column("proposal", "idempotency_key")
