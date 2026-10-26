"""Persist scheduled confidence changes."""

from alembic import op
import sqlalchemy as sa

revision = "20261015_confidence"
down_revision = "20261015_eventids"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scheduled_confidence",
        sa.Column(
            "rule_id", sa.Integer, sa.ForeignKey("yara_rules.id"), primary_key=True
        ),
        sa.Column("confidence", sa.Integer, nullable=False),
        sa.Column("due_at", sa.DateTime, nullable=False),
        sa.Column(
            "created_user_id", sa.Integer, sa.ForeignKey("kb_users.id"), nullable=False
        ),
        sa.Column("applied_at", sa.DateTime),
    )
    op.create_index(
        "ix_scheduled_confidence_due_at", "scheduled_confidence", ["due_at"]
    )


def downgrade():
    op.drop_table("scheduled_confidence")
