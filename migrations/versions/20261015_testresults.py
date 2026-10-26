"""Retain all sample results to detect lost matches."""

from alembic import op
import sqlalchemy as sa

revision = "20261015_testresults"
down_revision = "20261015_ports"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "yara_testing_history_files_matches",
        sa.Column("matched", sa.Boolean, nullable=False, server_default=sa.true()),
    )
    op.add_column(
        "yara_testing_history_files_matches", sa.Column("sha256", sa.String(64))
    )


def downgrade():
    op.drop_column("yara_testing_history_files_matches", "sha256")
    op.drop_column("yara_testing_history_files_matches", "matched")
