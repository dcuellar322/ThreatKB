"""Keep complete SHA-1 parent identifiers for extracted samples."""

from alembic import op
import sqlalchemy as sa

revision = "20261015_file_hash_width"
down_revision = "20261015_query_indexes"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("files") as batch:
        batch.alter_column(
            "parent_sha1",
            existing_type=sa.String(32),
            type_=sa.String(40),
            existing_nullable=True,
        )
        batch.create_index("ix_files_artifact", ["entity_type", "entity_id", "id"])


def downgrade():
    with op.batch_alter_table("files") as batch:
        batch.drop_index("ix_files_artifact")
        batch.alter_column(
            "parent_sha1",
            existing_type=sa.String(40),
            type_=sa.String(32),
            existing_nullable=True,
        )
