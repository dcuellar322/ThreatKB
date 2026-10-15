"""Index the workbench's updated-time sorts as well as legacy creation sorts."""

from alembic import op
import sqlalchemy as sa

revision = "20261015_updated_sorts"
down_revision = "20261015_file_hash_width"
branch_labels = None
depends_on = None
INDEXES = []
for table, date in [
    ("yara_rules", "last_revision_date"),
    ("c2ip", "date_modified"),
    ("c2dns", "date_modified"),
    ("tasks", "date_modified"),
]:
    INDEXES.extend(
        [
            (f"ix_{table}_active_updated", table, ["active", date, "id"]),
            (f"ix_{table}_state_updated", table, ["active", "state", date, "id"]),
            (
                f"ix_{table}_owner_updated",
                table,
                ["owner_user_id", "active", date, "id"],
            ),
        ]
    )


def upgrade():
    for name, table, columns in INDEXES:
        if name not in {
            row["name"] for row in sa.inspect(op.get_bind()).get_indexes(table)
        }:
            op.create_index(name, table, columns)


def downgrade():
    for name, table, columns in reversed(INDEXES):
        op.drop_index(name, table_name=table)
