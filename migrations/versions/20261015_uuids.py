"""Add stable signature identities independently of legacy EventIDs."""

from alembic import op
import sqlalchemy as sa
from uuid import uuid4, uuid5, NAMESPACE_URL

revision = "20261015_uuids"
down_revision = "20261015_jobs"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("yara_rules", sa.Column("uuid", sa.String(36)))
    connection = op.get_bind()
    for row in connection.execute(sa.text("SELECT id,name FROM yara_rules")).mappings():
        prefix = "DEV_Synthetic_Indicator_"
        identity = (
            str(uuid5(NAMESPACE_URL, f"threatkb:dev:{int(row['name'][len(prefix) :])}"))
            if row["name"].startswith(prefix)
            else str(uuid4())
        )
        connection.execute(
            sa.text("UPDATE yara_rules SET uuid=:uuid WHERE id=:id"),
            {"uuid": identity, "id": row["id"]},
        )
    op.alter_column("yara_rules", "uuid", existing_type=sa.String(36), nullable=False)
    op.create_unique_constraint("uq_yara_rules_uuid", "yara_rules", ["uuid"])


def downgrade():
    raise RuntimeError(
        "Preserve stable UUID identities; restore a database backup for rollback."
    )
