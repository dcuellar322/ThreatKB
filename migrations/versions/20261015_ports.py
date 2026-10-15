"""Support upstream's externally maintained C2 port specifications."""
from alembic import op
import sqlalchemy as sa

revision = "20261015_ports"
down_revision = "20261015_confidence"
branch_labels = None
depends_on = None


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("c2ip")}
    if "ports" not in columns:
        op.add_column("c2ip", sa.Column("ports", sa.String(255), nullable=True))


def downgrade():
    # Values may predate this application migration and belong to an external
    # maintainer. Preserve them when rolling application migrations back.
    pass
