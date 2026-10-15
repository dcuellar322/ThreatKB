"""Enforce unique legacy EventIDs; allocation locks the category sequence."""
from alembic import op
import sqlalchemy as sa

revision = "20261015_eventids"
down_revision = "20261015_ipv6"
branch_labels = None
depends_on = None


def upgrade():
    duplicates = op.get_bind().execute(sa.text(
        "SELECT eventid, COUNT(*) FROM yara_rules GROUP BY eventid HAVING COUNT(*) > 1"
    )).all()
    if duplicates:
        raise RuntimeError(f"Resolve duplicate EventIDs before migration: {duplicates}")
    op.create_unique_constraint("uq_yara_rules_eventid", "yara_rules", ["eventid"])


def downgrade():
    op.drop_constraint("uq_yara_rules_eventid", "yara_rules", type_="unique")
