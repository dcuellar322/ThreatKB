"""Allow canonical IPv4 and IPv6 indicators."""

from alembic import op
import sqlalchemy as sa

revision = "20261015_ipv6"
down_revision = "c36406bbd63a"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column("c2ip", "ip", existing_type=sa.String(15), type_=sa.String(45))


def downgrade():
    raise RuntimeError(
        "IPv6 indicators must be exported or removed before narrowing the IP column."
    )
