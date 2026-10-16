"""Allow task tag mappings on databases upgraded from the legacy schema."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

revision = "20261015_task_tags"
down_revision = "20261015_updated_sorts"
branch_labels = None
depends_on = None


def source_column():
    bind = op.get_bind()
    if bind.dialect.name not in ("mysql", "mariadb"):
        return None
    return next(
        column
        for column in sa.inspect(bind).get_columns("tags_mapping")
        if column["name"] == "source_table"
    )


def upgrade():
    column = source_column()
    if column and isinstance(column["type"], mysql.ENUM):
        values = list(column["type"].enums)
        if "tasks" not in values:
            op.alter_column(
                "tags_mapping",
                "source_table",
                existing_type=column["type"],
                type_=mysql.ENUM(*values, "tasks"),
                existing_nullable=column["nullable"],
            )


def downgrade():
    column = source_column()
    if (
        column
        and isinstance(column["type"], mysql.ENUM)
        and "tasks" in column["type"].enums
    ):
        if op.get_bind().scalar(
            sa.text("SELECT COUNT(*) FROM tags_mapping WHERE source_table = 'tasks'")
        ):
            raise RuntimeError(
                "Remove task tag mappings before downgrading task tag support."
            )
        values = [value for value in column["type"].enums if value != "tasks"]
        op.alter_column(
            "tags_mapping",
            "source_table",
            existing_type=column["type"],
            type_=mysql.ENUM(*values),
            existing_nullable=column["nullable"],
        )
