"""Convert legacy MySQL text storage to full Unicode."""
from alembic import op
import sqlalchemy as sa
revision='20261015_unicode'
down_revision='20261015_uuids'
branch_labels=None
depends_on=None

def upgrade():
    connection=op.get_bind()
    if connection.dialect.name!='mysql': return
    for name in sa.inspect(connection).get_table_names():
        if name=='alembic_version':continue
        quoted=connection.dialect.identifier_preparer.quote(name)
        connection.execute(sa.text(f'ALTER TABLE {quoted} CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci'))

def downgrade():
    raise RuntimeError('Do not truncate Unicode data; restore a database backup for rollback.')
