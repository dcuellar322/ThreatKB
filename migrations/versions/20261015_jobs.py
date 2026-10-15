"""Persist background job lifecycle and results."""
from alembic import op
import sqlalchemy as sa
revision = '20261015_jobs'
down_revision = '20261015_testresults'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('background_jobs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('kind', sa.String(64), nullable=False),
        sa.Column('status', sa.String(32), nullable=False),
        sa.Column('payload', sa.JSON, nullable=False), sa.Column('result', sa.JSON),
        sa.Column('error', sa.Text), sa.Column('progress', sa.Integer, nullable=False),
        sa.Column('created_user_id', sa.Integer, sa.ForeignKey('kb_users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False), sa.Column('started_at', sa.DateTime),
        sa.Column('finished_at', sa.DateTime))
    op.create_index('ix_background_jobs_status', 'background_jobs', ['status'])
    op.create_index('ix_background_jobs_created_user_id', 'background_jobs', ['created_user_id'])


def downgrade():
    op.drop_table('background_jobs')
