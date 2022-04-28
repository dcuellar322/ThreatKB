"""New Macros Table.

Revision ID: 6f68d5b06411
Revises: 4f5f6f314c20
Create Date: 2019-04-28 16:27:29.443533

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '6f68d5b06411'
down_revision = '4f5f6f314c20'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('macros',
                    sa.Column('tag', sa.String(length=512), nullable=False),
                    sa.Column('value', sa.TEXT(), nullable=True),
                    sa.Column('active', sa.Boolean(), nullable=False),
                    sa.Column('date_created', sa.DateTime(timezone=True), nullable=True),
                    sa.Column('date_modified', sa.DateTime(timezone=True), nullable=True),
                    sa.Column('created_user_id', sa.Integer(), nullable=False),
                    sa.Column('modified_user_id', sa.Integer(), nullable=False),
                    sa.ForeignKeyConstraint(['created_user_id'], ['kb_users.id'], ),
                    sa.ForeignKeyConstraint(['modified_user_id'], ['kb_users.id'], ),
                    sa.PrimaryKeyConstraint('tag')
                    )
    op.create_index('ix_macros_active', 'macros', ['active'], unique=False)
    op.create_index('ix_macros_tag', 'macros', ['tag'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('ix_macros_tag', table_name='macros')
    op.drop_index('ix_macros_active', table_name='macros')
    op.drop_table('macros')
    # ### end Alembic commands ###
