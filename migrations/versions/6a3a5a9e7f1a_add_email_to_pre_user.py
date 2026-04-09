"""Add email column to pre_user

Revision ID: 6a3a5a9e7f1a
Revises: d55367ffb095
Create Date: 2026-04-09 21:05:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6a3a5a9e7f1a'
down_revision = 'd55367ffb095'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('pre_user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email', sa.String(length=255), nullable=True))
        batch_op.create_index('ix_pre_user_email', ['email'], unique=False)
        batch_op.create_unique_constraint('uq_pre_user_email', ['email'])


def downgrade():
    with op.batch_alter_table('pre_user', schema=None) as batch_op:
        batch_op.drop_constraint('uq_pre_user_email', type_='unique')
        batch_op.drop_index('ix_pre_user_email')
        batch_op.drop_column('email')
