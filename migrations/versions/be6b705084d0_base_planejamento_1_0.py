"""Base Planejamento 1.0

Revision ID: be6b705084d0
Revises: ea55f02882c1
Create Date: 2023-06-15 17:42:42.373226

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'be6b705084d0'
down_revision = 'ea55f02882c1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('posts_instagram', schema=None) as batch_op:
        batch_op.alter_column('caption',
               existing_type=sa.VARCHAR(length=64),
               type_=sa.String(length=10000),
               existing_nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('posts_instagram', schema=None) as batch_op:
        batch_op.alter_column('caption',
               existing_type=sa.String(length=10000),
               type_=sa.VARCHAR(length=64),
               existing_nullable=True)

    # ### end Alembic commands ###
