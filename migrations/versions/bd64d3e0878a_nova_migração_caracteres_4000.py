"""nova migração caracteres 4000

Revision ID: bd64d3e0878a
Revises: 1786db8ae12c
Create Date: 2023-07-11 18:32:26.483789

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bd64d3e0878a'
down_revision = '1786db8ae12c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('posts_instagram', schema=None) as batch_op:
        batch_op.alter_column('caption',
               existing_type=sa.VARCHAR(length=2000),
               type_=sa.String(length=4000),
               existing_nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('posts_instagram', schema=None) as batch_op:
        batch_op.alter_column('caption',
               existing_type=sa.String(length=4000),
               type_=sa.VARCHAR(length=2000),
               existing_nullable=True)

    # ### end Alembic commands ###
