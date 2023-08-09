"""atualizacao da class KR para os campos squad e meta 2

Revision ID: 9b5f05266e88
Revises: 8be8239b1f3b
Create Date: 2023-08-02 18:01:18.109695

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9b5f05266e88'
down_revision = '8be8239b1f3b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('kr', schema=None) as batch_op:
        batch_op.add_column(sa.Column('data_final', sa.DateTime(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('kr', schema=None) as batch_op:
        batch_op.drop_column('data_final')

    # ### end Alembic commands ###