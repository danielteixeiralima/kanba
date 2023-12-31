"""atualizacao da class KR para os campos squad e meta

Revision ID: 8be8239b1f3b
Revises: 5b6b2bfa1ba1
Create Date: 2023-08-02 17:49:21.017280

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8be8239b1f3b'
down_revision = '5b6b2bfa1ba1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('kr', schema=None) as batch_op:
        batch_op.add_column(sa.Column('squad_id', sa.Integer(), nullable=False))
        batch_op.add_column(sa.Column('meta', sa.String(length=255), nullable=True))
        batch_op.create_foreign_key(None, 'squad', ['squad_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('kr', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('meta')
        batch_op.drop_column('squad_id')

    # ### end Alembic commands ###
