"""empty message

Revision ID: e7d04ecb38e2
Revises: 
Create Date: 2023-05-19 19:02:31.387718

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision = 'e7d04ecb38e2'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    res = conn.execute(text("SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name = 'resposta' AND column_name = 'classificacao'"))
    try:
        res.fetchone()[0]
    except:
        with op.batch_alter_table('resposta') as batch_op:
            batch_op.add_column(sa.Column('classificacao', sa.String(length=200), nullable=True))

def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('resposta', schema=None) as batch_op:
        batch_op.drop_column('classificacao')

    # ### end Alembic commands ###
