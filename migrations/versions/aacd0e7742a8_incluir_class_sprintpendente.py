"""Incluir class SprintPendente

Revision ID: aacd0e7742a8
Revises: 392c789bc1df
Create Date: 2023-06-28 17:48:46.198423

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'aacd0e7742a8'
down_revision = '392c789bc1df'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('sprint_pendente',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('empresa_id', sa.Integer(), nullable=False),
    sa.Column('nome_empresa', sa.String(length=120), nullable=False),
    sa.Column('prioridade', sa.Integer(), nullable=False),
    sa.Column('tarefa', sa.Text(), nullable=False),
    sa.Column('usuario_id', sa.Integer(), nullable=True),
    sa.Column('usuario_grupo', sa.String(length=120), nullable=True),
    sa.Column('data_criacao', sa.DateTime(), nullable=True),
    sa.Column('dado_1_sprint', sa.JSON(), nullable=True),
    sa.ForeignKeyConstraint(['empresa_id'], ['empresa.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('sprint_pendente')
    # ### end Alembic commands ###
