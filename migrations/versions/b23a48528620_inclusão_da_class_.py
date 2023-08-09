"""inclusão da class MacroAcaoGeradoChatAprovacao

Revision ID: b23a48528620
Revises: 9b5f05266e88
Create Date: 2023-08-03 12:30:04.791240

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b23a48528620'
down_revision = '9b5f05266e88'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('macro_acao_gerado_chat_aprovacao',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('empresa_id', sa.Integer(), nullable=False),
    sa.Column('squad_id', sa.Integer(), nullable=False),
    sa.Column('objetivo_id', sa.Integer(), nullable=False),
    sa.Column('kr_id', sa.Integer(), nullable=False),
    sa.Column('macro_acao', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['empresa_id'], ['empresa.id'], ),
    sa.ForeignKeyConstraint(['kr_id'], ['kr.id'], ),
    sa.ForeignKeyConstraint(['objetivo_id'], ['okr.id'], ),
    sa.ForeignKeyConstraint(['squad_id'], ['squad.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('ads')
    with op.batch_alter_table('seguidores', schema=None) as batch_op:
        batch_op.drop_index('ix_seguidores_id_empresa')

    op.drop_table('seguidores')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('seguidores',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('id_empresa', sa.VARCHAR(length=64), autoincrement=False, nullable=True),
    sa.Column('data_criacao', sa.VARCHAR(length=64), autoincrement=False, nullable=True),
    sa.Column('nome_empresa', sa.VARCHAR(length=64), autoincrement=False, nullable=True),
    sa.Column('seguidores', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='seguidores_pkey')
    )
    with op.batch_alter_table('seguidores', schema=None) as batch_op:
        batch_op.create_index('ix_seguidores_id_empresa', ['id_empresa'], unique=False)

    op.create_table('ads',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('id_empresa', sa.INTEGER(), autoincrement=False, nullable=False),
    sa.Column('timestamp', sa.VARCHAR(length=64), autoincrement=False, nullable=True),
    sa.Column('nome_grupo', sa.VARCHAR(length=200), autoincrement=False, nullable=True),
    sa.Column('nome_campanha', sa.VARCHAR(length=200), autoincrement=False, nullable=True),
    sa.Column('nome_anuncio', sa.VARCHAR(length=200), autoincrement=False, nullable=True),
    sa.Column('valor', sa.DOUBLE_PRECISION(precision=53), autoincrement=False, nullable=True),
    sa.Column('impressoes', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('landing', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('cpm', sa.DOUBLE_PRECISION(precision=53), autoincrement=False, nullable=True),
    sa.Column('ctr', sa.DOUBLE_PRECISION(precision=53), autoincrement=False, nullable=True),
    sa.Column('cpc', sa.DOUBLE_PRECISION(precision=53), autoincrement=False, nullable=True),
    sa.Column('nome_empresa', sa.VARCHAR(length=64), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['id_empresa'], ['empresa.id'], name='ads_id_empresa_fkey'),
    sa.PrimaryKeyConstraint('id', name='ads_pkey')
    )
    op.drop_table('macro_acao_gerado_chat_aprovacao')
    # ### end Alembic commands ###
