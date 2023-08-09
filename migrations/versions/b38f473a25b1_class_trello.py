"""class trello

Revision ID: b38f473a25b1
Revises: a138471a2f83
Create Date: 2023-08-01 13:02:49.070530

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b38f473a25b1'
down_revision = 'a138471a2f83'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('seguidores', schema=None) as batch_op:
        batch_op.drop_index('ix_seguidores_id_empresa')

    op.drop_table('seguidores')
    op.drop_table('ads')
    with op.batch_alter_table('trello', schema=None) as batch_op:
        batch_op.add_column(sa.Column('start', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('close', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('pos', sa.String(length=64), nullable=True))
        batch_op.drop_column('nome_empresa')
        batch_op.drop_column('seguidores')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('trello', schema=None) as batch_op:
        batch_op.add_column(sa.Column('seguidores', sa.INTEGER(), autoincrement=False, nullable=True))
        batch_op.add_column(sa.Column('nome_empresa', sa.VARCHAR(length=64), autoincrement=False, nullable=True))
        batch_op.drop_column('pos')
        batch_op.drop_column('close')
        batch_op.drop_column('start')

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

    # ### end Alembic commands ###
