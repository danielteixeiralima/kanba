"""vincular class analise_anuncios

Revision ID: 392c789bc1df
Revises: 59ab5cccfece
Create Date: 2023-06-28 17:06:01.843654

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '392c789bc1df'
down_revision = '59ab5cccfece'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('post_instagram', schema=None) as batch_op:
        batch_op.drop_index('ix_post_instagram_id_empresa')

    op.drop_table('post_instagram')
    with op.batch_alter_table('analise_anuncios', schema=None) as batch_op:
        batch_op.add_column(sa.Column('nome_campanha', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('nome_grupo', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('nome_anuncio', sa.Text(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('analise_anuncios', schema=None) as batch_op:
        batch_op.drop_column('nome_anuncio')
        batch_op.drop_column('nome_grupo')
        batch_op.drop_column('nome_campanha')

    op.create_table('post_instagram',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('id_empresa', sa.VARCHAR(length=64), autoincrement=False, nullable=True),
    sa.Column('timestamp', sa.VARCHAR(length=64), autoincrement=False, nullable=True),
    sa.Column('caption', sa.VARCHAR(length=64), autoincrement=False, nullable=True),
    sa.Column('like_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('comments_count', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('reach', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('percentage', sa.DOUBLE_PRECISION(precision=53), autoincrement=False, nullable=True),
    sa.Column('media_product_type', sa.VARCHAR(length=64), autoincrement=False, nullable=True),
    sa.Column('plays', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('saved', sa.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('nome_empresa', sa.VARCHAR(length=64), autoincrement=False, nullable=True),
    sa.PrimaryKeyConstraint('id', name='post_instagram_pkey')
    )
    with op.batch_alter_table('post_instagram', schema=None) as batch_op:
        batch_op.create_index('ix_post_instagram_id_empresa', ['id_empresa'], unique=False)

    # ### end Alembic commands ###
