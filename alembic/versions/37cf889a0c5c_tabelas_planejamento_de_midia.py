"""tabelas Planejamento de midia

Revision ID: 37cf889a0c5c
Revises: 
Create Date: 2023-06-15 16:36:01.272165

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '37cf889a0c5c'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('analise_instagram',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('data_criacao', sa.String(length=64), nullable=True),
    sa.Column('analise', sa.Text(), nullable=True),
    sa.Column('nome_empresa', sa.String(length=64), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('empresa',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nome_contato', sa.String(length=80), nullable=True),
    sa.Column('email_contato', sa.String(length=120), nullable=True),
    sa.Column('telefone_contato', sa.String(length=20), nullable=True),
    sa.Column('endereco_empresa', sa.String(length=200), nullable=True),
    sa.Column('setor_atuacao', sa.String(length=200), nullable=True),
    sa.Column('tamanho_empresa', sa.String(length=200), nullable=True),
    sa.Column('descricao_empresa', sa.Text(), nullable=True),
    sa.Column('objetivos_principais', sa.Text(), nullable=True),
    sa.Column('historico_interacoes', sa.Text(), nullable=True),
    sa.Column('vincular_instagram', sa.String(length=200), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('posts_instagram',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('id_empresa', sa.String(length=64), nullable=True),
    sa.Column('timestamp', sa.String(length=64), nullable=True),
    sa.Column('caption', sa.String(length=64), nullable=True),
    sa.Column('like_count', sa.Integer(), nullable=True),
    sa.Column('comments_count', sa.Integer(), nullable=True),
    sa.Column('reach', sa.Integer(), nullable=True),
    sa.Column('percentage', sa.Float(), nullable=True),
    sa.Column('media_product_type', sa.String(length=64), nullable=True),
    sa.Column('plays', sa.Integer(), nullable=True),
    sa.Column('saved', sa.Integer(), nullable=True),
    sa.Column('nome_empresa', sa.String(length=64), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_posts_instagram_id_empresa'), 'posts_instagram', ['id_empresa'], unique=False)
    op.create_table('okr',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('id_empresa', sa.Integer(), nullable=False),
    sa.Column('objetivo', sa.String(length=200), nullable=True),
    sa.Column('data_inicio', sa.DateTime(), nullable=False),
    sa.Column('data_fim', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['id_empresa'], ['empresa.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('resposta',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('id_empresa', sa.Integer(), nullable=False),
    sa.Column('pergunta', sa.Text(), nullable=False),
    sa.Column('resposta', sa.Text(), nullable=True),
    sa.Column('classificacao', sa.String(length=200), nullable=True),
    sa.Column('data_criacao', sa.DateTime(), nullable=True),
    sa.Column('data_atualizacao', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['id_empresa'], ['empresa.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('usuario',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nome', sa.String(length=80), nullable=False),
    sa.Column('sobrenome', sa.String(length=80), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('celular', sa.String(length=20), nullable=False),
    sa.Column('id_empresa', sa.Integer(), nullable=False),
    sa.Column('data_entrada', sa.DateTime(), nullable=True),
    sa.Column('cargo', sa.String(length=80), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('sprint', sa.String(length=200), nullable=True),
    sa.Column('dayling_1', sa.String(length=200), nullable=True),
    sa.Column('dayling_2', sa.String(length=200), nullable=True),
    sa.Column('dayling_3', sa.String(length=200), nullable=True),
    sa.Column('dayling_4', sa.String(length=200), nullable=True),
    sa.Column('dayling_5', sa.String(length=200), nullable=True),
    sa.Column('password_hash', sa.String(length=128), nullable=True),
    sa.Column('is_admin', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['id_empresa'], ['empresa.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('kr',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('id_empresa', sa.Integer(), nullable=False),
    sa.Column('id_okr', sa.Integer(), nullable=False),
    sa.Column('texto', sa.String(length=200), nullable=True),
    sa.Column('data_inclusao', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['id_empresa'], ['empresa.id'], ),
    sa.ForeignKeyConstraint(['id_okr'], ['okr.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('sprint',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('empresa_id', sa.Integer(), nullable=False),
    sa.Column('nome_empresa', sa.String(length=120), nullable=False),
    sa.Column('prioridade', sa.Integer(), nullable=False),
    sa.Column('tarefa', sa.Text(), nullable=False),
    sa.Column('usuario_id', sa.Integer(), nullable=True),
    sa.Column('usuario_grupo', sa.String(length=120), nullable=True),
    sa.Column('data_criacao', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['empresa_id'], ['empresa.id'], ),
    sa.ForeignKeyConstraint(['usuario_id'], ['usuario.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('tarefa_semanal',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('empresa_id', sa.Integer(), nullable=False),
    sa.Column('usuario_id', sa.Integer(), nullable=False),
    sa.Column('tarefa_semana', sa.String(length=500), nullable=False),
    sa.Column('to_do', sa.String(length=10000), nullable=True),
    sa.Column('observacoes', sa.String(length=10000), nullable=True),
    sa.Column('data_para_conclusao', sa.DateTime(), nullable=False),
    sa.Column('data_criacao', sa.DateTime(), nullable=True),
    sa.Column('data_atualizacao', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['empresa_id'], ['empresa.id'], ),
    sa.ForeignKeyConstraint(['usuario_id'], ['usuario.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('macro_acao',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('texto', sa.String(length=500), nullable=False),
    sa.Column('aprovada', sa.Boolean(), nullable=True),
    sa.Column('data_inclusao', sa.DateTime(), nullable=True),
    sa.Column('kr_id', sa.Integer(), nullable=False),
    sa.Column('objetivo', sa.String(length=500), nullable=False),
    sa.Column('objetivo_id', sa.Integer(), nullable=False),
    sa.Column('empresa', sa.String(length=500), nullable=False),
    sa.Column('empresa_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['kr_id'], ['kr.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('macro_acao')
    op.drop_table('tarefa_semanal')
    op.drop_table('sprint')
    op.drop_table('kr')
    op.drop_table('usuario')
    op.drop_table('resposta')
    op.drop_table('okr')
    op.drop_index(op.f('ix_posts_instagram_id_empresa'), table_name='posts_instagram')
    op.drop_table('posts_instagram')
    op.drop_table('empresa')
    op.drop_table('analise_instagram')
    # ### end Alembic commands ###
