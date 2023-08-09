"""Teste 1 base nova

Revision ID: 5eae9f97a1b6
Revises: 37cf889a0c5c
Create Date: 2023-06-15 16:44:15.038959

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5eae9f97a1b6'
down_revision = '37cf889a0c5c'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'new_table',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String(50), nullable=False)
    )

def downgrade():
    op.drop_table('new_table')