"""Microsoft Entra ID sign-in.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-22
"""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Stores tenant-scoped Entra identities and short-lived OIDC state."""
    op.add_column('users', sa.Column('entra_tenant_id', sa.String(length=36), nullable=True))
    op.add_column('users', sa.Column('entra_object_id', sa.String(length=64), nullable=True))
    op.create_index('uq_users_entra_identity', 'users', ['entra_tenant_id', 'entra_object_id'],
                    unique=True,
                    postgresql_where=sa.text('entra_tenant_id IS NOT NULL AND '
                                             'entra_object_id IS NOT NULL'))
    op.create_table(
        'entra_login_states',
        sa.Column('state_hash', sa.LargeBinary(length=32), nullable=False),
        sa.Column('browser_hash', sa.LargeBinary(length=32), nullable=False),
        sa.Column('nonce', sa.String(length=128), nullable=False),
        sa.Column('code_verifier', sa.String(length=128), nullable=False),
        sa.Column('next_path', sa.String(length=2000), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('client_id', sa.String(length=36), nullable=False),
        sa.Column('redirect_uri', sa.String(length=500), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('state_hash', name=op.f('pk_entra_login_states')),
    )


def downgrade() -> None:
    """Removes Entra sign-in state and identity references."""
    op.drop_table('entra_login_states')
    op.drop_index('uq_users_entra_identity', table_name='users')
    op.drop_column('users', 'entra_object_id')
    op.drop_column('users', 'entra_tenant_id')
