"""Indexes on when findings were created and resolved, and when deliveries were made.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-17 21:40:00.000000
"""
from alembic import op

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Indexes the times pages and pruning select by, which every finding and delivery was read for before."""
    op.create_index('ix_findings_created_at', 'findings', ['created_at'], unique=False)
    op.create_index('ix_findings_resolved_at', 'findings', ['resolved_at'], unique=False)
    op.create_index('ix_webhook_deliveries_created_at', 'webhook_deliveries', ['created_at'], unique=False)


def downgrade() -> None:
    """Drops them again."""
    op.drop_index('ix_webhook_deliveries_created_at', table_name='webhook_deliveries')
    op.drop_index('ix_findings_resolved_at', table_name='findings')
    op.drop_index('ix_findings_created_at', table_name='findings')
