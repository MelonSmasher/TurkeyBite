"""initial schema

Revision ID: 0001
Revises: 
Create Date: 2026-10-05 17:06:14.185154
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('audit_events',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=False), nullable=False),
    sa.Column('at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('actor_type', sa.String(length=16), nullable=False),
    sa.Column('actor_id', sa.UUID(), nullable=True),
    sa.Column('actor_name', sa.String(length=200), nullable=False),
    sa.Column('action', sa.String(length=60), nullable=False),
    sa.Column('outcome', sa.String(length=16), nullable=False),
    sa.Column('target_type', sa.String(length=40), nullable=True),
    sa.Column('target_id', sa.String(length=200), nullable=True),
    sa.Column('target_label', sa.String(length=400), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_events'))
    )
    op.create_index('ix_audit_events_action', 'audit_events', ['action'], unique=False)
    op.create_index('ix_audit_events_at', 'audit_events', ['at'], unique=False)
    op.create_table('daily_stats',
    sa.Column('day', sa.Date(), nullable=False),
    sa.Column('dimension', sa.String(length=40), nullable=False),
    sa.Column('key', sa.String(length=300), nullable=False),
    sa.Column('count', sa.BigInteger(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('day', 'dimension', 'key', name=op.f('pk_daily_stats'))
    )
    op.create_table('leases',
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('holder', sa.String(length=200), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('name', name=op.f('pk_leases'))
    )
    op.create_table('users',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('username', sa.String(length=150), nullable=False),
    sa.Column('display_name', sa.String(length=200), nullable=True),
    sa.Column('email', sa.String(length=320), nullable=True),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=True),
    sa.Column('ldap_dn', sa.String(length=1000), nullable=True),
    sa.Column('disabled', sa.Boolean(), nullable=False),
    sa.Column('disabled_reason', sa.String(length=16), nullable=True),
    sa.Column('directory_checked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('totp_secret_enc', sa.Text(), nullable=True),
    sa.Column('totp_enabled', sa.Boolean(), nullable=False),
    sa.Column('totp_last_step', sa.BigInteger(), nullable=True),
    sa.Column('failed_logins', sa.Integer(), nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('preferences', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users'))
    )
    op.create_index('uq_users_username_lower', 'users', [sa.literal_column('lower(username)')], unique=True)
    op.create_table('api_keys',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('prefix', sa.String(length=16), nullable=False),
    sa.Column('key_hash', sa.LargeBinary(length=32), nullable=False),
    sa.Column('scopes', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('created_by_id', sa.UUID(), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_used_ip', sa.String(length=64), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_api_keys_created_by_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_api_keys_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_api_keys')),
    sa.UniqueConstraint('prefix', name=op.f('uq_api_keys_prefix'))
    )
    op.create_index(op.f('ix_api_keys_user_id'), 'api_keys', ['user_id'], unique=False)
    op.create_table('dashboards',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('owner_id', sa.UUID(), nullable=True),
    sa.Column('builtin_key', sa.String(length=100), nullable=True),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('icon', sa.String(length=40), nullable=False),
    sa.Column('widgets', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('time_range', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('shared', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], name=op.f('fk_dashboards_owner_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_dashboards')),
    sa.UniqueConstraint('builtin_key', name=op.f('uq_dashboards_builtin_key'))
    )
    op.create_index(op.f('ix_dashboards_owner_id'), 'dashboards', ['owner_id'], unique=False)
    op.create_table('rules',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('builtin_key', sa.String(length=100), nullable=True),
    sa.Column('builtin_version', sa.Integer(), nullable=True),
    sa.Column('modified', sa.Boolean(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('category', sa.String(length=50), nullable=False),
    sa.Column('type', sa.String(length=30), nullable=False),
    sa.Column('query', sa.Text(), nullable=False),
    sa.Column('params', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('group_by', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('interval_seconds', sa.Integer(), nullable=False),
    sa.Column('window_seconds', sa.Integer(), nullable=False),
    sa.Column('dedup_seconds', sa.Integer(), nullable=False),
    sa.Column('schedule', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('exceptions', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('webhook_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('title_template', sa.String(length=300), nullable=False),
    sa.Column('created_by_id', sa.UUID(), nullable=True),
    sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('evaluated_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('running_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_status', sa.String(length=16), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('last_duration_ms', sa.Integer(), nullable=True),
    sa.Column('last_hits', sa.Integer(), nullable=True),
    sa.Column('consecutive_failures', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_rules_created_by_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_rules')),
    sa.UniqueConstraint('builtin_key', name=op.f('uq_rules_builtin_key'))
    )
    op.create_index(op.f('ix_rules_next_run_at'), 'rules', ['next_run_at'], unique=False)
    op.create_table('saved_searches',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('owner_id', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('query', sa.Text(), nullable=False),
    sa.Column('time_range', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('columns', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('shared', sa.Boolean(), nullable=False),
    sa.Column('pinned', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], name=op.f('fk_saved_searches_owner_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_saved_searches'))
    )
    op.create_index(op.f('ix_saved_searches_owner_id'), 'saved_searches', ['owner_id'], unique=False)
    op.create_table('settings',
    sa.Column('key', sa.String(length=100), nullable=False),
    sa.Column('value', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_by_id', sa.UUID(), nullable=True),
    sa.ForeignKeyConstraint(['updated_by_id'], ['users.id'], name=op.f('fk_settings_updated_by_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('key', name=op.f('pk_settings'))
    )
    op.create_table('user_sessions',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('token_hash', sa.LargeBinary(length=32), nullable=False),
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.String(length=400), nullable=True),
    sa.Column('method', sa.String(length=16), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_user_sessions_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_user_sessions')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_user_sessions_token_hash'))
    )
    op.create_index(op.f('ix_user_sessions_user_id'), 'user_sessions', ['user_id'], unique=False)
    op.create_table('webhooks',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('url_enc', sa.Text(), nullable=False),
    sa.Column('url_display', sa.String(length=400), nullable=False),
    sa.Column('format', sa.String(length=20), nullable=False),
    sa.Column('secret_enc', sa.Text(), nullable=False),
    sa.Column('headers_enc', sa.Text(), nullable=True),
    sa.Column('events', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('all_findings', sa.Boolean(), nullable=False),
    sa.Column('min_severity', sa.String(length=10), nullable=False),
    sa.Column('redact_entities', sa.Boolean(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_by_id', sa.UUID(), nullable=True),
    sa.Column('last_status', sa.String(length=16), nullable=True),
    sa.Column('last_delivery_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('failure_streak', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name=op.f('fk_webhooks_created_by_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_webhooks'))
    )
    op.create_table('findings',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('number', sa.BigInteger(), sa.Identity(always=False, start=1000), nullable=False),
    sa.Column('rule_id', sa.UUID(), nullable=True),
    sa.Column('rule_name', sa.String(length=200), nullable=False),
    sa.Column('rule_type', sa.String(length=30), nullable=False),
    sa.Column('category', sa.String(length=50), nullable=False),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=400), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('entity_field', sa.String(length=100), nullable=True),
    sa.Column('entity_value', sa.String(length=400), nullable=True),
    sa.Column('dedup_key', sa.String(length=64), nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('event_count', sa.BigInteger(), nullable=False),
    sa.Column('occurrences', sa.Integer(), nullable=False),
    sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('assignee_id', sa.UUID(), nullable=True),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('resolved_by_id', sa.UUID(), nullable=True),
    sa.Column('snoozed_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['assignee_id'], ['users.id'], name=op.f('fk_findings_assignee_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['resolved_by_id'], ['users.id'], name=op.f('fk_findings_resolved_by_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['rule_id'], ['rules.id'], name=op.f('fk_findings_rule_id_rules'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_findings')),
    sa.UniqueConstraint('number', name=op.f('uq_findings_number'))
    )
    op.create_index('ix_findings_entity', 'findings', ['entity_value'], unique=False)
    op.create_index('ix_findings_last_seen', 'findings', ['last_seen'], unique=False)
    op.create_index(op.f('ix_findings_rule_id'), 'findings', ['rule_id'], unique=False)
    op.create_index('ix_findings_status_severity', 'findings', ['status', 'severity'], unique=False)
    op.create_index('uq_findings_open_dedup', 'findings', ['dedup_key'], unique=True, postgresql_where=sa.text("status IN ('new', 'acknowledged', 'in_progress')"))
    op.create_table('rule_runs',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=False), nullable=False),
    sa.Column('rule_id', sa.UUID(), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('window_start', sa.DateTime(timezone=True), nullable=True),
    sa.Column('window_end', sa.DateTime(timezone=True), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('hits', sa.Integer(), nullable=False),
    sa.Column('findings_created', sa.Integer(), nullable=False),
    sa.Column('findings_updated', sa.Integer(), nullable=False),
    sa.Column('duration_ms', sa.Integer(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['rule_id'], ['rules.id'], name=op.f('fk_rule_runs_rule_id_rules'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_rule_runs'))
    )
    op.create_index('ix_rule_runs_rule_started', 'rule_runs', ['rule_id', 'started_at'], unique=False)
    op.create_table('finding_activity',
    sa.Column('id', sa.BigInteger(), sa.Identity(always=False), nullable=False),
    sa.Column('finding_id', sa.UUID(), nullable=False),
    sa.Column('actor_id', sa.UUID(), nullable=True),
    sa.Column('actor_name', sa.String(length=200), nullable=False),
    sa.Column('kind', sa.String(length=20), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('data', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], name=op.f('fk_finding_activity_actor_id_users'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], name=op.f('fk_finding_activity_finding_id_findings'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_finding_activity'))
    )
    op.create_index(op.f('ix_finding_activity_finding_id'), 'finding_activity', ['finding_id'], unique=False)
    op.create_table('webhook_deliveries',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('webhook_id', sa.UUID(), nullable=False),
    sa.Column('event', sa.String(length=40), nullable=False),
    sa.Column('finding_id', sa.UUID(), nullable=True),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('next_attempt_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_status_code', sa.Integer(), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('response_snippet', sa.Text(), nullable=True),
    sa.Column('duration_ms', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], name=op.f('fk_webhook_deliveries_finding_id_findings'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['webhook_id'], ['webhooks.id'], name=op.f('fk_webhook_deliveries_webhook_id_webhooks'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_webhook_deliveries'))
    )
    op.create_index('ix_webhook_deliveries_due', 'webhook_deliveries', ['status', 'next_attempt_at'], unique=False)
    op.create_index('ix_webhook_deliveries_webhook_created', 'webhook_deliveries', ['webhook_id', 'created_at'], unique=False)
    op.create_index('ix_webhook_deliveries_finding_id', 'webhook_deliveries', ['finding_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_webhook_deliveries_finding_id', table_name='webhook_deliveries')
    op.drop_index('ix_webhook_deliveries_webhook_created', table_name='webhook_deliveries')
    op.drop_index('ix_webhook_deliveries_due', table_name='webhook_deliveries')
    op.drop_table('webhook_deliveries')
    op.drop_index(op.f('ix_finding_activity_finding_id'), table_name='finding_activity')
    op.drop_table('finding_activity')
    op.drop_index('ix_rule_runs_rule_started', table_name='rule_runs')
    op.drop_table('rule_runs')
    op.drop_index('uq_findings_open_dedup', table_name='findings', postgresql_where=sa.text("status IN ('new', 'acknowledged', 'in_progress')"))
    op.drop_index('ix_findings_status_severity', table_name='findings')
    op.drop_index(op.f('ix_findings_rule_id'), table_name='findings')
    op.drop_index('ix_findings_last_seen', table_name='findings')
    op.drop_index('ix_findings_entity', table_name='findings')
    op.drop_table('findings')
    op.drop_table('webhooks')
    op.drop_index(op.f('ix_user_sessions_user_id'), table_name='user_sessions')
    op.drop_table('user_sessions')
    op.drop_table('settings')
    op.drop_index(op.f('ix_saved_searches_owner_id'), table_name='saved_searches')
    op.drop_table('saved_searches')
    op.drop_index(op.f('ix_rules_next_run_at'), table_name='rules')
    op.drop_table('rules')
    op.drop_index(op.f('ix_dashboards_owner_id'), table_name='dashboards')
    op.drop_table('dashboards')
    op.drop_index(op.f('ix_api_keys_user_id'), table_name='api_keys')
    op.drop_table('api_keys')
    op.drop_index('uq_users_username_lower', table_name='users')
    op.drop_table('users')
    op.drop_table('leases')
    op.drop_table('daily_stats')
    op.drop_index('ix_audit_events_at', table_name='audit_events')
    op.drop_index('ix_audit_events_action', table_name='audit_events')
    op.drop_table('audit_events')
