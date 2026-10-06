"""The console's own records.

Nothing here copies an event. A finding keeps the query that reproduces its
evidence, the counts that summarised it when it fired, and the entity it is
about; the events themselves are read from OpenSearch when someone looks.
DailyStat keeps counts per day and category, never per person, so long-term
trends survive index retention without keeping anyone's history longer than
the retention period allows.
"""

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import (BigInteger, Boolean, Date, DateTime, ForeignKey, Identity, Index, Integer,
                        LargeBinary, String, Text, func, text)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _now() -> datetime:
    # Set in Python rather than by the database, so the new value is known
    # without reading the row back, which an async session cannot do lazily
    return datetime.now(timezone.utc)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=_now, nullable=False)


# -- people and machines ------------------------------------------------------

class User(TimestampMixin, Base):
    __tablename__ = 'users'
    __table_args__ = (Index('uq_users_username_lower', func.lower(text('username')), unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(150), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(200))
    email: Mapped[str | None] = mapped_column(String(320))
    # local: password kept here; ldap: the directory decides; service: API keys only
    source: Mapped[str] = mapped_column(String(16), nullable=False, default='local')
    role: Mapped[str] = mapped_column(String(16), nullable=False, default='viewer')
    password_hash: Mapped[str | None] = mapped_column(String(255))
    ldap_dn: Mapped[str | None] = mapped_column(String(1000))
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # admin, or directory when the directory stopped granting access; only the
    # directory's own disabling is undone by the directory granting it again
    disabled_reason: Mapped[str | None] = mapped_column(String(16))
    # When the directory last confirmed a directory account still has access
    directory_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    totp_secret_enc: Mapped[str | None] = mapped_column(Text)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # The last time step a code was accepted for, so a code cannot be used twice
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    preferences: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Bumped when a password changes, which ends every session issued before
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UserSession(Base):
    __tablename__ = 'user_sessions'

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    # SHA-256 of the cookie's token; the token itself is never stored
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False, unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'),
                                               nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                   server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))
    method: Mapped[str] = mapped_column(String(16), nullable=False, default='local')

    user: Mapped[User] = relationship(lazy='joined')


class ApiKey(Base):
    __tablename__ = 'api_keys'

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'),
                                               nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # The public part of the key, which finds the row; the secret part is
    # only ever compared as a hash
    prefix: Mapped[str] = mapped_column(String(16), nullable=False, unique=True)
    key_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    scopes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey('users.id', ondelete='SET NULL'))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_ip: Mapped[str | None] = mapped_column(String(64))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(foreign_keys=[user_id], lazy='joined')


class Setting(Base):
    """Settings an admin changes at runtime, one JSON document per key."""
    __tablename__ = 'settings'

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=_now, nullable=False)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey('users.id', ondelete='SET NULL'))


# -- analysis -----------------------------------------------------------------

class Rule(TimestampMixin, Base):
    __tablename__ = 'rules'

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    # Set for the rules that ship with the console. Their definition can be
    # changed, but the rule cannot be deleted, only disabled, and it can be
    # reset to the shipped definition.
    builtin_key: Mapped[str | None] = mapped_column(String(100), unique=True)
    builtin_version: Mapped[int | None] = mapped_column(Integer)
    modified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default='')
    category: Mapped[str] = mapped_column(String(50), nullable=False, default='custom')
    type: Mapped[str] = mapped_column(String(30), nullable=False)
    query: Mapped[str] = mapped_column(Text, nullable=False, default='')
    params: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    group_by: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default='medium')
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=900)
    dedup_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    schedule: Mapped[dict | None] = mapped_column(JSONB)
    exceptions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    webhook_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    title_template: Mapped[str] = mapped_column(String(300), nullable=False, default='{rule}: {entity}')
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey('users.id', ondelete='SET NULL'))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # The end of the last window evaluated without error: the next run starts
    # from here, so a window that failed, or was missed while the console or
    # the cluster was down, is evaluated later rather than never
    evaluated_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set while a run is under way, by whichever process claimed it, so no
    # other starts the same rule; it lapses if that process dies
    running_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(16))
    last_error: Mapped[str | None] = mapped_column(Text)
    last_duration_ms: Mapped[int | None] = mapped_column(Integer)
    last_hits: Mapped[int | None] = mapped_column(Integer)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class RuleRun(Base):
    __tablename__ = 'rule_runs'
    __table_args__ = (Index('ix_rule_runs_rule_started', 'rule_id', 'started_at'),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('rules.id', ondelete='CASCADE'),
                                               nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)


class Finding(TimestampMixin, Base):
    __tablename__ = 'findings'
    __table_args__ = (
        Index('ix_findings_status_severity', 'status', 'severity'),
        Index('ix_findings_entity', 'entity_value'),
        Index('ix_findings_last_seen', 'last_seen'),
        # One open finding per rule and entity: a rule that keeps matching
        # adds occurrences to it rather than raising another
        Index('uq_findings_open_dedup', 'dedup_key', unique=True,
              postgresql_where=text("status IN ('new', 'acknowledged', 'in_progress')")),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    number: Mapped[int] = mapped_column(BigInteger, Identity(start=1000), unique=True,
                                        nullable=False)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey('rules.id', ondelete='SET NULL'),
                                                      index=True)
    rule_name: Mapped[str] = mapped_column(String(200), nullable=False)
    rule_type: Mapped[str] = mapped_column(String(30), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False, default='custom')
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default='new')
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default='')
    entity_field: Mapped[str | None] = mapped_column(String(100))
    entity_value: Mapped[str | None] = mapped_column(String(400))
    dedup_key: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    occurrences: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # The query and window that reproduce the evidence, and the summary
    # counts when it fired: what to look at, never a copy of what was seen
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey('users.id', ondelete='SET NULL'))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey('users.id', ondelete='SET NULL'))
    snoozed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    assignee: Mapped[User | None] = relationship(foreign_keys=[assignee_id], lazy='joined')


class FindingActivity(Base):
    __tablename__ = 'finding_activity'

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('findings.id', ondelete='CASCADE'),
                                                  nullable=False, index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey('users.id', ondelete='SET NULL'))
    actor_name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, default='')
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 nullable=False)


# -- outbound -----------------------------------------------------------------

class Webhook(TimestampMixin, Base):
    __tablename__ = 'webhooks'

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # Chat services put the posting credential in the URL itself, so it is
    # encrypted like the headers; the display form shows only where it goes
    url_enc: Mapped[str] = mapped_column(Text, nullable=False)
    url_display: Mapped[str] = mapped_column(String(400), nullable=False)
    format: Mapped[str] = mapped_column(String(20), nullable=False, default='json')
    secret_enc: Mapped[str] = mapped_column(Text, nullable=False)
    headers_enc: Mapped[str | None] = mapped_column(Text)
    events: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # Every finding at or above min_severity goes here, besides the findings
    # of rules that name this webhook
    all_findings: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    min_severity: Mapped[str] = mapped_column(String(10), nullable=False, default='high')
    # Leave out who the finding is about, for a channel more people read
    redact_entities: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey('users.id', ondelete='SET NULL'))
    last_status: Mapped[str | None] = mapped_column(String(16))
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_streak: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class WebhookDelivery(Base):
    __tablename__ = 'webhook_deliveries'
    __table_args__ = (
        Index('ix_webhook_deliveries_due', 'status', 'next_attempt_at'),
        Index('ix_webhook_deliveries_webhook_created', 'webhook_id', 'created_at'),
        # A finding's deliveries, and pruning findings, which sets these to null
        Index('ix_webhook_deliveries_finding_id', 'finding_id'),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    webhook_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('webhooks.id', ondelete='CASCADE'),
                                                  nullable=False)
    event: Mapped[str] = mapped_column(String(40), nullable=False)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey('findings.id', ondelete='SET NULL'))
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default='pending')
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status_code: Mapped[int | None] = mapped_column(Integer)
    last_error: Mapped[str | None] = mapped_column(Text)
    response_snippet: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


# -- what people keep ------------------------------------------------------------

class SavedSearch(TimestampMixin, Base):
    __tablename__ = 'saved_searches'

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'),
                                                nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default='')
    query: Mapped[str] = mapped_column(Text, nullable=False, default='')
    time_range: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    columns: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    shared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    owner: Mapped[User] = relationship(lazy='joined')


class Dashboard(TimestampMixin, Base):
    __tablename__ = 'dashboards'

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'),
                                                       index=True)
    builtin_key: Mapped[str | None] = mapped_column(String(100), unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default='')
    icon: Mapped[str] = mapped_column(String(40), nullable=False, default='layout-dashboard')
    widgets: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    time_range: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    shared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    owner: Mapped[User | None] = relationship(lazy='joined')


class DailyStat(Base):
    """Counts per day and dimension, kept after the events they count are gone."""
    __tablename__ = 'daily_stats'

    day: Mapped[date] = mapped_column(Date, primary_key=True)
    dimension: Mapped[str] = mapped_column(String(40), primary_key=True)
    key: Mapped[str] = mapped_column(String(300), primary_key=True)
    count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                                 onupdate=_now, nullable=False)


class AuditEvent(Base):
    __tablename__ = 'audit_events'
    __table_args__ = (Index('ix_audit_events_at', 'at'),
                      Index('ix_audit_events_action', 'action'))

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(),
                                         nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor_name: Mapped[str] = mapped_column(String(200), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default='success')
    target_type: Mapped[str | None] = mapped_column(String(40))
    target_id: Mapped[str | None] = mapped_column(String(200))
    target_label: Mapped[str | None] = mapped_column(String(400))
    ip: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class Lease(Base):
    """A named lock with an expiry, for jobs only one replica should run at a time."""
    __tablename__ = 'leases'

    name: Mapped[str] = mapped_column(String(100), primary_key=True)
    holder: Mapped[str] = mapped_column(String(200), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
