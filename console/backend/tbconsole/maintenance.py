"""Housekeeping: what the console stops keeping, and directory accounts rechecked.

Hourly, under a lease so one replica does it:

* sessions past their expiry or idle limit are deleted;
* webhook deliveries that were sent or gave up are deleted after
  TBCONSOLE_DELIVERY_RETENTION_DAYS;
* findings closed for longer than TBCONSOLE_FINDING_RETENTION_DAYS are
  deleted, with their timelines, and audit events older than
  TBCONSOLE_AUDIT_RETENTION_DAYS; 0 keeps either for ever;
* directory accounts with a session or an API key are looked up again, so
  someone removed from the directory, or from every group that grants a role,
  loses access within the hour rather than when their session ends. Their
  role follows the directory's, as it does at sign-in. Only a definite answer
  changes anything: a directory that cannot be reached changes nothing.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import audit, settings_store
from . import db as database
from .config import get_settings
from .models import ApiKey, AuditEvent, Finding, User, UserSession, WebhookDelivery
from .rollups import acquire_lease
from .security import crypto, ldap

log = logging.getLogger(__name__)

CLOSED = ('resolved', 'false_positive')


async def prune(db: AsyncSession, now: datetime | None = None) -> dict:
    """Deletes what is past keeping. Returns how many of each."""
    settings = get_settings()
    now = now or datetime.now(timezone.utc)
    removed = {}
    idle = now - timedelta(minutes=settings.session_idle_minutes)
    removed['sessions'] = (await db.execute(delete(UserSession).where(
        or_(UserSession.expires_at < now, UserSession.last_seen_at < idle)))).rowcount
    removed['deliveries'] = (await db.execute(delete(WebhookDelivery).where(
        WebhookDelivery.status.in_(('succeeded', 'dead')),
        WebhookDelivery.created_at < now - timedelta(days=settings.delivery_retention_days)))).rowcount
    removed['findings'] = 0
    if settings.finding_retention_days:
        removed['findings'] = (await db.execute(delete(Finding).where(
            Finding.status.in_(CLOSED),
            Finding.resolved_at < now - timedelta(days=settings.finding_retention_days)))).rowcount
    removed['audit'] = 0
    if settings.audit_retention_days:
        removed['audit'] = (await db.execute(delete(AuditEvent).where(
            AuditEvent.at < now - timedelta(days=settings.audit_retention_days)))).rowcount
    await db.commit()
    return removed


# A recheck that would revoke more than this share of the accounts it looked
# at, and more than a handful, is more likely a directory or settings mistake
# than a mass departure: it revokes nobody and says so
REVOKE_SHARE = 0.2
REVOKE_FLOOR = 3


async def recheck_directory(now: datetime | None = None) -> dict:
    """Looks up again every directory account that can act, or that the
    directory disabled and might restore. Returns counts.

    Every look-up is made first, with no transaction open; only if all of them
    got a clear answer is anything changed, one account at a time."""
    now = now or datetime.now(timezone.utc)
    counts = {'checked': 0, 'revoked': 0, 'changed': 0, 'restored': 0, 'held_back': 0}
    async with database.sessionmaker()() as db:
        cfg = ldap.config_with_defaults(await settings_store.get(db, 'ldap'))
        if not cfg.get('enabled'):
            return counts
        secret = crypto.decrypt(cfg['bind_password_enc']) if cfg.get('bind_password_enc') else ''
        active_session = select(UserSession.user_id).where(UserSession.expires_at > now)
        usable_key = select(ApiKey.user_id).where(
            ApiKey.revoked_at.is_(None), or_(ApiKey.expires_at.is_(None), ApiKey.expires_at > now))
        accounts = [(u.id, u.username, u.ldap_dn) for u in (await db.execute(select(User).where(
            User.source == 'ldap',
            or_(User.disabled_reason == 'directory',
                and_(User.disabled.is_(False),
                     or_(User.id.in_(active_session), User.id.in_(usable_key))))))).scalars()]
    verdicts = []
    for user_id, username, dn in accounts:
        verdicts.append((user_id, await asyncio.to_thread(ldap.recheck, cfg, secret, dn, username)))
    counts['checked'] = len(verdicts)
    losing = [v for v in verdicts if v[1] is None or v[1].role is None]
    hold_back = len(losing) > REVOKE_FLOOR and len(losing) > REVOKE_SHARE * len(verdicts)
    if hold_back:
        log.warning('directory recheck would revoke %s of %s accounts; revoking none. '
                    'Check the LDAP settings.', len(losing), len(verdicts))
        counts['held_back'] = len(losing)
    for user_id, identity in verdicts:
        async with database.sessionmaker()() as db:
            user = await db.get(User, user_id)
            if user is None:
                continue
            user.directory_checked_at = now
            if identity is None or identity.role is None:
                if not user.disabled and not hold_back:
                    user.disabled = True
                    user.disabled_reason = 'directory'
                    await db.execute(delete(UserSession).where(UserSession.user_id == user.id))
                    audit.record(db, 'user.directory_revoked', actor_name='TurkeyBite Console',
                                 actor_type='system', target_type='user', target_id=user.id,
                                 target_label=user.username,
                                 details={'reason': 'not in the directory, or no longer allowed to '
                                                    'sign in' if identity is None
                                          else 'no group grants a role'})
                    counts['revoked'] += 1
            else:
                if user.disabled and user.disabled_reason == 'directory':
                    user.disabled = False
                    user.disabled_reason = None
                    audit.record(db, 'user.directory_restored', actor_name='TurkeyBite Console',
                                 actor_type='system', target_type='user', target_id=user.id,
                                 target_label=user.username)
                    counts['restored'] += 1
                if identity.role != user.role:
                    audit.record(db, 'user.directory_role', actor_name='TurkeyBite Console',
                                 actor_type='system', target_type='user', target_id=user.id,
                                 target_label=user.username,
                                 details={'from': user.role, 'to': identity.role})
                    user.role = identity.role
                    counts['changed'] += 1
                user.ldap_dn = identity.dn
            await db.commit()
    return counts


class Maintenance:
    def __init__(self, every_seconds: int = 3600):
        self.every_seconds = every_seconds
        self._task: asyncio.Task | None = None
        self.last_run: datetime | None = None
        self.last_error: str | None = None
        self._last_directory: datetime | None = None

    async def run_once(self) -> None:
        settings = get_settings()
        async with database.sessionmaker()() as db:
            if not await acquire_lease(db, 'maintenance', max(60, self.every_seconds - 60)):
                return
            removed = await prune(db)
            if any(removed.values()):
                log.info('maintenance removed %s', removed)
        now = datetime.now(timezone.utc)
        due = timedelta(minutes=settings.ldap_recheck_minutes)
        if self._last_directory is None or now - self._last_directory >= due:
            try:
                counts = await recheck_directory(now)
                self._last_directory = now
                if counts['revoked'] or counts['changed'] or counts['restored'] or counts['held_back']:
                    log.info('directory recheck: %s', counts)
            except ldap.LdapError as e:
                log.warning('directory recheck got no clear answer, so changed nothing: %s', e)
        self.last_run = datetime.now(timezone.utc)

    async def loop(self) -> None:
        while True:
            try:
                await self.run_once()
                self.last_error = None
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.last_error = f'{type(e).__name__}: {e}'
                log.exception('maintenance failed')
            # Directory rechecks may be due more often than the hourly prune
            interval = min(self.every_seconds, get_settings().ldap_recheck_minutes * 60)
            await asyncio.sleep(interval)

    def start(self) -> None:
        self._task = asyncio.create_task(self.loop(), name='maintenance')

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
