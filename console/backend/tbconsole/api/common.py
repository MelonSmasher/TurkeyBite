"""Helpers the routes share: ranges, risk scores, and how records are shown."""

import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analysis import engine
from ..models import ApiKey, Dashboard, Finding, Rule, SavedSearch, User, Webhook, WebhookDelivery
from ..search import fields as F
from ..search.timerange import RangeError, TimeRange, iso, parse_moment, parse_range

SEVERITY_WEIGHT = {'critical': 40, 'high': 20, 'medium': 8, 'low': 3, 'info': 1}


def time_range(start: str | None, end: str | None, default: str = 'now-24h') -> TimeRange:
    try:
        return parse_range(start, end, default_start=default)
    except RangeError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e


def moment_param(text: str, name: str) -> datetime:
    """An ISO 8601 time from a request, in UTC, or a 400 saying which."""
    try:
        return parse_moment(text)
    except RangeError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'{name}: {e}') from e


def like_escape(text: str) -> str:
    """`text` for a LIKE pattern, matched literally: % and _ are not wildcards."""
    return text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def not_found(what: str = 'That') -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f'{what} does not exist, or you cannot see it')


def parse_uuid(value: str, what: str = 'That') -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except ValueError as e:
        raise not_found(what) from e


def ts(value: datetime | None) -> str | None:
    return iso(value) if value else None


async def risk_scores(db: AsyncSession, entities: list[str] | None = None) -> dict[str, dict]:
    """A 0 to 100 score per entity from its open findings, heaviest first.

    Severity-weighted and capped. Kept simple on purpose: a score people can
    explain is one they will trust, and the findings behind it are a click away.
    """
    stmt = (select(Finding.entity_value, Finding.severity, func.count())
            .where(Finding.status.in_(engine.OPEN), Finding.entity_value.is_not(None))
            .group_by(Finding.entity_value, Finding.severity))
    if entities is not None:
        if not entities:
            return {}
        stmt = stmt.where(Finding.entity_value.in_(entities))
    scores: dict[str, dict] = {}
    for entity, severity, count in (await db.execute(stmt)).all():
        item = scores.setdefault(entity, {'score': 0, 'findings': 0, 'by_severity': {}})
        item['score'] += SEVERITY_WEIGHT.get(severity, 1) * count
        item['findings'] += count
        item['by_severity'][severity] = item['by_severity'].get(severity, 0) + count
    for item in scores.values():
        item['score'] = min(100, item['score'])
    return scores


# -- how records are shown ---------------------------------------------------------

def user_out(user: User, full: bool = False) -> dict:
    out = {'id': str(user.id), 'username': user.username,
           'display_name': user.display_name or user.username, 'role': user.role,
           'source': user.source}
    if full:
        out.update({
            'email': user.email, 'disabled': user.disabled,
            'disabled_reason': user.disabled_reason, 'mfa_enabled': user.totp_enabled,
            'locked': bool(user.locked_until and user.locked_until > datetime.now(timezone.utc)),
            'locked_until': ts(user.locked_until), 'last_login_at': ts(user.last_login_at),
            'created_at': ts(user.created_at), 'ldap_dn': user.ldap_dn,
            'failed_logins': user.failed_logins,
            'directory_checked_at': ts(user.directory_checked_at),
        })
    return out


def finding_out(f: Finding) -> dict:
    return {
        'id': str(f.id), 'number': f.number, 'rule_id': str(f.rule_id) if f.rule_id else None,
        'rule_name': f.rule_name, 'rule_type': f.rule_type, 'category': f.category,
        'severity': f.severity, 'status': f.status, 'title': f.title, 'summary': f.summary,
        'entity_field': f.entity_field, 'entity': f.entity_value, 'first_seen': ts(f.first_seen),
        'last_seen': ts(f.last_seen), 'event_count': f.event_count, 'occurrences': f.occurrences,
        'evidence': f.evidence or {}, 'tags': f.tags or [],
        'assignee': user_out(f.assignee) if f.assignee else None,
        'resolved_at': ts(f.resolved_at), 'snoozed_until': ts(f.snoozed_until),
        'created_at': ts(f.created_at), 'updated_at': ts(f.updated_at),
    }


def rule_out(r: Rule) -> dict:
    return {
        'id': str(r.id), 'builtin_key': r.builtin_key, 'builtin': r.builtin_key is not None,
        'builtin_version': r.builtin_version, 'modified': r.modified,
        'update_available': engine.update_available(r), 'name': r.name,
        'description': r.description, 'category': r.category, 'type': r.type, 'query': r.query,
        'params': r.params or {}, 'group_by': r.group_by or [], 'severity': r.severity,
        'enabled': r.enabled, 'interval_seconds': r.interval_seconds,
        'window_seconds': r.window_seconds, 'dedup_seconds': r.dedup_seconds,
        'schedule': r.schedule, 'exceptions': r.exceptions or [],
        'webhook_ids': [str(i) for i in r.webhook_ids or []], 'tags': r.tags or [],
        'title_template': r.title_template, 'last_run_at': ts(r.last_run_at),
        'next_run_at': ts(r.next_run_at), 'last_status': r.last_status,
        'last_error': r.last_error, 'last_duration_ms': r.last_duration_ms,
        'last_hits': r.last_hits, 'consecutive_failures': r.consecutive_failures,
        'created_at': ts(r.created_at), 'updated_at': ts(r.updated_at),
    }


def webhook_out(w: Webhook, reveal: bool = False) -> dict:
    """A webhook. Its full URL, which for a chat service is its credential,
    only for those who can change it."""
    from ..webhooks.service import url_of
    try:
        url = url_of(w) if reveal else w.url_display
    except Exception:
        url = w.url_display
    return {
        'id': str(w.id), 'name': w.name, 'url': url, 'url_display': w.url_display,
        'format': w.format,
        'events': w.events or [], 'all_findings': w.all_findings, 'min_severity': w.min_severity,
        'redact_entities': w.redact_entities, 'enabled': w.enabled,
        'has_headers': bool(w.headers_enc), 'last_status': w.last_status,
        'last_delivery_at': ts(w.last_delivery_at), 'failure_streak': w.failure_streak,
        'created_at': ts(w.created_at), 'updated_at': ts(w.updated_at),
    }


def _delivery_names(d: WebhookDelivery) -> list[str]:
    """The people and machines a delivery names: who its finding is about,
    when that is a person or machine and not, say, a domain, and a new value
    that is one. Not what redaction already replaced."""
    finding = (d.payload or {}).get('finding') or {}
    names = []
    field = F.BY_NAME.get(finding.get('entity_field') or '')
    if finding.get('entity') and field is not None and field.identity:
        names.append(str(finding['entity']))
    new_value = finding.get('new_value') or {}
    if new_value.get('identity') and new_value.get('value') is not None:
        names.append(str(new_value['value']))
    return [n for n in names if n != '[redacted]']


def delivery_out(d: WebhookDelivery, full: bool = False, about: bool = True) -> dict:
    """A delivery. What it says about a finding, its title and who it is
    about, only with `about`, for those who may read findings."""
    out = {
        'id': str(d.id), 'webhook_id': str(d.webhook_id), 'event': d.event,
        'finding_id': str(d.finding_id) if d.finding_id else None, 'status': d.status,
        'attempts': d.attempts, 'next_attempt_at': ts(d.next_attempt_at),
        'last_status_code': d.last_status_code, 'last_error': d.last_error,
        'duration_ms': d.duration_ms, 'created_at': ts(d.created_at),
        'delivered_at': ts(d.delivered_at),
        'entity': ((d.payload or {}).get('finding') or {}).get('entity') if about else None,
        'entity_field': ((d.payload or {}).get('finding') or {}).get('entity_field') if about else None,
        # Every person or machine the delivery names, for the app to mask
        'names': _delivery_names(d) if about else [],
        'title': (((d.payload or {}).get('finding') or {}).get('title') if about else None)
        or ((d.payload or {}).get('rule') or {}).get('name') or (d.payload or {}).get('message'),
    }
    if full:
        out['payload'] = d.payload
    return out


def apikey_out(k: ApiKey) -> dict:
    now = datetime.now(timezone.utc)
    state = 'active'
    if k.revoked_at:
        state = 'revoked'
    elif k.expires_at and k.expires_at <= now:
        state = 'expired'
    return {
        'id': str(k.id), 'name': k.name, 'prefix': k.prefix, 'display': f'tbc_{k.prefix}_…',
        'scopes': k.scopes or [], 'state': state, 'owner': user_out(k.user),
        'created_at': ts(k.created_at), 'expires_at': ts(k.expires_at),
        'last_used_at': ts(k.last_used_at), 'last_used_ip': k.last_used_ip,
        'revoked_at': ts(k.revoked_at),
    }


def dashboard_out(d: Dashboard, me: uuid.UUID | None = None) -> dict:
    return {
        'id': str(d.id), 'name': d.name, 'description': d.description, 'icon': d.icon,
        'widgets': d.widgets or [], 'time_range': d.time_range or {}, 'shared': d.shared,
        'builtin': d.builtin_key is not None, 'owner': user_out(d.owner) if d.owner else None,
        'mine': d.owner_id is not None and d.owner_id == me,
        'created_at': ts(d.created_at), 'updated_at': ts(d.updated_at),
    }


def saved_search_out(s: SavedSearch, me: uuid.UUID | None = None) -> dict:
    return {
        'id': str(s.id), 'name': s.name, 'description': s.description, 'query': s.query,
        'time_range': s.time_range or {}, 'columns': s.columns or [], 'shared': s.shared,
        'pinned': s.pinned, 'owner': user_out(s.owner), 'mine': s.owner_id == me,
        'created_at': ts(s.created_at), 'updated_at': ts(s.updated_at),
    }
