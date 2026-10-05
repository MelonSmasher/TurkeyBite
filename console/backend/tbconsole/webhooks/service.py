"""Queueing deliveries. The dispatcher sends them; this decides what and where."""

import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..analysis.ruletypes import SEVERITY_RANK
from ..config import get_settings
from ..models import Finding, Rule, Webhook, WebhookDelivery
from ..security import crypto


def display_url(url: str) -> str:
    """Where a webhook goes, without the path or query that may carry its credential."""
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = (parts.hostname or '') + (f':{port}' if port else '')
    tail = '/…' if (parts.path not in ('', '/') or parts.query) else '/'
    return f'{parts.scheme}://{netloc}{tail}'[:400]


def set_url(hook: Webhook, url: str) -> None:
    hook.url_enc = crypto.encrypt(url)
    hook.url_display = display_url(url)


def url_of(hook: Webhook) -> str:
    return crypto.decrypt(hook.url_enc)


_URL = re.compile(r'\b[a-z][a-z0-9+.-]*://\S+', re.IGNORECASE)
_ADDRESS = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\[[0-9a-f:]+\](?::\d+)?', re.IGNORECASE)


def public_error(error: str | None) -> str | None:
    """A rule's error as it may leave the console: without the addresses of
    the cluster or anything else on the inside, and short. The whole error is
    on the rule's page."""
    if not error:
        return error
    text = _ADDRESS.sub('[address]', _URL.sub('[url]', error))
    return text if len(text) <= 300 else text[:299] + '…'


def finding_url(finding: Finding) -> str:
    return f'{get_settings().public_url}/findings/{finding.id}'


def finding_body(finding: Finding, redact: bool = False) -> dict:
    """A finding as webhooks and the API describe it to the outside."""
    evidence = finding.evidence or {}
    body = {
        'id': str(finding.id), 'number': finding.number, 'title': finding.title,
        'summary': finding.summary, 'severity': finding.severity, 'status': finding.status,
        'category': finding.category, 'rule_id': str(finding.rule_id) if finding.rule_id else None,
        'rule_name': finding.rule_name, 'rule_type': finding.rule_type,
        'entity_field': finding.entity_field, 'entity': finding.entity_value,
        'first_seen': finding.first_seen.isoformat(), 'last_seen': finding.last_seen.isoformat(),
        'event_count': finding.event_count, 'occurrences': finding.occurrences,
        'top_domains': evidence.get('top_domains', []),
        'top_categories': evidence.get('top_categories', []),
        'tags': finding.tags,
    }
    if redact:
        # Who it is about stays in the console, where viewing it is audited
        entity = finding.entity_value or ''
        body['entity'] = '[redacted]' if entity else None
        if entity:
            body['title'] = body['title'].replace(entity, '[redacted]')
            body['summary'] = body['summary'].replace(entity, '[redacted]')
    return body


def event_body(event: str, finding: Finding | None = None, redact: bool = False,
               rule: Rule | None = None, message: str = '') -> dict:
    body: dict = {
        'event': event, 'id': str(uuid.uuid4()),
        'occurred_at': datetime.now(timezone.utc).isoformat(), 'source': 'turkeybite-console',
    }
    if finding is not None:
        body['finding'] = finding_body(finding, redact)
        body['url'] = finding_url(finding)
    if rule is not None:
        body['rule'] = {'id': str(rule.id), 'name': rule.name,
                        'last_error': public_error(rule.last_error),
                        'consecutive_failures': rule.consecutive_failures}
        body['url'] = f'{get_settings().public_url}/rules/{rule.id}'
    if message:
        body['message'] = message
    return body


async def targets(db: AsyncSession, event: str, severity: str | None,
                  rule: Rule | None) -> list[Webhook]:
    """The enabled webhooks subscribed to `event` that this finding should reach."""
    clauses = [Webhook.all_findings.is_(True)]
    named = [uuid.UUID(str(i)) for i in (rule.webhook_ids if rule is not None else []) or []]
    if named:
        clauses.append(Webhook.id.in_(named))
    hooks = (await db.execute(select(Webhook).where(Webhook.enabled.is_(True), or_(*clauses)))).scalars().all()
    chosen = []
    for hook in hooks:
        if event not in (hook.events or []):
            continue
        if hook.id in named:
            chosen.append(hook)
        elif severity is None or SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(hook.min_severity, 0):
            chosen.append(hook)
    return chosen


async def enqueue_finding(db: AsyncSession, event: str, finding: Finding,
                          rule: Rule | None) -> int:
    """Queues `event` about `finding` for every webhook that wants it. Returns how many."""
    hooks = await targets(db, event, finding.severity, rule)
    for hook in hooks:
        db.add(WebhookDelivery(webhook_id=hook.id, event=event, finding_id=finding.id,
                               payload=event_body(event, finding, hook.redact_entities),
                               status='pending', next_attempt_at=datetime.now(timezone.utc)))
    return len(hooks)


async def enqueue_rule_failing(db: AsyncSession, rule: Rule) -> int:
    hooks = (await db.execute(select(Webhook).where(Webhook.enabled.is_(True)))).scalars().all()
    count = 0
    for hook in hooks:
        if 'rule.failing' in (hook.events or []):
            db.add(WebhookDelivery(webhook_id=hook.id, event='rule.failing',
                                   payload=event_body('rule.failing', rule=rule),
                                   status='pending', next_attempt_at=datetime.now(timezone.utc)))
            count += 1
    return count
