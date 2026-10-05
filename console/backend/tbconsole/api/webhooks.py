"""Webhooks and their deliveries."""

import json
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..analysis.ruletypes import SEVERITIES
from ..db import get_session
from ..deps import Principal, require
from ..models import Webhook, WebhookDelivery
from ..security import crypto, rbac
from ..webhooks import dispatcher, formats, safety, signing
from ..webhooks.service import event_body
from .common import delivery_out, parse_uuid, webhook_out

router = APIRouter(tags=['webhooks'])

SAFE_HEADER = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
RESERVED_HEADERS = {'content-type', 'content-length', 'host', 'user-agent',
                    'x-turkeybite-signature', 'x-turkeybite-event', 'x-turkeybite-delivery'}


class WebhookBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=8, max_length=2000)
    format: str = 'json'
    events: list[str] = Field(default_factory=lambda: ['finding.created'])
    all_findings: bool = False
    min_severity: str = 'high'
    redact_entities: bool = False
    enabled: bool = True
    # None keeps the headers already saved; {} removes them
    headers: dict[str, str] | None = None


async def _validate(body: WebhookBody) -> None:
    if body.format not in formats.FORMATS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f'format is one of {", ".join(formats.FORMATS)}')
    unknown = set(body.events) - set(formats.EVENTS)
    if unknown or not body.events:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f'events are some of {", ".join(formats.EVENTS)}')
    if body.min_severity not in SEVERITIES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f'min_severity is one of {", ".join(SEVERITIES)}')
    for name, value in (body.headers or {}).items():
        if not name or any(ch not in SAFE_HEADER for ch in name) or name.lower() in RESERVED_HEADERS:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f'{name!r} cannot be a custom header')
        if '\n' in value or '\r' in value or len(value) > 4000:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f'The value of {name} is not allowed')
    try:
        await safety.check(body.url)
    except safety.UnsafeUrl as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e


async def _get(db: AsyncSession, webhook_id: str) -> Webhook:
    hook = await db.get(Webhook, parse_uuid(webhook_id, 'That webhook'))
    if hook is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That webhook does not exist')
    return hook


@router.get('/webhooks/meta')
async def meta(_: Principal = Depends(require(rbac.WEBHOOKS_READ))) -> dict:
    return {'formats': formats.FORMATS, 'events': formats.EVENTS, 'severities': list(SEVERITIES),
            'signature_header': signing.HEADER, 'tolerance_seconds': signing.TOLERANCE_SECONDS}


@router.get('/webhooks')
async def list_webhooks(_: Principal = Depends(require(rbac.WEBHOOKS_READ)),
                        db: AsyncSession = Depends(get_session)) -> list[dict]:
    hooks = (await db.execute(select(Webhook).order_by(Webhook.name))).scalars().all()
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    counts = (await db.execute(
        select(WebhookDelivery.webhook_id, WebhookDelivery.status, func.count())
        .where(WebhookDelivery.created_at >= since)
        .group_by(WebhookDelivery.webhook_id, WebhookDelivery.status))).all()
    stats: dict = {}
    for hook_id, state, count in counts:
        stats.setdefault(hook_id, {})[state] = count
    out = []
    for hook in hooks:
        item = webhook_out(hook)
        item['last_24h'] = stats.get(hook.id, {})
        out.append(item)
    return out


@router.post('/webhooks', status_code=status.HTTP_201_CREATED)
async def create_webhook(body: WebhookBody, request: Request,
                         principal: Principal = Depends(require(rbac.WEBHOOKS_WRITE)),
                         db: AsyncSession = Depends(get_session)) -> dict:
    await _validate(body)
    secret = signing.new_secret()
    hook = Webhook(name=body.name.strip(), url=body.url.strip(), format=body.format,
                   secret_enc=crypto.encrypt(secret), events=body.events,
                   all_findings=body.all_findings, min_severity=body.min_severity,
                   redact_entities=body.redact_entities, enabled=body.enabled,
                   created_by_id=principal.user.id,
                   headers_enc=crypto.encrypt(json.dumps(body.headers)) if body.headers else None)
    db.add(hook)
    await db.flush()
    audit.record(db, 'webhook.create', principal=principal, request=request,
                 target_type='webhook', target_id=hook.id, target_label=hook.name)
    await db.commit()
    await db.refresh(hook)
    # The secret is shown this once; afterwards it can only be replaced
    return {**webhook_out(hook), 'secret': secret}


@router.get('/webhooks/{webhook_id}')
async def get_webhook(webhook_id: str, _: Principal = Depends(require(rbac.WEBHOOKS_READ)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    hook = await _get(db, webhook_id)
    out = webhook_out(hook)
    if hook.headers_enc:
        try:
            out['header_names'] = sorted(json.loads(crypto.decrypt(hook.headers_enc)))
        except (crypto.SecretUnreadable, ValueError):
            out['header_names'] = []
    return out


@router.put('/webhooks/{webhook_id}')
async def update_webhook(webhook_id: str, body: WebhookBody, request: Request,
                         principal: Principal = Depends(require(rbac.WEBHOOKS_WRITE)),
                         db: AsyncSession = Depends(get_session)) -> dict:
    hook = await _get(db, webhook_id)
    await _validate(body)
    hook.name = body.name.strip()
    hook.url = body.url.strip()
    hook.format = body.format
    hook.events = body.events
    hook.all_findings = body.all_findings
    hook.min_severity = body.min_severity
    hook.redact_entities = body.redact_entities
    hook.enabled = body.enabled
    if body.headers is not None:
        hook.headers_enc = crypto.encrypt(json.dumps(body.headers)) if body.headers else None
    audit.record(db, 'webhook.update', principal=principal, request=request,
                 target_type='webhook', target_id=hook.id, target_label=hook.name)
    await db.commit()
    await db.refresh(hook)
    return webhook_out(hook)


@router.delete('/webhooks/{webhook_id}')
async def delete_webhook(webhook_id: str, request: Request,
                         principal: Principal = Depends(require(rbac.WEBHOOKS_WRITE)),
                         db: AsyncSession = Depends(get_session)) -> dict:
    hook = await _get(db, webhook_id)
    audit.record(db, 'webhook.delete', principal=principal, request=request,
                 target_type='webhook', target_id=hook.id, target_label=hook.name)
    await db.delete(hook)
    await db.commit()
    return {'ok': True}


@router.post('/webhooks/{webhook_id}/rotate-secret')
async def rotate_secret(webhook_id: str, request: Request,
                        principal: Principal = Depends(require(rbac.WEBHOOKS_WRITE)),
                        db: AsyncSession = Depends(get_session)) -> dict:
    hook = await _get(db, webhook_id)
    secret = signing.new_secret()
    hook.secret_enc = crypto.encrypt(secret)
    audit.record(db, 'webhook.rotate_secret', principal=principal, request=request,
                 target_type='webhook', target_id=hook.id, target_label=hook.name)
    await db.commit()
    return {'secret': secret}


@router.post('/webhooks/{webhook_id}/test')
async def test_webhook(webhook_id: str, request: Request,
                       principal: Principal = Depends(require(rbac.WEBHOOKS_WRITE)),
                       db: AsyncSession = Depends(get_session)) -> dict:
    """Sends a test delivery now and says what the receiver answered."""
    hook = await _get(db, webhook_id)
    delivery = WebhookDelivery(
        webhook_id=hook.id, event='test', status='pending',
        payload=event_body('test', message=f'{principal.user.username} sent a test from the '
                                           'TurkeyBite Console. If you can read this, the webhook works.'))
    db.add(delivery)
    await db.flush()
    async with httpx.AsyncClient(timeout=10) as http:
        outcome = await dispatcher.send(http, hook, delivery)
    dispatcher.apply(delivery, hook, outcome, datetime.now(timezone.utc))
    # A test is not retried: its result is the answer
    if delivery.status == 'failed':
        delivery.status = 'dead'
        delivery.next_attempt_at = None
    audit.record(db, 'webhook.test', principal=principal, request=request,
                 target_type='webhook', target_id=hook.id, target_label=hook.name,
                 outcome='success' if delivery.status == 'succeeded' else 'failure')
    await db.commit()
    return delivery_out(delivery, full=True)


@router.get('/webhooks/{webhook_id}/deliveries')
async def deliveries(webhook_id: str, state: str | None = None, limit: int = 50,
                     _: Principal = Depends(require(rbac.WEBHOOKS_READ)),
                     db: AsyncSession = Depends(get_session)) -> list[dict]:
    hook = await _get(db, webhook_id)
    stmt = select(WebhookDelivery).where(WebhookDelivery.webhook_id == hook.id)
    if state:
        stmt = stmt.where(WebhookDelivery.status == state)
    rows = (await db.execute(stmt.order_by(WebhookDelivery.created_at.desc())
                             .limit(max(1, min(limit, 200))))).scalars().all()
    return [delivery_out(d) for d in rows]


@router.get('/webhook-deliveries')
async def all_deliveries(state: str | None = None, limit: int = 50,
                         _: Principal = Depends(require(rbac.WEBHOOKS_READ)),
                         db: AsyncSession = Depends(get_session)) -> list[dict]:
    stmt = select(WebhookDelivery)
    if state:
        stmt = stmt.where(WebhookDelivery.status == state)
    rows = (await db.execute(stmt.order_by(WebhookDelivery.created_at.desc())
                             .limit(max(1, min(limit, 200))))).scalars().all()
    return [delivery_out(d) for d in rows]


@router.get('/webhook-deliveries/{delivery_id}')
async def get_delivery(delivery_id: str, _: Principal = Depends(require(rbac.WEBHOOKS_READ)),
                       db: AsyncSession = Depends(get_session)) -> dict:
    delivery = await db.get(WebhookDelivery, parse_uuid(delivery_id, 'That delivery'))
    if delivery is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That delivery does not exist')
    out = delivery_out(delivery, full=True)
    hook = await db.get(Webhook, delivery.webhook_id)
    if hook is not None:
        out['rendered'] = formats.render(hook.format, delivery.payload)
    return out


@router.post('/webhook-deliveries/{delivery_id}/redeliver')
async def redeliver(delivery_id: str, request: Request,
                    principal: Principal = Depends(require(rbac.WEBHOOKS_WRITE)),
                    db: AsyncSession = Depends(get_session)) -> dict:
    delivery = await db.get(WebhookDelivery, parse_uuid(delivery_id, 'That delivery'))
    if delivery is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That delivery does not exist')
    copy = await dispatcher.redeliver(db, delivery)
    audit.record(db, 'webhook.redeliver', principal=principal, request=request,
                 target_type='delivery', target_id=delivery.id)
    await db.commit()
    return delivery_out(copy)
