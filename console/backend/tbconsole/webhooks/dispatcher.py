"""Sends queued deliveries, retrying with backoff until they land or run out.

Deliveries wait in Postgres, so a restart loses none, and are claimed with
SELECT ... FOR UPDATE SKIP LOCKED, so any number of console processes can run
the dispatcher without two sending the same one. A 2xx is success. A 4xx other
than 408 or 429 is the receiver saying no, and retrying would only be refused
again, so it fails at once. Anything else is retried after 30 seconds, 2, 10
and 30 minutes, then 2 and 6 hours, after which the delivery is dead and can
only be sent again by hand.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import db as database
from ..config import get_settings
from ..models import Webhook, WebhookDelivery
from ..security.crypto import SecretUnreadable, decrypt
from . import formats, safety, signing

log = logging.getLogger(__name__)

BACKOFF = (30, 120, 600, 1800, 7200, 21600)
MAX_ATTEMPTS = len(BACKOFF) + 1
BATCH = 20


def _headers(hook: Webhook, delivery: WebhookDelivery, body: bytes) -> dict:
    headers = {}
    if hook.headers_enc:
        try:
            custom = json.loads(decrypt(hook.headers_enc))
            headers.update({str(k): str(v) for k, v in custom.items()})
        except (SecretUnreadable, ValueError):
            log.warning('webhook %s: custom headers cannot be read; sending without them', hook.id)
    headers.update({
        'Content-Type': 'application/json',
        'User-Agent': 'TurkeyBite-Console-Webhooks/1',
        'X-TurkeyBite-Event': delivery.event,
        'X-TurkeyBite-Delivery': str(delivery.id),
        signing.HEADER: signing.sign(decrypt(hook.secret_enc), body),
    })
    return headers


async def send(http: httpx.AsyncClient, hook: Webhook, delivery: WebhookDelivery) -> dict:
    """One attempt. Returns what happened, for the delivery row."""
    started = time.monotonic()
    outcome: dict = {'status_code': None, 'error': None, 'snippet': None, 'retry': True}
    try:
        await safety.check(hook.url)
        body = json.dumps(formats.render(hook.format, delivery.payload),
                          separators=(',', ':')).encode('utf-8')
        response = await http.post(hook.url, content=body, headers=_headers(hook, delivery, body),
                                   follow_redirects=False)
        outcome['status_code'] = response.status_code
        outcome['snippet'] = response.text[:500]
        if 200 <= response.status_code < 300:
            outcome['retry'] = False
        elif 400 <= response.status_code < 500 and response.status_code not in (408, 429):
            outcome['error'] = f'the receiver refused it with HTTP {response.status_code}'
            outcome['retry'] = False
        else:
            outcome['error'] = f'HTTP {response.status_code}'
    except safety.UnsafeUrl as e:
        outcome['error'] = str(e)
        outcome['retry'] = False
    except SecretUnreadable as e:
        outcome['error'] = str(e)
        outcome['retry'] = False
    except httpx.HTTPError as e:
        outcome['error'] = f'{type(e).__name__}: {e}'
    outcome['duration_ms'] = int((time.monotonic() - started) * 1000)
    return outcome


def apply(delivery: WebhookDelivery, hook: Webhook, outcome: dict, now: datetime) -> None:
    delivery.attempts += 1
    delivery.last_status_code = outcome['status_code']
    delivery.last_error = outcome['error']
    delivery.response_snippet = outcome['snippet']
    delivery.duration_ms = outcome['duration_ms']
    hook.last_delivery_at = now
    if outcome['error'] is None:
        delivery.status = 'succeeded'
        delivery.delivered_at = now
        delivery.next_attempt_at = None
        hook.last_status = 'succeeded'
        hook.failure_streak = 0
        return
    hook.last_status = 'failed'
    hook.failure_streak += 1
    if outcome['retry'] and delivery.attempts < MAX_ATTEMPTS:
        delivery.status = 'failed'
        delivery.next_attempt_at = now + timedelta(seconds=BACKOFF[delivery.attempts - 1])
    else:
        delivery.status = 'dead'
        delivery.next_attempt_at = None


async def claim(db: AsyncSession, now: datetime) -> list[WebhookDelivery]:
    """Takes up to BATCH due deliveries, leasing them so no one else sends them.

    The lease is the next attempt time pushed past how long a send can take.
    If this process dies mid-send, the lease lapses and another sends it
    again, which is why receivers are told the delivery id: a delivery can
    arrive twice, never not at all.
    """
    rows = (await db.execute(
        select(WebhookDelivery)
        .where(WebhookDelivery.status.in_(('pending', 'failed')),
               WebhookDelivery.next_attempt_at <= now)
        .order_by(WebhookDelivery.next_attempt_at)
        .limit(BATCH)
        .with_for_update(skip_locked=True))).scalars().all()
    lease = now + timedelta(seconds=get_settings().webhook_timeout_sec * 3 + 30)
    for row in rows:
        row.next_attempt_at = lease
    return list(rows)


async def run_once(http: httpx.AsyncClient) -> int:
    """Sends what is due. Returns how many attempts were made."""
    sessions = database.sessionmaker()
    async with sessions() as db:
        async with db.begin():
            due = await claim(db, datetime.now(timezone.utc))
            hooks = {h.id: h for h in (await db.execute(
                select(Webhook).where(Webhook.id.in_({d.webhook_id for d in due})))).scalars()} if due else {}
    if not due:
        return 0
    # Sent outside any transaction, so a slow receiver holds no lock
    sendable = [d for d in due if d.webhook_id in hooks]
    results = await asyncio.gather(*[send(http, hooks[d.webhook_id], d) for d in sendable])
    async with sessions() as db:
        async with db.begin():
            for delivery, outcome in zip(sendable, results):
                row = await db.get(WebhookDelivery, delivery.id, with_for_update=True)
                hook = await db.get(Webhook, delivery.webhook_id)
                if row is None or hook is None:
                    continue
                apply(row, hook, outcome, datetime.now(timezone.utc))
    return len(sendable)


async def redeliver(db: AsyncSession, delivery: WebhookDelivery) -> WebhookDelivery:
    """A fresh copy of a delivery, queued now. The original keeps its history."""
    copy = WebhookDelivery(webhook_id=delivery.webhook_id, event=delivery.event,
                           finding_id=delivery.finding_id, payload=delivery.payload,
                           status='pending', next_attempt_at=datetime.now(timezone.utc))
    db.add(copy)
    return copy


class Dispatcher:
    def __init__(self, poll_seconds: float = 2.0):
        self.poll_seconds = poll_seconds
        self.http = httpx.AsyncClient(timeout=get_settings().webhook_timeout_sec)
        self._task: asyncio.Task | None = None
        self.last_tick: datetime | None = None

    async def loop(self) -> None:
        while True:
            try:
                sent = await run_once(self.http)
                self.last_tick = datetime.now(timezone.utc)
                if sent:
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception('webhook dispatcher pass failed')
            await asyncio.sleep(self.poll_seconds)

    def start(self) -> None:
        self._task = asyncio.create_task(self.loop(), name='webhook-dispatcher')

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.http.aclose()


async def pending_count() -> int:
    async with database.sessionmaker()() as db:
        return int((await db.execute(select(func.count()).select_from(WebhookDelivery).where(
            WebhookDelivery.status.in_(('pending', 'failed'))))).scalar_one())

