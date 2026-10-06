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
import ssl
import time
from datetime import datetime, timedelta, timezone

import certifi
import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import db as database
from ..config import get_settings
from ..models import Webhook, WebhookDelivery
from ..security.crypto import SecretUnreadable, decrypt
from . import formats, safety, signing
from .service import url_of

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


SNIPPET_BYTES = 600
# Beyond the per-read timeout, how long one whole attempt may take, the name's
# lookup included
DEADLINE_SLACK = 5.0
# Addresses of a name tried in turn, and the least time each has to connect
MAX_ADDRESSES = 4
MIN_CONNECT = 2.0


def _trust() -> ssl.SSLContext | bool:
    """The certificates a receiver's may be signed by: the usual public ones,
    and those in TBCONSOLE_WEBHOOK_CA_CERTS, for a receiver on the LAN with
    an internal CA."""
    extra = get_settings().webhook_ca_certs
    if not extra:
        return True
    context = ssl.create_default_context(cafile=certifi.where())
    context.load_verify_locations(cafile=str(extra))
    return context


def client() -> httpx.AsyncClient:
    """A client for one delivery. It ignores HTTP_PROXY and the like from the
    environment, which would send pinned addresses through a proxy that checks
    certificates against the address; a proxy is used only when
    TBCONSOLE_WEBHOOK_PROXY names one. SSL_CERT_FILE is ignored with them, so
    extra certificates come from TBCONSOLE_WEBHOOK_CA_CERTS instead."""
    settings = get_settings()
    return httpx.AsyncClient(timeout=settings.webhook_timeout_sec, trust_env=False, verify=_trust(),
                             proxy=settings.webhook_proxy or None, follow_redirects=False)


def _words(e: httpx.TransportError) -> tuple[str, bool]:
    """What a transport error means, and whether to retry, in words of our
    own: the library's text can quote what was being sent, header values
    included, and the error is shown to people who may not see those."""
    if isinstance(e, httpx.TimeoutException):
        return 'the receiver did not answer in time', True
    if isinstance(e, httpx.ProxyError):
        return 'the proxy would not pass it on', True
    if isinstance(e, httpx.ConnectError):
        return 'could not connect to the receiver', True
    if isinstance(e, httpx.RemoteProtocolError):
        return 'the receiver broke off, or answered in a way HTTP does not allow', True
    if isinstance(e, httpx.LocalProtocolError):
        return 'the request could not be written as it stands; check the custom headers', False
    return f'the connection failed ({type(e).__name__})', True


async def _post(http: httpx.AsyncClient, target: safety.Target, body: bytes, headers: dict,
                outcome: dict) -> None:
    settings = get_settings()
    # Through a proxy the name goes as it is, and the proxy connects; otherwise
    # each checked address in turn, with the name as Host and TLS server name
    attempts = [None] if settings.webhook_proxy else target.addresses[:MAX_ADDRESSES]
    # An address that does not answer leaves time for the next
    connect = max(MIN_CONNECT, settings.webhook_timeout_sec / len(attempts))
    timeout = httpx.Timeout(settings.webhook_timeout_sec, connect=min(connect, settings.webhook_timeout_sec))
    for i, address in enumerate(attempts):
        url, extensions, sent = target.url, {}, dict(headers)
        # A compressed answer is not unpacked: a few bytes of it can be gigabytes
        sent['Accept-Encoding'] = 'identity'
        if address is not None:
            url = target.url_for(address)
            sent['Host'] = target.host_header
            if target.tls:
                extensions = {'sni_hostname': target.host}
        try:
            async with http.stream('POST', url, content=body, headers=sent, timeout=timeout,
                                   extensions=extensions) as response:
                outcome['status_code'] = response.status_code
                encoding = response.headers.get('content-encoding', 'identity').strip().lower()
                if encoding not in ('', 'identity'):
                    outcome['snippet'] = f'(an answer compressed as {encoding[:20]}, not shown)'
                    return
                # Only the start of the answer is read: a receiver that sends
                # a gigabyte back does not get the console to hold it. Not
                # compressed, so the bytes are as they came
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= SNIPPET_BYTES:
                        break
                outcome['snippet'] = b''.join(chunks)[:SNIPPET_BYTES].decode('utf-8', 'replace')[:300]
            return
        except (httpx.ConnectError, httpx.ConnectTimeout):
            if i == len(attempts) - 1:
                raise


async def send(hook: Webhook, delivery: WebhookDelivery, http: httpx.AsyncClient | None = None) -> dict:
    """One attempt. Returns what happened, for the delivery row. Never raises.

    Connects to an address the safety check resolved, not to whatever the name
    resolves to by then, so a name that changes between the check and the
    request cannot steer the delivery somewhere else. Each delivery has its own
    connection, so one verified for a hook's name is never reused for another
    name that shares its address. The whole attempt has a deadline, so a
    receiver that answers a byte at a time cannot hold the others up.
    """
    started = time.monotonic()
    outcome: dict = {'status_code': None, 'error': None, 'snippet': None, 'retry': True}
    own = http is None
    try:
        if not hook.enabled:
            raise _Permanent('the webhook is disabled')
        body = json.dumps(formats.render(hook.format, delivery.payload),
                          separators=(',', ':')).encode('utf-8')
        headers = _headers(hook, delivery, body)
        http = http or client()

        async def attempt() -> None:
            # The lookup inside the deadline too: a name server that never
            # answers must not hold the batch up any more than a receiver
            target = await safety.resolve(url_of(hook))
            await _post(http, target, body, headers, outcome)
        await asyncio.wait_for(attempt(), timeout=get_settings().webhook_timeout_sec + DEADLINE_SLACK)
        code = outcome['status_code']
        if 200 <= code < 300:
            outcome['retry'] = False
        elif 400 <= code < 500 and code not in (408, 429):
            outcome['error'] = f'the receiver refused it with HTTP {code}'
            outcome['retry'] = False
        else:
            outcome['error'] = f'HTTP {code}'
    except (safety.UnsafeUrl, SecretUnreadable, _Permanent) as e:
        outcome['error'] = str(e)
        outcome['retry'] = False
    except (asyncio.TimeoutError, TimeoutError):
        outcome['error'] = 'the receiver took too long to answer'
    except httpx.TransportError as e:
        outcome['error'], outcome['retry'] = _words(e)
    except Exception as e:
        # A header or URL the HTTP library will not send, or anything else
        # unforeseen: recorded and given up on, never left to stall the batch
        log.warning('webhook %s: delivery %s failed: %s', hook.id, delivery.id, type(e).__name__)
        outcome['error'] = f'could not be sent ({type(e).__name__})'
        outcome['retry'] = False
    finally:
        if own and http is not None:
            await http.aclose()
    outcome['duration_ms'] = int((time.monotonic() - started) * 1000)
    return outcome


class _Permanent(Exception):
    """A delivery that can never succeed as it stands."""


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


async def run_once() -> int:
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
    results = await asyncio.gather(*[send(hooks[d.webhook_id], d) for d in sendable],
                                   return_exceptions=True)
    async with sessions() as db:
        async with db.begin():
            for delivery, outcome in zip(sendable, results):
                if isinstance(outcome, BaseException):
                    outcome = {'status_code': None, 'error': f'could not be sent: {type(outcome).__name__}',
                               'snippet': None, 'retry': False, 'duration_ms': 0}
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
        self._task: asyncio.Task | None = None
        self.last_tick: datetime | None = None

    async def loop(self) -> None:
        while True:
            try:
                sent = await run_once()
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


async def pending_count() -> int:
    async with database.sessionmaker()() as db:
        return int((await db.execute(select(func.count()).select_from(WebhookDelivery).where(
            WebhookDelivery.status.in_(('pending', 'failed'))))).scalar_one())

