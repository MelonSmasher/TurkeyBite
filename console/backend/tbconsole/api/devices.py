"""Device lookup: what another system's inventories know about a device, asked by signed webhook.

An admin points it at a system that answers, such as the Security Alert
Console's device lookup, and chooses the webhook whose secret and custom
headers sign the question, so the other side knows the console as it does
from that webhook's deliveries. Someone working a finding then sees where a
machine is plugged in and who last used it here, without going there.
"""

import ipaddress
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit, settings_store
from ..db import get_session
from ..deps import Principal, require
from ..models import Webhook
from ..search.timerange import iso
from ..security import rbac
from ..webhooks import dispatcher

router = APIRouter(prefix='/devices', tags=['devices'])

# Lookups a minute for one person, in this process: each asks every inventory
# the other side has
PER_MINUTE = 20
_asked: dict[str, deque] = defaultdict(deque)
# The most of each part of an answer that is kept
MAX_INVENTORIES = 12
MAX_RECORDS = 10
MAX_FACTS = 30


class LookupBody(BaseModel):
    """The address to look up."""

    address: str = Field(min_length=1, max_length=64)


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _text(value, limit: int = 300) -> str:
    return '' if value is None else str(value)[:limit]


def _link(value) -> str:
    """A link from the answer, only if it is an http(s) one."""
    if not isinstance(value, str) or len(value) > 2000:
        return ''
    return value if urlsplit(value).scheme in ('http', 'https') else ''


def _count(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _record(record: dict) -> dict:
    facts = [[_text(f[0], 80), _text(f[1])] for f in _list(record.get('facts'))[:MAX_FACTS]
             if isinstance(f, (list, tuple)) and len(f) == 2]
    return {'title': _text(record.get('title'), 200), 'subtitle': _text(record.get('subtitle'), 200),
            'facts': facts, 'link': _link(record.get('link'))}


def _clean(answer: dict, asked: str) -> dict:
    """The answer in the shape the app shows, holding nothing but text, numbers and http(s) links.

    It comes from another system, so nothing in it is taken as it is.
    """
    inventories = []
    for card in _list(answer.get('inventories'))[:MAX_INVENTORIES]:
        if not isinstance(card, dict):
            continue
        records = [_record(r) for r in _list(card.get('records'))[:MAX_RECORDS] if isinstance(r, dict)]
        inventories.append({
            'name': _text(card.get('name'), 80), 'configured': bool(card.get('configured', True)),
            'asks': bool(card.get('asks', True)), 'found': bool(card.get('found')) or bool(records),
            'records': records, 'note': _text(card.get('note')), 'problem': _text(card.get('problem')),
        })
    alerts = answer.get('alerts') if isinstance(answer.get('alerts'), dict) else {}
    link = answer.get('link')
    # A path is on the system that answered
    link = _link(urljoin(asked, link)) if isinstance(link, str) and link.startswith('/') else _link(link)
    return {'inventories': inventories,
            'alerts': {'count': _count(alerts.get('count')), 'open': _count(alerts.get('open'))},
            'link': link}


def _limited(who: str) -> bool:
    now = time.monotonic()
    asked = _asked[who]
    while asked and asked[0] < now - 60:
        asked.popleft()
    if len(asked) >= PER_MINUTE:
        return True
    asked.append(now)
    return False


@router.post('/lookup')
async def lookup(body: LookupBody, request: Request,
                 principal: Principal = Depends(require(rbac.FINDINGS_WRITE)),
                 db: AsyncSession = Depends(get_session)) -> dict:
    """What another system's inventories know about the device at an address.

    Asked by signed webhook of the system an admin set up, such as a security
    console: where the device is plugged in, who last used it, and the like,
    inventory by inventory. Each lookup is written to the audit log.
    """
    try:
        address = str(ipaddress.ip_address(body.address.strip()))
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Device lookup takes an IP address.') from e
    general = await settings_store.general(db)
    url, hook_id = general.get('device_lookup_url') or '', general.get('device_lookup_webhook_id') or ''
    if not url or not hook_id:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            'Device lookup is not set up. An admin can set it up under Authentication.')
    try:
        hook = await db.get(Webhook, uuid.UUID(hook_id))
    except ValueError:
        hook = None
    if hook is None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            'The webhook device lookup signs with no longer exists. An admin can choose '
                            'another under Authentication.')
    if _limited(str(principal.user.id)):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f'At most {PER_MINUTE} device lookups a minute. Try again shortly.')
    # On the record before the question goes, and the database connection
    # back in the pool while the other side answers
    audit.record(db, 'device.lookup', principal=principal, request=request, target_type='bite.client',
                 target_id=address, target_label=address)
    await db.commit()
    payload = {'event': 'device.lookup', 'id': str(uuid.uuid4()), 'address': address,
               'requested_by': principal.user.username, 'occurred_at': iso(datetime.now(timezone.utc))}
    try:
        answer = await dispatcher.ask(hook, url, 'device.lookup', payload)
    except dispatcher.AskFailed as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f'The device lookup got no answer: {e}.') from e
    return {'address': address, **_clean(answer, url)}
