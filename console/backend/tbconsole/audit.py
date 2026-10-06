"""The audit log: who did what, from where.

Sign-ins, failed ones included, every change to users, keys, rules, webhooks
and settings, exports, and every look at one person's or machine's profile.
TurkeyBite records what people look up; the console records who looked at
that, so the watching is watched too.
"""

import time

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditEvent
from .security.sessions import client_ip


def record(db: AsyncSession, action: str, *, principal=None, actor_name: str | None = None,
           actor_type: str | None = None, actor_id=None, request: Request | None = None,
           target_type: str | None = None, target_id=None, target_label: str | None = None,
           outcome: str = 'success', details: dict | None = None) -> AuditEvent:
    """Adds an audit event to the session. The caller commits it with its own change."""
    if principal is not None:
        actor_type = actor_type or principal.kind
        actor_name = actor_name or principal.name
        actor_id = principal.user.id
    event = AuditEvent(
        actor_type=actor_type or 'anonymous', actor_id=actor_id,
        actor_name=(actor_name or 'anonymous')[:200], action=action, outcome=outcome,
        target_type=target_type, target_id=str(target_id)[:200] if target_id is not None else None,
        target_label=(target_label or '')[:400] or None,
        ip=client_ip(request) if request is not None else None,
        details=details or {})
    db.add(event)
    return event


# Looks recorded lately, per person, so a screen that asks the same question
# of several endpoints at once (the events, their histogram) is one row
_LOOK_WINDOW = 60.0
_looks: dict[tuple, float] = {}


def look(db: AsyncSession, action: str, *, principal, request: Request | None, key: str,
         details: dict | None = None, target_type: str | None = None) -> bool:
    """Records a look at people, such as a search that names someone, unless
    the same person recorded the same look in the last minute. True if it did."""
    now = time.monotonic()
    marker = (str(principal.user.id), action, key)
    if now - _looks.get(marker, float('-inf')) < _LOOK_WINDOW:
        return False
    if len(_looks) > 10000:
        for k in [k for k, at in _looks.items() if now - at >= _LOOK_WINDOW]:
            del _looks[k]
    _looks[marker] = now
    record(db, action, principal=principal, request=request, target_type=target_type,
           details=details)
    return True
