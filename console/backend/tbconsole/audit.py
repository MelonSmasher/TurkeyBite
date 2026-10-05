"""The audit log: who did what, from where.

Sign-ins, failed ones included, every change to users, keys, rules, webhooks
and settings, exports, and every look at one person's or machine's profile.
TurkeyBite records what people look up; the console records who looked at
that, so the watching is watched too.
"""

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditEvent


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
        ip=request.client.host if request is not None and request.client else None,
        details=details or {})
    db.add(event)
    return event
