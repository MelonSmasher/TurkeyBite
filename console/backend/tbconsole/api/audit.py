"""Reading the audit log."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..deps import Principal, require
from ..models import AuditEvent
from ..security import rbac
from .common import ts

router = APIRouter(prefix='/audit', tags=['audit'])


@router.get('')
async def list_events(action: str | None = None, actor: str | None = None,
                      outcome: str | None = None, q: str | None = None,
                      before: str | None = None, limit: int = 100,
                      _: Principal = Depends(require(rbac.AUDIT_READ)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    stmt = select(AuditEvent)
    if action:
        stmt = stmt.where(AuditEvent.action.like(action.replace('*', '%')))
    if actor:
        stmt = stmt.where(AuditEvent.actor_name.ilike(f'%{actor[:100]}%'))
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if q:
        like = f'%{q[:200]}%'
        stmt = stmt.where(or_(AuditEvent.target_label.ilike(like), AuditEvent.target_id.ilike(like),
                              AuditEvent.actor_name.ilike(like), AuditEvent.action.ilike(like)))
    if before:
        try:
            stmt = stmt.where(AuditEvent.at < datetime.fromisoformat(before.replace('Z', '+00:00')))
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'before is a time') from e
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(AuditEvent.at.desc(), AuditEvent.id.desc())
                             .limit(max(1, min(limit, 500))))).scalars().all()
    return {'total': total, 'items': [{
        'id': e.id, 'at': ts(e.at), 'actor_type': e.actor_type, 'actor': e.actor_name,
        'action': e.action, 'outcome': e.outcome, 'target_type': e.target_type,
        'target_id': e.target_id, 'target_label': e.target_label, 'ip': e.ip,
        'details': e.details} for e in rows]}


@router.get('/actions')
async def actions(_: Principal = Depends(require(rbac.AUDIT_READ)),
                  db: AsyncSession = Depends(get_session)) -> list[str]:
    return list((await db.execute(select(AuditEvent.action).distinct()
                                  .order_by(AuditEvent.action))).scalars())
