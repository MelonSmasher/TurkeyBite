"""Reading the audit log."""

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..deps import Principal, require
from ..models import AuditEvent
from ..security import rbac
from .common import like_escape, moment_param, ts

router = APIRouter(prefix='/audit', tags=['audit'])


@router.get('')
async def list_events(action: str | None = None, actor: str | None = None,
                      outcome: str | None = None, q: str | None = None,
                      before: str | None = None, limit: int = 100,
                      _: Principal = Depends(require(rbac.AUDIT_READ)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    stmt = select(AuditEvent)
    if action:
        stmt = stmt.where(AuditEvent.action.like(like_escape(action[:100]).replace('*', '%'), escape='\\'))
    if actor:
        stmt = stmt.where(AuditEvent.actor_name.ilike(f'%{like_escape(actor[:100])}%', escape='\\'))
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if q:
        like = f'%{like_escape(q[:200])}%'
        stmt = stmt.where(or_(AuditEvent.target_label.ilike(like, escape='\\'),
                              AuditEvent.target_id.ilike(like, escape='\\'),
                              AuditEvent.actor_name.ilike(like, escape='\\'),
                              AuditEvent.action.ilike(like, escape='\\')))
    if before:
        stmt = stmt.where(AuditEvent.at < moment_param(before, 'before'))
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
