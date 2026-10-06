"""Findings: what the rules raised, and the work of deciding what each one means."""

import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import case, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..analysis import engine
from ..analysis.ruletypes import SEVERITIES, SEVERITY_RANK
from ..db import get_session
from ..deps import Principal, require
from ..models import Finding, FindingActivity, Rule, User, WebhookDelivery
from ..search import queries as Q
from ..search import tbql
from ..search.tbql import quote
from ..security import rbac
from ..webhooks import service as hooks
from .common import delivery_out, finding_out, like_escape, moment_param, parse_uuid, rule_out, ts, user_out

router = APIRouter(prefix='/findings', tags=['findings'])

STATUSES = ('new', 'acknowledged', 'in_progress', 'resolved', 'false_positive')
CLOSED = ('resolved', 'false_positive')
_NUMBER = re.compile(r'(?:[Ff]-?)?(\d{1,9})')


class FindingPatch(BaseModel):
    status: Literal['new', 'acknowledged', 'in_progress', 'resolved', 'false_positive'] | None = None
    assignee_id: str | None = None
    unassign: bool = False
    severity: Literal['info', 'low', 'medium', 'high', 'critical'] | None = None
    snooze_hours: int | None = Field(None, ge=0, le=24 * 30)
    tags: list[str] | None = Field(None, max_length=20)
    note: str = Field('', max_length=4000)


class BulkBody(FindingPatch):
    ids: list[str] = Field(min_length=1, max_length=500)


class CommentBody(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


class ExceptionBody(BaseModel):
    scope: Literal['entity', 'entity_domain', 'domain'] = 'entity'
    note: str = Field('', max_length=1000)
    expires_days: int | None = Field(None, ge=1, le=365)


def _order(sort: str):
    rank = case({s: i for s, i in SEVERITY_RANK.items()}, value=Finding.severity, else_=0)
    return {
        'severity': (rank.desc(), Finding.last_seen.desc()),
        'last_seen': (Finding.last_seen.desc(),),
        'first_seen': (Finding.first_seen.desc(),),
        'events': (Finding.event_count.desc(),),
        'number': (Finding.number.desc(),),
    }.get(sort, (rank.desc(), Finding.last_seen.desc()))


@router.get('')
async def list_findings(
        status_: list[str] = Query(default=[], alias='status'),
        severity: list[str] = Query(default=[]), category: list[str] = Query(default=[]),
        rule_id: str | None = None, entity: str | None = None, assignee: str | None = None,
        q: str | None = None, sort: str = 'severity', limit: int = 50, offset: int = 0,
        since: str | None = None,
        principal: Principal = Depends(require(rbac.FINDINGS_READ)),
        db: AsyncSession = Depends(get_session)) -> dict:
    stmt = select(Finding)
    statuses = [s for s in status_ if s]
    if statuses == ['open']:
        statuses = list(engine.OPEN)
    if statuses:
        stmt = stmt.where(Finding.status.in_(statuses))
    if severity:
        stmt = stmt.where(Finding.severity.in_(severity))
    if category:
        stmt = stmt.where(Finding.category.in_(category))
    if rule_id:
        stmt = stmt.where(Finding.rule_id == parse_uuid(rule_id, 'That rule'))
    if entity:
        stmt = stmt.where(Finding.entity_value == entity)
    if assignee == 'me':
        stmt = stmt.where(Finding.assignee_id == principal.user.id)
    elif assignee == 'none':
        stmt = stmt.where(Finding.assignee_id.is_(None))
    elif assignee:
        stmt = stmt.where(Finding.assignee_id == parse_uuid(assignee, 'That user'))
    if since:
        stmt = stmt.where(Finding.last_seen >= moment_param(since, 'since'))
    if q and q.strip():
        text_ = q.strip()[:200]
        like = '%' + like_escape(text_) + '%'
        clauses = [Finding.title.ilike(like, escape='\\'),
                   Finding.entity_value.ilike(like, escape='\\'),
                   Finding.rule_name.ilike(like, escape='\\'),
                   Finding.summary.ilike(like, escape='\\')]
        number = _NUMBER.fullmatch(text_)
        if number:
            clauses.append(Finding.number == int(number.group(1)))
        stmt = stmt.where(or_(*clauses))
    count = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await db.execute(stmt.order_by(*_order(sort)).limit(max(1, min(limit, 200)))
                             .offset(max(0, min(offset, 100_000))))).scalars().all()
    return {'total': count, 'items': [finding_out(f) for f in rows]}


@router.get('/stats')
async def stats(days: int = 14, _: Principal = Depends(require(rbac.FINDINGS_READ)),
                db: AsyncSession = Depends(get_session)) -> dict:
    days = max(1, min(days, 90))
    now = datetime.now(timezone.utc)
    by_status = dict((await db.execute(select(Finding.status, func.count())
                                       .group_by(Finding.status))).all())
    open_by_severity = dict((await db.execute(
        select(Finding.severity, func.count()).where(Finding.status.in_(engine.OPEN))
        .group_by(Finding.severity))).all())
    open_by_category = dict((await db.execute(
        select(Finding.category, func.count()).where(Finding.status.in_(engine.OPEN))
        .group_by(Finding.category))).all())
    day = func.date_trunc('day', Finding.created_at)
    created = (await db.execute(
        select(day, Finding.severity, func.count())
        .where(Finding.created_at >= now - timedelta(days=days)).group_by(day, Finding.severity)
        .order_by(day))).all()
    per_day: dict[str, dict] = {}
    for moment, severity, count in created:
        key = moment.date().isoformat()
        per_day.setdefault(key, {s: 0 for s in SEVERITIES})[severity] = count
    series = []
    for i in range(days - 1, -1, -1):
        key = (now - timedelta(days=i)).date().isoformat()
        series.append({'day': key, **per_day.get(key, {s: 0 for s in SEVERITIES})})
    mttr = (await db.execute(select(func.avg(
        func.extract('epoch', Finding.resolved_at - Finding.first_seen))).where(
        Finding.resolved_at.is_not(None), Finding.resolved_at >= now - timedelta(days=30)))).scalar()
    unassigned = (await db.execute(select(func.count()).select_from(Finding).where(
        Finding.status.in_(engine.OPEN), Finding.assignee_id.is_(None)))).scalar_one()
    return {
        'by_status': {s: int(by_status.get(s, 0)) for s in STATUSES},
        'open': sum(int(by_status.get(s, 0)) for s in engine.OPEN),
        'open_by_severity': {s: int(open_by_severity.get(s, 0)) for s in SEVERITIES},
        'open_by_category': {k: int(v) for k, v in open_by_category.items()},
        'created_per_day': series,
        'mean_seconds_to_resolve': float(mttr) if mttr is not None else None,
        'unassigned_open': int(unassigned),
    }


def _entity(finding: Finding) -> str | None:
    """Who a finding is about, whole: a very long value is stored cut short,
    with the whole of it kept in the evidence."""
    return (finding.evidence or {}).get('entity_full') or finding.entity_value


# As many as a rule's own form takes
MAX_EXCEPTIONS = 200


class Reopened(Exception):
    """Reopening would make a second open finding for the same rule and entity."""

    def __init__(self, number: int):
        super().__init__(number)
        self.number = number


async def _get(db: AsyncSession, finding_id: str) -> Finding:
    finding = await db.get(Finding, parse_uuid(finding_id, 'That finding'))
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That finding does not exist')
    return finding


@router.get('/{finding_id}')
async def get_finding(finding_id: str, _: Principal = Depends(require(rbac.FINDINGS_READ)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    finding = await _get(db, finding_id)
    activity = (await db.execute(select(FindingActivity).where(
        FindingActivity.finding_id == finding.id).order_by(FindingActivity.created_at.desc())
        .limit(200))).scalars().all()
    deliveries = (await db.execute(select(WebhookDelivery).where(
        WebhookDelivery.finding_id == finding.id).order_by(WebhookDelivery.created_at.desc())
        .limit(50))).scalars().all()
    rule = await db.get(Rule, finding.rule_id) if finding.rule_id else None
    related = (await db.execute(select(Finding).where(
        Finding.entity_value == finding.entity_value, Finding.id != finding.id,
        Finding.entity_value.is_not(None)).order_by(Finding.last_seen.desc()).limit(10))).scalars().all()
    out = finding_out(finding)
    out['activity'] = [{'id': a.id, 'kind': a.kind, 'actor': a.actor_name, 'body': a.body,
                        'data': a.data, 'at': ts(a.created_at)} for a in activity]
    out['deliveries'] = [delivery_out(d) for d in deliveries]
    out['rule'] = rule_out(rule) if rule else None
    out['related'] = [finding_out(f) for f in related]
    if finding.entity_field and finding.entity_value:
        out['entity_query'] = Q.entity_term(finding.entity_field, _entity(finding))
    return out


async def _apply(db: AsyncSession, finding: Finding, body: FindingPatch, principal: Principal,
                 request: Request) -> list[str]:
    changes = []
    now = datetime.now(timezone.utc)
    actor = principal.user.display_name or principal.user.username
    if body.status and body.status != finding.status:
        before = finding.status
        if body.status in engine.OPEN and before not in engine.OPEN and finding.dedup_key:
            # Its rule may have raised a new one since this closed; two open
            # findings about the same thing is what the dedup index forbids
            newer = (await db.execute(select(Finding.number).where(
                Finding.dedup_key == finding.dedup_key, Finding.id != finding.id,
                Finding.status.in_(engine.OPEN)))).scalar_one_or_none()
            if newer is not None:
                raise Reopened(newer)
        finding.status = body.status
        if body.status in CLOSED:
            finding.resolved_at = now
            finding.resolved_by_id = principal.user.id
        else:
            finding.resolved_at = None
            finding.resolved_by_id = None
        db.add(FindingActivity(finding_id=finding.id, actor_id=principal.user.id, actor_name=actor,
                               kind='status', body=body.note,
                               data={'from': before, 'to': body.status}))
        changes.append(f'status {before} -> {body.status}')
    if body.unassign and finding.assignee_id is not None:
        finding.assignee_id = None
        db.add(FindingActivity(finding_id=finding.id, actor_id=principal.user.id,
                               actor_name=actor, kind='assign', data={'to': None}))
        changes.append('unassigned')
    elif body.assignee_id:
        assignee = await db.get(User, parse_uuid(body.assignee_id, 'That user'))
        if assignee is None or assignee.disabled or not rbac.permissions_for(assignee.role) >= {
                rbac.FINDINGS_WRITE}:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                'Findings can only be assigned to someone who can work on them.')
        if finding.assignee_id != assignee.id:
            finding.assignee_id = assignee.id
            db.add(FindingActivity(finding_id=finding.id, actor_id=principal.user.id,
                                   actor_name=actor, kind='assign',
                                   data={'to': assignee.display_name or assignee.username}))
            changes.append(f'assigned to {assignee.username}')
    if body.severity and body.severity != finding.severity:
        db.add(FindingActivity(finding_id=finding.id, actor_id=principal.user.id, actor_name=actor,
                               kind='severity', data={'from': finding.severity, 'to': body.severity}))
        changes.append(f'severity {finding.severity} -> {body.severity}')
        finding.severity = body.severity
    if body.snooze_hours is not None:
        finding.snoozed_until = now + timedelta(hours=body.snooze_hours) if body.snooze_hours else None
        db.add(FindingActivity(finding_id=finding.id, actor_id=principal.user.id, actor_name=actor,
                               kind='snooze', data={'hours': body.snooze_hours}))
        changes.append(f'snoozed {body.snooze_hours}h')
    if body.tags is not None:
        finding.tags = sorted({t.strip()[:40] for t in body.tags if t.strip()})
        changes.append('tags')
    if body.note and not body.status:
        db.add(FindingActivity(finding_id=finding.id, actor_id=principal.user.id, actor_name=actor,
                               kind='comment', body=body.note))
    if changes:
        audit.record(db, 'finding.update', principal=principal, request=request,
                     target_type='finding', target_id=finding.id,
                     target_label=f'F-{finding.number}', details={'changes': changes})
    return changes


async def _announce(db: AsyncSession, finding: Finding, changes: list[str]) -> None:
    if any(c.startswith(('status', 'assigned', 'unassigned')) for c in changes):
        rule = await db.get(Rule, finding.rule_id) if finding.rule_id else None
        await hooks.enqueue_finding(db, 'finding.status_changed', finding, rule)


@router.patch('/{finding_id}')
async def update_finding(finding_id: str, body: FindingPatch, request: Request,
                         principal: Principal = Depends(require(rbac.FINDINGS_WRITE)),
                         db: AsyncSession = Depends(get_session)) -> dict:
    finding = await _get(db, finding_id)
    try:
        changes = await _apply(db, finding, body, principal, request)
        await _announce(db, finding, changes)
        await db.commit()
    except Reopened as e:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f'F-{e.number} is already open for the same rule and entity; '
                            'work on that one instead.') from e
    except IntegrityError as e:
        # The rule opened a new finding for the same thing a moment ago: met
        # at the commit, or at any query before it that flushed the change
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            'The rule has just opened a newer finding for the same thing; '
                            'work on that one instead.') from e
    await db.refresh(finding)
    return finding_out(finding)


@router.post('/bulk')
async def bulk_update(body: BulkBody, request: Request,
                      principal: Principal = Depends(require(rbac.FINDINGS_WRITE)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    ids = [parse_uuid(i, 'That finding') for i in body.ids]
    findings = (await db.execute(select(Finding).where(Finding.id.in_(ids))
                                 .order_by(Finding.number))).scalars().all()
    changed, skipped = 0, []
    try:
        for finding in findings:
            try:
                changes = await _apply(db, finding, body, principal, request)
            except Reopened:
                skipped.append(finding.number)
                continue
            if changes:
                changed += 1
                await _announce(db, finding, changes)
        await db.commit()
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT,
                            'A rule has just opened a newer finding for one of these; '
                            'reload and try again.') from e
    return {'updated': changed, 'skipped': skipped}


@router.post('/{finding_id}/comments')
async def comment(finding_id: str, body: CommentBody, request: Request,
                  principal: Principal = Depends(require(rbac.FINDINGS_WRITE)),
                  db: AsyncSession = Depends(get_session)) -> dict:
    finding = await _get(db, finding_id)
    activity = FindingActivity(finding_id=finding.id, actor_id=principal.user.id,
                               actor_name=principal.user.display_name or principal.user.username,
                               kind='comment', body=body.body.strip())
    db.add(activity)
    audit.record(db, 'finding.comment', principal=principal, request=request,
                 target_type='finding', target_id=finding.id, target_label=f'F-{finding.number}')
    await db.commit()
    return {'id': activity.id, 'kind': 'comment', 'actor': activity.actor_name,
            'body': activity.body, 'at': ts(activity.created_at)}


@router.post('/{finding_id}/exception')
async def add_exception(finding_id: str, body: ExceptionBody, request: Request,
                        principal: Principal = Depends(require(rbac.FINDINGS_WRITE, rbac.RULES_WRITE)),
                        db: AsyncSession = Depends(get_session)) -> dict:
    """Marks a finding a false positive and teaches its rule not to raise it again."""
    finding = await _get(db, finding_id)
    rule = await db.get(Rule, finding.rule_id, with_for_update=True) if finding.rule_id else None
    if rule is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'The rule that raised this is gone.')
    if len(rule.exceptions or []) >= MAX_EXCEPTIONS:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f'{rule.name} already has {MAX_EXCEPTIONS} exceptions, the most a rule can '
                            'have. Remove some on the rule first.')
    parts = []
    if body.scope in ('entity', 'entity_domain'):
        if not finding.entity_field or finding.entity_value is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                'This finding is not about one person or machine.')
        entity = _entity(finding)
        if '\ufffd' in entity:
            # Stored without the characters it came with, a NUL say, which
            # Postgres cannot keep: it would never match them
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                'This finding\'s value has characters an exception cannot match.')
        parts.append(Q.entity_term(finding.entity_field, entity))
    if body.scope in ('entity_domain', 'domain'):
        domains = [d['key'] for d in (finding.evidence or {}).get('top_domains', [])][:5]
        if not domains:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'This finding names no domain.')
        parts.append('domain:(' + ' OR '.join(quote(d) for d in domains) + ')')
    query = ' AND '.join(parts)
    try:
        tbql.compile(query)
    except tbql.TbqlError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f'An exception for this finding would not work: {e.message}') from e
    now = datetime.now(timezone.utc)
    exception = {'id': str(uuid.uuid4()), 'query': query, 'note': body.note,
                 'created_by': principal.user.username, 'created_at': ts(now),
                 'expires_at': ts(now + timedelta(days=body.expires_days)) if body.expires_days else None,
                 'finding': f'F-{finding.number}'}
    # Exceptions are the rule's own, not part of its shipped definition, so
    # adding one leaves a built-in rule able to take the next version
    rule.exceptions = [*(rule.exceptions or []), exception]
    changes = await _apply(db, finding, FindingPatch(status='false_positive',
                                                     note=body.note or f'Exception added: {query}'),
                           principal, request)
    await _announce(db, finding, changes)
    audit.record(db, 'rule.exception_added', principal=principal, request=request,
                 target_type='rule', target_id=rule.id, target_label=rule.name,
                 details={'query': query, 'finding': f'F-{finding.number}'})
    await db.commit()
    return {'ok': True, 'exception': exception, 'rule': rule_out(rule)}


@router.get('/{finding_id}/assignable')
async def assignable(finding_id: str, _: Principal = Depends(require(rbac.FINDINGS_READ)),
                     db: AsyncSession = Depends(get_session)) -> list[dict]:
    users = (await db.execute(select(User).where(User.disabled.is_(False),
                                                 User.role.in_(('analyst', 'admin')),
                                                 User.source != 'service')
                              .order_by(User.username))).scalars().all()
    return [user_out(u) for u in users]
