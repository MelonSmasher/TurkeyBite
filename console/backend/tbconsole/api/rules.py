"""Rules: the shipped ones and your own, testing them, and their run history."""

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..analysis import defaults, engine
from ..analysis.ruletypes import SEVERITIES, TYPES, RuleError, RuleSpec, normalise
from ..db import get_session
from ..deps import Principal, require, search_client
from ..models import Finding, Rule, RuleRun, Webhook
from ..search import fields as F
from ..search.client import SearchClient
from ..security import rbac
from .common import parse_uuid, rule_out, time_range, ts

router = APIRouter(prefix='/rules', tags=['rules'])

CATEGORIES = {'threat': 'Threats', 'policy': 'Policy', 'content': 'Content', 'anomaly': 'Anomalies',
              'health': 'Health', 'custom': 'Custom'}


class Schedule(BaseModel):
    """The days and hours a rule is active, in a time zone; days run from 0 (Monday) to 6 (Sunday)."""

    days: list[int] = Field(default_factory=lambda: list(range(7)))
    start: str = Field('00:00', pattern=r'^([01]\d|2[0-3]):[0-5]\d$')
    end: str = Field('24:00', pattern=r'^(([01]\d|2[0-3]):[0-5]\d|24:00)$')
    timezone: str = 'UTC'


class RuleBody(BaseModel):
    """A rule's whole definition, as the rule editor sends it."""

    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=200)
    description: str = Field('', max_length=4000)
    category: str = 'custom'
    type: str
    query: str = Field('', max_length=20000)
    params: dict = Field(default_factory=dict)
    group_by: list[str] = Field(default_factory=list, max_length=4)
    severity: str = 'medium'
    enabled: bool = False
    interval_seconds: int = 300
    window_seconds: int = 900
    dedup_seconds: int = Field(3600, ge=0, le=30 * 86400)
    schedule: Schedule | None = None
    exceptions: list[dict] = Field(default_factory=list, max_length=200)
    webhook_ids: list[str] = Field(default_factory=list, max_length=20)
    tags: list[str] = Field(default_factory=list, max_length=20)
    title_template: str = Field('{rule}: {entity}', max_length=300)


class BacktestBody(RuleBody):
    """A rule, saved or not, and the range to backtest it over."""

    model_config = ConfigDict(extra='forbid', populate_by_name=True)
    name: str = Field('Draft', max_length=200)
    start: str | None = Field('now-24h', alias='from')
    end: str | None = Field('now', alias='to')


def _spec(body: RuleBody) -> RuleSpec:
    return RuleSpec(name=body.name, type=body.type, query=body.query, params=body.params,
                    group_by=body.group_by, window_seconds=body.window_seconds,
                    interval_seconds=body.interval_seconds, exceptions=body.exceptions,
                    schedule=body.schedule.model_dump() if body.schedule else None)


def _check_exceptions(exceptions: list[dict]) -> None:
    for item in exceptions:
        if not isinstance(item.get('query'), str) or not item['query'].strip():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Every exception needs a query.')
        expires = item.get('expires_at')
        if expires is None:
            continue
        try:
            moment = datetime.fromisoformat(str(expires).replace('Z', '+00:00'))
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                f'{expires!r} is not a time an exception can expire at') from e
        if moment.tzinfo is None:
            item['expires_at'] = ts(moment.replace(tzinfo=timezone.utc))


async def _validate(db: AsyncSession, body: RuleBody) -> dict:
    if body.severity not in SEVERITIES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'severity is one of {", ".join(SEVERITIES)}')
    if body.category not in CATEGORIES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'category is one of {", ".join(CATEGORIES)}')
    if body.schedule:
        try:
            ZoneInfo(body.schedule.timezone)
        except Exception as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                f'{body.schedule.timezone!r} is not a time zone') from e
        if any(d < 0 or d > 6 for d in body.schedule.days):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'days are 0 (Monday) to 6 (Sunday)')
    _check_exceptions(body.exceptions)
    try:
        params = normalise(_spec(body))
        engine.check_title(body.title_template)
    except RuleError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    hook_ids = [parse_uuid(i, 'That webhook') for i in body.webhook_ids]
    if hook_ids:
        found = set((await db.execute(select(Webhook.id).where(Webhook.id.in_(hook_ids)))).scalars())
        if set(hook_ids) - found:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'A webhook named on the rule does not exist')
    return params


def _assign(rule: Rule, body: RuleBody, params: dict) -> bool:
    """Copies a body onto a rule. True when the definition itself changed."""
    before = {name: getattr(rule, name) for name in defaults.DEFINITION_FIELDS}
    basis = engine.cursor_basis(rule)
    rule.name = body.name.strip()
    rule.description = body.description
    rule.category = body.category
    rule.type = body.type
    rule.query = body.query.strip()
    rule.params = params
    rule.group_by = body.group_by
    rule.severity = body.severity
    rule.interval_seconds = body.interval_seconds
    rule.window_seconds = body.window_seconds
    rule.dedup_seconds = body.dedup_seconds
    rule.schedule = body.schedule.model_dump() if body.schedule else None
    rule.exceptions = body.exceptions
    rule.webhook_ids = [str(parse_uuid(i)) for i in body.webhook_ids]
    rule.tags = sorted({t.strip()[:40] for t in body.tags if t.strip()})
    rule.title_template = body.title_template
    engine.forget_position_if_changed(rule, basis)
    return any(getattr(rule, name) != before[name] for name in defaults.DEFINITION_FIELDS)


def _restart(rule: Rule) -> None:
    """A rule switched back on starts from now.

    The weeks it was off are not windows it missed.
    """
    rule.next_run_at = datetime.now(timezone.utc)
    rule.evaluated_until = None


async def _get(db: AsyncSession, rule_id: str) -> Rule:
    rule = await db.get(Rule, parse_uuid(rule_id, 'That rule'))
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That rule does not exist')
    return rule


@router.get('/meta')
async def meta(_: Principal = Depends(require(rbac.RULES_READ))) -> dict:
    """What the rule editor offers: the types and their settings, severities, categories, fields to group by and title placeholders."""
    return {
        'types': TYPES, 'severities': list(SEVERITIES), 'categories': CATEGORIES,
        'group_fields': [{'name': F.ENTITY, 'label': F.ENTITY_LABEL}] + [
            {'name': f.name, 'label': f.label} for f in F.FIELDS
            if f.aggregatable and f.type in ('keyword', 'ip')],
        'title_placeholders': ['{rule}', '{entity}', '{count}', '{value}', '{field}'],
    }


@router.get('')
async def list_rules(_: Principal = Depends(require(rbac.RULES_READ)),
                     db: AsyncSession = Depends(get_session)) -> list[dict]:
    """Every rule, with its open findings and the findings it raised each day for the last two weeks."""
    rules = (await db.execute(select(Rule).order_by(Rule.category, Rule.name))).scalars().all()
    now = datetime.now(timezone.utc)
    open_counts = dict((await db.execute(
        select(Finding.rule_id, func.count()).where(Finding.status.in_(engine.OPEN))
        .group_by(Finding.rule_id))).all())
    day = func.date_trunc('day', Finding.created_at)
    recent = (await db.execute(
        select(Finding.rule_id, day, func.count()).where(Finding.created_at >= now - timedelta(days=14))
        .group_by(Finding.rule_id, day))).all()
    spark: dict = {}
    for rule_id, moment, count in recent:
        spark.setdefault(rule_id, {})[moment.date().isoformat()] = count
    days = [(now - timedelta(days=i)).date().isoformat() for i in range(13, -1, -1)]
    out = []
    for rule in rules:
        item = rule_out(rule)
        item['open_findings'] = int(open_counts.get(rule.id, 0))
        item['findings_14d'] = [spark.get(rule.id, {}).get(d, 0) for d in days]
        out.append(item)
    return out


@router.post('', status_code=status.HTTP_201_CREATED)
async def create_rule(body: RuleBody, request: Request,
                      principal: Principal = Depends(require(rbac.RULES_WRITE)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    """Makes a rule."""
    params = await _validate(db, body)
    rule = Rule(created_by_id=principal.user.id, enabled=body.enabled,
                next_run_at=datetime.now(timezone.utc))
    _assign(rule, body, params)
    db.add(rule)
    await db.flush()
    audit.record(db, 'rule.create', principal=principal, request=request, target_type='rule',
                 target_id=rule.id, target_label=rule.name)
    await db.commit()
    await db.refresh(rule)
    return rule_out(rule)


@router.post('/backtest')
async def backtest(body: BacktestBody, _: Principal = Depends(require(rbac.RULES_WRITE)),
                   search: SearchClient = Depends(search_client)) -> dict:
    """What a rule, saved or not, would have raised over a range. Records nothing.

    It needs rules:write: a backtest runs dozens of aggregations over up to a
    month of events, which is the cost of authoring a rule, not of reading.
    """
    _check_exceptions(body.exceptions)
    try:
        normalise(_spec(body))
    except RuleError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    tr = time_range(body.start, body.end)
    if tr.seconds > 31 * 86400:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Backtest at most 31 days at a time.')
    return await engine.backtest(search, _spec(body), tr)


@router.get('/{rule_id}')
async def get_rule(rule_id: str, _: Principal = Depends(require(rbac.RULES_READ)),
                   db: AsyncSession = Depends(get_session)) -> dict:
    """One rule, with how many findings it raised and, for a built-in rule, its shipped definition."""
    rule = await _get(db, rule_id)
    out = rule_out(rule)
    if rule.builtin_key:
        definition = defaults.BY_KEY.get(rule.builtin_key, {})
        out['default'] = {name: definition.get(name) for name in defaults.DEFINITION_FIELDS}
        out['default']['version'] = definition.get('version')
    out['open_findings'] = (await db.execute(select(func.count()).select_from(Finding).where(
        Finding.rule_id == rule.id, Finding.status.in_(engine.OPEN)))).scalar_one()
    out['total_findings'] = (await db.execute(select(func.count()).select_from(Finding).where(
        Finding.rule_id == rule.id))).scalar_one()
    return out


@router.put('/{rule_id}')
async def update_rule(rule_id: str, body: RuleBody, request: Request,
                      principal: Principal = Depends(require(rbac.RULES_WRITE)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    """Replaces a rule's definition.

    A built-in rule whose definition changes is marked modified, and new
    versions of it are no longer taken on without asking.
    """
    rule = await _get(db, rule_id)
    params = await _validate(db, body)
    changed = _assign(rule, body, params)
    soonest = datetime.now(timezone.utc) + timedelta(seconds=rule.interval_seconds)
    if rule.next_run_at is None or rule.next_run_at > soonest:
        # A shorter interval takes effect now, not after the old one runs out
        rule.next_run_at = soonest
    if rule.builtin_key and changed:
        rule.modified = True
    if body.enabled != rule.enabled:
        rule.enabled = body.enabled
        if body.enabled:
            _restart(rule)
    audit.record(db, 'rule.update', principal=principal, request=request, target_type='rule',
                 target_id=rule.id, target_label=rule.name)
    await db.commit()
    await db.refresh(rule)
    return rule_out(rule)


@router.delete('/{rule_id}')
async def delete_rule(rule_id: str, request: Request,
                      principal: Principal = Depends(require(rbac.RULES_WRITE)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    """Deletes a rule. Built-in rules cannot be deleted, only switched off."""
    rule = await _get(db, rule_id)
    if rule.builtin_key:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            'Built-in rules cannot be deleted; disable this one instead.')
    audit.record(db, 'rule.delete', principal=principal, request=request, target_type='rule',
                 target_id=rule.id, target_label=rule.name)
    await db.delete(rule)
    await db.commit()
    return {'ok': True}


async def _toggle(db: AsyncSession, rule_id: str, enabled: bool, principal: Principal,
                  request: Request) -> dict:
    rule = await _get(db, rule_id)
    if enabled and not rule.enabled:
        _restart(rule)
    rule.enabled = enabled
    audit.record(db, 'rule.enable' if enabled else 'rule.disable', principal=principal,
                 request=request, target_type='rule', target_id=rule.id, target_label=rule.name)
    await db.commit()
    await db.refresh(rule)
    return rule_out(rule)


@router.post('/{rule_id}/enable')
async def enable(rule_id: str, request: Request,
                 principal: Principal = Depends(require(rbac.RULES_WRITE)),
                 db: AsyncSession = Depends(get_session)) -> dict:
    """Switches a rule on. It starts from now; the time it was off is not caught up on."""
    return await _toggle(db, rule_id, True, principal, request)


@router.post('/{rule_id}/disable')
async def disable(rule_id: str, request: Request,
                  principal: Principal = Depends(require(rbac.RULES_WRITE)),
                  db: AsyncSession = Depends(get_session)) -> dict:
    """Switches a rule off."""
    return await _toggle(db, rule_id, False, principal, request)


@router.post('/{rule_id}/clone', status_code=status.HTTP_201_CREATED)
async def clone(rule_id: str, request: Request,
                principal: Principal = Depends(require(rbac.RULES_WRITE)),
                db: AsyncSession = Depends(get_session)) -> dict:
    """Copies a rule, built-in or not, into a new one of the caller's, switched off."""
    source = await _get(db, rule_id)
    copy = Rule(created_by_id=principal.user.id, enabled=False, modified=False,
                name=f'Copy of {source.name}'[:200], next_run_at=datetime.now(timezone.utc))
    for name in defaults.DEFINITION_FIELDS:
        if name != 'name':
            setattr(copy, name, getattr(source, name))
    copy.category = source.category
    copy.exceptions = list(source.exceptions or [])
    copy.webhook_ids = list(source.webhook_ids or [])
    db.add(copy)
    await db.flush()
    audit.record(db, 'rule.clone', principal=principal, request=request, target_type='rule',
                 target_id=copy.id, target_label=copy.name, details={'from': str(source.id)})
    await db.commit()
    await db.refresh(copy)
    return rule_out(copy)


@router.post('/{rule_id}/reset')
async def reset(rule_id: str, request: Request,
                principal: Principal = Depends(require(rbac.RULES_WRITE)),
                db: AsyncSession = Depends(get_session)) -> dict:
    """Puts a built-in rule back as it ships, at the current version, undoing any edits."""
    rule = await _get(db, rule_id)
    if not rule.builtin_key or rule.builtin_key not in defaults.BY_KEY:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Only built-in rules have a default.')
    engine.reset_to_default(rule)
    audit.record(db, 'rule.reset', principal=principal, request=request, target_type='rule',
                 target_id=rule.id, target_label=rule.name)
    await db.commit()
    await db.refresh(rule)
    return rule_out(rule)


@router.post('/{rule_id}/run')
async def run_now(rule_id: str, request: Request,
                  principal: Principal = Depends(require(rbac.RULES_WRITE)),
                  search: SearchClient = Depends(search_client),
                  db: AsyncSession = Depends(get_session)) -> dict:
    """Runs a rule now, as the scheduler would, and returns what the run found."""
    rule = await _get(db, rule_id)
    claimed = await engine.claim_run(db, rule.id)
    if claimed is None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            'This rule is running right now. Try again in a moment.')
    now, lease = claimed
    try:
        outcome = await engine.run_rule(db, search, rule, now=now, lease=lease)
    except BaseException:
        await db.rollback()
        await engine.release_run(rule.id, lease)
        raise
    audit.record(db, 'rule.run', principal=principal, request=request, target_type='rule',
                 target_id=rule.id, target_label=rule.name)
    await db.commit()
    return {'status': outcome.status, 'hits': outcome.hits, 'created': outcome.created,
            'updated': outcome.updated, 'error': outcome.error, 'reason': outcome.reason,
            'duration_ms': outcome.duration_ms}


@router.get('/{rule_id}/runs')
async def runs(rule_id: str, limit: int = 50, _: Principal = Depends(require(rbac.RULES_READ)),
               db: AsyncSession = Depends(get_session)) -> list[dict]:
    """A rule's recent runs, newest first."""
    rule = await _get(db, rule_id)
    rows = (await db.execute(select(RuleRun).where(RuleRun.rule_id == rule.id)
                             .order_by(RuleRun.started_at.desc())
                             .limit(max(1, min(limit, 200))))).scalars().all()
    return [{'id': r.id, 'started_at': ts(r.started_at), 'status': r.status, 'hits': r.hits,
             'created': r.findings_created, 'updated': r.findings_updated,
             'duration_ms': r.duration_ms, 'error': r.error,
             'window_start': ts(r.window_start), 'window_end': ts(r.window_end)} for r in rows]
