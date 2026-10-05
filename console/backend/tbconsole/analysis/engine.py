"""Running rules, turning hits into findings, and the scheduler that drives it.

One open finding per rule and entity. A rule that matches the same person
again while their finding is still open adds an occurrence to it and counts
the new events, rather than raising another finding; the finding's re-alert
gap, the rule's dedup_seconds, decides whether that also sends a reminder.
Once a finding is resolved or marked a false positive, the next match raises
a new one.

Rules are claimed with FOR UPDATE SKIP LOCKED and their next run is pushed
forward before they run, so any number of console processes can run the
scheduler and each rule runs once per interval.
"""

import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import db as database
from ..models import Finding, FindingActivity, Rule, RuleRun
from ..search.client import SearchClient, SearchError
from ..search.timerange import TimeRange, iso
from ..webhooks import service as hooks
from . import defaults
from .ruletypes import SEVERITY_RANK, Evaluation, Evaluator, Hit, RuleError, RuleSpec

log = logging.getLogger(__name__)

OPEN = ('new', 'acknowledged', 'in_progress')
RUNS_KEPT = 200
FAILURES_BEFORE_ALERT = 3


def spec_of(rule: Rule) -> RuleSpec:
    return RuleSpec(name=rule.name, type=rule.type, query=rule.query, params=rule.params or {},
                    group_by=rule.group_by or [], window_seconds=rule.window_seconds,
                    interval_seconds=rule.interval_seconds, exceptions=rule.exceptions or [])


def in_schedule(schedule: dict | None, now: datetime) -> bool:
    """Whether `now` falls in a rule's active hours. No schedule means always."""
    if not schedule:
        return True
    try:
        zone = ZoneInfo(schedule.get('timezone') or 'UTC')
    except (ZoneInfoNotFoundError, ValueError):
        zone = ZoneInfo('UTC')
    local = now.astimezone(zone)
    days = schedule.get('days')
    start = schedule.get('start') or '00:00'
    end = schedule.get('end') or '24:00'
    minute = local.hour * 60 + local.minute

    def minutes(text: str) -> int:
        hours, _, mins = text.partition(':')
        return int(hours) * 60 + int(mins or 0)
    lo, hi = minutes(start), minutes(end)
    if lo == hi:
        inside, day = True, local.weekday()
    elif lo < hi:
        inside, day = lo <= minute < hi, local.weekday()
    else:
        # Wraps midnight: 22:00 to 06:00 belongs to the day it started on
        inside = minute >= lo or minute < hi
        day = local.weekday() if minute >= lo else (local.weekday() - 1) % 7
    return inside and (days is None or day in days)


def dedup_key(rule_id: uuid.UUID, hit: Hit) -> str:
    raw = f'{rule_id}|{hit.entity_field or ""}|{hit.entity_value or ""}|{hit.distinct}'
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:40]


def render_title(template: str, rule: Rule, hit: Hit) -> str:
    entity = hit.entity_value or 'the network'
    values = {'rule': rule.name, 'entity': entity, 'count': f'{hit.count:,}',
              'value': hit.distinct or (f'{hit.value:g}' if isinstance(hit.value, float) else str(hit.value)),
              'field': hit.entity_field or ''}
    try:
        title = (template or '{rule}: {entity}').format(**values)
    except (KeyError, IndexError, ValueError):
        title = f'{rule.name}: {entity}'
    if hit.distinct and hit.distinct not in title:
        title = f'{title} ({hit.distinct})'
    return title[:400]


@dataclass
class RunOutcome:
    status: str
    hits: int = 0
    created: int = 0
    updated: int = 0
    error: str | None = None
    reason: str = ''
    duration_ms: int = 0


async def _apply_hit(db: AsyncSession, rule: Rule, hit: Hit, now: datetime) -> tuple[bool, Finding]:
    """Creates or updates the open finding for a hit. Returns (created, finding)."""
    key = dedup_key(rule.id, hit)
    finding = (await db.execute(select(Finding).where(
        Finding.dedup_key == key, Finding.status.in_(OPEN))
        .with_for_update(of=Finding))).scalar_one_or_none()
    evidence = hit.evidence()
    last_event = datetime.fromisoformat(hit.last.replace('Z', '+00:00')) if hit.last else now
    if finding is None:
        first_event = datetime.fromisoformat(hit.first.replace('Z', '+00:00')) if hit.first else now
        finding = Finding(
            rule_id=rule.id, rule_name=rule.name, rule_type=rule.type, category=rule.category,
            severity=rule.severity, status='new', title=render_title(rule.title_template, rule, hit),
            summary=hit.summary, entity_field=hit.entity_field, entity_value=hit.entity_value,
            dedup_key=key, first_seen=first_event, last_seen=last_event, event_count=hit.count,
            occurrences=1, evidence=dict(evidence, last_notified=iso(now)), tags=list(rule.tags or []))
        db.add(finding)
        await db.flush()
        db.add(FindingActivity(finding_id=finding.id, actor_name='TurkeyBite Console',
                               kind='created', body=hit.summary,
                               data={'window': evidence['from'] + '/' + evidence['to'],
                                     'count': hit.count}))
        return True, finding
    finding.last_seen = max(finding.last_seen, last_event)
    finding.occurrences += 1
    finding.event_count += max(hit.recent, 0)
    finding.summary = hit.summary
    # Escalate to the rule's severity if it was raised since
    if SEVERITY_RANK.get(rule.severity, 0) > SEVERITY_RANK.get(finding.severity, 0):
        finding.severity = rule.severity
    previous = finding.evidence or {}
    finding.evidence = dict(evidence, last_notified=previous.get('last_notified'),
                            first_window=previous.get('first_window', previous.get('from')))
    return False, finding


async def _remind_due(finding: Finding, rule: Rule, now: datetime) -> bool:
    if finding.snoozed_until and finding.snoozed_until > now:
        return False
    last = (finding.evidence or {}).get('last_notified')
    if not last:
        return True
    last_at = datetime.fromisoformat(last.replace('Z', '+00:00'))
    return (now - last_at).total_seconds() >= rule.dedup_seconds


async def record_hits(db: AsyncSession, rule: Rule, hits: list[Hit], now: datetime) -> tuple[int, int]:
    """Turns hits into findings and queues their webhooks. Returns (created, updated)."""
    created = updated = 0
    for hit in hits:
        try:
            async with db.begin_nested():
                is_new, finding = await _apply_hit(db, rule, hit, now)
        except IntegrityError:
            # Another process opened the same finding a moment ago; add to it
            async with db.begin_nested():
                is_new, finding = await _apply_hit(db, rule, hit, now)
        if is_new:
            created += 1
            await hooks.enqueue_finding(db, 'finding.created', finding, rule)
        else:
            updated += 1
            if await _remind_due(finding, rule, now):
                sent = await hooks.enqueue_finding(db, 'finding.reminder', finding, rule)
                if sent:
                    finding.evidence = dict(finding.evidence or {}, last_notified=iso(now))
                db.add(FindingActivity(finding_id=finding.id, actor_name='TurkeyBite Console',
                                       kind='occurrence', body=hit.summary,
                                       data={'count': hit.count, 'reminded': bool(sent)}))
    return created, updated


async def run_rule(db: AsyncSession, search: SearchClient, rule: Rule, now: datetime | None = None,
                   persist: bool = True) -> RunOutcome:
    """Evaluates one rule at `now` and records what it found."""
    now = now or datetime.now(timezone.utc)
    started = time.monotonic()
    if not in_schedule(rule.schedule, now):
        outcome = RunOutcome('skipped', reason='outside its active hours')
    else:
        recent_since = rule.last_run_at if rule.last_run_at and rule.last_run_at < now else None
        if recent_since is not None and (now - recent_since).total_seconds() > rule.window_seconds:
            recent_since = None
        try:
            evaluation: Evaluation = await Evaluator(search).evaluate(spec_of(rule), now, recent_since)
            outcome = RunOutcome(evaluation.status, hits=len(evaluation.hits), reason=evaluation.reason)
            if persist and evaluation.hits:
                outcome.created, outcome.updated = await record_hits(db, rule, evaluation.hits, now)
        except (RuleError, SearchError) as e:
            outcome = RunOutcome('error', error=str(e))
        except Exception as e:  # a rule must never take the scheduler down
            log.exception('rule %s failed', rule.id)
            outcome = RunOutcome('error', error=f'{type(e).__name__}: {e}')
    outcome.duration_ms = int((time.monotonic() - started) * 1000)
    if not persist:
        return outcome
    rule.last_run_at = now
    rule.last_status = outcome.status
    rule.last_error = outcome.error or (outcome.reason or None)
    rule.last_duration_ms = outcome.duration_ms
    rule.last_hits = outcome.hits
    if outcome.status == 'error':
        rule.consecutive_failures += 1
        if rule.consecutive_failures == FAILURES_BEFORE_ALERT:
            await hooks.enqueue_rule_failing(db, rule)
    else:
        rule.consecutive_failures = 0
    db.add(RuleRun(rule_id=rule.id, started_at=now, finished_at=datetime.now(timezone.utc),
                   window_start=now - timedelta(seconds=rule.window_seconds), window_end=now,
                   status=outcome.status, hits=outcome.hits, findings_created=outcome.created,
                   findings_updated=outcome.updated, duration_ms=outcome.duration_ms,
                   error=outcome.error or (outcome.reason or None)))
    return outcome


async def prune_runs(db: AsyncSession, rule_id: uuid.UUID) -> None:
    ids = (await db.execute(select(RuleRun.id).where(RuleRun.rule_id == rule_id)
                            .order_by(RuleRun.started_at.desc()).offset(RUNS_KEPT))).scalars().all()
    if ids:
        await db.execute(delete(RuleRun).where(RuleRun.id.in_(ids)))


# -- backtesting ------------------------------------------------------------------

MAX_BACKTEST_STEPS = 96


async def backtest(search: SearchClient, spec: RuleSpec, tr: TimeRange) -> dict:
    """What a rule would have raised over `tr`, evaluated at its interval.

    Nothing is recorded. Long ranges are sampled at a coarser step so a test
    stays a few dozen queries.
    """
    step = max(spec.interval_seconds, int(tr.seconds / MAX_BACKTEST_STEPS) + 1)
    evaluator = Evaluator(search)
    moment = tr.start + timedelta(seconds=spec.window_seconds)
    if moment > tr.end:
        moment = tr.end
    series, samples, entities, statuses = [], [], {}, set()
    previous: datetime | None = None
    while moment <= tr.end:
        evaluation = await evaluator.evaluate(spec, moment, previous)
        statuses.add(evaluation.status)
        series.append({'t': iso(moment), 'hits': len(evaluation.hits),
                       'status': evaluation.status, 'reason': evaluation.reason})
        for hit in evaluation.hits:
            key = f'{hit.entity_field}|{hit.entity_value}|{hit.distinct}'
            entities[key] = entities.get(key, 0) + 1
            if len(samples) < 25:
                samples.append({'t': iso(moment), 'entity_field': hit.entity_field,
                                'entity': hit.entity_value, 'summary': hit.summary,
                                'count': hit.count, 'value': hit.value,
                                'evidence_query': hit.evidence_query})
        previous = moment
        moment += timedelta(seconds=step)
    return {'step_seconds': step, 'evaluations': len(series), 'series': series,
            'would_fire': sum(s['hits'] for s in series), 'distinct_findings': len(entities),
            'samples': samples,
            'warming_up': [s['reason'] for s in series if s['status'] == 'skipped'][:1]}


# -- built-in rules ------------------------------------------------------------------

async def sync_builtin_rules(db: AsyncSession) -> dict:
    """Adds missing built-in rules and upgrades unmodified ones. Returns counts."""
    existing = {r.builtin_key: r for r in (await db.execute(
        select(Rule).where(Rule.builtin_key.is_not(None)))).scalars()}
    added = upgraded = 0
    now = datetime.now(timezone.utc)
    for definition in defaults.DEFAULT_RULES:
        rule = existing.get(definition['key'])
        if rule is None:
            rule = Rule(builtin_key=definition['key'], builtin_version=definition['version'],
                        enabled=definition['enabled'], modified=False,
                        next_run_at=now + timedelta(seconds=30))
            for name in defaults.DEFINITION_FIELDS:
                if name in definition:
                    setattr(rule, name, definition[name])
            db.add(rule)
            added += 1
        elif not rule.modified and (rule.builtin_version or 0) < definition['version']:
            for name in defaults.DEFINITION_FIELDS:
                if name in definition:
                    setattr(rule, name, definition[name])
            rule.builtin_version = definition['version']
            upgraded += 1
    await db.commit()
    return {'added': added, 'upgraded': upgraded}


def reset_to_default(rule: Rule) -> None:
    definition = defaults.BY_KEY[rule.builtin_key]
    for name in defaults.DEFINITION_FIELDS:
        setattr(rule, name, definition.get(name, None if name == 'schedule' else getattr(rule, name)))
    rule.builtin_version = definition['version']
    rule.modified = False


def update_available(rule: Rule) -> bool:
    definition = defaults.BY_KEY.get(rule.builtin_key or '')
    return bool(definition and rule.modified and (rule.builtin_version or 0) < definition['version'])


# -- the scheduler ---------------------------------------------------------------------

async def claim_due(db: AsyncSession, now: datetime, limit: int = 10) -> list[Rule]:
    rules = (await db.execute(
        select(Rule).where(Rule.enabled.is_(True), Rule.next_run_at <= now)
        .order_by(Rule.next_run_at).limit(limit).with_for_update(skip_locked=True))).scalars().all()
    for rule in rules:
        rule.next_run_at = now + timedelta(seconds=rule.interval_seconds)
    return list(rules)


class Scheduler:
    def __init__(self, search: SearchClient, poll_seconds: float = 5.0, concurrency: int = 4):
        self.search = search
        self.poll_seconds = poll_seconds
        self.semaphore = asyncio.Semaphore(concurrency)
        self._task: asyncio.Task | None = None
        self.last_tick: datetime | None = None

    async def _run_one(self, rule_id: uuid.UUID) -> None:
        async with self.semaphore:
            async with database.sessionmaker()() as db:
                rule = await db.get(Rule, rule_id)
                if rule is None or not rule.enabled:
                    return
                await run_rule(db, self.search, rule)
                await prune_runs(db, rule.id)
                await db.commit()

    async def tick(self) -> int:
        now = datetime.now(timezone.utc)
        async with database.sessionmaker()() as db:
            async with db.begin():
                due = await claim_due(db, now)
                ids = [r.id for r in due]
        if ids:
            await asyncio.gather(*[self._run_one(i) for i in ids], return_exceptions=True)
        self.last_tick = datetime.now(timezone.utc)
        return len(ids)

    async def loop(self) -> None:
        while True:
            try:
                ran = await self.tick()
                if ran:
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception('scheduler tick failed')
            await asyncio.sleep(self.poll_seconds)

    def start(self) -> None:
        self._task = asyncio.create_task(self.loop(), name='rule-scheduler')

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
