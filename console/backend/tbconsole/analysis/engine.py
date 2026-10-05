"""Running rules, turning hits into findings, and the scheduler that drives it.

One open finding per rule and entity. A rule that matches the same person
again while their finding is still open adds an occurrence to it and counts
the new events, rather than raising another finding; the finding's re-alert
gap, the rule's dedup_seconds, decides whether that also sends a reminder.
Once a finding is resolved or marked a false positive, the next match raises
a new one.

Rules are claimed with FOR UPDATE SKIP LOCKED and their next run is pushed
forward before they run, and a rule's row stays locked while it runs, so any
number of console processes can run the scheduler, each rule runs once per
interval, and a slow run is never overlapped by the next.

If runs were missed, because the console was stopped or the cluster was
down, the next run catches up: it evaluates the windows it missed, up to a
limit, so events that arrived meanwhile are still looked at.
"""

import asyncio
import hashlib
import logging
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, time as clock, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import db as database
from ..config import get_settings
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
# How far back a run catches up on windows it missed, and in how many steps
CATCH_UP = timedelta(hours=6)
CATCH_UP_STEPS = 12
ENTITY_MAX = 400
# pg_advisory_xact_lock key for syncing built-in rules and dashboards
SYNC_LOCK = 0x7462_0001


def spec_of(rule: Rule) -> RuleSpec:
    return RuleSpec(name=rule.name, type=rule.type, query=rule.query, params=rule.params or {},
                    group_by=rule.group_by or [], window_seconds=rule.window_seconds,
                    interval_seconds=rule.interval_seconds, exceptions=rule.exceptions or [],
                    schedule=rule.schedule)


def _zone(schedule: dict) -> ZoneInfo:
    try:
        return ZoneInfo(schedule.get('timezone') or 'UTC')
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo('UTC')


def _minutes(text: str) -> int:
    hours, _, mins = text.partition(':')
    return int(hours) * 60 + int(mins or 0)


def _bounds(schedule: dict) -> tuple[int, int]:
    return _minutes(schedule.get('start') or '00:00'), _minutes(schedule.get('end') or '24:00')


def in_schedule(schedule: dict | None, now: datetime) -> bool:
    """Whether `now` falls in a rule's active hours. No schedule means always."""
    if not schedule:
        return True
    local = now.astimezone(_zone(schedule))
    days = schedule.get('days')
    minute = local.hour * 60 + local.minute
    lo, hi = _bounds(schedule)
    if lo == hi:
        inside, day = True, local.weekday()
    elif lo < hi:
        inside, day = lo <= minute < hi, local.weekday()
    else:
        # Wraps midnight: 22:00 to 06:00 belongs to the day it started on
        inside = minute >= lo or minute < hi
        day = local.weekday() if minute >= lo else (local.weekday() - 1) % 7
    return inside and (days is None or day in days)


def active_since(schedule: dict | None, now: datetime) -> datetime | None:
    """When the active hours that `now` falls in began, so a window can be cut
    there rather than reach into the hours before. None without a schedule,
    or for one that never pauses."""
    if not schedule or not in_schedule(schedule, now):
        return None
    lo, hi = _bounds(schedule)
    if lo == hi:
        return None
    zone = _zone(schedule)
    local = now.astimezone(zone)
    day = local.date()
    if lo > hi and local.hour * 60 + local.minute < lo:
        day -= timedelta(days=1)
    begin = datetime.combine(day, clock(lo // 60, lo % 60), tzinfo=zone)
    return begin.astimezone(timezone.utc)


def dedup_key(rule_id: uuid.UUID, hit: Hit) -> str:
    raw = f'{rule_id}|{hit.entity_field or ""}|{hit.entity_value or ""}|{hit.distinct}'
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()[:40]


TITLE_FIELDS = ('rule', 'entity', 'count', 'value', 'field')
_PLACEHOLDER = re.compile(r'\{([^{}]*)\}')


def check_title(template: str) -> None:
    """Refuses a title template with anything but the known placeholders. Raises RuleError."""
    unknown = sorted({name for name in _PLACEHOLDER.findall(template or '')
                      if name not in TITLE_FIELDS})
    if unknown:
        known = ', '.join('{' + n + '}' for n in TITLE_FIELDS)
        raise RuleError(f'{{{unknown[0]}}} is not something a title can show; use {known}.')


def render_title(template: str, rule: Rule, hit: Hit) -> str:
    """A finding's title. Placeholders are replaced as plain text, never
    formatted, so a template cannot reach into the values or pad them out."""
    entity = hit.entity_value or 'the network'
    values = {'rule': rule.name, 'entity': entity, 'count': f'{hit.count:,}',
              'value': hit.distinct or (f'{hit.value:g}' if isinstance(hit.value, float) else str(hit.value)),
              'field': hit.entity_field or ''}
    title = _PLACEHOLDER.sub(lambda m: values.get(m.group(1), m.group(0)),
                             template or '{rule}: {entity}')
    if not title.strip():
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
    entity = hit.entity_value
    if entity is not None and len(str(entity)) > ENTITY_MAX:
        # The dedup key holds the whole value; the column, a readable part
        entity = str(entity)[:ENTITY_MAX - 1] + '…'
    if finding is None:
        first_event = datetime.fromisoformat(hit.first.replace('Z', '+00:00')) if hit.first else now
        finding = Finding(
            rule_id=rule.id, rule_name=rule.name, rule_type=rule.type, category=rule.category,
            severity=rule.severity, status='new', title=render_title(rule.title_template, rule, hit),
            summary=hit.summary, entity_field=hit.entity_field, entity_value=entity,
            dedup_key=key, first_seen=first_event, last_seen=last_event, event_count=hit.count,
            occurrences=1, evidence=dict(evidence, last_notified=iso(now), rule_severity=rule.severity),
            tags=list(rule.tags or []))
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
    previous = finding.evidence or {}
    # Escalate if the rule's severity was raised since the finding opened, but
    # not merely because an analyst lowered this finding's
    raised_from = previous.get('rule_severity', finding.severity)
    if (SEVERITY_RANK.get(rule.severity, 0) > SEVERITY_RANK.get(raised_from, 0)
            and SEVERITY_RANK.get(rule.severity, 0) > SEVERITY_RANK.get(finding.severity, 0)):
        finding.severity = rule.severity
    finding.evidence = dict(evidence, last_notified=previous.get('last_notified'),
                            rule_severity=rule.severity,
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
                # The clock restarts whether or not a webhook wants reminders,
                # so the timeline gets one occurrence per re-alert gap, not one
                # per run
                sent = await hooks.enqueue_finding(db, 'finding.reminder', finding, rule)
                finding.evidence = dict(finding.evidence or {}, last_notified=iso(now))
                db.add(FindingActivity(finding_id=finding.id, actor_name='TurkeyBite Console',
                                       kind='occurrence', body=hit.summary,
                                       data={'count': hit.count, 'reminded': bool(sent)}))
    return created, updated


def _moments(rule: Rule, now: datetime, delay: timedelta) -> tuple[list[datetime], str]:
    """The instants to evaluate at: now less the ingest delay, and before it
    the ends of windows that were missed since the last run, oldest first.
    Also says what was skipped."""
    step = timedelta(seconds=rule.window_seconds)
    last = rule.last_run_at - delay if rule.last_run_at else None
    now = now - delay
    if last is None or last >= now or now - last <= step:
        return [now], ''
    note = ''
    if now - last > CATCH_UP:
        note = f'the {_hours(now - last - CATCH_UP)} before the last {_hours(CATCH_UP)} were not checked'
        last = now - CATCH_UP
    moments = []
    moment = last + step
    while moment < now:
        moments.append(moment)
        moment += step
    if len(moments) > CATCH_UP_STEPS:
        note = note or f'caught up on the last {CATCH_UP_STEPS} windows only'
        moments = moments[-CATCH_UP_STEPS:]
    return moments + [now], note


def _hours(span: timedelta) -> str:
    hours = span.total_seconds() / 3600
    return f'{hours:.0f} hour{"s" if round(hours) != 1 else ""}' if hours >= 1 else \
        f'{span.total_seconds() / 60:.0f} minutes'


async def run_rule(db: AsyncSession, search: SearchClient, rule: Rule, now: datetime | None = None,
                   persist: bool = True) -> RunOutcome:
    """Evaluates one rule at `now`, catching up on missed windows, and records what it found."""
    now = now or datetime.now(timezone.utc)
    started = time.monotonic()
    delay = timedelta(seconds=get_settings().rule_ingest_delay_sec)
    moments, note = _moments(rule, now, delay)
    moments = [m for m in moments if in_schedule(rule.schedule, m)]
    outcome = RunOutcome('skipped', reason='outside its active hours')
    first_start = now - delay - timedelta(seconds=rule.window_seconds)
    if moments:
        outcome = RunOutcome('ok', reason=note)
        evaluator = Evaluator(search)
        spec = spec_of(rule)
        last_end = rule.last_run_at - delay if rule.last_run_at else None
        previous = last_end if last_end and last_end < moments[0] else None
        try:
            for i, moment in enumerate(moments):
                recent_since = previous
                if recent_since is not None and (moment - recent_since).total_seconds() > rule.window_seconds:
                    recent_since = None
                # Cut a window that reaches back past the start of active hours
                start = None
                if rule.schedule and not in_schedule(rule.schedule, moment - timedelta(
                        seconds=rule.window_seconds)):
                    start = active_since(rule.schedule, moment)
                if i == 0:
                    full = moment - timedelta(seconds=rule.window_seconds)
                    first_start = max(start, full) if start else full
                evaluation: Evaluation = await evaluator.evaluate(spec, moment, recent_since, start)
                outcome.hits += len(evaluation.hits)
                if evaluation.status != 'ok':
                    outcome.status = evaluation.status
                    outcome.reason = '; '.join(r for r in (outcome.reason, evaluation.reason) if r)
                elif evaluation.reason:
                    outcome.reason = '; '.join(r for r in (outcome.reason, evaluation.reason) if r)
                if persist and evaluation.hits:
                    created, updated = await record_hits(db, rule, evaluation.hits, now)
                    outcome.created += created
                    outcome.updated += updated
                previous = moment
        except (RuleError, SearchError) as e:
            outcome = RunOutcome('error', error=str(e))
        except Exception as e:  # a rule must never take the scheduler down
            log.exception('rule %s failed', rule.id)
            outcome = RunOutcome('error', error=f'{type(e).__name__}: {e}')
        if outcome.status == 'skipped' and outcome.hits:
            outcome.status = 'ok'
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
                   window_start=first_start, window_end=now - delay,
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
        if not in_schedule(spec.schedule, moment):
            series.append({'t': iso(moment), 'hits': 0, 'status': 'skipped',
                           'reason': 'outside its active hours'})
            previous = None
            moment += timedelta(seconds=step)
            continue
        start = None
        if spec.schedule and not in_schedule(spec.schedule, moment - timedelta(seconds=spec.window_seconds)):
            start = active_since(spec.schedule, moment)
        evaluation = await evaluator.evaluate(spec, moment, previous, start)
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
            'warming_up': [s['reason'] for s in series if s['status'] == 'skipped'
                           and s['reason'] != 'outside its active hours'][:1]}


# -- built-in rules ------------------------------------------------------------------

async def sync_builtin_rules(db: AsyncSession) -> dict:
    """Adds missing built-in rules and upgrades unmodified ones. Returns counts.

    Several console processes starting at once would each add the same
    rules, so they take turns."""
    await db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': SYNC_LOCK})
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
            _copy_definition(rule, definition)
            db.add(rule)
            added += 1
        elif not rule.modified and (rule.builtin_version or 0) < definition['version']:
            _copy_definition(rule, definition)
            rule.builtin_version = definition['version']
            upgraded += 1
    await db.commit()
    return {'added': added, 'upgraded': upgraded}


def _copy_definition(rule: Rule, definition: dict) -> None:
    for name in defaults.DEFINITION_FIELDS:
        if name in definition:
            value = definition[name]
            # Stored as the API stores them, so a save without changes is not a change
            setattr(rule, name, sorted(set(value)) if name == 'tags' else value)


def reset_to_default(rule: Rule) -> None:
    definition = defaults.BY_KEY[rule.builtin_key]
    _copy_definition(rule, definition)
    if 'schedule' not in definition:
        rule.schedule = None
    rule.builtin_version = definition['version']
    rule.modified = False


def update_available(rule: Rule) -> bool:
    definition = defaults.BY_KEY.get(rule.builtin_key or '')
    return bool(definition and rule.modified and (rule.builtin_version or 0) < definition['version'])


# -- the scheduler ---------------------------------------------------------------------

async def lock_rule(db: AsyncSession, rule_id: uuid.UUID, wait: bool = False) -> Rule | None:
    """The rule, locked for a run; None if it does not exist or, unless
    `wait`, is running elsewhere right now."""
    stmt = select(Rule).where(Rule.id == rule_id).execution_options(populate_existing=True)
    stmt = stmt.with_for_update(of=Rule) if wait else stmt.with_for_update(of=Rule, skip_locked=True)
    return (await db.execute(stmt)).scalar_one_or_none()


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
                # Held until the run commits: a run still going when the rule
                # comes due again, here or in another process, is not doubled
                rule = await lock_rule(db, rule_id, wait=False)
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
            results = await asyncio.gather(*[self._run_one(i) for i in ids], return_exceptions=True)
            for rule_id, result in zip(ids, results):
                if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError):
                    log.error('running rule %s failed', rule_id, exc_info=result)
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
