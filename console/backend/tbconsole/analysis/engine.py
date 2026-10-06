"""Running rules, turning hits into findings, and the scheduler that drives it.

One open finding per rule and entity. A rule that matches the same person
again while their finding is still open adds an occurrence to it and counts
the new events, rather than raising another finding; the finding's re-alert
gap, the rule's dedup_seconds, decides whether that also sends a reminder.
Once a finding is resolved or marked a false positive, the next match raises
a new one.

Rules are claimed with FOR UPDATE SKIP LOCKED and their next run pushed
forward, and the claim takes a short lease on the rule, so any number of
console processes can run the scheduler, each rule runs once per interval,
and a slow run is not overlapped by the next. The lease is a column, not a
held lock: nothing waits on a rule while its run is asking OpenSearch, and no
database connection is held for it then.

A rule remembers the end of the last window it evaluated without error. The
next run starts from there, so windows missed while the console was stopped,
or that failed while the cluster was down, are evaluated when it is back, up
to a limit, and events that arrived late with their own timestamps still are.
"""

import asyncio
import hashlib
import logging
import re
import time
import uuid
from dataclasses import dataclass
from functools import partial
from datetime import datetime, time as clock, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import delete, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import db as database
from ..config import get_settings
from ..models import Finding, FindingActivity, Rule, RuleRun
from ..search.client import SearchClient, SearchError
from ..search.timerange import TimeRange, iso
from ..webhooks import service as hooks
from . import defaults
from .ruletypes import SEVERITY_RANK, BudgetSpent, Evaluation, Evaluator, Hit, RuleError, RuleSpec

log = logging.getLogger(__name__)

OPEN = ('new', 'acknowledged', 'in_progress')
RUNS_KEPT = 200
FAILURES_BEFORE_ALERT = 3
# How far back a run catches up on windows it missed, and in how many steps
CATCH_UP = timedelta(hours=6)
CATCH_UP_STEPS = 12
ENTITY_MAX = 400
# How long a claimed run may take before another process may start it
RUN_LEASE = timedelta(minutes=15)
# A run stops evaluating after this, to record what it did within its lease
RUN_DEADLINE = timedelta(minutes=9)
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


def _wall(day, minute: int, zone: ZoneInfo) -> datetime:
    """The instant a local wall-clock time names, in UTC: the first, when the
    clocks go back and it happens twice. A time the clocks skip, such as 02:30
    on the night they spring forward, names the moment they jump past it."""
    nominal = datetime.combine(day, clock(0, 0)) + timedelta(minutes=minute)
    candidates = [nominal.replace(tzinfo=zone, fold=fold).astimezone(timezone.utc) for fold in (0, 1)]
    for moment in sorted(candidates):
        if moment.astimezone(zone).replace(tzinfo=None) == nominal:
            return moment
    lo, hi = sorted(candidates)
    while hi - lo > timedelta(seconds=1):
        middle = lo + (hi - lo) / 2
        if middle.astimezone(zone).replace(tzinfo=None) >= nominal:
            hi = middle
        else:
            lo = middle
    return hi.replace(microsecond=0) if hi.microsecond else hi


def _periods(schedule: dict, around: datetime):
    """The active periods that could hold `around`: each (start, end) in UTC,
    from the one that began the day before to the one that begins the day
    after. A period belongs to the day it starts on. 08:00 to 16:00 lasts
    eight hours; 22:00 to 06:00 runs over midnight; a start equal to its end,
    or 00:00 to 24:00, is a whole day."""
    zone = _zone(schedule)
    lo, hi = _bounds(schedule)
    length = (hi - lo) % (24 * 60) or 24 * 60
    days = schedule.get('days')
    today = around.astimezone(zone).date()
    for offset in (-1, 0, 1):
        day = today + timedelta(days=offset)
        if days is not None and day.weekday() not in days:
            continue
        yield _wall(day, lo, zone), _wall(day, lo + length, zone)


def _period(schedule: dict, now: datetime) -> tuple[datetime, datetime] | None:
    for start, end in _periods(schedule, now):
        if start <= now < end:
            return start, end
    return None


def in_schedule(schedule: dict | None, now: datetime) -> bool:
    """Whether `now` falls in a rule's active hours. No schedule means always."""
    if not schedule:
        return True
    return _period(schedule, now) is not None


def window_cut(schedule: dict | None, end: datetime) -> datetime | None:
    """Where a window ending at `end` is cut, at the start of the active
    hours it belongs to: those `end` is in, or, for the window that ends
    them, those it closes."""
    if not schedule:
        return None
    return active_since(schedule, end if in_schedule(schedule, end) else end - timedelta(seconds=1))


def active_since(schedule: dict | None, now: datetime) -> datetime | None:
    """When the active hours that `now` falls in began, so a window can be cut
    there rather than reach into the hours before. Periods that run on into
    one another, such as whole days back to back, count as one. None without
    a schedule, or for one that never pauses."""
    if not schedule:
        return None
    current = _period(schedule, now)
    if current is None:
        return None
    start = current[0]
    for _ in range(8):
        before = _period(schedule, start - timedelta(seconds=1))
        if before is None or before[1] != start:
            return min(start, now)
        start = before[0]
    return None


def active_until(schedule: dict | None, now: datetime) -> datetime | None:
    """When the active hours that `now` falls in end, joined periods counted
    as one. None as for active_since."""
    if not schedule:
        return None
    current = _period(schedule, now)
    if current is None:
        return None
    end = current[1]
    for _ in range(8):
        after = _period(schedule, end)
        if after is None or after[0] != end:
            return max(end, now)
        end = after[1]
    return None


def _clean(value):
    """Postgres stores no NUL character, in text or in JSON; a value from the
    events that holds one would otherwise abort the whole run."""
    if isinstance(value, str):
        return value.replace('\x00', '\ufffd')
    if isinstance(value, dict):
        return {_clean(k): _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


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


async def _apply_hit(db: AsyncSession, rule: Rule, hit: Hit, now: datetime,
                     touched: set) -> tuple[bool, Finding]:
    """Creates or updates the open finding for a hit. Returns (created, finding).

    `touched` holds the findings this run has matched already: a run that
    catches up on several windows counts one occurrence, not one per window."""
    key = dedup_key(rule.id, hit)
    finding = (await db.execute(select(Finding).where(
        Finding.dedup_key == key, Finding.status.in_(OPEN))
        .with_for_update(of=Finding))).scalar_one_or_none()
    evidence = _clean(hit.evidence())
    summary = _clean(hit.summary)
    last_event = datetime.fromisoformat(hit.last.replace('Z', '+00:00')) if hit.last else now
    entity = _clean(hit.entity_value) if hit.entity_value is not None else None
    if entity is not None and len(str(entity)) > ENTITY_MAX:
        # The column holds a readable part; the evidence keeps the whole
        # value, which exceptions and links need
        evidence['entity_full'] = str(entity)
        entity = str(entity)[:ENTITY_MAX - 1] + '…'
    if finding is None:
        first_event = datetime.fromisoformat(hit.first.replace('Z', '+00:00')) if hit.first else now
        finding = Finding(
            rule_id=rule.id, rule_name=rule.name, rule_type=rule.type, category=rule.category,
            severity=rule.severity, status='new',
            title=_clean(render_title(rule.title_template, rule, hit)),
            summary=summary, entity_field=hit.entity_field, entity_value=entity,
            dedup_key=key, first_seen=first_event, last_seen=last_event, event_count=hit.count,
            occurrences=1, evidence=dict(evidence, last_notified=iso(now), rule_severity=rule.severity),
            tags=list(rule.tags or []))
        db.add(finding)
        await db.flush()
        touched.add(finding.id)
        db.add(FindingActivity(finding_id=finding.id, actor_name='TurkeyBite Console',
                               kind='created', body=summary,
                               data={'window': evidence['from'] + '/' + evidence['to'],
                                     'count': hit.count}))
        return True, finding
    finding.last_seen = max(finding.last_seen, last_event)
    if finding.id not in touched:
        finding.occurrences += 1
        touched.add(finding.id)
    finding.event_count += max(hit.recent, 0)
    finding.summary = summary
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


async def record_hits(db: AsyncSession, rule: Rule, hits: list[Hit], now: datetime,
                      touched: set | None = None) -> tuple[int, int, int]:
    """Turns hits into findings and queues their webhooks. Returns (created,
    updated, failed): a hit that cannot be stored is logged and skipped, so one
    odd value does not cost the run every other finding."""
    touched = set() if touched is None else touched
    created = updated = failed = 0
    for hit in hits:
        try:
            try:
                async with db.begin_nested():
                    is_new, finding = await _apply_hit(db, rule, hit, now, touched)
            except IntegrityError:
                # Another process opened the same finding a moment ago; add to it
                async with db.begin_nested():
                    is_new, finding = await _apply_hit(db, rule, hit, now, touched)
        except SQLAlchemyError:
            log.exception('rule %s: a hit for %s could not be recorded', rule.id, hit.entity_value)
            failed += 1
            continue
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
                                       kind='occurrence', body=_clean(hit.summary),
                                       data={'count': hit.count, 'reminded': bool(sent)}))
    return created, updated, failed


def plan(rule: Rule, end: datetime) -> tuple[list[datetime], str]:
    """The window ends to evaluate this run, oldest first, and a note on any
    that were given up.

    Within a window's length of where the rule last got to, one window ending
    now, as usual. Further behind, whole windows tile forward from there, so
    none is skipped and none is evaluated twice; what is left over, less than
    a window, waits for the next run. Outside the rule's active hours nothing
    is evaluated, except the last stretch of hours that ended since it last
    ran."""
    step = timedelta(seconds=rule.window_seconds)
    last = rule.evaluated_until
    note = ''
    if last is not None and last >= end:
        return [], ''
    if last is None or end - last <= step:
        candidates = [end]
    else:
        origin = last
        # Never further back than catch-up reaches, or than one window, for
        # a window longer than that
        last = max(last, end - max(CATCH_UP, step))
        candidates = []
        moment = last + step
        while moment <= end:
            candidates.append(moment)
            moment += step
        if len(candidates) > CATCH_UP_STEPS:
            candidates = candidates[-CATCH_UP_STEPS:]
        uncovered = candidates[0] - step - origin
        if uncovered > timedelta(0):
            note = f'{_hours(uncovered)} of missed windows were not checked'
    if not rule.schedule:
        return candidates, note
    moments: list[datetime] = []
    previous = rule.evaluated_until
    for moment in candidates:
        if in_schedule(rule.schedule, moment):
            moments.append(moment)
            previous = moment
            continue
        # The active hours ended since the last window: evaluate up to their end
        if previous is not None and in_schedule(rule.schedule, previous):
            tail = active_until(rule.schedule, previous)
            if tail is not None and previous < tail <= moment:
                moments.append(tail)
                previous = tail
    return moments, note


def _hours(span: timedelta) -> str:
    hours = span.total_seconds() / 3600
    if hours >= 1:
        return f'{hours:.0f} hour{"s" if round(hours) != 1 else ""}'
    return f'{span.total_seconds() / 60:.0f} minutes'


def _error_text(e: Exception) -> str:
    """What went wrong, in words fit for the rule's page and its alerts: never
    the SQL or the values a database error carries."""
    if isinstance(e, SQLAlchemyError):
        return f'the database refused it ({type(getattr(e, "orig", None) or e).__name__})'
    return f'{type(e).__name__}: {str(e)[:300]}'


async def run_rule(db: AsyncSession, search: SearchClient, rule: Rule, now: datetime | None = None,
                   persist: bool = True, lease: datetime | None = None) -> RunOutcome:
    """Evaluates one rule's due windows and records what they found.

    Every window is evaluated before anything is written, so no transaction
    is open while OpenSearch is asked; the windows that succeeded are then
    recorded together, and the rule's mark moves to the end of the last.

    With `lease`, the claim this run holds: before writing, the rule is read
    again under a lock, and if its lease is no longer this one, because the
    run outlived it and another took over, nothing is written. A run stops
    evaluating well before its lease ends, and records what it got done."""
    now = now or datetime.now(timezone.utc)
    started = time.monotonic()
    end = now - timedelta(seconds=get_settings().rule_ingest_delay_sec)
    moments, note = plan(rule, end)
    window = timedelta(seconds=rule.window_seconds)
    was_enabled = rule.enabled
    basis = cursor_basis(rule)
    outcome = RunOutcome('ok', reason=note)
    done: list[tuple[datetime, Evaluation]] = []
    state = dict(rule.state or {})
    if not moments:
        outcome = RunOutcome('skipped', reason='outside its active hours'
                             if rule.schedule and not in_schedule(rule.schedule, end) else 'nothing new to look at')
    else:
        evaluator = Evaluator(search)
        spec = spec_of(rule)
        previous = rule.evaluated_until
        for moment in moments:
            if time.monotonic() - started > RUN_DEADLINE.total_seconds():
                outcome.reason = '; '.join(r for r in (outcome.reason, 'stopped early to finish within '
                                                       'its lease; the rest is evaluated next run') if r)
                break
            recent_since = previous if previous is not None and previous < moment \
                and moment - previous <= window else None
            start = window_cut(rule.schedule, moment)
            try:
                evaluation = await evaluator.evaluate(spec, moment, recent_since, start, state=state)
            except (RuleError, SearchError) as e:
                outcome.status, outcome.error = 'error', str(e)
                break
            except Exception as e:  # a rule must never take the scheduler down
                log.exception('rule %s failed', rule.id)
                outcome.status, outcome.error = 'error', _error_text(e)
                break
            done.append((moment, evaluation))
            if evaluation.state is not None:
                state = evaluation.state
            previous = moment
        for _, evaluation in done:
            outcome.hits += len(evaluation.hits)
            if evaluation.reason:
                outcome.reason = '; '.join(r for r in (outcome.reason, evaluation.reason) if r)
        if done and outcome.status == 'ok' and all(e.status == 'skipped' for _, e in done):
            outcome.status = 'skipped'
    outcome.duration_ms = int((time.monotonic() - started) * 1000)
    if not persist:
        return outcome
    # The rule as it is now, locked for the few writes that follow: it may
    # have been edited, switched off, deleted, or claimed by another run
    current = (await db.execute(select(Rule).where(Rule.id == rule.id).with_for_update()
                                .execution_options(populate_existing=True))).scalar_one_or_none()
    if current is None:
        return RunOutcome('skipped', reason='the rule was deleted during the run')
    rule = current
    if lease is not None and rule.running_until != lease:
        log.warning('rule %s: a run outlived its lease and another took over; its results are '
                    'not recorded', rule.id)
        return RunOutcome('skipped', reason='another run took over')
    if was_enabled and not rule.enabled:
        rule.running_until = None
        return RunOutcome('skipped', reason='switched off during the run')
    if cursor_basis(rule) != basis:
        # Edited while it ran, an exception added say: what it found was
        # found by the old version, so the new one looks again next run
        rule.running_until = None
        return RunOutcome('skipped', reason='changed during the run; the next run uses the new version')
    touched: set = set()
    failed = 0
    for moment, evaluation in done:
        if evaluation.hits:
            created, updated, lost = await record_hits(db, rule, evaluation.hits, now, touched)
            outcome.created += created
            outcome.updated += updated
            failed += lost
        # Only ever forward: a mark never goes back over windows already done
        rule.evaluated_until = max(rule.evaluated_until or moment, moment)
    if done:
        rule.state = state
    if not moments and outcome.status == 'skipped':
        # Nothing in these hours is the rule's to look at
        rule.evaluated_until = max(rule.evaluated_until or end, end)
    if failed:
        outcome.reason = '; '.join(r for r in (outcome.reason, f'{failed} hits could not be recorded') if r)
    rule.last_run_at = now
    rule.running_until = None
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
    first = done[0][0] - window if done else end - window
    if done and rule.schedule:
        cut = window_cut(rule.schedule, done[0][0])
        first = max(first, cut) if cut else first
    db.add(RuleRun(rule_id=rule.id, started_at=now, finished_at=datetime.now(timezone.utc),
                   window_start=first, window_end=done[-1][0] if done else end,
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
# Requests one backtest may send, whatever the rule: a first-seen rule over
# a busy network pages through many values at every step
BACKTEST_BUDGET = 600


async def backtest(search: SearchClient, spec: RuleSpec, tr: TimeRange) -> dict:
    """What a rule would have raised over `tr`, evaluated at its interval.

    Nothing is recorded. Long ranges are sampled at a coarser step so a test
    stays a few dozen queries.
    """
    step = max(spec.interval_seconds, int(tr.seconds / MAX_BACKTEST_STEPS) + 1)
    evaluator = Evaluator(search, budget=BACKTEST_BUDGET)
    moment = tr.start + timedelta(seconds=spec.window_seconds)
    if moment > tr.end:
        moment = tr.end
    series, samples, entities, statuses = [], [], {}, set()
    previous: datetime | None = None
    stopped: str | None = None
    while moment <= tr.end:
        if not in_schedule(spec.schedule, moment):
            series.append({'t': iso(moment), 'hits': 0, 'status': 'skipped',
                           'reason': 'outside its active hours'})
            previous = None
            moment += timedelta(seconds=step)
            continue
        start = window_cut(spec.schedule, moment)
        try:
            evaluation = await evaluator.evaluate(spec, moment, previous, start)
        except BudgetSpent:
            stopped = iso(moment)
            break
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
                           and s['reason'] != 'outside its active hours'][:1],
            # Where it stopped, when the rule needs more requests than a backtest may send
            'stopped_at': stopped}


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


# What a rule's saved reading position is a position in: change any of them,
# and it points at nothing, or at values of the wrong kind
CURSOR_FIELDS = ('type', 'query', 'params', 'group_by', 'exceptions')


def cursor_basis(rule: Rule) -> tuple:
    return tuple(getattr(rule, name) for name in CURSOR_FIELDS)


def forget_position_if_changed(rule: Rule, before: tuple) -> None:
    """Clears where a first-seen or silence rule had got to, when what it
    reads has changed since `before`, so it starts again from the beginning."""
    if cursor_basis(rule) != before:
        rule.state = {}


def _copy_definition(rule: Rule, definition: dict) -> None:
    before = cursor_basis(rule)
    for name in defaults.DEFINITION_FIELDS:
        if name in definition:
            value = definition[name]
            # Stored as the API stores them, so a save without changes is not a change
            setattr(rule, name, sorted(set(value)) if name == 'tags' else value)
    forget_position_if_changed(rule, before)


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

async def claim_run(db: AsyncSession, rule_id: uuid.UUID) -> tuple[datetime, datetime] | None:
    """Takes the lease to run a rule, and commits it. Returns the database's
    time, which the run uses as now, and the lease, which the run shows when
    it writes; None when the rule is running elsewhere. Database time, so
    replicas with different clocks agree."""
    row = (await db.execute(
        update(Rule).where(Rule.id == rule_id,
                           or_(Rule.running_until.is_(None), Rule.running_until < func.now()))
        .values(running_until=func.now() + RUN_LEASE)
        .returning(func.now(), Rule.running_until))).first()
    await db.commit()
    return (row[0], row[1]) if row else None


async def release_run(rule_id: uuid.UUID, lease: datetime) -> None:
    """Gives a lease back, if it is still this run's, after a run that ended
    without recording, so the rule need not wait out the lease."""
    async with database.sessionmaker()() as db:
        await db.execute(update(Rule).where(Rule.id == rule_id, Rule.running_until == lease)
                         .values(running_until=None))
        await db.commit()


async def claim_due(db: AsyncSession, now: datetime, limit: int = 10) -> list[Rule]:
    rules = (await db.execute(
        select(Rule).where(Rule.enabled.is_(True), Rule.next_run_at <= now,
                           or_(Rule.running_until.is_(None), Rule.running_until < now))
        .order_by(Rule.next_run_at).limit(limit).with_for_update(skip_locked=True))).scalars().all()
    for rule in rules:
        # On the rule's own beat, so that a tick arriving a few seconds late
        # does not push every run after it later too
        interval = timedelta(seconds=rule.interval_seconds)
        beat = rule.next_run_at + interval
        rule.next_run_at = beat if beat > now else now + interval
    return list(rules)


class Scheduler:
    """Runs due rules, side by side: each in a task of its own, so one slow
    rule holds up nothing but itself."""

    def __init__(self, search: SearchClient, poll_seconds: float = 5.0, concurrency: int = 4):
        self.search = search
        self.poll_seconds = poll_seconds
        self.concurrency = concurrency
        self.tasks: set[asyncio.Task] = set()
        self._task: asyncio.Task | None = None
        self.last_tick: datetime | None = None

    async def _run_one(self, rule_id: uuid.UUID) -> None:
        async with database.sessionmaker()() as db:
            claimed = await claim_run(db, rule_id)
            if claimed is None:
                return
            now, lease = claimed
            try:
                rule = await db.get(Rule, rule_id)
                if rule is None or not rule.enabled:
                    await release_run(rule_id, lease)
                    return
                # Nothing is held while OpenSearch is asked
                await db.commit()
                await run_rule(db, self.search, rule, now=now, lease=lease)
                await prune_runs(db, rule.id)
                await db.commit()
            except asyncio.CancelledError:
                # Given back even when the run was cancelled, so the rule
                # does not wait out the lease; in a task of its own, since
                # this one is being stopped
                asyncio.ensure_future(release_run(rule_id, lease))
                raise
            except Exception:
                await db.rollback()
                await release_run(rule_id, lease)
                raise

    def _finished(self, rule_id: uuid.UUID, task: asyncio.Task) -> None:
        self.tasks.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            log.error('running rule %s failed', rule_id, exc_info=error)

    async def tick(self) -> int:
        """Starts the rules that are due, as many as there are free places.
        Returns how many it started."""
        free = self.concurrency - len(self.tasks)
        if free <= 0:
            return 0
        async with database.sessionmaker()() as db:
            async with db.begin():
                # The database's clock, so replicas agree on what is due
                now = (await db.execute(select(func.now()))).scalar_one()
                due = await claim_due(db, now, limit=free)
                ids = [r.id for r in due]
        for rule_id in ids:
            task = asyncio.create_task(self._run_one(rule_id), name=f'rule-{rule_id}')
            self.tasks.add(task)
            task.add_done_callback(partial(self._finished, rule_id))
        self.last_tick = datetime.now(timezone.utc)
        return len(ids)

    async def drain(self) -> None:
        """Waits for the runs under way, for tests and for stopping."""
        if self.tasks:
            await asyncio.gather(*list(self.tasks), return_exceptions=True)

    async def loop(self) -> None:
        while True:
            try:
                started = await self.tick()
                if started and len(self.tasks) < self.concurrency:
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
        for task in list(self.tasks):
            task.cancel()
        await self.drain()
