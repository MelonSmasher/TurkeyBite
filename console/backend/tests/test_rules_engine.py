"""Rule types and the engine: what fires, what does not, and how findings are kept."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from tbconsole import db
from tbconsole.analysis import defaults, engine
from tbconsole.analysis.ruletypes import Evaluator, RuleError, RuleSpec, normalise
from tbconsole.models import Finding, FindingActivity, Rule, RuleRun, Webhook, WebhookDelivery
from tbconsole.security import crypto

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def grouped(field, buckets, extra=None):
    """An aggregation answer for group_aggs over one entity field."""
    from tbconsole.search import fields as F
    aggs = {}
    for i, name in enumerate(F.ENTITY_FIELDS):
        aggs[f'g{i}'] = {'doc_count': 0, 't': {'buckets': []}}
        if name == field:
            aggs[f'g{i}']['t']['buckets'] = buckets
    return {'hits': {'total': {'value': sum(b['doc_count'] for b in buckets)}}, 'aggregations': aggs}


def bucket(key, count, **extra):
    return {'key': key, 'doc_count': count, 'dom': {'buckets': [{'key': 'x.example', 'doc_count': count}]},
            'cat': {'buckets': []}, 'first': {'value_as_string': '2026-10-05T11:50:00.000Z'},
            'last': {'value_as_string': '2026-10-05T11:58:00.000Z'}, 'recent': {'doc_count': count}, **extra}


# -- validation -------------------------------------------------------------------

def test_every_shipped_rule_is_valid():
    for rule in defaults.DEFAULT_RULES:
        spec = RuleSpec(name=rule['name'], type=rule['type'], query=rule['query'], params=rule['params'],
                        group_by=rule['group_by'], window_seconds=rule['window_seconds'],
                        interval_seconds=rule['interval_seconds'])
        normalise(spec)


def test_the_shipped_rules_have_unique_keys():
    keys = [r['key'] for r in defaults.DEFAULT_RULES]
    assert len(keys) == len(set(keys))


@pytest.mark.parametrize('change, message', [
    ({'type': 'nonsense'}, 'not a rule type'),
    ({'query': 'categry:x'}, 'The query has a mistake'),
    ({'params': {'threshold': 0}}, 'at least 1'),
    ({'window_seconds': 10}, 'between a minute'),
    ({'group_by': ['packet.secret']}, 'cannot group by'),
])
def test_a_bad_rule_is_refused_in_words(change, message):
    spec = RuleSpec(**{'name': 'x', 'type': 'threshold', **change})
    with pytest.raises(RuleError, match=message):
        normalise(spec)


# -- evaluation -----------------------------------------------------------------

async def test_threshold_fires_per_entity_at_the_threshold(search):
    search.answer = lambda body, index=None: grouped('bite.client_user', [bucket('ava', 3), bucket('liam', 1)])
    spec = RuleSpec(name='t', type='threshold', query='risk:threat', params={'threshold': 2}, group_by=['entity'])
    result = await Evaluator(search).evaluate(spec, NOW)
    assert [h.entity_value for h in result.hits] == ['ava']
    assert result.hits[0].entity_field == 'bite.client_user'
    assert 'user:ava' in result.hits[0].evidence_query
    # The time window and the query both reach OpenSearch
    filters = search.bodies[0]['query']['bool']['filter']
    assert filters[0]['range']['@timestamp']['lt'].startswith('2026-10-05T12:00')


async def test_exceptions_are_excluded_in_the_query(search):
    search.answer = lambda body, index=None: grouped('bite.client_user', [])
    spec = RuleSpec(name='t', type='threshold', params={'threshold': 1}, group_by=['entity'],
                    exceptions=[{'query': 'host:staff-1'},
                                {'query': 'host:old', 'expires_at': '2020-01-01T00:00:00Z'}])
    await Evaluator(search).evaluate(spec, NOW)
    must_not = search.bodies[0]['query']['bool']['must_not']
    assert len(must_not) == 1, 'an expired exception no longer applies'


async def test_unique_count_compares_distinct_values(search):
    search.answer = lambda body, index=None: grouped('bite.client', [
        bucket('10.0.0.1', 900, distinct={'value': 650}), bucket('10.0.0.2', 900, distinct={'value': 20})])
    spec = RuleSpec(name='u', type='unique_count', params={'field': 'domain', 'threshold': 300}, group_by=['entity'])
    hits = (await Evaluator(search).evaluate(spec, NOW)).hits
    assert [h.entity_value for h in hits] == ['10.0.0.1']
    assert hits[0].value == 650


async def test_ratio_needs_both_the_share_and_enough_events(search):
    search.answer = lambda body, index=None: grouped('bite.client', [
        bucket('a', 200, num={'doc_count': 150}),   # 75%, enough events: fires
        bucket('b', 20, num={'doc_count': 20}),     # 100%, too few events
        bucket('c', 400, num={'doc_count': 40})])   # 10%
    spec = RuleSpec(name='r', type='ratio', params={'numerator': 'rcode:NXDOMAIN', 'ratio': 0.6, 'min_count': 50},
                    group_by=['entity'])
    hits = (await Evaluator(search).evaluate(spec, NOW)).hits
    assert [h.entity_value for h in hits] == ['a']


async def test_spike_needs_a_real_rise_over_the_baseline(search):
    def periods(baseline, current):
        buckets = [{'key': f'b{i}', 'doc_count': v} for i, v in enumerate(baseline, start=1)]
        return {'buckets': buckets + [{'key': 'cur', 'doc_count': current}]}
    flat = [10] * 24
    search.answer = lambda body, index=None: grouped('bite.client_user', [
        {**bucket('burst', 0), 'periods': periods(flat, 400), 'cur': bucket('burst', 400)},
        {**bucket('steady', 0), 'periods': periods(flat, 12), 'cur': bucket('steady', 12)},
        {**bucket('busy-always', 0), 'periods': periods([380] * 24, 420), 'cur': bucket('busy-always', 420)}])
    spec = RuleSpec(name='s', type='spike', params={'baseline_windows': 24, 'z_score': 4, 'ratio': 3, 'min_count': 50},
                    group_by=['entity'], window_seconds=3600)
    hits = (await Evaluator(search).evaluate(spec, NOW)).hits
    assert [h.entity_value for h in hits] == ['burst']


async def test_new_value_waits_until_it_has_the_history(search):
    youngest = (NOW - timedelta(days=2)).timestamp() * 1000
    search.answer = lambda body, index=None: {'aggregations': {'oldest': {'value': youngest}}, 'hits': {'total': {'value': 0}}}
    spec = RuleSpec(name='n', type='new_value', params={'field': 'site', 'lookback_days': 14})
    result = await Evaluator(search).evaluate(spec, NOW)
    assert result.status == 'skipped'
    assert 'warming up' in result.reason


async def test_new_value_reports_only_values_unseen_before(search):
    oldest = (NOW - timedelta(days=60)).timestamp() * 1000
    answers = iter([
        {'aggregations': {'oldest': {'value': oldest}}},
        {'aggregations': {'v': {'buckets': [bucket('seen.example', 4), bucket('new.example', 2)]}}, 'hits': {'total': {'value': 6}}},
        {'aggregations': {'v': {'buckets': [{'key': 'seen.example', 'doc_count': 99}]}}, 'hits': {'total': {'value': 99}}},
    ])
    search.answer = lambda body, index=None: next(answers)
    spec = RuleSpec(name='n', type='new_value', params={'field': 'site', 'lookback_days': 14})
    hits = (await Evaluator(search).evaluate(spec, NOW)).hits
    assert [h.extra['new_value'] for h in hits] == ['new.example']
    assert hits[0].distinct == 'new.example'


async def test_absence_fires_only_after_a_normal_period(search):
    counts = iter([0, 500])
    search.answer = lambda body, index=None: {'hits': {'total': {'value': next(counts)}}, 'count': 500}
    spec = RuleSpec(name='a', type='absence', params={'threshold': 1, 'lookback_seconds': 86400, 'min_baseline': 100})
    hits = (await Evaluator(search).evaluate(spec, NOW)).hits
    assert len(hits) == 1 and hits[0].entity_value is None


# -- the engine and findings -------------------------------------------------------------

async def _rule(**extra) -> Rule:
    async with db.sessionmaker()() as session:
        rule = Rule(name='Threat seen', type='threshold', query='risk:threat', params={'threshold': 1},
                    group_by=['entity'], severity='high', enabled=True, window_seconds=900, interval_seconds=300,
                    dedup_seconds=3600, category='threat', **extra)
        session.add(rule)
        await session.commit()
        await session.refresh(rule)
        return rule


async def _run(search, rule_id, now):
    async with db.sessionmaker()() as session:
        rule = await session.get(Rule, rule_id)
        outcome = await engine.run_rule(session, search, rule, now=now)
        await session.commit()
        return outcome


async def test_a_repeat_match_updates_one_open_finding(search):
    rule = await _rule()
    search.answer = lambda body, index=None: grouped('bite.client_user', [bucket('ava', 3)])
    first = await _run(search, rule.id, NOW)
    second = await _run(search, rule.id, NOW + timedelta(minutes=5))
    assert (first.created, second.created, second.updated) == (1, 0, 1)
    async with db.sessionmaker()() as session:
        findings = (await session.execute(select(Finding))).scalars().all()
        assert len(findings) == 1
        assert findings[0].occurrences == 2
        assert findings[0].title == 'Threat seen: ava'
        runs = (await session.execute(select(func.count()).select_from(RuleRun))).scalar_one()
        assert runs == 2


async def test_a_resolved_finding_is_not_reopened_a_new_one_is_raised(search):
    rule = await _rule()
    search.answer = lambda body, index=None: grouped('bite.client_user', [bucket('ava', 3)])
    await _run(search, rule.id, NOW)
    async with db.sessionmaker()() as session:
        finding = (await session.execute(select(Finding))).scalar_one()
        finding.status = 'resolved'
        await session.commit()
    outcome = await _run(search, rule.id, NOW + timedelta(minutes=5))
    assert outcome.created == 1


async def test_new_findings_are_queued_for_matching_webhooks(search):
    async with db.sessionmaker()() as session:
        session.add_all([
            Webhook(name='all high', url='https://example.com/a', secret_enc=crypto.encrypt('s'),
                    events=['finding.created'], all_findings=True, min_severity='high'),
            Webhook(name='critical only', url='https://example.com/b', secret_enc=crypto.encrypt('s'),
                    events=['finding.created'], all_findings=True, min_severity='critical'),
            Webhook(name='off', url='https://example.com/c', secret_enc=crypto.encrypt('s'),
                    events=['finding.created'], all_findings=True, min_severity='info', enabled=False),
        ])
        await session.commit()
    rule = await _rule()
    search.answer = lambda body, index=None: grouped('bite.client_user', [bucket('ava', 3)])
    await _run(search, rule.id, NOW)
    async with db.sessionmaker()() as session:
        deliveries = (await session.execute(select(WebhookDelivery))).scalars().all()
        assert len(deliveries) == 1
        assert deliveries[0].payload['finding']['entity'] == 'ava'


async def test_a_rule_outside_its_hours_does_not_run(search):
    rule = await _rule(schedule={'days': [0, 1, 2, 3, 4], 'start': '22:00', 'end': '06:00', 'timezone': 'UTC'})
    outcome = await _run(search, rule.id, NOW)  # a Monday at noon
    assert outcome.status == 'skipped'
    assert not search.bodies


def test_schedules_that_wrap_midnight_belong_to_the_day_they_start():
    schedule = {'days': [4], 'start': '22:00', 'end': '06:00', 'timezone': 'UTC'}  # Friday night
    friday_late = datetime(2026, 10, 9, 23, 0, tzinfo=timezone.utc)
    saturday_early = datetime(2026, 10, 10, 3, 0, tzinfo=timezone.utc)
    saturday_late = datetime(2026, 10, 10, 23, 0, tzinfo=timezone.utc)
    assert engine.in_schedule(schedule, friday_late)
    assert engine.in_schedule(schedule, saturday_early)
    assert not engine.in_schedule(schedule, saturday_late)


async def test_a_failing_rule_records_the_error_and_keeps_going(search):
    from tbconsole.search.client import SearchUnavailable

    async def broken(body, index=None):
        raise SearchUnavailable('no OpenSearch host could be reached')
    search.search = broken
    rule = await _rule()
    outcome = await _run(search, rule.id, NOW)
    assert outcome.status == 'error'
    async with db.sessionmaker()() as session:
        rule = await session.get(Rule, rule.id)
        assert rule.consecutive_failures == 1 and 'could be reached' in rule.last_error


async def test_builtin_rules_are_added_once_and_upgraded_only_when_unmodified(monkeypatch):
    async with db.sessionmaker()() as session:
        first = await engine.sync_builtin_rules(session)
        again = await engine.sync_builtin_rules(session)
    assert first['added'] == len(defaults.DEFAULT_RULES) and again['added'] == 0
    async with db.sessionmaker()() as session:
        tuned = (await session.execute(select(Rule).where(Rule.builtin_key == 'gambling'))).scalar_one()
        tuned.params = {'threshold': 9}
        tuned.modified = True
        await session.commit()
    bumped = [dict(r, version=r['version'] + 1, params={'threshold': 99}) if r['key'] in ('gambling', 'drugs') else r
              for r in defaults.DEFAULT_RULES]
    monkeypatch.setattr(defaults, 'DEFAULT_RULES', bumped)
    monkeypatch.setattr(defaults, 'BY_KEY', {r['key']: r for r in bumped})
    async with db.sessionmaker()() as session:
        result = await engine.sync_builtin_rules(session)
        assert result['upgraded'] == 1
        gambling = (await session.execute(select(Rule).where(Rule.builtin_key == 'gambling'))).scalar_one()
        drugs = (await session.execute(select(Rule).where(Rule.builtin_key == 'drugs'))).scalar_one()
        assert gambling.params == {'threshold': 9} and engine.update_available(gambling)
        assert drugs.params == {'threshold': 99}
        engine.reset_to_default(gambling)
        assert gambling.params == {'threshold': 99} and not gambling.modified


async def test_backtest_samples_a_range_and_records_nothing(search):
    search.answer = lambda body, index=None: grouped('bite.client_user', [bucket('ava', 3)])
    spec = RuleSpec(name='t', type='threshold', query='risk:threat', params={'threshold': 1}, group_by=['entity'],
                    interval_seconds=300, window_seconds=900)
    from tbconsole.search.timerange import TimeRange
    result = await engine.backtest(search, spec, TimeRange(NOW - timedelta(hours=24), NOW))
    assert result['evaluations'] <= engine.MAX_BACKTEST_STEPS + 1
    assert result['distinct_findings'] == 1
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(func.count()).select_from(Finding))).scalar_one() == 0
        assert (await session.execute(select(func.count()).select_from(FindingActivity))).scalar_one() == 0
