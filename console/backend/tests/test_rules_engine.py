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


def composite(buckets, after=None):
    out = {'aggregations': {'c': {'buckets': buckets}}, 'hits': {'total': {'value': 0}}}
    if after is not None:
        out['aggregations']['c']['after_key'] = after
    return out


def keyed(key: dict, count: int) -> dict:
    return {**bucket('', count), 'key': key}


def history(counts: dict) -> dict:
    """The answer to a first-seen rule's history check: a filter per pair."""
    return {'aggregations': {'f': {'buckets': {str(k): {'doc_count': v} for k, v in counts.items()}}},
            'hits': {'total': {'value': 0}}}


async def test_new_value_reports_only_values_unseen_before(search):
    oldest = (NOW - timedelta(days=60)).timestamp() * 1000
    answers = iter([
        {'aggregations': {'oldest': {'value': oldest}}},
        composite([keyed({'v': 'seen.example'}, 4), keyed({'v': 'new.example'}, 2)], {'v': 'new.example'}),
        history({0: 99, 1: 0}),
    ])
    search.answer = lambda body, index=None: next(answers)
    spec = RuleSpec(name='n', type='new_value', params={'field': 'site', 'lookback_days': 14})
    hits = (await Evaluator(search).evaluate(spec, NOW)).hits
    assert [h.extra['new_value'] for h in hits] == ['new.example']
    assert hits[0].distinct == 'new.example'
    assert hits[0].evidence_query == 'domain:new.example' or 'new.example' in hits[0].evidence_query


async def test_absence_fires_only_after_a_normal_period(search):
    counts = iter([0, 500])
    search.answer = lambda body, index=None: {'hits': {'total': {'value': next(counts)}}, 'count': 500}
    spec = RuleSpec(name='a', type='absence', params={'threshold': 1, 'lookback_seconds': 86400, 'min_baseline': 100})
    hits = (await Evaluator(search).evaluate(spec, NOW)).hits
    assert len(hits) == 1 and hits[0].entity_value is None


# -- the engine and findings -------------------------------------------------------------

async def _rule(**extra) -> Rule:
    async with db.sessionmaker()() as session:
        rule = Rule(**{'name': 'Threat seen', 'type': 'threshold', 'query': 'risk:threat',
                       'params': {'threshold': 1}, 'group_by': ['entity'], 'severity': 'high', 'enabled': True,
                       'window_seconds': 900, 'interval_seconds': 300, 'dedup_seconds': 3600,
                       'category': 'threat', **extra})
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
            Webhook(name='all high', url_enc=crypto.encrypt('https://example.com/a'), url_display='https://example.com/', secret_enc=crypto.encrypt('s'),
                    events=['finding.created'], all_findings=True, min_severity='high'),
            Webhook(name='critical only', url_enc=crypto.encrypt('https://example.com/b'), url_display='https://example.com/', secret_enc=crypto.encrypt('s'),
                    events=['finding.created'], all_findings=True, min_severity='critical'),
            Webhook(name='off', url_enc=crypto.encrypt('https://example.com/c'), url_display='https://example.com/', secret_enc=crypto.encrypt('s'),
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


# -- what the critical review found -------------------------------------------------------

def _group_field(body):
    """The entity field a composite request is scoped to, from its group filter."""
    for part in body['query']['bool']['filter']:
        inner = part.get('bool', {}).get('filter', [{}])
        if inner and 'exists' in inner[0]:
            return inner[0]['exists']['field']
    return None


@pytest.mark.parametrize('change, message', [
    ({'window_seconds': 300, 'interval_seconds': 600}, 'at least as long as the time between runs'),
    ({'type': 'spike', 'window_seconds': 86400, 'interval_seconds': 3600,
      'params': {'baseline_windows': 96}}, 'keep it within 90'),
    ({'type': 'absence', 'params': {'lookback_seconds': 60 * 86400}}, 'at most'),
])
def test_rules_that_would_miss_events_or_read_too_far_back_are_refused(change, message):
    spec = RuleSpec(**{'name': 'x', 'type': 'threshold', **change})
    with pytest.raises(RuleError, match=message):
        normalise(spec)


def test_every_part_of_an_evidence_query_is_bracketed():
    from tbconsole.analysis.ruletypes import _evidence_query
    spec = RuleSpec(name='x', type='ratio', query='risk:threat OR risk:malware',
                    exceptions=[{'query': 'host:lab-1'}])
    text = _evidence_query(spec, 'bite.client_user', 'ava', 'rcode:NXDOMAIN OR rcode:SERVFAIL')
    assert text == ('(risk:threat OR risk:malware) AND user:ava AND (rcode:NXDOMAIN OR rcode:SERVFAIL)'
                    ' AND NOT (host:lab-1)')
    # A query with no spaces is bracketed too: an OR needs none around it
    assert _evidence_query(RuleSpec(name='x', type='threshold', query='(a:1)OR(b:2)'), None, None) == '((a:1)OR(b:2))'


async def test_threshold_asks_only_for_groups_at_the_threshold(search):
    search.answer = lambda body, index=None: grouped('bite.client_user', [])
    spec = RuleSpec(name='t', type='threshold', params={'threshold': 25}, group_by=['entity'])
    await Evaluator(search).evaluate(spec, NOW)
    assert search.bodies[0]['aggs']['g0']['aggs']['t']['terms']['min_doc_count'] == 25


async def test_distinct_and_ratio_rules_keep_the_groups_they_measure_not_the_busiest(search):
    search.answer = lambda body, index=None: grouped('bite.client_user', [])
    await Evaluator(search).evaluate(RuleSpec(name='u', type='unique_count', group_by=['entity'],
                                              params={'field': 'domain', 'threshold': 5}), NOW)
    await Evaluator(search).evaluate(RuleSpec(name='r', type='ratio', group_by=['entity'],
                                              params={'min_count': 40}), NOW)
    unique_terms = search.bodies[0]['aggs']['g0']['aggs']['t']['terms']
    assert unique_terms['order'] == {'distinct': 'desc'}
    # Ratio ranks groups by their share, worked out by OpenSearch, among many
    scan = search.bodies[1]['aggs']['g0']['aggs']['t']
    assert scan['terms']['min_doc_count'] == 40 and scan['terms']['size'] > 200
    assert scan['aggs']['best']['bucket_sort']['sort'] == [{'share': {'order': 'desc'}}]


async def test_new_value_pages_through_every_value_not_just_the_busiest(search, monkeypatch):
    from tbconsole.analysis import ruletypes
    monkeypatch.setattr(ruletypes, 'PAGE', 2)
    oldest = (NOW - timedelta(days=60)).timestamp() * 1000
    answers = iter([
        {'aggregations': {'oldest': {'value': oldest}}},
        composite([keyed({'v': 'a.example'}, 900), keyed({'v': 'b.example'}, 500)], {'v': 'b.example'}),
        composite([keyed({'v': 'rare.example'}, 1)], {'v': 'rare.example'}),
        history({0: 9, 1: 9, 2: 0}),
    ])
    search.answer = lambda body, index=None: next(answers)
    spec = RuleSpec(name='n', type='new_value', params={'field': 'site', 'lookback_days': 14})
    hits = (await Evaluator(search).evaluate(spec, NOW)).hits
    assert [h.extra['new_value'] for h in hits] == ['rare.example']
    assert search.bodies[2]['aggs']['c']['composite']['after'] == {'v': 'b.example'}
    # The history is asked about every value in the window, each on its own
    filters = search.bodies[3]['aggs']['f']['filters']['filters']
    assert [f['bool']['filter'][0]['term']['bite.registrable_domain'] for f in filters.values()] == [
        'a.example', 'b.example', 'rare.example']


async def test_new_value_per_entity_compares_each_entity_with_its_own_history(search):
    oldest = (NOW - timedelta(days=60)).timestamp() * 1000

    def answer(body, index=None):
        aggs = body.get('aggs', {})
        if 'oldest' in aggs:
            return {'aggregations': {'oldest': {'value': oldest}}}
        if 'f' in aggs:
            # Ava has watched video before; Liam has not
            seen = {}
            for key, f in aggs['f']['filters']['filters'].items():
                terms = {k: v for t in f['bool']['filter'] for k, v in t['term'].items()}
                seen[int(key)] = 50 if terms.get('bite.client_user') == 'ava' else 0
            return history(seen)
        if _group_field(body) != 'bite.client_user':
            return composite([])
        return composite([keyed({'g': 'ava', 'v': 'video'}, 3), keyed({'g': 'liam', 'v': 'video'}, 2)])
    search.answer = answer
    spec = RuleSpec(name='n', type='new_value', group_by=['entity'],
                    params={'field': 'bite.purpose', 'lookback_days': 14})
    hits = (await Evaluator(search).evaluate(spec, NOW)).hits
    assert [(h.entity_value, h.distinct) for h in hits] == [('liam', 'video')]
    assert hits[0].entity_field == 'bite.client_user'
    # Each pair is checked on its own field: a user name never meets the IP field
    for body in search.bodies:
        for f in ((body.get('aggs') or {}).get('f') or {}).get('filters', {}).get('filters', {}).values():
            assert all('bite.client' not in t['term'] for t in f['bool']['filter'])


async def test_grouped_silence_looks_at_every_group_that_was_active(search, monkeypatch):
    from tbconsole.analysis import ruletypes
    monkeypatch.setattr(ruletypes, 'PAGE', 2)
    pages = {
        None: composite([{'key': {'g': 'busy-1'}, 'doc_count': 900, 'past': {'doc_count': 890}, 'now': {'doc_count': 10}},
                         {'key': {'g': 'busy-2'}, 'doc_count': 800, 'past': {'doc_count': 790}, 'now': {'doc_count': 10}}],
                        {'g': 'busy-2'}),
        'busy-2': composite([{'key': {'g': 'quiet-agent'}, 'doc_count': 40, 'past': {'doc_count': 40},
                              'now': {'doc_count': 0}, 'last': {'value_as_string': '2026-10-05T09:00:00.000Z'}}]),
    }

    def answer(body, index=None):
        if _group_field(body) != 'bite.client_user':
            return composite([])
        after = body['aggs']['c']['composite'].get('after')
        return pages[after['g'] if after else None]
    search.answer = answer
    spec = RuleSpec(name='a', type='absence', group_by=['entity'], window_seconds=3600, interval_seconds=900,
                    params={'threshold': 1, 'lookback_seconds': 86400, 'min_baseline': 20})
    hits = (await Evaluator(search).evaluate(spec, NOW)).hits
    assert [h.entity_value for h in hits] == ['quiet-agent']


async def test_a_run_after_downtime_catches_up_on_the_windows_it_missed(search):
    rule = await _rule(evaluated_until=NOW - timedelta(hours=1))
    search.answer = lambda body, index=None: grouped('bite.client_user', [])
    outcome = await _run(search, rule.id, NOW)
    ends = [b['query']['bool']['filter'][0]['range']['@timestamp']['lt'] for b in search.bodies]
    assert ends == ['2026-10-05T11:15:00.000Z', '2026-10-05T11:30:00.000Z', '2026-10-05T11:45:00.000Z',
                    '2026-10-05T12:00:00.000Z']
    assert outcome.status == 'ok' and not outcome.reason
    async with db.sessionmaker()() as session:
        run = (await session.execute(select(RuleRun))).scalar_one()
        assert run.window_start == NOW - timedelta(hours=1)


async def test_catching_up_is_bounded_and_says_what_it_skipped(search):
    rule = await _rule(evaluated_until=NOW - timedelta(days=2))
    search.answer = lambda body, index=None: grouped('bite.client_user', [])
    outcome = await _run(search, rule.id, NOW)
    assert len(search.bodies) == engine.CATCH_UP_STEPS + 1
    assert 'were not checked' in outcome.reason


async def test_a_window_is_cut_at_the_start_of_active_hours(search):
    rule = await _rule(schedule={'days': None, 'start': '08:00', 'end': '16:00', 'timezone': 'UTC'})
    search.answer = lambda body, index=None: grouped('bite.client_user', [])
    morning = datetime(2026, 10, 5, 8, 5, tzinfo=timezone.utc)
    await _run(search, rule.id, morning)
    assert search.bodies[0]['query']['bool']['filter'][0]['range']['@timestamp']['gte'] == '2026-10-05T08:00:00.000Z'


async def test_spikes_wait_for_a_whole_window_inside_active_hours(search):
    spec = RuleSpec(name='s', type='spike', window_seconds=3600, interval_seconds=900,
                    schedule={'days': None, 'start': '08:00', 'end': '16:00', 'timezone': 'UTC'})
    result = await Evaluator(search).evaluate(spec, datetime(2026, 10, 5, 8, 30, tzinfo=timezone.utc),
                                              start=datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc))
    assert result.status == 'skipped' and not search.bodies


def test_active_hours_that_wrap_midnight_began_the_evening_before():
    schedule = {'days': None, 'start': '22:00', 'end': '06:00', 'timezone': 'UTC'}
    began = engine.active_since(schedule, datetime(2026, 10, 6, 2, 0, tzinfo=timezone.utc))
    assert began == datetime(2026, 10, 5, 22, 0, tzinfo=timezone.utc)
    assert engine.active_since(schedule, datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)) is None
    assert engine.active_since(None, NOW) is None


async def test_an_analysts_severity_survives_the_next_match_but_a_raised_rule_still_escalates(search):
    rule = await _rule()
    search.answer = lambda body, index=None: grouped('bite.client_user', [bucket('ava', 3)])
    await _run(search, rule.id, NOW)
    async with db.sessionmaker()() as session:
        finding = (await session.execute(select(Finding))).scalar_one()
        finding.severity = 'low'
        await session.commit()
    await _run(search, rule.id, NOW + timedelta(minutes=5))
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(Finding.severity))).scalar_one() == 'low'
        stored = await session.get(Rule, rule.id)
        stored.severity = 'critical'
        await session.commit()
    await _run(search, rule.id, NOW + timedelta(minutes=10))
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(Finding.severity))).scalar_one() == 'critical'


async def test_without_webhooks_a_repeat_match_logs_one_occurrence_per_re_alert_gap(search):
    rule = await _rule()
    search.answer = lambda body, index=None: grouped('bite.client_user', [bucket('ava', 3)])
    for minutes in (0, 61, 66, 71):
        await _run(search, rule.id, NOW + timedelta(minutes=minutes))
    async with db.sessionmaker()() as session:
        kinds = (await session.execute(select(FindingActivity.kind))).scalars().all()
    assert sorted(kinds) == ['created', 'occurrence']


async def test_a_very_long_entity_is_stored_cut_but_kept_apart_from_its_neighbours(search):
    rule = await _rule()
    long_a, long_b = 'a' * 500 + 'x', 'a' * 500 + 'y'
    search.answer = lambda body, index=None: grouped('bite.client_user', [bucket(long_a, 3), bucket(long_b, 2)])
    await _run(search, rule.id, NOW)
    async with db.sessionmaker()() as session:
        values = (await session.execute(select(Finding.entity_value))).scalars().all()
    assert len(values) == 2 and all(len(v) == engine.ENTITY_MAX and v.endswith('…') for v in values)


def test_titles_replace_placeholders_as_text_and_refuse_anything_else():
    from tbconsole.analysis.ruletypes import Hit
    from tbconsole.search.timerange import TimeRange

    class R:
        name = 'Threat'
    hit = Hit(entity_field='bite.client_user', entity_value='{rule}', count=1200, recent=1, value=1200,
              summary='', evidence_query='', window=TimeRange(NOW, NOW))
    # A value that looks like a placeholder stays as it is
    assert engine.render_title('{rule} for {entity}: {count}', R, hit) == 'Threat for {rule}: 1,200'
    for bad in ('{count:>999999999}', '{rule.__class__}', '{0}', '{entity!r}'):
        with pytest.raises(RuleError, match='not something a title can show'):
            engine.check_title(bad)
    engine.check_title('Plain words, no placeholders')


async def test_a_rule_that_is_running_is_not_run_again_alongside(search):
    rule = await _rule()
    async with db.sessionmaker()() as first:
        assert await engine.claim_run(first, rule.id) is not None
    async with db.sessionmaker()() as second:
        assert await engine.claim_run(second, rule.id) is None
    # No lock is held meanwhile: the rule can still be edited
    async with db.sessionmaker()() as editor:
        (await editor.get(Rule, rule.id)).name = 'Renamed while running'
        await editor.commit()
    # A run gives the lease back
    await _run(search, rule.id, NOW)
    async with db.sessionmaker()() as other:
        assert await engine.claim_run(other, rule.id) is not None


async def test_the_scheduler_logs_a_rule_that_blew_up(search, monkeypatch, caplog):
    rule = await _rule(next_run_at=NOW - timedelta(minutes=1))

    async def boom(*args, **kwargs):
        raise RuntimeError('kaboom')
    monkeypatch.setattr(engine, 'run_rule', boom)
    ran = await engine.Scheduler(search).tick()
    assert ran == 1
    assert any('running rule' in r.message and r.exc_info for r in caplog.records)
    assert rule.id


async def test_builtin_tags_are_stored_sorted_so_an_unchanged_save_is_no_change():
    async with db.sessionmaker()() as session:
        await engine.sync_builtin_rules(session)
        for rule in (await session.execute(select(Rule))).scalars():
            assert rule.tags == sorted(rule.tags)


# -- round two -------------------------------------------------------------------------

def test_an_answer_some_shards_could_not_give_is_refused():
    from tbconsole.search.client import SearchRejected, _whole
    _whole({'_shards': {'total': 3, 'failed': 0}})
    with pytest.raises(SearchRejected, match='2 of 22 shards'):
        _whole({'_shards': {'total': 22, 'failed': 2, 'failures': [
            {'reason': {'type': 'query_shard_exception', 'reason': "'zoe' is not an IP string literal"}}]}})


async def test_a_window_that_failed_is_evaluated_by_a_later_run(search):
    from tbconsole.search.client import SearchUnavailable
    rule = await _rule(evaluated_until=NOW - timedelta(minutes=45))
    calls = []

    async def flaky(body, index=None):
        calls.append(body)
        if len(calls) == 2:
            raise SearchUnavailable('the cluster went away')
        return grouped('bite.client_user', [])
    search.search = flaky
    outcome = await _run(search, rule.id, NOW)
    assert outcome.status == 'error'
    async with db.sessionmaker()() as session:
        stored = await session.get(Rule, rule.id)
        # Only the first window, 11:15 to 11:30, counts as done
        assert stored.evaluated_until == NOW - timedelta(minutes=30)
    calls.clear()
    await _run(search, rule.id, NOW + timedelta(minutes=5))
    ends = [b['query']['bool']['filter'][0]['range']['@timestamp']['lt'] for b in calls]
    assert ends[0] == '2026-10-05T11:45:00.000Z'


async def test_catching_up_counts_one_occurrence_per_run(search):
    rule = await _rule()
    search.answer = lambda body, index=None: grouped('bite.client_user', [bucket('ava', 3)])
    await _run(search, rule.id, NOW)
    await _run(search, rule.id, NOW + timedelta(hours=1))  # four windows
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(Finding.occurrences))).scalar_one() == 2


async def test_the_end_of_active_hours_is_evaluated_after_they_end(search):
    schedule = {'days': None, 'start': '08:00', 'end': '16:00', 'timezone': 'UTC'}
    rule = await _rule(schedule=schedule, evaluated_until=datetime(2026, 10, 5, 15, 55, tzinfo=timezone.utc))
    search.answer = lambda body, index=None: grouped('bite.client_user', [])
    await _run(search, rule.id, datetime(2026, 10, 5, 16, 3, tzinfo=timezone.utc))
    assert [b['query']['bool']['filter'][0]['range']['@timestamp']['lt'] for b in search.bodies] == [
        '2026-10-05T16:00:00.000Z']
    search.bodies.clear()
    await _run(search, rule.id, datetime(2026, 10, 5, 16, 30, tzinfo=timezone.utc))
    assert search.bodies == [], 'nothing more until the hours start again'


def test_active_hours_never_start_after_now_on_the_night_clocks_spring_forward():
    # 02:30 does not exist in New York on 8 March 2026
    schedule = {'days': None, 'start': '02:30', 'end': '06:00', 'timezone': 'America/New_York'}
    now = datetime(2026, 3, 8, 7, 10, tzinfo=timezone.utc)  # 03:10 EDT
    assert engine.active_since(schedule, now) <= now


async def test_a_long_window_is_cut_at_the_start_of_todays_hours(search):
    schedule = {'days': None, 'start': '08:00', 'end': '16:00', 'timezone': 'UTC'}
    rule = await _rule(schedule=schedule, window_seconds=86400, interval_seconds=3600)
    search.answer = lambda body, index=None: grouped('bite.client_user', [])
    await _run(search, rule.id, datetime(2026, 10, 5, 9, 0, tzinfo=timezone.utc))
    assert search.bodies[0]['query']['bool']['filter'][0]['range']['@timestamp']['gte'] == '2026-10-05T08:00:00.000Z'


async def test_a_nul_in_an_entity_is_stored_cleaned_not_fatal(search):
    rule = await _rule()
    search.answer = lambda body, index=None: grouped('bite.client_user', [bucket('ava\x00x', 3)])
    outcome = await _run(search, rule.id, NOW)
    assert outcome.status == 'ok' and outcome.created == 1
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(Finding.entity_value))).scalar_one() == 'ava�x'


def test_a_database_error_is_described_without_its_sql():
    from sqlalchemy.exc import DataError
    error = DataError('INSERT INTO findings VALUES (secret stuff)', {'entity': 'ava'}, ValueError('bad'))
    text = engine._error_text(error)
    assert 'INSERT' not in text and 'ava' not in text and 'database' in text


async def test_ratio_ranks_by_share_not_by_size(search):
    search.answer = lambda body, index=None: grouped('bite.client', [
        bucket('big', 5000, num={'doc_count': 3000}),     # 60%
        bucket('small', 60, num={'doc_count': 57})])      # 95%
    spec = RuleSpec(name='r', type='ratio', params={'numerator': 'rcode:NXDOMAIN', 'ratio': 0.5, 'min_count': 50},
                    group_by=['entity'])
    hits = (await Evaluator(search).evaluate(spec, NOW)).hits
    assert [h.entity_value for h in hits] == ['small', 'big']
    # The details are read for the chosen groups alone
    include = search.bodies[1]['aggs']['g3']['aggs']['t']['terms']['include']
    assert include == ['small', 'big']


async def test_a_backtest_stops_at_its_budget_and_says_where(search, monkeypatch):
    monkeypatch.setattr(engine, 'BACKTEST_BUDGET', 5)
    search.answer = lambda body, index=None: grouped('bite.client_user', [])
    spec = RuleSpec(name='t', type='threshold', params={'threshold': 1}, group_by=['entity'],
                    interval_seconds=300, window_seconds=900)
    from tbconsole.search.timerange import TimeRange
    result = await engine.backtest(search, spec, TimeRange(NOW - timedelta(hours=24), NOW))
    assert len(search.bodies) == 5 and result['stopped_at']


async def test_a_value_with_a_wildcard_is_quoted_in_an_evidence_query():
    from tbconsole.analysis.ruletypes import _evidence_query
    assert _evidence_query(RuleSpec(name='x', type='threshold'), 'bite.client_user', '*') == 'user:"*"'


async def test_a_new_value_exact_page_is_not_called_truncated(search, monkeypatch):
    from tbconsole.analysis import ruletypes
    monkeypatch.setattr(ruletypes, 'MAX_PAIRS', 2)
    oldest = (NOW - timedelta(days=60)).timestamp() * 1000
    answers = iter([
        {'aggregations': {'oldest': {'value': oldest}}},
        composite([keyed({'v': 'a.example'}, 3), keyed({'v': 'b.example'}, 2)], {'v': 'b.example'}),
        composite([]),
        history({0: 1, 1: 1}),
    ])
    search.answer = lambda body, index=None: next(answers)
    result = await Evaluator(search).evaluate(RuleSpec(name='n', type='new_value', params={'field': 'site'}), NOW)
    assert result.reason == ''
