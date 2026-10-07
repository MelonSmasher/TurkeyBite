"""The API end to end: roles, findings triage, rules, webhooks, dashboards, exports, audit."""

# Bandit's findings are marked nosec line by line: pytest checks with assert
# (B101), and the fixtures hold made-up passwords (B105, B106). None of this
# is code that ships.

import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from tbconsole import db
from tbconsole.models import AuditEvent, Finding, Rule, Webhook

from .conftest import login, make_user


async def _finding(rule_id=None, entity='ava', status='new', severity='high', full=None) -> Finding:
    now = datetime.now(timezone.utc)
    async with db.sessionmaker()() as session:
        finding = Finding(rule_id=rule_id, rule_name='Threat seen', rule_type='threshold', category='threat',
                          severity=severity, status=status, title=f'Threat seen: {entity}', summary='3 events',
                          entity_field='bite.client_user', entity_value=entity, dedup_key=uuid.uuid4().hex,
                          first_seen=now, last_seen=now, event_count=3,
                          evidence={'query': f'risk:threat AND user:{entity}',
                                    'top_domains': [{'key': 'evil.example', 'count': 3}],
                                    **({'entity_full': full} if full else {})})
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        return finding


async def test_viewers_read_but_do_not_write(client):
    await make_user('vic', role='viewer')
    headers = await login(client, 'vic')
    assert (await client.get('/api/v1/rules')).status_code == 200  # nosec B101
    assert (await client.post('/api/v1/rules', headers=headers, json={'name': 'x', 'type': 'threshold'})).status_code == 403  # nosec B101
    assert (await client.get('/api/v1/users')).status_code == 403  # nosec B101
    assert (await client.get('/api/v1/audit')).status_code == 403  # nosec B101


async def test_built_in_rules_are_there_and_cannot_be_deleted(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    rules = (await client.get('/api/v1/rules')).json()
    assert len([r for r in rules if r['builtin']]) >= 15  # nosec B101
    builtin = rules[0]
    assert (await client.delete(f"/api/v1/rules/{builtin['id']}", headers=headers)).status_code == 400  # nosec B101
    clone = (await client.post(f"/api/v1/rules/{builtin['id']}/clone", headers=headers)).json()
    assert clone['name'].startswith('Copy of') and not clone['enabled'] and not clone['builtin']  # nosec B101
    assert (await client.delete(f"/api/v1/rules/{clone['id']}", headers=headers)).status_code == 200  # nosec B101


async def test_editing_a_built_in_rule_marks_it_modified_and_reset_restores_it(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    rule = next(r for r in (await client.get('/api/v1/rules')).json() if r['builtin_key'] == 'gambling')
    body = {k: rule[k] for k in ('name', 'description', 'category', 'type', 'query', 'group_by', 'severity',
                                 'enabled', 'interval_seconds', 'window_seconds', 'dedup_seconds', 'tags', 'title_template')}
    body['params'] = {'threshold': 7}
    edited = (await client.put(f"/api/v1/rules/{rule['id']}", headers=headers, json=body)).json()
    assert edited['modified'] and edited['params']['threshold'] == 7  # nosec B101
    reset = (await client.post(f"/api/v1/rules/{rule['id']}/reset", headers=headers)).json()
    assert not reset['modified'] and reset['params']['threshold'] == 3  # nosec B101


async def test_a_rule_with_a_bad_query_is_refused_with_the_reason(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    response = await client.post('/api/v1/rules', headers=headers,
                                 json={'name': 'x', 'type': 'threshold', 'query': 'categry:porn'})
    assert response.status_code == 400 and 'Did you mean category' in response.json()['detail']  # nosec B101


async def test_triage_records_activity_and_the_audit_log(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    finding = await _finding()
    me = (await client.get('/api/v1/auth/me')).json()['user']
    response = await client.patch(f'/api/v1/findings/{finding.id}', headers=headers,
                                  json={'status': 'in_progress', 'assignee_id': me['id']})
    assert response.json()['status'] == 'in_progress' and response.json()['assignee']['username'] == 'ana'  # nosec B101
    await client.post(f'/api/v1/findings/{finding.id}/comments', headers=headers, json={'body': 'Looking now'})
    detail = (await client.get(f'/api/v1/findings/{finding.id}')).json()
    kinds = [a['kind'] for a in detail['activity']]
    assert {'status', 'assign', 'comment'} <= set(kinds)  # nosec B101
    async with db.sessionmaker()() as session:
        actions = (await session.execute(select(AuditEvent.action))).scalars().all()
        assert 'finding.update' in actions  # nosec B101


async def test_a_false_positive_teaches_the_rule_an_exception(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    rule = next(r for r in (await client.get('/api/v1/rules')).json() if r['builtin_key'] == 'anonymiser')
    finding = await _finding(rule_id=uuid.UUID(rule['id']), entity='it-admin')
    response = await client.post(f'/api/v1/findings/{finding.id}/exception', headers=headers,
                                 json={'scope': 'entity', 'note': 'IT testing', 'expires_days': 30})
    assert response.status_code == 200  # nosec B101
    exception = response.json()['exception']
    assert exception['query'] == 'user:it-admin' and exception['expires_at']  # nosec B101
    async with db.sessionmaker()() as session:
        stored = await session.get(Rule, uuid.UUID(rule['id']))
        # Exceptions are the rule's own: a built-in rule keeps taking new versions
        assert not stored.modified and stored.exceptions[-1]['query'] == 'user:it-admin'  # nosec B101
        assert (await session.get(Finding, finding.id)).status == 'false_positive'  # nosec B101


async def test_an_exception_a_rule_could_not_keep_or_use_is_refused(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    rule = next(r for r in (await client.get('/api/v1/rules')).json() if r['builtin_key'] == 'anonymiser')
    rule_id = uuid.UUID(rule['id'])
    # A NUL is stored as U+FFFD
    for entity, words in (('a' * 1100, 'would not work'), ('ava\ufffd', 'cannot match')):
        finding = await _finding(rule_id=rule_id, entity=entity[:200] + '…', full=entity)
        response = await client.post(f'/api/v1/findings/{finding.id}/exception', headers=headers,
                                     json={'scope': 'entity'})
        assert response.status_code == 400 and words in response.json()['detail']  # nosec B101
    async with db.sessionmaker()() as session:
        stored = await session.get(Rule, rule_id)
        stored.exceptions = [{'query': f'user:u{i}'} for i in range(200)]
        await session.commit()
    finding = await _finding(rule_id=rule_id, entity='liam')
    response = await client.post(f'/api/v1/findings/{finding.id}/exception', headers=headers,
                                 json={'scope': 'entity'})
    assert response.status_code == 409 and 'the most a rule can have' in response.json()['detail']  # nosec B101


async def test_bulk_triage(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    findings = [await _finding(entity=f'u{i}') for i in range(3)]
    result = await client.post('/api/v1/findings/bulk', headers=headers,
                               json={'ids': [str(f.id) for f in findings], 'status': 'acknowledged'})
    assert result.json()['updated'] == 3  # nosec B101
    stats = (await client.get('/api/v1/findings/stats')).json()
    assert stats['by_status']['acknowledged'] == 3  # nosec B101


async def test_webhooks_refuse_addresses_on_the_consoles_network(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    for url in ('http://127.0.0.1:8080/x', 'http://169.254.169.254/latest/meta-data', 'http://10.0.0.5/hook',
                'ftp://example.com/x', 'https://user:pw@example.com/x'):
        response = await client.post('/api/v1/webhooks', headers=headers,
                                     json={'name': 'x', 'url': url, 'format': 'json', 'events': ['finding.created']})
        assert response.status_code == 400, url  # nosec B101


async def test_a_webhook_secret_is_shown_once_and_stored_encrypted(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    created = await client.post('/api/v1/webhooks', headers=headers,
                                json={'name': 'hook', 'url': 'https://93.184.215.14/hook', 'format': 'slack',
                                      'events': ['finding.created'], 'headers': {'Authorization': 'Bearer x'}})
    assert created.status_code == 201, created.text  # nosec B101
    body = created.json()
    assert body['secret'].startswith('whsec_')  # nosec B101
    again = (await client.get(f"/api/v1/webhooks/{body['id']}")).json()
    assert 'secret' not in again and again['header_names'] == ['Authorization']  # nosec B101
    async with db.sessionmaker()() as session:
        from tbconsole.models import Webhook
        stored = await session.get(Webhook, uuid.UUID(body['id']))
        assert body['secret'] not in stored.secret_enc  # nosec B101
    bad_header = await client.post('/api/v1/webhooks', headers=headers,
                                   json={'name': 'h', 'url': 'https://93.184.215.14/h', 'format': 'json',
                                         'events': ['finding.created'], 'headers': {'X-TurkeyBite-Signature': 'forged'}})
    assert bad_header.status_code == 400  # nosec B101


async def test_the_last_admin_cannot_be_removed(client):
    root = await make_user('root', role='admin')
    headers = await login(client, 'root')
    assert (await client.patch(f'/api/v1/users/{root.id}', headers=headers, json={'role': 'viewer'})).status_code == 400  # nosec B101
    assert (await client.delete(f'/api/v1/users/{root.id}', headers=headers)).status_code == 400  # nosec B101
    other = await make_user('second', role='admin')
    assert (await client.patch(f'/api/v1/users/{other.id}', headers=headers, json={'role': 'viewer'})).status_code == 200  # nosec B101


async def test_directory_roles_are_not_edited_here(client):
    await make_user('root', role='admin')
    ldap_user = await make_user('dir', role='viewer', source='ldap')
    headers = await login(client, 'root')
    response = await client.patch(f'/api/v1/users/{ldap_user.id}', headers=headers, json={'role': 'admin'})
    assert response.status_code == 400 and 'groups' in response.json()['detail']  # nosec B101


async def test_built_in_dashboards_are_read_only_but_can_be_cloned(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    boards = (await client.get('/api/v1/dashboards')).json()
    builtin = next(b for b in boards if b['builtin'])
    response = await client.put(f"/api/v1/dashboards/{builtin['id']}", headers=headers,
                                json={'name': 'mine now', 'widgets': []})
    assert response.status_code == 400  # nosec B101
    clone = (await client.post(f"/api/v1/dashboards/{builtin['id']}/clone", headers=headers)).json()
    assert clone['mine'] and len(clone['widgets']) == len(builtin['widgets'])  # nosec B101


async def test_a_private_dashboard_is_invisible_to_others(app, client):
    import httpx
    await make_user('ana', role='analyst')
    await make_user('bob', role='analyst')
    headers = await login(client, 'ana')
    board = (await client.post('/api/v1/dashboards', headers=headers, json={'name': 'private', 'widgets': []})).json()
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver')
    await login(other, 'bob')
    assert (await other.get(f"/api/v1/dashboards/{board['id']}")).status_code == 404  # nosec B101
    await other.aclose()


async def test_entity_kind_is_selected_before_limit(client, search):
    from collections import Counter

    await make_user('ana', role='analyst')
    await login(client, 'ana')
    events = ([{'bite.client_hosts_short': 'busy-machine', 'bite.client': '10.0.0.1'}] * 20
              + [{'bite.client_user': 'quiet-person', 'bite.client_hostname_short': 'laptop',
                  'bite.client': '10.0.0.2'}]
              + [{'bite.client': '10.0.0.3'}] * 2)

    def matches(doc, condition):
        if 'exists' in condition:
            return condition['exists']['field'] in doc
        if 'range' in condition:
            return True  # All fixture events are in the requested time range.
        clauses = condition['bool']
        return (all(matches(doc, c) for c in clauses.get('filter', []))
                and not any(matches(doc, c) for c in clauses.get('must_not', []))
                and (not clauses.get('should')
                     or any(matches(doc, c) for c in clauses['should'])))

    def aggregate(body, index=None):
        docs = [doc for doc in events if matches(doc, body['query'])]
        aggs = {}
        for name, agg in body['aggs'].items():
            terms = agg['aggs']['t']['terms']
            counts = Counter(doc[terms['field']] for doc in docs if matches(doc, agg['filter']))
            aggs[name] = {'t': {'buckets': [
                {'key': key, 'doc_count': count, 'notable': {'doc_count': count}}
                for key, count in counts.most_common(terms['size'])]}}
        return {'hits': {'total': {'value': len(docs)}}, 'aggregations': aggs}

    search.answer = aggregate
    for kind, expected, count in [('all', 'busy-machine', 23), ('user', 'quiet-person', 1),
                                  ('host', 'busy-machine', 20), ('ip', '10.0.0.3', 2)]:
        response = await client.get('/api/v1/entities', params={'kind': kind, 'size': 1})
        assert response.status_code == 200  # nosec B101
        result = response.json()
        assert [item['key'] for item in result['items']] == [expected]  # nosec B101
        assert result['total_events'] == count  # nosec B101
    assert (await client.get('/api/v1/entities', params={'kind': 'unknown'})).status_code == 422  # nosec B101


async def test_viewing_a_profile_is_audited(client, search):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    search.answer = lambda body, index=None: {'hits': {'total': {'value': 0}, 'hits': []}, 'aggregations': {}}
    response = await client.get('/api/v1/entities/profile', params={'field': 'user', 'value': 'noah.kim'})
    assert response.status_code == 200  # nosec B101
    async with db.sessionmaker()() as session:
        event = (await session.execute(select(AuditEvent).where(AuditEvent.action == 'entity.view'))).scalar_one()
        assert event.target_id == 'noah.kim' and event.actor_name == 'ana'  # nosec B101


async def test_a_profile_of_something_that_is_not_an_identity_is_refused(client):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    response = await client.get('/api/v1/entities/profile', params={'field': 'bite.contexts', 'value': 'porn'})
    assert response.status_code == 400  # nosec B101


async def test_exports_neutralise_spreadsheet_formulas_and_are_audited(client, search):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    hits = [{'_id': '1', '_index': 'tb-index-2026-10-05',
             '_source': {'@timestamp': '2026-10-05T10:00:00Z', 'bite': {'requested': ['=HYPERLINK("http://x")'],
                                                                     'client_user': '+cmd'}}}]
    answers = iter([{'hits': {'total': {'value': 1}, 'hits': hits}}, {'hits': {'total': {'value': 1}, 'hits': []}}])
    search.answer = lambda body, index=None: next(answers)
    response = await client.post('/api/v1/events/export', headers=headers,
                                 json={'query': '', 'format': 'csv', 'columns': ['domain', 'user'], 'limit': 10})
    assert response.status_code == 200  # nosec B101
    rows = response.text.splitlines()
    assert rows[0] == 'bite.requested,bite.client_user'  # nosec B101
    assert rows[1].startswith('"\'=HYPERLINK') and rows[1].endswith("'+cmd")  # nosec B101
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(AuditEvent).where(AuditEvent.action == 'events.export'))).scalar_one()  # nosec B101


async def test_viewers_cannot_export(client):
    await make_user('vic', role='viewer')
    headers = await login(client, 'vic')
    response = await client.post('/api/v1/events/export', headers=headers, json={'format': 'csv'})
    assert response.status_code == 403  # nosec B101


async def test_a_query_mistake_comes_back_with_its_position(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    response = await client.post('/api/v1/events/search', headers=headers, json={'query': 'risk:threat AND'})
    assert response.status_code == 400  # nosec B101
    assert response.json()['query_error']['position'] == 12  # nosec B101


async def test_documents_are_only_read_from_turkeybite_indices(client, search):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    search.answer = lambda body, index=None: {'hits': {'hits': [
        {'_index': index, '_id': 'abc', '_source': {'bite': {'client_user': 'ava'}}}]}}
    for index in ('.kibana', 'security-auditlog-2026', '..%2Fsecret'):
        assert (await client.get(f'/api/v1/events/doc/{index}/abc')).status_code == 404  # nosec B101
    # Refused before OpenSearch was asked, not because it had nothing
    assert search.bodies == []  # nosec B101
    response = await client.get('/api/v1/events/doc/tb-index-2026.10.05/abc')
    assert response.status_code == 200 and len(search.bodies) == 1  # nosec B101
    async with db.sessionmaker()() as session:
        viewed = (await session.execute(select(AuditEvent).where(AuditEvent.action == 'event.view'))).scalars().all()
    assert [e.target_label for e in viewed] == ['ava']  # nosec B101


async def test_search_unavailability_is_a_503(client, search):
    from tbconsole.search.client import SearchUnavailable
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')

    async def down(body, index=None):
        raise SearchUnavailable('no OpenSearch host could be reached')
    search.search = down
    response = await client.post('/api/v1/events/search', headers=headers, json={'query': ''})
    assert response.status_code == 503 and response.json()['code'] == 'search_unavailable'  # nosec B101


async def test_security_headers_are_set(client):
    response = await client.get('/api/v1/auth/config')
    assert "default-src 'self'" in response.headers['content-security-policy']  # nosec B101
    assert response.headers['x-frame-options'] == 'DENY'  # nosec B101
    assert response.headers['cache-control'] == 'no-store'  # nosec B101


async def test_the_overview_puts_each_answer_where_it_belongs(client, search):
    # Four queries run at once; each answer must land in its own part
    await make_user('ana', role='analyst')
    await login(client, 'ana')

    def answer(body, index=None):
        aggs = body.get('aggs', {})
        if 'timeline' in aggs:
            return {'hits': {'total': {'value': 100}}, 'aggregations': {'notable': {'doc_count': 7}}}
        if 'heat' in aggs:
            return {'hits': {'total': {'value': 0}}, 'aggregations': {'heat': {'buckets': [
                {'key_as_string': '2026-10-05T10:00:00.000Z', 'doc_count': 5, 'notable': {'doc_count': 1}}]}}}
        if 'latest' in aggs:
            return {'hits': {'total': {'value': 0}}, 'aggregations': {'latest': {'value': 1791230400000}}}
        return {'hits': {'total': {'value': 40}}, 'aggregations': {'notable': {'doc_count': 2}}}
    search.answer = answer
    data = (await client.get('/api/v1/overview')).json()
    assert data['kpis']['events'] == {'value': 100, 'previous': 40, 'change': 1.5}  # nosec B101
    assert data['kpis']['notable']['previous'] == 2  # nosec B101
    assert data['heat'] == [{'t': '2026-10-05T10:00:00.000Z', 'count': 5, 'notable': 1}]  # nosec B101
    assert data['freshness']['latest_event'].startswith('2026-10-05')  # nosec B101


async def test_every_accent_the_app_offers_can_be_saved(client):
    # The app's own list, in frontend/src/lib/stores/prefs.svelte.ts
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    for accent in ('iris', 'ocean', 'forest', 'ember', 'rose', 'slate'):
        response = await client.put('/api/v1/account/preferences', headers=headers,
                                    json={'theme': 'dark', 'accent': accent, 'density': 'compact', 'privacy_mode': True})
        assert response.status_code == 200, accent  # nosec B101
    me = (await client.get('/api/v1/auth/me')).json()
    assert me['preferences']['accent'] == 'slate' and me['preferences']['privacy_mode'] is True  # nosec B101
    bad = await client.put('/api/v1/account/preferences', headers=headers, json={'accent': 'chartreuse'})
    assert bad.status_code == 400  # nosec B101


async def test_preferences_saved_at_once_from_two_tabs_both_stay(client):
    import asyncio
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    for _ in range(5):
        await asyncio.gather(
            client.put('/api/v1/account/preferences', headers=headers, json={'theme': 'dark'}),
            client.put('/api/v1/account/preferences', headers=headers, json={'privacy_mode': True}),
            client.put('/api/v1/account/preferences', headers=headers, json={'density': 'compact'}))
        me = (await client.get('/api/v1/auth/me')).json()['preferences']
        assert (me['theme'], me['privacy_mode'], me['density']) == ('dark', True, 'compact')  # nosec B101
        await client.put('/api/v1/account/preferences', headers=headers,
                         json={'theme': 'light', 'privacy_mode': False, 'density': 'comfortable'})


async def test_the_organisations_default_range_reaches_the_app(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    assert (await client.get('/api/v1/auth/me')).json()['default_range'] == 'now-24h'  # nosec B101
    general = (await client.get('/api/v1/settings/general')).json()
    bad = await client.put('/api/v1/settings/general', headers=headers, json={**general, 'default_range': 'now-9999999d'})
    assert bad.status_code == 422  # nosec B101
    saved = await client.put('/api/v1/settings/general', headers=headers, json={**general, 'default_range': 'now-7d'})
    assert saved.status_code == 200  # nosec B101
    assert (await client.get('/api/v1/auth/me')).json()['default_range'] == 'now-7d'  # nosec B101


async def test_a_tab_left_from_another_persons_session_cannot_save_its_preferences_onto_yours(client):
    await make_user('carol', role='analyst')
    await make_user('bob', role='analyst')
    carol = (await client.get('/api/v1/auth/me', headers=await login(client, 'carol'))).json()['user']['id']
    headers = await login(client, 'bob')
    stale = await client.put('/api/v1/account/preferences', headers=headers,
                             json={'privacy_mode': False, 'user_id': carol})
    assert stale.status_code == 409  # nosec B101
    bob = (await client.get('/api/v1/auth/me')).json()['user']['id']
    mine = await client.put('/api/v1/account/preferences', headers=headers, json={'privacy_mode': True, 'user_id': bob})
    assert mine.status_code == 200 and 'user_id' not in mine.json()  # nosec B101


async def _sac_hook():
    from tbconsole.security import crypto
    from tbconsole.webhooks.service import set_url
    async with db.sessionmaker()() as session:
        hook = Webhook(name='SAC', secret_enc=crypto.encrypt('whsec_test'), events=['finding.created'],
                       all_findings=False, min_severity='info',
                       headers_enc=crypto.encrypt('{"X-Webhook-Token": "tok-123"}'))
        set_url(hook, 'https://sac.example.edu/ingest/webhook/turkeybite/')
        session.add(hook)
        await session.commit()
        return str(hook.id)


async def test_device_lookup_is_a_url_without_credentials_and_a_webhook_to_sign_with(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    general = (await client.get('/api/v1/settings/general')).json()
    assert general['device_lookup_url'] == '' and general['device_lookup_webhook_id'] == ''  # nosec B101
    url = 'https://sac.example.edu/ingest/webhook/turkeybite/device-lookup/'
    for bad in ('sac.example.edu/device-lookup/', 'javascript:alert(1)', 'https://user:pw@sac.example.edu/x',
                'https://sac.example.edu:99999/x', 'https://sac.example.edu:port/x', 'https://sac.example.edu/x y'):
        response = await client.put('/api/v1/settings/general', headers=headers, json={'device_lookup_url': bad})
        assert response.status_code == 422, bad  # nosec B101
    # The URL and the webhook go together, and the webhook has to exist
    alone = await client.put('/api/v1/settings/general', headers=headers, json={'device_lookup_url': url})
    assert alone.status_code == 400  # nosec B101
    missing = await client.put('/api/v1/settings/general', headers=headers,
                               json={'device_lookup_url': url, 'device_lookup_webhook_id': str(uuid.uuid4())})
    assert missing.status_code == 400  # nosec B101
    hook_id = await _sac_hook()
    saved = await client.put('/api/v1/settings/general', headers=headers,
                             json={'device_lookup_url': url, 'device_lookup_webhook_id': hook_id})
    assert saved.status_code == 200 and saved.json()['org_name'] == general['org_name']  # nosec B101
    # Everyone hears only that lookups are on, not where they go
    me = (await client.get('/api/v1/auth/me')).json()
    assert me['device_lookup'] is True and 'sac.example.edu' not in str(me)  # nosec B101
    # A setting left out keeps its value
    await client.put('/api/v1/settings/general', headers=headers, json={'org_name': 'Elsewhere'})
    assert (await client.get('/api/v1/settings/general')).json()['device_lookup_url'] == url  # nosec B101


async def test_a_device_lookup_asks_the_other_side_and_shows_only_what_is_safe(client, monkeypatch):
    from tbconsole.webhooks import dispatcher
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    asked = []

    async def ask(hook, url, event, payload, http=None):
        asked.append((hook.name, url, event, payload))
        return {'query': {'value': payload['address']}, 'link': '/respond/device/?q=10.20.30.40',
                'alerts': {'count': 3, 'open': 'x'},
                'inventories': [
                    {'name': 'Netdisco', 'configured': True, 'asks': True, 'found': True, 'records': [
                        {'title': 'core-sw1 ge-0/0/12', 'subtitle': 'VLAN 120', 'link': 'javascript:alert(1)',
                         'facts': [['Switch', 'core-sw1'], ['VLAN', 120], ['bad']]}]},
                    {'name': 'Lansweeper', 'configured': True, 'problem': 'could not be reached'},
                    'not a card']}
    monkeypatch.setattr(dispatcher, 'ask', ask)
    off = await client.post('/api/v1/devices/lookup', headers=headers, json={'address': '10.20.30.40'})
    assert off.status_code == 409  # nosec B101
    hook_id = await _sac_hook()
    url = 'https://sac.example.edu/ingest/webhook/turkeybite/device-lookup/'
    await client.put('/api/v1/settings/general', headers=headers,
                     json={'device_lookup_url': url, 'device_lookup_webhook_id': hook_id})
    assert (await client.post('/api/v1/devices/lookup', headers=headers,  # nosec B101
                              json={'address': 'lab-12'})).status_code == 400
    response = await client.post('/api/v1/devices/lookup', headers=headers, json={'address': '10.20.30.40'})
    assert response.status_code == 200, response.text  # nosec B101
    data = response.json()
    assert asked[0][1:3] == (url, 'device.lookup')  # nosec B101
    assert asked[0][3]['address'] == '10.20.30.40' and asked[0][3]['requested_by'] == 'root'  # nosec B101
    netdisco, lansweeper = data['inventories']
    assert netdisco['records'][0]['facts'] == [['Switch', 'core-sw1'], ['VLAN', '120']]  # nosec B101
    assert netdisco['records'][0]['link'] == ''  # nosec B101
    assert lansweeper['problem'] == 'could not be reached' and not lansweeper['found']  # nosec B101
    assert data['alerts'] == {'count': 3, 'open': 0}  # nosec B101
    assert data['link'] == 'https://sac.example.edu/respond/device/?q=10.20.30.40'  # nosec B101
    async with db.sessionmaker()() as session:
        row = (await session.execute(select(AuditEvent).where(AuditEvent.action == 'device.lookup'))).scalar_one()
        assert row.target_id == '10.20.30.40' and row.actor_name == 'root'  # nosec B101

    async def fails(hook, url, event, payload, http=None):
        raise dispatcher.AskFailed('it answered HTTP 403: Invalid TurkeyBite signature')
    monkeypatch.setattr(dispatcher, 'ask', fails)
    failed = await client.post('/api/v1/devices/lookup', headers=headers, json={'address': '10.20.30.40'})
    assert failed.status_code == 502 and 'Invalid TurkeyBite signature' in failed.json()['detail']  # nosec B101


async def test_deleting_the_webhook_device_lookup_signs_with_turns_lookups_off(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    hook_id = await _sac_hook()
    await client.put('/api/v1/settings/general', headers=headers,
                     json={'device_lookup_url': 'https://sac.example.edu/device-lookup/',
                           'device_lookup_webhook_id': hook_id})
    assert (await client.delete(f'/api/v1/webhooks/{hook_id}', headers=headers)).status_code == 200  # nosec B101
    assert (await client.get('/api/v1/auth/me')).json()['device_lookup'] is False  # nosec B101
    # And other settings still save
    saved = await client.put('/api/v1/settings/general', headers=headers, json={'org_name': 'Elsewhere'})
    assert saved.status_code == 200  # nosec B101
    # Even when a save raced the deletion and put the old id back: lookup is
    # off, and the next save clears it
    from tbconsole import settings_store
    async with db.sessionmaker()() as session:
        general = await settings_store.general(session)
        await settings_store.put(session, 'general', {**general, 'device_lookup_url': 'https://sac.example.edu/x',
                                                      'device_lookup_webhook_id': hook_id}, None)
        await session.commit()
    assert (await client.get('/api/v1/auth/me')).json()['device_lookup'] is False  # nosec B101
    cleared = await client.put('/api/v1/settings/general', headers=headers, json={'org_name': 'Again'})
    assert cleared.status_code == 200 and cleared.json()['device_lookup_webhook_id'] == ''  # nosec B101


def test_an_answer_of_the_wrong_shape_is_read_as_nothing():
    from tbconsole.api.devices import _clean
    odd = {'inventories': {'a': 1}, 'alerts': [], 'link': 5}
    assert _clean(odd, 'https://sac.example.edu/x') == {  # nosec B101
        'inventories': [], 'alerts': {'count': 0, 'open': 0}, 'link': ''}
    cards = _clean({'inventories': [{'name': 'N', 'records': 'x'}, {'name': 'M', 'records': [{'facts': 'y'}]}]},
                   'https://sac.example.edu/x')['inventories']
    assert cards[0]['records'] == [] and cards[1]['records'][0]['facts'] == []  # nosec B101


async def test_a_viewer_cannot_look_devices_up(client):
    await make_user('val', role='viewer')
    headers = await login(client, 'val')
    response = await client.post('/api/v1/devices/lookup', headers=headers, json={'address': '10.20.30.40'})
    assert response.status_code == 403  # nosec B101


async def test_a_profile_gives_the_address_a_machine_was_last_seen_at(client, search):
    await make_user('ana', role='analyst')
    await login(client, 'ana')

    def answer(body, index=None):
        if body.get('size') == 1 and body.get('_source') == ['@timestamp', 'bite.client', 'bite.client_ips']:
            # A browser's event: the machine's own addresses, IPv6 among them
            return {'hits': {'total': {'value': 1}, 'hits': [{'_source': {
                '@timestamp': '2026-10-07T12:00:00Z', 'bite': {'client_ips': ['fe80::1', '10.20.30.40']}}}]}}
        return {'hits': {'total': {'value': 0}, 'hits': []}, 'aggregations': {}}
    search.answer = answer
    machine = (await client.get('/api/v1/entities/profile', params={'field': 'host', 'value': 'lab-12'})).json()
    assert machine['latest_address'] == {'addresses': ['10.20.30.40', 'fe80::1'],  # nosec B101
                                         'at': '2026-10-07T12:00:00Z'}
    latest = next(b for b in search.bodies
                  if b.get('size') == 1 and b.get('_source') == ['@timestamp', 'bite.client', 'bite.client_ips'])
    assert {'term': {'bite.client_hostname_short': 'lab-12'}} in latest['query']['bool']['filter']  # nosec B101
    # An address is its own latest address
    address = (await client.get('/api/v1/entities/profile', params={'field': 'client', 'value': '10.0.0.5'})).json()
    assert address['latest_address'] == {'addresses': ['10.0.0.5'], 'at': None}  # nosec B101
    # Not seen lately: none
    search.answer = lambda body, index=None: {'hits': {'total': {'value': 0}, 'hits': []}, 'aggregations': {}}
    quiet = (await client.get('/api/v1/entities/profile', params={'field': 'user', 'value': 'ava'})).json()
    assert quiet['latest_address'] is None  # nosec B101
