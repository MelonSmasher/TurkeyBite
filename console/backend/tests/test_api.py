"""The API end to end: roles, findings triage, rules, webhooks, dashboards, exports, audit."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from tbconsole import db
from tbconsole.models import AuditEvent, Finding, Rule

from .conftest import login, make_user


async def _finding(rule_id=None, entity='ava', status='new', severity='high') -> Finding:
    now = datetime.now(timezone.utc)
    async with db.sessionmaker()() as session:
        finding = Finding(rule_id=rule_id, rule_name='Threat seen', rule_type='threshold', category='threat',
                          severity=severity, status=status, title=f'Threat seen: {entity}', summary='3 events',
                          entity_field='bite.client_user', entity_value=entity, dedup_key=uuid.uuid4().hex,
                          first_seen=now, last_seen=now, event_count=3,
                          evidence={'query': f'risk:threat AND user:{entity}',
                                    'top_domains': [{'key': 'evil.example', 'count': 3}]})
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        return finding


async def test_viewers_read_but_do_not_write(client):
    await make_user('vic', role='viewer')
    headers = await login(client, 'vic')
    assert (await client.get('/api/v1/rules')).status_code == 200
    assert (await client.post('/api/v1/rules', headers=headers, json={'name': 'x', 'type': 'threshold'})).status_code == 403
    assert (await client.get('/api/v1/users')).status_code == 403
    assert (await client.get('/api/v1/audit')).status_code == 403


async def test_built_in_rules_are_there_and_cannot_be_deleted(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    rules = (await client.get('/api/v1/rules')).json()
    assert len([r for r in rules if r['builtin']]) >= 15
    builtin = rules[0]
    assert (await client.delete(f"/api/v1/rules/{builtin['id']}", headers=headers)).status_code == 400
    clone = (await client.post(f"/api/v1/rules/{builtin['id']}/clone", headers=headers)).json()
    assert clone['name'].startswith('Copy of') and not clone['enabled'] and not clone['builtin']
    assert (await client.delete(f"/api/v1/rules/{clone['id']}", headers=headers)).status_code == 200


async def test_editing_a_built_in_rule_marks_it_modified_and_reset_restores_it(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    rule = next(r for r in (await client.get('/api/v1/rules')).json() if r['builtin_key'] == 'gambling')
    body = {k: rule[k] for k in ('name', 'description', 'category', 'type', 'query', 'group_by', 'severity',
                                 'enabled', 'interval_seconds', 'window_seconds', 'dedup_seconds', 'tags', 'title_template')}
    body['params'] = {'threshold': 7}
    edited = (await client.put(f"/api/v1/rules/{rule['id']}", headers=headers, json=body)).json()
    assert edited['modified'] and edited['params']['threshold'] == 7
    reset = (await client.post(f"/api/v1/rules/{rule['id']}/reset", headers=headers)).json()
    assert not reset['modified'] and reset['params']['threshold'] == 3


async def test_a_rule_with_a_bad_query_is_refused_with_the_reason(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    response = await client.post('/api/v1/rules', headers=headers,
                                 json={'name': 'x', 'type': 'threshold', 'query': 'categry:porn'})
    assert response.status_code == 400 and 'Did you mean category' in response.json()['detail']


async def test_triage_records_activity_and_the_audit_log(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    finding = await _finding()
    me = (await client.get('/api/v1/auth/me')).json()['user']
    response = await client.patch(f'/api/v1/findings/{finding.id}', headers=headers,
                                  json={'status': 'in_progress', 'assignee_id': me['id']})
    assert response.json()['status'] == 'in_progress' and response.json()['assignee']['username'] == 'ana'
    await client.post(f'/api/v1/findings/{finding.id}/comments', headers=headers, json={'body': 'Looking now'})
    detail = (await client.get(f'/api/v1/findings/{finding.id}')).json()
    kinds = [a['kind'] for a in detail['activity']]
    assert {'status', 'assign', 'comment'} <= set(kinds)
    async with db.sessionmaker()() as session:
        actions = (await session.execute(select(AuditEvent.action))).scalars().all()
        assert 'finding.update' in actions


async def test_a_false_positive_teaches_the_rule_an_exception(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    rule = next(r for r in (await client.get('/api/v1/rules')).json() if r['builtin_key'] == 'anonymiser')
    finding = await _finding(rule_id=uuid.UUID(rule['id']), entity='it-admin')
    response = await client.post(f'/api/v1/findings/{finding.id}/exception', headers=headers,
                                 json={'scope': 'entity', 'note': 'IT testing', 'expires_days': 30})
    assert response.status_code == 200
    exception = response.json()['exception']
    assert exception['query'] == 'user:it-admin' and exception['expires_at']
    async with db.sessionmaker()() as session:
        stored = await session.get(Rule, uuid.UUID(rule['id']))
        assert stored.modified and stored.exceptions[-1]['query'] == 'user:it-admin'
        assert (await session.get(Finding, finding.id)).status == 'false_positive'


async def test_bulk_triage(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    findings = [await _finding(entity=f'u{i}') for i in range(3)]
    result = await client.post('/api/v1/findings/bulk', headers=headers,
                               json={'ids': [str(f.id) for f in findings], 'status': 'acknowledged'})
    assert result.json()['updated'] == 3
    stats = (await client.get('/api/v1/findings/stats')).json()
    assert stats['by_status']['acknowledged'] == 3


async def test_webhooks_refuse_addresses_on_the_consoles_network(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    for url in ('http://127.0.0.1:8080/x', 'http://169.254.169.254/latest/meta-data', 'http://10.0.0.5/hook',
                'ftp://example.com/x', 'https://user:pw@example.com/x'):
        response = await client.post('/api/v1/webhooks', headers=headers,
                                     json={'name': 'x', 'url': url, 'format': 'json', 'events': ['finding.created']})
        assert response.status_code == 400, url


async def test_a_webhook_secret_is_shown_once_and_stored_encrypted(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    created = await client.post('/api/v1/webhooks', headers=headers,
                                json={'name': 'hook', 'url': 'https://93.184.215.14/hook', 'format': 'slack',
                                      'events': ['finding.created'], 'headers': {'Authorization': 'Bearer x'}})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body['secret'].startswith('whsec_')
    again = (await client.get(f"/api/v1/webhooks/{body['id']}")).json()
    assert 'secret' not in again and again['header_names'] == ['Authorization']
    async with db.sessionmaker()() as session:
        from tbconsole.models import Webhook
        stored = await session.get(Webhook, uuid.UUID(body['id']))
        assert body['secret'] not in stored.secret_enc
    bad_header = await client.post('/api/v1/webhooks', headers=headers,
                                   json={'name': 'h', 'url': 'https://93.184.215.14/h', 'format': 'json',
                                         'events': ['finding.created'], 'headers': {'X-TurkeyBite-Signature': 'forged'}})
    assert bad_header.status_code == 400


async def test_the_last_admin_cannot_be_removed(client):
    root = await make_user('root', role='admin')
    headers = await login(client, 'root')
    assert (await client.patch(f'/api/v1/users/{root.id}', headers=headers, json={'role': 'viewer'})).status_code == 400
    assert (await client.delete(f'/api/v1/users/{root.id}', headers=headers)).status_code == 400
    other = await make_user('second', role='admin')
    assert (await client.patch(f'/api/v1/users/{other.id}', headers=headers, json={'role': 'viewer'})).status_code == 200


async def test_directory_roles_are_not_edited_here(client):
    await make_user('root', role='admin')
    ldap_user = await make_user('dir', role='viewer', source='ldap')
    headers = await login(client, 'root')
    response = await client.patch(f'/api/v1/users/{ldap_user.id}', headers=headers, json={'role': 'admin'})
    assert response.status_code == 400 and 'groups' in response.json()['detail']


async def test_built_in_dashboards_are_read_only_but_can_be_cloned(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    boards = (await client.get('/api/v1/dashboards')).json()
    builtin = next(b for b in boards if b['builtin'])
    response = await client.put(f"/api/v1/dashboards/{builtin['id']}", headers=headers,
                                json={'name': 'mine now', 'widgets': []})
    assert response.status_code == 400
    clone = (await client.post(f"/api/v1/dashboards/{builtin['id']}/clone", headers=headers)).json()
    assert clone['mine'] and len(clone['widgets']) == len(builtin['widgets'])


async def test_a_private_dashboard_is_invisible_to_others(app, client):
    import httpx
    await make_user('ana', role='analyst')
    await make_user('bob', role='analyst')
    headers = await login(client, 'ana')
    board = (await client.post('/api/v1/dashboards', headers=headers, json={'name': 'private', 'widgets': []})).json()
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver')
    await login(other, 'bob')
    assert (await other.get(f"/api/v1/dashboards/{board['id']}")).status_code == 404
    await other.aclose()


async def test_viewing_a_profile_is_audited(client, search):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    search.answer = lambda body, index=None: {'hits': {'total': {'value': 0}, 'hits': []}, 'aggregations': {}}
    response = await client.get('/api/v1/entities/profile', params={'field': 'user', 'value': 'noah.kim'})
    assert response.status_code == 200
    async with db.sessionmaker()() as session:
        event = (await session.execute(select(AuditEvent).where(AuditEvent.action == 'entity.view'))).scalar_one()
        assert event.target_id == 'noah.kim' and event.actor_name == 'ana'


async def test_a_profile_of_something_that_is_not_an_identity_is_refused(client):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    response = await client.get('/api/v1/entities/profile', params={'field': 'bite.contexts', 'value': 'porn'})
    assert response.status_code == 400


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
    assert response.status_code == 200
    rows = response.text.splitlines()
    assert rows[0] == 'bite.requested,bite.client_user'
    assert rows[1].startswith('"\'=HYPERLINK') and rows[1].endswith("'+cmd")
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(AuditEvent).where(AuditEvent.action == 'events.export'))).scalar_one()


async def test_viewers_cannot_export(client):
    await make_user('vic', role='viewer')
    headers = await login(client, 'vic')
    response = await client.post('/api/v1/events/export', headers=headers, json={'format': 'csv'})
    assert response.status_code == 403


async def test_a_query_mistake_comes_back_with_its_position(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    response = await client.post('/api/v1/events/search', headers=headers, json={'query': 'risk:threat AND'})
    assert response.status_code == 400
    assert response.json()['query_error']['position'] == 12


async def test_documents_are_only_read_from_turkeybite_indices(client):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    for index in ('.kibana', 'security-auditlog-2026', '..%2Fsecret'):
        assert (await client.get(f'/api/v1/events/doc/{index}/abc')).status_code == 404


async def test_search_unavailability_is_a_503(client, search):
    from tbconsole.search.client import SearchUnavailable
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')

    async def down(body, index=None):
        raise SearchUnavailable('no OpenSearch host could be reached')
    search.search = down
    response = await client.post('/api/v1/events/search', headers=headers, json={'query': ''})
    assert response.status_code == 503 and response.json()['code'] == 'search_unavailable'


async def test_security_headers_are_set(client):
    response = await client.get('/api/v1/auth/config')
    assert "default-src 'self'" in response.headers['content-security-policy']
    assert response.headers['x-frame-options'] == 'DENY'
    assert response.headers['cache-control'] == 'no-store'


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
    assert data['kpis']['events'] == {'value': 100, 'previous': 40, 'change': 1.5}
    assert data['kpis']['notable']['previous'] == 2
    assert data['heat'] == [{'t': '2026-10-05T10:00:00.000Z', 'count': 5, 'notable': 1}]
    assert data['freshness']['latest_event'].startswith('2026-10-05')


async def test_every_accent_the_app_offers_can_be_saved(client):
    # The app's own list, in frontend/src/lib/stores/prefs.svelte.ts
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    for accent in ('iris', 'ocean', 'forest', 'ember', 'rose', 'slate'):
        response = await client.put('/api/v1/account/preferences', headers=headers,
                                    json={'theme': 'dark', 'accent': accent, 'density': 'compact', 'privacy_mode': True})
        assert response.status_code == 200, accent
    me = (await client.get('/api/v1/auth/me')).json()
    assert me['preferences']['accent'] == 'slate' and me['preferences']['privacy_mode'] is True
    bad = await client.put('/api/v1/account/preferences', headers=headers, json={'accent': 'chartreuse'})
    assert bad.status_code == 400
