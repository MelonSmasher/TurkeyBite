"""What the critical review found, each held in place by a test.

Sign-in and accounts, the directory, webhooks, findings, searches, housekeeping
and configuration, in roughly that order.
"""

import argparse
import io
import ipaddress
import socket
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pyotp
import pytest
from sqlalchemy import func, select

from tbconsole import db, settings_store
from tbconsole.models import (AuditEvent, Finding, FindingActivity, User, UserSession, Webhook,
                              WebhookDelivery)
from tbconsole.security import crypto
from tbconsole.webhooks import dispatcher, formats, safety
from tbconsole.webhooks.service import public_error, set_url

from .conftest import login, make_user


async def _audit(action: str) -> list[AuditEvent]:
    async with db.sessionmaker()() as session:
        return list((await session.execute(select(AuditEvent).where(AuditEvent.action == action))).scalars())


async def _finding(entity='ava', status='new', dedup_key=None, title=None, **extra) -> Finding:
    now = datetime.now(timezone.utc)
    async with db.sessionmaker()() as session:
        finding = Finding(rule_name='Threat seen', rule_type='threshold', category='threat',
                          severity=extra.pop('severity', 'high'), status=status,
                          title=title or f'Threat seen: {entity}', summary='3 events',
                          entity_field='bite.client_user', entity_value=entity,
                          dedup_key=dedup_key or uuid.uuid4().hex, first_seen=now, last_seen=now,
                          event_count=3, evidence={'top_domains': [{'key': 'evil.example', 'count': 3}]},
                          **extra)
        session.add(finding)
        await session.commit()
        await session.refresh(finding)
        return finding


# -- signing in ---------------------------------------------------------------------

async def test_setting_up_a_second_factor_needs_the_password(client):
    await make_user('ana')
    headers = await login(client, 'ana')
    wrong = await client.post('/api/v1/account/mfa/setup', headers=headers, json={'password': 'nope'})
    assert wrong.status_code == 400
    right = await client.post('/api/v1/account/mfa/setup', headers=headers,
                              json={'password': 'correct horse battery'})
    assert right.status_code == 200 and right.json()['secret']
    assert sorted(e.outcome for e in await _audit('account.mfa_setup')) == ['failure', 'success']


async def test_an_api_key_cannot_manage_its_owners_account(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    key = (await client.post('/api/v1/api-keys', headers=headers,
                             json={'name': 'k', 'scopes': ['findings:read']})).json()['key']
    client.cookies.clear()
    auth = {'Authorization': f'Bearer {key}'}
    for method, path, body in (('put', '/api/v1/account/preferences', {'theme': 'dark'}),
                               ('post', '/api/v1/account/password', {'current': 'x', 'new': 'y'}),
                               ('post', '/api/v1/account/mfa/setup', {'password': 'x'}),
                               ('get', '/api/v1/account/sessions', None)):
        response = await client.request(method, path, headers=auth, json=body)
        assert response.status_code == 403, path


async def test_a_lockout_holds_at_the_second_factor_too(client):
    secret = pyotp.random_base32()
    await make_user('root', role='admin', totp_enabled=True, totp_secret_enc=crypto.encrypt(secret))
    started = (await client.post('/api/v1/auth/login', json={'username': 'root',
                                                            'password': 'correct horse battery'})).json()
    assert started['mfa_required']
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'root'))).scalar_one()
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        await session.commit()
    refused = await client.post('/api/v1/auth/mfa', json={'token': started['token'],
                                                         'code': pyotp.TOTP(secret).now()})
    assert refused.status_code == 401


async def test_guessing_one_username_does_not_lock_out_everyone_at_the_same_address(client):
    await make_user('alice')
    for _ in range(10):
        response = await client.post('/api/v1/auth/login', json={'username': 'mallory', 'password': 'guess'})
        assert response.status_code == 401
    assert (await client.post('/api/v1/auth/login',
                              json={'username': 'mallory', 'password': 'guess'})).status_code == 429
    # Someone else, from the same address, is not held back
    await login(client, 'alice')


async def test_admin_only_areas_are_closed_to_analysts(client):
    await make_user('ana', role='analyst')
    await make_user('root', role='admin')
    await login(client, 'ana')
    for path in ('/api/v1/users', '/api/v1/settings/general', '/api/v1/settings/ldap', '/api/v1/audit'):
        assert (await client.get(path)).status_code == 403, path
    assert (await client.get('/api/v1/webhooks')).status_code == 200
    headers = await login(client, 'root')
    for path in ('/api/v1/users', '/api/v1/settings/general', '/api/v1/settings/ldap', '/api/v1/audit'):
        assert (await client.get(path)).status_code == 200, path
    analyst = {'X-CSRF-Token': headers['X-CSRF-Token']}
    client.cookies.clear()
    await login(client, 'ana')
    analyst = {'X-CSRF-Token': client.cookies.get('tbc_csrf')}
    created = await client.post('/api/v1/webhooks', headers=analyst, json={'name': 'x', 'url': 'https://example.org/'})
    assert created.status_code == 403


async def test_create_user_resets_a_password_ends_sessions_and_keeps_the_role(client, monkeypatch):
    from tbconsole import __main__ as cli
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    monkeypatch.setattr('sys.stdin', io.StringIO('An-entirely-new-passphrase-2026\n'))
    code = await cli.create_user(argparse.Namespace(username='ana', role=None, password_stdin=True,
                                                    reset_mfa=False))
    assert code == 0
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'ana'))).scalar_one()
        assert user.role == 'analyst' and user.password_changed_at is not None
        assert (await session.execute(select(func.count()).select_from(UserSession))).scalar_one() == 0
    assert len(await _audit('user.password_reset')) == 1
    assert (await client.get('/api/v1/auth/me')).status_code == 401


async def test_create_user_can_turn_off_a_lost_second_factor(monkeypatch):
    from tbconsole import __main__ as cli
    await make_user('root', role='admin', totp_enabled=True, totp_secret_enc=crypto.encrypt('ABC'))
    monkeypatch.setattr('sys.stdin', io.StringIO('An-entirely-new-passphrase-2026\n'))
    await cli.create_user(argparse.Namespace(username='root', role=None, password_stdin=True, reset_mfa=True))
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'root'))).scalar_one()
        assert not user.totp_enabled and user.totp_secret_enc is None and user.role == 'admin'


async def test_signing_in_from_another_sites_page_is_refused(client):
    await make_user('ana')
    response = await client.post('/api/v1/auth/login', headers={'Origin': 'https://evil.example'},
                                 json={'username': 'ana', 'password': 'correct horse battery'})
    assert response.status_code == 403
    same = await client.post('/api/v1/auth/login', headers={'Origin': 'http://testserver'},
                             json={'username': 'ana', 'password': 'correct horse battery'})
    assert same.status_code == 200


async def test_a_session_write_needs_both_the_csrf_token_and_a_matching_origin(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    body = {'name': 'x', 'query': 'risk:threat'}
    assert (await client.post('/api/v1/saved-searches', json=body)).status_code == 403
    assert (await client.post('/api/v1/saved-searches', json=body,
                              headers={**headers, 'Origin': 'https://evil.example'})).status_code == 403
    assert (await client.post('/api/v1/saved-searches', json=body, headers=headers)).status_code == 201


@pytest.mark.parametrize('method, path, needs', [
    ('get', '/api/v1/rules', 'rules:read'),
    ('get', '/api/v1/dashboards', 'dashboards:read'),
    ('get', '/api/v1/saved-searches', 'dashboards:read'),
    ('get', '/api/v1/webhooks', 'webhooks:read'),
    ('get', '/api/v1/overview', 'events:read'),
    ('get', '/api/v1/entities', 'events:read'),
    ('get', '/api/v1/fields', 'events:read'),
    ('get', '/api/v1/trends', 'events:read'),
    ('get', '/api/v1/findings/stats', 'findings:read'),
    ('get', '/api/v1/api-keys', 'apikeys:self'),
    ('get', '/api/v1/users', 'users:admin'),
    ('get', '/api/v1/settings/general', 'settings:admin'),
    ('get', '/api/v1/audit', 'audit:read'),
])
async def test_every_area_holds_api_keys_to_their_scopes(client, method, path, needs):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    keys = {}
    for scopes in ([needs], ['findings:read'] if needs != 'findings:read' else ['rules:read']):
        created = await client.post('/api/v1/api-keys', headers=headers, json={'name': 'k', 'scopes': scopes})
        keys[scopes[0]] = created.json()['key']
    client.cookies.clear()
    allowed = await client.request(method, path, headers={'Authorization': f'Bearer {keys[needs]}'})
    other = next(k for s, k in keys.items() if s != needs)
    refused = await client.request(method, path, headers={'Authorization': f'Bearer {other}'})
    assert allowed.status_code == 200, allowed.text
    assert refused.status_code == 403


def test_the_demo_will_not_touch_a_cluster_without_being_told_to(capsys):
    from tbconsole import __main__ as cli
    assert cli.main(['demo', 'seed']) == 2
    assert '--yes-replace-everything' in capsys.readouterr().err


# -- the directory --------------------------------------------------------------------

async def _save_directory(cfg: dict, password: str = 'svc-pw') -> None:
    async with db.sessionmaker()() as session:
        await settings_store.put(session, 'ldap', dict(cfg, bind_password_enc=crypto.encrypt(password)), None)
        await session.commit()


async def test_directory_sign_in_creates_the_account_with_its_groups_role(client, directory):
    await _save_directory(directory)
    response = await client.post('/api/v1/auth/login', json={'username': 'ava', 'password': 'ava-pw'})
    assert response.status_code == 200
    assert response.json()['user']['role'] == 'analyst' and response.json()['user']['source'] == 'ldap'
    assert (await client.post('/api/v1/auth/login', json={'username': 'ava', 'password': 'wrong'})).status_code == 401
    assert (await client.post('/api/v1/auth/login', json={'username': 'bob', 'password': 'bob-pw'})).status_code == 403


async def test_the_directory_takes_access_away_within_the_hour_and_gives_it_back(client, directory):
    from tbconsole import maintenance
    await _save_directory(directory)
    await login(client, 'ava', 'ava-pw')
    # Ava's group no longer grants a role
    await _save_directory(dict(directory, role_mappings=[{'group': 'cn=other', 'role': 'analyst'}]))
    async with db.sessionmaker()() as session:
        counts = await maintenance.recheck_directory(session)
    assert counts['revoked'] == 1
    assert (await client.get('/api/v1/auth/me')).status_code == 401
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'ava'))).scalar_one()
        assert user.disabled and user.disabled_reason == 'directory'
    assert len(await _audit('user.directory_revoked')) == 1
    # The group grants it again: signing in works, and the account is enabled
    await _save_directory(directory)
    await login(client, 'ava', 'ava-pw')
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'ava'))).scalar_one()
        assert not user.disabled and user.disabled_reason is None


async def test_a_directory_that_is_down_is_a_503_and_local_accounts_still_work(client, directory):
    await _save_directory(directory, password='the-wrong-service-password')
    await make_user('root', role='admin')
    response = await client.post('/api/v1/auth/login', json={'username': 'ava', 'password': 'ava-pw'})
    assert response.status_code == 503 and 'Local accounts can still sign in' in response.json()['detail']
    await login(client, 'root')


async def test_an_admins_disabling_outlasts_the_directory(client, directory):
    await _save_directory(directory)
    await make_user('ava', source='ldap', role='analyst', disabled=True, disabled_reason='admin')
    response = await client.post('/api/v1/auth/login', json={'username': 'ava', 'password': 'ava-pw'})
    assert response.status_code == 401


async def test_a_recheck_that_cannot_reach_the_directory_changes_nothing(client, directory):
    from tbconsole import maintenance
    from tbconsole.security import ldap
    await _save_directory(directory)
    await login(client, 'ava', 'ava-pw')
    await _save_directory(directory, password='the-wrong-service-password')
    async with db.sessionmaker()() as session:
        with pytest.raises(ldap.LdapUnavailable):
            await maintenance.recheck_directory(session)
    assert (await client.get('/api/v1/auth/me')).status_code == 200


async def test_the_saved_bind_password_only_goes_where_it_was_saved_for(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    base = {'enabled': False, 'urls': ['ldaps://dc1.example.org'], 'bind_dn': 'cn=svc,dc=example,dc=org',
            'user_base_dn': 'dc=example,dc=org'}
    assert (await client.put('/api/v1/settings/ldap', headers=headers,
                             json={**base, 'bind_password': 'svc-pw'})).status_code == 200
    # Unchanged servers and DN: the saved password is kept
    assert (await client.put('/api/v1/settings/ldap', headers=headers,
                             json={**base, 'timeout_sec': 9})).status_code == 200
    for change in ({'urls': ['ldaps://attacker.example.net']}, {'bind_dn': 'cn=admin,dc=example,dc=org'}):
        response = await client.put('/api/v1/settings/ldap', headers=headers, json={**base, **change})
        assert response.status_code == 400 and 'bind password again' in response.json()['detail']
        tested = await client.post('/api/v1/settings/ldap/test', headers=headers, json={**base, **change})
        assert tested.status_code == 400
    # Testing a server in clear text would send passwords in clear text
    clear = await client.post('/api/v1/settings/ldap/test', headers=headers,
                              json={**base, 'urls': ['ldap://dc1.example.org'], 'bind_password': 'x'})
    assert clear.status_code == 400 and 'in clear' in clear.json()['detail']


# -- webhooks --------------------------------------------------------------------------

class _Loop:
    """Stands in for the event loop's resolver, answering with fixed addresses."""

    def __init__(self, *addresses):
        self.addresses = addresses

    async def getaddrinfo(self, host, port, type=0):
        return [(socket.AF_INET6 if ':' in a else socket.AF_INET, socket.SOCK_STREAM, 6, '', (a, port))
                for a in self.addresses]


class _Asyncio:
    def __init__(self, *addresses):
        self.loop = _Loop(*addresses)

    def get_running_loop(self):
        return self.loop


async def _hook(url: str, **extra) -> Webhook:
    async with db.sessionmaker()() as session:
        hook = Webhook(**{'name': 'h', 'secret_enc': crypto.encrypt('s'), 'events': ['finding.created'],
                          'all_findings': True, 'min_severity': 'info', **extra})
        set_url(hook, url)
        session.add(hook)
        await session.commit()
        await session.refresh(hook)
        return hook


def _delivery(hook: Webhook) -> WebhookDelivery:
    return WebhookDelivery(id=uuid.uuid4(), webhook_id=hook.id, event='test',
                           payload={'event': 'test', 'message': 'hi'}, status='pending', attempts=0)


async def test_delivery_connects_to_the_address_it_checked_and_names_the_host(monkeypatch):
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14'))
    hook = await _hook('https://hooks.example.test:8443/in/abc?x=1')
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        return httpx.Response(204)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        outcome = await dispatcher.send(http, hook, _delivery(hook))
    assert outcome['error'] is None
    request = seen[0]
    assert str(request.url) == 'https://93.184.215.14:8443/in/abc?x=1'
    assert request.headers['host'] == 'hooks.example.test:8443'
    assert request.extensions['sni_hostname'] == 'hooks.example.test'


async def test_a_redirect_is_not_followed_and_a_test_delivery_reports_what_came_back(client, monkeypatch):
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14'))
    hook = await _hook('https://hooks.example.test/in')
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={'Location': 'http://169.254.169.254/latest'})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        outcome = await dispatcher.send(http, hook, _delivery(hook))
    assert len(seen) == 1 and outcome['status_code'] == 302 and outcome['error']
    # Through the API: only someone who may change webhooks can test one
    real = httpx.AsyncClient

    class Fake(real):
        def __init__(self, *args, **kwargs):
            super().__init__(transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok')))
    monkeypatch.setattr('tbconsole.api.webhooks.httpx.AsyncClient', Fake)
    await make_user('ana', role='analyst')
    await make_user('root', role='admin')
    headers = await login(client, 'ana')
    assert (await client.post(f'/api/v1/webhooks/{hook.id}/test', headers=headers)).status_code == 403
    headers = await login(client, 'root')
    tested = await client.post(f'/api/v1/webhooks/{hook.id}/test', headers=headers)
    assert tested.status_code == 200 and tested.json()['status'] == 'succeeded'
    assert tested.json()['response_snippet'] == 'ok'


async def test_a_disabled_webhook_sends_nothing_already_queued():
    hook = await _hook('https://hooks.example.test/in', enabled=False)
    calls = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200))) as http:
        outcome = await dispatcher.send(http, hook, _delivery(hook))
    assert calls == [] and outcome['retry'] is False and 'disabled' in outcome['error']


@pytest.mark.parametrize('addresses', [
    ('169.254.169.254',), ('93.184.215.14', '10.0.0.5'), ('::ffff:169.254.169.254',), ('64:ff9b::a9fe:a9fe',),
])
async def test_delivery_refuses_an_address_it_may_not_reach_and_does_not_connect(monkeypatch, addresses):
    monkeypatch.setattr(safety, 'asyncio', _Asyncio(*addresses))
    hook = await _hook('https://hooks.example.test/in')
    calls = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200))) as http:
        outcome = await dispatcher.send(http, hook, _delivery(hook))
    assert outcome['retry'] is False and 'may not reach' in outcome['error']
    assert calls == []


def test_addresses_hidden_inside_ipv6_are_judged_as_what_they_are():
    for text in ('::ffff:169.254.169.254', '64:ff9b::a9fe:a9fe', '2002:a9fe:a9fe::1'):
        assert safety._blocked(ipaddress.ip_address(text), allow_private=True), text
    assert safety._blocked(ipaddress.ip_address('::ffff:10.0.0.1'), allow_private=False)
    assert not safety._blocked(ipaddress.ip_address('::ffff:93.184.215.14'), allow_private=False)


@pytest.mark.parametrize('url', ['https://exämple.org/hook', 'https://example.org/a\r\nX-Evil: 1',
                                 'https://example.org/a b', 'ftp://example.org/', 'https://user:pw@example.org/'])
def test_a_url_that_could_smuggle_or_mislead_is_refused(url):
    with pytest.raises(safety.UnsafeUrl):
        safety.check_shape(url)


async def test_a_webhooks_full_url_is_encrypted_and_shown_only_to_those_who_may_change_it(client):
    hook = await _hook('https://hooks.slack.com/services/T0/B0/SECRETPART')
    async with db.sessionmaker()() as session:
        stored = await session.get(Webhook, hook.id)
        assert 'SECRETPART' not in stored.url_enc and stored.url_display == 'https://hooks.slack.com/…'
    await make_user('ana', role='analyst')
    await make_user('root', role='admin')
    await login(client, 'ana')
    listed = await client.get('/api/v1/webhooks')
    assert 'SECRETPART' not in listed.text and listed.json()[0]['url'] == 'https://hooks.slack.com/…'
    assert 'SECRETPART' not in (await client.get(f'/api/v1/webhooks/{hook.id}')).text
    await login(client, 'root')
    assert (await client.get('/api/v1/webhooks')).json()[0]['url'].endswith('/SECRETPART')


def test_chat_messages_cannot_be_turned_into_links_or_pings():
    event = {'event': 'finding.created', 'url': 'https://console.example.org/findings/1', 'finding': {
        'title': 'Threat seen: <https://evil.example|Reset your password>', 'severity': 'high',
        'summary': 'x' * 5000, 'entity': '@everyone [click](https://evil.example)', 'event_count': 3,
        'status': 'new', 'rule_name': 'r'}}
    slack = formats.render('slack', event)
    blocks = slack['attachments'][0]['blocks']
    # Everything Slack reads as mrkdwn is escaped; its plain_text header shows as it is
    mrkdwn = [slack['text'], blocks[1]['text']['text']] + [f['text'] for f in blocks[2]['fields']]
    assert not any('<https://evil' in t or '<' in t for t in mrkdwn)
    assert '&lt;https://evil.example|Reset your password&gt;' in slack['text']
    assert blocks[0]['text']['type'] == 'plain_text'
    assert len(blocks[1]['text']['text']) <= 3000
    assert all(len(f['text']) <= 2000 for f in blocks[2]['fields'])
    discord = formats.render('discord', event)
    assert discord['allowed_mentions'] == {'parse': []}
    assert '[click]' not in str(discord['embeds'][0]['fields'])


def test_a_failing_rules_error_leaves_out_the_inside_of_the_network():
    text = public_error('Cannot reach https://10.0.0.5:9200/_search: timed out talking to 10.0.0.6:9300 '
                        'and [fd00::5]:9200')
    assert '10.0.0' not in text and 'fd00' not in text and '[url]' in text and '[address]' in text
    assert len(public_error('e' * 2000)) <= 300


# -- findings ----------------------------------------------------------------------------

async def test_reopening_a_finding_that_has_an_open_successor_is_refused(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    old = await _finding(status='resolved', dedup_key='same')
    await _finding(status='new', dedup_key='same')
    response = await client.patch(f'/api/v1/findings/{old.id}', headers=headers, json={'status': 'new'})
    assert response.status_code == 409 and 'already open' in response.json()['detail']
    bulk = await client.post('/api/v1/findings/bulk', headers=headers,
                             json={'ids': [str(old.id)], 'status': 'acknowledged'})
    assert bulk.json() == {'updated': 0, 'skipped': [old.number]}


async def test_bulk_changes_tell_the_webhooks_that_listen_for_them(client):
    await _hook('https://example.org/hook', events=['finding.status_changed'])
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    a, b = await _finding('ava'), await _finding('liam')
    response = await client.post('/api/v1/findings/bulk', headers=headers,
                                 json={'ids': [str(a.id), str(b.id)], 'status': 'resolved'})
    assert response.json()['updated'] == 2
    async with db.sessionmaker()() as session:
        events = (await session.execute(select(WebhookDelivery.event))).scalars().all()
    assert events == ['finding.status_changed', 'finding.status_changed']


async def test_finding_search_takes_wildcards_literally_and_survives_huge_numbers(client):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    await _finding('ava', title='Blocked 100% of lookups')
    await _finding('liam', title='Blocked 1000 lookups')
    found = (await client.get('/api/v1/findings', params={'q': '100%'})).json()
    assert [f['title'] for f in found['items']] == ['Blocked 100% of lookups']
    assert (await client.get('/api/v1/findings', params={'q': '_'})).json()['total'] == 0
    assert (await client.get('/api/v1/findings', params={'q': 'F-99999999999999'})).status_code == 200
    assert (await client.get('/api/v1/findings', params={'since': '2026-10-01T00:00:00'})).status_code == 200


async def test_an_events_only_key_sees_events_but_no_findings(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    await _finding('ava')
    profile = await client.get('/api/v1/entities/profile', params={'field': 'user', 'value': 'ava'})
    assert len(profile.json()['findings']) == 1
    key = (await client.post('/api/v1/api-keys', headers=headers,
                             json={'name': 'events', 'scopes': ['events:read']})).json()['key']
    client.cookies.clear()
    auth = {'Authorization': f'Bearer {key}'}
    profile = (await client.get('/api/v1/entities/profile', headers=auth,
                                params={'field': 'user', 'value': 'ava'})).json()
    assert profile['findings'] == [] and profile['risk']['score'] == 0
    overview = (await client.get('/api/v1/overview', headers=auth)).json()
    assert overview['findings']['latest'] == [] and sum(overview['findings']['open'].values()) == 0
    domain = (await client.get('/api/v1/domains/evil.example', headers=auth)).json()
    assert domain['findings'] == []
    assert (await client.get('/api/v1/findings', headers=auth)).status_code == 403


async def test_a_domain_page_needs_a_domain(client):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    for bad in ('%25', 'a b', 'x' * 300):
        assert (await client.get(f'/api/v1/domains/{bad}')).status_code == 400, bad


async def test_comments_and_saved_searches_are_audited(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    finding = await _finding('ava')
    await client.post(f'/api/v1/findings/{finding.id}/comments', headers=headers, json={'body': 'Called the family'})
    saved = (await client.post('/api/v1/saved-searches', headers=headers,
                               json={'name': 'Ava', 'query': 'user:ava', 'shared': True})).json()
    await client.delete(f"/api/v1/saved-searches/{saved['id']}", headers=headers)
    assert len(await _audit('finding.comment')) == 1
    saves = await _audit('search.save')
    assert saves[0].details == {'query': 'user:ava', 'shared': True}
    assert len(await _audit('search.delete')) == 1


# -- searches and rules ------------------------------------------------------------------------

async def test_runaway_queries_and_ranges_are_refused_in_words(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    for body in ({'query': '(' * 300 + 'risk:threat' + ')' * 300},
                 {'query': 'NOT ' * 300 + 'risk:threat'},
                 {'from': 'now-99999999999d'},
                 {'from': 'now-9999999d'}):
        response = await client.post('/api/v1/events/search', headers=headers, json=body)
        assert response.status_code == 400, body
    pivot = await client.post('/api/v1/analytics/pivot', headers=headers,
                              json={'from': 'now-30d', 'over_time': True, 'interval': '1m'})
    assert pivot.status_code == 400 and 'too many buckets' in pivot.json()['detail']


async def test_autocomplete_matches_either_case_and_lucene_specials_literally(client, search):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    await client.get('/api/v1/fields/rcode/values', params={'prefix': 'nx@~'})
    include = search.bodies[-1]['aggs']['v']['terms']['include']
    assert include == '[nN][xX]\\@\\~.*'


async def test_backtests_and_titles_are_for_rule_authors(client):
    await make_user('vic', role='viewer')
    await make_user('ana', role='analyst')
    rule = {'name': 'r', 'type': 'threshold', 'query': 'risk:threat', 'params': {'threshold': 1}}
    headers = await login(client, 'vic')
    assert (await client.post('/api/v1/rules/backtest', headers=headers, json=rule)).status_code == 403
    headers = await login(client, 'ana')
    assert (await client.post('/api/v1/rules/backtest', headers=headers, json=rule)).status_code == 200
    bad = await client.post('/api/v1/rules', headers=headers, json={**rule, 'title_template': '{count:>999999999}'})
    assert bad.status_code == 400 and 'not something a title can show' in bad.json()['detail']
    naive = await client.post('/api/v1/rules', headers=headers, json={
        **rule, 'exceptions': [{'query': 'host:lab-1', 'expires_at': '2027-01-01T00:00:00'}]})
    assert naive.status_code == 201
    assert naive.json()['exceptions'][0]['expires_at'].endswith('Z')


async def test_rules_read_a_little_behind_now_so_late_events_are_still_counted(search, monkeypatch):
    from tbconsole.analysis import engine
    from tbconsole.config import get_settings
    from tbconsole.models import Rule
    monkeypatch.setattr(get_settings(), 'rule_ingest_delay_sec', 60)
    now = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
    async with db.sessionmaker()() as session:
        rule = Rule(name='r', type='threshold', query='', params={'threshold': 1}, group_by=[],
                    severity='low', window_seconds=900, interval_seconds=300, dedup_seconds=0,
                    category='custom', last_run_at=now - timedelta(minutes=5))
        session.add(rule)
        await session.commit()
        await engine.run_rule(session, search, rule, now=now)
        await session.commit()
    window = search.bodies[0]['query']['bool']['filter'][0]['range']['@timestamp']
    assert window == {'gte': '2026-10-05T11:44:00.000Z', 'lt': '2026-10-05T11:59:00.000Z'}


async def test_a_shorter_interval_takes_effect_at_once(client):
    from tbconsole.models import Rule
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    rule = (await client.post('/api/v1/rules', headers=headers, json={
        'name': 'weekly', 'type': 'threshold', 'query': 'risk:threat', 'params': {'threshold': 1},
        'interval_seconds': 7 * 86400, 'window_seconds': 7 * 86400})).json()
    async with db.sessionmaker()() as session:
        stored = await session.get(Rule, uuid.UUID(rule['id']))
        stored.next_run_at = datetime.now(timezone.utc) + timedelta(days=7)
        await session.commit()
    await client.put(f"/api/v1/rules/{rule['id']}", headers=headers, json={
        'name': 'weekly', 'type': 'threshold', 'query': 'risk:threat', 'params': {'threshold': 1},
        'interval_seconds': 300, 'window_seconds': 900})
    async with db.sessionmaker()() as session:
        stored = await session.get(Rule, uuid.UUID(rule['id']))
        assert stored.next_run_at - datetime.now(timezone.utc) < timedelta(minutes=6)


def test_first_seen_needs_a_name_or_an_address():
    from tbconsole.analysis.ruletypes import RuleError, RuleSpec, normalise
    with pytest.raises(RuleError, match='a name or an address'):
        normalise(RuleSpec(name='n', type='new_value', params={'field': '@timestamp'}))


async def test_run_now_waits_its_turn_behind_a_run_in_progress(client):
    from tbconsole.analysis import engine
    from tbconsole.models import Rule
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    async with db.sessionmaker()() as session:
        rule = Rule(name='r', type='threshold', query='', params={'threshold': 1}, group_by=[],
                    severity='low', window_seconds=900, interval_seconds=300, dedup_seconds=0,
                    category='custom')
        session.add(rule)
        await session.commit()
        rule_id = rule.id
    async with db.sessionmaker()() as holder:
        await engine.lock_rule(holder, rule_id)
        busy = await client.post(f'/api/v1/rules/{rule_id}/run', headers=headers)
        assert busy.status_code == 409
        await holder.rollback()
    assert (await client.post(f'/api/v1/rules/{rule_id}/run', headers=headers)).status_code == 200


# -- housekeeping ----------------------------------------------------------------------------

async def test_housekeeping_deletes_only_what_is_past_keeping():
    from tbconsole import maintenance
    now = datetime.now(timezone.utc)
    user = await make_user('ana')
    old = now - timedelta(days=400)
    hook = await _hook('https://example.org/hook')
    async with db.sessionmaker()() as session:
        # Expired; idle past the limit; and one still good
        for expires, seen in ((now - timedelta(hours=1), now), (now + timedelta(days=1), now - timedelta(days=2)),
                              (now + timedelta(days=1), now)):
            session.add(UserSession(token_hash=crypto.sha256(uuid.uuid4().hex), user_id=user.id,
                                    expires_at=expires, last_seen_at=seen))
        for state, age in (('succeeded', 40), ('dead', 40), ('pending', 40), ('succeeded', 1)):
            session.add(WebhookDelivery(webhook_id=hook.id, event='test', payload={}, status=state,
                                        created_at=now - timedelta(days=age)))
        session.add(AuditEvent(action='old', at=old, actor_type='system', actor_name='x'))
        session.add(AuditEvent(action='recent', actor_type='system', actor_name='x'))
        await session.commit()
    gone = await _finding('ava', status='resolved', resolved_at=old)
    await _finding('liam', status='resolved', resolved_at=now)
    await _finding('ivy', status='new')
    async with db.sessionmaker()() as session:
        session.add(FindingActivity(finding_id=gone.id, actor_name='x', kind='comment', body='hi'))
        await session.commit()
        removed = await maintenance.prune(session, now)
    assert removed == {'sessions': 2, 'deliveries': 2, 'findings': 1, 'audit': 1}
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(func.count()).select_from(FindingActivity))).scalar_one() == 0
        assert (await session.execute(select(func.count()).select_from(Finding))).scalar_one() == 2


# -- configuration and serving ------------------------------------------------------------------

def test_a_database_password_with_url_characters_needs_no_escaping():
    from tbconsole.config import Settings
    settings = Settings(secret_key='k' * 40, database_url='postgresql+asyncpg://tbconsole@db:5432/tbconsole',
                        database_password='p@ss/w:rd', opensearch_ca_certs='', static_dir='')
    from sqlalchemy.engine import make_url
    assert make_url(settings.database_url).password == 'p@ss/w:rd'
    assert settings.opensearch_ca_certs is None and settings.static_dir is None


async def test_the_app_answers_head_requests_for_its_pages(tmp_path, monkeypatch):
    from tbconsole.config import get_settings
    from tbconsole.main import create_app
    (tmp_path / 'index.html').write_text('<!doctype html><title>console</title>')
    monkeypatch.setattr(get_settings(), 'static_dir', tmp_path)
    app = create_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as c:
        assert (await c.head('/findings')).status_code == 200
        assert (await c.get('/findings')).text.startswith('<!doctype html>')
        assert (await c.get('/api/v1/nothing-here')).status_code == 404


def test_today_starts_at_the_callers_midnight():
    from tbconsole.search import timerange
    now = datetime(2026, 10, 5, 2, 30, tzinfo=timezone.utc)  # 22:30 on the 4th in New York
    token = timerange._zone.set('UTC')
    try:
        assert timerange.parse_range('now/d', 'now', now=now).start == datetime(2026, 10, 5, tzinfo=timezone.utc)
        timerange.use_zone('America/New_York')
        assert timerange.parse_range('now/d', 'now', now=now).start == datetime(2026, 10, 4, 4, tzinfo=timezone.utc)
        timerange.use_zone('Not/AZone')
        assert timerange.zone_name() == 'America/New_York'
    finally:
        timerange._zone.reset(token)


async def test_a_missing_asset_is_a_404_so_a_stale_app_knows_to_reload(tmp_path, monkeypatch):
    from tbconsole.config import get_settings
    from tbconsole.main import create_app
    (tmp_path / 'index.html').write_text('<!doctype html>')
    (tmp_path / 'assets').mkdir()
    (tmp_path / 'assets' / 'app-1.js').write_text('1')
    monkeypatch.setattr(get_settings(), 'static_dir', tmp_path)
    app = create_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as c:
        assert (await c.get('/assets/app-1.js')).status_code == 200
        assert (await c.get('/assets/app-0.js')).status_code == 404
