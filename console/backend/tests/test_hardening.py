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
        finding = Finding(**{'rule_name': 'Threat seen', 'rule_type': 'threshold', 'category': 'threat',
                             'severity': 'high', 'status': status,
                             'title': title or f'Threat seen: {entity}', 'summary': '3 events',
                             'entity_field': 'bite.client_user', 'entity_value': entity,
                             'dedup_key': dedup_key or uuid.uuid4().hex, 'first_seen': now, 'last_seen': now,
                             'event_count': 3, 'evidence': {'top_domains': [{'key': 'evil.example', 'count': 3}]},
                             **extra})
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
                                                    reset_mfa=False, enable=False, revoke_keys=False))
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
    await cli.create_user(argparse.Namespace(username='root', role=None, password_stdin=True, reset_mfa=True,
                                             enable=False, revoke_keys=False))
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
    counts = await maintenance.recheck_directory()
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
    with pytest.raises(ldap.LdapUnavailable):
        await maintenance.recheck_directory()
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
        outcome = await dispatcher.send(hook, _delivery(hook), http)
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
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert len(seen) == 1 and outcome['status_code'] == 302 and outcome['error']
    # Through the API: only someone who may change webhooks can test one
    monkeypatch.setattr(dispatcher, 'client', lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok'))))
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
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert calls == [] and outcome['retry'] is False and 'disabled' in outcome['error']


@pytest.mark.parametrize('addresses', [
    ('169.254.169.254',), ('93.184.215.14', '10.0.0.5'), ('::ffff:169.254.169.254',), ('64:ff9b::a9fe:a9fe',),
])
async def test_delivery_refuses_an_address_it_may_not_reach_and_does_not_connect(monkeypatch, addresses):
    monkeypatch.setattr(safety, 'asyncio', _Asyncio(*addresses))
    hook = await _hook('https://hooks.example.test/in')
    calls = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200))) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
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
        assert await engine.claim_run(holder, rule_id) is not None
    busy = await client.post(f'/api/v1/rules/{rule_id}/run', headers=headers)
    assert busy.status_code == 409
    async with db.sessionmaker()() as holder:
        (await holder.get(Rule, rule_id)).running_until = None
        await holder.commit()
    assert (await client.post(f'/api/v1/rules/{rule_id}/run', headers=headers)).status_code == 200
    async with db.sessionmaker()() as session:
        assert (await session.get(Rule, rule_id)).running_until is None, 'the lease is given back'


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


# -- round two -------------------------------------------------------------------------

async def _client_from(app, host: str):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(host, 1234)),
                             base_url='http://testserver')


async def test_an_address_that_is_not_one_is_not_stored_and_cannot_dodge_the_lockout(app):
    await make_user('root', role='admin')
    forged = 'x' * 100
    async with await _client_from(app, forged) as c:
        for _ in range(5):
            response = await c.post('/api/v1/auth/login', json={'username': 'root', 'password': 'nope'})
            assert response.status_code == 401
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'root'))).scalar_one()
        assert user.locked_until is not None, 'the failures counted'
        ips = (await session.execute(select(AuditEvent.ip).where(AuditEvent.action == 'auth.login'))).scalars().all()
    assert len(ips) == 5 and set(ips) == {None}


def test_the_brake_lets_others_at_a_busy_address_through_and_counts_ipv6_by_network():
    from tbconsole.security import limits
    limits.reset()
    for i in range(limits.ADDRESS_LIMIT):
        limits.failed('203.0.113.7', f'guess-{i}')
    assert limits.limited('203.0.113.7', 'guess-1'), 'a name it got wrong is held back'
    assert not limits.limited('203.0.113.7', 'alice'), 'a name it has not tried is not'
    for _ in range(limits.PAIR_LIMIT):
        limits.failed('2001:db8::1', 'root')
    assert limits.limited('2001:db8::ffff', 'root'), 'the same /64'
    assert not limits.limited('2001:db8:0:1::1', 'root')
    limits.reset()


async def test_one_two_factor_token_makes_one_session(client):
    secret = pyotp.random_base32()
    await make_user('root', role='admin', totp_enabled=True, totp_secret_enc=crypto.encrypt(secret))
    token = (await client.post('/api/v1/auth/login', json={'username': 'root',
                                                          'password': 'correct horse battery'})).json()['token']
    totp = pyotp.TOTP(secret)
    assert (await client.post('/api/v1/auth/mfa', json={'token': token, 'code': totp.now()})).status_code == 200
    again = totp.at(datetime.now(timezone.utc) + timedelta(seconds=30))
    assert (await client.post('/api/v1/auth/mfa', json={'token': token, 'code': again})).status_code == 401


async def test_a_borrowed_session_cannot_guess_the_password(client):
    await make_user('ana')
    headers = await login(client, 'ana')
    from tbconsole.security import limits
    for _ in range(limits.PAIR_LIMIT):
        assert (await client.post('/api/v1/account/mfa/setup', headers=headers,
                                  json={'password': 'guess'})).status_code == 400
    assert (await client.post('/api/v1/account/mfa/setup', headers=headers,
                              json={'password': 'correct horse battery'})).status_code == 429


async def test_changing_your_password_ends_every_other_session_and_keeps_yours(client, app):
    await make_user('ana')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as other:
        await login(other, 'ana')
        headers = await login(client, 'ana')
        response = await client.post('/api/v1/account/password', headers=headers,
                                     json={'current': 'correct horse battery', 'new': 'A-much-better-passphrase-26'})
        assert response.status_code == 200
        assert (await client.get('/api/v1/auth/me')).status_code == 200
        assert (await other.get('/api/v1/auth/me')).status_code == 401
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(User.password_changed_at))).scalar_one() is not None


async def test_a_link_on_another_site_cannot_act_with_the_cookie(client):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    response = await client.get('/api/v1/entities/profile', params={'field': 'user', 'value': 'ava'},
                                headers={'Sec-Fetch-Site': 'cross-site'})
    assert response.status_code == 403
    assert (await client.get('/api/v1/auth/me', headers={'Sec-Fetch-Site': 'same-origin'})).status_code == 200
    assert await _audit('entity.view') == []


async def test_the_default_port_written_out_is_the_same_origin(client, monkeypatch):
    from tbconsole.config import get_settings
    monkeypatch.setattr(get_settings(), 'public_url', 'http://testserver:80')
    await make_user('ana')
    response = await client.post('/api/v1/auth/login', headers={'Origin': 'http://testserver'},
                                 json={'username': 'ana', 'password': 'correct horse battery'})
    assert response.status_code == 200


async def test_create_user_leaves_a_disabled_account_disabled_unless_asked_and_can_revoke_keys(monkeypatch):
    from tbconsole import __main__ as cli
    from tbconsole.models import ApiKey
    from tbconsole.security import apikeys
    user = await make_user('svc', role='analyst', disabled=True, disabled_reason='admin')
    async with db.sessionmaker()() as session:
        _, prefix, digest = apikeys.generate() if hasattr(apikeys, 'generate') else (None, 'abcd1234', b'0' * 32)
        session.add(ApiKey(user_id=user.id, name='k', prefix=prefix, key_hash=digest, scopes=['findings:read']))
        await session.commit()
    monkeypatch.setattr('sys.stdin', io.StringIO('An-entirely-new-passphrase-2026\n'))
    await cli.create_user(argparse.Namespace(username='svc', role=None, password_stdin=True, reset_mfa=False,
                                             enable=False, revoke_keys=True))
    async with db.sessionmaker()() as session:
        stored = await session.get(User, user.id)
        assert stored.disabled
        assert (await session.execute(select(ApiKey.revoked_at))).scalar_one() is not None


async def test_reencrypt_moves_every_secret_to_the_current_key(monkeypatch, capsys):
    from tbconsole import __main__ as cli
    from tbconsole.config import get_settings
    settings = get_settings()
    old = settings.secret_key
    await make_user('root', totp_enabled=True, totp_secret_enc=crypto.encrypt('TOTPSECRET'))
    hook = await _hook('https://example.org/hook')
    monkeypatch.setattr(settings, 'secret_key', 'a-brand-new-secret-key-that-is-long-enough-01')
    monkeypatch.setattr(settings, 'secret_key_previous', [old])
    crypto._fernet.cache_clear() if hasattr(crypto._fernet, 'cache_clear') else None
    assert await cli.reencrypt(argparse.Namespace()) == 0
    monkeypatch.setattr(settings, 'secret_key_previous', [])
    crypto._fernet.cache_clear() if hasattr(crypto._fernet, 'cache_clear') else None
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User))).scalar_one()
        assert crypto.decrypt(user.totp_secret_enc) == 'TOTPSECRET'
        stored = await session.get(Webhook, hook.id)
        assert crypto.decrypt(stored.url_enc) == 'https://example.org/hook'


async def test_an_admin_can_disable_someone_the_directory_already_had(client):
    await make_user('root', role='admin')
    ava = await make_user('ava', source='ldap', role='analyst', disabled=True, disabled_reason='directory')
    headers = await login(client, 'root')
    response = await client.patch(f'/api/v1/users/{ava.id}', headers=headers, json={'disabled': True})
    assert response.status_code == 200
    async with db.sessionmaker()() as session:
        assert (await session.get(User, ava.id)).disabled_reason == 'admin'


async def test_signing_in_with_another_name_for_the_same_person_finds_their_account(client, directory):
    # The console keeps the uid; this person signs in with their email address
    await _save_directory(dict(directory, user_filter='(&(objectClass=person)(|(uid={username})(mail={username})))'))
    first = await client.post('/api/v1/auth/login', json={'username': 'ava@example.org', 'password': 'ava-pw'})
    second = await client.post('/api/v1/auth/login', json={'username': 'ava@example.org', 'password': 'ava-pw'})
    assert first.status_code == 200 and second.status_code == 200
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(func.count()).select_from(User))).scalar_one() == 1


async def test_a_directory_that_answers_busy_says_nothing_about_anyone(directory, monkeypatch):
    from tbconsole.security import ldap
    original = ldap._answered

    def busy(conn, what, allow=ldap._ANSWERED):
        conn.result = {'result': 51, 'description': 'busy'}
        return original(conn, what, allow)
    monkeypatch.setattr(ldap, '_answered', busy)
    with pytest.raises(ldap.LdapUnavailable, match='busy'):
        ldap.recheck(directory, 'svc-pw', 'uid=ava,ou=people,dc=example,dc=org', 'ava')


async def test_a_recheck_that_would_revoke_most_people_revokes_nobody(client, directory, monkeypatch):
    from tbconsole import maintenance
    await _save_directory(directory)
    for name in ('p1', 'p2', 'p3', 'p4', 'p5'):
        user = await make_user(name, source='ldap', role='analyst', ldap_dn=f'uid={name},ou=people,dc=example,dc=org')
        async with db.sessionmaker()() as session:
            session.add(UserSession(token_hash=crypto.sha256(name), user_id=user.id,
                                    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                                    last_seen_at=datetime.now(timezone.utc)))
            await session.commit()
    counts = await maintenance.recheck_directory()
    assert counts['held_back'] == 5 and counts['revoked'] == 0
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(func.count()).select_from(User).where(User.disabled))).scalar_one() == 0


async def test_accounts_revoked_before_do_not_hold_back_the_next_revocation(client, directory):
    # Five people the directory already took away, still looked at in case it
    # gives them back, must not count as five more revocations every hour
    from tbconsole import maintenance
    await _save_directory(directory)
    for name in ('p1', 'p2', 'p3', 'p4', 'p5'):
        await make_user(name, source='ldap', role='analyst', disabled=True, disabled_reason='directory',
                        ldap_dn=f'uid={name},ou=people,dc=example,dc=org')
    await login(client, 'ava', 'ava-pw')
    await make_user('bob', source='ldap', role='analyst', ldap_dn='uid=bob,ou=people,dc=example,dc=org')
    async with db.sessionmaker()() as session:
        bob = (await session.execute(select(User).where(User.username == 'bob'))).scalar_one()
        session.add(UserSession(token_hash=crypto.sha256('bob'), user_id=bob.id,
                                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                                last_seen_at=datetime.now(timezone.utc)))
        await session.commit()
    # Bob is in no group that grants a role: one of two active accounts loses
    # access, which is a revocation, not a mass one
    counts = await maintenance.recheck_directory()
    assert counts['held_back'] == 0 and counts['revoked'] == 1
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(User.disabled).where(User.username == 'bob'))).scalar_one()
        assert not (await session.execute(select(User.disabled).where(User.username == 'ava'))).scalar_one()


async def test_a_header_with_space_at_an_end_is_refused_when_saved(client, monkeypatch):
    monkeypatch.setattr(safety, 'check', lambda url: _noop())
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    for value in ('Bearer TOKEN ', ' Bearer TOKEN', 'a\x7fb'):
        response = await client.post('/api/v1/webhooks', headers=headers, json={
            'name': 'x', 'url': 'https://example.org/', 'headers': {'Authorization': value}})
        assert response.status_code == 400, repr(value)
    for name in ('Transfer-Encoding', 'Connection', 'TE'):
        response = await client.post('/api/v1/webhooks', headers=headers, json={
            'name': 'x', 'url': 'https://example.org/', 'headers': {name: 'x'}})
        assert response.status_code == 400, name


async def _noop():
    return None


async def test_a_request_that_cannot_be_written_records_no_header_text(monkeypatch):
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14'))
    hook = await _hook('https://hooks.example.test/in')

    def handler(request):
        raise httpx.LocalProtocolError('Illegal header value b"Bearer SECRET-TOKEN "')
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert 'SECRET' not in outcome['error'] and outcome['retry'] is False


async def test_a_receiver_that_dawdles_is_cut_off_and_a_huge_answer_is_not_kept(monkeypatch):
    import asyncio as aio
    from tbconsole.config import get_settings
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14'))
    monkeypatch.setattr(dispatcher, 'DEADLINE_SLACK', 0)
    monkeypatch.setattr(get_settings(), 'webhook_timeout_sec', 0.2)
    hook = await _hook('https://hooks.example.test/in')

    async def slow(request):
        await aio.sleep(2)
        return httpx.Response(200)
    async with httpx.AsyncClient(transport=httpx.MockTransport(slow)) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert 'too long' in outcome['error'] and outcome['retry'] is True
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b'x' * 5_000_000))) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert outcome['error'] is None and len(outcome['snippet']) <= 300


async def test_deliveries_ignore_proxy_settings_in_the_environment_and_use_a_configured_one(monkeypatch):
    from tbconsole.config import get_settings
    assert dispatcher.client()._trust_env is False
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14'))
    monkeypatch.setattr(get_settings(), 'webhook_proxy', 'http://proxy.example.test:3128')
    hook = await _hook('https://hooks.example.test/in')
    seen = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200))) as http:
        await dispatcher.send(hook, _delivery(hook), http)
    # Through a proxy the name goes as it is; the proxy connects
    assert seen[0].url.host == 'hooks.example.test'


async def test_a_second_address_is_tried_when_the_first_will_not_connect(monkeypatch):
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14', '93.184.215.15'))
    hook = await _hook('https://hooks.example.test/in')
    seen = []

    def handler(request):
        seen.append(request.url.host)
        if request.url.host == '93.184.215.14':
            raise httpx.ConnectError('refused')
        return httpx.Response(204)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert seen == ['93.184.215.14', '93.184.215.15'] and outcome['error'] is None


async def test_an_ipv6_host_header_is_bracketed():
    target = await safety.resolve('https://[2606:4700::1111]:8443/x')
    assert target.host_header == '[2606:4700::1111]:8443'
    with pytest.raises(safety.UnsafeUrl):
        safety.check_shape('https://example.org:0/x')


async def test_a_webhooks_read_key_sees_deliveries_but_not_who_they_were_about(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    hook = await _hook('https://example.org/hook')
    async with db.sessionmaker()() as session:
        session.add(WebhookDelivery(webhook_id=hook.id, event='finding.created', status='succeeded', payload={
            'event': 'finding.created', 'finding': {'title': 'Threat seen: ava', 'entity': 'ava'}}))
        await session.commit()
    key = (await client.post('/api/v1/api-keys', headers=headers,
                             json={'name': 'k', 'scopes': ['webhooks:read']})).json()['key']
    client.cookies.clear()
    auth = {'Authorization': f'Bearer {key}'}
    listed = await client.get('/api/v1/webhook-deliveries', headers=auth)
    assert listed.status_code == 200 and 'ava' not in listed.text
    one = await client.get(f"/api/v1/webhook-deliveries/{listed.json()[0]['id']}", headers=auth)
    assert one.status_code == 200 and 'ava' not in one.text


def test_google_chat_and_teams_cannot_be_made_to_mention_or_link():
    from tbconsole.webhooks import formats, signing
    event = {'event': 'finding.created', 'finding': {
        'title': 'Seen: <users/all>', 'summary': '[click](https://evil.example) <https://evil|x>', 'severity': 'high',
        'entity': 'ava', 'status': 'new', 'rule_name': 'r', 'event_count': 1}}
    chat = formats.render('google_chat', event)
    readable = [chat['text']] + [str(w) for w in chat['cardsV2'][0]['card']['sections'][0]['widgets']]
    assert not any('<users/all>' in t or '<https://evil' in t for t in readable)
    teams = formats.render('teams', event)
    assert '[click](' not in str(teams)
    assert signing.verify('s', b'x', None) is False and signing.verify('s', b'x', 't=1,v1=é') is False


async def test_the_live_tail_stops_for_someone_signed_out(client, app):
    from starlette.requests import Request as StarletteRequest
    from tbconsole.api.events import _still_allowed
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    cookie = client.cookies.get('tbc_session')

    def request():
        scope = {'type': 'http', 'method': 'GET', 'path': '/api/v1/events/live', 'query_string': b'',
                 'headers': [(b'cookie', f'tbc_session={cookie}'.encode())], 'client': ('127.0.0.1', 1)}
        return StarletteRequest(scope)
    assert await _still_allowed(request()) is True
    await client.post('/api/v1/auth/logout', headers={'X-CSRF-Token': client.cookies.get('tbc_csrf')})
    assert await _still_allowed(request()) is False


async def test_the_live_tail_cap_holds(client, monkeypatch):
    from tbconsole.api import events
    user = await make_user('ana', role='analyst')
    await login(client, 'ana')
    monkeypatch.setitem(events._live, str(user.id), events.MAX_LIVE_PER_USER)
    assert (await client.get('/api/v1/events/live')).status_code == 429


async def test_looks_at_people_through_pivots_histograms_lists_and_suggestions_are_audited(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    await client.post('/api/v1/analytics/pivot', headers=headers, json={'rows': 'user'})
    await client.post('/api/v1/events/search', headers=headers, json={'query': 'user:ava'})
    await client.post('/api/v1/events/histogram', headers=headers, json={'query': 'user:ava'})
    await client.get('/api/v1/entities', params={'query': 'user:ava'})
    await client.get('/api/v1/fields/user/values', params={'prefix': 'a'})
    await client.get('/api/v1/fields/user/values', params={'prefix': 'av'})
    assert len(await _audit('analytics.pivot')) == 1
    assert len(await _audit('events.search')) == 1, 'the histogram of the same search is the same look'
    assert len(await _audit('entities.list')) == 1
    assert len(await _audit('events.top')) == 1, 'suggestions are one look, not one per keystroke'


async def test_times_out_of_range_and_bodies_that_are_not_json_are_400s_not_500s(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    for body in ({'from': '9999-12-31T23:59:59-01:00'}, {'from': '0001-01-01T00:00:00+01:00'}):
        assert (await client.post('/api/v1/events/search', headers=headers, json=body)).status_code == 400
    assert (await client.get('/api/v1/findings', params={'since': '9999-12-31T23:59:59-01:00'})).status_code == 400
    raw = await client.post('/api/v1/events/search', headers={**headers, 'Content-Type': 'application/json'},
                            content=b'\xff\xfenot json')
    assert raw.status_code == 422


async def test_the_probes_answer_head_and_readiness_fails_without_the_database(client, monkeypatch):
    assert (await client.head('/healthz')).status_code == 200
    assert (await client.head('/readyz')).status_code == 200

    def broken():
        raise ConnectionRefusedError('no database')
    monkeypatch.setattr(db, 'sessionmaker', broken)
    assert (await client.get('/readyz')).status_code == 503


def test_a_database_password_needs_a_user_name_to_go_with():
    from pydantic import ValidationError

    from tbconsole.config import Settings
    with pytest.raises(ValidationError, match='user name'):
        Settings(secret_key='k' * 40, database_url='postgresql+asyncpg://db:5432/tbconsole',
                 database_password='secret')


def test_ldap_timeouts_reach_the_socket_as_whole_seconds(monkeypatch):
    # ldap3 packs receive_timeout with struct 'LL': a float there fails every
    # sign-in against a real directory, which the in-memory one never shows
    from tbconsole.security import ldap
    seen = {}

    class Recording:
        def __init__(self, *args, **kwargs):
            seen.update(kwargs)
            raise ConnectionRefusedError('stop here')
    monkeypatch.setattr(ldap, 'Connection', Recording)
    cfg = ldap.config_with_defaults({'enabled': True, 'urls': ['ldaps://dc.example.org'], 'timeout_sec': 5.0})
    with pytest.raises(ldap.LdapUnavailable):
        ldap.authenticate(cfg, 'pw', 'ava', 'ava-pw')
    assert isinstance(seen['receive_timeout'], int)


async def test_the_sign_in_check_gives_its_connection_back_before_the_request_goes_on(client):
    # A live tail or an export would otherwise hold a pooled connection, idle
    # in a transaction, for as long as it streams
    from starlette.requests import Request as StarletteRequest

    from tbconsole.deps import optional_principal
    await make_user('ana')
    await login(client, 'ana')
    scope = {'type': 'http', 'method': 'GET', 'path': '/', 'query_string': b'', 'client': ('127.0.0.1', 1),
             'headers': [(b'cookie', f"tbc_session={client.cookies.get('tbc_session')}".encode())]}
    async with db.sessionmaker()() as session:
        principal = await optional_principal(StarletteRequest(scope), session)
        assert principal is not None and principal.user.username == 'ana'
        assert not session.in_transaction()


async def test_a_first_seen_person_is_named_redacted_and_listed_for_masking(client):
    from tbconsole.webhooks.service import finding_body
    finding = await _finding('lab-12', title='First seen person (k.larsen)', entity_field='bite.client_hostname_short',
                             evidence={'detail': {'field': 'bite.client_user', 'new_value': 'k.larsen'}})
    body = finding_body(finding)
    assert body['new_value'] == {'field': 'bite.client_user', 'value': 'k.larsen', 'identity': True}
    redacted = finding_body(finding, redact=True)
    assert 'k.larsen' not in str(redacted) and redacted['new_value']['value'] == '[redacted]'
    hook = await _hook('https://example.org/hook')
    async with db.sessionmaker()() as session:
        session.add(WebhookDelivery(webhook_id=hook.id, event='finding.created', status='succeeded',
                                    payload={'event': 'finding.created', 'finding': body}))
        await session.commit()
    await make_user('root', role='admin')
    await login(client, 'root')
    listed = (await client.get('/api/v1/webhook-deliveries')).json()
    assert listed[0]['names'] == ['lab-12', 'k.larsen']
