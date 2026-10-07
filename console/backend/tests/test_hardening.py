"""What the critical review found, each held in place by a test.

Sign-in and accounts, the directory, webhooks, findings, searches, housekeeping
and configuration, in roughly that order.
"""

# Bandit's findings are marked nosec line by line: pytest checks with assert
# (B101), and the fixtures hold made-up passwords (B105, B106). None of this
# is code that ships.

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
    wrong = await client.post('/api/v1/account/mfa/setup', headers=headers, json={'password': 'nope'})  # nosec B105
    assert wrong.status_code == 400  # nosec B101
    right = await client.post('/api/v1/account/mfa/setup', headers=headers,
                              json={'password': 'correct horse battery'})  # nosec B105
    assert right.status_code == 200 and right.json()['secret']  # nosec B101
    assert sorted(e.outcome for e in await _audit('account.mfa_setup')) == ['failure', 'success']  # nosec B101


async def test_an_api_key_cannot_manage_its_owners_account(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    key = (await client.post('/api/v1/api-keys', headers=headers,
                             json={'name': 'k', 'scopes': ['findings:read']})).json()['key']
    client.cookies.clear()
    auth = {'Authorization': f'Bearer {key}'}
    for method, path, body in (('put', '/api/v1/account/preferences', {'theme': 'dark'}),
                               ('post', '/api/v1/account/password', {'current': 'x', 'new': 'y'}),
                               ('post', '/api/v1/account/mfa/setup', {'password': 'x'}),  # nosec B105
                               ('get', '/api/v1/account/sessions', None)):
        response = await client.request(method, path, headers=auth, json=body)
        assert response.status_code == 403, path  # nosec B101


async def test_a_lockout_holds_at_the_second_factor_too(client):
    secret = pyotp.random_base32()
    await make_user('root', role='admin', totp_enabled=True, totp_secret_enc=crypto.encrypt(secret))
    started = (await client.post('/api/v1/auth/login', json={'username': 'root',
                                                            'password': 'correct horse battery'})).json()  # nosec B105
    assert started['mfa_required']  # nosec B101
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'root'))).scalar_one()
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        await session.commit()
    refused = await client.post('/api/v1/auth/mfa', json={'token': started['token'],
                                                         'code': pyotp.TOTP(secret).now()})
    assert refused.status_code == 401  # nosec B101


async def test_guessing_one_username_does_not_lock_out_everyone_at_the_same_address(client):
    await make_user('alice')
    for _ in range(10):
        response = await client.post('/api/v1/auth/login', json={'username': 'mallory', 'password': 'guess'})  # nosec B105
        assert response.status_code == 401  # nosec B101
    assert (await client.post('/api/v1/auth/login',  # nosec B101
                              json={'username': 'mallory', 'password': 'guess'})).status_code == 429  # nosec B105
    # Someone else, from the same address, is not held back
    await login(client, 'alice')


async def test_admin_only_areas_are_closed_to_analysts(client):
    await make_user('ana', role='analyst')
    await make_user('root', role='admin')
    await login(client, 'ana')
    for path in ('/api/v1/users', '/api/v1/settings/general', '/api/v1/settings/ldap', '/api/v1/audit'):
        assert (await client.get(path)).status_code == 403, path  # nosec B101
    assert (await client.get('/api/v1/webhooks')).status_code == 200  # nosec B101
    headers = await login(client, 'root')
    for path in ('/api/v1/users', '/api/v1/settings/general', '/api/v1/settings/ldap', '/api/v1/audit'):
        assert (await client.get(path)).status_code == 200, path  # nosec B101
    analyst = {'X-CSRF-Token': headers['X-CSRF-Token']}
    client.cookies.clear()
    await login(client, 'ana')
    analyst = {'X-CSRF-Token': client.cookies.get('tbc_csrf')}
    created = await client.post('/api/v1/webhooks', headers=analyst, json={'name': 'x', 'url': 'https://example.org/'})
    assert created.status_code == 403  # nosec B101


async def test_create_user_resets_a_password_ends_sessions_and_keeps_the_role(client, monkeypatch):
    from tbconsole import __main__ as cli
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    monkeypatch.setattr('sys.stdin', io.StringIO('An-entirely-new-passphrase-2026\n'))
    code = await cli.create_user(argparse.Namespace(username='ana', role=None, password_stdin=True,
                                                    reset_mfa=False, enable=False, revoke_keys=False))
    assert code == 0  # nosec B101
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'ana'))).scalar_one()
        assert user.role == 'analyst' and user.password_changed_at is not None  # nosec B101
        assert (await session.execute(select(func.count()).select_from(UserSession))).scalar_one() == 0  # nosec B101
    assert len(await _audit('user.password_reset')) == 1  # nosec B101
    assert (await client.get('/api/v1/auth/me')).status_code == 401  # nosec B101


async def test_create_user_can_turn_off_a_lost_second_factor(monkeypatch):
    from tbconsole import __main__ as cli
    await make_user('root', role='admin', totp_enabled=True, totp_secret_enc=crypto.encrypt('ABC'))
    monkeypatch.setattr('sys.stdin', io.StringIO('An-entirely-new-passphrase-2026\n'))
    await cli.create_user(argparse.Namespace(username='root', role=None, password_stdin=True, reset_mfa=True,
                                             enable=False, revoke_keys=False))
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'root'))).scalar_one()
        assert not user.totp_enabled and user.totp_secret_enc is None and user.role == 'admin'  # nosec B101


async def test_signing_in_from_another_sites_page_is_refused(client):
    await make_user('ana')
    response = await client.post('/api/v1/auth/login', headers={'Origin': 'https://evil.example'},
                                 json={'username': 'ana', 'password': 'correct horse battery'})  # nosec B105
    assert response.status_code == 403  # nosec B101
    same = await client.post('/api/v1/auth/login', headers={'Origin': 'http://testserver'},
                             json={'username': 'ana', 'password': 'correct horse battery'})  # nosec B105
    assert same.status_code == 200  # nosec B101


async def test_a_session_write_needs_both_the_csrf_token_and_a_matching_origin(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    body = {'name': 'x', 'query': 'risk:threat'}
    assert (await client.post('/api/v1/saved-searches', json=body)).status_code == 403  # nosec B101
    assert (await client.post('/api/v1/saved-searches', json=body,  # nosec B101
                              headers={**headers, 'Origin': 'https://evil.example'})).status_code == 403
    assert (await client.post('/api/v1/saved-searches', json=body, headers=headers)).status_code == 201  # nosec B101


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
    assert allowed.status_code == 200, allowed.text  # nosec B101
    assert refused.status_code == 403  # nosec B101


def test_the_demo_will_not_touch_a_cluster_without_being_told_to(capsys):
    from tbconsole import __main__ as cli
    assert cli.main(['demo', 'seed']) == 2  # nosec B101
    assert '--yes-replace-everything' in capsys.readouterr().err  # nosec B101


# -- the directory --------------------------------------------------------------------

async def _save_directory(cfg: dict, password: str = 'svc-pw') -> None:
    async with db.sessionmaker()() as session:
        await settings_store.put(session, 'ldap', dict(cfg, bind_password_enc=crypto.encrypt(password)), None)
        await session.commit()


async def test_directory_sign_in_creates_the_account_with_its_groups_role(client, directory):
    await _save_directory(directory)
    response = await client.post('/api/v1/auth/login', json={'username': 'ava', 'password': 'ava-pw'})  # nosec B105
    assert response.status_code == 200  # nosec B101
    assert response.json()['user']['role'] == 'analyst' and response.json()['user']['source'] == 'ldap'  # nosec B101
    assert (await client.post('/api/v1/auth/login', json={'username': 'ava', 'password': 'wrong'})).status_code == 401  # nosec B101, B105
    assert (await client.post('/api/v1/auth/login', json={'username': 'bob', 'password': 'bob-pw'})).status_code == 403  # nosec B101, B105


async def test_the_directory_takes_access_away_within_the_hour_and_gives_it_back(client, directory):
    from tbconsole import maintenance
    await _save_directory(directory)
    await login(client, 'ava', 'ava-pw')
    # Ava's group no longer grants a role
    await _save_directory(dict(directory, role_mappings=[{'group': 'cn=other', 'role': 'analyst'}]))
    counts = await maintenance.recheck_directory()
    assert counts['revoked'] == 1  # nosec B101
    assert (await client.get('/api/v1/auth/me')).status_code == 401  # nosec B101
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'ava'))).scalar_one()
        assert user.disabled and user.disabled_reason == 'directory'  # nosec B101
    assert len(await _audit('user.directory_revoked')) == 1  # nosec B101
    # The group grants it again: signing in works, and the account is enabled
    await _save_directory(directory)
    await login(client, 'ava', 'ava-pw')
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'ava'))).scalar_one()
        assert not user.disabled and user.disabled_reason is None  # nosec B101


async def test_a_directory_that_is_down_is_a_503_and_local_accounts_still_work(client, directory):
    await _save_directory(directory, password='the-wrong-service-password')  # nosec B106
    await make_user('root', role='admin')
    response = await client.post('/api/v1/auth/login', json={'username': 'ava', 'password': 'ava-pw'})  # nosec B105
    assert response.status_code == 503 and 'Local accounts can still sign in' in response.json()['detail']  # nosec B101
    await login(client, 'root')


async def test_an_admins_disabling_outlasts_the_directory(client, directory):
    await _save_directory(directory)
    await make_user('ava', source='ldap', role='analyst', disabled=True, disabled_reason='admin',
                    ldap_dn='uid=ava,ou=people,dc=example,dc=org')
    response = await client.post('/api/v1/auth/login', json={'username': 'ava', 'password': 'ava-pw'})  # nosec B105
    assert response.status_code == 401  # nosec B101


async def test_a_recheck_that_cannot_reach_the_directory_changes_nothing(client, directory):
    from tbconsole import maintenance
    from tbconsole.security import ldap
    await _save_directory(directory)
    await login(client, 'ava', 'ava-pw')
    await _save_directory(directory, password='the-wrong-service-password')  # nosec B106
    with pytest.raises(ldap.LdapUnavailable):
        await maintenance.recheck_directory()
    assert (await client.get('/api/v1/auth/me')).status_code == 200  # nosec B101


async def test_the_saved_bind_password_only_goes_where_it_was_saved_for(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    base = {'enabled': False, 'urls': ['ldaps://dc1.example.org'], 'bind_dn': 'cn=svc,dc=example,dc=org',
            'user_base_dn': 'dc=example,dc=org'}
    assert (await client.put('/api/v1/settings/ldap', headers=headers,  # nosec B101
                             json={**base, 'bind_password': 'svc-pw'})).status_code == 200  # nosec B105
    # Unchanged servers and DN: the saved password is kept
    assert (await client.put('/api/v1/settings/ldap', headers=headers,  # nosec B101
                             json={**base, 'timeout_sec': 9})).status_code == 200
    for change in ({'urls': ['ldaps://attacker.example.net']}, {'bind_dn': 'cn=admin,dc=example,dc=org'}):
        response = await client.put('/api/v1/settings/ldap', headers=headers, json={**base, **change})
        assert response.status_code == 400 and 'bind password again' in response.json()['detail']  # nosec B101
        tested = await client.post('/api/v1/settings/ldap/test', headers=headers, json={**base, **change})
        assert tested.status_code == 400  # nosec B101
    # Testing a server in clear text would send passwords in clear text
    clear = await client.post('/api/v1/settings/ldap/test', headers=headers,
                              json={**base, 'urls': ['ldap://dc1.example.org'], 'bind_password': 'x'})  # nosec B105
    assert clear.status_code == 400 and 'in clear' in clear.json()['detail']  # nosec B101


# -- webhooks --------------------------------------------------------------------------

class _Loop:
    """Stands in for the event loop's resolver, answering with fixed addresses."""

    def __init__(self, *addresses):
        self.addresses = addresses

    async def getaddrinfo(self, host, port, **_options):
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
    assert outcome['error'] is None  # nosec B101
    request = seen[0]
    assert str(request.url) == 'https://93.184.215.14:8443/in/abc?x=1'  # nosec B101
    assert request.headers['host'] == 'hooks.example.test:8443'  # nosec B101
    assert request.extensions['sni_hostname'] == 'hooks.example.test'  # nosec B101


async def test_a_redirect_is_not_followed_and_a_test_delivery_reports_what_came_back(client, monkeypatch):
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14'))
    hook = await _hook('https://hooks.example.test/in')
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(302, headers={'Location': 'http://169.254.169.254/latest'})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert len(seen) == 1 and outcome['status_code'] == 302 and outcome['error']  # nosec B101
    # Through the API: only someone who may change webhooks can test one
    monkeypatch.setattr(dispatcher, 'client', lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text='ok'))))
    await make_user('ana', role='analyst')
    await make_user('root', role='admin')
    headers = await login(client, 'ana')
    assert (await client.post(f'/api/v1/webhooks/{hook.id}/test', headers=headers)).status_code == 403  # nosec B101
    headers = await login(client, 'root')
    tested = await client.post(f'/api/v1/webhooks/{hook.id}/test', headers=headers)
    assert tested.status_code == 200 and tested.json()['status'] == 'succeeded'  # nosec B101
    assert tested.json()['response_snippet'] == 'ok'  # nosec B101


async def test_a_disabled_webhook_sends_nothing_already_queued():
    hook = await _hook('https://hooks.example.test/in', enabled=False)
    calls = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200))) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert calls == [] and outcome['retry'] is False and 'disabled' in outcome['error']  # nosec B101


@pytest.mark.parametrize('addresses', [
    ('169.254.169.254',), ('93.184.215.14', '10.0.0.5'), ('::ffff:169.254.169.254',), ('64:ff9b::a9fe:a9fe',),
])
async def test_delivery_refuses_an_address_it_may_not_reach_and_does_not_connect(monkeypatch, addresses):
    monkeypatch.setattr(safety, 'asyncio', _Asyncio(*addresses))
    hook = await _hook('https://hooks.example.test/in')
    calls = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200))) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert outcome['retry'] is False and 'may not reach' in outcome['error']  # nosec B101
    assert calls == []  # nosec B101


def test_addresses_hidden_inside_ipv6_are_judged_as_what_they_are():
    for text in ('::ffff:169.254.169.254', '64:ff9b::a9fe:a9fe', '2002:a9fe:a9fe::1'):
        assert safety._blocked(ipaddress.ip_address(text), allow_private=True), text  # nosec B101
    assert safety._blocked(ipaddress.ip_address('::ffff:10.0.0.1'), allow_private=False)  # nosec B101
    assert not safety._blocked(ipaddress.ip_address('::ffff:93.184.215.14'), allow_private=False)  # nosec B101


@pytest.mark.parametrize('url', ['https://exämple.org/hook', 'https://example.org/a\r\nX-Evil: 1',
                                 'https://example.org/a b', 'ftp://example.org/', 'https://user:pw@example.org/'])
def test_a_url_that_could_smuggle_or_mislead_is_refused(url):
    with pytest.raises(safety.UnsafeUrl):
        safety.check_shape(url)


async def test_a_webhooks_full_url_is_encrypted_and_shown_only_to_those_who_may_change_it(client):
    hook = await _hook('https://hooks.slack.com/services/T0/B0/SECRETPART')
    async with db.sessionmaker()() as session:
        stored = await session.get(Webhook, hook.id)
        assert 'SECRETPART' not in stored.url_enc and stored.url_display == 'https://hooks.slack.com/…'  # nosec B101
    await make_user('ana', role='analyst')
    await make_user('root', role='admin')
    await login(client, 'ana')
    listed = await client.get('/api/v1/webhooks')
    assert 'SECRETPART' not in listed.text and listed.json()[0]['url'] == 'https://hooks.slack.com/…'  # nosec B101
    assert 'SECRETPART' not in (await client.get(f'/api/v1/webhooks/{hook.id}')).text  # nosec B101
    await login(client, 'root')
    assert (await client.get('/api/v1/webhooks')).json()[0]['url'].endswith('/SECRETPART')  # nosec B101


def test_chat_messages_cannot_be_turned_into_links_or_pings():
    event = {'event': 'finding.created', 'url': 'https://console.example.org/findings/1', 'finding': {
        'title': 'Threat seen: <https://evil.example|Reset your password>', 'severity': 'high',
        'summary': 'x' * 5000, 'entity': '@everyone [click](https://evil.example)', 'event_count': 3,
        'status': 'new', 'rule_name': 'r'}}
    slack = formats.render('slack', event)
    blocks = slack['attachments'][0]['blocks']
    # Everything Slack reads as mrkdwn is escaped; its plain_text header shows as it is
    mrkdwn = [slack['text'], blocks[1]['text']['text']] + [f['text'] for f in blocks[2]['fields']]
    assert not any('<https://evil' in t or '<' in t for t in mrkdwn)  # nosec B101
    assert '&lt;https://evil.example|Reset your password&gt;' in slack['text']  # nosec B101
    assert blocks[0]['text']['type'] == 'plain_text'  # nosec B101
    assert len(blocks[1]['text']['text']) <= 3000  # nosec B101
    assert all(len(f['text']) <= 2000 for f in blocks[2]['fields'])  # nosec B101
    discord = formats.render('discord', event)
    assert discord['allowed_mentions'] == {'parse': []}  # nosec B101
    assert '[click]' not in str(discord['embeds'][0]['fields'])  # nosec B101


def test_a_failing_rules_error_leaves_out_the_inside_of_the_network():
    text = public_error('Cannot reach https://10.0.0.5:9200/_search: timed out talking to 10.0.0.6:9300 '
                        'and [fd00::5]:9200')
    assert '10.0.0' not in text and 'fd00' not in text and '[url]' in text and '[address]' in text  # nosec B101
    assert len(public_error('e' * 2000)) <= 300  # nosec B101


# -- findings ----------------------------------------------------------------------------

async def test_reopening_a_finding_that_has_an_open_successor_is_refused(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    old = await _finding(status='resolved', dedup_key='same')
    await _finding(status='new', dedup_key='same')
    response = await client.patch(f'/api/v1/findings/{old.id}', headers=headers, json={'status': 'new'})
    assert response.status_code == 409 and 'already open' in response.json()['detail']  # nosec B101
    bulk = await client.post('/api/v1/findings/bulk', headers=headers,
                             json={'ids': [str(old.id)], 'status': 'acknowledged'})
    assert bulk.json() == {'updated': 0, 'skipped': [old.number]}  # nosec B101


async def test_a_rule_opening_a_successor_mid_reopen_is_a_conflict_not_an_error(client, monkeypatch):
    from tbconsole.api import findings as api_findings
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    old = await _finding(status='resolved', dedup_key='same')

    async def rule_runs_meanwhile(db, finding, changes):
        await _finding(status='new', dedup_key='same')
        # A query that flushes the reopening, before the commit
        await db.execute(select(Finding.id))
    monkeypatch.setattr(api_findings, '_announce', rule_runs_meanwhile)
    response = await client.patch(f'/api/v1/findings/{old.id}', headers=headers, json={'status': 'new'})
    assert response.status_code == 409  # nosec B101


async def test_bulk_changes_tell_the_webhooks_that_listen_for_them(client):
    await _hook('https://example.org/hook', events=['finding.status_changed'])
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    a, b = await _finding('ava'), await _finding('liam')
    response = await client.post('/api/v1/findings/bulk', headers=headers,
                                 json={'ids': [str(a.id), str(b.id)], 'status': 'resolved'})
    assert response.json()['updated'] == 2  # nosec B101
    async with db.sessionmaker()() as session:
        events = (await session.execute(select(WebhookDelivery.event))).scalars().all()
    assert events == ['finding.status_changed', 'finding.status_changed']  # nosec B101


async def test_finding_search_takes_wildcards_literally_and_survives_huge_numbers(client):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    await _finding('ava', title='Blocked 100% of lookups')
    await _finding('liam', title='Blocked 1000 lookups')
    found = (await client.get('/api/v1/findings', params={'q': '100%'})).json()
    assert [f['title'] for f in found['items']] == ['Blocked 100% of lookups']  # nosec B101
    assert (await client.get('/api/v1/findings', params={'q': '_'})).json()['total'] == 0  # nosec B101
    assert (await client.get('/api/v1/findings', params={'q': 'F-99999999999999'})).status_code == 200  # nosec B101
    assert (await client.get('/api/v1/findings', params={'since': '2026-10-01T00:00:00'})).status_code == 200  # nosec B101


async def test_an_events_only_key_sees_events_but_no_findings(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    await _finding('ava')
    profile = await client.get('/api/v1/entities/profile', params={'field': 'user', 'value': 'ava'})
    assert len(profile.json()['findings']) == 1  # nosec B101
    key = (await client.post('/api/v1/api-keys', headers=headers,
                             json={'name': 'events', 'scopes': ['events:read']})).json()['key']
    client.cookies.clear()
    auth = {'Authorization': f'Bearer {key}'}
    profile = (await client.get('/api/v1/entities/profile', headers=auth,
                                params={'field': 'user', 'value': 'ava'})).json()
    assert profile['findings'] == [] and profile['risk']['score'] == 0  # nosec B101
    overview = (await client.get('/api/v1/overview', headers=auth)).json()
    assert overview['findings']['latest'] == [] and sum(overview['findings']['open'].values()) == 0  # nosec B101
    domain = (await client.get('/api/v1/domains/evil.example', headers=auth)).json()
    assert domain['findings'] == []  # nosec B101
    assert (await client.get('/api/v1/findings', headers=auth)).status_code == 403  # nosec B101


async def test_a_domain_page_needs_a_domain(client):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    for bad in ('%25', 'a b', 'x' * 300):
        assert (await client.get(f'/api/v1/domains/{bad}')).status_code == 400, bad  # nosec B101


async def test_comments_and_saved_searches_are_audited(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    finding = await _finding('ava')
    await client.post(f'/api/v1/findings/{finding.id}/comments', headers=headers, json={'body': 'Called the family'})
    saved = (await client.post('/api/v1/saved-searches', headers=headers,
                               json={'name': 'Ava', 'query': 'user:ava', 'shared': True})).json()
    await client.delete(f"/api/v1/saved-searches/{saved['id']}", headers=headers)
    assert len(await _audit('finding.comment')) == 1  # nosec B101
    saves = await _audit('search.save')
    assert saves[0].details == {'query': 'user:ava', 'shared': True}  # nosec B101
    assert len(await _audit('search.delete')) == 1  # nosec B101


# -- searches and rules ------------------------------------------------------------------------

async def test_runaway_queries_and_ranges_are_refused_in_words(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    for body in ({'query': '(' * 300 + 'risk:threat' + ')' * 300},
                 {'query': 'NOT ' * 300 + 'risk:threat'},
                 {'from': 'now-99999999999d'},
                 {'from': 'now-9999999d'}):
        response = await client.post('/api/v1/events/search', headers=headers, json=body)
        assert response.status_code == 400, body  # nosec B101
    pivot = await client.post('/api/v1/analytics/pivot', headers=headers,
                              json={'from': 'now-30d', 'over_time': True, 'interval': '1m'})
    assert pivot.status_code == 400 and 'too many buckets' in pivot.json()['detail']  # nosec B101


async def test_autocomplete_matches_either_case_and_lucene_specials_literally(client, search):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    await client.get('/api/v1/fields/rcode/values', params={'prefix': 'nx@~'})
    include = search.bodies[-1]['aggs']['v']['terms']['include']
    assert include == '[nN][xX]\\@\\~.*'  # nosec B101


async def test_backtests_and_titles_are_for_rule_authors(client):
    await make_user('vic', role='viewer')
    await make_user('ana', role='analyst')
    rule = {'name': 'r', 'type': 'threshold', 'query': 'risk:threat', 'params': {'threshold': 1}}
    headers = await login(client, 'vic')
    assert (await client.post('/api/v1/rules/backtest', headers=headers, json=rule)).status_code == 403  # nosec B101
    headers = await login(client, 'ana')
    assert (await client.post('/api/v1/rules/backtest', headers=headers, json=rule)).status_code == 200  # nosec B101
    bad = await client.post('/api/v1/rules', headers=headers, json={**rule, 'title_template': '{count:>999999999}'})
    assert bad.status_code == 400 and 'not something a title can show' in bad.json()['detail']  # nosec B101
    naive = await client.post('/api/v1/rules', headers=headers, json={
        **rule, 'exceptions': [{'query': 'host:lab-1', 'expires_at': '2027-01-01T00:00:00'}]})
    assert naive.status_code == 201  # nosec B101
    assert naive.json()['exceptions'][0]['expires_at'].endswith('Z')  # nosec B101


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
    assert window == {'gte': '2026-10-05T11:44:00.000Z', 'lt': '2026-10-05T11:59:00.000Z'}  # nosec B101


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
        assert stored.next_run_at - datetime.now(timezone.utc) < timedelta(minutes=6)  # nosec B101


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
        assert await engine.claim_run(holder, rule_id) is not None  # nosec B101
    busy = await client.post(f'/api/v1/rules/{rule_id}/run', headers=headers)
    assert busy.status_code == 409  # nosec B101
    async with db.sessionmaker()() as holder:
        (await holder.get(Rule, rule_id)).running_until = None
        await holder.commit()
    assert (await client.post(f'/api/v1/rules/{rule_id}/run', headers=headers)).status_code == 200  # nosec B101
    async with db.sessionmaker()() as session:
        assert (await session.get(Rule, rule_id)).running_until is None, 'the lease is given back'  # nosec B101


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
    assert removed == {'sessions': 2, 'deliveries': 2, 'findings': 1, 'audit': 1}  # nosec B101
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(func.count()).select_from(FindingActivity))).scalar_one() == 0  # nosec B101
        assert (await session.execute(select(func.count()).select_from(Finding))).scalar_one() == 2  # nosec B101


# -- configuration and serving ------------------------------------------------------------------

def test_a_database_password_with_url_characters_needs_no_escaping():
    from tbconsole.config import Settings
    settings = Settings(secret_key='k' * 40, database_url='postgresql+asyncpg://tbconsole@db:5432/tbconsole',
                        database_password='p@ss/w:rd', opensearch_ca_certs='', static_dir='')  # nosec B106
    from sqlalchemy.engine import make_url
    assert make_url(settings.database_url).password == 'p@ss/w:rd'  # nosec B101, B105
    assert settings.opensearch_ca_certs is None and settings.static_dir is None  # nosec B101


async def test_the_app_answers_head_requests_for_its_pages(tmp_path, monkeypatch):
    from tbconsole.config import get_settings
    from tbconsole.main import create_app
    (tmp_path / 'index.html').write_text('<!doctype html><title>console</title>')
    monkeypatch.setattr(get_settings(), 'static_dir', tmp_path)
    app = create_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as c:
        assert (await c.head('/findings')).status_code == 200  # nosec B101
        assert (await c.get('/findings')).text.startswith('<!doctype html>')  # nosec B101
        assert (await c.get('/api/v1/nothing-here')).status_code == 404  # nosec B101


async def test_a_page_opened_from_another_site_says_so_to_the_app(tmp_path, monkeypatch):
    from tbconsole.config import get_settings
    from tbconsole.main import create_app
    (tmp_path / 'index.html').write_text('<!doctype html><html><head><title>console</title></head></html>')
    monkeypatch.setattr(get_settings(), 'static_dir', tmp_path)
    app = create_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as c:
        linked = await c.get('/entities/user/ava', headers={'Sec-Fetch-Site': 'cross-site'})
        typed = await c.get('/entities/user/ava', headers={'Sec-Fetch-Site': 'none'})
    assert 'name="tbc-arrival"' in linked.text and linked.headers['cache-control'] == 'no-store'  # nosec B101
    assert 'tbc-arrival' not in typed.text  # nosec B101


async def test_swagger_ui_and_its_cdn_are_off_unless_asked_for(monkeypatch):
    from tbconsole.config import get_settings
    from tbconsole.main import create_app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url='http://testserver') as c:
        assert (await c.get('/api/docs')).status_code == 404  # nosec B101
        assert (await c.get('/api/openapi.json')).status_code == 200  # nosec B101
    monkeypatch.setattr(get_settings(), 'api_docs', True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url='http://testserver') as c:
        docs = await c.get('/api/docs')
    assert docs.status_code == 200 and 'cdn.jsdelivr.net' in docs.headers['content-security-policy']  # nosec B101


def test_today_starts_at_the_callers_midnight():
    from tbconsole.search import timerange
    now = datetime(2026, 10, 5, 2, 30, tzinfo=timezone.utc)  # 22:30 on the 4th in New York
    token = timerange._zone.set('UTC')
    try:
        assert timerange.parse_range('now/d', 'now', now=now).start == datetime(2026, 10, 5, tzinfo=timezone.utc)  # nosec B101
        timerange.use_zone('America/New_York')
        assert timerange.parse_range('now/d', 'now', now=now).start == datetime(2026, 10, 4, 4, tzinfo=timezone.utc)  # nosec B101
        timerange.use_zone('Not/AZone')
        assert timerange.zone_name() == 'America/New_York'  # nosec B101
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
        assert (await c.get('/assets/app-1.js')).status_code == 200  # nosec B101
        assert (await c.get('/assets/app-0.js')).status_code == 404  # nosec B101


# -- round two -------------------------------------------------------------------------

async def _client_from(app, host: str):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(host, 1234)),
                             base_url='http://testserver')


async def test_an_address_that_is_not_one_is_not_stored_and_cannot_dodge_the_lockout(app):
    await make_user('root', role='admin')
    forged = 'x' * 100
    async with await _client_from(app, forged) as c:
        for _ in range(5):
            response = await c.post('/api/v1/auth/login', json={'username': 'root', 'password': 'nope'})  # nosec B105
            assert response.status_code == 401  # nosec B101
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'root'))).scalar_one()
        assert user.locked_until is not None, 'the failures counted'  # nosec B101
        ips = (await session.execute(select(AuditEvent.ip).where(AuditEvent.action == 'auth.login'))).scalars().all()
    assert len(ips) == 5 and set(ips) == {None}  # nosec B101


def test_the_brake_lets_others_at_a_busy_address_through_and_counts_ipv6_by_network():
    from tbconsole.security import limits
    limits.reset()
    for i in range(limits.ADDRESS_LIMIT):
        limits.failed('203.0.113.7', f'guess-{i}')
    assert limits.limited('203.0.113.7', 'guess-1'), 'a name it got wrong is held back'  # nosec B101
    assert not limits.limited('203.0.113.7', 'alice'), 'a name it has not tried is not'  # nosec B101
    for _ in range(limits.PAIR_LIMIT):
        limits.failed('2001:db8::1', 'root')
    assert limits.limited('2001:db8:0:ff::1', 'root'), 'the same /56'  # nosec B101
    assert not limits.limited('2001:db8:0:100::1', 'root')  # nosec B101
    limits.reset()


async def test_one_two_factor_token_makes_one_session(client):
    secret = pyotp.random_base32()
    await make_user('root', role='admin', totp_enabled=True, totp_secret_enc=crypto.encrypt(secret))
    token = (await client.post('/api/v1/auth/login', json={'username': 'root',
                                                          'password': 'correct horse battery'})).json()['token']  # nosec B105
    totp = pyotp.TOTP(secret)
    assert (await client.post('/api/v1/auth/mfa', json={'token': token, 'code': totp.now()})).status_code == 200  # nosec B101
    again = totp.at(datetime.now(timezone.utc) + timedelta(seconds=30))
    assert (await client.post('/api/v1/auth/mfa', json={'token': token, 'code': again})).status_code == 401  # nosec B101


async def test_a_borrowed_session_cannot_guess_the_password(client):
    await make_user('ana')
    headers = await login(client, 'ana')
    from tbconsole.config import get_settings
    for _ in range(get_settings().login_max_failures):
        assert (await client.post('/api/v1/account/mfa/setup', headers=headers,  # nosec B101
                                  json={'password': 'guess'})).status_code == 400  # nosec B105
    # Locked: refused whatever the password, the right one too
    assert (await client.post('/api/v1/account/mfa/setup', headers=headers,  # nosec B101
                              json={'password': 'correct horse battery'})).status_code == 429  # nosec B105


async def test_changing_your_password_ends_every_other_session_and_keeps_yours(client, app):
    await make_user('ana')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as other:
        await login(other, 'ana')
        headers = await login(client, 'ana')
        response = await client.post('/api/v1/account/password', headers=headers,
                                     json={'current': 'correct horse battery', 'new': 'A-much-better-passphrase-26'})
        assert response.status_code == 200  # nosec B101
        assert (await client.get('/api/v1/auth/me')).status_code == 200  # nosec B101
        assert (await other.get('/api/v1/auth/me')).status_code == 401  # nosec B101
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(User.password_changed_at))).scalar_one() is not None  # nosec B101


async def test_a_link_on_another_site_cannot_act_with_the_cookie(client):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    response = await client.get('/api/v1/entities/profile', params={'field': 'user', 'value': 'ava'},
                                headers={'Sec-Fetch-Site': 'cross-site'})
    assert response.status_code == 403  # nosec B101
    assert (await client.get('/api/v1/auth/me', headers={'Sec-Fetch-Site': 'same-origin'})).status_code == 200  # nosec B101
    assert await _audit('entity.view') == []  # nosec B101


async def test_the_default_port_written_out_is_the_same_origin(client, monkeypatch):
    from tbconsole.config import get_settings
    monkeypatch.setattr(get_settings(), 'public_url', 'http://testserver:80')
    await make_user('ana')
    response = await client.post('/api/v1/auth/login', headers={'Origin': 'http://testserver'},
                                 json={'username': 'ana', 'password': 'correct horse battery'})  # nosec B105
    assert response.status_code == 200  # nosec B101


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
        assert stored.disabled  # nosec B101
        assert (await session.execute(select(ApiKey.revoked_at))).scalar_one() is not None  # nosec B101


async def test_reencrypt_moves_every_secret_to_the_current_key(monkeypatch, capsys):
    from tbconsole import __main__ as cli
    from tbconsole.config import get_settings
    settings = get_settings()
    old = settings.secret_key
    await make_user('root', totp_enabled=True, totp_secret_enc=crypto.encrypt('TOTPSECRET'))
    hook = await _hook('https://example.org/hook')
    monkeypatch.setattr(settings, 'secret_key', 'a-brand-new-secret-key-that-is-long-enough-01')
    monkeypatch.setattr(settings, 'secret_key_previous', [old])
    if hasattr(crypto._fernet, 'cache_clear'):
        crypto._fernet.cache_clear()
    assert await cli.reencrypt(argparse.Namespace()) == 0  # nosec B101
    monkeypatch.setattr(settings, 'secret_key_previous', [])
    if hasattr(crypto._fernet, 'cache_clear'):
        crypto._fernet.cache_clear()
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User))).scalar_one()
        assert crypto.decrypt(user.totp_secret_enc) == 'TOTPSECRET'  # nosec B101
        stored = await session.get(Webhook, hook.id)
        assert crypto.decrypt(stored.url_enc) == 'https://example.org/hook'  # nosec B101


async def test_an_admin_can_disable_someone_the_directory_already_had(client):
    await make_user('root', role='admin')
    ava = await make_user('ava', source='ldap', role='analyst', disabled=True, disabled_reason='directory')
    headers = await login(client, 'root')
    response = await client.patch(f'/api/v1/users/{ava.id}', headers=headers, json={'disabled': True})
    assert response.status_code == 200  # nosec B101
    async with db.sessionmaker()() as session:
        assert (await session.get(User, ava.id)).disabled_reason == 'admin'  # nosec B101


async def test_signing_in_with_another_name_for_the_same_person_finds_their_account(client, directory):
    # The console keeps the uid; this person signs in with their email address
    await _save_directory(dict(directory, user_filter='(&(objectClass=person)(|(uid={username})(mail={username})))'))
    first = await client.post('/api/v1/auth/login', json={'username': 'ava@example.org', 'password': 'ava-pw'})  # nosec B105
    second = await client.post('/api/v1/auth/login', json={'username': 'ava@example.org', 'password': 'ava-pw'})  # nosec B105
    assert first.status_code == 200 and second.status_code == 200  # nosec B101
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(func.count()).select_from(User))).scalar_one() == 1  # nosec B101


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
    assert counts['held_back'] == 5 and counts['revoked'] == 0  # nosec B101
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(func.count()).select_from(User).where(User.disabled))).scalar_one() == 0  # nosec B101


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
    assert counts['held_back'] == 0 and counts['revoked'] == 1  # nosec B101
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(User.disabled).where(User.username == 'bob'))).scalar_one()  # nosec B101
        assert not (await session.execute(select(User.disabled).where(User.username == 'ava'))).scalar_one()  # nosec B101


async def test_a_header_with_space_at_an_end_is_refused_when_saved(client, monkeypatch):
    monkeypatch.setattr(safety, 'check', lambda url: _noop())
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    for value in ('Bearer TOKEN ', ' Bearer TOKEN', 'a\x7fb'):
        response = await client.post('/api/v1/webhooks', headers=headers, json={
            'name': 'x', 'url': 'https://example.org/', 'headers': {'Authorization': value}})
        assert response.status_code == 400, repr(value)  # nosec B101
    for name in ('Transfer-Encoding', 'Connection', 'TE'):
        response = await client.post('/api/v1/webhooks', headers=headers, json={
            'name': 'x', 'url': 'https://example.org/', 'headers': {name: 'x'}})
        assert response.status_code == 400, name  # nosec B101


async def _noop():
    return None


async def test_a_request_that_cannot_be_written_records_no_header_text(monkeypatch):
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14'))
    hook = await _hook('https://hooks.example.test/in')

    def handler(request):
        raise httpx.LocalProtocolError('Illegal header value b"Bearer SECRET-TOKEN "')
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert 'SECRET' not in outcome['error'] and outcome['retry'] is False  # nosec B101


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
    assert 'too long' in outcome['error'] and outcome['retry'] is True  # nosec B101
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b'x' * 5_000_000))) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert outcome['error'] is None and len(outcome['snippet']) <= 300  # nosec B101


async def test_deliveries_ignore_proxy_settings_in_the_environment_and_use_a_configured_one(monkeypatch):
    from tbconsole.config import get_settings
    assert dispatcher.client()._trust_env is False  # nosec B101
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14'))
    monkeypatch.setattr(get_settings(), 'webhook_proxy', 'http://proxy.example.test:3128')
    hook = await _hook('https://hooks.example.test/in')
    seen = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200))) as http:
        await dispatcher.send(hook, _delivery(hook), http)
    # Through a proxy the name goes as it is; the proxy connects
    assert seen[0].url.host == 'hooks.example.test'  # nosec B101


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
    assert seen == ['93.184.215.14', '93.184.215.15'] and outcome['error'] is None  # nosec B101


async def test_a_second_address_is_tried_when_the_first_does_not_answer_in_time(monkeypatch):
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14', '93.184.215.15'))
    hook = await _hook('https://hooks.example.test/in')
    seen = []

    def handler(request):
        seen.append((request.url.host, request.extensions['timeout']['connect']))
        if request.url.host == '93.184.215.14':
            raise httpx.ConnectTimeout('timed out')
        return httpx.Response(204)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert [host for host, _ in seen] == ['93.184.215.14', '93.184.215.15'] and outcome['error'] is None  # nosec B101
    # Each has its share of the time, so the second is not left none
    assert seen[0][1] == 5.0  # nosec B101


async def test_a_name_that_takes_forever_to_look_up_is_cut_off_too(monkeypatch):
    import asyncio as aio
    from tbconsole.config import get_settings

    class Hangs(_Loop):
        async def getaddrinfo(self, host, port, **_options):
            await aio.sleep(5)
    lookup = _Asyncio()
    lookup.loop = Hangs()
    monkeypatch.setattr(safety, 'asyncio', lookup)
    monkeypatch.setattr(dispatcher, 'DEADLINE_SLACK', 0)
    monkeypatch.setattr(get_settings(), 'webhook_timeout_sec', 0.2)
    hook = await _hook('https://hooks.example.test/in')
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(204))) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert 'too long' in outcome['error'] and outcome['retry'] is True and outcome['duration_ms'] < 2000  # nosec B101


async def test_a_compressed_answer_is_not_unpacked(monkeypatch):
    import gzip
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14'))
    hook = await _hook('https://hooks.example.test/in')
    seen = []

    def handler(request):
        seen.append(request.headers['accept-encoding'])
        return httpx.Response(200, headers={'Content-Encoding': 'gzip'}, content=gzip.compress(b'0' * 10_000_000))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert seen == ['identity']  # nosec B101
    assert outcome['error'] is None and outcome['snippet'] == '(an answer compressed as gzip, not shown)'  # nosec B101


def test_a_webhook_proxy_or_ca_file_that_cannot_work_stops_the_console_starting(tmp_path):
    from pydantic import ValidationError
    from tbconsole.config import Settings
    for proxy in ('socks5://proxy.example.test:1080', 'proxy.example.test:3128', 'http://'):
        with pytest.raises(ValidationError, match='WEBHOOK_PROXY'):
            Settings(webhook_proxy=proxy)
    assert Settings(webhook_proxy=' ').webhook_proxy is None  # nosec B101
    with pytest.raises(ValidationError, match='not a file'):
        Settings(webhook_ca_certs=str(tmp_path / 'missing.pem'))
    (tmp_path / 'notes.pem').write_text('these are not certificates')
    with pytest.raises(ValidationError, match='no PEM'):
        Settings(webhook_ca_certs=str(tmp_path / 'notes.pem'))
    assert Settings(webhook_ca_certs='').webhook_ca_certs is None  # nosec B101


def test_webhook_receivers_may_be_signed_by_an_internal_ca(monkeypatch):
    import ssl
    import certifi
    from tbconsole.config import get_settings
    assert dispatcher._trust() is True  # nosec B101
    monkeypatch.setattr(get_settings(), 'webhook_ca_certs', certifi.where())
    assert isinstance(dispatcher._trust(), ssl.SSLContext)  # nosec B101


async def test_a_test_delivery_is_recorded_as_unfinished_until_it_finishes(client, monkeypatch):
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14'))
    hook = await _hook('https://hooks.example.test/in')
    during = []

    async def send(hook, delivery, http=None):
        async with db.sessionmaker()() as session:
            stored = await session.get(WebhookDelivery, delivery.id)
            during.append((stored.status, stored.next_attempt_at, stored.last_error))
        return {'status_code': 204, 'error': None, 'snippet': '', 'retry': False, 'duration_ms': 1}
    monkeypatch.setattr(dispatcher, 'send', send)
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    tested = await client.post(f'/api/v1/webhooks/{hook.id}/test', headers=headers)
    assert during == [('dead', None, 'the test did not finish')]  # nosec B101
    assert tested.json()['status'] == 'succeeded' and tested.json()['last_error'] is None  # nosec B101


async def test_a_redelivery_names_no_one_to_a_key_that_may_not_read_findings(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    hook = await _hook('https://example.org/hook')
    async with db.sessionmaker()() as session:
        delivery = WebhookDelivery(webhook_id=hook.id, event='finding.created', status='dead', payload={
            'event': 'finding.created', 'finding': {'title': 'Threat seen: ava', 'entity': 'ava',
                                                    'entity_field': 'bite.client_user'}})
        session.add(delivery)
        await session.commit()
    key = (await client.post('/api/v1/api-keys', headers=headers,
                             json={'name': 'k', 'scopes': ['webhooks:read', 'webhooks:write']})).json()['key']
    client.cookies.clear()
    again = await client.post(f'/api/v1/webhook-deliveries/{delivery.id}/redeliver',
                              headers={'Authorization': f'Bearer {key}'})
    assert again.status_code == 200 and 'ava' not in again.text  # nosec B101


def test_a_delivery_about_a_domain_names_no_one():
    from tbconsole.api.common import delivery_out
    about_domain = WebhookDelivery(id=uuid.uuid4(), webhook_id=uuid.uuid4(), event='finding.created', payload={
        'finding': {'entity': 'evil.example', 'entity_field': 'bite.registrable_domain'}})
    about_person = WebhookDelivery(id=uuid.uuid4(), webhook_id=uuid.uuid4(), event='finding.created', payload={
        'finding': {'entity': 'ava', 'entity_field': 'bite.client_user'}})
    redacted = WebhookDelivery(id=uuid.uuid4(), webhook_id=uuid.uuid4(), event='finding.created', payload={
        'finding': {'entity': '[redacted]', 'entity_field': 'bite.client_user'}})
    assert delivery_out(about_domain)['names'] == []  # nosec B101
    assert delivery_out(about_person)['names'] == ['ava']  # nosec B101
    assert delivery_out(redacted)['names'] == []  # nosec B101


async def test_an_ipv6_host_header_is_bracketed():
    target = await safety.resolve('https://[2606:4700::1111]:8443/x')
    assert target.host_header == '[2606:4700::1111]:8443'  # nosec B101
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
    assert listed.status_code == 200 and 'ava' not in listed.text  # nosec B101
    one = await client.get(f"/api/v1/webhook-deliveries/{listed.json()[0]['id']}", headers=auth)
    assert one.status_code == 200 and 'ava' not in one.text  # nosec B101


def test_google_chat_and_teams_cannot_be_made_to_mention_or_link():
    from tbconsole.webhooks import signing
    event = {'event': 'finding.created', 'finding': {
        'title': 'Seen: <users/all>', 'summary': '[click](https://evil.example) <https://evil|x>', 'severity': 'high',
        'entity': 'ava', 'status': 'new', 'rule_name': 'r', 'event_count': 1}}
    chat = formats.render('google_chat', event)
    readable = [chat['text']] + [str(w) for w in chat['cardsV2'][0]['card']['sections'][0]['widgets']]
    assert not any('<users/all>' in t or '<https://evil' in t for t in readable)  # nosec B101
    teams = formats.render('teams', event)
    assert '[click](' not in str(teams)  # nosec B101
    assert signing.verify('s', b'x', None) is False and signing.verify('s', b'x', 't=1,v1=é') is False  # nosec B101


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
    assert await _still_allowed(request()) is True  # nosec B101
    await client.post('/api/v1/auth/logout', headers={'X-CSRF-Token': client.cookies.get('tbc_csrf')})
    assert await _still_allowed(request()) is False  # nosec B101


async def test_the_live_tail_cap_holds(client, monkeypatch):
    from tbconsole.api import events
    user = await make_user('ana', role='analyst')
    await login(client, 'ana')
    monkeypatch.setitem(events._live, str(user.id), {i: None for i in range(events.MAX_LIVE_PER_USER)})
    assert (await client.get('/api/v1/events/live')).status_code == 429  # nosec B101


def test_live_tails_asked_for_at_once_cannot_get_past_the_cap(monkeypatch):
    from tbconsole.api import events
    monkeypatch.setattr(events, '_live', {})
    taken = [events._take_slot('ana') for _ in range(events.MAX_LIVE_PER_USER + 1)]
    # Each is counted when asked for, before any stream has started
    assert None not in taken[:-1] and taken[-1] is None  # nosec B101
    events._free_slot('ana', taken[0])
    assert events._take_slot('ana') is not None  # nosec B101
    # A slot whose stream never started lapses
    monkeypatch.setattr(events, 'LIVE_START_GRACE', -1)
    assert events._take_slot('ana') is not None  # nosec B101


async def test_looks_at_people_through_pivots_histograms_lists_and_suggestions_are_audited(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    await client.post('/api/v1/analytics/pivot', headers=headers, json={'rows': 'user'})
    await client.post('/api/v1/events/search', headers=headers, json={'query': 'user:ava'})
    await client.post('/api/v1/events/histogram', headers=headers, json={'query': 'user:ava'})
    await client.get('/api/v1/entities', params={'query': 'user:ava'})
    await client.get('/api/v1/fields/user/values', params={'prefix': 'a'})
    await client.get('/api/v1/fields/user/values', params={'prefix': 'av'})
    assert len(await _audit('analytics.pivot')) == 1  # nosec B101
    assert len(await _audit('events.search')) == 1, 'the histogram of the same search is the same look'  # nosec B101
    assert len(await _audit('entities.list')) == 1  # nosec B101
    assert len(await _audit('events.top')) == 1, 'suggestions are one look, not one per keystroke'  # nosec B101


async def test_the_people_list_and_the_overview_are_looks_at_people_but_a_refresh_is_not_another(client):
    await make_user('ana', role='analyst')
    await login(client, 'ana')
    for _ in range(2):
        await client.get('/api/v1/entities')
        await client.get('/api/v1/overview')
    assert len(await _audit('entities.list')) == 1  # nosec B101
    assert len(await _audit('analytics.overview')) == 1  # nosec B101


async def test_times_out_of_range_and_bodies_that_are_not_json_are_400s_not_500s(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    for body in ({'from': '9999-12-31T23:59:59-01:00'}, {'from': '0001-01-01T00:00:00+01:00'}):
        assert (await client.post('/api/v1/events/search', headers=headers, json=body)).status_code == 400  # nosec B101
    assert (await client.get('/api/v1/findings', params={'since': '9999-12-31T23:59:59-01:00'})).status_code == 400  # nosec B101
    raw = await client.post('/api/v1/events/search', headers={**headers, 'Content-Type': 'application/json'},
                            content=b'\xff\xfenot json')
    assert raw.status_code == 422  # nosec B101


async def test_the_probes_answer_head_and_readiness_fails_without_the_database(client, monkeypatch):
    assert (await client.head('/healthz')).status_code == 200  # nosec B101
    assert (await client.head('/readyz')).status_code == 200  # nosec B101

    def broken():
        raise ConnectionRefusedError('no database')
    monkeypatch.setattr(db, 'sessionmaker', broken)
    assert (await client.get('/readyz')).status_code == 503  # nosec B101


async def test_readiness_answers_in_time_when_the_database_hangs(client, monkeypatch):
    import asyncio as aio
    from tbconsole import main

    class Hangs:
        async def __aenter__(self):
            await aio.sleep(30)

        async def __aexit__(self, *exc):
            return False
    monkeypatch.setattr(main, 'READY_TIMEOUT', 0.1)
    monkeypatch.setattr(db, 'sessionmaker', lambda: Hangs)
    assert (await client.get('/readyz')).status_code == 503  # nosec B101


async def test_pruning_failing_does_not_stop_the_directory_recheck(monkeypatch):
    from tbconsole import maintenance as M
    rechecked = []

    async def broken(session, now=None):
        raise OverflowError('date value out of range')

    async def recheck(now=None):
        rechecked.append(now)
        return {'revoked': 0, 'changed': 0, 'restored': 0, 'held_back': 0}
    monkeypatch.setattr(M, 'prune', broken)
    monkeypatch.setattr(M, 'recheck_directory', recheck)
    with pytest.raises(M.MaintenanceProblem, match='pruning failed'):
        await M.Maintenance().run_once()
    assert len(rechecked) == 1  # nosec B101


def test_retention_cannot_reach_past_what_a_date_can_hold():
    from pydantic import ValidationError
    from tbconsole.config import Settings
    for name in ('finding_retention_days', 'audit_retention_days', 'delivery_retention_days'):
        with pytest.raises(ValidationError):
            Settings(**{name: 1_000_000})


def test_a_database_password_needs_a_user_name_to_go_with():
    from pydantic import ValidationError

    from tbconsole.config import Settings
    with pytest.raises(ValidationError, match='user name'):
        Settings(secret_key='k' * 40, database_url='postgresql+asyncpg://db:5432/tbconsole',
                 database_password='secret')  # nosec B106


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
    assert isinstance(seen['receive_timeout'], int)  # nosec B101


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
        assert principal is not None and principal.user.username == 'ana'  # nosec B101
        assert not session.in_transaction()  # nosec B101


async def test_a_first_seen_person_is_named_redacted_and_listed_for_masking(client):
    from tbconsole.webhooks.service import finding_body
    finding = await _finding('lab-12', title='First seen person (k.larsen)', entity_field='bite.client_hostname_short',
                             evidence={'detail': {'field': 'bite.client_user', 'new_value': 'k.larsen'}})
    body = finding_body(finding)
    assert body['new_value'] == {'field': 'bite.client_user', 'value': 'k.larsen', 'identity': True}  # nosec B101
    redacted = finding_body(finding, redact=True)
    assert 'k.larsen' not in str(redacted) and redacted['new_value']['value'] == '[redacted]'  # nosec B101
    hook = await _hook('https://example.org/hook')
    async with db.sessionmaker()() as session:
        session.add(WebhookDelivery(webhook_id=hook.id, event='finding.created', status='succeeded',
                                    payload={'event': 'finding.created', 'finding': body}))
        await session.commit()
    await make_user('root', role='admin')
    await login(client, 'root')
    listed = (await client.get('/api/v1/webhook-deliveries')).json()
    assert listed[0]['names'] == ['lab-12', 'k.larsen']  # nosec B101


# -- round three -----------------------------------------------------------------------

async def test_two_directory_people_with_one_name_never_share_an_account(client, directory, monkeypatch):
    # The console keeps uid; people sign in by mail. A staff member shares a
    # student's uid in another branch of the directory.
    from ldap3 import MOCK_SYNC, Connection

    from tbconsole.security import ldap
    seed = Connection(ldap._MOCK_SERVER, user='cn=svc,dc=example,dc=org', password='svc-pw',  # nosec B106
                      client_strategy=MOCK_SYNC)
    seed.strategy.add_entry('uid=ava,ou=staff,dc=example,dc=org', {
        'userPassword': 'staff-pw', 'objectClass': ['person', 'inetOrgPerson'], 'uid': 'ava', 'sn': 'Staff',
        'mail': 'ava.staff@example.org', 'memberOf': ['CN=IT,ou=groups,dc=example,dc=org']})
    await _save_directory(dict(directory, user_base_dn='dc=example,dc=org',
                               user_filter='(&(objectClass=person)(mail={username}))'))
    student = await client.post('/api/v1/auth/login', json={'username': 'ava@example.org', 'password': 'ava-pw'})  # nosec B105
    assert student.status_code == 200 and student.json()['user']['role'] == 'analyst'  # nosec B101
    async with httpx.AsyncClient(transport=client._transport, base_url='http://testserver') as other:
        staff = await other.post('/api/v1/auth/login', json={'username': 'ava.staff@example.org', 'password': 'staff-pw'})  # nosec B105
    assert staff.status_code == 409, 'refused, rather than handed the student\'s account'  # nosec B101
    assert (await client.get('/api/v1/users')).status_code == 403, 'the student did not become admin'  # nosec B101


def test_an_entrys_lasting_id_is_read_in_whichever_form_it_comes():

    from tbconsole.security import ldap
    value = uuid.uuid4()
    assert ldap._guid({'objectGUID': [value.bytes_le]}) == str(value)  # nosec B101
    assert ldap._guid({'entryUUID': [str(value).upper()]}) == str(value)  # nosec B101
    assert ldap._guid({'objectGUID': '{' + str(value) + '}'}) == str(value)  # nosec B101
    assert ldap._guid({}) is None  # nosec B101


async def test_one_unclear_entry_does_not_stop_the_others_being_revoked(client, directory, monkeypatch):
    from tbconsole import maintenance
    from tbconsole.security import ldap
    await _save_directory(directory)
    for name in ('ava', 'bob'):
        user = await make_user(name, source='ldap', role='analyst', ldap_dn=f'uid={name},ou=people,dc=example,dc=org')
        async with db.sessionmaker()() as session:
            session.add(UserSession(token_hash=crypto.sha256(name), user_id=user.id,
                                    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                                    last_seen_at=datetime.now(timezone.utc)))
            await session.commit()
    real = ldap.recheck

    def referral_for_ava(cfg, secret, dn, username):
        if username == 'ava':
            raise ldap.LdapUnavailable('referral')
        return real(cfg, secret, dn, username)
    monkeypatch.setattr(ldap, 'recheck', referral_for_ava)
    counts = await maintenance.recheck_directory()
    assert counts['unclear'] == 1 and counts['revoked'] == 1, 'bob, in no granting group, still goes'  # nosec B101


def test_a_recheck_folds_wildcards_around_the_name():
    import re
    assert re.sub(r'\**\{username\}\**', '*', '(uid=*{username}*)') == '(uid=*)'  # nosec B101


def test_a_flood_from_one_address_never_refuses_a_name_it_has_not_tried():
    from tbconsole.security import limits
    limits.reset()
    for i in range(5000):
        limits.failed('203.0.113.9', f'junk-{i}')
    assert not limits.limited('203.0.113.9', 'alice')  # nosec B101
    assert limits.limited('203.0.113.9', 'junk-7')  # nosec B101
    limits.reset()


def test_width_and_case_variants_of_a_name_are_one_name_to_the_brake():
    from tbconsole.security import limits
    limits.reset()
    for variant in ('bob', 'ＢＯＢ', 'Bob') * 4:
        limits.failed('203.0.113.10', variant)
    assert limits.limited('203.0.113.10', 'ｂｏｂ')  # nosec B101
    limits.failed('203.0.113.11', '')
    assert limits._recent(('203.0.113.11', '')) == 1, 'a blank name is not counted twice'  # nosec B101
    limits.reset()


async def test_a_hanging_directory_is_braked_and_holds_no_database_connection(client, directory, monkeypatch):
    from tbconsole.security import ldap, limits
    await _save_directory(directory)

    def down(*args):
        raise ldap.LdapUnavailable('no answer')
    monkeypatch.setattr(ldap, 'authenticate', down)
    monkeypatch.setattr(ldap, '_breaker', ldap._Breaker())
    for _ in range(limits.PAIR_LIMIT + 1):
        # The directory being away is not a wrong password: never counted
        # against the name, so its owner is not locked out by it
        assert (await client.post('/api/v1/auth/login', json={'username': 'ava', 'password': 'x'})).status_code == 503  # nosec B101, B105
    # After a few failures in a row the directory is given a rest: no thread is asked
    calls = []
    monkeypatch.setattr(ldap, 'authenticate', lambda *a: calls.append(a))
    assert (await client.post('/api/v1/auth/login', json={'username': 'zed', 'password': 'x'})).status_code == 503  # nosec B101, B105
    assert calls == []  # nosec B101
    assert len(await _audit('auth.login')) <= 2, 'one row for the outage, not one per attempt'  # nosec B101


async def test_one_address_flooding_sign_in_waits_on_itself_and_others_get_in(app, monkeypatch):
    import asyncio
    import time as clock
    from tbconsole.security import limits, passwords
    await make_user('ana')
    limits.reset()
    monkeypatch.setattr(limits, 'QUEUE', 4)
    real = passwords.verify_password

    def slow(stored, password):
        clock.sleep(0.15)
        return real(stored, password)
    monkeypatch.setattr(passwords, 'verify_password', slow)
    async with await _client_from(app, '198.51.100.7') as flooder, await _client_from(app, '198.51.100.8') as ana:
        flood = [flooder.post('/api/v1/auth/login', json={'username': f'junk-{i}', 'password': 'x'})  # nosec B105
                 for i in range(20)]
        started = clock.monotonic()
        answers, mine = await asyncio.gather(
            asyncio.gather(*flood),
            ana.post('/api/v1/auth/login', json={'username': 'ana', 'password': 'correct horse battery'}))  # nosec B105
    codes = sorted(a.status_code for a in answers)
    # Two at a time and four waiting from the flooding address; the rest turned away at once
    assert codes.count(401) == limits.IN_FLIGHT + 4 and codes.count(429) == 20 - limits.IN_FLIGHT - 4  # nosec B101
    assert mine.status_code == 200  # nosec B101
    assert clock.monotonic() - started < 3  # nosec B101
    assert limits._gates == {}, 'nothing is kept once the sign-ins are done'  # nosec B101
    limits.reset()


async def test_guesses_sent_together_from_several_addresses_still_lock_the_account(app, monkeypatch):
    import asyncio
    from tbconsole.config import get_settings
    from tbconsole.security import limits, passwords
    await make_user('ana')
    limits.reset()
    real, checked = passwords.verify_password, []

    def counting(stored, password):
        if stored is not None:
            checked.append(password)
        return real(stored, password)
    monkeypatch.setattr(passwords, 'verify_password', counting)
    clients = [await _client_from(app, f'198.51.100.{i}') for i in (21, 22, 23)]
    try:
        answers = await asyncio.gather(*[
            clients[i % 3].post('/api/v1/auth/login', json={'username': 'ana', 'password': f'guess-{i}'})
            for i in range(30)])
    finally:
        for c in clients:
            await c.aclose()
    # Checked one at a time: the lock the fifth set holds for the rest
    assert len(checked) == get_settings().login_max_failures  # nosec B101
    assert all(a.status_code in (401, 429) for a in answers)  # nosec B101
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(User.username == 'ana'))).scalar_one()
        assert user.locked_until is not None  # nosec B101
    limits.reset()


async def test_guesses_on_the_account_page_sent_together_lock_it_too(client, monkeypatch):
    import asyncio
    from tbconsole.config import get_settings
    from tbconsole.security import passwords
    await make_user('ana')
    headers = await login(client, 'ana')
    real, checked = passwords.verify_password, []

    def counting(stored, password):
        checked.append(password)
        return real(stored, password)
    monkeypatch.setattr(passwords, 'verify_password', counting)
    await asyncio.gather(*[client.post('/api/v1/account/mfa/setup', headers=headers, json={'password': f'g{i}'})
                           for i in range(15)])
    assert len(checked) == get_settings().login_max_failures  # nosec B101
    right = await client.post('/api/v1/account/mfa/setup', headers=headers, json={'password': 'correct horse battery'})  # nosec B105
    assert right.status_code == 429  # nosec B101


async def test_no_database_connection_is_held_while_a_password_is_checked(client, monkeypatch):
    from tbconsole.security import passwords
    await make_user('ana')
    await make_user('locked', locked_until=datetime.now(timezone.utc) + timedelta(minutes=5))
    real = passwords.verify_password
    held = []

    def watched(stored, password):
        held.append(db.engine().pool.checkedout())
        return real(stored, password)
    monkeypatch.setattr(passwords, 'verify_password', watched)
    for name, password in (('ana', 'correct horse battery'), ('ana', 'wrong'), ('nobody', 'x'), ('locked', 'x')):
        await client.post('/api/v1/auth/login', json={'username': name, 'password': password})
        client.cookies.clear()
    assert held == [0, 0, 0, 0]  # nosec B101


async def test_a_locked_account_page_answers_the_same_whatever_the_password(client):
    await make_user('ana')
    headers = await login(client, 'ana')
    for _ in range(5):
        await client.post('/api/v1/account/mfa/setup', headers=headers, json={'password': 'guess'})  # nosec B105
    wrong = await client.post('/api/v1/account/mfa/setup', headers=headers, json={'password': 'guess again'})  # nosec B105
    right = await client.post('/api/v1/account/mfa/setup', headers=headers, json={'password': 'correct horse battery'})  # nosec B105
    assert (wrong.status_code, wrong.json()) == (right.status_code, right.json()) and right.status_code == 429  # nosec B101


async def test_the_same_two_factor_token_sent_at_once_makes_one_session(client):
    import asyncio
    secret = pyotp.random_base32()
    await make_user('root', role='admin', totp_enabled=True, totp_secret_enc=crypto.encrypt(secret))
    token = (await client.post('/api/v1/auth/login', json={'username': 'root',
                                                          'password': 'correct horse battery'})).json()['token']  # nosec B105
    code = pyotp.TOTP(secret).now()
    answers = await asyncio.gather(*[client.post('/api/v1/auth/mfa', json={'token': token, 'code': code})
                                     for _ in range(5)])
    assert sorted(a.status_code for a in answers).count(200) == 1  # nosec B101
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(func.count()).select_from(UserSession))).scalar_one() == 1  # nosec B101


async def test_wrong_passwords_on_the_account_page_lock_the_account(client):
    await make_user('ana')
    headers = await login(client, 'ana')
    for _ in range(5):
        await client.post('/api/v1/account/mfa/setup', headers=headers, json={'password': 'guess'})  # nosec B105
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(User.locked_until))).scalar_one() is not None  # nosec B101



def test_groups_are_read_by_asking_each_mapped_group_not_by_listing_them_all():
    # Someone in a thousand groups, with a directory whose size limit would cut
    # the list: only the groups mapped to roles are asked about, one by one
    from tbconsole.security import ldap

    class Directory:
        def __init__(self, codes):
            self.codes, self.asked, self.result, self.response = codes, [], {}, []

        def search(self, base, search_filter, search_scope=None, attributes=None):
            self.asked.append((base, search_filter, search_scope))
            code = self.codes.get(base, 0)
            self.result = {'result': code, 'description': {0: 'success', 32: 'noSuchObject', 51: 'busy'}[code]}
            member = code == 0 and base.startswith('cn=it-security')
            self.response = [{'type': 'searchResEntry', 'dn': base}] if member else []
    cfg = {'group_filter': '(member={dn})', 'group_base_dn': 'ou=groups,dc=example,dc=org', 'attr_groups': '',
           'role_mappings': [{'group': 'cn=it-security,ou=groups,dc=example,dc=org', 'role': 'admin'},
                             {'group': 'cn=staff,ou=groups,dc=example,dc=org', 'role': 'viewer'},
                             {'group': 'cn=gone,ou=groups,dc=example,dc=org', 'role': 'analyst'},
                             {'group': 'cn=elsewhere,dc=other,dc=org', 'role': 'admin'}]}
    directory = Directory({'cn=gone,ou=groups,dc=example,dc=org': 32})
    groups = ldap._groups(directory, cfg, 'uid=max,ou=people,dc=example,dc=org', {})
    assert groups == ['cn=it-security,ou=groups,dc=example,dc=org']  # nosec B101
    assert [a[0] for a in directory.asked] == ['cn=it-security,ou=groups,dc=example,dc=org',  # nosec B101
                                               'cn=staff,ou=groups,dc=example,dc=org',
                                               'cn=gone,ou=groups,dc=example,dc=org']
    assert {a[1] for a in directory.asked} == {'(member=uid=max,ou=people,dc=example,dc=org)'}  # nosec B101
    # A directory too busy to say is not an answer
    with pytest.raises(ldap.LdapUnavailable, match='busy'):
        ldap._groups(Directory({'cn=staff,ou=groups,dc=example,dc=org': 51}), cfg,
                     'uid=max,ou=people,dc=example,dc=org', {})


async def test_through_a_proxy_a_name_only_the_proxy_can_resolve_is_sent_there(monkeypatch):
    from tbconsole.config import get_settings

    class NoDns(_Loop):
        async def getaddrinfo(self, host, port, **_options):
            raise socket.gaierror('no name servers here')
    lookup = _Asyncio()
    lookup.loop = NoDns()
    monkeypatch.setattr(safety, 'asyncio', lookup)
    hook = await _hook('https://hooks.example.test/in')
    with pytest.raises(safety.UnsafeUrl, match='does not resolve'):
        await safety.resolve('https://hooks.example.test/in')
    monkeypatch.setattr(get_settings(), 'webhook_proxy', 'http://proxy.example.test:3128')
    seen = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(204))) as http:
        outcome = await dispatcher.send(hook, _delivery(hook), http)
    assert outcome['error'] is None and seen[0].url.host == 'hooks.example.test'  # nosec B101
    # A name that does resolve here, to somewhere webhooks may not reach, is still refused
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('169.254.169.254'))
    with pytest.raises(safety.UnsafeUrl, match='may not reach'):
        await safety.resolve('https://hooks.example.test/in')



def test_ipv6_hosts_in_one_site_take_their_turns_together():
    from tbconsole.security import limits
    # A host rotating through its own /64s is still one site, for its turns as
    # for its failures
    assert limits.gate_source('2001:db8:0:1::5') == limits.gate_source('2001:db8:0:ff::9') == '2001:db8::/56'  # nosec B101
    assert limits.gate_source('2001:db8:0:100::5') != limits.gate_source('2001:db8::5')  # nosec B101
    assert limits.gate_source('203.0.113.9') == '203.0.113.9'  # nosec B101
    assert limits.source('2001:db8:0:ff::9') == '2001:db8::/56'  # nosec B101
    assert limits.gate_source(None) == 'unknown'  # nosec B101



async def test_a_few_addresses_flooding_the_directory_do_not_turn_others_away(app, directory, monkeypatch):
    import asyncio
    import time as clock
    from tbconsole.security import ldap, limits
    await _save_directory(directory)
    limits.reset()
    monkeypatch.setattr(ldap, '_breaker', ldap._Breaker())
    real = ldap.authenticate

    def slow(*args):
        # A directory a fifth of a second away
        clock.sleep(0.2)
        return real(*args)
    monkeypatch.setattr(ldap, 'authenticate', slow)
    flooders = [await _client_from(app, f'198.51.100.{30 + i}') for i in range(8)]
    async with await _client_from(app, '198.51.100.99') as ava:
        try:
            junk = [flooders[i % 8].post('/api/v1/auth/login', json={'username': f'junk-{i}', 'password': 'x'})  # nosec B105
                    for i in range(64)]
            mine = [ava.post('/api/v1/auth/login', json={'username': 'ava', 'password': 'ava-pw'}) for _ in range(3)]  # nosec B105
            answers = await asyncio.gather(*junk, *mine)
        finally:
            for c in flooders:
                await c.aclose()
    # Each address takes one turn at a time, so ava waits her turn, not a 503
    assert [a.status_code for a in answers[-3:]] == [200, 200, 200]  # nosec B101
    assert not any(a.status_code == 503 for a in answers)  # nosec B101
    limits.reset()



async def test_a_question_to_another_system_is_signed_and_its_answer_read(monkeypatch):
    from tbconsole.webhooks import signing
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('93.184.215.14'))
    hook = await _hook('https://sac.example.test/ingest/webhook/turkeybite/')
    hook.headers_enc = crypto.encrypt('{"X-Webhook-Token": "tok-123"}')
    seen = []

    def answers(request):
        seen.append(request)
        return httpx.Response(200, json={'inventories': [], 'link': '/x'})
    async with httpx.AsyncClient(transport=httpx.MockTransport(answers)) as http:
        answer = await dispatcher.ask(hook, 'https://sac.example.test/device-lookup/', 'device.lookup',
                                      {'id': 'q-1', 'address': '10.0.0.5'}, http)
    assert answer == {'inventories': [], 'link': '/x'}  # nosec B101
    request = seen[0]
    assert request.headers['x-webhook-token'] == 'tok-123'  # nosec B101
    assert request.headers['x-turkeybite-event'] == 'device.lookup'  # nosec B101
    stamp, mac = (dict(p.split('=', 1) for p in request.headers[signing.HEADER].split(','))[k] for k in ('t', 'v1'))
    assert signing.sign('s', request.content, int(stamp)).endswith(mac)  # nosec B101
    # Refused, not JSON, or too big: no answer, in words
    for response, words in ((httpx.Response(403, json={'error': 'Invalid TurkeyBite signature'}), 'HTTP 403: Invalid'),
                            (httpx.Response(200, text='<html>'), 'not JSON'),
                            (httpx.Response(200, content=b'{"a": "' + b'x' * (dispatcher.ASK_MAX_BYTES + 10) + b'"}'),
                             'too large')):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r, resp=response: resp)) as http:
            with pytest.raises(dispatcher.AskFailed, match=words):
                await dispatcher.ask(hook, 'https://sac.example.test/device-lookup/', 'device.lookup', {}, http)
    # A secret that can no longer be read, after the console's key changed
    unreadable = await _hook('https://sac.example.test/ingest/webhook/turkeybite/')
    unreadable.secret_enc = 'not-a-fernet-token'  # nosec B105
    with pytest.raises(dispatcher.AskFailed, match='cannot be read'):
        await dispatcher.ask(unreadable, 'https://sac.example.test/device-lookup/', 'device.lookup', {})
    # Somewhere webhooks may not go, it may not ask either
    monkeypatch.setattr(safety, 'asyncio', _Asyncio('169.254.169.254'))
    with pytest.raises(dispatcher.AskFailed, match='may not reach'):
        await dispatcher.ask(hook, 'https://sac.example.test/device-lookup/', 'device.lookup', {})
