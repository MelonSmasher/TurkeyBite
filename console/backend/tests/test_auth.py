"""Signing in: local accounts, lockout, a second factor, sessions, CSRF, and API keys."""

import time

import pyotp
from sqlalchemy import select

from tbconsole import db
from tbconsole.models import AuditEvent, User
from tbconsole.security import crypto

from .conftest import login, make_user


async def test_a_local_account_signs_in_and_out(client):
    await make_user()
    headers = await login(client)
    me = (await client.get('/api/v1/auth/me')).json()
    assert me['user']['username'] == 'alice' and 'rules:write' in me['permissions']
    assert (await client.post('/api/v1/auth/logout', headers=headers)).status_code == 200
    assert (await client.get('/api/v1/auth/me')).status_code == 401


async def test_wrong_passwords_and_missing_users_get_the_same_answer(client):
    await make_user()
    wrong = await client.post('/api/v1/auth/login', json={'username': 'alice', 'password': 'nope'})
    missing = await client.post('/api/v1/auth/login', json={'username': 'nobody', 'password': 'nope'})
    assert wrong.status_code == missing.status_code == 401
    assert wrong.json() == missing.json()


async def test_five_wrong_passwords_lock_the_account(client):
    await make_user()
    for _ in range(5):
        await client.post('/api/v1/auth/login', json={'username': 'alice', 'password': 'wrong one'})
    locked = await client.post('/api/v1/auth/login', json={'username': 'alice', 'password': 'correct horse battery'})
    assert locked.status_code == 401
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User))).scalar_one()
        assert user.locked_until is not None
        failures = (await session.execute(select(AuditEvent).where(AuditEvent.outcome == 'failure'))).scalars().all()
        assert len(failures) >= 5


async def test_a_service_account_cannot_sign_in(client):
    await make_user('svc-siem', source='service')
    response = await client.post('/api/v1/auth/login', json={'username': 'svc-siem', 'password': 'anything at all'})
    assert response.status_code == 401


async def test_a_second_factor_is_asked_for_and_a_code_cannot_be_reused(client):
    secret = pyotp.random_base32()
    await make_user(totp_secret_enc=crypto.encrypt(secret), totp_enabled=True)
    first = await client.post('/api/v1/auth/login', json={'username': 'alice', 'password': 'correct horse battery'})
    assert first.json()['mfa_required'] and 'tbc_session' not in first.cookies
    token = first.json()['token']
    code = pyotp.TOTP(secret).now()
    assert (await client.post('/api/v1/auth/mfa', json={'token': token, 'code': '000000'})).status_code == 401
    assert (await client.post('/api/v1/auth/mfa', json={'token': token, 'code': code})).status_code == 200
    client.cookies.clear()
    replay = await client.post('/api/v1/auth/mfa', json={'token': token, 'code': code})
    assert replay.status_code == 401


async def test_a_forged_mfa_token_is_refused(client):
    await make_user(totp_secret_enc=crypto.encrypt(pyotp.random_base32()), totp_enabled=True)
    response = await client.post('/api/v1/auth/mfa', json={'token': 'eyJ1Ijoi.forged', 'code': '123456'})
    assert response.status_code == 401


async def test_writes_need_the_csrf_header(client):
    await make_user()
    headers = await login(client)
    body = {'name': 'x', 'type': 'threshold', 'params': {'threshold': 1}}
    assert (await client.post('/api/v1/rules', json=body)).status_code == 403
    assert (await client.post('/api/v1/rules', json=body, headers={'X-CSRF-Token': 'guess'})).status_code == 403
    assert (await client.post('/api/v1/rules', json=body, headers=headers)).status_code == 201


async def test_a_cross_site_origin_is_refused_even_with_the_token(client):
    await make_user()
    headers = await login(client)
    response = await client.post('/api/v1/rules', json={'name': 'x', 'type': 'threshold'},
                                 headers={**headers, 'Origin': 'https://evil.example'})
    assert response.status_code == 403


async def test_changing_a_password_signs_out_other_sessions(app, client):
    import httpx
    await make_user()
    headers = await login(client)
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver')
    await login(other)
    response = await client.post('/api/v1/account/password', headers=headers,
                                 json={'current': 'correct horse battery', 'new': 'a much better passphrase'})
    assert response.status_code == 200
    assert (await other.get('/api/v1/auth/me')).status_code == 401
    assert (await client.get('/api/v1/auth/me')).status_code == 200
    await other.aclose()


async def test_an_api_key_acts_within_its_scopes_and_its_owners_role(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    created = await client.post('/api/v1/api-keys', headers=headers,
                                json={'name': 'reader', 'scopes': ['findings:read'], 'expires_days': 30})
    assert created.status_code == 201
    key = created.json()['key']
    client.cookies.clear()
    auth = {'Authorization': f'Bearer {key}'}
    assert (await client.get('/api/v1/findings', headers=auth)).status_code == 200
    # Outside the key's scopes, though the role would allow it
    assert (await client.get('/api/v1/rules', headers=auth)).status_code == 403
    # A key needs no CSRF token, since a browser never sends it on its own
    assert (await client.post('/api/v1/findings/bulk', headers=auth, json={'ids': ['x'], 'status': 'resolved'})).status_code == 403


async def test_nobody_mints_a_key_beyond_their_role(client):
    await make_user('vic', role='viewer')
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    response = await client.post('/api/v1/api-keys', headers=headers,
                                 json={'name': 'too much', 'scopes': ['users:admin']})
    assert response.status_code == 400


async def test_a_revoked_or_wrong_key_is_refused(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    created = (await client.post('/api/v1/api-keys', headers=headers,
                                 json={'name': 'k', 'scopes': ['findings:read']})).json()
    await client.delete(f"/api/v1/api-keys/{created['id']}", headers=headers)
    client.cookies.clear()
    assert (await client.get('/api/v1/findings', headers={'Authorization': f"Bearer {created['key']}"})).status_code == 401
    tampered = created['key'][:-4] + 'AAAA'
    assert (await client.get('/api/v1/findings', headers={'Authorization': f'Bearer {tampered}'})).status_code == 401


async def test_the_admin_mfa_policy_holds_back_everything_but_the_account(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    await client.put('/api/v1/settings/general', headers=headers, json={'org_name': 'Test',
                                                                       'require_mfa_for_local_admins': True})
    from tbconsole import settings_store
    settings_store.forget_cache()
    assert (await client.get('/api/v1/rules')).status_code == 403
    assert (await client.get('/api/v1/auth/me')).json()['mfa_required'] is True
    assert (await client.post('/api/v1/account/mfa/setup', headers=headers)).status_code == 200


async def test_sessions_expire_when_idle(client, monkeypatch):
    from tbconsole.config import get_settings
    await make_user()
    await login(client)
    monkeypatch.setattr(get_settings(), 'session_idle_minutes', 0)
    time.sleep(0.01)
    assert (await client.get('/api/v1/auth/me')).status_code == 401
