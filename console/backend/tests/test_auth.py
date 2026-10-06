"""Signing in: local accounts, lockout, a second factor, sessions, CSRF, and API keys."""

# Bandit's findings are marked nosec line by line: pytest checks with assert
# (B101), and the fixtures hold made-up passwords (B105, B106). None of this
# is code that ships.

import time
import uuid

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
    assert me['user']['username'] == 'alice' and 'rules:write' in me['permissions']  # nosec B101
    assert (await client.post('/api/v1/auth/logout', headers=headers)).status_code == 200  # nosec B101
    assert (await client.get('/api/v1/auth/me')).status_code == 401  # nosec B101


async def test_wrong_passwords_and_missing_users_get_the_same_answer(client):
    await make_user()
    wrong = await client.post('/api/v1/auth/login', json={'username': 'alice', 'password': 'nope'})  # nosec B105
    missing = await client.post('/api/v1/auth/login', json={'username': 'nobody', 'password': 'nope'})  # nosec B105
    assert wrong.status_code == missing.status_code == 401  # nosec B101
    assert wrong.json() == missing.json()  # nosec B101


async def test_five_wrong_passwords_lock_the_account(client):
    await make_user()
    for _ in range(5):
        await client.post('/api/v1/auth/login', json={'username': 'alice', 'password': 'wrong one'})  # nosec B105
    locked = await client.post('/api/v1/auth/login', json={'username': 'alice', 'password': 'correct horse battery'})  # nosec B105
    assert locked.status_code == 401  # nosec B101
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User))).scalar_one()
        assert user.locked_until is not None  # nosec B101
        failures = (await session.execute(select(AuditEvent).where(AuditEvent.outcome == 'failure'))).scalars().all()
        assert len(failures) >= 5  # nosec B101


async def test_a_service_account_cannot_sign_in(client):
    await make_user('svc-siem', source='service')
    response = await client.post('/api/v1/auth/login', json={'username': 'svc-siem', 'password': 'anything at all'})  # nosec B105
    assert response.status_code == 401  # nosec B101


async def test_a_second_factor_is_asked_for_and_a_code_cannot_be_reused(client):
    secret = pyotp.random_base32()
    await make_user(totp_secret_enc=crypto.encrypt(secret), totp_enabled=True)
    first = await client.post('/api/v1/auth/login', json={'username': 'alice', 'password': 'correct horse battery'})  # nosec B105
    assert first.json()['mfa_required'] and 'tbc_session' not in first.cookies  # nosec B101
    token = first.json()['token']
    code = pyotp.TOTP(secret).now()
    assert (await client.post('/api/v1/auth/mfa', json={'token': token, 'code': '000000'})).status_code == 401  # nosec B101
    assert (await client.post('/api/v1/auth/mfa', json={'token': token, 'code': code})).status_code == 200  # nosec B101
    client.cookies.clear()
    replay = await client.post('/api/v1/auth/mfa', json={'token': token, 'code': code})
    assert replay.status_code == 401  # nosec B101


async def test_a_forged_mfa_token_is_refused(client):
    await make_user(totp_secret_enc=crypto.encrypt(pyotp.random_base32()), totp_enabled=True)
    response = await client.post('/api/v1/auth/mfa', json={'token': 'eyJ1Ijoi.forged', 'code': '123456'})  # nosec B105
    assert response.status_code == 401  # nosec B101


async def test_writes_need_the_csrf_header(client):
    await make_user()
    headers = await login(client)
    body = {'name': 'x', 'type': 'threshold', 'params': {'threshold': 1}}
    assert (await client.post('/api/v1/rules', json=body)).status_code == 403  # nosec B101
    assert (await client.post('/api/v1/rules', json=body, headers={'X-CSRF-Token': 'guess'})).status_code == 403  # nosec B101
    assert (await client.post('/api/v1/rules', json=body, headers=headers)).status_code == 201  # nosec B101


async def test_a_cross_site_origin_is_refused_even_with_the_token(client):
    await make_user()
    headers = await login(client)
    response = await client.post('/api/v1/rules', json={'name': 'x', 'type': 'threshold'},
                                 headers={**headers, 'Origin': 'https://evil.example'})
    assert response.status_code == 403  # nosec B101


async def test_changing_a_password_signs_out_other_sessions(app, client):
    import httpx
    await make_user()
    headers = await login(client)
    other = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver')
    await login(other)
    response = await client.post('/api/v1/account/password', headers=headers,
                                 json={'current': 'correct horse battery', 'new': 'a much better passphrase'})
    assert response.status_code == 200  # nosec B101
    assert (await other.get('/api/v1/auth/me')).status_code == 401  # nosec B101
    assert (await client.get('/api/v1/auth/me')).status_code == 200  # nosec B101
    await other.aclose()


async def test_an_api_key_acts_within_its_scopes_and_its_owners_role(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    created = await client.post('/api/v1/api-keys', headers=headers,
                                json={'name': 'reader', 'scopes': ['findings:read'], 'expires_days': 30})
    assert created.status_code == 201  # nosec B101
    key = created.json()['key']
    client.cookies.clear()
    auth = {'Authorization': f'Bearer {key}'}
    assert (await client.get('/api/v1/findings', headers=auth)).status_code == 200  # nosec B101
    # Outside the key's scopes, though the role would allow it
    assert (await client.get('/api/v1/rules', headers=auth)).status_code == 403  # nosec B101
    assert (await client.post('/api/v1/findings/bulk', headers=auth,  # nosec B101
                              json={'ids': [str(uuid.uuid4())], 'status': 'resolved'})).status_code == 403


async def test_a_key_needs_no_csrf_token_and_narrows_when_its_owner_is_demoted(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    key = (await client.post('/api/v1/api-keys', headers=headers, json={
        'name': 'triage', 'scopes': ['findings:read', 'findings:write']})).json()['key']
    client.cookies.clear()
    auth = {'Authorization': f'Bearer {key}'}
    # No cookie and no CSRF header: a browser never sends a bearer key on its own
    assert (await client.post('/api/v1/findings/bulk', headers=auth,  # nosec B101
                              json={'ids': [str(uuid.uuid4())], 'status': 'resolved'})).status_code == 200
    from sqlalchemy import update

    async with db.sessionmaker()() as session:
        await session.execute(update(User).where(User.username == 'ana').values(role='viewer'))
        await session.commit()
    # The key still says findings:write, but its owner no longer may
    assert (await client.post('/api/v1/findings/bulk', headers=auth,  # nosec B101
                              json={'ids': [str(uuid.uuid4())], 'status': 'resolved'})).status_code == 403
    assert (await client.get('/api/v1/findings', headers=auth)).status_code == 200  # nosec B101


async def test_nobody_mints_a_key_beyond_their_role(client):
    await make_user('vic', role='viewer')
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    response = await client.post('/api/v1/api-keys', headers=headers,
                                 json={'name': 'too much', 'scopes': ['users:admin']})
    assert response.status_code == 400  # nosec B101


async def test_a_revoked_or_wrong_key_is_refused(client):
    await make_user('ana', role='analyst')
    headers = await login(client, 'ana')
    created = (await client.post('/api/v1/api-keys', headers=headers,
                                 json={'name': 'k', 'scopes': ['findings:read']})).json()
    await client.delete(f"/api/v1/api-keys/{created['id']}", headers=headers)
    client.cookies.clear()
    assert (await client.get('/api/v1/findings', headers={'Authorization': f"Bearer {created['key']}"})).status_code == 401  # nosec B101
    tampered = created['key'][:-4] + 'AAAA'
    assert (await client.get('/api/v1/findings', headers={'Authorization': f'Bearer {tampered}'})).status_code == 401  # nosec B101


async def test_the_admin_mfa_policy_holds_back_everything_but_the_account(client):
    await make_user('root', role='admin')
    headers = await login(client, 'root')
    await client.put('/api/v1/settings/general', headers=headers, json={'org_name': 'Test',
                                                                       'require_mfa_for_local_admins': True})
    from tbconsole import settings_store
    settings_store.forget_cache()
    assert (await client.get('/api/v1/rules')).status_code == 403  # nosec B101
    assert (await client.get('/api/v1/auth/me')).json()['mfa_required'] is True  # nosec B101
    assert (await client.post('/api/v1/account/mfa/setup', headers=headers,  # nosec B101
                              json={'password': 'correct horse battery'})).status_code == 200  # nosec B105


async def test_sessions_expire_when_idle(client, monkeypatch):
    from tbconsole.config import get_settings
    await make_user()
    await login(client)
    monkeypatch.setattr(get_settings(), 'session_idle_minutes', 0)
    time.sleep(0.01)
    assert (await client.get('/api/v1/auth/me')).status_code == 401  # nosec B101
