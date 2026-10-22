"""Microsoft Entra ID OIDC sign-in."""

import base64
import json
import time
from urllib.parse import parse_qs, urlsplit

import pytest
import httpx
from sqlalchemy import select
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tbconsole import db, settings_store
from tbconsole.config import get_settings
from tbconsole.models import EntraLoginState, Setting, User
from tbconsole.security import crypto, entra

from .conftest import login, make_user

TENANT = '11111111-2222-3333-4444-555555555555'
OBJECT_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


@pytest.fixture
def secure_settings(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, 'public_url', 'https://testserver')
    monkeypatch.setattr(settings, 'cookie_secure', True)


@pytest.fixture
async def client(secure_settings, app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url='https://testserver') as test_client:
        yield test_client


async def configure_entra():
    async with db.sessionmaker()() as session:
        await settings_store.put(session, 'entra', {
            'enabled': True,
            'tenant_id': TENANT,
            'client_id': '11111111-aaaa-bbbb-cccc-555555555555',
            'client_secret_enc': crypto.encrypt('test-client-secret'),
        }, None)
        await session.commit()


def identity_claims(**overrides):
    claims = {
        'tid': TENANT,
        'oid': OBJECT_ID,
        'roles': ['analyst'],
        'preferred_username': 'alice@example.org',
        'name': 'Alice Example',
        'email': 'alice@example.org',
    }
    return claims | overrides


async def start(client):
    response = await client.get('/api/v1/auth/entra/start', params={'next': '/findings'},
                               follow_redirects=False)
    assert response.status_code == 303  # nosec B101
    state = parse_qs(urlsplit(response.headers['location']).query)['state'][0]
    return response, state


async def test_entra_start_is_browser_bound_pkce_and_uses_safe_return_path(client, monkeypatch):
    await configure_entra()
    response = await client.get('/api/v1/auth/entra/start', params={'next': '//evil.example'},
                                follow_redirects=False)
    location = urlsplit(response.headers['location'])
    query = parse_qs(location.query)
    assert response.status_code == 303  # nosec B101
    assert location.hostname == 'login.microsoftonline.com'  # nosec B101
    assert query['redirect_uri'] == ['https://testserver/api/v1/auth/entra/callback']  # nosec B101
    assert query['code_challenge_method'] == ['S256']  # nosec B101
    assert len(client.cookies.get('tbc_entra')) >= 32  # nosec B101
    async with db.sessionmaker()() as session:
        state = (await session.execute(select(EntraLoginState))).scalar_one()
        assert len(state.state_hash) == 32 and state.next_path == '/'  # nosec B101


async def test_entra_start_requires_https_public_url(client, monkeypatch):
    await configure_entra()
    monkeypatch.setattr(get_settings(), 'public_url', 'http://testserver')
    response = await client.get('/api/v1/auth/entra/start')
    assert response.status_code == 409  # nosec B101


async def test_entra_callback_creates_identity_by_tenant_and_object_id(
        client, monkeypatch):
    await configure_entra()

    async def exchange(settings, code, verifier):
        assert code == 'authorization-code' and verifier  # nosec B101
        return 'signed-id-token'

    async def validate(settings, token, nonce):
        assert token == 'signed-id-token' and nonce  # nosec B101
        return identity_claims()

    monkeypatch.setattr(entra, 'exchange_code', exchange)
    monkeypatch.setattr(entra, 'validate_id_token', validate)
    _, state = await start(client)

    response = await client.get('/api/v1/auth/entra/callback',
                                params={'state': state, 'code': 'authorization-code'},
                                follow_redirects=False)
    assert response.status_code == 303  # nosec B101
    assert response.headers['location'] == 'https://testserver/findings'  # nosec B101
    assert 'tbc_session' in response.cookies  # nosec B101
    me = (await client.get('/api/v1/auth/me')).json()['user']
    assert me['username'] == 'alice@example.org' and me['source'] == 'entra'  # nosec B101
    assert me['role'] == 'analyst'  # nosec B101
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User))).scalar_one()
        assert user.entra_tenant_id == TENANT and user.entra_object_id == OBJECT_ID  # nosec B101
        assert user.password_hash is None  # nosec B101


async def test_entra_role_is_refreshed_and_local_username_is_never_linked(
        client, monkeypatch):
    await configure_entra()
    await make_user('alice@example.org', source='local')
    async def exchange(settings, code, verifier):
        return 'signed-id-token'

    async def validate(settings, token, nonce):
        return identity_claims(roles=['admin'])

    monkeypatch.setattr(entra, 'exchange_code', exchange)
    monkeypatch.setattr(entra, 'validate_id_token', validate)
    _, state = await start(client)
    response = await client.get('/api/v1/auth/entra/callback',
                                params={'state': state, 'code': 'authorization-code'},
                                follow_redirects=False)
    assert response.status_code == 303  # nosec B101
    assert response.headers['location'].endswith('/login?entra=failed')  # nosec B101
    async with db.sessionmaker()() as session:
        users = (await session.execute(select(User))).scalars().all()
        assert len(users) == 1 and users[0].source == 'local'  # nosec B101


async def test_local_password_login_stays_available_with_entra_enabled(client, monkeypatch):
    await configure_entra()
    await make_user('local-tester', source='local')
    response = await client.post('/api/v1/auth/login',
                                 json={'username': 'local-tester',
                                       'password': 'correct horse battery'})
    assert response.status_code == 200  # nosec B101
    assert response.json()['user']['source'] == 'local'  # nosec B101
    assert 'tbc_session' in response.cookies  # nosec B101


async def test_admin_cannot_override_an_entra_role(client, monkeypatch):
    await configure_entra()
    await make_user('admin', role='admin')
    managed = await make_user('managed-user', role='analyst', source='entra',
                              entra_tenant_id=TENANT, entra_object_id=OBJECT_ID)
    csrf = await login(client, 'admin')
    response = await client.patch(f'/api/v1/users/{managed.id}', headers=csrf,
                                  json={'role': 'admin'})
    assert response.status_code == 400  # nosec B101
    assert 'Entra application roles' in response.json()['detail']  # nosec B101


async def test_admin_can_save_encrypted_entra_settings_without_exposing_the_secret(client):
    await make_user('admin', role='admin')
    csrf = await login(client, 'admin')
    payload = {
        'enabled': False,
        'tenant_id': TENANT,
        'client_id': '11111111-aaaa-bbbb-cccc-555555555555',
        'client_secret': 'test-client-secret',
    }
    saved = await client.put('/api/v1/settings/entra', headers=csrf, json=payload)
    assert saved.status_code == 200  # nosec B101
    assert saved.json()['has_client_secret']  # nosec B101
    assert 'client_secret' not in saved.json() and 'client_secret_enc' not in saved.json()  # nosec B101
    async with db.sessionmaker()() as session:
        stored = await session.get(Setting, 'entra')
        assert stored.value['client_secret_enc'] != 'test-client-secret'  # nosec B101
        assert crypto.decrypt(stored.value['client_secret_enc']) == 'test-client-secret'  # nosec B101

    changed_client = await client.put('/api/v1/settings/entra', headers=csrf,
                                      json={**payload, 'client_id': OBJECT_ID,
                                            'client_secret': None})
    assert changed_client.status_code == 400  # nosec B101


async def test_entra_unassigned_identity_cannot_sign_in(client, monkeypatch):
    await configure_entra()
    async def exchange(settings, code, verifier):
        return 'signed-id-token'

    async def validate(settings, token, nonce):
        return identity_claims(roles=[])

    monkeypatch.setattr(entra, 'exchange_code', exchange)
    monkeypatch.setattr(entra, 'validate_id_token', validate)
    _, state = await start(client)
    response = await client.get('/api/v1/auth/entra/callback',
                                params={'state': state, 'code': 'authorization-code'},
                                follow_redirects=False)
    assert response.status_code == 303  # nosec B101
    assert response.headers['location'].endswith('/login?entra=failed')  # nosec B101
    assert not response.cookies.get('tbc_session')  # nosec B101
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(User))).scalars().all() == []  # nosec B101


async def test_entra_callback_rejects_state_from_another_browser(client, monkeypatch):
    await configure_entra()
    _, state = await start(client)
    client.cookies.set('tbc_entra', 'x' * 48, path='/api/v1/auth/entra')
    response = await client.get('/api/v1/auth/entra/callback',
                                params={'state': state, 'code': 'authorization-code'},
                                follow_redirects=False)
    assert response.status_code == 303  # nosec B101
    assert response.headers['location'].endswith('/login?entra=failed')  # nosec B101
    async with db.sessionmaker()() as session:
        assert (await session.execute(select(User))).scalars().all() == []  # nosec B101


async def test_entra_id_token_signature_issuer_audience_and_nonce_are_verified(monkeypatch):
    config = entra.Config(TENANT, '11111111-aaaa-bbbb-cccc-555555555555',
                          'test-client-secret', 'https://console.example.org/api/v1/auth/entra/callback')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_numbers()

    def b64url(data):
        return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

    def integer(value):
        return value.to_bytes((value.bit_length() + 7) // 8, 'big')

    header = b64url(json.dumps({'alg': 'RS256', 'kid': 'test-key'}).encode())
    claims = b64url(json.dumps({
        'iss': f'https://login.microsoftonline.com/{TENANT}/v2.0',
        'aud': config.client_id,
        'tid': TENANT,
        'oid': OBJECT_ID,
        'nonce': 'expected-nonce',
        'iat': int(time.time()),
        'exp': int(time.time()) + 300,
    }).encode())
    body = f'{header}.{claims}'
    signature = key.sign(body.encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
    token = f'{body}.{b64url(signature)}'
    metadata = {
        'issuer': f'https://login.microsoftonline.com/{TENANT}/v2.0',
        'jwks_uri': 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
    }
    jwks = {'keys': [{
        'kid': 'test-key', 'kty': 'RSA', 'use': 'sig',
        'n': b64url(integer(public.n)), 'e': b64url(integer(public.e)),
    }]}

    class FakeResponse:
        def __init__(self, value):
            self.status_code = 200
            self.value = value

        def json(self):
            return self.value

        def raise_for_status(self):
            return None

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def get(self, url):
            return FakeResponse(metadata if url.endswith('openid-configuration')
                                else jwks)

    monkeypatch.setattr(entra.httpx, 'AsyncClient', lambda **_: FakeClient())
    verified = await entra.validate_id_token(config, token, 'expected-nonce')
    assert verified['oid'] == OBJECT_ID  # nosec B101
    with pytest.raises(entra.EntraError):
        await entra.validate_id_token(config, token, 'wrong-nonce')
