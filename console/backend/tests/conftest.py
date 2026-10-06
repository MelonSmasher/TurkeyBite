"""Shared fixtures: a real Postgres schema, a fake OpenSearch, and an app to call.

The tests need a Postgres, as the console does, since they rely on what only
Postgres does: partial unique indexes, JSONB, SKIP LOCKED. They use
TBCONSOLE_TEST_DATABASE_URL, by default a database called tbconsole_test on
the development Postgres from docker-compose.dev.yml, created if missing. Its
tables are emptied before every test.

OpenSearch is replaced by FakeSearch, which answers each request with what a
test hands it and records every body it was sent.
"""

import asyncio
import os

import pytest

TEST_DB = os.environ.get('TBCONSOLE_TEST_DATABASE_URL',
                         'postgresql+asyncpg://tbconsole:tbconsole-dev@127.0.0.1:55432/tbconsole_test')
os.environ['TBCONSOLE_DATABASE_URL'] = TEST_DB
os.environ.setdefault('TBCONSOLE_SECRET_KEY', 'test-secret-key-that-is-long-enough-0123456789')
os.environ['TBCONSOLE_COOKIE_SECURE'] = 'false'
os.environ['TBCONSOLE_RUN_WORKERS'] = 'false'
os.environ['TBCONSOLE_STATIC_DIR'] = ''
os.environ['TBCONSOLE_PUBLIC_URL'] = 'http://testserver'
os.environ['TBCONSOLE_RULE_INGEST_DELAY_SEC'] = '0'

from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from tbconsole import db, models  # noqa: E402,F401
from tbconsole.config import get_settings  # noqa: E402


async def _prepare() -> None:
    base, _, name = TEST_DB.rpartition('/')
    admin = create_async_engine(f'{base}/postgres', isolation_level='AUTOCOMMIT')
    async with admin.connect() as conn:
        exists = (await conn.execute(text('SELECT 1 FROM pg_database WHERE datname = :n'),
                                     {'n': name})).scalar()
        if not exists:
            await conn.execute(text(f'CREATE DATABASE "{name}"'))
    await admin.dispose()
    engine = create_async_engine(TEST_DB)
    async with engine.begin() as conn:
        await conn.run_sync(db.Base.metadata.drop_all)
        await conn.run_sync(db.Base.metadata.create_all)
    await engine.dispose()


@pytest.fixture(scope='session', autouse=True)
def schema():
    get_settings.cache_clear()
    asyncio.run(_prepare())
    yield


@pytest.fixture(autouse=True)
async def clean():
    """Empties every table, and leaves no engine bound to a closed loop."""
    async with db.sessionmaker()() as session:
        names = ', '.join(t.name for t in reversed(db.Base.metadata.sorted_tables))
        await session.execute(text(f'TRUNCATE {names} RESTART IDENTITY CASCADE'))
        await session.commit()
    from tbconsole import audit, settings_store
    from tbconsole.security import limits
    settings_store.forget_cache()
    limits.reset()
    audit._looks.clear()
    yield
    await db.dispose()


class FakeSearch:
    """OpenSearch as the console sees it. Hand it answers; it records requests."""

    def __init__(self, answer=None):
        self.answer = answer or (lambda body, index=None: {'hits': {'total': {'value': 0}, 'hits': []},
                                                            'aggregations': {}})
        self.bodies = []
        self.index = 'tb-index-*'

    async def search(self, body, index=None):
        self.bodies.append(body)
        return self.answer(body, index)

    async def count(self, query, index=None):
        result = await self.search({'query': query, '_count': True}, index)
        return result.get('count', result.get('hits', {}).get('total', {}).get('value', 0))

    async def get(self, index, doc_id):
        result = await self.search({'query': {'ids': {'values': [doc_id]}}}, index)
        hits = result.get('hits', {}).get('hits', [])
        return hits[0] if hits else None

    async def info(self):
        return {'cluster_name': 'fake', 'version': {'distribution': 'opensearch', 'number': '3.9.0'}}

    async def health(self):
        return {'status': 'green', 'number_of_nodes': 1}

    async def indices(self):
        return []

    async def close(self):
        pass


@pytest.fixture
def search():
    return FakeSearch()


@pytest.fixture
async def app(search):
    from tbconsole.deps import search_client
    from tbconsole.main import create_app
    application = create_app()
    application.dependency_overrides[search_client] = lambda: search
    async with application.router.lifespan_context(application):
        application.state.search = search
        yield application


@pytest.fixture
async def client(app):
    import httpx
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url='http://testserver') as c:
        yield c


async def make_user(username='alice', role='analyst', source='local', password='correct horse battery',
                    **extra):
    from tbconsole.security import passwords
    async with db.sessionmaker()() as session:
        user = models.User(username=username, role=role, source=source, preferences={},
                           display_name=username.title(),
                           password_hash=passwords.hash_password(password) if source == 'local' else None,
                           **extra)
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


async def login(client, username='alice', password='correct horse battery'):
    """Signs in and returns the CSRF header the session needs for writes."""
    response = await client.post('/api/v1/auth/login', json={'username': username, 'password': password})
    assert response.status_code == 200, response.text
    return {'X-CSRF-Token': client.cookies.get('tbc_csrf')}


@pytest.fixture
def directory(monkeypatch):
    from ldap3 import MOCK_SYNC, OFFLINE_SLAPD_2_4, Connection, Server

    from tbconsole.security import ldap as ldap_
    server = Server('mock', get_info=OFFLINE_SLAPD_2_4)
    seed = Connection(server, user='cn=svc,dc=example,dc=org', password='svc-pw', client_strategy=MOCK_SYNC)
    seed.strategy.add_entry('cn=svc,dc=example,dc=org', {'userPassword': 'svc-pw', 'objectClass': 'person', 'sn': 'svc'})
    seed.strategy.add_entry('uid=ava,ou=people,dc=example,dc=org', {
        'userPassword': 'ava-pw', 'objectClass': ['person', 'inetOrgPerson'], 'uid': 'ava', 'sn': 'Chen',
        'displayName': 'Ava Chen', 'mail': 'ava@example.org',
        'memberOf': ['cn=safeguarding,ou=groups,dc=example,dc=org']})
    seed.strategy.add_entry('uid=bob,ou=people,dc=example,dc=org', {
        'userPassword': 'bob-pw', 'objectClass': ['person', 'inetOrgPerson'], 'uid': 'bob', 'sn': 'B',
        'memberOf': ['cn=students,ou=groups,dc=example,dc=org']})
    monkeypatch.setattr(ldap_, '_STRATEGY', MOCK_SYNC)
    monkeypatch.setattr(ldap_, '_MOCK_SERVER', server)
    return ldap_.config_with_defaults({
        'enabled': True, 'urls': ['ldap://mock'], 'bind_dn': 'cn=svc,dc=example,dc=org',
        'user_base_dn': 'ou=people,dc=example,dc=org', 'user_filter': '(&(objectClass=person)(uid={username}))',
        'role_mappings': [{'group': 'cn=safeguarding,ou=groups,dc=example,dc=org', 'role': 'analyst'},
                          {'group': 'CN=IT,ou=groups,dc=example,dc=org', 'role': 'admin'}]})
