"""Tests for the documentation site at /docs/.

The console passes requests on to the docs container, so what matters is
what it lets through: only people signed in, only paths under /docs/, none of
the browser's cookies, and none of the container's own headers. The container
is a fake that records what it was asked.
"""

import gzip

import httpx
import pytest

from tbconsole.config import Settings, get_settings
from tests.conftest import login, make_user

DOCS = 'http://docs.test'


class Body(httpx.AsyncByteStream):
    """A body that arrives as it would over the network, unread."""

    def __init__(self, data: bytes):
        self.data = data

    async def __aiter__(self):
        yield self.data


class FakeDocs:
    """The docs container: answers each request and records it."""

    def __init__(self):
        self.requests = []
        self.down = False

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.down:
            raise httpx.ConnectError('refused', request=request)
        if request.url.path == '/docs/console':
            return httpx.Response(301, headers={'location': '/docs/console/'}, stream=Body(b''))
        if request.url.path == '/docs/missing/':
            return httpx.Response(404, headers={'content-type': 'text/html'}, stream=Body(b'<h1>gone</h1>'))
        body = b'<html>' + request.url.path.encode() + b'</html>' * 200
        headers = {'content-type': 'text/html', 'cache-control': 'public, max-age=3600',
                   'etag': '"abc"', 'server': 'nginx/1.29', 'x-internal': 'secret'}
        if 'gzip' in request.headers.get('accept-encoding', ''):
            body = gzip.compress(body)
            headers['content-encoding'] = 'gzip'
        headers['content-length'] = str(len(body))
        return httpx.Response(200, headers=headers, stream=Body(body))


@pytest.fixture
async def docs_app(monkeypatch, search):
    monkeypatch.setenv('TBCONSOLE_DOCS_URL', DOCS)
    get_settings.cache_clear()
    from tbconsole.deps import search_client
    from tbconsole.main import create_app
    fake = FakeDocs()
    application = create_app()
    application.dependency_overrides[search_client] = lambda: search
    async with application.router.lifespan_context(application):
        application.state.search = search
        await application.state.docs.aclose()
        application.state.docs = httpx.AsyncClient(base_url=DOCS, transport=httpx.MockTransport(fake.handle))
        application.state.fake_docs = fake
        yield application
    monkeypatch.delenv('TBCONSOLE_DOCS_URL')
    get_settings.cache_clear()


@pytest.fixture
async def docs_client(docs_app):
    transport = httpx.ASGITransport(app=docs_app)
    async with httpx.AsyncClient(transport=transport, base_url='http://testserver') as c:
        yield c


async def signed_in(client):
    await make_user('alice', role='viewer')
    await login(client)


async def test_someone_not_signed_in_is_sent_to_sign_in_and_back(docs_client, docs_app):
    response = await docs_client.get('/docs/tutorial/?x=1')
    assert response.status_code == 303
    assert response.headers['location'] == '/login?next=%2Fdocs%2Ftutorial%2F%3Fx%3D1'
    assert docs_app.state.fake_docs.requests == []


async def test_a_page_is_passed_on_to_someone_signed_in(docs_client, docs_app):
    await signed_in(docs_client)
    response = await docs_client.get('/docs/tutorial/', headers={'accept-encoding': 'identity'})
    assert response.status_code == 200
    assert response.text.startswith('<html>/docs/tutorial/</html>')
    assert response.headers['etag'] == '"abc"'
    # Private, since only someone signed in may see it, and with the site's
    # own policy rather than the app's
    assert response.headers['cache-control'] == 'private, max-age=3600'
    assert "script-src 'self' 'unsafe-inline'" in response.headers['content-security-policy']
    assert response.headers['x-frame-options'] == 'DENY'
    assert 'x-internal' not in response.headers
    assert 'nginx' not in response.headers.get('server', '')


async def test_the_cookies_never_reach_the_container(docs_client, docs_app):
    await signed_in(docs_client)
    await docs_client.get('/docs/', headers={'authorization': 'Bearer tbc_x', 'if-none-match': '"abc"'})
    sent = docs_app.state.fake_docs.requests[-1].headers
    assert 'cookie' not in sent
    assert 'authorization' not in sent
    assert sent['if-none-match'] == '"abc"'


async def test_a_compressed_answer_is_passed_on_as_it_came(docs_client, docs_app):
    await signed_in(docs_client)
    response = await docs_client.get('/docs/', headers={'accept-encoding': 'gzip'})
    assert response.status_code == 200
    assert response.headers['content-encoding'] == 'gzip'
    # httpx undoes the compression it was sent, so the page reads whole
    assert response.text.startswith('<html>/docs/</html>')


async def test_redirects_and_missing_pages_come_back_as_they_are(docs_client):
    await signed_in(docs_client)
    response = await docs_client.get('/docs/console')
    assert (response.status_code, response.headers['location']) == (301, '/docs/console/')
    response = await docs_client.get('/docs/missing/')
    assert response.status_code == 404


@pytest.mark.parametrize('path', ['/docs/%2e%2e/api/v1/auth/me', '/docs/a/%2E%2E/%2E%2E/healthz',
                                  '/docs/%5c..%5capi', '/docs/%2e/x', '/docs/%0aevil'])
async def test_a_path_that_could_leave_docs_is_refused(docs_client, docs_app, path):
    await signed_in(docs_client)
    response = await docs_client.get(path)
    assert response.status_code == 404
    assert docs_app.state.fake_docs.requests == []


async def test_only_reading_is_passed_on(docs_client, docs_app):
    await signed_in(docs_client)
    response = await docs_client.post('/docs/', headers={'X-CSRF-Token': docs_client.cookies.get('tbc_csrf')})
    assert response.status_code == 405
    assert docs_app.state.fake_docs.requests == []


async def test_a_link_from_another_site_still_opens_the_docs(docs_client):
    await signed_in(docs_client)
    response = await docs_client.get('/docs/', headers={'sec-fetch-site': 'cross-site'})
    assert response.status_code == 200


async def test_a_container_that_is_down_is_said_so(docs_client, docs_app):
    await signed_in(docs_client)
    docs_app.state.fake_docs.down = True
    response = await docs_client.get('/docs/')
    assert response.status_code == 502


async def test_the_app_is_told_the_docs_are_there(docs_client):
    await signed_in(docs_client)
    assert (await docs_client.get('/api/v1/auth/me')).json()['docs'] is True


async def test_without_a_docs_url_there_is_no_docs(client):
    await make_user('alice', role='viewer')
    await login(client)
    assert (await client.get('/api/v1/auth/me')).json()['docs'] is False
    assert (await client.get('/docs/')).status_code == 404


@pytest.mark.parametrize('value', ['docs:8080', 'ftp://docs:8080', 'http://docs:8080/docs'])
def test_a_docs_url_that_is_not_an_address_is_refused(value):
    with pytest.raises(ValueError):
        Settings(secret_key='x' * 40, docs_url=value)


def test_a_docs_url_loses_its_trailing_slash():
    assert Settings(secret_key='x' * 40, docs_url='http://docs:8080/').docs_url == 'http://docs:8080'
