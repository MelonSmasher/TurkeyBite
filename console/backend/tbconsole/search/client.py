"""A small read-only client for OpenSearch's and Elasticsearch's REST API.

httpx rather than opensearch-py, because the console uses six endpoints that
are the same in both products, and one client that speaks to either is worth
more than a library tied to one. Several URLs may be given; a request that
cannot connect to one tries the next.

The console never writes to the cluster. Give it an account that can only read
the TurkeyBite indices, as console/README.md describes.
"""

import json
import logging
import ssl

import httpx

from ..config import Settings, get_settings

log = logging.getLogger(__name__)


class SearchError(Exception):
    """Base for a search that did not produce an answer."""


class SearchUnavailable(SearchError):
    """No OpenSearch host answered."""


class SearchRejected(SearchError):
    """OpenSearch answered and refused the request."""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _reason(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:300] or f'HTTP {response.status_code}'
    error = body.get('error') if isinstance(body, dict) else None
    if isinstance(error, dict):
        causes = error.get('root_cause') or []
        if causes and isinstance(causes[0], dict) and causes[0].get('reason'):
            return str(causes[0]['reason'])
        return str(error.get('reason') or error.get('type') or error)
    if error:
        return str(error)
    return f'HTTP {response.status_code}'


class SearchClient:
    def __init__(self, settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None):
        settings = settings or get_settings()
        self.urls = [u.rstrip('/') for u in settings.opensearch_urls]
        self.index = settings.opensearch_index
        verify: bool | ssl.SSLContext = settings.opensearch_verify_certs
        if settings.opensearch_verify_certs and settings.opensearch_ca_certs:
            verify = ssl.create_default_context(cafile=str(settings.opensearch_ca_certs))
        auth = None
        if settings.opensearch_username:
            auth = (settings.opensearch_username, settings.opensearch_password or '')
        self.http = httpx.AsyncClient(
            auth=auth, verify=verify, transport=transport,
            timeout=httpx.Timeout(settings.opensearch_timeout_sec, connect=5.0),
            headers={'Content-Type': 'application/json', 'Accept': 'application/json',
                     'User-Agent': 'TurkeyBite-Console'})
        self._preferred = 0

    async def close(self) -> None:
        await self.http.aclose()

    async def request(self, method: str, path: str, body=None, params=None,
                      content: bytes | None = None) -> dict:
        """Sends one request, trying each URL in turn until one connects."""
        if body is not None:
            content = json.dumps(body).encode('utf-8')
        last: Exception | None = None
        order = self.urls[self._preferred:] + self.urls[:self._preferred]
        for offset, base in enumerate(order):
            try:
                response = await self.http.request(method, base + path, params=params,
                                                   content=content)
            except httpx.TransportError as e:
                log.warning('OpenSearch at %s did not answer: %s', base, e)
                last = e
                continue
            self._preferred = (self._preferred + offset) % len(self.urls)
            if response.status_code >= 500 or response.status_code == 429:
                last = SearchRejected(response.status_code, _reason(response))
                continue
            if response.status_code >= 400:
                raise SearchRejected(response.status_code, _reason(response))
            return response.json()
        if isinstance(last, SearchRejected):
            raise SearchUnavailable(f'OpenSearch could not answer: {last.reason}')
        raise SearchUnavailable(f'no OpenSearch host could be reached: {last}')

    # -- the endpoints the console uses ----------------------------------------

    async def search(self, body: dict, index: str | None = None) -> dict:
        result = await self.request('POST', f'/{index or self.index}/_search', body,
                                    params={'ignore_unavailable': 'true',
                                            'allow_no_indices': 'true'})
        _whole(result)
        return result

    async def count(self, query: dict, index: str | None = None) -> int:
        result = await self.request('POST', f'/{index or self.index}/_count', {'query': query},
                                    params={'ignore_unavailable': 'true',
                                            'allow_no_indices': 'true'})
        _whole(result)
        return int(result.get('count', 0))

    async def get(self, index: str, doc_id: str) -> dict | None:
        """One document, looked up by id within one index of the pattern."""
        result = await self.search({'size': 1, 'query': {'ids': {'values': [doc_id]}}},
                                   index=index)
        hits = result.get('hits', {}).get('hits', [])
        return hits[0] if hits else None

    async def info(self) -> dict:
        return await self.request('GET', '/')

    async def health(self) -> dict:
        return await self.request('GET', '/_cluster/health')

    async def indices(self) -> list[dict]:
        result = await self.request('GET', f'/_cat/indices/{self.index}',
                                    params={'format': 'json', 'bytes': 'b',
                                            'h': 'index,health,docs.count,store.size,creation.date'})
        return result if isinstance(result, list) else []


def _whole(result: dict) -> None:
    """Refuses an answer some shards failed to give. OpenSearch still says 200
    then, with what the other shards found, and a partial count read as a
    whole one is wrong in the worst way: a rule takes what it did not see for
    something that is not there, and calls a value new or a source silent."""
    shards = result.get('_shards') or {}
    failed = int(shards.get('failed') or 0)
    if not failed:
        return
    reasons = [str(((f.get('reason') or {}).get('reason')) or (f.get('reason') or {}).get('type') or '')
               for f in shards.get('failures') or [] if isinstance(f, dict)]
    reason = next((r for r in reasons if r), 'no reason given')
    raise SearchRejected(400, f'{failed} of {shards.get("total", "?")} shards could not answer: {reason}')


def total(result: dict) -> int:
    value = result.get('hits', {}).get('total', 0)
    if isinstance(value, dict):
        return int(value.get('value', 0))
    return int(value or 0)
