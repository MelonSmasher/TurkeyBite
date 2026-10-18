"""The documentation site at /docs/, for people who are signed in.

The site is built and served by its own container, docker/docs, which the
console reaches at TBCONSOLE_DOCS_URL and nobody else can. Serving it here
puts it on the console's own address, behind the console's sign-in, with no
change to the reverse proxy in front: someone not signed in is sent to sign
in and brought back to the page they asked for.

Reading the documentation changes nothing and names nobody, so unlike the
API it is not refused when a link on another site leads to it, and it is not
written to the audit log.

Only GET and HEAD are passed on, the path as it was asked for and checked
first, so the container is never asked for anything outside /docs/. What it
answers is streamed back as it came, compressed or not, with the headers a
browser needs and none of the container's own; caching is made private,
since only someone signed in may see it. The pages' Content-Security-Policy
comes from the site's build, which allows the theme's inline scripts by
their hashes: the site shares the console's origin, so 'unsafe-inline'
would let any inline script act as whoever is signed in.
"""

from urllib.parse import quote, unquote

import httpx
from fastapi import Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response, StreamingResponse

from . import db
from .config import get_settings
from .security import sessions

PREFIX = '/docs'
# Headers asked with that the site's answer depends on
FORWARD = ('accept', 'accept-encoding', 'if-none-match', 'if-modified-since')
# Headers of the answer that are passed back. The Content-Security-Policy
# among them is the one the site's build wrote, which allows its own inline
# scripts by their hashes and nothing else inline.
RETURN = ('content-type', 'content-length', 'content-encoding', 'etag', 'last-modified',
          'location', 'vary', 'content-security-policy')
TIMEOUT = httpx.Timeout(10.0, connect=3.0)

# For an answer that comes without the site's policy, from an older docs
# image say: the app's own, which blocks the pages' inline scripts rather
# than let any inline script run on the console's origin
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; worker-src 'self'; "
       "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")


def client() -> httpx.AsyncClient | None:
    """The client the app keeps for the docs container, or None when there is none."""
    url = get_settings().docs_url
    if not url:
        return None
    # Nothing from the environment: no proxy stands between the console and
    # a container beside it
    return httpx.AsyncClient(base_url=url, timeout=TIMEOUT, trust_env=False,
                             follow_redirects=False)


def is_docs(path: str) -> bool:
    """Whether a request path is the documentation site's."""
    return path == PREFIX or path.startswith(PREFIX + '/')


def _target(request: Request) -> str | None:
    """The path and query to ask the container for, or None for one to refuse.

    The path is passed on as it arrived, still encoded, once its decoded
    form is checked to stay under /docs/: no dot segments, no backslashes and
    no control characters, which a server could read differently.
    """
    raw = request.scope.get('raw_path') or request.url.path.encode()
    path = raw.decode('latin-1')
    decoded = unquote(path)
    segments = decoded.split('/')
    if (not is_docs(decoded) or '\\' in decoded or '..' in segments or '.' in segments
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded)):
        return None
    query = request.scope.get('query_string', b'').decode('latin-1')
    return path + ('?' + query if query else '')


async def _signed_in(request: Request) -> bool:
    token = request.cookies.get(sessions.SESSION_COOKIE)
    if not token:
        return False
    async with db.sessionmaker()() as session:
        return await sessions.lookup(session, token) is not None


async def serve(request: Request) -> Response:
    """The documentation page asked for, to someone signed in."""
    target = _target(request)
    if target is None:
        return PlainTextResponse('Not Found', status_code=404)
    if not await _signed_in(request):
        return RedirectResponse('/login?next=' + quote(target, safe=''), status_code=303)
    docs: httpx.AsyncClient | None = getattr(request.app.state, 'docs', None)
    if docs is None:
        return PlainTextResponse('Not Found', status_code=404)
    headers = {name: request.headers[name] for name in FORWARD if name in request.headers}
    try:
        upstream = await docs.send(docs.build_request(request.method, target, headers=headers),
                                   stream=True)
    except httpx.HTTPError:
        return PlainTextResponse('The documentation is not available right now.', status_code=502)
    returned = {name: upstream.headers[name] for name in RETURN if name in upstream.headers}
    cache = [part.strip() for part in upstream.headers.get('cache-control', 'no-cache').split(',')]
    returned['cache-control'] = ', '.join(
        ['private'] + [part for part in cache if part and part not in ('public', 'private')])
    returned.setdefault('content-security-policy', CSP)
    return StreamingResponse(_relay(upstream), status_code=upstream.status_code, headers=returned)


async def _relay(upstream: httpx.Response):
    """The answer's body as it came, its connection let go however the stream ends."""
    try:
        async for chunk in upstream.aiter_raw():
            yield chunk
    finally:
        await upstream.aclose()
