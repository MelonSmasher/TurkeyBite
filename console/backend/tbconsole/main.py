"""The application: API, background workers, and the built frontend."""

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from sqlalchemy import func, select, text
from starlette.middleware.base import BaseHTTPMiddleware

from . import __version__, db
from .analysis import engine
from .analysis.engine import Scheduler
from .analysis.ruletypes import RuleError
from .api import router as api_router
from .api.dashboards import sync_builtin_dashboards
from .config import get_settings
from .models import User
from .maintenance import Maintenance
from .rollups import Rollups
from .search.client import SearchClient, SearchRejected, SearchUnavailable
from .search.tbql import TbqlError
from .search.timerange import RangeError, use_zone
from .security import passwords
from .webhooks.dispatcher import Dispatcher

log = logging.getLogger('tbconsole')

# How long the readiness probe waits on the database
READY_TIMEOUT = 5.0

# The Swagger UI loads its script and styles from a CDN, so its page alone,
# when TBCONSOLE_API_DOCS turns it on, is allowed them
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
DOCS_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: "
            "https://fastapi.tiangolo.com; connect-src 'self'; frame-ancestors 'none'")


class SecurityHeaders(BaseHTTPMiddleware):
    """Security headers on every response, and the caller's time zone for each request."""

    async def dispatch(self, request: Request, call_next):
        """Takes the request's time zone, then adds the headers the response does not set itself."""
        use_zone(request.headers.get('x-timezone'))
        response: Response = await call_next(request)
        docs = get_settings().api_docs and request.url.path in ('/api/docs', '/api/docs/oauth2-redirect')
        response.headers.setdefault('Content-Security-Policy', DOCS_CSP if docs else CSP)
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'same-origin')
        response.headers.setdefault('Permissions-Policy',
                                    'camera=(), microphone=(), geolocation=(), payment=()')
        if get_settings().cookie_secure:
            response.headers.setdefault('Strict-Transport-Security',
                                        'max-age=31536000; includeSubDomains')
        if request.url.path.startswith('/api/'):
            response.headers.setdefault('Cache-Control', 'no-store')
        return response


async def bootstrap_admin() -> None:
    """Creates the first admin from the TBCONSOLE_BOOTSTRAP_ADMIN_ settings, if there are no users at all."""
    settings = get_settings()
    if not (settings.bootstrap_admin_username and settings.bootstrap_admin_password):
        return
    async with db.sessionmaker()() as session:
        # Processes starting together take turns, so only one creates it
        await session.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': engine.SYNC_LOCK})
        users = (await session.execute(select(func.count()).select_from(User))).scalar_one()
        if users:
            return
        problems = passwords.password_problems(settings.bootstrap_admin_password,
                                               settings.bootstrap_admin_username)
        if problems:
            log.error('TBCONSOLE_BOOTSTRAP_ADMIN_PASSWORD is not acceptable: %s', ' '.join(problems))
            return
        session.add(User(username=settings.bootstrap_admin_username, source='local', role='admin',
                         display_name='Administrator',
                         password_hash=passwords.hash_password(settings.bootstrap_admin_password),
                         preferences={}))
        await session.commit()
        log.warning('Created the first admin, %s. Change its password after signing in.',
                    settings.bootstrap_admin_username)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Brings the built-in rules and dashboards up to date and runs the workers while the app is up."""
    settings = get_settings()
    app.state.search = SearchClient(settings)
    async with db.sessionmaker()() as session:
        await session.execute(text('SELECT 1'))
        synced = await engine.sync_builtin_rules(session)
        await sync_builtin_dashboards(session)
    if synced['added'] or synced['upgraded']:
        log.info('Built-in rules: %(added)s added, %(upgraded)s upgraded', synced)
    await bootstrap_admin()
    workers = []
    if settings.run_workers:
        app.state.scheduler = Scheduler(app.state.search)
        app.state.dispatcher = Dispatcher()
        app.state.rollups = Rollups(app.state.search)
        app.state.maintenance = Maintenance()
        workers = [app.state.scheduler, app.state.dispatcher, app.state.rollups,
                   app.state.maintenance]
        for worker in workers:
            worker.start()
    try:
        yield
    finally:
        for worker in workers:
            await worker.stop()
        await app.state.search.close()
        await db.dispose()


def create_app() -> FastAPI:  # noqa: MC0001  # the error handlers and routes are nested in it
    """The application: the API, its error handlers, the health probes and the built frontend."""
    settings = get_settings()
    app = FastAPI(title='TurkeyBite Console', version=__version__, lifespan=lifespan,
                  docs_url='/api/docs' if settings.api_docs else None, redoc_url=None,
                  openapi_url='/api/openapi.json',
                  description='Search, analytics, findings and alerting for TurkeyBite. '
                              'Authenticate with `Authorization: Bearer tbc_...`.')
    app.add_middleware(SecurityHeaders)

    @app.exception_handler(TbqlError)
    async def _tbql(_: Request, e: TbqlError):
        return JSONResponse({'detail': e.message, 'query_error': e.public()}, status_code=400)

    @app.exception_handler(RangeError)
    async def _range(_: Request, e: RangeError):
        return JSONResponse({'detail': str(e)}, status_code=400)

    @app.exception_handler(RuleError)
    async def _rule(_: Request, e: RuleError):
        return JSONResponse({'detail': str(e)}, status_code=400)

    @app.exception_handler(SearchUnavailable)
    async def _unavailable(_: Request, e: SearchUnavailable):
        return JSONResponse({'detail': f'OpenSearch is unavailable: {e}', 'code': 'search_unavailable'},
                            status_code=503)

    @app.exception_handler(SearchRejected)
    async def _rejected(_: Request, e: SearchRejected):
        return JSONResponse({'detail': f'OpenSearch refused the query: {e.reason}',
                             'code': 'search_rejected'}, status_code=502)

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, e: RequestValidationError):
        problems = []
        for error in e.errors():
            where = '.'.join(str(p) for p in error.get('loc', ()) if p not in ('body', 'query'))
            problems.append(f'{where}: {error.get("msg")}' if where else error.get('msg'))
        # What was sent is not echoed back: it may not be JSON at all, and it
        # may hold a password
        return JSONResponse({'detail': '; '.join(problems) or 'invalid request',
                             'errors': [{k: v for k, v in err.items() if k not in ('ctx', 'input', 'url')}
                                        for err in e.errors()]}, status_code=422)

    app.include_router(api_router)

    @app.api_route('/healthz', methods=['GET', 'HEAD'], include_in_schema=False)
    async def healthz():
        return {'ok': True}

    @app.api_route('/readyz', methods=['GET', 'HEAD'], include_in_schema=False)
    async def readyz():
        """Ready when the database answers, within a few seconds.

        A 503 otherwise, for a probe to see before its own timeout gives up.
        """
        async def ask():
            async with db.sessionmaker()() as session:
                await session.execute(text('SELECT 1'))
        # Not wait_for, which waits for what it cancels to finish: a query on
        # a connection to a database that froze can take that long too
        task = asyncio.ensure_future(ask())
        task.add_done_callback(lambda t: t.cancelled() or t.exception())
        done, _ = await asyncio.wait({task}, timeout=READY_TIMEOUT)
        if not done:
            task.cancel()
        try:
            if not done:
                raise TimeoutError('the database did not answer in time')
            task.result()
        except Exception:
            return JSONResponse({'ok': False, 'detail': 'the database is not answering'},
                                status_code=503)
        return {'ok': True}

    static = settings.static_dir
    if static and Path(static).is_dir() and (Path(static) / 'index.html').is_file():
        root = Path(static).resolve()


        @app.api_route('/{path:path}', methods=['GET', 'HEAD'], include_in_schema=False)
        async def spa(path: str, request: Request):
            if path.startswith('api/'):
                return JSONResponse({'detail': 'Not Found'}, status_code=404)
            candidate = (root / path).resolve()
            if path.startswith('assets/') and not candidate.is_file():
                # A page's code from before a redeploy: say it is gone rather
                # than answer with index.html, so the app knows to reload
                return Response(status_code=404)
            if path and candidate.is_file() and root in candidate.parents:
                headers = {}
                if '/assets/' in f'/{path}':
                    # Vite puts a content hash in every asset's name
                    headers['Cache-Control'] = 'public, max-age=31536000, immutable'
                return FileResponse(candidate, headers=headers)
            # Read each time, small as it is, so a new build is served at once
            index = (root / 'index.html').read_text(encoding='utf-8')
            if request.headers.get('sec-fetch-site') in ('cross-site', 'same-site'):
                # Marks a page opened from a link on another site, so the app
                # asks before it looks anyone up: otherwise such a link could
                # put a look at someone in the audit log under the name of
                # whoever followed it
                return HTMLResponse(index.replace('</head>', '<meta name="tbc-arrival" content="elsewhere"></head>', 1),
                                    headers={'Cache-Control': 'no-store'})
            return HTMLResponse(index, headers={'Cache-Control': 'no-cache'})
    return app
