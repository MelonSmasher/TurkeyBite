"""The application: API, background workers, and the built frontend."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
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
from .rollups import Rollups
from .search.client import SearchClient, SearchRejected, SearchUnavailable
from .search.tbql import TbqlError
from .search.timerange import RangeError
from .security import passwords
from .webhooks.dispatcher import Dispatcher

log = logging.getLogger('tbconsole')

# The Swagger UI loads its script and styles from a CDN, so its page alone
# is allowed them
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
DOCS_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: "
            "https://fastapi.tiangolo.com; connect-src 'self'; frame-ancestors 'none'")


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        docs = request.url.path in ('/api/docs', '/api/docs/oauth2-redirect')
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
    settings = get_settings()
    if not (settings.bootstrap_admin_username and settings.bootstrap_admin_password):
        return
    async with db.sessionmaker()() as session:
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
        workers = [app.state.scheduler, app.state.dispatcher, app.state.rollups]
        for worker in workers:
            worker.start()
    try:
        yield
    finally:
        for worker in workers:
            await worker.stop()
        await app.state.search.close()
        await db.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title='TurkeyBite Console', version=__version__, lifespan=lifespan,
                  docs_url='/api/docs', redoc_url=None, openapi_url='/api/openapi.json',
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
        return JSONResponse({'detail': '; '.join(problems) or 'invalid request',
                             'errors': [{k: v for k, v in err.items() if k != 'ctx'}
                                        for err in e.errors()]}, status_code=422)

    app.include_router(api_router)

    @app.get('/healthz', include_in_schema=False)
    async def healthz():
        return {'ok': True}

    @app.get('/readyz', include_in_schema=False)
    async def readyz():
        async with db.sessionmaker()() as session:
            await session.execute(text('SELECT 1'))
        return {'ok': True}

    static = settings.static_dir
    if static and Path(static).is_dir() and (Path(static) / 'index.html').is_file():
        root = Path(static).resolve()

        @app.get('/{path:path}', include_in_schema=False)
        async def spa(path: str):
            if path.startswith('api/'):
                return JSONResponse({'detail': 'Not Found'}, status_code=404)
            candidate = (root / path).resolve()
            if path and candidate.is_file() and root in candidate.parents:
                headers = {}
                if '/assets/' in f'/{path}':
                    # Vite puts a content hash in every asset's name
                    headers['Cache-Control'] = 'public, max-age=31536000, immutable'
                return FileResponse(candidate, headers=headers)
            return FileResponse(root / 'index.html', headers={'Cache-Control': 'no-cache'})
    return app
