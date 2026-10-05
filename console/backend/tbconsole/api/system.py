"""How the console and what it reads from are doing."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .. import __version__
from ..analysis import engine
from ..config import get_settings
from ..db import get_session
from ..deps import Principal, require, search_client
from ..models import DailyStat, Finding, Rule, WebhookDelivery
from ..search.client import SearchClient, SearchError
from ..security import rbac
from .common import ts

router = APIRouter(prefix='/system', tags=['system'])


@router.get('/status')
async def status_(request: Request, _: Principal = Depends(require(rbac.SETTINGS_ADMIN)),
                  search: SearchClient = Depends(search_client),
                  db: AsyncSession = Depends(get_session)) -> dict:
    settings = get_settings()
    opensearch: dict = {'ok': False, 'urls': settings.opensearch_urls,
                        'index_pattern': settings.opensearch_index,
                        'verify_certs': settings.opensearch_verify_certs}
    try:
        info, health = await search.info(), await search.health()
        version = info.get('version') or {}
        opensearch.update({
            'ok': True, 'cluster_name': info.get('cluster_name'),
            'distribution': version.get('distribution', 'elasticsearch'),
            'version': version.get('number'), 'health': health.get('status'),
            'nodes': health.get('number_of_nodes')})
        indices = await search.indices()
        opensearch['indices'] = sorted(
            [{'index': i.get('index'), 'health': i.get('health'),
              'docs': int(i.get('docs.count') or 0), 'bytes': int(i.get('store.size') or 0)}
             for i in indices], key=lambda i: i['index'], reverse=True)
        opensearch['docs'] = sum(i['docs'] for i in opensearch['indices'])
        opensearch['bytes'] = sum(i['bytes'] for i in opensearch['indices'])
    except SearchError as e:
        opensearch['error'] = str(e)
    workers = {'enabled': settings.run_workers}
    app = request.app.state
    for name in ('scheduler', 'dispatcher', 'rollups', 'maintenance'):
        worker = getattr(app, name, None)
        if worker is not None:
            workers[name] = {'last': ts(getattr(worker, 'last_tick', None)
                                        or getattr(worker, 'last_run', None)),
                             'error': getattr(worker, 'last_error', None)}
    await db.execute(text('SELECT 1'))
    rules_enabled = (await db.execute(select(func.count()).select_from(Rule).where(
        Rule.enabled.is_(True)))).scalar_one()
    rules_failing = (await db.execute(select(func.count()).select_from(Rule).where(
        Rule.enabled.is_(True), Rule.last_status == 'error'))).scalar_one()
    pending = (await db.execute(select(func.count()).select_from(WebhookDelivery).where(
        WebhookDelivery.status.in_(('pending', 'failed'))))).scalar_one()
    dead = (await db.execute(select(func.count()).select_from(WebhookDelivery).where(
        WebhookDelivery.status == 'dead'))).scalar_one()
    open_findings = (await db.execute(select(func.count()).select_from(Finding).where(
        Finding.status.in_(engine.OPEN)))).scalar_one()
    rollup_days = (await db.execute(select(func.count(func.distinct(DailyStat.day))))).scalar_one()
    # Whichever replica holds the lease does the counting, so when it last ran
    # comes from the counts themselves rather than from this process
    rollups_last = (await db.execute(select(func.max(DailyStat.updated_at)))).scalar()
    if isinstance(workers.get('rollups'), dict):
        workers['rollups']['last'] = ts(rollups_last)
    return {
        'version': __version__, 'time': ts(datetime.now(timezone.utc)),
        'database': {'ok': True},
        'opensearch': opensearch, 'workers': workers,
        'rules': {'enabled': rules_enabled, 'failing': rules_failing},
        'webhooks': {'queued': pending, 'dead': dead},
        'findings': {'open': open_findings},
        'rollups': {'days': rollup_days},
        'public_url': settings.public_url,
    }
