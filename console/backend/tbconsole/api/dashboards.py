"""Dashboards and saved searches.

A dashboard is a list of widgets, each a pivot over the events, a list of
findings, a single number or a note. Widgets keep their query, not their
results: a dashboard is drawn fresh from OpenSearch every time it is opened.
The console ships three, which can be cloned and changed but not edited.
"""

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..analysis import engine
from ..db import get_session
from ..deps import Principal, require
from ..models import Dashboard, SavedSearch
from ..security import rbac
from .common import dashboard_out, parse_uuid, saved_search_out

router = APIRouter(tags=['dashboards'])

WIDGET_TYPES = ('pivot', 'findings', 'stat', 'note')
VIZ = ('area', 'stacked', 'line', 'bar', 'hbar', 'table', 'number', 'heatmap')
MAX_WIDGETS = 40
MAX_WIDGETS_BYTES = 64 * 1024


def _w(title, span, pivot=None, viz='bar', kind='pivot', *, height='md', **extra) -> dict:  # pylint: disable=too-many-arguments  # a widget's parts
    slug = ''.join(ch if ch.isalnum() else '-' for ch in title.lower()).strip('-')
    widget = {'id': slug[:40], 'title': title, 'type': kind, 'span': span,
              'height': height, 'viz': viz}
    if pivot is not None:
        widget['pivot'] = pivot
    widget.update(extra)
    return widget


BUILTIN_DASHBOARDS = [
    {
        'key': 'security-posture', 'name': 'Security posture', 'icon': 'shield',
        'description': 'Threats, risky traffic and who it comes from.',
        'time_range': {'from': 'now-7d', 'to': 'now'},
        'widgets': [
            _w('Threat events', 3, {'query': 'risk:threat', 'metric': 'count'}, 'number', 'stat',
               height='sm'),
            _w('Anonymiser events', 3, {'query': 'risk:policy.anonymiser', 'metric': 'count'},
               'number', 'stat', height='sm'),
            _w('Clients with threats', 3, {'query': 'risk:threat', 'metric': 'unique',
                                           'metric_field': 'bite.client'}, 'number', 'stat',
               height='sm'),
            _w('Open critical findings', 3, None, 'number', 'findings', height='sm',
               findings={'status': 'open', 'severity': ['critical'], 'limit': 5, 'count_only': True}),
            _w('Risky traffic by severity', 8, {
                'query': 'risk_severity:(high OR medium)', 'metric': 'count', 'over_time': True,
                'split': 'bite.risk_severity', 'split_size': 3}, 'stacked'),
            _w('Open findings', 4, None, 'table', 'findings',
               findings={'status': 'open', 'severity': ['critical', 'high'], 'limit': 8}),
            _w('Top risks', 6, {'query': 'has:risk AND NOT risk:(privacy.tracking OR '
                                         'privacy.advertising)', 'metric': 'count',
                                'rows': 'bite.risk', 'rows_size': 10}, 'hbar'),
            _w('Who reaches risky sites', 6, {'query': 'risk_severity:(high OR medium)',
                                              'metric': 'count', 'rows': 'entity',
                                              'rows_size': 10}, 'hbar'),
        ],
    },
    {
        'key': 'network-usage', 'name': 'Network usage', 'icon': 'activity',
        'description': 'What the network is used for, and by how many.',
        'time_range': {'from': 'now-7d', 'to': 'now'},
        'widgets': [
            _w('Events by type', 8, {'query': '', 'metric': 'count', 'over_time': True,
                                     'split': 'bite.type', 'split_size': 3}, 'area'),
            _w('Active users', 4, {'query': '', 'metric': 'unique', 'metric_field': 'bite.client_user',
                                   'over_time': True}, 'line'),
            _w('Purposes', 6, {'query': 'has:purpose', 'metric': 'count', 'rows': 'bite.purpose',
                               'rows_size': 12}, 'hbar'),
            _w('Services', 6, {'query': 'has:service', 'metric': 'count', 'rows': 'bite.service',
                               'rows_size': 12}, 'hbar'),
            _w('Top domains', 12, {'query': 'NOT incidental:true', 'metric': 'count',
                                   'rows': 'bite.registrable_domain', 'rows_size': 15,
                                   'split': 'bite.type', 'split_size': 2}, 'table'),
        ],
    },
    {
        'key': 'dns-health', 'name': 'DNS health', 'icon': 'radio-tower',
        'description': 'Failures, reverse lookups and how well the lists cover traffic.',
        'time_range': {'from': 'now-24h', 'to': 'now'},
        'widgets': [
            _w('Responses over time', 8, {'query': 'type:dns', 'metric': 'count', 'over_time': True,
                                          'split': 'bite.response_code', 'split_size': 4}, 'stacked'),
            _w('Reverse lookups', 4, {'query': 'type:dns', 'metric': 'count',
                                      'rows': 'bite.ptr_status', 'rows_size': 6}, 'hbar'),
            _w('Most failed names', 6, {'query': 'rcode:NXDOMAIN', 'metric': 'count',
                                        'rows': 'bite.requested', 'rows_size': 12}, 'hbar'),
            _w('Clients with most failures', 6, {'query': 'rcode:NXDOMAIN', 'metric': 'count',
                                                 'rows': 'entity', 'rows_size': 12}, 'hbar'),
            _w('Uncategorised domains', 12, {'query': 'type:dns AND NOT has:category',
                                             'metric': 'count', 'rows': 'bite.registrable_domain',
                                             'rows_size': 15}, 'table'),
        ],
    },
]


class DashboardBody(BaseModel):
    """A dashboard: its name, look, widgets and default range, and whether others can see it."""

    name: str = Field(min_length=1, max_length=200)
    description: str = Field('', max_length=2000)
    icon: str = Field('layout-dashboard', max_length=40)
    widgets: list[dict] = Field(default_factory=list, max_length=MAX_WIDGETS)
    time_range: dict = Field(default_factory=dict)
    shared: bool = False


class SavedSearchBody(BaseModel):
    """A search to keep: its query, range and columns, and whether it is shared or pinned."""

    name: str = Field(min_length=1, max_length=200)
    description: str = Field('', max_length=2000)
    query: str = Field('', max_length=20000)
    time_range: dict = Field(default_factory=dict)
    columns: list[str] = Field(default_factory=list, max_length=40)
    shared: bool = False
    pinned: bool = False


def _check_widgets(widgets: list[dict]) -> list[dict]:
    if len(json.dumps(widgets)) > MAX_WIDGETS_BYTES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'This dashboard is too large.')
    for widget in widgets:
        if widget.get('type') not in WIDGET_TYPES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                f'Widget type is one of {", ".join(WIDGET_TYPES)}')
        if widget.get('viz') and widget['viz'] not in VIZ:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f'Widget viz is one of {", ".join(VIZ)}')
        if widget.get('span', 6) not in (3, 4, 6, 8, 12):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Widget span is 3, 4, 6, 8 or 12')
        widget.setdefault('id', str(uuid.uuid4())[:8])
    return widgets


async def sync_builtin_dashboards(db: AsyncSession) -> None:
    """Writes the built-in dashboards as they ship, adding any that are missing."""
    # Several console processes may start at once; they take turns
    await db.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': engine.SYNC_LOCK})
    existing = {d.builtin_key: d for d in (await db.execute(
        select(Dashboard).where(Dashboard.builtin_key.is_not(None)))).scalars()}
    for spec in BUILTIN_DASHBOARDS:
        board = existing.get(spec['key'])
        if board is None:
            board = Dashboard(builtin_key=spec['key'], shared=True)
            db.add(board)
        board.name = spec['name']
        board.description = spec['description']
        board.icon = spec['icon']
        # Built-in dashboards are read-only, so the shipped layout always wins
        board.widgets = spec['widgets']
        board.time_range = spec['time_range']
    await db.commit()


def _visible(principal: Principal):
    return or_(Dashboard.owner_id == principal.user.id, Dashboard.shared.is_(True),
               Dashboard.builtin_key.is_not(None))


async def _get_dashboard(db: AsyncSession, dashboard_id: str, principal: Principal,
                         write: bool = False) -> Dashboard:
    board = await db.get(Dashboard, parse_uuid(dashboard_id, 'That dashboard'))
    if board is None or not (board.owner_id == principal.user.id or board.shared
                             or board.builtin_key):
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That dashboard does not exist')
    if write:
        if board.builtin_key:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                'Built-in dashboards cannot be changed; clone this one first.')
        if board.owner_id != principal.user.id and principal.user.role != 'admin':
            raise HTTPException(status.HTTP_403_FORBIDDEN, 'Only its owner can change this dashboard.')
    return board


@router.get('/dashboards')
async def list_dashboards(principal: Principal = Depends(require(rbac.DASHBOARDS_READ)),
                          db: AsyncSession = Depends(get_session)) -> list[dict]:
    """The dashboards the caller can see, the built-in ones first, then by name."""
    rows = (await db.execute(select(Dashboard).where(_visible(principal))
                             .order_by(Dashboard.builtin_key.is_(None), Dashboard.name))).scalars().all()
    return [dashboard_out(d, principal.user.id) for d in rows]


@router.post('/dashboards', status_code=status.HTTP_201_CREATED)
async def create_dashboard(body: DashboardBody, request: Request,
                           principal: Principal = Depends(require(rbac.DASHBOARDS_WRITE)),
                           db: AsyncSession = Depends(get_session)) -> dict:
    """Makes a dashboard, owned by the caller."""
    board = Dashboard(owner_id=principal.user.id, name=body.name.strip(),
                      description=body.description, icon=body.icon,
                      widgets=_check_widgets(body.widgets), time_range=body.time_range,
                      shared=body.shared)
    db.add(board)
    await db.flush()
    audit.record(db, 'dashboard.create', principal=principal, request=request,
                 target_type='dashboard', target_id=board.id, target_label=board.name)
    await db.commit()
    await db.refresh(board)
    return dashboard_out(board, principal.user.id)


@router.get('/dashboards/{dashboard_id}')
async def get_dashboard(dashboard_id: str,
                        principal: Principal = Depends(require(rbac.DASHBOARDS_READ)),
                        db: AsyncSession = Depends(get_session)) -> dict:
    """One dashboard, if the caller can see it."""
    return dashboard_out(await _get_dashboard(db, dashboard_id, principal), principal.user.id)


@router.put('/dashboards/{dashboard_id}')
async def update_dashboard(dashboard_id: str, body: DashboardBody, request: Request,
                           principal: Principal = Depends(require(rbac.DASHBOARDS_WRITE)),
                           db: AsyncSession = Depends(get_session)) -> dict:
    """Replaces a dashboard, for its owner or an admin. Built-in dashboards cannot be changed."""
    board = await _get_dashboard(db, dashboard_id, principal, write=True)
    board.name = body.name.strip()
    board.description = body.description
    board.icon = body.icon
    board.widgets = _check_widgets(body.widgets)
    board.time_range = body.time_range
    board.shared = body.shared
    audit.record(db, 'dashboard.update', principal=principal, request=request,
                 target_type='dashboard', target_id=board.id, target_label=board.name)
    await db.commit()
    await db.refresh(board)
    return dashboard_out(board, principal.user.id)


@router.post('/dashboards/{dashboard_id}/clone', status_code=status.HTTP_201_CREATED)
async def clone_dashboard(dashboard_id: str, request: Request,
                          principal: Principal = Depends(require(rbac.DASHBOARDS_WRITE)),
                          db: AsyncSession = Depends(get_session)) -> dict:
    """Copies a dashboard the caller can see, built-in ones included, into a new unshared one of their own."""
    source = await _get_dashboard(db, dashboard_id, principal)
    board = Dashboard(owner_id=principal.user.id, name=f'{source.name} (copy)'[:200],
                      description=source.description, icon=source.icon,
                      widgets=json.loads(json.dumps(source.widgets or [])),
                      time_range=dict(source.time_range or {}), shared=False)
    db.add(board)
    await db.flush()
    audit.record(db, 'dashboard.create', principal=principal, request=request,
                 target_type='dashboard', target_id=board.id, target_label=board.name,
                 details={'cloned_from': str(source.id)})
    await db.commit()
    await db.refresh(board)
    return dashboard_out(board, principal.user.id)


@router.delete('/dashboards/{dashboard_id}')
async def delete_dashboard(dashboard_id: str, request: Request,
                           principal: Principal = Depends(require(rbac.DASHBOARDS_WRITE)),
                           db: AsyncSession = Depends(get_session)) -> dict:
    """Deletes a dashboard, for its owner or an admin. Built-in dashboards cannot be deleted."""
    board = await _get_dashboard(db, dashboard_id, principal, write=True)
    audit.record(db, 'dashboard.delete', principal=principal, request=request,
                 target_type='dashboard', target_id=board.id, target_label=board.name)
    await db.delete(board)
    await db.commit()
    return {'ok': True}


# -- saved searches -------------------------------------------------------------

async def _get_search(db: AsyncSession, search_id: str, principal: Principal,
                      write: bool = False) -> SavedSearch:
    saved = await db.get(SavedSearch, parse_uuid(search_id, 'That search'))
    if saved is None or not (saved.owner_id == principal.user.id or saved.shared):
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That search does not exist')
    if write and saved.owner_id != principal.user.id and principal.user.role != 'admin':
        raise HTTPException(status.HTTP_403_FORBIDDEN, 'Only its owner can change this search.')
    return saved


@router.get('/saved-searches')
async def list_searches(principal: Principal = Depends(require(rbac.DASHBOARDS_READ)),
                        db: AsyncSession = Depends(get_session)) -> list[dict]:
    """The saved searches the caller can see, their own and shared ones, pinned first."""
    rows = (await db.execute(select(SavedSearch).where(or_(
        SavedSearch.owner_id == principal.user.id, SavedSearch.shared.is_(True)))
        .order_by(SavedSearch.pinned.desc(), SavedSearch.name))).scalars().all()
    return [saved_search_out(s, principal.user.id) for s in rows]


@router.post('/saved-searches', status_code=status.HTTP_201_CREATED)
async def create_search(body: SavedSearchBody, request: Request,
                        principal: Principal = Depends(require(rbac.DASHBOARDS_WRITE)),
                        db: AsyncSession = Depends(get_session)) -> dict:
    """Saves a search, owned by the caller."""
    saved = SavedSearch(owner_id=principal.user.id, **body.model_dump())
    db.add(saved)
    await db.flush()
    # A saved search can name a person, and a shared one shows it to everyone
    audit.record(db, 'search.save', principal=principal, request=request,
                 target_type='saved_search', target_id=saved.id, target_label=saved.name,
                 details={'query': saved.query, 'shared': saved.shared})
    await db.commit()
    await db.refresh(saved)
    return saved_search_out(saved, principal.user.id)


@router.put('/saved-searches/{search_id}')
async def update_search(search_id: str, body: SavedSearchBody, request: Request,
                        principal: Principal = Depends(require(rbac.DASHBOARDS_WRITE)),
                        db: AsyncSession = Depends(get_session)) -> dict:
    """Replaces a saved search, for its owner or an admin."""
    saved = await _get_search(db, search_id, principal, write=True)
    for name, value in body.model_dump().items():
        setattr(saved, name, value)
    audit.record(db, 'search.update', principal=principal, request=request,
                 target_type='saved_search', target_id=saved.id, target_label=saved.name,
                 details={'query': saved.query, 'shared': saved.shared})
    await db.commit()
    await db.refresh(saved)
    return saved_search_out(saved, principal.user.id)


@router.delete('/saved-searches/{search_id}')
async def delete_search(search_id: str, request: Request,
                        principal: Principal = Depends(require(rbac.DASHBOARDS_WRITE)),
                        db: AsyncSession = Depends(get_session)) -> dict:
    """Deletes a saved search, for its owner or an admin."""
    saved = await _get_search(db, search_id, principal, write=True)
    audit.record(db, 'search.delete', principal=principal, request=request,
                 target_type='saved_search', target_id=saved.id, target_label=saved.name,
                 details={'query': saved.query})
    await db.delete(saved)
    await db.commit()
    return {'ok': True}
