"""Searching events: the explorer, field values, one document, export and live tail."""

import asyncio
import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..config import get_settings
from ..db import get_session
from ..deps import Principal, require, search_client
from ..search import fields as F
from ..search import queries as Q
from ..search import tbql
from ..search.client import SearchClient, total
from ..search.timerange import auto_interval, interval_seconds, iso
from ..security import rbac
from .common import time_range

router = APIRouter(tags=['events'])

MAX_WINDOW = 10000
EXPORT_LIMIT = 10000
_INDEX_RE = re.compile(r'^[a-z0-9][a-z0-9._\-]{0,254}$')


class RangeBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    query: str = Field('', max_length=20000)
    start: str | None = Field(None, alias='from')
    end: str | None = Field(None, alias='to')


class SearchBody(RangeBody):
    size: int = Field(50, ge=1, le=500)
    offset: int = Field(0, ge=0, le=MAX_WINDOW)
    sort: Literal['desc', 'asc'] = 'desc'


class HistogramBody(RangeBody):
    interval: str = 'auto'
    split: Literal['none', 'type', 'severity'] = 'severity'


class TopBody(RangeBody):
    field: str
    size: int = Field(10, ge=1, le=100)


class ExportBody(RangeBody):
    format: Literal['csv', 'ndjson'] = 'csv'
    columns: list[str] = Field(default_factory=list, max_length=40)
    limit: int = Field(1000, ge=1, le=EXPORT_LIMIT)


class ValidateBody(BaseModel):
    query: str = Field('', max_length=20000)


def _hit_out(hit: dict) -> dict:
    return {'id': hit.get('_id'), 'index': hit.get('_index'), 'source': hit.get('_source') or {},
            'sort': hit.get('sort')}


@router.get('/fields')
async def list_fields(_: Principal = Depends(require(rbac.EVENTS_READ))) -> dict:
    return {'fields': F.catalog(), 'entity': {'name': F.ENTITY, 'label': F.ENTITY_LABEL,
                                              'fields': list(F.ENTITY_FIELDS)}}


def prefix_pattern(prefix: str) -> str:
    """A Lucene regular expression for values starting with `prefix`, in either
    case, since values keep theirs (NXDOMAIN, lab-12). Everything but letters
    and digits is escaped: Lucene gives @, &, ~, < and # meanings Python's
    re.escape does not know about."""
    out = []
    for ch in prefix:
        if ch.isalpha() and ch.isascii():
            out.append(f'[{ch.lower()}{ch.upper()}]')
        elif ch.isascii() and ch.isdigit():
            out.append(ch)
        else:
            out.append('\\' + ch)
    return ''.join(out) + '.*'


@router.get('/fields/{name}/values')
async def field_values(name: str, prefix: str = '', start: str | None = None,
                       _: Principal = Depends(require(rbac.EVENTS_READ)),
                       search: SearchClient = Depends(search_client)) -> dict:
    """Common values of a field, for autocompleting the search bar."""
    f = F.resolve(name)
    if f is None or not f.aggregatable or f.type not in ('keyword', 'boolean'):
        return {'field': name, 'values': []}
    if f.type == 'boolean':
        return {'field': f.name, 'values': [{'key': 'true'}, {'key': 'false'}]}
    tr = time_range(start, None, 'now-7d')
    agg: dict = {'terms': {'field': f.name, 'size': 15}}
    prefix = prefix.strip()[:100]
    if prefix:
        agg['terms']['include'] = prefix_pattern(prefix)
    result = await search.search({'size': 0, 'query': {'bool': {'filter': [tr.filter()]}},
                                  'aggs': {'v': agg}})
    buckets = ((result.get('aggregations') or {}).get('v') or {}).get('buckets', [])
    return {'field': f.name, 'values': [{'key': b.get('key_as_string', b['key']),
                                         'count': b['doc_count']} for b in buckets]}


@router.get('/events/freshness')
async def freshness(_: Principal = Depends(require(rbac.EVENTS_READ)),
                    search: SearchClient = Depends(search_client)) -> dict:
    """How recent the newest event is, and how many arrived in the last five minutes.

    The top bar's pipeline indicator: TurkeyBite going quiet is worth seeing
    from every page, not only from the overview.
    """
    result = await search.search({
        'size': 0, 'track_total_hits': False,
        'aggs': {'latest': {'max': {'field': '@timestamp'}},
                 'recent': {'filter': {'range': {'@timestamp': {'gte': 'now-5m'}}}}}})
    a = result.get('aggregations') or {}
    latest = (a.get('latest') or {}).get('value_as_string')
    return {'latest': latest, 'last_5m': (a.get('recent') or {}).get('doc_count', 0)}


@router.post('/query/validate')
async def validate(body: ValidateBody, _: Principal = Depends(require(rbac.EVENTS_READ))) -> dict:
    try:
        node = tbql.parse(body.query)
        tbql.to_dsl(node)
    except tbql.TbqlError as e:
        return {'ok': False, 'error': e.public()}
    return {'ok': True, 'fields': sorted(tbql.fields_used(node))}


@router.post('/events/search')
async def search_events(body: SearchBody, request: Request,
                        principal: Principal = Depends(require(rbac.EVENTS_READ)),
                        search: SearchClient = Depends(search_client),
                        db: AsyncSession = Depends(get_session)) -> dict:
    tr = time_range(body.start, body.end)
    if body.offset + body.size > MAX_WINDOW:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f'Only the first {MAX_WINDOW:,} matches can be paged through; '
                            'narrow the search.')
    result = await search.search({
        'size': body.size, 'from': body.offset, 'track_total_hits': True,
        'query': Q.bool_query(tr, body.query),
        'sort': [{'@timestamp': {'order': body.sort}}],
        '_source': {'excludes': ['packet']},
    })
    # A search that picks someone out is as much a look at them as their
    # profile, so it is recorded the same way; the first page is enough
    if body.offset == 0 and (get_settings().audit_all_searches or tbql.names_someone(body.query)):
        audit.record(db, 'events.search', principal=principal, request=request,
                     details={'query': body.query[:2000], **tr.public()})
        await db.commit()
    return {'total': total(result), 'took': result.get('took'), 'range': tr.public(),
            'hits': [_hit_out(h) for h in result.get('hits', {}).get('hits', [])]}


@router.post('/events/histogram')
async def histogram(body: HistogramBody, _: Principal = Depends(require(rbac.EVENTS_READ)),
                    search: SearchClient = Depends(search_client)) -> dict:
    tr = time_range(body.start, body.end)
    if body.interval == 'auto':
        seconds, name = auto_interval(tr)
    else:
        try:
            seconds, name = interval_seconds(body.interval), body.interval
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
        if tr.seconds / seconds > 2000:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'That interval makes too many bars.')
    sub = None
    if body.split == 'type':
        sub = {'s': {'terms': {'field': 'bite.type', 'size': 5}}}
    elif body.split == 'severity':
        sub = {'s': {'terms': {'field': 'bite.risk_severity', 'size': 5, 'missing': 'none'}}}
    result = await search.search({'size': 0, 'track_total_hits': True,
                                  'query': Q.bool_query(tr, body.query),
                                  'aggs': {'h': Q.date_histogram(name, tr, sub)}})
    buckets = ((result.get('aggregations') or {}).get('h') or {}).get('buckets', [])
    series = []
    keys: set[str] = set()
    for b in buckets:
        split = {sb['key']: sb['doc_count'] for sb in (b.get('s') or {}).get('buckets', [])}
        keys |= set(split)
        series.append({'t': b.get('key_as_string'), 'ts': b.get('key'), 'count': b['doc_count'],
                       'split': split})
    return {'interval': name, 'interval_seconds': seconds, 'total': total(result),
            'range': tr.public(), 'keys': sorted(keys), 'buckets': series}


@router.post('/events/top')
async def top_values(body: TopBody, request: Request,
                     principal: Principal = Depends(require(rbac.EVENTS_READ)),
                     search: SearchClient = Depends(search_client),
                     db: AsyncSession = Depends(get_session)) -> dict:
    """The commonest values of one field among the matching events."""
    tr = time_range(body.start, body.end)
    field_def = F.resolve(body.field)
    if body.field == F.ENTITY or (field_def is not None and field_def.identity):
        # A ranking of people is a look at them, recorded as one
        audit.record(db, 'events.top', principal=principal, request=request,
                     target_type=body.field, details={'query': body.query[:2000], **tr.public()})
        await db.commit()
    if body.field == F.ENTITY:
        groups = list(F.ENTITY_FIELDS)
        result = await search.search({'size': 0, 'track_total_hits': True,
                                      'query': Q.bool_query(tr, body.query),
                                      'aggs': Q.group_aggs(groups, body.size)})
        buckets = Q.group_buckets(result.get('aggregations') or {}, groups)[:body.size]
        return {'field': F.ENTITY, 'total': total(result),
                'values': [{'key': b['key'], 'field': b['field'], 'count': b['doc_count']}
                           for b in buckets]}
    f = F.resolve(body.field)
    if f is None or not f.aggregatable:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'{body.field!r} cannot be counted')
    result = await search.search({
        'size': 0, 'track_total_hits': True, 'query': Q.bool_query(tr, body.query),
        'aggs': {'v': {'terms': {'field': f.name, 'size': body.size}},
                 'missing': {'missing': {'field': f.name}},
                 'distinct': {'cardinality': {'field': f.name}}}})
    a = result.get('aggregations') or {}
    return {'field': f.name, 'total': total(result),
            'missing': (a.get('missing') or {}).get('doc_count', 0),
            'distinct': (a.get('distinct') or {}).get('value', 0),
            'values': [{'key': b.get('key_as_string', b['key']), 'count': b['doc_count']}
                       for b in (a.get('v') or {}).get('buckets', [])]}


@router.get('/events/doc/{index}/{doc_id}')
async def get_document(index: str, doc_id: str, request: Request,
                       principal: Principal = Depends(require(rbac.EVENTS_READ)),
                       search: SearchClient = Depends(search_client),
                       db: AsyncSession = Depends(get_session)) -> dict:
    prefix = get_settings().opensearch_index.rstrip('*')
    if not _INDEX_RE.match(index) or not index.startswith(prefix) or len(doc_id) > 512:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That event does not exist')
    hit = await search.get(index, doc_id)
    if hit is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That event does not exist')
    bite = (hit.get('_source') or {}).get('bite') or {}
    audit.record(db, 'event.view', principal=principal, request=request, target_type='event',
                 target_id=f'{index}/{doc_id}',
                 target_label=str(bite.get('client_user') or bite.get('client_hostname_short')
                                  or bite.get('client') or '')[:400] or None)
    await db.commit()
    return _hit_out(hit)


def _cell(source: dict, path: str):
    value = source
    for part in path.split('.'):
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


@router.post('/events/export')
async def export(body: ExportBody, request: Request,
                 principal: Principal = Depends(require(rbac.EVENTS_READ, rbac.EVENTS_EXPORT)),
                 search: SearchClient = Depends(search_client),
                 db: AsyncSession = Depends(get_session)):
    tr = time_range(body.start, body.end)
    columns = []
    for name in body.columns or [f.name for f in F.FIELDS if f.columns_default]:
        f = F.resolve(name)
        if f is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f'There is no field called {name!r}.')
        columns.append(f.name)
    query = Q.bool_query(tr, body.query)
    audit.record(db, 'events.export', principal=principal, request=request,
                 details={'query': body.query, 'format': body.format, 'limit': body.limit,
                          **tr.public()})
    await db.commit()

    async def rows():
        sent = 0
        page = min(1000, body.limit)
        if body.format == 'csv':
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(columns)
            yield buffer.getvalue()
        while sent < body.limit:
            result = await search.search({
                'size': min(page, body.limit - sent), 'from': sent,
                'query': query, 'sort': [{'@timestamp': {'order': 'desc'}}],
                '_source': {'excludes': ['packet']} if body.format == 'csv' else True})
            hits = result.get('hits', {}).get('hits', [])
            if not hits:
                break
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            for hit in hits:
                source = hit.get('_source') or {}
                if body.format == 'csv':
                    cells = []
                    for column in columns:
                        value = _cell(source, column)
                        if isinstance(value, list):
                            value = '|'.join(str(v) for v in value)
                        # A leading = + - @ makes a spreadsheet run the cell
                        text = '' if value is None else str(value)
                        if text[:1] in ('=', '+', '-', '@', '\t', '\r'):
                            text = "'" + text
                        cells.append(text)
                    writer.writerow(cells)
                else:
                    buffer.write(json.dumps({'_id': hit.get('_id'), '_index': hit.get('_index'),
                                             **source}) + '\n')
            sent += len(hits)
            yield buffer.getvalue()
            if len(hits) < page:
                break

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    media = 'text/csv' if body.format == 'csv' else 'application/x-ndjson'
    return StreamingResponse(rows(), media_type=media, headers={
        'Content-Disposition': f'attachment; filename="turkeybite-{stamp}.{body.format}"'})


# Live tails open at once, per person, in this process
MAX_LIVE_PER_USER = 3
_live: dict[str, int] = {}


@router.get('/events/live')
async def live(request: Request, query: str = '',
               principal: Principal = Depends(require(rbac.EVENTS_READ)),
               search: SearchClient = Depends(search_client)):
    """New matching events as server-sent events, polled every two seconds.

    Each stream holds no database connection, and a person can have only a
    few open, so tails left open in forgotten tabs cannot starve anyone.
    """
    try:
        compiled = tbql.compile(query)
    except tbql.TbqlError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, e.message) from e
    who = str(principal.user.id)
    if _live.get(who, 0) >= MAX_LIVE_PER_USER:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f'At most {MAX_LIVE_PER_USER} live tails at once; close one in another tab.')

    async def stream():
        # Counted only once the stream is running, so one that never starts
        # cannot leave the count up
        _live[who] = _live.get(who, 0) + 1
        try:
            async for chunk in _stream():
                yield chunk
        finally:
            _live[who] = max(0, _live.get(who, 1) - 1)

    async def _stream():
        since = datetime.now(timezone.utc) - timedelta(seconds=30)
        deadline = datetime.now(timezone.utc) + timedelta(minutes=30)
        seen: set[str] = set()
        yield 'retry: 5000\n\n'
        while datetime.now(timezone.utc) < deadline:
            if await request.is_disconnected():
                return
            try:
                result = await search.search({
                    'size': 100, 'sort': [{'@timestamp': {'order': 'asc'}}],
                    '_source': {'excludes': ['packet']},
                    'query': {'bool': {'filter': [
                        {'range': {'@timestamp': {'gte': iso(since)}}}, compiled]}}})
                hits = result.get('hits', {}).get('hits', [])
                fresh = [h for h in hits if h.get('_id') not in seen]
                for hit in fresh:
                    seen.add(hit.get('_id'))
                    yield f'event: hit\ndata: {json.dumps(_hit_out(hit))}\n\n'
                if hits:
                    newest = hits[-1].get('_source', {}).get('@timestamp')
                    if newest:
                        since = datetime.fromisoformat(newest.replace('Z', '+00:00'))
                if len(seen) > 5000:
                    seen.clear()
                yield ': keep-alive\n\n'
            except Exception as e:
                yield f'event: problem\ndata: {json.dumps({"message": str(e)})}\n\n'
            await asyncio.sleep(2)
        yield 'event: end\ndata: {}\n\n'

    return StreamingResponse(stream(), media_type='text/event-stream',
                             headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

