"""The overview, the pivot workbench, and long-term trends."""

import asyncio
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import Field
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..analysis import engine
from ..analysis.ruletypes import SEVERITY_RANK
from ..config import get_settings
from ..db import get_session
from ..deps import Principal, require, search_client
from ..models import DailyStat, Finding
from ..search import fields as F
from ..search import queries as Q
from ..search import tbql
from ..search.client import SearchClient, total
from ..search.timerange import TimeRange, auto_interval, interval_seconds, iso
from ..security import rbac
from .common import finding_out, risk_scores, time_range
from .events import RangeBody

router = APIRouter(tags=['analytics'])

# What the overview calls risky: severities worth a person's attention.
# Tracking and advertising are low severity and on nearly every page, so
# counting them would make every network look equally on fire.
NOTABLE = {'terms': {'bite.risk_severity': ['high', 'medium']}}
THREAT = {'prefix': {'bite.risk': 'threat.'}}
NOISE = ('privacy.tracking', 'privacy.advertising')


def _buckets(aggs: dict, name: str) -> list[dict]:
    return [{'key': b.get('key_as_string', b.get('key')), 'count': b.get('doc_count', 0)}
            for b in ((aggs or {}).get(name) or {}).get('buckets', [])]


def _changes(current: dict[str, int], previous: dict[str, int], facet: str) -> list[dict]:
    out = []
    for key, count in current.items():
        before = previous.get(key, 0)
        if count < 20 and before < 20:
            continue
        change = (count - before) / max(before, 1)
        out.append({'facet': facet, 'key': key, 'count': count, 'previous': before,
                    'change': round(change, 3), 'new': before == 0})
    for key, before in previous.items():
        if key not in current and before >= 20:
            out.append({'facet': facet, 'key': key, 'count': 0, 'previous': before,
                        'change': -1.0, 'new': False})
    return out


@router.get('/overview')
async def overview(request: Request, start: str | None = None, end: str | None = None,
                   principal: Principal = Depends(require(rbac.EVENTS_READ)),
                   search: SearchClient = Depends(search_client),
                   db: AsyncSession = Depends(get_session)) -> dict:
    tr = time_range(start, end)
    # It names the riskiest people, so it is a look at them
    if audit.look(db, 'analytics.overview', principal=principal, request=request, key=f'{start}|{end}',
                  window=audit.LIST_LOOK_WINDOW, details=tr.public()):
        await db.commit()
    prev = tr.previous()
    _, interval = auto_interval(tr, 72)
    # The weekly rhythm needs a week: a shorter range shows the seven days
    # that end where it does
    heat_tr = tr if tr.seconds >= 7 * 86400 else TimeRange(tr.end - timedelta(days=7), tr.end)
    heat_interval = '1h' if heat_tr.seconds <= 31 * 86400 else '1d'
    entity_fields = list(F.ENTITY_FIELDS)
    current_aggs = {
        'timeline': Q.date_histogram(interval, tr, {
            'sev': {'terms': {'field': 'bite.risk_severity', 'size': 4, 'missing': 'none'}}}),
        'clients': {'cardinality': {'field': 'bite.client'}},
        'users': {'cardinality': {'field': 'bite.client_user'}},
        'hosts': {'cardinality': {'field': 'bite.client_hostname_short'}},
        'domains': {'cardinality': {'field': 'bite.registrable_domain'}},
        'notable': {'filter': NOTABLE},
        'threats': {'filter': THREAT},
        'categorised': {'filter': {'exists': {'field': 'bite.contexts'}}},
        'noise': {'filter': {'terms': {'bite.risk': list(NOISE)}}},
        'risk': {'filter': {'bool': {'must_not': [{'terms': {'bite.risk': list(NOISE)}}]}},
                 'aggs': {'t': {'terms': {'field': 'bite.risk', 'size': 30,
                                          'exclude': list(NOISE)}}}},
        'purpose': {'terms': {'field': 'bite.purpose', 'size': 30}},
        'service': {'terms': {'field': 'bite.service', 'size': 30}},
        'types': {'terms': {'field': 'bite.type', 'size': 5}},
        'risky_entities': {'filter': NOTABLE, 'aggs': Q.group_aggs(entity_fields, 8, {
            'last': {'max': {'field': '@timestamp'}},
            'risks': {'terms': {'field': 'bite.risk', 'size': 3, 'exclude': list(NOISE)}}})},
    }
    heat_aggs = {
        'heat': {'date_histogram': {'field': '@timestamp', 'fixed_interval': heat_interval,
                                    'min_doc_count': 1},
                 'aggs': {'notable': {'filter': NOTABLE}}},
    }
    previous_aggs = {
        'clients': {'cardinality': {'field': 'bite.client'}},
        'users': {'cardinality': {'field': 'bite.client_user'}},
        'notable': {'filter': NOTABLE},
        'threats': {'filter': THREAT},
        'risk': {'terms': {'field': 'bite.risk', 'size': 30, 'exclude': list(NOISE)}},
        'purpose': {'terms': {'field': 'bite.purpose', 'size': 30}},
        'service': {'terms': {'field': 'bite.service', 'size': 30}},
    }
    current, previous, latest, heat = await asyncio.gather(
        search.search({'size': 0, 'track_total_hits': True,
                       'query': {'bool': {'filter': [tr.filter()]}}, 'aggs': current_aggs}),
        search.search({'size': 0, 'track_total_hits': True,
                       'query': {'bool': {'filter': [prev.filter()]}}, 'aggs': previous_aggs}),
        search.search({'size': 0, 'aggs': {'latest': {'max': {'field': '@timestamp'}}}}),
        search.search({'size': 0, 'query': {'bool': {'filter': [heat_tr.filter()]}},
                       'aggs': heat_aggs}),
    )
    heat_buckets = ((heat.get('aggregations') or {}).get('heat') or {}).get('buckets', [])
    a = current.get('aggregations') or {}
    p = previous.get('aggregations') or {}

    timeline = []
    for b in (a.get('timeline') or {}).get('buckets', []):
        sev = {s['key']: s['doc_count'] for s in (b.get('sev') or {}).get('buckets', [])}
        timeline.append({'t': b.get('key_as_string'), 'count': b['doc_count'],
                         'high': sev.get('high', 0), 'medium': sev.get('medium', 0),
                         'low': sev.get('low', 0), 'none': sev.get('none', 0)})

    def as_map(aggs, name, inner=None):
        part = (aggs or {}).get(name) or {}
        if inner:
            part = part.get(inner) or {}
        return {b['key']: b['doc_count'] for b in part.get('buckets', [])}
    changes = (_changes(as_map(a, 'risk', 't'), as_map(p, 'risk'), 'risk')
               + _changes(as_map(a, 'purpose'), as_map(p, 'purpose'), 'purpose')
               + _changes(as_map(a, 'service'), as_map(p, 'service'), 'service'))
    changes.sort(key=lambda c: abs(c['change']) * min(1.0, max(c['count'], c['previous']) / 100),
                 reverse=True)

    risky_entities = Q.group_buckets((a.get('risky_entities') or {}), entity_fields)[:8]
    # Findings come from the console's own records, and only for those who
    # may read findings: an events-only API key gets the events alone
    can_findings = principal.can(rbac.FINDINGS_READ)
    scores = await risk_scores(db, [str(b['key']) for b in risky_entities]) if can_findings else {}
    open_counts: dict = {}
    created_now = created_before = 0
    latest_findings: list = []
    if can_findings:
        open_counts = dict((await db.execute(
            select(Finding.severity, func.count()).where(Finding.status.in_(engine.OPEN))
            .group_by(Finding.severity))).all())
        created_now = (await db.execute(select(func.count()).select_from(Finding).where(
            Finding.created_at >= tr.start, Finding.created_at < tr.end))).scalar_one()
        created_before = (await db.execute(select(func.count()).select_from(Finding).where(
            Finding.created_at >= prev.start, Finding.created_at < prev.end))).scalar_one()
        rank = case({s: i for s, i in SEVERITY_RANK.items()}, value=Finding.severity, else_=0)
        latest_findings = (await db.execute(
            select(Finding).where(Finding.status.in_(engine.OPEN))
            .order_by(rank.desc(), Finding.last_seen.desc()).limit(6))).scalars().all()

    latest_ms = ((latest.get('aggregations') or {}).get('latest') or {}).get('value')
    total_now, total_before = total(current), total(previous)

    def kpi(now_value, before_value):
        return {'value': now_value, 'previous': before_value,
                'change': None if not before_value else round((now_value - before_value) / before_value, 4)}

    return {
        'range': tr.public(), 'previous_range': prev.public(), 'interval': interval,
        'kpis': {
            'events': kpi(total_now, total_before),
            'notable': kpi((a.get('notable') or {}).get('doc_count', 0),
                           (p.get('notable') or {}).get('doc_count', 0)),
            'threats': kpi((a.get('threats') or {}).get('doc_count', 0),
                           (p.get('threats') or {}).get('doc_count', 0)),
            'clients': kpi(int((a.get('clients') or {}).get('value') or 0),
                           int((p.get('clients') or {}).get('value') or 0)),
            'users': kpi(int((a.get('users') or {}).get('value') or 0),
                         int((p.get('users') or {}).get('value') or 0)),
            'findings': kpi(created_now, created_before),
        },
        'coverage': {
            'categorised': (a.get('categorised') or {}).get('doc_count', 0),
            'noise': (a.get('noise') or {}).get('doc_count', 0),
            'domains': int((a.get('domains') or {}).get('value') or 0),
            'hosts': int((a.get('hosts') or {}).get('value') or 0),
        },
        'freshness': {'latest_event': iso(datetime.fromtimestamp(latest_ms / 1000, tz=timezone.utc))
                      if latest_ms else None},
        'timeline': timeline,
        'types': _buckets(a, 'types'),
        'top_risks': _buckets(a.get('risk') or {}, 't')[:8],
        'top_purposes': _buckets(a, 'purpose')[:10],
        'top_services': _buckets(a, 'service')[:10],
        'changes': changes[:8],
        'risky_entities': [{
            'field': b['field'], 'key': b['key'], 'count': b['doc_count'],
            'last': (b.get('last') or {}).get('value_as_string'),
            'risks': [r['key'] for r in (b.get('risks') or {}).get('buckets', [])],
            'score': scores.get(str(b['key']), {}).get('score', 0),
            'open_findings': scores.get(str(b['key']), {}).get('findings', 0),
        } for b in risky_entities],
        'heat': [{'t': b.get('key_as_string'), 'count': b['doc_count'],
                  'notable': (b.get('notable') or {}).get('doc_count', 0)}
                 for b in heat_buckets],
        'heat_interval': heat_interval, 'heat_range': heat_tr.public(),
        'findings': {
            'open': {s: int(open_counts.get(s, 0)) for s in ('critical', 'high', 'medium', 'low', 'info')},
            'latest': [finding_out(f) for f in latest_findings],
        },
    }


class PivotBody(RangeBody):
    metric: Literal['count', 'unique'] = 'count'
    metric_field: str | None = None
    rows: str | None = None
    rows_size: int = Field(10, ge=1, le=100)
    split: str | None = None
    split_size: int = Field(5, ge=1, le=20)
    over_time: bool = False
    interval: str = 'auto'


def _resolve(name: str | None, what: str) -> str | None:
    if not name:
        return None
    if name == F.ENTITY:
        return F.ENTITY
    f = F.resolve(name)
    if f is None or not f.aggregatable:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'{what}: {name!r} cannot be grouped')
    return f.name


def _terms(field: str, size: int, sub: dict | None) -> dict:
    if field == F.ENTITY:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'entity can only be the rows')
    return Q.terms_agg(field, size, sub)


@router.post('/analytics/pivot')
async def pivot(body: PivotBody, request: Request,
                principal: Principal = Depends(require(rbac.EVENTS_READ)),
                search: SearchClient = Depends(search_client),
                db: AsyncSession = Depends(get_session)) -> dict:
    """Counts or distinct counts, by up to two fields, or over time."""
    tr = time_range(body.start, body.end)
    rows = _resolve(body.rows, 'Rows')
    split = _resolve(body.split, 'Split')
    # A pivot that ranks people, or narrows to someone, is a look at them
    by_people = [f for f in (rows, split) if f and (f == F.ENTITY or F.BY_NAME[f].identity)]
    if by_people or get_settings().audit_all_searches or tbql.names_someone(body.query):
        if audit.look(db, 'analytics.pivot', principal=principal, request=request,
                      key=f'{body.query}|{rows}|{split}|{body.start}|{body.end}',
                      target_type=by_people[0] if by_people else None,
                      details={'query': body.query[:2000], 'rows': rows, 'split': split, **tr.public()}):
            await db.commit()
    metric_field = _resolve(body.metric_field, 'Metric') if body.metric == 'unique' else None
    if body.metric == 'unique' and (not metric_field or metric_field == F.ENTITY):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Choose a field to count distinct values of')
    metric = {'m': {'cardinality': {'field': metric_field}}} if metric_field else None

    def value(bucket: dict) -> float:
        if metric_field:
            return (bucket.get('m') or {}).get('value') or 0
        return bucket.get('doc_count', 0)

    query = Q.bool_query(tr, body.query)
    if body.over_time:
        if body.interval == 'auto':
            seconds, name = auto_interval(tr, 120)
        else:
            seconds, name = interval_seconds(body.interval), body.interval
            if tr.seconds / seconds > 2000:
                raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                    'That interval makes too many buckets; choose a longer one.')
        sub = metric
        if split:
            sub = {'s': _terms(split, body.split_size, metric)}
        result = await search.search({'size': 0, 'track_total_hits': True, 'query': query,
                                      'aggs': {'h': Q.date_histogram(name, tr, sub)}})
        series: dict[str, list] = defaultdict(list)
        times = []
        for b in ((result.get('aggregations') or {}).get('h') or {}).get('buckets', []):
            times.append(b.get('key_as_string'))
            if split:
                seen = {sb.get('key_as_string', sb['key']): value(sb)
                        for sb in (b.get('s') or {}).get('buckets', [])}
                for key in seen:
                    series.setdefault(str(key), [])
                for key in list(series):
                    series[key].append(seen.get(key, 0))
            else:
                series['All'].append(value(b))
        # Keys first seen part way through are padded at the front
        width = len(times)
        out = [{'key': k, 'points': [0] * (width - len(v)) + v, 'total': sum(v)}
               for k, v in series.items()]
        out.sort(key=lambda s: s['total'], reverse=True)
        return {'kind': 'series', 'interval': name, 'interval_seconds': seconds,
                'times': times, 'series': out[:body.split_size if split else 1],
                'total': total(result), 'range': tr.public()}

    sub = metric
    if split:
        sub = dict(sub or {})
        sub['s'] = _terms(split, body.split_size, metric)
    if rows == F.ENTITY:
        groups = list(F.ENTITY_FIELDS)
        result = await search.search({'size': 0, 'track_total_hits': True, 'query': query,
                                      'aggs': Q.group_aggs(groups, body.rows_size, sub)})
        buckets = Q.group_buckets(result.get('aggregations') or {}, groups)[:body.rows_size]
    elif rows:
        result = await search.search({'size': 0, 'track_total_hits': True, 'query': query,
                                      'aggs': {'r': _terms(rows, body.rows_size, sub)}})
        buckets = [dict(b, key=b.get('key_as_string', b['key']))
                   for b in ((result.get('aggregations') or {}).get('r') or {}).get('buckets', [])]
    else:
        aggs = dict(sub or {})
        result = await search.search({'size': 0, 'track_total_hits': True, 'query': query,
                                      'aggs': aggs} if aggs else
                                     {'size': 0, 'track_total_hits': True, 'query': query})
        buckets = [dict((result.get('aggregations') or {}), key='All', doc_count=total(result))]
    columns: list[str] = []
    out_rows = []
    for b in buckets:
        cells = {}
        for sb in (b.get('s') or {}).get('buckets', []):
            key = str(sb.get('key_as_string', sb['key']))
            cells[key] = value(sb)
            if key not in columns:
                columns.append(key)
        out_rows.append({'key': b.get('key'), 'field': b.get('field'), 'value': value(b),
                         'cells': cells})
    return {'kind': 'table', 'rows': out_rows, 'columns': columns, 'total': total(result),
            'range': tr.public()}


@router.get('/trends')
async def trends(days: int = 90, _: Principal = Depends(require(rbac.EVENTS_READ)),
                 db: AsyncSession = Depends(get_session),
                 search: SearchClient = Depends(search_client)) -> dict:
    """Daily counts from the rollups, which outlive the indices."""
    if days < 7 or days > 730:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'days is between 7 and 730')
    today = datetime.now(timezone.utc).date()
    first = today - timedelta(days=days - 1)
    rows = (await db.execute(select(DailyStat).where(DailyStat.day >= first)
                             .order_by(DailyStat.day))).scalars().all()
    by_day: dict = defaultdict(lambda: defaultdict(dict))
    for row in rows:
        by_day[row.day][row.dimension][row.key] = row.count
    dates = [first + timedelta(days=i) for i in range(days)]

    def series(dimension: str, key: str = '') -> list[int]:
        return [int(by_day[d][dimension].get(key, 0)) if d in by_day else 0 for d in dates]

    def top_keys(dimension: str, n: int, exclude=()) -> list[str]:
        sums: dict[str, int] = defaultdict(int)
        for d in dates:
            for key, count in by_day[d][dimension].items() if d in by_day else ():
                if key not in exclude:
                    sums[key] += count
        return [k for k, _ in sorted(sums.items(), key=lambda kv: kv[1], reverse=True)[:n]]

    counted = sorted(by_day)
    oldest_event = None
    try:
        res = await search.search({'size': 0, 'aggs': {'o': {'min': {'field': '@timestamp'}}}})
        value = ((res.get('aggregations') or {}).get('o') or {}).get('value')
        if value:
            oldest_event = iso(datetime.fromtimestamp(value / 1000, tz=timezone.utc))
    except Exception:
        oldest_event = None
    return {
        'days': [d.isoformat() for d in dates],
        'total': series('total'),
        'notable': [h + m for h, m in zip(series('severity', 'high'), series('severity', 'medium'))],
        'severity': {s: series('severity', s) for s in ('high', 'medium', 'low')},
        'types': {t: series('type', t) for t in top_keys('type', 4)},
        'clients': series('unique', 'clients'),
        'users': series('unique', 'users'),
        'risks': {k: series('risk', k) for k in top_keys('risk', 6, exclude=NOISE)},
        'purposes': {k: series('purpose', k) for k in top_keys('purpose', 8)},
        'nxdomain': series('response_code', 'NXDOMAIN'),
        'coverage': {'first_counted_day': counted[0].isoformat() if counted else None,
                     'days_counted': len(counted), 'oldest_event': oldest_event},
    }
