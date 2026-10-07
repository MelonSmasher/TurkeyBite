"""Profiles of the people and machines in the events, and of domains.

Looking at one person's profile is the most sensitive thing the console does,
so every profile view is written to the audit log, with who looked, at whom,
and over what range.
"""

import asyncio
import re
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import cast, or_, select, String
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..db import get_session
from ..deps import Principal, require, search_client
from ..models import Finding
from ..search import fields as F
from ..search import queries as Q
from ..search import tbql
from ..search.client import SearchClient, total
from ..search.timerange import TimeRange, auto_interval
from ..security import rbac
from .analytics import NOISE, NOTABLE
from .common import finding_out, like_escape, risk_scores, time_range

router = APIRouter(tags=['entities'])

_DOMAIN = re.compile(r'[a-z0-9_*-]+(\.[a-z0-9_*-]+)*\.?', re.ASCII)

IDENTITY_FIELDS = ('bite.client_user', 'bite.client_hostname_short', 'bite.client_hostname',
                   'bite.client', 'bite.client_ips', 'bite.client_hosts_short',
                   'bite.client_platform', 'bite.client_browser', 'bite.client_mac')


def _identity_field(name: str) -> str:
    f = F.resolve(name)
    if f is None or not f.identity:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'{name!r} does not identify anyone')
    return f.name


def _top(aggs: dict, name: str) -> list[dict]:
    return [{'key': b.get('key_as_string', b.get('key')), 'count': b.get('doc_count', 0)}
            for b in ((aggs or {}).get(name) or {}).get('buckets', [])]


@router.get('/entities')
async def list_entities(request: Request, *,  # pylint: disable=too-many-arguments,too-many-locals  # the whole list in one response
                        start: str | None = None, end: str | None = None,
                        query: str = '',
                        sort: str = 'notable', size: int = 50,
                        kind: Literal['all', 'user', 'host', 'ip'] = 'all',
                        principal: Principal = Depends(require(rbac.EVENTS_READ)),
                        search: SearchClient = Depends(search_client),
                        db: AsyncSession = Depends(get_session)) -> dict:
    """The people and machines in the events, each with what they did and how risky."""
    tr = time_range(start, end)
    # The list names people, narrowed or not: a look at them. Once in a
    # while for the same list, which the page asks for again as it is used
    narrowed = bool(query.strip())
    if audit.look(db, 'entities.list', principal=principal, request=request,
                  key=f'{query}|{start}|{end}|{sort}|{kind}', window=60 if narrowed else audit.LIST_LOOK_WINDOW,
                  details={'query': query[:2000], 'sort': sort, 'kind': kind, **tr.public()}):
        await db.commit()
    size = max(1, min(size, 200))
    groups = list(F.ENTITY_FIELDS)
    selected = {
        'all': groups,
        'user': ['bite.client_user'],
        'host': ['bite.client_hostname_short', 'bite.client_hosts_short'],
        'ip': ['bite.client'],
    }[kind]
    sub = {
        'notable': {'filter': NOTABLE},
        'threats': {'filter': {'prefix': {'bite.risk': 'threat.'}}},
        'last': {'max': {'field': '@timestamp'}},
        'first': {'min': {'field': '@timestamp'}},
        'domains': {'cardinality': {'field': 'bite.registrable_domain'}},
        'risks': {'terms': {'field': 'bite.risk', 'size': 3, 'exclude': list(NOISE)}},
        'platform': {'terms': {'field': 'bite.client_platform', 'size': 1}},
        'types': {'terms': {'field': 'bite.type', 'size': 2}},
    }
    aggs = Q.group_aggs(groups, size if sort != 'notable' else min(size * 3, 500), sub)
    # Keep the full identity precedence: a browser user must not become an
    # address merely because the Addresses tab is selected.
    aggs = {key: agg for i, (key, agg) in enumerate(aggs.items()) if groups[i] in selected}
    extra = ([{'bool': {'should': [Q.group_filter(groups, groups.index(field))
                                  for field in selected], 'minimum_should_match': 1}}]
             if kind != 'all' else None)
    if sort == 'notable':
        for part in aggs.values():
            part['aggs']['t']['terms']['order'] = {'notable': 'desc'}
    result = await search.search({'size': 0, 'track_total_hits': True,
                                  'query': Q.bool_query(tr, query, extra=extra), 'aggs': aggs})
    buckets = Q.group_buckets(result.get('aggregations') or {}, groups)
    if sort == 'notable':
        buckets.sort(key=lambda b: ((b.get('notable') or {}).get('doc_count', 0), b['doc_count']),
                     reverse=True)
    buckets = buckets[:size]
    scores = (await risk_scores(db, [str(b['key']) for b in buckets])
              if principal.can(rbac.FINDINGS_READ) else {})
    items = []
    for b in buckets:
        score = scores.get(str(b['key']), {})
        items.append({
            'field': b['field'], 'key': b['key'], 'label': F.BY_NAME[b['field']].label,
            'events': b['doc_count'], 'notable': (b.get('notable') or {}).get('doc_count', 0),
            'threats': (b.get('threats') or {}).get('doc_count', 0),
            'domains': int((b.get('domains') or {}).get('value') or 0),
            'first': (b.get('first') or {}).get('value_as_string'),
            'last': (b.get('last') or {}).get('value_as_string'),
            'risks': [r['key'] for r in (b.get('risks') or {}).get('buckets', [])],
            'platform': next(iter(r['key'] for r in (b.get('platform') or {}).get('buckets', [])), None),
            'types': [r['key'] for r in (b.get('types') or {}).get('buckets', [])],
            'score': score.get('score', 0), 'open_findings': score.get('findings', 0),
        })
    if sort == 'score':
        items.sort(key=lambda i: (i['score'], i['notable']), reverse=True)
    return {'range': tr.public(), 'total_events': total(result), 'items': items}


@router.get('/entities/profile')
async def profile(field: str, value: str, request: Request, *,  # pylint: disable=too-many-arguments,too-many-locals  # the whole profile in one response
                  start: str | None = None, end: str | None = None,
                  principal: Principal = Depends(require(rbac.EVENTS_READ)),
                  search: SearchClient = Depends(search_client),
                  db: AsyncSession = Depends(get_session)) -> dict:
    """Everything the events say about one person or machine over a range, with their findings and risk.

    `field` is the identity field that names them and `value` its value.
    Every view is written to the audit log.
    """
    field = _identity_field(field)
    if F.BY_NAME[field].type == 'ip' and not tbql.ip_or_net(value):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'{value!r} is not an address')
    tr = time_range(start, end, 'now-7d')
    selector = {'term': {field: value}}
    _, interval = auto_interval(tr, 72)
    aggs = {
        **{f'id_{i}': {'terms': {'field': name, 'size': 6}} for i, name in enumerate(IDENTITY_FIELDS)},
        'timeline': Q.date_histogram(interval, tr, {
            'sev': {'terms': {'field': 'bite.risk_severity', 'size': 4, 'missing': 'none'}}}),
        'domains': {'terms': {'field': 'bite.registrable_domain', 'size': 15},
                    'aggs': {'risk': {'terms': {'field': 'bite.risk', 'size': 2}},
                             'purpose': {'terms': {'field': 'bite.purpose', 'size': 1}},
                             'last': {'max': {'field': '@timestamp'}}}},
        'risky_domains': {'filter': NOTABLE, 'aggs': {
            'd': {'terms': {'field': 'bite.registrable_domain', 'size': 10},
                  'aggs': {'risk': {'terms': {'field': 'bite.risk', 'size': 2}},
                           'last': {'max': {'field': '@timestamp'}}}}}},
        'purposes': {'terms': {'field': 'bite.purpose', 'size': 12}},
        'risks': {'terms': {'field': 'bite.risk', 'size': 10}},
        'services': {'terms': {'field': 'bite.service', 'size': 10}},
        'notable': {'filter': NOTABLE},
        'distinct_domains': {'cardinality': {'field': 'bite.registrable_domain'}},
        'first': {'min': {'field': '@timestamp'}},
        'last': {'max': {'field': '@timestamp'}},
        'rcodes': {'terms': {'field': 'bite.response_code', 'size': 6}},
    }
    # Their weekly rhythm needs a week, as on the overview
    heat_tr = tr if tr.seconds >= 7 * 86400 else TimeRange(tr.end - timedelta(days=7), tr.end)
    heat_aggs = {'heat': {'date_histogram': {'field': '@timestamp', 'fixed_interval': '1h',
                                             'min_doc_count': 1},
                          'aggs': {'notable': {'filter': NOTABLE}}}}
    query = {'bool': {'filter': [tr.filter(), selector]}}
    recent_query = {'bool': {'filter': [tr.filter(), selector, NOTABLE]}}
    result, recent, heat, latest = await asyncio.gather(
        search.search({'size': 0, 'track_total_hits': True, 'query': query, 'aggs': aggs}),
        search.search({'size': 15, 'query': recent_query, '_source': {'excludes': ['packet']},
                       'sort': [{'@timestamp': {'order': 'desc'}}]}),
        search.search({'size': 0, 'query': {'bool': {'filter': [heat_tr.filter(), selector]}},
                       'aggs': heat_aggs}),
        _latest_address(search, field, value, selector))
    a = result.get('aggregations') or {}
    heat_buckets = ((heat.get('aggregations') or {}).get('heat') or {}).get('buckets', [])
    findings: list = []
    score = {'score': 0, 'findings': 0, 'by_severity': {}}
    if principal.can(rbac.FINDINGS_READ):
        findings = (await db.execute(select(Finding).where(Finding.entity_value == str(value))
                                     .order_by(Finding.last_seen.desc()).limit(30))).scalars().all()
        score = (await risk_scores(db, [str(value)])).get(str(value), score)
    audit.record(db, 'entity.view', principal=principal, request=request, target_type=field,
                 target_id=value, target_label=f'{F.BY_NAME[field].label} {value}',
                 details=tr.public())
    await db.commit()
    timeline = []
    for b in (a.get('timeline') or {}).get('buckets', []):
        sev = {s['key']: s['doc_count'] for s in (b.get('sev') or {}).get('buckets', [])}
        timeline.append({'t': b.get('key_as_string'), 'count': b['doc_count'],
                         'high': sev.get('high', 0), 'medium': sev.get('medium', 0),
                         'low': sev.get('low', 0), 'none': sev.get('none', 0)})

    def domain_rows(buckets):
        return [{'key': b['key'], 'count': b['doc_count'],
                 'risks': [r['key'] for r in (b.get('risk') or {}).get('buckets', [])],
                 'purpose': next(iter(r['key'] for r in (b.get('purpose') or {}).get('buckets', [])), None),
                 'last': (b.get('last') or {}).get('value_as_string')} for b in buckets]
    return {
        'field': field, 'value': value, 'label': F.BY_NAME[field].label, 'range': tr.public(),
        'interval': interval, 'events': total(result),
        'notable': (a.get('notable') or {}).get('doc_count', 0),
        'distinct_domains': int((a.get('distinct_domains') or {}).get('value') or 0),
        'first': (a.get('first') or {}).get('value_as_string'),
        'last': (a.get('last') or {}).get('value_as_string'),
        'identity': {name: _top(a, f'id_{i}') for i, name in enumerate(IDENTITY_FIELDS)},
        'timeline': timeline,
        'domains': domain_rows((a.get('domains') or {}).get('buckets', [])),
        'risky_domains': domain_rows(((a.get('risky_domains') or {}).get('d') or {}).get('buckets', [])),
        'purposes': _top(a, 'purposes'), 'risks': _top(a, 'risks'), 'services': _top(a, 'services'),
        'response_codes': _top(a, 'rcodes'),
        'heat': [{'t': b.get('key_as_string'), 'count': b['doc_count'],
                  'notable': (b.get('notable') or {}).get('doc_count', 0)}
                 for b in heat_buckets],
        'heat_range': heat_tr.public(),
        'recent_notable': [{'id': h['_id'], 'index': h['_index'], 'source': h['_source']}
                           for h in recent.get('hits', {}).get('hits', [])],
        'findings': [finding_out(f) for f in findings],
        'risk': score,
        'latest_address': latest,
    }


# How far back a device's latest address is looked for
LATEST_ADDRESS_DAYS = 30


async def _latest_address(search: SearchClient, field: str, value: str, selector: dict) -> dict | None:
    """The addresses a person or machine was last seen at, whatever the page's range, and when.

    A browser reports the machine's own addresses, and a lookup the address
    it came from; whichever the latest event has, IPv4 first, at most three.
    An address is its own latest address. None when none was seen in the last
    LATEST_ADDRESS_DAYS days.
    """
    if F.BY_NAME[field].type == 'ip':
        # A network is not a device's address
        return None if '/' in value else {'addresses': [value], 'at': None}
    result = await search.search({
        'size': 1, '_source': ['@timestamp', 'bite.client', 'bite.client_ips'],
        'query': {'bool': {'filter': [
            {'range': {'@timestamp': {'gte': f'now-{LATEST_ADDRESS_DAYS}d'}}}, selector,
            {'bool': {'should': [{'exists': {'field': 'bite.client'}}, {'exists': {'field': 'bite.client_ips'}}],
                      'minimum_should_match': 1}}]}},
        'sort': [{'@timestamp': {'order': 'desc'}}]})
    hits = result.get('hits', {}).get('hits', [])
    if not hits:
        return None
    source = hits[0].get('_source') or {}
    bite = source.get('bite') or {}
    found = bite.get('client_ips') or bite.get('client') or []
    found = [found] if isinstance(found, str) else [str(a) for a in found if a]
    addresses = sorted(dict.fromkeys(found), key=lambda a: ':' in a)[:3]
    return {'addresses': addresses, 'at': source.get('@timestamp')} if addresses else None


@router.get('/domains/{domain}')
async def domain_profile(domain: str, request: Request, *,  # pylint: disable=too-many-arguments,too-many-locals  # the whole profile in one response
                         start: str | None = None, end: str | None = None,
                         principal: Principal = Depends(require(rbac.EVENTS_READ)),
                         search: SearchClient = Depends(search_client),
                         db: AsyncSession = Depends(get_session)) -> dict:
    """Everything the events say about one domain, and why it is categorised as it is."""
    domain = domain.strip().lower()
    if len(domain) > 253 or not _DOMAIN.fullmatch(domain):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'That is not a domain')
    tr = time_range(start, end, 'now-7d')
    _, interval = auto_interval(tr, 72)
    selector = {'bool': {'should': [{'term': {'bite.registrable_domain': domain}},
                                    {'term': {'bite.requested': domain}}],
                         'minimum_should_match': 1}}
    groups = list(F.ENTITY_FIELDS)
    terms = {name: {'terms': {'field': f, 'size': size}} for name, f, size in (
        ('contexts', 'bite.contexts', 20), ('candidates', 'bite.contexts_candidate', 20),
        ('suppressed', 'bite.contexts_suppressed', 20), ('claims', 'bite.claims', 40),
        ('sources', 'bite.sources', 20), ('purposes', 'bite.purpose', 10),
        ('services', 'bite.service', 10), ('risks', 'bite.risk', 10),
        ('severity', 'bite.risk_severity', 3), ('subdomains', 'bite.requested', 25),
        ('cnames', 'bite.cname_chain', 15), ('resolved', 'bite.resolved_ips', 15),
        ('rcodes', 'bite.response_code', 6), ('types', 'bite.type', 3),
        ('quad9', 'bite.resolvers.quad9', 5),
        ('cf_security', 'bite.resolvers.cloudflare-security', 5),
        ('cf_family', 'bite.resolvers.cloudflare-family', 5), ('matched', 'bite.matched_on', 10),
        ('match_source', 'bite.match_source', 3), ('registrable', 'bite.registrable_domain', 3))}
    aggs = {
        **terms,
        'incidental': {'filter': {'term': {'bite.incidental': True}}},
        'timeline': Q.date_histogram(interval, tr),
        'entities': {'filter': {'match_all': {}}, 'aggs': Q.group_aggs(groups, 15, {
            'last': {'max': {'field': '@timestamp'}}})},
        'entity_count_users': {'cardinality': {'field': 'bite.client_user'}},
        'entity_count_clients': {'cardinality': {'field': 'bite.client'}},
        'first': {'min': {'field': '@timestamp'}},
        'last': {'max': {'field': '@timestamp'}},
    }
    result = await search.search({'size': 0, 'track_total_hits': True,
                                  'query': {'bool': {'filter': [tr.filter(), selector]}},
                                  'aggs': aggs})
    a = result.get('aggregations') or {}
    findings: list = []
    if principal.can(rbac.FINDINGS_READ):
        pattern = f'%{like_escape(domain)}%'
        findings = (await db.execute(select(Finding).where(or_(
            Finding.title.ilike(pattern, escape='\\'), Finding.entity_value == domain,
            cast(Finding.evidence['top_domains'], String).ilike(pattern, escape='\\')))
            .order_by(Finding.last_seen.desc()).limit(20))).scalars().all()
    audit.record(db, 'domain.view', principal=principal, request=request, target_type='domain',
                 target_id=domain, details=tr.public())
    await db.commit()
    claims = []
    for b in _top(a, 'claims'):
        category, _, source = str(b['key']).partition(':')
        claims.append({'category': category, 'source': source or '?', 'count': b['count']})
    return {
        'domain': domain, 'range': tr.public(), 'interval': interval, 'events': total(result),
        'first': (a.get('first') or {}).get('value_as_string'),
        'last': (a.get('last') or {}).get('value_as_string'),
        'registrable': _top(a, 'registrable'),
        'categories': _top(a, 'contexts'), 'candidates': _top(a, 'candidates'),
        'suppressed': _top(a, 'suppressed'), 'claims': claims, 'sources': _top(a, 'sources'),
        'purposes': _top(a, 'purposes'), 'services': _top(a, 'services'),
        'risks': _top(a, 'risks'), 'severity': _top(a, 'severity'),
        'subdomains': _top(a, 'subdomains'), 'cnames': _top(a, 'cnames'),
        'resolved': _top(a, 'resolved'), 'response_codes': _top(a, 'rcodes'),
        'types': _top(a, 'types'), 'matched_on': _top(a, 'matched'),
        'match_source': _top(a, 'match_source'),
        'resolvers': {'quad9': _top(a, 'quad9'), 'cloudflare-security': _top(a, 'cf_security'),
                      'cloudflare-family': _top(a, 'cf_family')},
        'incidental': (a.get('incidental') or {}).get('doc_count', 0),
        'timeline': [{'t': b.get('key_as_string'), 'count': b['doc_count']}
                     for b in (a.get('timeline') or {}).get('buckets', [])],
        'entities': [{'field': b['field'], 'key': b['key'], 'count': b['doc_count'],
                      'last': (b.get('last') or {}).get('value_as_string')}
                     for b in Q.group_buckets(a.get('entities') or {}, groups)[:15]],
        'users': int((a.get('entity_count_users') or {}).get('value') or 0),
        'clients': int((a.get('entity_count_clients') or {}).get('value') or 0),
        'findings': [finding_out(f) for f in findings],
    }
