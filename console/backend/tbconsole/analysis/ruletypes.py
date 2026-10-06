"""What each kind of rule asks of OpenSearch, and what counts as a hit.

A rule is a TBQL query plus a type. The query says which events are in
scope; the type says what about them is worth a finding:

    threshold     at least N matching events
    unique_count  at least N distinct values of a field
    ratio         a share of matching events also match a second query
    spike         far more matching events than this window usually holds
    new_value     a value of a field not seen for days before
    absence       events stopped: none now, where there were some before

Each groups by the rule's group_by fields, entity by default, so one rule
raises one finding per person or machine rather than one for everybody. Most
evaluations are one aggregation request, however many groups match: the
groups that can fire are the busiest, so a terms aggregation ordered by what
the rule measures finds them. First seen and silence are the exceptions,
since what they look for is rare or absent rather than busy; they page
through every group with composite aggregations.
"""

import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..search import fields as F
from ..search import queries as Q
from ..search import tbql
from ..search.client import SearchClient, total
from ..search.timerange import TimeRange, iso

SEVERITIES = ('info', 'low', 'medium', 'high', 'critical')
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

MAX_GROUPS = 200                  # groups one terms aggregation returns, and hits kept
PAGE = 500                        # composite buckets per request
MAX_PAIRS = 5000                  # first seen: (group, value) pairs looked at
MAX_NEW = 1000                    # first seen: findings one evaluation may raise
HISTORY_CHUNK = 500               # first seen: pairs checked against history per request
RATIO_SCAN = 2000                 # ratio: groups per field ranked by share
MAX_SILENT_GROUPS = 20000         # silence: groups looked at
MAX_HISTORY = timedelta(days=90)  # the furthest back any evaluation reads


class RuleError(ValueError):
    """A rule definition that cannot be evaluated, in words for its author."""


class BudgetSpent(RuleError):
    """An evaluation asked OpenSearch more than it was allowed to."""


@dataclass
class RuleSpec:
    """The parts of a rule evaluation needs, from a Rule row or an unsaved draft."""
    name: str
    type: str
    query: str = ''
    params: dict = field(default_factory=dict)
    group_by: list = field(default_factory=list)
    window_seconds: int = 900
    interval_seconds: int = 300
    exceptions: list = field(default_factory=list)
    schedule: dict | None = None

    @property
    def exclusions(self) -> list[str]:
        """The exception queries still in force; an expired one no longer applies."""
        out = []
        now = datetime.now(timezone.utc)
        for item in self.exceptions or []:
            text = item.get('query') if isinstance(item, dict) else item
            expires = item.get('expires_at') if isinstance(item, dict) else None
            if expires:
                try:
                    if datetime.fromisoformat(str(expires).replace('Z', '+00:00')) <= now:
                        continue
                except ValueError:
                    pass
            if text and str(text).strip():
                out.append(str(text))
        return out


@dataclass
class Hit:
    entity_field: str | None
    entity_value: str | None
    count: int                      # events in the window
    recent: int                     # events since the previous run, for counting
    value: float                    # what was measured: a count, a ratio, a score
    summary: str
    evidence_query: str
    window: TimeRange
    top_domains: list = field(default_factory=list)
    top_categories: list = field(default_factory=list)
    first: str | None = None
    last: str | None = None
    extra: dict = field(default_factory=dict)
    # Part of the dedup key: a new_value rule raises one finding per value
    distinct: str = ''

    def evidence(self) -> dict:
        return {
            'query': self.evidence_query,
            'from': iso(self.window.start), 'to': iso(self.window.end),
            'count': self.count, 'value': self.value,
            'top_domains': self.top_domains, 'top_categories': self.top_categories,
            'first_event': self.first, 'last_event': self.last,
            **({'detail': self.extra} if self.extra else {}),
        }


@dataclass
class Evaluation:
    hits: list[Hit]
    status: str = 'ok'              # ok, skipped
    reason: str = ''


# -- definitions, for the editor and for validation ---------------------------------

TYPES = {
    'threshold': {
        'label': 'Threshold',
        'summary': 'At least N matching events in the window.',
        'params': {'threshold': {'type': 'int', 'min': 1, 'default': 1,
                                 'label': 'Events at least'}},
    },
    'unique_count': {
        'label': 'Distinct values',
        'summary': 'At least N distinct values of a field, such as domains per client.',
        'params': {'field': {'type': 'field', 'default': 'bite.requested',
                             'label': 'Count distinct'},
                   'threshold': {'type': 'int', 'min': 1, 'default': 100,
                                 'label': 'Distinct values at least'}},
    },
    'ratio': {
        'label': 'Ratio',
        'summary': 'A share of the matching events also match a second query.',
        'params': {'numerator': {'type': 'query', 'default': 'rcode:NXDOMAIN',
                                 'label': 'Share that match'},
                   'ratio': {'type': 'float', 'min': 0.01, 'max': 1.0, 'default': 0.5,
                             'label': 'Share at least'},
                   'min_count': {'type': 'int', 'min': 1, 'default': 50,
                                 'label': 'Only with events at least'}},
    },
    'spike': {
        'label': 'Spike',
        'summary': 'Far more matching events than the same window usually holds.',
        'params': {'baseline_windows': {'type': 'int', 'min': 3, 'max': 96, 'default': 24,
                                        'label': 'Windows of history'},
                   'z_score': {'type': 'float', 'min': 1.0, 'default': 4.0,
                               'label': 'Standard deviations above'},
                   'ratio': {'type': 'float', 'min': 1.0, 'default': 3.0,
                             'label': 'And times the average at least'},
                   'min_count': {'type': 'int', 'min': 1, 'default': 50,
                                 'label': 'Only with events at least'}},
    },
    'new_value': {
        'label': 'First seen',
        'summary': 'A value of a field that had not been seen for days before.',
        'params': {'field': {'type': 'field', 'default': 'bite.registrable_domain',
                             'label': 'New value of'},
                   'lookback_days': {'type': 'int', 'min': 1, 'max': 90, 'default': 14,
                                     'label': 'Not seen in days'}},
    },
    'absence': {
        'label': 'Silence',
        'summary': 'Events stopped: fewer than N now, or none from a group that was active.',
        'params': {'threshold': {'type': 'int', 'min': 1, 'default': 1,
                                 'label': 'Fewer events than'},
                   'lookback_seconds': {'type': 'int', 'min': 600, 'max': 30 * 86400,
                                        'default': 86400,
                                        'label': 'Active in the seconds before'},
                   'min_baseline': {'type': 'int', 'min': 1, 'default': 20,
                                    'label': 'With events at least'}},
    },
}


def _num(params: dict, name: str, kind: str, spec: dict):
    value = params.get(name, spec.get('default'))
    try:
        value = int(value) if kind == 'int' else float(value)
    except (TypeError, ValueError) as e:
        raise RuleError(f'{spec.get("label", name)} has to be a number.') from e
    if 'min' in spec and value < spec['min']:
        raise RuleError(f'{spec.get("label", name)} has to be at least {spec["min"]}.')
    if 'max' in spec and value > spec['max']:
        raise RuleError(f'{spec.get("label", name)} has to be at most {spec["max"]}.')
    return value


def normalise(spec: RuleSpec) -> dict:
    """The rule's params with defaults filled in, checked. Raises RuleError."""
    kind = TYPES.get(spec.type)
    if kind is None:
        raise RuleError(f'{spec.type!r} is not a rule type.')
    if spec.window_seconds < 60 or spec.window_seconds > 30 * 86400:
        raise RuleError('The window has to be between a minute and 30 days.')
    if spec.interval_seconds < 60 or spec.interval_seconds > 7 * 86400:
        raise RuleError('Rules can run at most every minute and at least weekly.')
    if spec.window_seconds < spec.interval_seconds:
        raise RuleError('The window has to be at least as long as the time between runs, '
                        'or events that arrive between runs are never looked at.')
    try:
        tbql.compile(spec.query or '')
        for text in spec.exclusions:
            tbql.compile(text)
    except tbql.TbqlError as e:
        raise RuleError(f'The query has a mistake: {e.message}') from e
    try:
        F.group_fields(spec.group_by or [])
    except ValueError as e:
        raise RuleError(str(e)) from e
    params = {}
    for name, pspec in kind['params'].items():
        ptype = pspec['type']
        if ptype in ('int', 'float'):
            params[name] = _num(spec.params or {}, name, ptype, pspec)
        elif ptype == 'field':
            f = F.resolve(str((spec.params or {}).get(name) or pspec['default']))
            if f is None or not f.aggregatable:
                raise RuleError(f'{pspec["label"]} has to be a field that can be counted.')
            if spec.type == 'new_value' and f.type not in ('keyword', 'ip'):
                # Every timestamp or count is new; only names and addresses can be first seen
                raise RuleError(f'{pspec["label"]} has to be a name or an address, not a '
                                f'{f.type}.')
            params[name] = f.name
        elif ptype == 'query':
            text = str((spec.params or {}).get(name) or pspec['default'])
            try:
                tbql.compile(text)
            except tbql.TbqlError as e:
                raise RuleError(f'{pspec["label"]} has a mistake: {e.message}') from e
            params[name] = text
    if spec.type == 'spike':
        history = timedelta(seconds=spec.window_seconds * (params['baseline_windows'] + 1))
        if history > MAX_HISTORY:
            raise RuleError(f'The window times the windows of history reaches back '
                            f'{history.days} days; keep it within {MAX_HISTORY.days}.')
    return params


# -- helpers --------------------------------------------------------------------

def _evidence_query(spec: RuleSpec, entity_field: str | None, entity_value, extra: str = '') -> str:
    """TBQL for the events behind a hit. Every part is bracketed, so an OR in
    one cannot reach across the ANDs that join them."""
    parts = []
    if spec.query and spec.query.strip():
        parts.append(f'({spec.query.strip()})')
    if entity_field and entity_value is not None:
        parts.append(Q.entity_term(entity_field, entity_value))
    if extra and extra.strip():
        parts.append(f'({extra.strip()})')
    for text in spec.exclusions:
        parts.append(f'NOT ({text})')
    return ' AND '.join(parts)


def _detail_aggs(recent_since: datetime | None) -> dict:
    aggs = {
        'dom': {'terms': {'field': 'bite.requested', 'size': 5}},
        'cat': {'terms': {'field': 'bite.contexts', 'size': 5}},
        'first': {'min': {'field': '@timestamp'}},
        'last': {'max': {'field': '@timestamp'}},
    }
    if recent_since is not None:
        aggs['recent'] = {'filter': {'range': {'@timestamp': {'gte': iso(recent_since)}}}}
    return aggs


def _details(bucket: dict) -> dict:
    def top(name):
        return [{'key': b.get('key'), 'count': b.get('doc_count', 0)}
                for b in (bucket.get(name) or {}).get('buckets', [])]

    def moment(name):
        part = bucket.get(name) or {}
        return part.get('value_as_string') or (
            None if part.get('value') is None else str(part.get('value')))
    return {'top_domains': top('dom'), 'top_categories': top('cat'), 'first': moment('first'),
            'last': moment('last')}


def _fmt(n: float) -> str:
    if isinstance(n, float) and not n.is_integer():
        return f'{n:,.1f}'
    return f'{int(n):,}'


def _span(seconds: float) -> str:
    seconds = int(seconds)
    for unit, size in (('day', 86400), ('hour', 3600), ('minute', 60)):
        if seconds >= size and seconds % size == 0:
            n = seconds // size
            return f'{n} {unit}{"s" if n != 1 else ""}'
    return f'{seconds} seconds'


class Evaluator:
    def __init__(self, search: SearchClient, budget: int | None = None):
        self.search = search
        # How many requests it may still send, for a backtest; None is no limit
        self.budget = budget

    async def _search(self, body: dict) -> dict:
        if self.budget is not None:
            if self.budget <= 0:
                raise BudgetSpent('This asked OpenSearch too many questions; try a shorter range.')
            self.budget -= 1
        return await self.search.search(body)

    async def evaluate(self, spec: RuleSpec, now: datetime,
                       recent_since: datetime | None = None,
                       start: datetime | None = None) -> Evaluation:
        """Evaluates `spec` over the window ending at `now`, or from `start`
        when the window has been cut short, at the start of active hours."""
        params = normalise(spec)
        full = now - timedelta(seconds=spec.window_seconds)
        if start is not None and start > full:
            if spec.type in ('spike', 'absence'):
                # Both compare a whole window with what came before; part of
                # one would look like a drop, or hide a rise
                return Evaluation([], 'skipped', 'waiting for a whole window inside its active hours')
            full = start
        window = TimeRange(full, now)
        groups = F.group_fields(spec.group_by or [])
        method = getattr(self, f'_{spec.type}')
        return await method(spec, params, window, groups, recent_since)

    async def _run(self, query: dict, aggs: dict) -> dict:
        return await self._search({'size': 0, 'track_total_hits': True, 'query': query,
                                   'aggs': aggs})

    async def _composite(self, query: dict, sources: list[tuple[str, str]], sub: dict | None,
                         limit: int) -> tuple[list[dict], bool]:
        """Every bucket of a composite aggregation, a page at a time, up to
        `limit`. Returns the buckets and whether there were more: it reads one
        past the limit to know, so a page that ends exactly there is not
        mistaken for a cut."""
        out: list[dict] = []
        after = None
        while len(out) <= limit:
            size = min(PAGE, limit + 1 - len(out))
            composite: dict = {'size': size, 'sources': [
                {name: {'terms': {'field': name_field}}} for name, name_field in sources]}
            if after:
                composite['after'] = after
            agg: dict = {'composite': composite}
            if sub:
                agg['aggs'] = sub
            result = await self._search({'size': 0, 'query': query, 'aggs': {'c': agg}})
            part = (result.get('aggregations') or {}).get('c') or {}
            buckets = part.get('buckets', [])
            out.extend(buckets)
            after = part.get('after_key')
            if not buckets or not after or len(buckets) < size:
                break
        return out[:limit], len(out) > limit

    async def _each_group(self, query: dict, groups: list[str], extra: list[tuple[str, str]],
                          sub: dict | None, limit: int) -> tuple[list[dict], bool]:
        """Composite buckets per group field, each as {field, key, ...}; with
        no groups, one field-less set. `extra` are further sources."""
        out: list[dict] = []
        truncated = False
        targets = [(i, name) for i, name in enumerate(groups)] or [(None, None)]
        for i, name in targets:
            q = query
            sources = list(extra)
            if name is not None:
                q = {'bool': {'filter': [query, Q.group_filter(groups, i)]}}
                sources = [('g', name), *extra]
            buckets, more = await self._composite(q, sources, sub, limit - len(out))
            truncated = truncated or more
            for b in buckets:
                key = b.get('key') or {}
                out.append(dict(b, field=name, key=key.get('g'),
                                values={k: v for k, v in key.items() if k != 'g'}))
        return out, truncated

    def _grouped(self, result: dict, groups: list[str]) -> list[dict]:
        if not groups:
            aggs = result.get('aggregations') or {}
            bucket = {'doc_count': total(result), **aggs.get('all', {})}
            return [dict(bucket, field=None, key=None)] if bucket['doc_count'] else []
        return Q.group_buckets(result.get('aggregations') or {}, groups)

    def _aggs(self, groups: list[str], sub: dict, order: dict | None = None,
              min_doc_count: int | None = None) -> dict:
        if groups:
            return Q.group_aggs(groups, MAX_GROUPS, sub, order, min_doc_count)
        return {'all': {'filter': {'match_all': {}}, 'aggs': sub}}

    # -- the types --------------------------------------------------------------

    async def _threshold(self, spec, params, window, groups, recent_since) -> Evaluation:
        query = Q.bool_query(window, spec.query, exclude=spec.exclusions)
        result = await self._run(query, self._aggs(groups, _detail_aggs(recent_since),
                                                   min_doc_count=params['threshold']))
        hits = []
        for b in self._grouped(result, groups):
            count = b.get('doc_count', 0)
            if count < params['threshold']:
                continue
            d = _details(b)
            hits.append(Hit(
                entity_field=b['field'], entity_value=b['key'], count=count,
                recent=(b.get('recent') or {}).get('doc_count', count), value=count,
                summary=f'{_fmt(count)} matching event{"s" if count != 1 else ""} in '
                        f'{_span(spec.window_seconds)} (threshold {_fmt(params["threshold"])}).',
                evidence_query=_evidence_query(spec, b['field'], b['key']), window=window,
                top_domains=d['top_domains'], top_categories=d['top_categories'],
                first=d['first'], last=d['last']))
        return Evaluation(hits)

    async def _unique_count(self, spec, params, window, groups, recent_since) -> Evaluation:
        target = params['field']
        sub = dict(_detail_aggs(recent_since))
        sub['distinct'] = {'cardinality': {'field': target, 'precision_threshold': 3000}}
        query = Q.bool_query(window, spec.query, exclude=spec.exclusions)
        # The groups with the most distinct values, not the most events
        result = await self._run(query, self._aggs(groups, sub, order={'distinct': 'desc'}))
        label = F.BY_NAME[target].label.lower()
        hits = []
        for b in self._grouped(result, groups):
            distinct = int((b.get('distinct') or {}).get('value') or 0)
            if distinct < params['threshold']:
                continue
            d = _details(b)
            hits.append(Hit(
                entity_field=b['field'], entity_value=b['key'], count=b.get('doc_count', 0),
                recent=(b.get('recent') or {}).get('doc_count', b.get('doc_count', 0)),
                value=distinct,
                summary=f'{_fmt(distinct)} distinct {label} values in {_span(spec.window_seconds)}'
                        f' (threshold {_fmt(params["threshold"])}).',
                evidence_query=_evidence_query(spec, b['field'], b['key']), window=window,
                top_domains=d['top_domains'], top_categories=d['top_categories'],
                first=d['first'], last=d['last'], extra={'distinct_field': target}))
        return Evaluation(hits)

    async def _ratio(self, spec, params, window, groups, recent_since) -> Evaluation:
        numerator = tbql.compile(params['numerator'])
        query = Q.bool_query(window, spec.query, exclude=spec.exclusions)
        if not groups:
            sub = dict(_detail_aggs(recent_since))
            sub['num'] = {'filter': numerator}
            candidates = self._grouped(await self._run(query, self._aggs(groups, sub)), groups)
        else:
            candidates = await self._ratio_groups(query, numerator, params, groups, recent_since)
        hits = []
        for b in candidates:
            count = b.get('doc_count', 0)
            matched = (b.get('num') or {}).get('doc_count', 0)
            if count < params['min_count'] or not count:
                continue
            share = matched / count
            if share < params['ratio']:
                continue
            d = _details(b)
            hits.append(Hit(
                entity_field=b['field'], entity_value=b['key'], count=count,
                recent=(b.get('recent') or {}).get('doc_count', count), value=round(share, 4),
                summary=f'{share:.0%} of {_fmt(count)} events match {params["numerator"]} '
                        f'(threshold {params["ratio"]:.0%}).',
                evidence_query=_evidence_query(spec, b['field'], b['key'], params['numerator']),
                window=window, top_domains=d['top_domains'], top_categories=d['top_categories'],
                first=d['first'], last=d['last'], extra={'matched': matched}))
        hits.sort(key=lambda h: h.value, reverse=True)
        return Evaluation(hits)

    async def _ratio_groups(self, query, numerator, params, groups, recent_since) -> list[dict]:
        """The groups with the highest share, not the most events: first ranked
        by share across many groups with OpenSearch working out each share,
        then the details read for the best of them alone."""
        share_aggs = {
            'num': {'filter': numerator},
            'share': {'bucket_script': {'buckets_path': {'n': 'num>_count', 'c': '_count'},
                                        'script': 'params.n / params.c'}},
            'keep': {'bucket_selector': {'buckets_path': {'s': 'share'},
                                         'script': {'source': 'params.s >= params.r',
                                                    'params': {'r': params['ratio']}}}},
            'best': {'bucket_sort': {'sort': [{'share': {'order': 'desc'}}], 'size': MAX_GROUPS}},
        }
        ranked = self._grouped(await self._run(query, {
            # Beyond the usual cap on terms: only the share and its count come back
            f'g{i}': {'filter': Q.group_filter(groups, i),
                      'aggs': {'t': {'terms': {'field': name, 'size': RATIO_SCAN,
                                               'min_doc_count': max(1, params['min_count'])},
                                     'aggs': share_aggs}}}
            for i, name in enumerate(groups)}), groups)
        best = sorted(ranked, key=lambda b: ((b.get('num') or {}).get('doc_count', 0)
                                             / max(b.get('doc_count', 1), 1)), reverse=True)[:MAX_GROUPS]
        if not best:
            return []
        keys: dict[str, list] = {}
        for b in best:
            keys.setdefault(b['field'], []).append(b['key'])
        sub = dict(_detail_aggs(recent_since))
        sub['num'] = {'filter': numerator}
        detail_query = {'bool': {'filter': [query, {'bool': {'should': [
            {'terms': {f: v}} for f, v in keys.items()], 'minimum_should_match': 1}}]}}
        aggs = {}
        for i, name in enumerate(groups):
            if name not in keys:
                continue
            terms = Q.terms_agg(name, len(keys[name]), sub)
            terms['terms']['include'] = [str(k) for k in keys[name]]
            aggs[f'g{i}'] = {'filter': Q.group_filter(groups, i), 'aggs': {'t': terms}}
        return self._grouped(await self._run(detail_query, aggs), groups)

    async def _spike(self, spec, params, window, groups, recent_since) -> Evaluation:
        n = params['baseline_windows']
        size = timedelta(seconds=spec.window_seconds)
        ranges = []
        for i in range(n, 0, -1):
            end = window.start - size * (i - 1)
            ranges.append({'key': f'b{i}', 'from': iso(end - size), 'to': iso(end)})
        ranges.append({'key': 'cur', 'from': iso(window.start), 'to': iso(window.end)})
        history = TimeRange(window.start - size * n, window.end)
        sub = {'periods': {'date_range': {'field': '@timestamp', 'ranges': ranges}}}
        detail = _detail_aggs(recent_since)
        current = {'cur': {'filter': window.filter(), 'aggs': detail}}
        sub.update(current)
        query = Q.bool_query(history, spec.query, exclude=spec.exclusions)
        if groups:
            aggs = Q.group_aggs(groups, MAX_GROUPS, sub)
            for part in aggs.values():
                part['aggs']['t']['terms']['order'] = {'cur': 'desc'}
        else:
            aggs = {'all': {'filter': {'match_all': {}}, 'aggs': sub}}
        result = await self._run(query, aggs)
        hits = []
        for b in self._grouped(result, groups):
            periods = {p['key']: p.get('doc_count', 0)
                       for p in (b.get('periods') or {}).get('buckets', [])}
            cur = periods.get('cur', 0)
            baseline = [periods.get(f'b{i}', 0) for i in range(1, n + 1)]
            mean = statistics.fmean(baseline) if baseline else 0.0
            std = statistics.pstdev(baseline) if len(baseline) > 1 else 0.0
            # A flat baseline would make any rise infinitely significant;
            # Poisson noise is the least spread a count can honestly have
            spread = max(std, math.sqrt(max(mean, 1.0)))
            z = (cur - mean) / spread
            if cur < params['min_count'] or z < params['z_score'] or cur < params['ratio'] * max(mean, 1.0):
                continue
            d = _details(b.get('cur') or {})
            hits.append(Hit(
                entity_field=b['field'], entity_value=b['key'], count=cur,
                recent=((b.get('cur') or {}).get('recent') or {}).get('doc_count', cur),
                value=round(z, 2),
                summary=f'{_fmt(cur)} events in {_span(spec.window_seconds)} against a usual '
                        f'{_fmt(round(mean, 1))}: {z:.1f} standard deviations above.',
                evidence_query=_evidence_query(spec, b['field'], b['key']), window=window,
                top_domains=d['top_domains'], top_categories=d['top_categories'],
                first=d['first'], last=d['last'],
                extra={'baseline_mean': round(mean, 2), 'baseline_std': round(std, 2),
                       'baseline': baseline}))
        return Evaluation(hits)

    async def _new_value(self, spec, params, window, groups, recent_since) -> Evaluation:
        target = params['field']
        lookback = TimeRange(window.start - timedelta(days=params['lookback_days']), window.start)
        # Every value is new to a console that has not got the history yet;
        # wait until it has rather than raising a finding for everything
        oldest = await self._search({'size': 0, 'aggs': {'oldest': {'min': {'field': '@timestamp'}}},
                                     'query': {'match_all': {}}})
        oldest_ms = ((oldest.get('aggregations') or {}).get('oldest') or {}).get('value')
        if oldest_ms is None:
            return Evaluation([], 'skipped', 'there are no events yet')
        if oldest_ms / 1000 > lookback.start.timestamp() + 3600:
            have = (window.start.timestamp() - oldest_ms / 1000) / 86400
            return Evaluation([], 'skipped', f'warming up: needs {params["lookback_days"]} days of '
                                             f'history, has {max(have, 0):.1f}')
        # Every (group, value) pair in the window, not just the busiest: a
        # value that is new is usually a rare one
        current_query = Q.bool_query(window, spec.query, exclude=spec.exclusions)
        pairs, truncated = await self._each_group(current_query, groups, [('v', target)],
                                                  _detail_aggs(recent_since), MAX_PAIRS)
        if not pairs:
            return Evaluation([])
        for p in pairs:
            p['value'] = p['values'].get('v')
        seen = await self._seen_before(spec, lookback, target, pairs)
        label = F.BY_NAME[target].label.lower()
        target_alias = F.BY_NAME[target].aliases[0] if F.BY_NAME[target].aliases else target
        fresh = [p for i, p in enumerate(pairs) if i not in seen]
        fresh.sort(key=lambda p: p.get('doc_count', 0), reverse=True)
        reason = ''
        if truncated:
            reason = f'looked at the first {MAX_PAIRS:,} values in the window'
        if len(fresh) > MAX_NEW:
            reason = f'{len(fresh):,} values were new; kept the {MAX_NEW:,} busiest'
            fresh = fresh[:MAX_NEW]
        hits = []
        for p in fresh:
            d = _details(p)
            count = p.get('doc_count', 0)
            value = p['value']
            scope = ' for this entity' if p['field'] else ''
            hits.append(Hit(
                entity_field=p['field'], entity_value=p['key'], count=count,
                recent=(p.get('recent') or {}).get('doc_count', count), value=count,
                summary=f'First seen {label} {value}: not seen in the {params["lookback_days"]} '
                        f'days before{scope}.',
                evidence_query=_evidence_query(spec, p['field'], p['key'],
                                               tbql.term_for(target_alias, value)),
                window=window, top_domains=d['top_domains'], top_categories=d['top_categories'],
                first=d['first'], last=d['last'], extra={'field': target, 'new_value': value},
                distinct=str(value)))
        return Evaluation(hits, reason=reason)

    async def _seen_before(self, spec, lookback: TimeRange, target: str, pairs: list[dict]) -> set[int]:
        """Which of `pairs` occurred in `lookback`, by index. Each pair is its
        own filter, matched on its own field, so a name is never compared with
        an address field and no answer can be cut short: the count of requests
        is fixed by the pairs, not by how much history there is."""
        base = Q.bool_query(lookback, spec.query, exclude=spec.exclusions)
        seen: set[int] = set()
        for start in range(0, len(pairs), HISTORY_CHUNK):
            chunk = pairs[start:start + HISTORY_CHUNK]
            filters = {}
            for n, p in enumerate(chunk, start=start):
                clause = [{'term': {target: p['value']}}]
                if p['field']:
                    clause.append({'term': {p['field']: p['key']}})
                filters[str(n)] = {'bool': {'filter': clause}}
            result = await self._search({'size': 0, 'query': base,
                                         'aggs': {'f': {'filters': {'filters': filters}}}})
            buckets = ((result.get('aggregations') or {}).get('f') or {}).get('buckets') or {}
            for key, bucket in buckets.items():
                if (bucket or {}).get('doc_count', 0) > 0:
                    seen.add(int(key))
        return seen

    async def _absence(self, spec, params, window, groups, recent_since) -> Evaluation:
        lookback = TimeRange(window.start - timedelta(seconds=params['lookback_seconds']),
                             window.start)
        if not groups:
            query = Q.bool_query(window, spec.query, exclude=spec.exclusions)
            count = total(await self._search({'size': 0, 'track_total_hits': True,
                                              'query': query}))
            if count >= params['threshold']:
                return Evaluation([])
            before = total(await self._search({'size': 0, 'track_total_hits': True, 'query':
                                               Q.bool_query(lookback, spec.query, exclude=spec.exclusions)}))
            if before < params['min_baseline']:
                # Quiet then, quiet now: nothing stopped
                return Evaluation([])
            return Evaluation([Hit(
                entity_field=None, entity_value=None, count=count, recent=count, value=count,
                summary=f'{_fmt(count)} matching events in the last {_span(spec.window_seconds)}, '
                        f'after {_fmt(before)} in the {_span(params["lookback_seconds"])} before.',
                evidence_query=_evidence_query(spec, None, None), window=window,
                extra={'before': before})])
        sub = {'past': {'filter': lookback.filter()}, 'now': {'filter': window.filter()},
               'last': {'max': {'field': '@timestamp'}}}
        query = Q.bool_query(TimeRange(lookback.start, window.end), spec.query,
                             exclude=spec.exclusions)
        # Every group that was active, not just the busiest: a quiet machine
        # going silent matters as much as a loud one
        buckets, truncated = await self._each_group(query, groups, [], sub, MAX_SILENT_GROUPS)
        hits = []
        for b in buckets:
            past = (b.get('past') or {}).get('doc_count', 0)
            now_count = (b.get('now') or {}).get('doc_count', 0)
            if past < params['min_baseline'] or now_count >= params['threshold']:
                continue
            last = (b.get('last') or {}).get('value_as_string')
            hits.append(Hit(
                entity_field=b['field'], entity_value=b['key'], count=now_count, recent=0,
                value=past,
                summary=f'No events for {_span(spec.window_seconds)} after {_fmt(past)} in the '
                        f'{_span(params["lookback_seconds"])} before. Last seen {last or "unknown"}.',
                evidence_query=_evidence_query(spec, b['field'], b['key']), window=window,
                last=last, extra={'before': past}))
        reason = f'looked at the first {MAX_SILENT_GROUPS:,} groups' if truncated else ''
        if len(hits) > MAX_GROUPS:
            reason = f'{len(hits):,} groups fell silent; kept the {MAX_GROUPS} that were busiest'
            hits = sorted(hits, key=lambda h: h.value, reverse=True)[:MAX_GROUPS]
        return Evaluation(hits, reason=reason)
