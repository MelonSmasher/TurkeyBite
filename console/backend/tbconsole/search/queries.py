"""Query and aggregation builders shared by the API and the rule engine."""

from . import fields as F
from . import tbql
from .timerange import TimeRange, zone_name

# Caps on what one request can ask OpenSearch for
MAX_TERMS_SIZE = 500
MAX_PAGE = 500


def bool_query(tr: TimeRange | None, text: str = '', extra: list[dict] | None = None,
               exclude: list[str] | None = None) -> dict:
    """The time range, a TBQL query and anything else, ANDed.

    `exclude` are TBQL queries whose matches are left out, which is how a
    rule's exceptions apply.
    """
    filters = []
    if tr is not None:
        filters.append(tr.filter())
    compiled = tbql.compile(text or '')
    if compiled != {'match_all': {}}:
        filters.append(compiled)
    filters.extend(extra or [])
    must_not = [tbql.compile(q) for q in exclude or [] if q and q.strip()]
    query: dict = {'bool': {'filter': filters}}
    if must_not:
        query['bool']['must_not'] = must_not
    return query


def terms_agg(field: str, size: int, sub: dict | None = None, order: dict | None = None,
              min_doc_count: int | None = None) -> dict:
    agg: dict = {'terms': {'field': field, 'size': max(1, min(size, MAX_TERMS_SIZE))}}
    if order:
        agg['terms']['order'] = order
    if min_doc_count and min_doc_count > 1:
        agg['terms']['min_doc_count'] = min_doc_count
    if sub:
        agg['aggs'] = sub
    return agg


def group_filter(group_fields: list[str], i: int) -> dict:
    """The events that group by `group_fields[i]`: they have it, and none before it."""
    flt: dict = {'bool': {'filter': [{'exists': {'field': group_fields[i]}}]}}
    if i:
        flt['bool']['must_not'] = [{'exists': {'field': b}} for b in group_fields[:i]]
    return flt


def group_aggs(group_fields: list[str], size: int, sub: dict | None = None,
               order: dict | None = None, min_doc_count: int | None = None) -> dict:
    """Aggregations that bucket by the first of `group_fields` an event has.

    One filtered terms aggregation per field, each taking only events that
    lack every field before it, so an event lands in exactly one group. With
    one field this is just a terms aggregation under a filter. `order` decides
    which groups make the cut when there are more than `size`.
    """
    return {f'g{i}': {'filter': group_filter(group_fields, i),
                      'aggs': {'t': terms_agg(name, size, sub, order, min_doc_count)}}
            for i, name in enumerate(group_fields)}


def group_buckets(aggregations: dict, group_fields: list[str]) -> list[dict]:
    """Flattens group_aggs results to [{field, key, doc_count, ...}], largest first."""
    out = []
    for i, name in enumerate(group_fields):
        part = (aggregations or {}).get(f'g{i}') or {}
        for bucket in (part.get('t') or {}).get('buckets', []):
            item = dict(bucket)
            item['field'] = name
            item['key'] = bucket.get('key_as_string', bucket.get('key'))
            out.append(item)
    out.sort(key=lambda b: b.get('doc_count', 0), reverse=True)
    return out


def entity_term(field: str, value) -> str:
    """TBQL selecting one entity, for links and evidence."""
    f = F.BY_NAME.get(field)
    name = f.aliases[0] if f and f.aliases else field
    return tbql.term_for(name, value)


def date_histogram(interval: str, tr: TimeRange, sub: dict | None = None,
                   tz: str | None = None) -> dict:
    agg: dict = {'date_histogram': {
        'field': '@timestamp', 'fixed_interval': interval, 'min_doc_count': 0,
        # Day buckets start at the caller's midnight
        'time_zone': tz or zone_name(),
        'extended_bounds': {'min': int(tr.start.timestamp() * 1000),
                            'max': int(tr.end.timestamp() * 1000) - 1},
    }}
    if sub:
        agg['aggs'] = sub
    return agg


def histogram_series(buckets: list[dict]) -> list[dict]:
    return [{'t': b.get('key_as_string') or b.get('key'), 'ts': b.get('key'),
             'count': b.get('doc_count', 0)} for b in buckets]
