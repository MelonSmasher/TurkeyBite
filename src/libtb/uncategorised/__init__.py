"""The domains no list names, ranked by how much they are used, and labelling them.

The lists cover what their publishers care about, which is mostly threats,
ads and adult content. What a campus spends its day on is everything else, so
a domain no list names reaches every report as uncategorised. Lookups follow a
steep curve, and a few hundred domains are most of them: labelling the top of
the uncategorised list covers more of a deployment's own traffic than any list
it could download or buy.

`report` asks OpenSearch for the registrable domains of DNS lookups that carry
no category, ranked by how many distinct clients looked each up, which one
device polling an API cannot inflate the way it inflates the lookups.
`review_lines` writes them out for an operator to put a category against each,
and `read_labels` and `apply` take that file back and add each labelled domain
to lists/<category>/custom. That is the operator's own list: it is believed
alone, covers every name under the domain, and is never overwritten by a list
refresh.

Only domain names and counts leave OpenSearch, never who looked a domain up.
"""

import os
import re
from collections import namedtuple

from libtb.taxonomy import SERVICE, TAXONOMY

Row = namedtuple('Row', 'domain lookups clients candidates')

ORDERS = ('clients', 'lookups')

# Second spellings of a category, left out of what is offered so each label
# has one obvious name. `label` still takes them.
SPELLINGS = frozenset(('torrent', 'proxy', 'windows-tracking'))

# A hostname as the cleaned lists hold them: lower case, dot separated, each
# label up to 63 characters, and punycode for anything else
_LABEL = r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?'
DOMAIN = re.compile(rf'^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})+$')

# Where an operator's own labels go, beside the shipped `turkeybite` list
CUSTOM = 'custom'


def offered():
    """The categories a label can name, in the order to show them.

    Every category in the taxonomy except the vendor ones, which say whose
    service a host is and belong to the vendor lists, the editorial ones,
    which label news by viewpoint, and the second spellings.
    """
    return sorted(category for category, rows in TAXONOMY.items()
                  if category not in SPELLINGS
                  and not any(facet == SERVICE for facet, _ in rows)
                  and not any(path.startswith('editorial.') for _, path in rows))


def describe(category):
    """A category and what the taxonomy says it means: shopping (commerce.retail)."""
    return f'{category} ({", ".join(path for _, path in TAXONOMY[category])})'


def query(days, top, order='clients', exclude=()):
    """The aggregation that finds the uncategorised domains, newest `days` days.

    Reverse lookups and names whose suffix is not on the Public Suffix List,
    such as printer.local, are left out: no list could name them.
    """
    if order not in ORDERS:
        raise ValueError(f'order must be one of {", ".join(ORDERS)}, not {order!r}')
    must_not = [{'exists': {'field': 'bite.contexts'}},
                {'term': {'bite.psl_fallback': True}},
                {'wildcard': {'bite.registrable_domain': {'value': '*arpa'}}}]
    excluded = sorted({normalise(domain) for domain in exclude if domain.strip()})
    if excluded:
        must_not.append({'terms': {'bite.registrable_domain': excluded}})
    terms = {'field': 'bite.registrable_domain', 'size': top}
    if order == 'clients':
        terms['order'] = {'clients': 'desc'}
    return {
        'size': 0,
        'track_total_hits': False,
        'query': {'bool': {
            'filter': [{'term': {'bite.type': 'dns'}},
                       {'exists': {'field': 'bite.registrable_domain'}},
                       {'range': {'@timestamp': {'gte': f'now-{int(days)}d'}}}],
            'must_not': must_not,
        }},
        'aggs': {'domains': {
            'terms': terms,
            'aggs': {
                'clients': {'cardinality': {'field': 'bite.client'}},
                'candidates': {'terms': {'field': 'bite.contexts_candidate', 'size': 3}},
            },
        }},
    }


def report(client, pattern, body):
    """The uncategorised domains in `pattern` that `body`, from query(), finds, as Rows."""
    response = client.search(index=pattern, body=body, request_timeout=120)
    rows = []
    # No aggregations at all when the pattern matches no index yet
    buckets = ((response.get('aggregations') or {}).get('domains') or {}).get('buckets') or []
    for bucket in buckets:
        rows.append(Row(bucket['key'], bucket['doc_count'], bucket['clients']['value'],
                        [c['key'] for c in bucket['candidates']['buckets']]))
    return rows


def _count(n, word):
    return f'{n:,} {word}' + ('' if n == 1 else 's')


def review_lines(rows, heading, suggestions=None):
    """The file an operator fills in: one domain a line, a category to be put after it.

    A suggested category is filled in and marked as one, for the operator to
    keep, change or delete.
    """
    suggestions = suggestions or {}
    lines = [f'# {heading}',
             '#',
             '# Put a category after each domain you want to label, then run',
             '#   turkeybite label <this file>',
             '# to see what would be added, and again with --apply to add it. A domain',
             '# with no category after it is left alone. A label goes in',
             '# lists/<category>/custom and covers the domain and every name under it.',
             '#',
             '# Categories:']
    for category in offered():
        lines.append(f'#   {describe(category)}')
    if suggestions:
        lines += ['#',
                  '# A category marked "suggested" was filled in by Claude from the domain',
                  '# name alone. Check each one before applying: change it, or delete it to',
                  '# leave the domain alone.']
    lines.append('')
    width = max([len(row.domain) for row in rows] + [30])
    for row in rows:
        note = f'{_count(row.lookups, "lookup")}, {_count(row.clients, "client")}'
        if row.candidates:
            note += '; lists claim ' + ', '.join(row.candidates)
        category = suggestions.get(row.domain, '')
        if category:
            note += '; suggested'
        lines.append(f'{row.domain:<{width}}  {category:<16}  # {note}'.rstrip())
    return lines


def normalise(domain):
    """A domain as the lists hold it: lower case, no trailing dot or leading *."""
    domain = domain.strip().lower().rstrip('.')
    if domain.startswith('*.'):
        domain = domain[2:]
    return domain


def read_labels(lines):
    """(labels, problems) from a filled-in review file.

    labels is a list of (domain, category). A line with a domain and nothing
    after it is skipped; anything that is not a domain followed by a category
    the taxonomy knows is a problem, named with its line number.
    """
    labels, problems = [], []
    for number, line in enumerate(lines, 1):
        words = line.split('#', 1)[0].split()
        if len(words) < 2:
            continue
        if len(words) > 2:
            problems.append(f'line {number}: expected a domain and a category, found {line.strip()!r}')
            continue
        domain, category = normalise(words[0]), words[1].lower()
        if not DOMAIN.match(domain):
            problems.append(f'line {number}: {words[0]!r} is not a domain name')
        elif category not in TAXONOMY:
            problems.append(f'line {number}: {category!r} is not a category; the review '
                            f'file lists them')
        else:
            labels.append((domain, category))
    return labels, problems


def _listed(path):
    """The domains a list already names, as the index reads it: whole lines.

    A line with a note after the domain names nothing the index can use, so
    a domain listed only that way is added again, on a line of its own.
    """
    if not os.path.exists(path):
        return set()
    with open(path, encoding='utf-8', errors='replace') as handle:
        return {normalise(line) for line in handle if line.strip() and not line.startswith('#')}


def apply(labels, lists_dir='lists', write=False):
    """Adds each labelled domain to lists/<category>/custom.

    Returns {category: [domains added]}. A domain already in that file is
    left out, so applying a file twice adds nothing the second time. Nothing
    is written unless `write`.
    """
    added, listed = {}, {}
    for domain, category in labels:
        if category not in listed:
            listed[category] = _listed(os.path.join(lists_dir, category, CUSTOM))
        new = added.setdefault(category, [])
        if domain not in listed[category] and domain not in new:
            new.append(domain)
    added = {category: domains for category, domains in added.items() if domains}
    if write:
        for category, domains in added.items():
            os.makedirs(os.path.join(lists_dir, category), exist_ok=True)
            path = os.path.join(lists_dir, category, CUSTOM)
            # A file whose last line has no newline would join the first new
            # domain onto it
            joined = ''
            if os.path.exists(path) and os.path.getsize(path):
                with open(path, 'rb') as handle:
                    handle.seek(-1, os.SEEK_END)
                    if handle.read(1) != b'\n':
                        joined = '\n'
            with open(path, 'a', encoding='utf-8') as handle:
                handle.write(joined + ''.join(domain + '\n' for domain in domains))
    return added
