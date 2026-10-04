"""Measures what the index says about domains whose nature is already known.

A false positive is invisible from inside the pipeline: an event labelled
malware looks the same whether the label is right or not. The way to find them
is to ask the index about domains that are known to be ordinary, and the most
popular domains on the web are the cheapest such set. The Tranco list ranks
them, is free, and is built to resist manipulation.

Popular is not the same as benign, so this reports rather than judges. Popular
domains genuinely are social networks and news sites, and some are adult. A
threat category on one of the top ten thousand domains is another matter, and
almost always means a list is wrong.

Each domain is checked bare and with www, because the bare name is often never
queried at all. Both go through libtb.evidence.categorise, the function the
workers call, so the report is what live events will say.
"""

import csv
from collections import Counter, defaultdict

from libtb.evidence import DEFAULT_MIN_PUBLISHERS, categorise
from libtb.psl import DEFAULT_PATH as PSL_PATH
from libtb.taxonomy import classify


def read_reference(path, limit=None):
    """Domains from a Tranco 'rank,domain' CSV or a plain one-per-line list."""
    domains = []
    with open(path, newline='', encoding='utf-8', errors='replace') as handle:
        for row in csv.reader(handle):
            if not row:
                continue
            value = row[-1].strip().lower().strip('.')
            if not value or value.startswith('#') or '.' not in value:
                continue
            domains.append(value)
            if limit and len(domains) >= limit:
                break
    return domains


def parse_bar(text):
    """A --min-publishers value: '2', or 'default=2,threat=1' for a mapping."""
    text = str(text).strip()
    if '=' not in text:
        return text
    bar = {}
    for part in text.split(','):
        key, _, value = part.partition('=')
        bar[key.strip()] = value.strip()
    return bar


def is_threat(category):
    return any(path.startswith('threat.') for path in classify([category]).get('risk', []))


def audit(index, domains, min_publishers=DEFAULT_MIN_PUBLISHERS, psl_path=PSL_PATH,
          disabled=frozenset()):
    """Runs the reference domains through the index.

    Returns a dict:

        asserted    category -> [(rank, domain, sources that claimed it)]
        candidate   category -> [(rank, domain, sources that claimed it)]
        blamed      source -> number of domains where it backed an asserted
                    threat category, the closest thing to a false positive
                    count this can produce. Low trust sources are left out,
                    since they cannot have contributed.
    """
    asserted = defaultdict(list)
    candidate = defaultdict(list)
    blamed = Counter()
    for rank, domain in enumerate(domains, 1):
        verdict = {'asserted': set(), 'candidate': set()}
        backers = defaultdict(set)
        counted = defaultdict(set)
        for host in (domain, 'www.' + domain):
            claims, result = categorise(index, host, min_publishers, psl_path, disabled)
            verdict['asserted'].update(result['asserted'])
            verdict['candidate'].update(result['candidate'])
            for _, source, category in claims:
                backers[category].add(source.name)
                if source.trust != 'low':
                    counted[category].add(source.name)
        verdict['candidate'] -= verdict['asserted']
        for category in verdict['asserted']:
            asserted[category].append((rank, domain, sorted(backers[category])))
            if is_threat(category):
                blamed.update(counted[category])
        for category in verdict['candidate']:
            candidate[category].append((rank, domain, sorted(backers[category])))
    return {'asserted': asserted, 'candidate': candidate, 'blamed': blamed}


def format_report(report, total, examples=5, categories=None):
    """The audit as printable lines."""
    lines = []

    def section(title, found):
        lines.append(title)
        rows = sorted(found.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        if categories:
            rows = [row for row in rows if row[0] in categories]
        if not rows:
            lines.append('  (none)')
        for category, hits in rows:
            marker = ' threat' if is_threat(category) else ''
            lines.append(f'  {category:24} {len(hits):6}{marker}')
            for rank, domain, sources in hits[:examples]:
                lines.append(f'      #{rank:<7} {domain:40} {", ".join(sources)}')
        lines.append('')

    lines.append(f'Audited {total} reference domains.')
    lines.append('')
    section('Asserted, which is what events will carry:', report['asserted'])
    section('Held back as candidates, recorded but not asserted:', report['candidate'])

    lines.append('Sources behind threat categories asserted on reference domains:')
    if not report['blamed']:
        lines.append('  (none)')
    for source, count in report['blamed'].most_common():
        lines.append(f'  {source:44} {count:6}')
    return lines
