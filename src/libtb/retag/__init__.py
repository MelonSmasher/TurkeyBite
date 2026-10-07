"""Relabels stored events with the lists as they are now.

An event's categories are decided once, when a worker processes it, from the
index of that moment. Change a list's trust, drop a list or add a correction
and only new events see it: everything already in OpenSearch keeps the labels
the old lists gave it. This runs the stored events back through the worker's
own decision, Processor.categorise_lookup for a DNS lookup and
Processor.categorise_visit for a page visit, and writes back what changed.

Only what the lists decide is replaced, the fields in VERDICT_FIELDS. The
input is read from the event itself: the name asked for, which is the first
of bite.searches, and bite.cname_chain. Index mode looks up only that first
name, so an event from before bite.searches existed is relabelled from
bite.requested, whose first entry is the same name. Nothing about who asked,
when, or the raw packet is touched, and processor.privacy is not re-applied.

The whole run weighs against one index generation, the one open when it
starts. The librarian may rebuild the index meanwhile; the run keeps the
generation it began with, so no two events are judged by different lists,
and every event it writes names that generation in bite.index_built_at. Run
it again afterwards to apply the newer one.

The public resolvers are never asked. Where processor.evidence.resolvers is
on, the answers already stored on the event in bite.resolvers are replayed,
so a candidate a resolver corroborated stays asserted. A candidate that now
qualifies for a resolver vote, but was not asked about at the time, stays a
candidate: sending a million old names to Quad9 is not this command's call.

An event whose verdict is unchanged is not written, so a rerun after a
partial one only writes what is left. An unchanged event keeps the
generation it was processed with, whose verdict it shares.

Each update is conditional on the sequence number read, so an event changed
by anything else in between is reported as a conflict and left alone.
"""

import sys
from collections import Counter, namedtuple

from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import OpenSearchException

from libtb.evidence import resolve
from libtb.evidence.resolvers import BLOCKED, PROVIDERS, SOURCES, qualifies
from libtb.index import DomainIndex
from libtb.opensearch import client_kwargs
from libtb.retention import index_pattern

# Everything categorise_lookup or categorise_visit can put on an event, and
# the compare-mode and fallback fields a verdict from index mode replaces.
# An event's value for any of these is replaced by the new verdict's, or
# removed when the new verdict has none.
VERDICT_FIELDS = (
    'contexts', 'contexts_candidate', 'contexts_suppressed', 'incidental',
    'claims', 'sources', 'matched_on', 'match_source',
    'cname_contexts', 'cname_matched_on', 'resolvers',
    'purpose', 'service', 'risk', 'risk_severity', 'unmapped_contexts',
    'index_built_at', 'contexts_index', 'context_match', 'index_error',
)

# Read from each event: the inputs to the decision and the decision itself
READ_FIELDS = ['bite.type', 'bite.searches', 'bite.requested', 'bite.cname_chain'] + [
    'bite.' + field for field in VERDICT_FIELDS]

# Painless, one source for every update so OpenSearch compiles it once
SCRIPT = ('for (e in params.set.entrySet()) { ctx._source.bite[e.getKey()] = e.getValue(); } '
          'for (k in params.unset) { ctx._source.bite.remove(k); }')

DNS, VISIT = 'dns', 'browser.history'

# Distinct inputs remembered at once. A few hundred thousand names cover most
# of a deployment's traffic, and each entry is small.
CACHE_MAX = 500_000

# How a run reads and writes. `scan` and `bulk` are opensearch-py's helpers,
# replaced in tests by a fake cluster.
Options = namedtuple('Options', 'apply batch_size limit log scan bulk')
Options.__new__.__defaults__ = (False, 1000, None, print, helpers.scan, helpers.streaming_bulk)


def default_pattern(prefix):
    """The daily indices a worker writes, <prefix>-YYYY-MM-DD.

    Nothing else that happens to share the prefix, such as an archive or an
    incident copy, is relabelled unless named with --index.
    """
    return index_pattern(prefix)


def client_for(elastic, connect=OpenSearch):
    """A client for the first host in processor.elastic that answers.

    Each host is tried with its own TLS settings and credentials, in order,
    as the workers try them. A run stays on the host it starts with: a scroll
    belongs to the node that opened it, so it cannot move mid-run. Raises
    OSError naming every host when none answers.
    """
    failures = []
    for host in elastic['hosts']:
        client = connect(**client_kwargs(host))
        try:
            if client.ping():
                return client
            failures.append(f'{host["uri"]}: no answer')
        except (OpenSearchException, OSError) as e:
            failures.append(f'{host["uri"]}: {e}')
        client.close()
    raise OSError('no OpenSearch host answered: ' + '; '.join(failures))


class ReplayChecker:
    """Stands in for resolvers.Checker, answering from what an event recorded.

    The same rule as the live checker: a provider's answer is a vote only when
    it could settle a candidate, and the verdict is weighed again after each
    block. Every answer the event holds is kept on it, vote or not: none can
    be asked for again, and a later run under other lists may need it.
    """

    def __init__(self, adult):
        """Consults the same providers the live checker would, given `adult`."""
        self.providers = tuple(p for p in PROVIDERS if adult or p.vote != 'porn')
        self.answers = {}

    def corroborate(self, _host, claims, verdict, min_publishers):
        """(claims, verdict, statuses), as resolvers.Checker.corroborate returns them."""
        statuses = dict(self.answers)
        for provider in self.providers:
            if not qualifies(provider, claims, verdict):
                continue
            status = self.answers.get(provider.name)
            if status is None:
                continue
            if status == BLOCKED:
                claims = list(claims) + [(None, SOURCES[provider.name], provider.vote)]
                verdict = resolve(claims, min_publishers)
        return claims, verdict, statuses


def _comparable(value):
    """A stored or computed value with list order taken out, for comparison."""
    if isinstance(value, list):
        try:
            return sorted(value)
        except TypeError:
            return value
    return value


def _input(bite):
    """(kind, host, chain) a stored bite is weighed on, or None when it has none."""
    kind = bite.get('type')
    names = bite.get('searches') or bite.get('requested')
    if kind not in (DNS, VISIT) or not isinstance(names, list) or not names:
        return None
    host = names[0]
    if not isinstance(host, str) or not host.strip():
        return None
    chain = bite.get('cname_chain') if kind == DNS else None
    chain = tuple(str(link) for link in chain) if isinstance(chain, list) else ()
    return kind, host.strip().lower(), chain


class Retagger:
    """Recomputes one event at a time against one index generation."""

    def __init__(self, processor):
        """Pins `processor` to the index open now and to replayed resolver answers.

        Raises ValueError outside index mode, and OSError or ValueError when
        the index cannot be opened.
        """
        mode, path = processor.index_settings()
        if mode != 'index':
            raise ValueError(f'processor.domain_index.mode is {mode!r}; only index mode '
                             f'weighs evidence, so only it can relabel stored events')
        self.processor = processor
        # A handle of its own rather than the process's shared one, which
        # reopens itself when the librarian swaps the file
        self.index = DomainIndex(path)
        processor.pinned_index = self.index
        conf = processor.resolver_conf()
        self.replay = ReplayChecker(conf.adult) if conf.enable else None
        # Read by Processor.resolver_checker in place of the live checker
        processor.checker = self.replay
        self.cache = {}

    @property
    def generation(self):
        """The index generation every verdict in this run is weighed against."""
        return self.index.built_at

    def close(self):
        """Releases the pinned index."""
        self.processor.pinned_index = None
        self.index.close()

    def verdict(self, bite):
        """(contexts, extra) for a stored bite, or None when it cannot be relabelled."""
        found = _input(bite)
        if found is None:
            return None
        kind, host, chain = found
        answers = bite.get('resolvers') if self.replay is not None else None
        answers = answers if isinstance(answers, dict) else {}
        key = (kind, host, chain, tuple(sorted(answers.items())))
        found = self.cache.get(key)
        if found is None:
            if self.replay is not None:
                self.replay.answers = answers
            if kind == DNS:
                found = self.processor.categorise_lookup([host], list(chain))
            else:
                found = self.processor.categorise_visit([host])
            if 'index_error' in found[1]:
                # The worker falls back to Valkey, or drops the chain, rather
                # than lose the event; writing that over a stored verdict would
                # be a loss
                raise RuntimeError(f'domain index unavailable: {found[1]["index_error"]}')
            if len(self.cache) >= CACHE_MAX:
                self.cache.clear()
            self.cache[key] = found
        return found

    def changes(self, bite):
        """(set, unset) to bring a stored bite in line, or None when it already is."""
        found = self.verdict(bite)
        if found is None:
            return None
        contexts, extra = found
        new = dict(extra, contexts=contexts)
        new = {field: new[field] for field in VERDICT_FIELDS if field in new}
        unchanged = all(_comparable(bite.get(field)) == _comparable(new.get(field))
                        for field in VERDICT_FIELDS if field != 'index_built_at')
        if unchanged:
            return None
        unset = [field for field in VERDICT_FIELDS if field in bite and field not in new]
        return new, unset


class _Run:
    """One pass over the indices: what it read, what it would write, and the tally."""

    def __init__(self, retagger, options):
        self.retagger = retagger
        self.options = options
        self.counts = Counter()
        self.added = Counter()
        self.removed = Counter()

    def update(self, hit):
        """The bulk update for one hit, or None when it needs none. Counts it."""
        self.counts['read'] += 1
        bite = (hit.get('_source') or {}).get('bite') or {}
        change = self.retagger.changes(bite)
        if change is None:
            current = self.retagger.verdict(bite) is not None
            self.counts['unchanged' if current else 'skipped'] += 1
            return None
        new, unset = change
        self.counts['changed'] += 1
        before, after = set(bite.get('contexts') or []), set(new.get('contexts') or [])
        self.added.update(after - before)
        self.removed.update(before - after)
        return {'_op_type': 'update', '_index': hit['_index'], '_id': hit['_id'],
                'if_seq_no': hit['_seq_no'], 'if_primary_term': hit['_primary_term'],
                'script': {'source': SCRIPT, 'lang': 'painless',
                           'params': {'set': new, 'unset': unset}}}

    def updates(self, hits):
        """The updates for every hit read, up to the limit."""
        limit, log = self.options.limit, self.options.log
        for hit in hits:
            if limit is not None and self.counts['read'] >= limit:
                return
            action = self.update(hit)
            if action is not None and self.options.apply:
                yield action
            if self.counts['read'] % 1_000_000 == 0:
                verb = 'changed' if self.options.apply else 'would change'
                log(f'{self.counts["read"]:,} read, {self.counts["changed"]:,} {verb}')

    def record(self, ok, item):
        """Counts one bulk result."""
        if ok:
            self.counts['written'] += 1
            return
        status = (item.get('update') or {}).get('status')
        self.counts['conflicts' if status == 409 else 'failed'] += 1
        if status != 409 and self.counts['failed'] <= 10:
            print(f'Not updated: {item}', file=sys.stderr)

    def result(self):
        """The counts and category tallies `format_report` prints."""
        return {'counts': dict(self.counts), 'added': dict(self.added),
                'removed': dict(self.removed), 'generation': self.retagger.generation}


def run(client, processor, pattern, options=Options()):
    """Relabels every event in the indices `pattern` matches. Returns the counts.

    Without `options.apply` nothing is written and the counts say what would be.
    """
    retagger = Retagger(processor)
    try:
        current = _Run(retagger, options)
        hits = options.scan(client, index=pattern, query={'query': {'match_all': {}}},
                            _source=READ_FIELDS, size=options.batch_size, scroll='15m',
                            seq_no_primary_term=True, request_timeout=120)
        actions = current.updates(hits)
        if options.apply:
            for ok, item in options.bulk(client, actions, chunk_size=options.batch_size,
                                         raise_on_error=False, max_retries=3,
                                         request_timeout=120):
                current.record(ok, item)
        else:
            for _ in actions:
                pass
        return current.result()
    finally:
        retagger.close()


def format_report(result, apply):
    """The result of `run` as printable lines."""
    counts = result['counts']
    verb = 'changed' if apply else 'would change'
    lines = [f'Weighed against index generation {result["generation"]}.',
             f'Read {counts.get("read", 0):,} events: {verb} '
             f'{counts.get("changed", 0):,}, {counts.get("unchanged", 0):,} already current, '
             f'{counts.get("skipped", 0):,} without a name to look up.']
    if apply:
        lines.append(f'Written {counts.get("written", 0):,}, conflicts '
                     f'{counts.get("conflicts", 0):,}, failed {counts.get("failed", 0):,}.')
    for title, found in (('Categories removed from events:', result['removed']),
                         ('Categories added to events:', result['added'])):
        lines.append(title)
        if not found:
            lines.append('  (none)')
        for category, n in sorted(found.items(), key=lambda kv: -kv[1]):
            lines.append(f'  {category:24} {n:>12,}')
    return lines
