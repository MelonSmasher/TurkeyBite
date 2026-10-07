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

The public resolvers are never asked. Where processor.evidence.resolvers is
on, the answers already stored on the event in bite.resolvers are replayed,
so a candidate a resolver corroborated stays asserted. A candidate that now
qualifies for a resolver vote, but was not asked about at the time, stays a
candidate: sending a million old names to Quad9 is not this command's call.

An event whose verdict is unchanged is not written, so a rerun after a
partial one only writes what is left. A written event carries the current
index generation in bite.index_built_at; an unchanged one keeps the
generation it was processed with, whose verdict it shares.

Each update is conditional on the sequence number read, so an event changed
by anything else in between is reported as a conflict and left alone.
"""

import sys
from collections import Counter

from opensearchpy import helpers

from libtb.evidence import resolve
from libtb.evidence.resolvers import BLOCKED, PROVIDERS, SOURCES, qualifies

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


class ReplayChecker(object):
    """Stands in for resolvers.Checker, answering from what an event recorded.

    The same rule as the live checker: a provider is consulted only when its
    vote could settle a candidate, and the verdict is weighed again after each
    block. A provider the event has no answer from casts no vote and is not
    recorded, since it was not asked.
    """

    def __init__(self, adult):
        self.providers = tuple(p for p in PROVIDERS if adult or p.vote != 'porn')
        self.answers = {}

    def corroborate(self, host, claims, verdict, min_publishers):
        statuses = {}
        for provider in self.providers:
            if not qualifies(provider, claims, verdict):
                continue
            status = self.answers.get(provider.name)
            if status is None:
                continue
            statuses[provider.name] = status
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


class Retagger(object):
    """Recomputes one event at a time, remembering verdicts by their inputs."""

    def __init__(self, processor):
        mode, _ = processor.index_settings()
        if mode != 'index':
            raise ValueError(f'processor.domain_index.mode is {mode!r}; only index mode '
                             f'weighs evidence, so only it can relabel stored events')
        self.processor = processor
        conf = processor.resolver_conf()
        self.replay = ReplayChecker(conf.adult) if conf.enable else None
        # Read by Processor.resolver_checker in place of the live checker
        processor.checker = self.replay
        self.cache = {}

    def verdict(self, bite):
        """(contexts, extra) for a stored bite, or None when it cannot be relabelled."""
        kind = bite.get('type')
        names = bite.get('searches') or bite.get('requested')
        if kind not in (DNS, VISIT) or not isinstance(names, list) or not names:
            return None
        host = names[0]
        if not isinstance(host, str) or not host.strip():
            return None
        host = host.strip().lower()
        chain = bite.get('cname_chain') if kind == DNS else None
        chain = [str(link) for link in chain] if isinstance(chain, list) else []
        answers = bite.get('resolvers') if self.replay is not None else None
        answers = answers if isinstance(answers, dict) else {}
        key = (kind, host, tuple(chain), tuple(sorted(answers.items())))
        found = self.cache.get(key)
        if found is None:
            if self.replay is not None:
                self.replay.answers = answers
            if kind == DNS:
                found = self.processor.categorise_lookup([host], chain)
            else:
                found = self.processor.categorise_visit([host])
            if 'index_error' in found[1]:
                # The worker falls back to Valkey rather than lose the event;
                # writing that fallback over a stored verdict would be a loss
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


def run(client, processor, pattern, apply=False, batch_size=1000, limit=None,
        log=print, scan=helpers.scan, bulk=helpers.streaming_bulk):
    """Relabels every event in the indices `pattern` matches. Returns the counts.

    Without `apply` nothing is written and the counts say what would be.
    """
    retagger = Retagger(processor)
    counts = Counter()
    added, removed = Counter(), Counter()

    def updates():
        hits = scan(client, index=pattern, query={'query': {'match_all': {}}},
                    _source=READ_FIELDS, size=batch_size, scroll='15m',
                    seq_no_primary_term=True, request_timeout=120)
        for hit in hits:
            if limit is not None and counts['read'] >= limit:
                return
            counts['read'] += 1
            bite = (hit.get('_source') or {}).get('bite') or {}
            change = retagger.changes(bite)
            if change is None:
                counts['unchanged' if retagger.verdict(bite) is not None else 'skipped'] += 1
            else:
                new, unset = change
                counts['changed'] += 1
                before, after = set(bite.get('contexts') or []), set(new.get('contexts') or [])
                added.update(after - before)
                removed.update(before - after)
                if apply:
                    yield {'_op_type': 'update', '_index': hit['_index'], '_id': hit['_id'],
                           'if_seq_no': hit['_seq_no'], 'if_primary_term': hit['_primary_term'],
                           'script': {'source': SCRIPT, 'lang': 'painless',
                                      'params': {'set': new, 'unset': unset}}}
            if counts['read'] % 1_000_000 == 0:
                log(f'{counts["read"]:,} read, {counts["changed"]:,} '
                    f'{"changed" if apply else "would change"}')

    if apply:
        for ok, item in bulk(client, updates(), chunk_size=batch_size, raise_on_error=False,
                             max_retries=3, request_timeout=120):
            if ok:
                counts['written'] += 1
                continue
            status = (item.get('update') or {}).get('status')
            counts['conflicts' if status == 409 else 'failed'] += 1
            if status != 409 and counts['failed'] <= 10:
                print(f'Not updated: {item}', file=sys.stderr)
    else:
        for _ in updates():
            pass
    return {'counts': dict(counts), 'added': dict(added), 'removed': dict(removed)}


def format_report(result, apply):
    counts = result['counts']
    verb = 'Changed' if apply else 'Would change'
    lines = [f'Read {counts.get("read", 0):,} events: {verb.lower()} '
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
