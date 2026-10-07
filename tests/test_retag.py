"""Tests for relabelling stored events with the current lists.

What has to hold: a relabelled event carries exactly the verdict a worker would
ship today for the same lookup, and nothing else of it changes. Old resolver
answers are replayed and no resolver is asked. An event already current is not
written, and every write is conditional on the copy that was read.

OpenSearch is replaced by a fake that holds documents and applies the update
script's effect, so the documents that come out are checked, not the requests.
"""

import copy
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'src'))

from libtb import psl
from libtb import processor as P
from libtb.evidence import resolvers as R
from libtb.index import Source
from libtb.index.builder import apply_ignorelist, build
from libtb.processor import Processor
from libtb.retag import VERDICT_FIELDS, Options, default_pattern, run

VENDOR = Source('vendor', 'nextdns', 'high', False, ())
STEVENBLACK = Source('stevenblack', 'StevenBlack', 'medium', False, ())
HAGEZI = Source('hagezi', 'hagezi', 'medium', False, ())
ARMY = Source('army', 'phishing.army', 'medium', False, ())
SOURCES = {s.name: s for s in (VENDOR, STEVENBLACK, HAGEZI, ARMY)}


class FakeCluster:
    """Documents by (index, id), with sequence numbers, updated as OpenSearch would."""

    def __init__(self, docs):
        """Holds `docs` as the event sources of one daily index, each at sequence 1."""
        self.docs = {}
        for i, source in enumerate(docs):
            self.docs[('tb-index-2026-10-01', str(i))] = {'seq': 1, 'source': source}
        self.updates = []
        # Called after the scan reads everything and before writes, to model
        # a document changing between the two
        self.between = None

    def scan(self, client, index, query, _source, size, scroll, seq_no_primary_term,
             request_timeout):
        hits = []
        wanted = {f.split('.', 1)[1] for f in _source}
        for (name, doc_id), doc in sorted(self.docs.items()):
            bite = doc['source'].get('bite', {})
            hits.append({'_index': name, '_id': doc_id, '_seq_no': doc['seq'],
                         '_primary_term': 1,
                         '_source': {'bite': {k: copy.deepcopy(v) for k, v in bite.items()
                                              if k in wanted}}})
        if self.between:
            self.between(self)
        return iter(hits)

    def bulk(self, client, actions, chunk_size, raise_on_error, max_retries, request_timeout):
        for action in actions:
            self.updates.append(action)
            doc = self.docs[(action['_index'], action['_id'])]
            if doc['seq'] != action['if_seq_no']:
                yield False, {'update': {'status': 409, '_id': action['_id']}}
                continue
            params = action['script']['params']
            bite = doc['source']['bite']
            bite.update(copy.deepcopy(params['set']))
            for key in params['unset']:
                bite.pop(key, None)
            doc['seq'] += 1
            yield True, {'update': {'status': 200}}

    def bite(self, i):
        return self.docs[('tb-index-2026-10-01', str(i))]['source']['bite']


class RetagTest(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-retag-')
        self.addCleanup(shutil.rmtree, self.root, True)
        self.path = os.path.join(self.root, 'domains.tbidx')
        entries = {
            '*.pornsite.com': {'stevenblack': {'porn'}, 'hagezi': {'porn'}},
            'ads.example.com': {'hagezi': {'advertising'}},
            '*.steampowered.com': {'vendor': {'games', 'steam'}},
            '*.tracker.example.net': {'stevenblack': {'tracking'}, 'hagezi': {'tracking'}},
            'bad.example.com': {'army': {'malicious'}},
            '*.tenor.com': {'stevenblack': {'porn'}, 'hagezi': {'porn'}},
        }
        apply_ignorelist(entries, ignorelist={'porn': ['*.tenor.com']})
        build(entries, path=self.path, built_at=2000, sources=SOURCES)
        for state in (P._index_handles, R._checkers):
            state.clear()
            self.addCleanup(state.clear)
        self.addCleanup(lambda: [i.close() for i in P._index_handles.values()])
        psl.forget()
        self.addCleanup(psl.forget)

    def processor(self, evidence=None):
        config = {'dns': {'lookup_ips': False},
                  'domain_index': {'mode': 'index', 'path': self.path}}
        if evidence is not None:
            config['evidence'] = evidence
        processor = Processor(config, {})
        processor.valkey_contexts = lambda searches: self.fail('Valkey was asked')
        return processor

    def shipped(self, name, answers=(), evidence=None):
        """The bite a worker ships today for this lookup."""
        processor = self.processor(evidence)
        shipped = []
        processor.ship_bite = shipped.append
        processor.process_dns_packet({
            'type': 'dns', 'resource': name,
            'dns': {'question': {'name': name}, 'answers': list(answers)},
            'network': {'direction': 'ingress'}, 'client': {'ip': '10.0.0.5'},
            '@timestamp': '2026-10-04T12:00:00Z'})
        return shipped[0]['bite']

    def stored(self, name, contexts, answers=(), **old):
        """A bite as an older worker stored it: today's inputs, an old verdict."""
        bite = self.shipped(name, answers)
        for field in VERDICT_FIELDS:
            bite.pop(field, None)
        bite.update(contexts=contexts, index_built_at=1000, **old)
        return {'@timestamp': '2026-10-01T00:00:00Z', 'bite': bite,
                'packet': {'kept': 'as it was'}}

    @staticmethod
    def options(apply=True, **kwargs):
        return Options(apply=apply, log=lambda m: None, **kwargs)

    def retag(self, docs, apply=True, evidence=None):
        cluster = FakeCluster(docs)
        result = run(None, self.processor(evidence), 'tb-index-*',
                     self.options(apply, scan=cluster.scan, bulk=cluster.bulk))
        return cluster, result

    # -- the verdict ----------------------------------------------------------

    def test_a_relabelled_event_carries_what_a_worker_ships_today(self):
        cname = [{'type': 'CNAME', 'data': 'x.tracker.example.net'}]
        old = self.stored('www.pornsite.com', ['porn', 'advertising'], cname,
                          contexts_candidate=['games'], claims=['advertising:gone'],
                          purpose=['wrong'])
        cluster, result = self.retag([old])
        bite = cluster.bite(0)
        today = self.shipped('www.pornsite.com', cname)
        for field in VERDICT_FIELDS:
            self.assertEqual(bite.get(field), today.get(field), field)
        self.assertEqual(bite['contexts'], ['porn', 'tracking'])
        self.assertEqual(bite['index_built_at'], 2000)
        self.assertEqual(result['removed'], {'advertising': 1})
        self.assertEqual(result['added'], {'tracking': 1})

    def test_a_label_no_longer_supported_is_removed_with_its_facets(self):
        # One medium list, so today only a candidate
        old = self.stored('ads.example.com', ['advertising'],
                          risk=['privacy.advertising'], match_source=['question'])
        cluster, _ = self.retag([old])
        bite = cluster.bite(0)
        self.assertEqual(bite['contexts'], [])
        self.assertEqual(bite['contexts_candidate'], ['advertising'])
        for gone in ('risk', 'match_source'):
            self.assertNotIn(gone, bite)

    def test_a_correction_added_since_reaches_old_events(self):
        old = self.stored('media.tenor.com', ['porn'], purpose=['adult.pornography'])
        cluster, _ = self.retag([old])
        bite = cluster.bite(0)
        self.assertEqual(bite['contexts'], [])
        self.assertEqual(bite['contexts_suppressed'], ['porn'])
        self.assertNotIn('purpose', bite)

    def test_a_page_visit_is_weighed_as_a_visit(self):
        old = {'bite': {'type': 'browser.history', 'contexts': ['news'],
                        'searches': ['store.steampowered.com', '*.store.steampowered.com',
                                     '*.com', 'steampowered.com', '*.steampowered.com'],
                        'url': 'https://store.steampowered.com/app/1'}}
        cluster, _ = self.retag([old])
        bite = cluster.bite(0)
        self.assertEqual(bite['contexts'], ['games', 'steam'])
        self.assertEqual(bite['url'], 'https://store.steampowered.com/app/1')
        # A visit has no CNAME chain, so it never says where a match came from
        self.assertNotIn('match_source', bite)

    # -- what is left alone -----------------------------------------------------

    def test_nothing_but_the_verdict_changes(self):
        old = self.stored('www.pornsite.com', ['advertising'])
        keep = copy.deepcopy(old)
        cluster, _ = self.retag([old])
        doc = cluster.docs[('tb-index-2026-10-01', '0')]['source']
        self.assertEqual(doc['packet'], keep['packet'])
        self.assertEqual(doc['@timestamp'], keep['@timestamp'])
        for field, value in keep['bite'].items():
            if field not in VERDICT_FIELDS:
                self.assertEqual(doc['bite'][field], value, field)

    def test_an_event_already_current_is_not_written(self):
        current = {'bite': self.shipped('www.pornsite.com')}
        current['bite']['index_built_at'] = 1000
        cluster, result = self.retag([current])
        self.assertEqual(cluster.updates, [])
        self.assertEqual(result['counts'], {'read': 1, 'unchanged': 1})
        # It keeps the generation it was processed with, whose verdict it shares
        self.assertEqual(cluster.bite(0)['index_built_at'], 1000)

    def test_list_order_alone_is_not_a_change(self):
        current = {'bite': self.shipped('www.pornsite.com',
                                        [{'type': 'CNAME', 'data': 'x.tracker.example.net'}])}
        current['bite']['contexts'] = list(reversed(current['bite']['contexts']))
        cluster, _ = self.retag([current])
        self.assertEqual(cluster.updates, [])

    def test_an_event_from_before_searches_is_relabelled_from_requested(self):
        # As stored in May 2025: the name asked for and its registrable domain
        old = {'bite': {'type': 'dns', 'requested': ['ads.example.com', 'example.com'],
                        'contexts': ['advertising']}}
        cluster, _ = self.retag([old])
        bite = cluster.bite(0)
        self.assertEqual(bite['contexts'], [])
        self.assertEqual(bite['contexts_candidate'], ['advertising'])
        self.assertEqual(bite['requested'], ['ads.example.com', 'example.com'])

    def test_an_event_with_nothing_to_look_up_is_skipped(self):
        cluster, result = self.retag([{'bite': {'type': 'dns', 'contexts': ['x']}},
                                      {'bite': {'type': 'other', 'searches': ['a.com']}}])
        self.assertEqual(cluster.updates, [])
        self.assertEqual(result['counts']['skipped'], 2)
        self.assertEqual(cluster.bite(0)['contexts'], ['x'])

    def test_a_dry_run_writes_nothing_and_reports_what_would_change(self):
        old = self.stored('ads.example.com', ['advertising'])
        cluster, result = self.retag([old], apply=False)
        self.assertEqual(cluster.updates, [])
        self.assertEqual(cluster.bite(0)['contexts'], ['advertising'])
        self.assertEqual(result['counts']['changed'], 1)
        self.assertEqual(result['removed'], {'advertising': 1})

    def test_a_rerun_after_applying_writes_nothing(self):
        cluster = FakeCluster([self.stored('ads.example.com', ['advertising']),
                               self.stored('www.pornsite.com', [])])
        for _ in range(2):
            cluster.updates = []
            run(None, self.processor(), 'tb-index-*',
                self.options(scan=cluster.scan, bulk=cluster.bulk))
        self.assertEqual(cluster.updates, [])

    def test_an_event_changed_since_it_was_read_is_not_overwritten(self):
        cluster = FakeCluster([self.stored('ads.example.com', ['advertising'])])

        def someone_else_writes(c):
            doc = c.docs[('tb-index-2026-10-01', '0')]
            doc['source']['bite']['contexts'] = ['set-by-someone-else']
            doc['seq'] += 1
        cluster.between = someone_else_writes
        result = run(None, self.processor(), 'tb-index-*',
                     self.options(scan=cluster.scan, bulk=cluster.bulk))
        self.assertEqual(result['counts']['conflicts'], 1)
        self.assertEqual(cluster.bite(0)['contexts'], ['set-by-someone-else'])

    # -- resolvers ---------------------------------------------------------------

    ON = {'resolvers': {'enable': True}}

    def test_a_stored_resolver_vote_is_replayed_and_nobody_is_asked(self):
        old = self.stored('bad.example.com', [], resolvers={'quad9': 'blocked'})
        with mock.patch.object(R, 'query', side_effect=AssertionError('a resolver was asked')):
            cluster, _ = self.retag([old], evidence=self.ON)
        bite = cluster.bite(0)
        self.assertEqual(bite['contexts'], ['malicious'])
        self.assertEqual(bite['resolvers'], {'quad9': 'blocked'})
        self.assertIn('malicious:quad9', bite['claims'])

    def test_a_name_never_asked_about_stays_a_candidate(self):
        old = self.stored('bad.example.com', ['malicious'])
        with mock.patch.object(R, 'query', side_effect=AssertionError('a resolver was asked')):
            cluster, _ = self.retag([old], evidence=self.ON)
        bite = cluster.bite(0)
        self.assertEqual(bite['contexts'], [])
        self.assertEqual(bite['contexts_candidate'], ['malicious'])
        self.assertNotIn('resolvers', bite)

    def test_events_differing_only_in_resolver_answers_are_weighed_apart(self):
        blocked = self.stored('bad.example.com', [], resolvers={'quad9': 'blocked'})
        clear = self.stored('bad.example.com', ['malicious'], resolvers={'quad9': 'clear'})
        cluster, _ = self.retag([blocked, clear], evidence=self.ON)
        self.assertEqual(cluster.bite(0)['contexts'], ['malicious'])
        self.assertEqual(cluster.bite(1)['contexts'], [])

    def test_a_stored_answer_that_no_longer_votes_is_kept(self):
        # Two lists now agree on porn, so Quad9's old answer settles nothing,
        # but it cannot be asked for again, so it stays on the event
        old = self.stored('www.pornsite.com', [], resolvers={'quad9': 'blocked'})
        cluster, _ = self.retag([old], evidence=self.ON)
        bite = cluster.bite(0)
        self.assertEqual(bite['contexts'], ['porn'])
        self.assertEqual(bite['resolvers'], {'quad9': 'blocked'})
        self.assertNotIn('malicious:quad9', bite['claims'])

    # -- one generation per run ---------------------------------------------------

    def rebuild(self, built_at, entries):
        build(entries, path=self.path, built_at=built_at, sources=SOURCES)

    def test_a_rebuild_during_the_run_does_not_mix_generations(self):
        # Two events for one name and one for another, with the index swapped
        # after the first is weighed: the run keeps the generation it began
        # with, for the cached name and the uncached one alike
        docs = [self.stored('ads.example.com', ['advertising']),
                self.stored('www.pornsite.com', []),
                self.stored('ads.example.com', ['advertising'])]
        cluster = FakeCluster(docs)
        swapped = []

        def scan(*args, **kwargs):
            for n, hit in enumerate(cluster.scan(*args, **kwargs)):
                if n == 1 and not swapped:
                    # Both lists now agree on ads.example.com, and nothing
                    # names pornsite.com any more
                    self.rebuild(3000, {'ads.example.com': {'hagezi': {'advertising'},
                                                            'stevenblack': {'advertising'}}})
                    swapped.append(True)
                yield hit
        result = run(None, self.processor(), 'tb-index-*',
                     self.options(scan=scan, bulk=cluster.bulk))
        self.assertEqual(swapped, [True])
        self.assertEqual(result['generation'], 2000)
        for i in range(3):
            self.assertEqual(cluster.bite(i)['index_built_at'], 2000, i)
        self.assertEqual(cluster.bite(0)['contexts'], [])
        self.assertEqual(cluster.bite(1)['contexts'], ['porn'])
        self.assertEqual(cluster.bite(2)['contexts'], [])

    def test_the_run_leaves_the_worker_index_unpinned(self):
        processor = self.processor()
        cluster = FakeCluster([self.stored('ads.example.com', ['advertising'])])
        run(None, processor, 'tb-index-*', self.options(scan=cluster.scan, bulk=cluster.bulk))
        self.assertIsNone(processor.pinned_index)

    # -- refusals -----------------------------------------------------------------

    def test_only_index_mode_can_relabel(self):
        processor = Processor({'domain_index': {'mode': 'compare', 'path': self.path}}, {})
        with self.assertRaises(ValueError):
            run(None, processor, 'tb-index-*', self.options(scan=FakeCluster([]).scan))

    def test_a_missing_index_stops_before_anything_is_read(self):
        processor = Processor({'domain_index': {'mode': 'index',
                                                'path': os.path.join(self.root, 'none')}}, {})
        cluster = FakeCluster([self.stored('ads.example.com', ['advertising'])])
        with self.assertRaises(OSError):
            run(None, processor, 'tb-index-*', self.options(scan=cluster.scan, bulk=cluster.bulk))
        self.assertEqual(cluster.bite(0)['contexts'], ['advertising'])

    def test_an_index_lost_midway_stops_rather_than_writing_a_partial_verdict(self):
        # The CNAME lookup failing on its own drops the chain's categories;
        # writing that would erase them from the event
        cname = [{'type': 'CNAME', 'data': 'x.tracker.example.net'}]
        cluster = FakeCluster([self.stored('www.pornsite.com', ['porn', 'tracking'], cname)])
        processor = self.processor()
        original = Processor.open_index

        def chain_fails(this, path):
            if this.resolve_chain_in_progress:
                raise OSError('index gone')
            return original(this, path)
        original_chain = Processor.resolve_chain

        def resolve_chain(this, chain):
            this.resolve_chain_in_progress = True
            try:
                return original_chain(this, chain)
            finally:
                this.resolve_chain_in_progress = False
        processor.resolve_chain_in_progress = False
        with mock.patch.object(Processor, 'open_index', chain_fails), \
                mock.patch.object(Processor, 'resolve_chain', resolve_chain):
            with self.assertRaises(RuntimeError):
                run(None, processor, 'tb-index-*',
                    self.options(scan=cluster.scan, bulk=cluster.bulk))
        self.assertEqual(cluster.bite(0)['contexts'], ['porn', 'tracking'])
        self.assertEqual(cluster.updates, [])

    def test_the_default_reaches_only_daily_indices(self):
        self.assertEqual(default_pattern('tb-index'), 'tb-index-2*')
        with self.assertRaises(ValueError):
            default_pattern('tb-*')


if __name__ == '__main__':
    unittest.main(verbosity=2)
