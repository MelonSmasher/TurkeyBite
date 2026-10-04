"""Tests for weighing the lists' claims.

The rule being replaced, that any list naming a domain makes the category true,
reported 291 of the 10,000 most popular domains as malicious. Nearly all of those
rested on a single list. So the risk here is in both directions: a category one
noisy list asserts must not get through, and agreement that only looks
independent, because one list copies the other, must not count as two votes.
"""

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))

from libtb import psl
from libtb.evidence import categorise, corroborated, dependent, describe, resolve
from libtb.index import DomainIndex, Source
from libtb.index.builder import apply_ignorelist, build
from libtb.processor import Processor

FIXTURE = os.path.join(HERE, 'fixture_public_suffix_list.dat')


def source(name, trust='medium', publisher=None, derived_from=()):
    return Source(name, publisher or name, trust, False, tuple(derived_from))


def claims(*pairs):
    return [('example.com', src, category) for src, category in pairs]


class ResolveTest(unittest.TestCase):

    def test_a_high_trust_source_is_believed_alone(self):
        verdict = resolve(claims((source('vendor', 'high'), 'steam')))
        self.assertEqual(verdict['asserted'], ['steam'])

    def test_a_medium_trust_source_alone_is_only_a_candidate(self):
        verdict = resolve(claims((source('broad'), 'porn')))
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(verdict['candidate'], ['porn'])

    def test_two_independent_medium_sources_are_believed(self):
        verdict = resolve(claims((source('a'), 'porn'), (source('b'), 'porn')))
        self.assertEqual(verdict['asserted'], ['porn'])

    def test_they_have_to_agree_on_the_same_category(self):
        verdict = resolve(claims((source('a'), 'porn'), (source('b'), 'gambling')))
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(verdict['candidate'], ['gambling', 'porn'])

    def test_one_publisher_agreeing_with_itself_is_one_opinion(self):
        # Block List Project's malware and phishing lists name the same ad networks
        verdict = resolve(claims(
            (source('blp-malware', publisher='blp'), 'malicious'),
            (source('blp-phishing', publisher='blp'), 'malicious')))
        self.assertEqual(verdict['asserted'], [])

    def test_a_copy_does_not_corroborate_its_original(self):
        verdict = resolve(claims(
            (source('hagezi'), 'porn'),
            (source('oisd', derived_from=['hagezi']), 'porn')))
        self.assertEqual(verdict['asserted'], [])

    def test_an_aggregator_does_not_merge_the_lists_it_copies(self):
        # oisd copies both, which says nothing about whether hagezi and
        # StevenBlack copy each other. Grouping through it did, once.
        verdict = resolve(claims(
            (source('hagezi'), 'porn'),
            (source('StevenBlack'), 'porn'),
            (source('oisd', derived_from=['hagezi', 'StevenBlack']), 'porn')))
        self.assertEqual(verdict['asserted'], ['porn'])

    def test_a_low_trust_source_never_counts(self):
        verdict = resolve(claims((source('noisy', 'low'), 'malware')))
        self.assertEqual(verdict['candidate'], ['malware'])

    def test_a_low_trust_source_does_not_corroborate_either(self):
        verdict = resolve(claims((source('noisy', 'low'), 'porn'), (source('broad'), 'porn')))
        self.assertEqual(verdict['asserted'], [])

    def test_the_ignorelist_cancels_even_a_trusted_claim(self):
        verdict = resolve(claims((source('vendor', 'high'), 'porn'),
                                 (source('ignorelist', 'high'), '!porn')))
        self.assertEqual(verdict, {'asserted': [], 'candidate': [], 'suppressed': ['porn']})

    def test_a_cancellation_for_an_unclaimed_category_reports_nothing(self):
        verdict = resolve(claims((source('ignorelist', 'high'), '!porn')))
        self.assertEqual(verdict, {'asserted': [], 'candidate': [], 'suppressed': []})

    def test_one_publisher_is_enough_when_configured(self):
        verdict = resolve(claims((source('broad'), 'porn')), min_publishers=1)
        self.assertEqual(verdict['asserted'], ['porn'])

    def test_three_publishers_can_be_required(self):
        two = claims((source('a'), 'porn'), (source('b'), 'porn'))
        self.assertEqual(resolve(two, min_publishers=3)['asserted'], [])
        three = two + claims((source('c'), 'porn'))
        self.assertEqual(resolve(three, min_publishers=3)['asserted'], ['porn'])

    def test_no_claims_is_no_verdict(self):
        self.assertEqual(resolve([]), {'asserted': [], 'candidate': [], 'suppressed': []})


class DependenceTest(unittest.TestCase):

    def test_dependence_runs_in_both_directions(self):
        original, copy = source('a'), source('b', derived_from=['a'])
        self.assertTrue(dependent(original, copy))
        self.assertTrue(dependent(copy, original))

    def test_sharing_an_upstream_is_not_dependence(self):
        self.assertFalse(dependent(source('a', derived_from=['up']),
                                   source('b', derived_from=['up'])))

    def test_corroboration_needs_a_pairwise_independent_group(self):
        a, b = source('a'), source('b', derived_from=['a'])
        self.assertFalse(corroborated([a, b], 2))
        self.assertTrue(corroborated([a, b, source('c')], 2))


class DescribeTest(unittest.TestCase):

    def test_claims_read_as_category_and_source(self):
        self.assertEqual(describe(claims((source('a'), 'porn'), (source('b'), 'porn'),
                                         (source('a'), 'porn'))),
                         ['porn:a', 'porn:b'])


class IndexFixture(unittest.TestCase):
    """Builds a real index so the whole path from file to verdict is covered."""

    SOURCES = {
        'vendor': source('vendor', 'high', 'nextdns'),
        'stevenblack': source('stevenblack', 'medium', 'StevenBlack'),
        'hagezi': source('hagezi', 'medium', 'hagezi'),
        'blp': source('blp', 'low', 'blocklistproject'),
        'cyberhost': source('cyberhost', 'medium', 'cyberhost'),
    }

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-evidence-')
        self.path = os.path.join(self.root, 'domains.tbidx')
        entries = {
            'pornsite.com': {'stevenblack': {'porn'}},
            '*.pornsite.com': {'hagezi': {'porn'}},
            'newsite.com': {'hagezi': {'porn'}},
            '*.coinbase.com': {'blp': {'malicious', 'crypto'}},
            '*.workers.dev': {'cyberhost': {'malicious'}},
            '*.steampowered.com': {'vendor': {'games', 'steam'}},
            '*.tenor.com': {'stevenblack': {'porn'}, 'hagezi': {'porn'}},
        }
        apply_ignorelist(entries, ignorelist={'porn': ['*.tenor.com']})
        build(entries, path=self.path, built_at=1000, sources=self.SOURCES)
        self.index = DomainIndex(self.path)

    def tearDown(self):
        self.index.close()
        shutil.rmtree(self.root, ignore_errors=True)
        psl.forget()


class IndexedVerdictTest(IndexFixture):

    def verdict(self, host):
        return categorise(self.index, host, psl_path=FIXTURE)[1]

    def test_agreement_across_exact_and_subtree_entries_counts(self):
        self.assertEqual(self.verdict('www.pornsite.com')['asserted'], ['porn'])

    def test_a_subdomain_only_one_list_covers_is_a_candidate(self):
        self.assertEqual(self.verdict('cdn.pornsite.com')['candidate'], ['porn'])

    def test_a_noisy_list_alone_asserts_nothing(self):
        verdict = self.verdict('www.coinbase.com')
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(verdict['candidate'], ['crypto', 'malicious'])

    def test_a_public_suffix_entry_says_nothing_about_its_tenants(self):
        verdict = self.verdict('shop.workers.dev')
        self.assertEqual(verdict, {'asserted': [], 'candidate': [], 'suppressed': []})

    def test_a_vendor_list_asserts_alone(self):
        self.assertEqual(self.verdict('store.steampowered.com')['asserted'], ['games', 'steam'])

    def test_a_correction_holds_against_agreement(self):
        self.assertEqual(self.verdict('media.tenor.com'),
                         {'asserted': [], 'candidate': [], 'suppressed': ['porn']})


class ProcessorWiringTest(IndexFixture):
    """What lands on the event in index mode."""

    def processor(self, mode='index', evidence=None):
        config = {'dns': {'lookup_ips': False},
                  'domain_index': {'mode': mode, 'path': self.path}}
        if evidence is not None:
            config['evidence'] = evidence
        processor = Processor(config, {})
        shipped = []
        processor.ship_bite = shipped.append
        processor.valkey_contexts = lambda searches: ['legacy']
        return processor, shipped

    def packet(self, name, answers=()):
        return {'type': 'dns', 'resource': name,
                'dns': {'question': {'name': name}, 'answers': list(answers)},
                'network': {'direction': 'ingress'}, 'client': {'ip': '10.0.0.5'},
                '@timestamp': '2026-10-04T12:00:00Z'}

    def bite(self, name, answers=(), **kwargs):
        processor, shipped = self.processor(**kwargs)
        processor.process_dns_packet(self.packet(name, answers))
        return shipped[0]['bite']

    def test_only_asserted_categories_reach_contexts(self):
        bite = self.bite('cdn.pornsite.com')
        self.assertEqual(bite['contexts'], [])
        self.assertEqual(bite['contexts_candidate'], ['porn'])
        self.assertNotIn('purpose', bite)

    def test_an_asserted_category_is_faceted(self):
        bite = self.bite('www.pornsite.com')
        self.assertEqual(bite['contexts'], ['porn'])
        self.assertEqual(bite['purpose'], ['adult.pornography'])
        self.assertNotIn('contexts_candidate', bite)

    def test_the_claims_say_which_list_said_what(self):
        self.assertEqual(self.bite('www.pornsite.com')['claims'],
                         ['porn:hagezi', 'porn:stevenblack'])

    def test_a_correction_is_reported(self):
        bite = self.bite('media.tenor.com')
        self.assertEqual(bite['contexts'], [])
        self.assertEqual(bite['contexts_suppressed'], ['porn'])

    def test_a_correction_on_the_question_holds_over_the_chain(self):
        bite = self.bite('media.tenor.com',
                         answers=[{'type': 'CNAME', 'data': 'www.pornsite.com'}])
        self.assertEqual(bite['cname_contexts'], ['porn'])
        self.assertEqual(bite['contexts'], [])
        self.assertNotIn('match_source', bite)

    def test_the_chain_can_settle_a_candidate(self):
        bite = self.bite('cdn.pornsite.com',
                         answers=[{'type': 'CNAME', 'data': 'www.pornsite.com'}])
        self.assertEqual(bite['contexts'], ['porn'])
        self.assertNotIn('contexts_candidate', bite)
        self.assertEqual(bite['match_source'], ['cname'])

    def test_the_bar_is_configurable(self):
        bite = self.bite('cdn.pornsite.com', evidence={'min_publishers': 1})
        self.assertEqual(bite['contexts'], ['porn'])

    def test_compare_mode_records_the_weighed_answer_beside_valkey(self):
        bite = self.bite('cdn.pornsite.com', mode='compare')
        self.assertEqual(bite['contexts'], ['legacy'])
        self.assertEqual(bite['contexts_index'], [])
        self.assertFalse(bite['context_match'])
        self.assertNotIn('contexts_candidate', bite)

    def test_no_match_carries_no_claims(self):
        bite = self.bite('www.unlisted.example')
        self.assertEqual(bite['contexts'], [])
        self.assertNotIn('claims', bite)


if __name__ == '__main__':
    unittest.main(verbosity=2)
