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
from libtb.evidence import (categorise, corroborated, dependent, describe, disabled_paths,
                            is_disabled, needed, resolve, thresholds)
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
        self.assertEqual(verdict, {'asserted': [], 'candidate': [], 'suppressed': ['porn'],
                                   'incidental': False})

    def test_a_cancellation_for_an_unclaimed_category_reports_nothing(self):
        verdict = resolve(claims((source('ignorelist', 'high'), '!porn')))
        self.assertEqual(verdict, {'asserted': [], 'candidate': [], 'suppressed': [],
                                   'incidental': False})

    def test_one_publisher_is_enough_when_configured(self):
        verdict = resolve(claims((source('broad'), 'porn')), min_publishers=1)
        self.assertEqual(verdict['asserted'], ['porn'])

    def test_three_publishers_can_be_required(self):
        two = claims((source('a'), 'porn'), (source('b'), 'porn'))
        self.assertEqual(resolve(two, min_publishers=3)['asserted'], [])
        three = two + claims((source('c'), 'porn'))
        self.assertEqual(resolve(three, min_publishers=3)['asserted'], ['porn'])

    def test_no_claims_is_no_verdict(self):
        self.assertEqual(resolve([]), {'asserted': [], 'candidate': [], 'suppressed': [],
                                       'incidental': False})


class TaxonomyAgreementTest(unittest.TestCase):
    """Sources agree on what a category means, not on how it is spelled."""

    def test_two_spellings_of_one_judgement_corroborate(self):
        verdict = resolve(claims((source('StevenBlack'), 'fake-news'),
                                 (source('local'), 'fakenews')))
        self.assertEqual(verdict['asserted'], ['fake-news', 'fakenews'])

    def test_a_service_named_two_ways_corroborates(self):
        verdict = resolve(claims((source('a'), 'signal'), (source('b'), 'whispersystems')))
        self.assertEqual(verdict['asserted'], ['signal', 'whispersystems'])

    def test_events_keep_the_spellings_the_lists_used(self):
        # Nothing is renamed, so a query for a category means what it meant
        verdict = resolve(claims((source('a'), 'fake-news'), (source('b'), 'fakenews'),
                                 (source('c'), 'porn')))
        self.assertEqual(verdict['asserted'], ['fake-news', 'fakenews'])
        self.assertEqual(verdict['candidate'], ['porn'])

    def test_different_meanings_still_do_not_corroborate(self):
        # The control for the two above: pooling by path must not pool everything
        verdict = resolve(claims((source('a'), 'malware'), (source('b'), 'phishing')))
        self.assertEqual(verdict['asserted'], [])

    def test_vendors_sharing_a_purpose_do_not_confirm_each_other(self):
        # Both say "a game storefront", which is true, but not whose
        verdict = resolve(claims((source('a'), 'steam'), (source('b'), 'epicgames')))
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(verdict['candidate'], ['epicgames', 'steam'])

    def test_a_vendor_is_believed_when_two_sources_name_it(self):
        verdict = resolve(claims((source('a'), 'steam'), (source('b'), 'steam')))
        self.assertEqual(verdict['asserted'], ['steam'])

    def test_a_trusted_vendor_supports_the_purpose_it_implies(self):
        # A vendor list naming TikTok says the host is a social network, so a
        # broad list saying the same needs nothing more. isnssdk.com is one.
        verdict = resolve(claims((source('vendor', 'high'), 'tiktok'),
                                 (source('broad'), 'social')))
        self.assertEqual(verdict['asserted'], ['social', 'tiktok'])

    def test_a_purpose_does_not_support_the_vendor(self):
        # The converse: two lists agreeing a host is social media says nothing
        # about which network it is
        verdict = resolve(claims((source('a'), 'social'), (source('b'), 'social'),
                                 (source('c'), 'tiktok')))
        self.assertEqual(verdict['asserted'], ['social'])
        self.assertEqual(verdict['candidate'], ['tiktok'])

    def test_a_copy_does_not_corroborate_under_another_spelling(self):
        verdict = resolve(claims(
            (source('hagezi'), 'fake-news'),
            (source('oisd', derived_from=['hagezi']), 'fakenews')))
        self.assertEqual(verdict['asserted'], [])

    def test_an_unmapped_category_is_corrected_only_by_its_own_spelling(self):
        verdict = resolve(claims((source('a', 'high'), 'politics'),
                                 (source('b', 'high'), 'opinion'),
                                 (source('ignorelist', 'high'), '!politics')))
        self.assertEqual(verdict['asserted'], ['opinion'])
        self.assertEqual(verdict['suppressed'], ['politics'])

    def test_an_unmapped_category_needs_the_same_spelling(self):
        different = resolve(claims((source('a'), 'politics'), (source('b'), 'opinion')))
        self.assertEqual(different['asserted'], [])
        same = resolve(claims((source('a'), 'politics'), (source('b'), 'politics')))
        self.assertEqual(same['asserted'], ['politics'])


class CorrectionTest(unittest.TestCase):
    """The ignorelist's corrections, read through the taxonomy."""

    IGNORELIST = source('ignorelist', 'high')

    def test_a_correction_cancels_every_spelling(self):
        verdict = resolve(claims((source('local', 'high'), 'fakenews'),
                                 (source('StevenBlack'), 'fake-news'),
                                 (self.IGNORELIST, '!fakenews')))
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(verdict['candidate'], [])
        self.assertEqual(verdict['suppressed'], ['fake-news', 'fakenews'])

    def test_the_same_claims_uncorrected_are_asserted(self):
        # The control for the one above
        verdict = resolve(claims((source('local', 'high'), 'fakenews'),
                                 (source('StevenBlack'), 'fake-news')))
        self.assertEqual(verdict['asserted'], ['fake-news', 'fakenews'])

    def test_a_correction_cancels_what_would_put_it_back(self):
        # ea says the host is a game platform, so leaving it would put
        # gaming.platforms back in bite.purpose
        verdict = resolve(claims((source('vendor', 'high'), 'ea'),
                                 (source('vendor', 'high'), 'games'),
                                 (self.IGNORELIST, '!games')))
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(verdict['suppressed'], ['ea', 'games'])

    def test_correcting_a_vendor_leaves_its_purpose(self):
        # A host can be social media without being Facebook
        verdict = resolve(claims((source('vendor', 'high'), 'facebook'),
                                 (source('vendor', 'high'), 'social'),
                                 (self.IGNORELIST, '!facebook')))
        self.assertEqual(verdict['asserted'], ['social'])
        self.assertEqual(verdict['suppressed'], ['facebook'])

    def test_a_corrected_claim_supports_nothing_that_survives(self):
        corrected = resolve(claims((source('vendor', 'high'), 'facebook'),
                                   (source('broad'), 'social'),
                                   (self.IGNORELIST, '!facebook')))
        self.assertEqual(corrected['asserted'], [])
        self.assertEqual(corrected['candidate'], ['social'])
        # The control: uncorrected, the trusted vendor supports the purpose
        uncorrected = resolve(claims((source('vendor', 'high'), 'facebook'),
                                     (source('broad'), 'social')))
        self.assertEqual(uncorrected['asserted'], ['facebook', 'social'])

    def test_a_different_judgement_is_untouched(self):
        verdict = resolve(claims((source('vendor', 'high'), 'malware'),
                                 (source('vendor', 'high'), 'phishing'),
                                 (self.IGNORELIST, '!malware')))
        self.assertEqual(verdict['asserted'], ['phishing'])


class ThresholdTest(unittest.TestCase):
    """A bar per taxonomy branch or path, with one for everything else."""

    def test_a_number_is_the_bar_for_everything(self):
        self.assertEqual(thresholds(3), {'default': 3})
        self.assertEqual(thresholds('3'), {'default': 3})

    def test_a_mapping_keeps_the_default_unless_it_is_named(self):
        self.assertEqual(thresholds({'threat': 1}), {'default': 2, 'threat': 1})
        self.assertEqual(thresholds({'default': 3, 'threat': 1}), {'default': 3, 'threat': 1})

    def test_below_one_means_one_as_it_always_has(self):
        self.assertEqual(thresholds(0), {'default': 1})

    def test_a_key_that_is_not_in_the_taxonomy_is_refused(self):
        # A typo would otherwise apply to nothing and say nothing
        with self.assertRaises(ValueError):
            thresholds({'threats': 1})
        with self.assertRaises(ValueError):
            thresholds({'fakenews': 1})  # a category, not a path

    def test_a_value_that_is_not_a_number_is_refused(self):
        for bad in ('one', None, True, 1.5):
            with self.assertRaises(ValueError):
                thresholds({'threat': bad})

    def test_the_most_specific_key_wins(self):
        bar = thresholds({'threat': 1, 'threat.phishing': 3})
        self.assertEqual(needed(('risk', 'threat.phishing'), bar), 3)
        self.assertEqual(needed(('risk', 'threat.malware'), bar), 1)
        self.assertEqual(needed(('purpose', 'adult.pornography'), bar), 2)

    def test_a_key_matches_whole_labels_only(self):
        bar = thresholds({'media': 1})
        self.assertEqual(needed(('purpose', 'media.video'), bar), 1)
        self.assertEqual(needed(('risk', 'policy.piracy'), bar), 2)

    def test_an_unmapped_category_takes_the_default(self):
        bar = thresholds({'default': 3, 'threat': 1})
        self.assertEqual(needed((None, 'politics'), bar), 3)

    def test_a_branch_can_be_believed_on_one_list(self):
        verdict = resolve(claims((source('a'), 'malware'), (source('b'), 'porn')),
                          min_publishers={'threat': 1})
        self.assertEqual(verdict['asserted'], ['malware'])
        # The control: the same claims under the single bar
        self.assertEqual(resolve(claims((source('a'), 'malware')))['asserted'], [])

    def test_a_branch_can_be_held_to_more(self):
        two = claims((source('a'), 'porn'), (source('b'), 'porn'))
        self.assertEqual(resolve(two, {'adult': 3})['asserted'], [])
        self.assertEqual(resolve(two, {'adult': 3, 'default': 3, 'adult.pornography': 2})
                         ['asserted'], ['porn'])

    def test_a_vendor_needs_every_statement_over_its_own_bar(self):
        # Relaxing the anonymiser bar relaxes `vpn`, but `expressvpn` also
        # names a service, which is still held to the default
        verdict = resolve(claims((source('a'), 'vpn'), (source('a'), 'expressvpn')),
                          min_publishers={'policy': 1})
        self.assertEqual(verdict['asserted'], ['vpn'])
        self.assertEqual(verdict['candidate'], ['expressvpn'])


class DisabledTest(unittest.TestCase):
    """Switching whole categories off by taxonomy branch or path."""

    def test_the_editorial_branch_is_disabled_by_default(self):
        default = disabled_paths(None)
        self.assertEqual(default, frozenset({'editorial'}))
        for category in ('fake-news', 'fakenews', 'fascist', 'zionist'):
            self.assertTrue(is_disabled(category, default), category)
        # Nothing else is
        for category in ('news', 'porn', 'malware', 'social'):
            self.assertFalse(is_disabled(category, default), category)

    def test_an_empty_list_switches_everything_back_on(self):
        self.assertEqual(disabled_paths([]), frozenset())
        self.assertFalse(is_disabled('fakenews', disabled_paths([])))

    def test_an_explicit_list_replaces_the_default(self):
        # Rather than adding to it: naming one thing turns editorial back on
        off = disabled_paths(['policy.anonymiser'])
        self.assertTrue(is_disabled('vpn', off))
        self.assertFalse(is_disabled('fakenews', off))

    def test_a_branch_disables_every_spelling_under_it(self):
        off = disabled_paths(['editorial'])
        for category in ('fake-news', 'fakenews', 'fascist', 'zionist'):
            self.assertTrue(is_disabled(category, off), category)
        # The control: nothing outside the branch
        for category in ('porn', 'malware', 'news', 'social'):
            self.assertFalse(is_disabled(category, off), category)

    def test_a_path_disables_only_that_leaf(self):
        off = disabled_paths('editorial.zionist')
        self.assertTrue(is_disabled('zionist', off))
        self.assertFalse(is_disabled('fascist', off))

    def test_a_vendor_goes_when_anything_it_says_is_disabled(self):
        # Kept, expressvpn would still put policy.anonymiser on the event
        off = disabled_paths(['policy.anonymiser'])
        self.assertTrue(is_disabled('expressvpn', off))
        self.assertTrue(is_disabled('vpn', off))

    def test_a_correction_for_a_disabled_category_goes_too(self):
        self.assertTrue(is_disabled('!fakenews', disabled_paths(['editorial'])))

    def test_an_unknown_entry_is_refused(self):
        # Including a category name, which is not a path: a typo here would
        # leave the category switched on and say nothing
        for bad in (['editorials'], ['fakenews'], 'news'):
            with self.assertRaises(ValueError):
                disabled_paths(bad)


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
            '*.opinion.com': {'vendor': {'fake-news', 'news'}, 'hagezi': {'fakenews'}},
            '*.corrected.com': {'vendor': {'fake-news'}},
        }
        apply_ignorelist(entries, ignorelist={'porn': ['*.tenor.com'],
                                              'fake-news': ['*.corrected.com']})
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
        self.assertEqual(verdict, {'asserted': [], 'candidate': [], 'suppressed': [],
                                   'incidental': False})

    def test_a_vendor_list_asserts_alone(self):
        self.assertEqual(self.verdict('store.steampowered.com')['asserted'], ['games', 'steam'])

    def test_a_correction_holds_against_agreement(self):
        self.assertEqual(self.verdict('media.tenor.com'),
                         {'asserted': [], 'candidate': [], 'suppressed': ['porn'],
                          'incidental': False})

    def test_a_disabled_category_leaves_no_trace(self):
        off = disabled_paths(['editorial'])
        claims, verdict = categorise(self.index, 'www.opinion.com', psl_path=FIXTURE,
                                     disabled=off)
        self.assertEqual(verdict, {'asserted': ['news'], 'candidate': [], 'suppressed': [],
                                   'incidental': False})
        self.assertEqual(describe(claims), ['news:vendor'])
        # The control: the same host with nothing disabled
        claims, verdict = categorise(self.index, 'www.opinion.com', psl_path=FIXTURE)
        self.assertEqual(verdict['asserted'], ['fake-news', 'fakenews', 'news'])

    def test_a_disabled_category_is_not_reported_as_suppressed(self):
        # Suppressed means the ignorelist corrected it, and the label would
        # still be stored against the client
        off = disabled_paths(['editorial'])
        verdict = categorise(self.index, 'www.corrected.com', psl_path=FIXTURE,
                             disabled=off)[1]
        self.assertEqual(verdict, {'asserted': [], 'candidate': [], 'suppressed': [],
                                   'incidental': False})


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

    def test_a_correction_on_the_question_holds_over_every_spelling_in_the_chain(self):
        # www.corrected.com's fake-news is corrected; the chain says fakenews
        bite = self.bite('www.corrected.com',
                         answers=[{'type': 'CNAME', 'data': 'www.opinion.com'}],
                         evidence={'disabled_categories': []})
        self.assertEqual(bite['cname_contexts'], ['fake-news', 'fakenews', 'news'])
        self.assertEqual(bite['contexts'], ['news'])

    def test_without_the_taxonomy_the_chain_would_bring_a_spelling_back(self):
        # Proves the merge's own check is load-bearing: compare spellings only
        # and fakenews comes straight back from the chain
        from unittest import mock
        same_spelling = lambda corrections, category: category in corrections
        with mock.patch('libtb.processor.cancels', same_spelling):
            bite = self.bite('www.corrected.com',
                             answers=[{'type': 'CNAME', 'data': 'www.opinion.com'}],
                             evidence={'disabled_categories': []})
        self.assertEqual(bite['contexts'], ['fakenews', 'news'])

    def test_the_chain_can_settle_a_candidate(self):
        bite = self.bite('cdn.pornsite.com',
                         answers=[{'type': 'CNAME', 'data': 'www.pornsite.com'}])
        self.assertEqual(bite['contexts'], ['porn'])
        self.assertNotIn('contexts_candidate', bite)
        self.assertEqual(bite['match_source'], ['cname'])

    def test_the_bar_is_configurable(self):
        bite = self.bite('cdn.pornsite.com', evidence={'min_publishers': 1})
        self.assertEqual(bite['contexts'], ['porn'])

    def test_the_bar_can_differ_by_branch(self):
        bite = self.bite('cdn.pornsite.com', evidence={'min_publishers': {'adult': 1}})
        self.assertEqual(bite['contexts'], ['porn'])
        bite = self.bite('cdn.pornsite.com', evidence={'min_publishers': {'threat': 1}})
        self.assertEqual(bite['contexts'], [])

    def test_a_bad_bar_stops_the_processor_at_start(self):
        with self.assertRaises(ValueError):
            self.processor(evidence={'min_publishers': {'threats': 1}})

    def test_a_disabled_category_never_reaches_the_event(self):
        bite = self.bite('www.opinion.com', evidence={'disabled_categories': ['editorial']})
        self.assertEqual(bite['contexts'], ['news'])
        self.assertEqual(bite['claims'], ['news:vendor'])
        self.assertEqual(bite['sources'], ['vendor'])
        self.assertNotIn('risk', bite)
        for field in ('contexts_candidate', 'contexts_suppressed'):
            self.assertNotIn(field, bite)

    def test_a_disabled_category_is_not_merged_from_the_chain(self):
        answers = [{'type': 'CNAME', 'data': 'www.opinion.com'}]
        bite = self.bite('www.unlisted.example', answers=answers,
                         evidence={'disabled_categories': ['editorial']})
        self.assertEqual(bite['contexts'], ['news'])
        # The control
        bite = self.bite('www.unlisted.example', answers=answers,
                         evidence={'disabled_categories': []})
        self.assertEqual(bite['contexts'], ['fake-news', 'fakenews', 'news'])

    def test_events_carry_no_editorial_label_unless_it_is_switched_on(self):
        bite = self.bite('www.opinion.com')
        self.assertEqual(bite['contexts'], ['news'])
        self.assertEqual(bite['claims'], ['news:vendor'])
        bite = self.bite('www.opinion.com', evidence={'disabled_categories': []})
        self.assertEqual(bite['contexts'], ['fake-news', 'fakenews', 'news'])
        self.assertEqual(bite['risk'], ['editorial.fakenews'])

    def test_an_explicit_list_on_the_processor_replaces_the_default(self):
        bite = self.bite('www.opinion.com',
                         evidence={'disabled_categories': ['adult.pornography']})
        self.assertEqual(bite['contexts'], ['fake-news', 'fakenews', 'news'])

    def test_an_unknown_disabled_entry_stops_the_processor_at_start(self):
        with self.assertRaises(ValueError):
            self.processor(evidence={'disabled_categories': ['fakenews']})

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
