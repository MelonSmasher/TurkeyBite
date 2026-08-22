"""Tests for the three facets.

The flat array asserts three unrelated things at once, so the risk in splitting
it is not a missing row: it is a row that lands in the wrong facet, or a category
silently mapping to nothing when a new list source appears.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from libtb.processor import Processor, taxonomy_fields
from libtb.taxonomy import PURPOSE, RISK, SERVICE, SEVERITY, TAXONOMY, classify


class MappingIntegrityTest(unittest.TestCase):
    """Properties every row has to hold, checked over the whole table."""

    def test_every_row_names_a_known_facet(self):
        for category, rows in TAXONOMY.items():
            for facet, path in rows:
                self.assertIn(facet, (PURPOSE, SERVICE, RISK), category)

    def test_every_path_is_non_empty_and_lower_case(self):
        for category, rows in TAXONOMY.items():
            for _, path in rows:
                self.assertTrue(path, category)
                self.assertEqual(path, path.lower(), category)
                self.assertFalse(path.startswith('.'), category)
                self.assertFalse(path.endswith('.'), category)

    def test_every_key_is_lower_case(self):
        for category in TAXONOMY:
            self.assertEqual(category, category.lower())

    def test_no_row_assigns_the_same_facet_twice(self):
        for category, rows in TAXONOMY.items():
            facets = [facet for facet, _ in rows]
            self.assertEqual(len(facets), len(set(facets)), category)

    def test_purpose_and_risk_paths_are_hierarchical(self):
        # Prefix queries are the point of these two facets, so a bare leaf with
        # no branch would be unqueryable by branch
        for category, rows in TAXONOMY.items():
            for facet, path in rows:
                if facet in (PURPOSE, RISK):
                    self.assertIn('.', path, f'{category} -> {path}')

    def test_every_severity_key_is_a_risk_path_in_use(self):
        risk_paths = {path for rows in TAXONOMY.values()
                      for facet, path in rows if facet == RISK}
        for path in SEVERITY:
            if path == 'threat.c2':
                continue  # declared ahead of a source that emits it
            self.assertIn(path, risk_paths, path)

    def test_the_editorial_branch_carries_no_severity(self):
        # Judgements to report on request, not to rank against malware
        for path in SEVERITY:
            self.assertFalse(path.startswith('editorial.'), path)


class ClassifyTest(unittest.TestCase):

    def test_a_purpose_category_lands_in_purpose(self):
        self.assertEqual(classify(['search']), {'purpose': ['information.search']})

    def test_a_risk_category_lands_in_risk_with_severity(self):
        got = classify(['malware'])
        self.assertEqual(got['risk'], ['threat.malware'])
        self.assertEqual(got['risk_severity'], 'high')

    def test_a_service_category_contributes_both_service_and_purpose(self):
        got = classify(['steam'])
        self.assertEqual(got['service'], ['valve.steam'])
        self.assertEqual(got['purpose'], ['gaming.storefronts'])

    def test_the_three_facets_separate_cleanly(self):
        got = classify(['facebook', 'social', 'tracking'])
        self.assertEqual(got['service'], ['meta.facebook'])
        self.assertEqual(got['purpose'], ['social.networks'])
        self.assertEqual(got['risk'], ['privacy.tracking'])

    def test_empty_facets_are_omitted_not_emitted_empty(self):
        got = classify(['search'])
        self.assertNotIn('service', got)
        self.assertNotIn('risk', got)
        self.assertNotIn('risk_severity', got)

    def test_severity_takes_the_highest_present(self):
        self.assertEqual(classify(['advertising', 'malware'])['risk_severity'], 'high')
        self.assertEqual(classify(['advertising', 'fraud'])['risk_severity'], 'medium')
        self.assertEqual(classify(['advertising'])['risk_severity'], 'low')

    def test_a_risk_with_no_severity_yields_no_severity(self):
        got = classify(['fascist'])
        self.assertEqual(got['risk'], ['editorial.fascist'])
        self.assertNotIn('risk_severity', got)

    # -- the unifications --------------------------------------------------

    def test_two_spellings_of_one_judgement_collapse(self):
        self.assertEqual(classify(['fake-news'])['risk'], ['editorial.fakenews'])
        self.assertEqual(classify(['fakenews'])['risk'], ['editorial.fakenews'])
        self.assertEqual(classify(['fake-news', 'fakenews'])['risk'],
                         ['editorial.fakenews'])

    def test_a_service_named_two_ways_collapses(self):
        self.assertEqual(classify(['signal'])['service'], ['signal'])
        self.assertEqual(classify(['whispersystems'])['service'], ['signal'])
        self.assertEqual(classify(['signal', 'whispersystems'])['service'], ['signal'])

    def test_every_vpn_vendor_carries_the_same_policy_risk(self):
        vendors = [c for c in TAXONOMY
                   if any(p == 'policy.anonymiser' for _, p in TAXONOMY[c])]
        self.assertGreater(len(vendors), 10)
        for vendor in vendors:
            self.assertEqual(classify([vendor])['risk'], ['policy.anonymiser'], vendor)

    def test_a_vpn_vendor_is_still_identifiable_as_a_service(self):
        # The flat array could not say "this is Proton and it is an anonymiser"
        got = classify(['protonvpn'])
        self.assertEqual(got['service'], ['proton.vpn'])
        self.assertEqual(got['risk'], ['policy.anonymiser'])

    def test_adult_content_is_a_purpose_not_a_risk(self):
        # Whether it is a policy violation is a separate question
        for category, path in (('porn', 'adult.pornography'),
                               ('gambling', 'adult.gambling'),
                               ('drugs', 'adult.drugs')):
            got = classify([category])
            self.assertEqual(got['purpose'], [path], category)
            self.assertNotIn('risk', got)

    # -- unmapped and bad input --------------------------------------------

    def test_an_unknown_category_is_reported_not_dropped(self):
        self.assertEqual(classify(['nosuchthing']), {'unmapped': ['nosuchthing']})

    def test_a_known_and_unknown_category_together(self):
        got = classify(['search', 'nosuchthing'])
        self.assertEqual(got['purpose'], ['information.search'])
        self.assertEqual(got['unmapped'], ['nosuchthing'])

    def test_categories_are_matched_case_insensitively(self):
        self.assertEqual(classify(['SEARCH'])['purpose'], ['information.search'])
        self.assertEqual(classify([' search '])['purpose'], ['information.search'])

    def test_duplicates_do_not_duplicate_paths(self):
        self.assertEqual(classify(['search', 'search'])['purpose'],
                         ['information.search'])

    def test_no_contexts_yields_nothing(self):
        for empty in (None, [], ()):
            self.assertEqual(classify(empty), {})

    def test_non_string_and_blank_entries_are_skipped(self):
        got = classify([None, 7, '', '   ', [], 'search'])
        self.assertEqual(got, {'purpose': ['information.search']})

    def test_results_are_sorted_for_stable_documents(self):
        got = classify(['tiktok', 'facebook', 'instagram'])
        self.assertEqual(got['service'], sorted(got['service']))
        self.assertEqual(got['purpose'], sorted(got['purpose']))


class TaxonomyFieldsTest(unittest.TestCase):
    """The bite-facing shape."""

    def test_unmapped_is_renamed_for_the_document(self):
        got = taxonomy_fields(['nosuchthing'])
        self.assertEqual(got, {'unmapped_contexts': ['nosuchthing']})

    def test_nothing_is_emitted_for_no_contexts(self):
        self.assertEqual(taxonomy_fields([]), {})


class FacetWiringTest(unittest.TestCase):
    """Facets have to reach both feeds, including chain-derived categories."""

    def dns_processor(self):
        processor = Processor({'dns': {'lookup_ips': False},
                              'domain_index': {'mode': 'index'}}, {})
        self.shipped = []
        processor.ship_bite = self.shipped.append
        return processor

    def dns_packet(self, answers=None):
        dns = {'question': {'name': 'www.example.com'}}
        if answers is not None:
            dns['answers'] = answers
        return {'type': 'dns', 'resource': 'www.example.com', 'dns': dns,
                'network': {'direction': 'ingress'}, 'client': {'ip': '10.0.0.5'},
                '@timestamp': '2026-08-22T04:00:00Z'}

    def test_a_dns_event_carries_the_facets(self):
        processor = self.dns_processor()
        processor.resolve_contexts = lambda s: (['facebook', 'social'], {})
        processor.resolve_chain = lambda c: ([], [], [])
        processor.process_dns_packet(self.dns_packet())
        bite = self.shipped[0]['bite']
        self.assertEqual(bite['contexts'], ['facebook', 'social'])
        self.assertEqual(bite['service'], ['meta.facebook'])
        self.assertEqual(bite['purpose'], ['social.networks'])

    def test_a_category_from_the_chain_is_faceted_too(self):
        processor = self.dns_processor()
        processor.resolve_contexts = lambda s: ([], {})
        processor.resolve_chain = lambda c: (['tracking'], [], list(c))
        processor.process_dns_packet(self.dns_packet(
            answers=[{'type': 'CNAME', 'data': 'metrics.vendor.example'}]))
        bite = self.shipped[0]['bite']
        self.assertEqual(bite['risk'], ['privacy.tracking'])
        self.assertEqual(bite['risk_severity'], 'low')

    def test_a_browser_event_carries_the_facets(self):
        processor = Processor({}, {})
        shipped = []
        processor.ship_bite = shipped.append
        processor.resolve_contexts = lambda s: (['malware'], {})
        processor.process_browser_history({
            'type': 'browser.history',
            'data': {'@timestamp': '2026-08-22T04:00:00Z',
                     'event': {'data': {'entry': {
                         'url': 'https://bad.example.com/x',
                         'url_data': {'Scheme': 'https', 'Host': 'bad.example.com'}}}}}})
        bite = shipped[0]['bite']
        self.assertEqual(bite['contexts'], ['malware'])
        self.assertEqual(bite['risk'], ['threat.malware'])
        self.assertEqual(bite['risk_severity'], 'high')

    def test_contexts_is_left_exactly_as_it_was(self):
        # The whole migration rests on nothing that reads the flat array breaking
        processor = self.dns_processor()
        processor.resolve_contexts = lambda s: (['social', 'facebook'], {})
        processor.resolve_chain = lambda c: ([], [], [])
        processor.process_dns_packet(self.dns_packet())
        self.assertEqual(self.shipped[0]['bite']['contexts'], ['social', 'facebook'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
