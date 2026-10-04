"""Tests for the report on how much one list repeats another.

The report exists to catch copying that `derived_from` does not declare, so
the case that matters is a heavy overlap between two lists weighed as
independent. It must flag that, and must not flag what the configuration
already accounts for, or the one useful line drowns in noise.
"""

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))

from libtb.audit.independence import format_report, measure, normalise, report
from libtb.index import DomainIndex, Source
from libtb.index.builder import apply_ignorelist, build, local_source


def source(name, trust='medium', publisher=None, derived_from=()):
    return Source(name, publisher or name, trust, False, tuple(derived_from))


def hosts(prefix, count):
    return [f'{prefix}{i}.example' for i in range(count)]


class IndependenceTest(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-independence-')
        self.path = os.path.join(self.root, 'domains.tbidx')
        self.index = None

    def tearDown(self):
        if self.index is not None:
            self.index.close()
        shutil.rmtree(self.root, ignore_errors=True)

    def build(self, lists, sources, ignorelist=None):
        """`lists` maps a source name to (category, [keys])."""
        entries = {}
        for name, (category, keys) in lists.items():
            for key in keys:
                entries.setdefault(key, {}).setdefault(name, set()).add(category)
        if ignorelist:
            apply_ignorelist(entries, ignorelist=ignorelist)
        build(entries, path=self.path, built_at=1000, sources=sources)
        self.index = DomainIndex(self.path)
        return self.index

    def pairs(self, found):
        return {(inner, outer): (how, matters)
                for _, inner, outer, _, how, _, matters in found['contained']}

    def test_an_undeclared_copy_is_flagged(self):
        index = self.build({'copy': ('gambling', hosts('g', 60)),
                            'big': ('gambling', hosts('g', 200))},
                           {'copy': source('copy'), 'big': source('big')})
        found = report(index, min_entries=50)
        self.assertEqual(self.pairs(found), {('copy', 'big'): ('undeclared', True)})

    def test_a_declared_copy_is_measured_not_flagged(self):
        index = self.build({'copy': ('gambling', hosts('g', 60)),
                            'big': ('gambling', hosts('g', 200))},
                           {'copy': source('copy', derived_from=['big']), 'big': source('big')})
        found = report(index, min_entries=50)
        how, matters = self.pairs(found)[('copy', 'big')]
        self.assertTrue(how.startswith('declared'))
        self.assertFalse(matters)
        self.assertEqual(found['declared'], [('copy', 'big', 0.3, 1.0)])

    def test_a_shared_upstream_is_named_and_still_flagged(self):
        # It is the likely explanation, but the evidence rules do not treat it
        # as dependence, so the pair can still count twice
        index = self.build({'copy': ('gambling', hosts('g', 60)),
                            'big': ('gambling', hosts('g', 200))},
                           {'copy': source('copy', derived_from=['up']),
                            'big': source('big', derived_from=['up', 'other'])})
        self.assertEqual(self.pairs(report(index, min_entries=50)),
                         {('copy', 'big'): ('undeclared, though both copy up', True)})

    def test_one_publisher_is_not_flagged(self):
        index = self.build({'a': ('porn', hosts('p', 60)), 'b': ('porn', hosts('p', 200))},
                           {'a': source('a', publisher='blp'), 'b': source('b', publisher='blp')})
        self.assertEqual(self.pairs(report(index, min_entries=50)),
                         {('a', 'b'): ('same publisher', False)})

    def test_lists_that_say_different_things_are_not_flagged(self):
        # Block List Project's malware list names ad networks, which an ad list
        # also names, but the two can never corroborate each other
        index = self.build({'ads': ('advertising', hosts('a', 60)),
                            'malware': ('malicious', hosts('a', 200))},
                           {'ads': source('ads'), 'malware': source('malware')})
        self.assertEqual(self.pairs(report(index, min_entries=50)),
                         {('ads', 'malware'): ('undeclared', False)})

    def test_a_high_trust_list_is_not_flagged(self):
        # It asserts alone, so whether it is independent changes nothing
        index = self.build({'vendor': ('piracy', hosts('v', 60)),
                            'broad': ('piracy', hosts('v', 200))},
                           {'vendor': source('vendor', 'high'), 'broad': source('broad')})
        self.assertEqual(self.pairs(report(index, min_entries=50)),
                         {('vendor', 'broad'): ('undeclared', False)})

    def test_a_small_overlap_is_not_reported(self):
        index = self.build({'a': ('porn', hosts('p', 100)),
                            'b': ('porn', hosts('p', 40) + hosts('q', 100))},
                           {'a': source('a'), 'b': source('b')})
        self.assertEqual(self.pairs(report(index, threshold=0.5, min_entries=50)), {})

    def test_a_tiny_list_is_left_out(self):
        index = self.build({'tiny': ('porn', hosts('p', 5)), 'big': ('porn', hosts('p', 200))},
                           {'tiny': source('tiny'), 'big': source('big')})
        self.assertEqual(self.pairs(report(index, min_entries=50)), {})
        self.assertEqual(len(report(index, min_entries=1)['contained']), 1)

    def test_spellings_of_one_site_count_as_one(self):
        self.assertEqual(normalise('*.www.example.com'), 'example.com')
        self.assertEqual(normalise('www.example.com'), 'example.com')
        index = self.build({'hosts': ('porn', ['www.a.example', 'a.example']),
                            'adblock': ('porn', ['*.a.example'])},
                           {'hosts': source('hosts'), 'adblock': source('adblock')})
        sizes, shared, _ = measure(index)
        self.assertEqual(sizes, {'hosts': 1, 'adblock': 1})
        self.assertEqual(sum(shared.values()), 1)

    def test_local_lists_and_corrections_are_left_out(self):
        index = self.build({'turkeybite': ('porn', hosts('p', 60)),
                            'broad': ('porn', hosts('p', 60))},
                           {'turkeybite': local_source('turkeybite'), 'broad': source('broad')},
                           ignorelist={'porn': hosts('p', 60)})
        sizes, shared, _ = measure(index)
        self.assertEqual(sizes, {'broad': 60})
        self.assertEqual(dict(shared), {})

    def test_a_declaration_nothing_configured_can_check_is_named(self):
        index = self.build({'irek': ('games', hosts('g', 60)),
                            'ut1-social': ('social', hosts('s', 60))},
                           {'irek': source('irek', derived_from=['ut1']),
                            'ut1-social': source('ut1-social', publisher='ut1')})
        found = report(index, min_entries=50)
        self.assertEqual(found['declared'], [])
        self.assertEqual(found['unmeasured'], [('irek', 'ut1')])

    def test_the_report_marks_the_pairs_that_matter(self):
        index = self.build({'copy': ('gambling', hosts('g', 60)),
                            'big': ('gambling', hosts('g', 200))},
                           {'copy': source('copy'), 'big': source('big')})
        text = '\n'.join(format_report(report(index, min_entries=50)))
        self.assertRegex(text, r'!\s+100% of copy \(60\) is in big \(200\)')
        self.assertIn('both say adult.gambling', text)


class EntriesTest(unittest.TestCase):

    def test_every_key_comes_back_with_its_claims(self):
        root = tempfile.mkdtemp(prefix='tb-entries-')
        self.addCleanup(shutil.rmtree, root, True)
        path = os.path.join(root, 'domains.tbidx')
        entries = {'b.example': {'x': {'porn'}}, '*.a.example': {'x': {'porn', 'gambling'}}}
        build(entries, path=path, built_at=1000, sources={'x': source('x')})
        index = DomainIndex(path)
        self.addCleanup(index.close)
        got = {key: sorted(category for _, category in claims)
               for key, claims in index.entries()}
        self.assertEqual(got, {'b.example': ['porn'], '*.a.example': ['gambling', 'porn']})


if __name__ == '__main__':
    unittest.main(verbosity=2)
