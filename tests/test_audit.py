"""Tests for the false positive audit.

The audit is only worth trusting if it reports what live events will say, so
these run it over a real index rather than over stubbed claims.
"""

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))

from libtb import psl
from libtb.audit import audit, format_report, parse_bar, read_reference
from libtb.index import DomainIndex, Source
from libtb.index.builder import build

FIXTURE = os.path.join(HERE, 'fixture_public_suffix_list.dat')

SOURCES = {
    'vendor': Source('vendor', 'nextdns', 'high', False, ()),
    'stevenblack': Source('stevenblack', 'StevenBlack', 'medium', False, ()),
    'hagezi': Source('hagezi', 'hagezi', 'medium', False, ()),
    'cyberhost': Source('cyberhost', 'cyberhost', 'medium', False, ()),
    'blp': Source('blp', 'blocklistproject', 'low', False, ()),
}


class AuditTest(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-audit-')
        self.path = os.path.join(self.root, 'domains.tbidx')

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        psl.forget()

    def run_audit(self, entries, domains):
        build(entries, path=self.path, built_at=1000, sources=SOURCES)
        index = DomainIndex(self.path)
        try:
            return audit(index, domains, psl_path=FIXTURE)
        finally:
            index.close()

    def test_a_tranco_csv_and_a_plain_list_both_read(self):
        path = os.path.join(self.root, 'ref.csv')
        with open(path, 'w') as fh:
            fh.write('1,google.com\n2,Example.COM.\n\n# note\n3,nodot\n')
        self.assertEqual(read_reference(path), ['google.com', 'example.com'])
        self.assertEqual(read_reference(path, limit=1), ['google.com'])
        with open(path, 'w') as fh:
            fh.write('google.com\nexample.com\n')
        self.assertEqual(read_reference(path), ['google.com', 'example.com'])

    def test_the_bar_reads_as_a_number_or_per_branch(self):
        self.assertEqual(parse_bar('2'), '2')
        self.assertEqual(parse_bar('default=2, threat=1'), {'default': '2', 'threat': '1'})

    def test_asserted_and_held_back_are_reported_apart(self):
        report = self.run_audit({
            'pornsite.com': {'stevenblack': {'porn'}},
            '*.pornsite.com': {'hagezi': {'porn'}},
            '*.coinbase.com': {'blp': {'malicious'}},
        }, ['pornsite.com', 'coinbase.com'])
        self.assertEqual([d for _, d, _ in report['asserted']['porn']], ['pornsite.com'])
        self.assertEqual([d for _, d, _ in report['candidate']['malicious']], ['coinbase.com'])
        self.assertNotIn('malicious', report['asserted'])

    def test_the_www_spelling_is_checked_too(self):
        # The bare name is often never queried, so a list naming only www
        # would otherwise pass unnoticed
        report = self.run_audit({'www.example.org': {'vendor': {'games'}}}, ['example.org'])
        self.assertEqual([d for _, d, _ in report['asserted']['games']], ['example.org'])

    def test_a_threat_is_blamed_on_the_lists_that_asserted_it(self):
        report = self.run_audit({'*.popular.com': {
            'hagezi': {'malicious'}, 'cyberhost': {'malicious'}, 'blp': {'malicious'},
        }}, ['popular.com'])
        # The low trust list claimed it too, but could not have contributed
        self.assertEqual(dict(report['blamed']), {'hagezi': 1, 'cyberhost': 1})

    def test_a_purpose_category_is_never_blamed(self):
        report = self.run_audit({'*.pornsite.com': {'vendor': {'porn'}}}, ['pornsite.com'])
        self.assertEqual(dict(report['blamed']), {})

    def test_the_report_marks_threats_and_names_their_sources(self):
        report = self.run_audit({'*.popular.com': {
            'hagezi': {'malicious'}, 'cyberhost': {'malicious'},
        }}, ['popular.com'])
        text = '\n'.join(format_report(report, 1))
        self.assertIn('malicious', text)
        self.assertIn('threat', text)
        self.assertIn('#1       popular.com', text)
        self.assertRegex(text, r'cyberhost\s+1')

    def test_the_report_can_be_limited_to_named_categories(self):
        report = self.run_audit({'*.popular.com': {'vendor': {'games', 'steam'}}}, ['popular.com'])
        text = '\n'.join(format_report(report, 1, categories={'steam'}))
        self.assertIn('steam', text)
        self.assertNotIn('games', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
