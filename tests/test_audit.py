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
from libtb.audit import audit_settings, audit, format_report, parse_bar, read_reference
from libtb.evidence import disabled_paths
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

    def run_audit(self, entries, domains, **kwargs):
        build(entries, path=self.path, built_at=1000, sources=SOURCES)
        index = DomainIndex(self.path)
        try:
            return audit(index, domains, psl_path=FIXTURE, **kwargs)
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

    def test_a_disabled_category_is_audited_as_events_will_carry_it(self):
        entries = {'*.opinion.com': {'vendor': {'fakenews', 'news'}}}
        report = self.run_audit(entries, ['opinion.com'],
                                disabled=disabled_paths(['editorial']))
        self.assertEqual(sorted(report['asserted']), ['news'])
        self.assertEqual(sorted(self.run_audit(entries, ['opinion.com'],
                                               disabled=disabled_paths([]))['asserted']),
                         ['fakenews', 'news'])

    def test_the_report_can_be_limited_to_named_categories(self):
        report = self.run_audit({'*.popular.com': {'vendor': {'games', 'steam'}}}, ['popular.com'])
        text = '\n'.join(format_report(report, 1, categories={'steam'}))
        self.assertIn('steam', text)
        self.assertNotIn('games', text)


class AuditSettingsTest(unittest.TestCase):
    """The audit reads processor.evidence exactly as the workers do."""

    def test_overriding_the_bar_keeps_the_configured_switches(self):
        # The case that broke: --index and --min-publishers given, so the
        # config was never read and the default replaced what was configured
        bar, disabled = audit_settings({'disabled_categories': []}, min_publishers='2')
        self.assertEqual(disabled, frozenset())
        self.assertEqual(bar, {'default': 2})

    def test_a_configured_list_survives_an_override_of_the_bar(self):
        _, disabled = audit_settings({'disabled_categories': ['editorial', 'adult.gambling']},
                                     min_publishers='default=2,threat=1')
        self.assertEqual(disabled, frozenset({'editorial', 'adult.gambling'}))

    def test_nothing_configured_means_the_default(self):
        self.assertEqual(audit_settings({})[1], frozenset({'editorial'}))

    def test_disable_replaces_the_configured_list(self):
        _, disabled = audit_settings({'disabled_categories': ['editorial']},
                                     disabled=['adult.gambling'])
        self.assertEqual(disabled, frozenset({'adult.gambling'}))

    def test_an_empty_disable_switches_nothing_off(self):
        self.assertEqual(audit_settings({}, disabled=[''])[1], frozenset())

    def test_a_bad_value_is_refused(self):
        for kwargs in ({'min_publishers': 'default=two'}, {'disabled': ['fakenews']}):
            with self.assertRaises(ValueError, msg=kwargs):
                audit_settings({}, **kwargs)


if __name__ == '__main__':
    unittest.main(verbosity=2)
