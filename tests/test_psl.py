"""Tests for registrable domains.

Taking the last two labels is wrong whenever the public part of a name is itself
more than one label, and it fails in two directions: an ignore entry for
bbc.co.uk never fires because the derived domain is co.uk, and an entry for co.uk
suppresses every .co.uk site observed.

The fixture is a real copy of the list, so these exercise the actual rule set
including its wildcard, exception and internationalised entries.
"""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))

from libtb import psl
from libtb.processor import Processor, domain_fields
from libtb.sieve import Filters

FIXTURE = os.path.join(HERE, 'fixture_public_suffix_list.dat')


class ParseTest(unittest.TestCase):

    def test_the_three_rule_kinds_are_separated(self):
        rules, wildcards, exceptions = psl.parse([
            '// a comment', '', 'com', 'co.uk', '*.ck', '!www.ck',
        ])
        self.assertIn('com', rules)
        self.assertIn('co.uk', rules)
        self.assertIn('ck', wildcards)
        self.assertIn('www.ck', exceptions)

    def test_comments_and_blanks_are_skipped(self):
        rules, _, _ = psl.parse(['// x', '   ', '', 'com'])
        self.assertEqual(rules, {'com'})

    def test_trailing_commentary_is_dropped(self):
        rules, _, _ = psl.parse(['com // the com tld'])
        self.assertEqual(rules, {'com'})

    def test_an_internationalised_rule_is_stored_in_both_spellings(self):
        # The list writes these in Unicode, DNS carries them as punycode, so a
        # query would never match the rule as written
        rules, _, _ = psl.parse(['公司.cn'])
        self.assertIn('公司.cn', rules)
        self.assertIn('xn--55qx5d.cn', rules)

    def test_ascii_form_leaves_ascii_alone(self):
        self.assertIsNone(psl.ascii_form('co.uk'))

    def test_a_short_rule_set_is_not_usable(self):
        self.assertFalse(psl.usable({'com', 'co.uk', 'github.io'}))

    def test_the_real_list_is_usable(self):
        with open(FIXTURE, encoding='utf-8') as handle:
            rules, _, _ = psl.parse(handle)
        self.assertTrue(psl.usable(rules))


class RegistrableDomainTest(unittest.TestCase):

    def setUp(self):
        psl.forget()

    def rd(self, host):
        return psl.registrable_domain(host, FIXTURE)

    def suffix(self, host):
        return psl.public_suffix(host, FIXTURE)

    def test_the_simple_case(self):
        self.assertEqual(self.rd('www.example.com'), 'example.com')

    def test_a_two_label_public_suffix(self):
        self.assertEqual(self.rd('news.bbc.co.uk'), 'bbc.co.uk')

    def test_a_deep_subdomain_still_reduces_to_the_owner(self):
        self.assertEqual(self.rd('a.b.c.d.bbc.co.uk'), 'bbc.co.uk')

    def test_a_private_suffix_gives_each_subdomain_its_own_owner(self):
        # Every Blogspot site has a different owner, so blogspot.com is not one
        # registrable domain
        self.assertEqual(self.rd('tiksaveng.blogspot.com'), 'tiksaveng.blogspot.com')
        self.assertEqual(self.rd('somesite.github.io'), 'somesite.github.io')

    def test_a_multi_label_private_suffix(self):
        self.assertEqual(self.rd('bucket.s3.amazonaws.com'),
                         'bucket.s3.amazonaws.com')

    def test_the_case_from_the_index_differential(self):
        self.assertEqual(self.rd('client.v.javhd.co.uk'), 'javhd.co.uk')

    def test_a_bare_public_suffix_has_no_owner(self):
        # This is the point: neither is a website, so neither can be grouped on
        for host in ('co.uk', 'github.io', 'com', 'blogspot.com', 'ac.uk'):
            self.assertIsNone(self.rd(host), host)

    def test_an_internationalised_suffix_in_punycode(self):
        self.assertIsNone(self.rd('xn--55qx5d.cn'))
        self.assertEqual(self.rd('a.xn--55qx5d.cn'), 'a.xn--55qx5d.cn')

    def test_a_wildcard_rule(self):
        # *.ck means any single label under ck is a public suffix
        self.assertEqual(self.suffix('foo.ck'), 'foo.ck')
        self.assertEqual(self.rd('bar.foo.ck'), 'bar.foo.ck')

    def test_an_exception_rule_beats_its_wildcard(self):
        # !www.ck means www.ck is not a public suffix, so ck is
        self.assertEqual(self.suffix('www.ck'), 'ck')
        self.assertEqual(self.rd('www.ck'), 'www.ck')

    def test_an_unknown_tld_falls_through_to_the_last_label(self):
        self.assertEqual(self.suffix('host.invalidtldxyz'), 'invalidtldxyz')
        self.assertEqual(self.rd('host.invalidtldxyz'), 'host.invalidtldxyz')

    def test_case_and_trailing_dots_are_handled(self):
        self.assertEqual(self.rd('WWW.Example.COM.'), 'example.com')

    def test_a_single_label_has_no_registrable_domain(self):
        for host in ('localhost', 'a', ''):
            self.assertIsNone(self.rd(host), repr(host))

    def test_bad_input_does_not_raise(self):
        for bad in (None, 7, [], {}, '.', '..'):
            self.assertIsNone(self.rd(bad), repr(bad))


class FallbackTest(unittest.TestCase):
    """A container that has not fetched the list yet must not get worse."""

    def setUp(self):
        # The cache is module level, so drop it or the result depends on which
        # test ran first
        psl.forget()
        self.missing = os.path.join(tempfile.mkdtemp(prefix='tb-psl-'), 'absent.dat')

    def tearDown(self):
        psl.forget()

    def garbage(self):
        path = os.path.join(tempfile.mkdtemp(prefix='tb-psl-bad-'), 'bad.dat')
        with open(path, 'w') as handle:
            handle.write('<html>404 not found</html>\n')
        return path

    def test_no_list_means_no_psl(self):
        self.assertFalse(psl.using_psl(self.missing))

    def test_no_list_falls_back_to_the_old_behaviour(self):
        # Exactly what the code did before, so nothing regresses
        self.assertEqual(psl.registrable_domain('www.example.com', self.missing),
                         'example.com')
        self.assertEqual(psl.registrable_domain('news.bbc.co.uk', self.missing),
                         'co.uk')

    def test_the_real_list_reports_itself_as_loaded(self):
        self.assertTrue(psl.using_psl(FIXTURE))

    def test_a_garbage_file_is_not_adopted(self):
        path = self.garbage()
        self.assertFalse(psl.using_psl(path))
        self.assertEqual(psl.registrable_domain('news.bbc.co.uk', path), 'co.uk')

    def test_garbage_does_not_replace_a_list_already_loaded(self):
        # The refresh loop overwrites in place, so a bad fetch must leave the
        # working rules alone rather than downgrade to the fallback
        self.assertTrue(psl.using_psl(FIXTURE))
        path = self.garbage()
        self.assertTrue(psl.using_psl(path))
        self.assertEqual(psl.registrable_domain('news.bbc.co.uk', path),
                         'bbc.co.uk')

    def test_the_list_is_picked_up_without_a_restart(self):
        # psl.sh fetches after the consumers are already running
        directory = tempfile.mkdtemp(prefix='tb-psl-late-')
        path = os.path.join(directory, 'public_suffix_list.dat')
        self.assertEqual(psl.registrable_domain('news.bbc.co.uk', path), 'co.uk')
        with open(FIXTURE, encoding='utf-8') as src, open(path, 'w') as dst:
            dst.write(src.read())
        self.assertEqual(psl.registrable_domain('news.bbc.co.uk', path),
                         'bbc.co.uk')


class SieveIgnoreMatchingTest(unittest.TestCase):
    """The live bug: browser ignore entries that never fired."""

    def sieve(self, ignore_domains):
        return Filters({
            'drop_error_packets': False, 'drop_replies': False,
            'ignore': {'clients': [], 'domains': [], 'hosts': []},
            'browserbeat': {'ignore': {'clients': [], 'users': [],
                                       'domains': ignore_domains, 'hosts': []}},
        })

    def event(self, host):
        return {'type': 'browser.history',
                'data': {'@timestamp': '2026-08-22T04:00:00Z',
                         'event': {'data': {'entry': {
                             'url': f'https://{host}/page',
                             'url_data': {'Scheme': 'https', 'Host': host}}}}}}

    def test_an_entry_for_a_two_label_suffix_domain_now_fires(self):
        # Derived co.uk and compared that, so this never matched
        self.assertFalse(self.sieve(['bbc.co.uk']).browserbeat(
            self.event('news.bbc.co.uk')))

    def test_a_deep_subdomain_is_still_caught(self):
        self.assertFalse(self.sieve(['bbc.co.uk']).browserbeat(
            self.event('a.b.news.bbc.co.uk')))

    def test_the_ordinary_case_still_works(self):
        self.assertFalse(self.sieve(['example.com']).browserbeat(
            self.event('www.example.com')))

    def test_an_unrelated_host_is_kept(self):
        self.assertTrue(self.sieve(['example.com']).browserbeat(
            self.event('www.other.net')))

    def test_a_partial_label_does_not_match(self):
        # notexample.com must not be caught by an entry for example.com
        self.assertTrue(self.sieve(['example.com']).browserbeat(
            self.event('www.notexample.com')))


class DomainFieldsTest(unittest.TestCase):

    def test_the_field_is_emitted(self):
        got = domain_fields('www.example.com', FIXTURE)
        self.assertEqual(got['registrable_domain'], 'example.com')
        self.assertNotIn('psl_fallback', got)

    def test_a_bare_suffix_emits_nothing(self):
        self.assertEqual(domain_fields('com', FIXTURE), {})

    def test_a_guessed_domain_is_marked_as_such(self):
        # The degradation has to be visible, or an aggregation over a window
        # containing it looks the same as one over correct data
        missing = os.path.join(tempfile.mkdtemp(prefix='tb-psl-'), 'absent.dat')
        got = domain_fields('news.bbc.co.uk', missing)
        self.assertEqual(got['registrable_domain'], 'co.uk')
        self.assertIs(got['psl_fallback'], True)

    def dns_bite(self, host, path):
        processor = Processor({'dns': {'lookup_ips': False},
                              'domain_index': {'mode': 'index'}}, {})
        shipped = []
        processor.ship_bite = shipped.append
        processor.resolve_contexts = lambda s: ([], {})
        processor.resolve_chain = lambda c: ([], [], [])
        original = Processor.process_dns_packet
        # The processor calls domain_fields with its default path; point that at
        # the fixture for the duration of the call
        import libtb.processor as P
        real = P.domain_fields
        P.domain_fields = lambda h, p=path: real(h, p)
        try:
            processor.process_dns_packet({
                'type': 'dns', 'resource': host,
                'dns': {'question': {'name': host}},
                'network': {'direction': 'ingress'}, 'client': {'ip': '10.0.0.5'},
                '@timestamp': '2026-08-22T04:00:00Z'})
        finally:
            P.domain_fields = real
        return shipped[0]['bite']

    def test_a_dns_event_carries_the_domain(self):
        bite = self.dns_bite('news.bbc.co.uk', FIXTURE)
        self.assertEqual(bite['registrable_domain'], 'bbc.co.uk')
        self.assertNotIn('psl_fallback', bite)


if __name__ == '__main__':
    unittest.main(verbosity=2)
