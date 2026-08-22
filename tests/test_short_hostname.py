"""Tests for carrying both the full hostname and its short form.

Neither feed has both. PTR returns an FQDN; Browserbeat reports a bare machine
name with no domain. Carrying both forms is what lets one query match across
them, and the FQDN has to survive, because distinct names in different
subdomains can share a first label.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from libtb.processor import (client_identity, short_hostname, short_hostnames)


class ShortHostnameTest(unittest.TestCase):

    def test_the_domain_is_stripped(self):
        self.assertEqual(short_hostname('host-a.example.com'), 'host-a')

    def test_a_deeper_domain_is_stripped_too(self):
        self.assertEqual(short_hostname('host-a.sub.example.com'), 'host-a')

    def test_a_bare_name_is_returned_unchanged(self):
        self.assertEqual(short_hostname('host-a'), 'host-a')

    def test_a_trailing_root_dot_is_handled(self):
        self.assertEqual(short_hostname('host-a.example.com.'), 'host-a')

    def test_the_result_is_lower_cased(self):
        self.assertEqual(short_hostname('HOST-A.EXAMPLE.COM'), 'host-a')

    def test_surrounding_whitespace_is_handled(self):
        self.assertEqual(short_hostname('  host-a.example.com  '), 'host-a')

    def test_empty_input_gives_empty_output(self):
        for empty in ('', '   ', '.', None):
            self.assertEqual(short_hostname(empty), '')

    def test_non_string_input_does_not_raise(self):
        for bad in (None, 7, [], {}, object()):
            self.assertEqual(short_hostname(bad), '')


class ShortHostnamesTest(unittest.TestCase):

    def test_each_name_is_shortened(self):
        self.assertEqual(
            short_hostnames(['a.example.com', 'b.example.net']), ['a', 'b'])

    def test_order_is_preserved(self):
        self.assertEqual(
            short_hostnames(['z.example.com', 'a.example.com']), ['z', 'a'])

    def test_names_sharing_a_first_label_collapse(self):
        # This is why the FQDN is kept: the short form is not unique
        self.assertEqual(
            short_hostnames(['host-a.example.com', 'host-a.sub.example.com']),
            ['host-a'])

    def test_empty_entries_are_dropped(self):
        self.assertEqual(short_hostnames(['', 'a.example.com', None, '.']), ['a'])

    def test_no_input_is_an_empty_list(self):
        for empty in (None, [], ()):
            self.assertEqual(short_hostnames(empty), [])


class BrowserShortNameTest(unittest.TestCase):

    def client(self, hostname):
        return {
            'Hostname': {'hostname': hostname, 'short': hostname},
            'user': 'someone',
            'platform': 'windows',
            'browser': 'chrome',
            'ip_addresses': ['10.0.0.1'],
        }

    def test_the_short_field_is_emitted_even_when_it_matches(self):
        # Browserbeat reports no domain, so both fields carry the same value.
        # Emitting it anyway is what makes one query work across both feeds.
        got = client_identity({'client': self.client('LIB-1-01-23-A')})
        self.assertEqual(got['client_hostname'], 'lib-1-01-23-a')
        self.assertEqual(got['client_hostname_short'], 'lib-1-01-23-a')

    def test_a_qualified_name_is_shortened(self):
        got = client_identity({'client': self.client('LIB-1.example.com')})
        self.assertEqual(got['client_hostname'], 'lib-1.example.com')
        self.assertEqual(got['client_hostname_short'], 'lib-1')

    def test_no_hostname_means_no_short_field(self):
        client = self.client('x')
        del client['Hostname']
        got = client_identity({'client': client})
        self.assertNotIn('client_hostname', got)
        self.assertNotIn('client_hostname_short', got)


if __name__ == '__main__':
    unittest.main(verbosity=2)
