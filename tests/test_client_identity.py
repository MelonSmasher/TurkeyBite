"""Tests for lifting browser client identity into bite.

Browserbeat knows who a machine is; the DNS feed knows what was asked. None of
the identity reached bite, so a browser event could say what was visited but not
by whom. Two things here are easy to get wrong: keeping the wrong addresses, and
splitting one machine across two names.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from libtb.processor import Processor, client_identity, routable_addresses


class RoutableAddressesTest(unittest.TestCase):
    """Browserbeat reports every interface, most of them useless."""

    def test_link_local_v4_is_dropped(self):
        self.assertEqual(routable_addresses(['169.254.31.109']), [])

    def test_link_local_v6_is_dropped(self):
        self.assertEqual(routable_addresses(['fe80::1']), [])

    def test_loopback_is_dropped(self):
        self.assertEqual(routable_addresses(['127.0.0.1', '::1']), [])

    def test_multicast_is_dropped(self):
        self.assertEqual(routable_addresses(['224.0.0.1', 'ff02::1']), [])

    def test_unspecified_is_dropped(self):
        self.assertEqual(routable_addresses(['0.0.0.0', '::']), [])

    def test_reserved_is_dropped(self):
        self.assertEqual(routable_addresses(['240.0.0.1']), [])

    def test_private_v4_is_kept_because_that_is_the_campus(self):
        # The whole point: DNS events carry these, so dropping them would leave
        # nothing to correlate on
        self.assertEqual(
            routable_addresses(['10.100.45.140', '172.16.0.5', '192.168.1.20']),
            ['10.100.45.140', '172.16.0.5', '192.168.1.20'])

    def test_global_addresses_are_kept(self):
        self.assertEqual(routable_addresses(['93.184.216.34']), ['93.184.216.34'])

    def test_ipv6_unique_local_is_kept(self):
        self.assertEqual(routable_addresses(['fc00::1']), ['fc00::1'])

    def test_the_real_world_mix_keeps_only_the_usable_one(self):
        # Shaped like a live Windows event: mostly link-local, one real address
        mixed = ['169.254.31.109', '10.100.45.140', '169.254.130.241',
                 '169.254.7.2', '169.254.88.19']
        self.assertEqual(routable_addresses(mixed), ['10.100.45.140'])

    def test_order_is_preserved_so_the_primary_interface_stays_first(self):
        self.assertEqual(
            routable_addresses(['10.0.0.1', '169.254.1.1', '192.168.5.5']),
            ['10.0.0.1', '192.168.5.5'])

    def test_duplicates_collapse(self):
        self.assertEqual(routable_addresses(['10.0.0.1', '10.0.0.1']), ['10.0.0.1'])

    def test_equivalent_ipv6_spellings_collapse(self):
        # 'fc00:0:0:0:0:0:0:1' and 'fc00::1' are the same address
        self.assertEqual(routable_addresses(['fc00::1', 'fc00:0:0:0:0:0:0:1']),
                         ['fc00::1'])

    def test_surrounding_whitespace_is_tolerated(self):
        self.assertEqual(routable_addresses([' 10.0.0.1 ']), ['10.0.0.1'])

    def test_unparseable_entries_are_skipped(self):
        self.assertEqual(routable_addresses(['not-an-ip', '', '10.0.0.1']),
                         ['10.0.0.1'])

    def test_non_string_entries_are_skipped(self):
        self.assertEqual(routable_addresses([None, 10, {'ip': '10.0.0.1'},
                                             ['10.0.0.1'], '10.0.0.2']),
                         ['10.0.0.2'])

    def test_no_input_is_an_empty_list(self):
        for empty in (None, [], (), set()):
            self.assertEqual(routable_addresses(empty), [])

    def test_a_non_list_input_does_not_raise(self):
        # A bare int is not iterable, and a string would be iterated character
        # by character. Either would have lost the event.
        for bad in (7, 1.5, '10.0.0.1', {'ip': '10.0.0.1'}, True, object()):
            self.assertEqual(routable_addresses(bad), [], repr(bad))


class ClientIdentityTest(unittest.TestCase):

    def client(self, **overrides):
        base = {
            'Hostname': {'hostname': 'LIB-1-01-23-A', 'short': 'LIB-1-01-23-A'},
            'user': 'vertor',
            'platform': 'windows',
            'browser': 'chrome',
            'ip_addresses': ['169.254.31.109', '10.100.45.140'],
        }
        base.update(overrides)
        return base

    def test_all_five_fields_are_lifted(self):
        got = client_identity({'client': self.client()})
        self.assertEqual(sorted(got), ['client_browser', 'client_hostname',
                                       'client_ips', 'client_platform',
                                       'client_user'])

    def test_the_hostname_comes_from_the_nested_object(self):
        got = client_identity({'client': self.client()})
        self.assertEqual(got['client_hostname'], 'lib-1-01-23-a')

    def test_only_routable_addresses_are_carried(self):
        got = client_identity({'client': self.client()})
        self.assertEqual(got['client_ips'], ['10.100.45.140'])

    # -- the case trap ------------------------------------------------------

    def test_names_are_lower_cased(self):
        got = client_identity({'client': self.client(user='VertoR')})
        self.assertEqual(got['client_hostname'], 'lib-1-01-23-a')
        self.assertEqual(got['client_user'], 'vertor')

    def test_two_cases_of_one_machine_become_one_name(self):
        # keyword fields are case sensitive, so without folding this machine
        # would be two machines to every aggregation and to the identity table
        upper = client_identity({'client': self.client(
            Hostname={'hostname': 'LIB-1-01-23-A', 'short': 'LIB-1-01-23-A'})})
        lower = client_identity({'client': self.client(
            Hostname={'hostname': 'lib-1-01-23-a', 'short': 'lib-1-01-23-a'})})
        self.assertEqual(upper['client_hostname'], lower['client_hostname'])

    def test_platform_and_browser_are_folded_too(self):
        got = client_identity({'client': self.client(platform='Windows',
                                                     browser='Chrome')})
        self.assertEqual((got['client_platform'], got['client_browser']),
                         ('windows', 'chrome'))

    # -- absent rather than null -------------------------------------------

    def test_a_missing_field_is_left_out_not_set_null(self):
        client = self.client()
        del client['user']
        got = client_identity({'client': client})
        self.assertNotIn('client_user', got)
        self.assertIn('client_hostname', got)

    def test_an_empty_string_is_left_out(self):
        got = client_identity({'client': self.client(user='')})
        self.assertNotIn('client_user', got)

    def test_a_whitespace_only_value_is_left_out(self):
        got = client_identity({'client': self.client(user='   ')})
        self.assertNotIn('client_user', got)

    def test_no_routable_address_omits_the_field_entirely(self):
        got = client_identity({'client': self.client(
            ip_addresses=['169.254.1.1', '127.0.0.1'])})
        self.assertNotIn('client_ips', got)

    # -- malformed packets --------------------------------------------------

    def test_a_missing_client_yields_nothing(self):
        self.assertEqual(client_identity({'entry': {}}), {})

    def test_a_non_dict_client_yields_nothing(self):
        for bad in ('a string', ['a', 'list'], 7, None):
            self.assertEqual(client_identity({'client': bad}), {})

    def test_a_non_dict_event_data_yields_nothing(self):
        for bad in (None, 'x', [], 3):
            self.assertEqual(client_identity(bad), {})

    def test_a_non_dict_hostname_drops_only_the_hostname(self):
        got = client_identity({'client': self.client(Hostname='LIB-1')})
        self.assertNotIn('client_hostname', got)
        self.assertEqual(got['client_user'], 'vertor')

    def test_non_string_values_are_ignored(self):
        got = client_identity({'client': self.client(user=42, platform=None)})
        self.assertNotIn('client_user', got)
        self.assertNotIn('client_platform', got)
        self.assertEqual(got['client_browser'], 'chrome')

    def test_ip_addresses_of_the_wrong_type_is_survivable(self):
        for bad in ('10.0.0.1', None, 7, {'a': 1}):
            got = client_identity({'client': self.client(ip_addresses=bad)})
            self.assertNotIn('client_ips', got)


class BrowserHistoryWiringTest(unittest.TestCase):
    """The helpers being right is not the same as them being called."""

    def setUp(self):
        self.processor = Processor({}, {})
        self.shipped = []
        self.processor.ship_bite = self.shipped.append
        self.processor.resolve_contexts = lambda searches: ([], {})

    def packet(self, client=None, processed=None):
        event_data = {
            'entry': {
                'url': 'https://www.example.com/page',
                'url_data': {'Scheme': 'https', 'Host': 'www.example.com'},
            },
        }
        if client is not None:
            event_data['client'] = client
        data = {'@timestamp': '2026-08-21T12:00:00Z', 'event': {'data': event_data}}
        if processed is not None:
            data['@processed'] = processed
        return {'type': 'browser.history', 'data': data}

    def full_client(self):
        return {
            'Hostname': {'hostname': 'LIB-1-01-23-A', 'short': 'LIB-1-01-23-A'},
            'user': 'vertor',
            'platform': 'windows',
            'browser': 'chrome',
            'ip_addresses': ['169.254.31.109', '10.100.45.140'],
        }

    def test_the_identity_reaches_bite(self):
        self.processor.process_browser_history(self.packet(self.full_client()))
        self.assertEqual(len(self.shipped), 1)
        bite = self.shipped[0]['bite']
        self.assertEqual(bite['client_hostname'], 'lib-1-01-23-a')
        self.assertEqual(bite['client_user'], 'vertor')
        self.assertEqual(bite['client_platform'], 'windows')
        self.assertEqual(bite['client_browser'], 'chrome')
        self.assertEqual(bite['client_ips'], ['10.100.45.140'])

    def test_the_existing_fields_are_untouched(self):
        self.processor.process_browser_history(self.packet(self.full_client()))
        bite = self.shipped[0]['bite']
        self.assertEqual(bite['type'], 'browser.history')
        self.assertEqual(bite['url'], 'https://www.example.com/page')
        self.assertEqual(bite['requested'], ['www.example.com'])
        self.assertEqual(bite['request'], 'https')

    def test_the_raw_packet_is_still_carried_unchanged(self):
        # The folded names are a convenience; the reported values stay recoverable
        self.processor.process_browser_history(self.packet(self.full_client()))
        raw = self.shipped[0]['packet']['data']['event']['data']['client']
        self.assertEqual(raw['Hostname']['hostname'], 'LIB-1-01-23-A')

    def test_an_event_with_no_client_still_ships(self):
        self.processor.process_browser_history(self.packet(client=None))
        self.assertEqual(len(self.shipped), 1)
        self.assertNotIn('client_hostname', self.shipped[0]['bite'])

    def test_a_processed_stamp_with_no_client_does_not_raise(self):
        # This path read client.browser through chained subscripts and would
        # have lost the event to a KeyError
        self.processor.process_browser_history(
            self.packet(client=None, processed='2026-08-21T08:00:00.000000-0400'))
        self.assertEqual(len(self.shipped), 1)

    def test_an_event_with_no_host_ships_nothing(self):
        packet = self.packet(self.full_client())
        packet['data']['event']['data']['entry']['url_data']['Host'] = ''
        self.assertIs(self.processor.process_browser_history(packet), False)
        self.assertEqual(self.shipped, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
