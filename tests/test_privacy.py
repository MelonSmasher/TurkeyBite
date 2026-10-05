"""Tests for what an event keeps of the URLs it carries, and of the raw packet.

Two failures matter. A query string, fragment or user:password@ surviving
anywhere on a trimmed event, in bite.url, in the packet's copy of the URL, in
Browserbeat's url_data, or in the log line beside it, would make the setting a
promise the event does not keep. And trimming must never touch a string that
is not a URL: hostnames, categories, DNS records and page titles have to reach
the event exactly as they arrived.

A URL with whitespace in it, or before it, must not slip through whole: a
string that starts as a URL is always cut. And there is one way out of the
processor, ship_bite, so the documents are captured where the outputs receive
them, never by replacing ship_bite, which would skip the very step under test.

`urls: full` with the packet kept must behave exactly as events did before
these settings existed, which is the control for every trimming test here.

No test touches the network.
"""

import copy
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'src'))

from libtb import inlet as I
from libtb import opensearch
from libtb import privacy as PV
from libtb import processor as P
from libtb.consumer import Consumer
from libtb.inlet import Inlet, describe
from libtb.processor import Processor

SEARCH = 'https://alice:hunter2@www.google.com/search?q=symptoms+of+flu&hl=en#results'


def url_data(**overrides):
    """Browserbeat's url_data: Go's url.URL serialised field by field."""
    fields = {'Scheme': 'https', 'Opaque': '', 'User': {}, 'Host': 'www.google.com',
              'Path': '/search', 'RawPath': '', 'OmitHost': False, 'ForceQuery': False,
              'RawQuery': 'q=symptoms+of+flu&hl=en', 'Fragment': 'results',
              'RawFragment': ''}
    fields.update(overrides)
    return fields


def browser_packet(url=SEARCH, title='symptoms of flu - Google Search'):
    return {
        'type': 'browser.history',
        'data': {
            '@timestamp': '2026-10-04T12:00:00Z',
            '@processed': '2026-10-04T08:00:05.000000-04:00',
            'host': {'hostname': 'LIB-1-01', 'short': 'LIB-1-01'},
            'event': {
                'module': 'browserbeat-chrome',
                'data': {
                    'entry': {'date': '2026-10-04 12:00:00', 'url': url, 'title': title,
                              'url_data': url_data()},
                    'client': {'Hostname': {'hostname': 'LIB-1-01', 'short': 'LIB-1-01'},
                               'user': 'vertor', 'platform': 'windows', 'browser': 'chrome',
                               'ip_addresses': ['10.100.45.140']},
                },
            },
        },
    }


def dns_packet(answers=()):
    return {'type': 'dns', 'resource': 'www.example.com', 'status': 'OK',
            'dns': {'question': {'name': 'www.example.com', 'etld_plus_one': 'example.com'},
                    'answers': list(answers), 'response_code': 'NOERROR'},
            'network': {'direction': 'ingress'}, 'client': {'ip': '10.0.0.5'},
            '@timestamp': '2026-10-04T12:00:00Z'}


class TrimUrlTest(unittest.TestCase):

    def trimmed(self, url):
        return PV.trim_url(url, PV.TRIMMED)

    def host(self, url):
        return PV.trim_url(url, PV.HOST)

    def test_the_query_string_is_dropped(self):
        self.assertEqual(self.trimmed('https://www.google.com/search?q=private+thing'),
                         'https://www.google.com/search')

    def test_the_fragment_is_dropped(self):
        self.assertEqual(self.trimmed('https://example.com/page#reset-token=abc'),
                         'https://example.com/page')

    def test_the_user_and_password_are_dropped(self):
        self.assertEqual(self.trimmed('https://alice:hunter2@example.com/p'),
                         'https://example.com/p')
        self.assertEqual(self.trimmed('ftp://alice@example.com/'), 'ftp://example.com/')

    def test_a_password_containing_an_at_sign_is_dropped_whole(self):
        self.assertEqual(self.trimmed('https://alice:p@ss@example.com/'), 'https://example.com/')

    def test_an_at_sign_after_the_host_is_not_mistaken_for_a_user(self):
        self.assertEqual(self.trimmed('https://medium.com/@alice/post?source=feed'),
                         'https://medium.com/@alice/post')
        self.assertEqual(self.trimmed('https://example.com?email=alice@example.org'),
                         'https://example.com')
        self.assertEqual(self.trimmed('https://example.com#to=alice@example.org'),
                         'https://example.com')

    def test_everything_at_once(self):
        self.assertEqual(self.trimmed(SEARCH), 'https://www.google.com/search')

    def test_the_port_is_kept(self):
        self.assertEqual(self.trimmed('https://example.com:8443/a?b=1'),
                         'https://example.com:8443/a')
        self.assertEqual(self.host('https://example.com:8443/a?b=1'), 'https://example.com:8443')

    def test_an_ipv6_host_keeps_its_brackets_and_port(self):
        self.assertEqual(self.trimmed('https://[2001:db8::1]:8443/x?y=1'),
                         'https://[2001:db8::1]:8443/x')
        self.assertEqual(self.host('https://[2001:db8::1]:8443/x?y=1'),
                         'https://[2001:db8::1]:8443')
        self.assertEqual(self.trimmed('http://u:p@[::1]/admin'), 'http://[::1]/admin')

    def test_host_mode_keeps_only_scheme_host_and_port(self):
        self.assertEqual(self.host(SEARCH), 'https://www.google.com')
        self.assertEqual(self.host('https://example.com?q=1'), 'https://example.com')

    def test_a_url_with_nothing_to_drop_is_unchanged(self):
        for url in ('https://example.com/', 'https://example.com', 'http://10.0.0.1:8080/x'):
            self.assertEqual(self.trimmed(url), url)

    def test_a_wrapped_url_is_trimmed_inside_its_wrapper(self):
        self.assertEqual(self.trimmed('view-source:https://u:p@example.com/x?q=1'),
                         'view-source:https://example.com/x')
        self.assertEqual(self.host('blob:https://example.com/0b8f-11ee'),
                         'blob:https://example.com')

    def test_surrounding_whitespace_does_not_hide_a_url(self):
        self.assertEqual(self.trimmed('  https://example.com/?q=1 \n'), 'https://example.com/')

    # Every kind of whitespace, before the URL and inside it. A URL that is
    # not one unbroken run of characters used to be left whole, query and all

    WHITESPACE = {'space': ' ', 'tab': '\t', 'newline': '\n', 'no-break space': '\u00a0',
                  'ideographic space': '\u3000', 'zero-width space': '\u200b',
                  'byte order mark': '\ufeff'}

    def test_whitespace_before_a_url_does_not_hide_it(self):
        for name, space in self.WHITESPACE.items():
            url = space + 'https://alice:pw@example.com/a?q=secret#f'
            self.assertEqual(self.trimmed(url), 'https://example.com/a', name)
            self.assertEqual(self.host(url), 'https://example.com', name)

    def test_whitespace_inside_a_url_does_not_keep_its_query(self):
        for name, space in self.WHITESPACE.items():
            for url in (f'https://example.com/a{space}b?q=secret',
                        f'https://example.com/a?q=se{space}cret',
                        f'https://example.com/a{space}?q=secret',
                        f'https://alice:p{space}w@example.com/a?q=secret'):
                for mode in (PV.TRIMMED, PV.HOST):
                    got = PV.trim_url(url, mode)
                    self.assertNotIn('secret', got, (name, url, mode))
                    self.assertNotIn('alice', got, (name, url, mode))
                    self.assertNotEqual(got, url, (name, url, mode))
            self.assertEqual(self.host(f'https://example.com/a{space}b?q=1'),
                             'https://example.com', name)

    def test_a_scheme_in_any_case_is_a_url(self):
        self.assertEqual(self.trimmed('HTTPS://ALICE:PW@EXAMPLE.COM/A?Q=1'),
                         'HTTPS://EXAMPLE.COM/A')
        self.assertEqual(self.host('Http://example.com/a?q=1'), 'Http://example.com')

    def test_an_http_url_without_slashes_or_with_backslashes_is_a_url(self):
        # Browsers accept both, so a recorded URL can arrive either way
        self.assertEqual(self.trimmed('https:example.com/a?q=1'), 'https:example.com/a')
        self.assertEqual(self.trimmed('https:\\\\alice:pw@example.com\\a?q=1'),
                         'https:\\\\example.com\\a')
        self.assertEqual(self.host('https:\\\\alice:pw@example.com\\a?q=1'),
                         'https:\\\\example.com')

    def test_a_scheme_browsers_use_without_slashes_is_a_url(self):
        # about:reader carries the page it wraps, reset token and all
        self.assertEqual(self.trimmed('about:reader?url=https%3A%2F%2Fmail.example.com%2F'
                                     'reset%3Ftoken%3Dabc'), 'about:reader')
        self.assertEqual(self.trimmed('magnet:?xt=urn:btih:abc&dn=secret'), 'magnet:')
        self.assertEqual(self.trimmed('mailto:x@y.example?body=secret'), 'mailto:x@y.example')
        self.assertEqual(self.trimmed('chrome://settings/?search=pw'), 'chrome://settings/')

    def test_direction_marks_quotes_and_brackets_do_not_hide_a_url(self):
        for lead, tail in (('\u200e', ''), ('\u200f', ''), ('\u202a', ''), ('\u2066', ''),
                           ('"', '"'), ("'", "'"), ('<', '>'), ('(', ')'), ('\u201c', '\u201d')):
            with self.subTest(lead=lead):
                self.assertNotIn('secret', self.trimmed(f'{lead}https://h.example/?q=secret{tail}'))

    def test_a_file_url_has_no_host_to_keep(self):
        self.assertEqual(self.host('file:///Users/alice/secret.txt?x'), 'file:///')
        self.assertEqual(self.host('file:///C:/Users/alice/a.txt'), 'file:///')
        self.assertEqual(self.trimmed('file:///Users/alice/secret.txt?x#y'),
                         'file:///Users/alice/secret.txt')

    def test_strings_that_are_not_urls_are_untouched(self):
        for text in ('hello world', 'www.example.com', 'example.com/?q=1', 'cats?dogs#birds',
                     'malicious:quad9', 'v=spf1 include:_spf.example.com ~all',
                     'Search for https://example.com/?q=1 here', 'mailto:alice@example.org',
                     'about:blank', 'symptoms of flu - Google Search', '',
                     'httpbin is a service?', 'http: the protocol', '2026-10-04T12:00:00Z',
                     '10.0.0.5', 'localhost:8080/a?b'):
            self.assertEqual(self.trimmed(text), text, text)
            self.assertEqual(self.host(text), text, text)

    def test_values_that_are_not_strings_are_untouched(self):
        for value in (None, 42, 1.5, True, ['https://example.com/?q=1']):
            self.assertIs(self.trimmed(value), value)

    def test_a_malformed_url_still_loses_its_query(self):
        # urllib raises on these, which would have left them whole
        self.assertEqual(self.trimmed('https://[::1/path?secret=1'), 'https://[::1/path')
        self.assertEqual(self.trimmed('https://example.com:notaport/x?secret=1'),
                         'https://example.com:notaport/x')
        self.assertEqual(self.trimmed('https://?secret=1'), 'https://')
        self.assertEqual(self.trimmed('https:///path?secret=1'), 'https:///path')
        self.assertEqual(self.host('https://u:p@?secret=1'), 'https://')

    def test_full_keeps_everything(self):
        self.assertEqual(PV.trim_url(SEARCH, PV.FULL), SEARCH)


class ScrubTest(unittest.TestCase):
    """URLs found anywhere in a document, and Browserbeat's url_data."""

    def test_url_data_loses_the_same_parts_as_the_url(self):
        got = PV.scrub(url_data(User={'username': 'alice', 'password': 'hunter2'},
                                RawFragment='results', ForceQuery=True), PV.TRIMMED)
        self.assertEqual(got, url_data(User=None, RawQuery='', Fragment='', RawFragment='',
                                       ForceQuery=False))

    def test_url_data_in_host_mode_loses_the_path_too(self):
        got = PV.scrub(url_data(RawPath='/search', Opaque='x'), PV.HOST)
        self.assertEqual((got['Path'], got['RawPath'], got['Opaque']), ('', '', ''))
        self.assertEqual((got['Scheme'], got['Host']), ('https', 'www.google.com'))

    def test_url_data_gains_no_fields(self):
        got = PV.scrub({'Scheme': 'https', 'Host': 'example.com', 'RawQuery': 'q=1'}, PV.HOST)
        self.assertEqual(got, {'Scheme': 'https', 'Host': 'example.com', 'RawQuery': ''})

    def test_a_dict_that_is_not_a_url_keeps_fields_with_those_names(self):
        value = {'RawQuery': 'kept', 'Fragment': 'kept', 'Host': 'example.com'}
        self.assertEqual(PV.scrub(value, PV.TRIMMED), value)

    def test_urls_are_found_in_nested_lists_and_dicts(self):
        got = PV.scrub({'a': [{'b': 'https://example.com/?q=1'}, 'plain']}, PV.TRIMMED)
        self.assertEqual(got, {'a': [{'b': 'https://example.com/'}, 'plain']})

    def test_the_input_is_not_modified(self):
        packet = browser_packet()
        before = copy.deepcopy(packet)
        PV.scrub(packet, PV.HOST)
        self.assertEqual(packet, before)


class SettingsTest(unittest.TestCase):

    def test_trimmed_and_kept_by_default(self):
        for absent in (None, {}):
            self.assertEqual(PV.settings(absent), PV.Settings('trimmed', 'keep'))

    def test_every_documented_value_is_accepted(self):
        for urls in ('full', 'trimmed', 'host'):
            for packet in ('keep', 'none'):
                self.assertEqual(PV.settings({'urls': urls, 'packet': packet}),
                                 PV.Settings(urls, packet))

    def test_mistakes_are_refused(self):
        for bad in ({'url': 'full'}, {'urls': 'Full'}, {'urls': 'none'}, {'urls': 'query'},
                    {'urls': None}, {'packet': 'drop'}, {'packet': None}, {'packet': False},
                    {'packet': 'full'}, ['urls'], 'trimmed', 0):
            with self.assertRaises(ValueError, msg=bad):
                PV.settings(bad)

    def test_an_unquoted_no_gets_a_hint(self):
        with self.assertRaisesRegex(ValueError, 'unquoted no'):
            PV.settings({'packet': False})

    def test_a_mistake_stops_the_processor_at_start(self):
        with self.assertRaises(ValueError):
            Processor({'privacy': {'urls': 'some'}}, {})

    def test_the_shipped_example_config_is_valid(self):
        import yaml
        with open(os.path.join(ROOT, 'src', 'support', 'config.example.yaml')) as fh:
            config = yaml.safe_load(fh)
        self.assertEqual(PV.settings(config['processor']['privacy']),
                         PV.Settings('trimmed', 'keep'))


class Wiring(object):
    """A processor whose lookups are stubbed, shipping to a stand-in OpenSearch.

    Documents are taken from the client, where OpenSearch would receive them,
    so the privacy settings applied inside ship_bite are part of the test.
    """

    def processor(self, privacy=None):
        for state in (opensearch._warned, P._opensearch_clients):
            state.clear()
        config = {'dns': {'lookup_ips': False}, 'domain_index': {'mode': 'index'},
                  'elastic': {'enable': True, 'index_prefix': 'tb-index',
                              'hosts': [{'uri': 'http://opensearch:9200', 'username': 'admin',
                                         'password': 'Not-the-default.1'}]},
                  'syslog': {'enable': False}}
        if privacy is not None:
            config['privacy'] = privacy
        processor = Processor(config, {})
        processor.resolve_contexts = lambda searches, **kwargs: (['search'], {})
        processor.resolve_chain = lambda chain: ([], [], [])
        self.client = mock.Mock()
        patcher = mock.patch.object(P, 'opensearch_client', return_value=self.client)
        patcher.start()
        self.addCleanup(patcher.stop)
        return processor

    @property
    def shipped(self):
        return [call.kwargs['body'] for call in self.client.index.call_args_list]


class BrowserWiringTest(Wiring, unittest.TestCase):
    """What a browser history event ships."""

    def ship(self, privacy=None, packet=None):
        packet = packet or browser_packet()
        self.processor(privacy).process_browser_history(packet)
        self.assertEqual(len(self.shipped), 1)
        return self.shipped[0], packet

    def test_by_default_no_query_fragment_or_password_is_shipped(self):
        doc, _ = self.ship()
        self.assertEqual(doc['bite']['url'], 'https://www.google.com/search')
        entry = doc['packet']['data']['event']['data']['entry']
        self.assertEqual(entry['url'], 'https://www.google.com/search')
        self.assertEqual((entry['url_data']['RawQuery'], entry['url_data']['Fragment'],
                          entry['url_data']['User']), ('', '', None))
        text = json.dumps(doc)
        for secret in ('q=symptoms', 'hunter2', 'alice', '#results', 'hl=en'):
            self.assertNotIn(secret, text)

    def test_what_categorises_the_visit_is_untouched(self):
        doc, _ = self.ship()
        bite = doc['bite']
        self.assertEqual(bite['requested'], ['www.google.com'])
        self.assertEqual(bite['contexts'], ['search'])
        self.assertEqual(bite['client_user'], 'vertor')
        self.assertEqual(bite['request'], 'https')
        entry = doc['packet']['data']['event']['data']['entry']
        self.assertEqual(entry['url_data']['Host'], 'www.google.com')
        self.assertEqual(entry['url_data']['Path'], '/search')

    def test_the_title_is_not_a_url_and_is_kept(self):
        # Documented: a search page's title is usually the search, and only
        # packet: none removes it
        doc, _ = self.ship()
        entry = doc['packet']['data']['event']['data']['entry']
        self.assertEqual(entry['title'], 'symptoms of flu - Google Search')

    def test_a_title_that_is_a_url_is_trimmed_like_one(self):
        doc, _ = self.ship(packet=browser_packet(title='https://example.com/reset?token=abc'))
        entry = doc['packet']['data']['event']['data']['entry']
        self.assertEqual(entry['title'], 'https://example.com/reset')

    def test_host_mode_keeps_only_the_site(self):
        doc, _ = self.ship({'urls': 'host'})
        self.assertEqual(doc['bite']['url'], 'https://www.google.com')
        entry = doc['packet']['data']['event']['data']['entry']
        self.assertEqual(entry['url'], 'https://www.google.com')
        self.assertEqual(entry['url_data']['Path'], '')

    def test_full_ships_exactly_what_it_did_before(self):
        # The control for every trimming test: the packet is the one that
        # arrived, not a copy, and the URL is whole
        doc, packet = self.ship({'urls': 'full', 'packet': 'keep'})
        self.assertIs(doc['packet'], packet)
        self.assertEqual(doc['bite']['url'], SEARCH)
        self.assertEqual(packet, browser_packet())

    def test_packet_none_leaves_the_packet_off(self):
        doc, _ = self.ship({'packet': 'none'})
        self.assertNotIn('packet', doc)
        self.assertEqual(doc['bite']['url'], 'https://www.google.com/search')
        self.assertEqual(doc['bite']['client_user'], 'vertor')

    def test_packet_none_with_full_urls_keeps_the_url_whole(self):
        doc, _ = self.ship({'urls': 'full', 'packet': 'none'})
        self.assertNotIn('packet', doc)
        self.assertEqual(doc['bite']['url'], SEARCH)

    def test_the_packet_that_arrived_is_not_modified(self):
        _, packet = self.ship({'urls': 'host'})
        self.assertEqual(packet['data']['event']['data']['entry']['url'], SEARCH)

    def test_a_browser_event_is_searched_in_full(self):
        # The control for the DNS test above: the same stray URL is trimmed
        packet = browser_packet()
        packet['notes'] = ['https://example.com/?looked=yes']
        doc, _ = self.ship(packet=packet)
        self.assertEqual(doc['packet']['notes'], ['https://example.com/'])


class DnsWiringTest(Wiring, unittest.TestCase):
    """What a DNS event ships. A lookup carries no URL, so trimming changes nothing."""

    def ship(self, privacy=None, packet=None):
        packet = packet or dns_packet()
        self.processor(privacy).process_dns_packet(packet)
        self.assertEqual(len(self.shipped), 1)
        return self.shipped[0], packet

    def test_a_dns_packet_reaches_the_event_unchanged(self):
        answers = [{'type': 'CNAME', 'data': 'edge.example.net'},
                   {'type': 'TXT', 'data': 'v=spf1 include:_spf.example.com ~all'},
                   {'type': 'A', 'data': '93.184.216.34'}]
        doc, packet = self.ship(packet=dns_packet(answers))
        self.assertEqual(doc['packet'], dns_packet(answers))
        self.assertEqual(doc['bite']['requested'], ['www.example.com'])
        self.assertEqual(doc['bite']['cname_chain'], ['edge.example.net'])

    def test_a_url_in_a_record_is_trimmed(self):
        for section in PV.DNS_RECORD_SECTIONS:
            packet = dns_packet()
            packet['dns'][section] = [{'type': 'TXT',
                                       'data': 'https://verify.example.com/?token=abc'}]
            self.processor().process_dns_packet(packet)
            doc = self.shipped[-1]
            self.assertEqual(doc['packet']['dns'][section][0]['data'],
                             'https://verify.example.com/', section)

    def test_only_the_records_are_looked_at(self):
        # Packetbeat writes no URL anywhere else, so a DNS event is not
        # searched string by string; the browser test below is the control
        packet = dns_packet()
        packet['notes'] = ['https://example.com/?looked=no']
        doc, _ = self.ship(packet=packet)
        self.assertEqual(doc['packet']['notes'], ['https://example.com/?looked=no'])

    def test_a_dns_event_with_nothing_to_trim_is_not_copied(self):
        doc, packet = self.ship()
        self.assertIs(doc['packet'], packet)

    def test_full_ships_the_packet_that_arrived(self):
        packet = dns_packet([{'type': 'TXT', 'data': 'https://verify.example.com/?token=abc'}])
        doc, _ = self.ship({'urls': 'full'}, packet=packet)
        self.assertIs(doc['packet'], packet)

    def test_packet_none_leaves_the_packet_off(self):
        doc, _ = self.ship({'packet': 'none'})
        self.assertNotIn('packet', doc)
        self.assertEqual(doc['bite']['client'], '10.0.0.5')


class QueuedBeforeUpgradeTest(Wiring, unittest.TestCase):
    """A job the core queued before the upgrade carries a processor without these settings."""

    def test_it_is_processed_with_the_defaults_rather_than_failed(self):
        import pickle
        processor = self.processor()
        # The stubbed lookups cannot be pickled, and a real job carries none
        del processor.resolve_contexts, processor.resolve_chain, processor._privacy
        processor = pickle.loads(pickle.dumps(processor))
        processor.resolve_contexts = lambda searches, **kwargs: ([], {})
        processor.process_browser_history(browser_packet())
        self.assertEqual(self.shipped[0]['bite']['url'], 'https://www.google.com/search')


class ChokePointTest(Wiring, unittest.TestCase):
    """ship_bite is the only way out, so a new event type cannot skip the settings."""

    def test_an_event_of_a_type_nobody_wrote_yet_is_trimmed(self):
        processor = self.processor()
        processor.ship_bite({'bite': {'type': 'http', 'url': SEARCH},
                             'packet': {'type': 'http', 'url': {'full': SEARCH}}})
        doc = self.shipped[0]
        self.assertEqual(doc['bite']['url'], 'https://www.google.com/search')
        self.assertEqual(doc['packet']['url']['full'], 'https://www.google.com/search')

    def test_packet_none_holds_for_it_too(self):
        processor = self.processor({'packet': 'none'})
        processor.ship_bite({'bite': {'type': 'http'}, 'packet': {'type': 'http'}})
        self.assertNotIn('packet', self.shipped[0])


class OutputsTest(unittest.TestCase):
    """OpenSearch and syslog are sent the same trimmed document."""

    def setUp(self):
        from libtb import opensearch
        for state in (opensearch._warned, P._opensearch_clients):
            state.clear()
            self.addCleanup(state.clear)

    def processor(self, opensearch, syslog):
        processor = Processor({
            'dns': {'lookup_ips': False}, 'domain_index': {'mode': 'index'},
            'elastic': {'enable': opensearch, 'index_prefix': 'tb-index',
                        'hosts': [{'uri': 'https://opensearch:9200', 'username': 'admin',
                                   'password': 'Not-the-default.1'}]},
            'syslog': {'enable': syslog, 'host': 'syslog.example.edu', 'port': 514}}, {})
        processor.resolve_contexts = lambda searches, **kwargs: ([], {})
        return processor

    def test_syslog_is_sent_the_trimmed_event(self):
        sent = []
        syslog = mock.Mock()
        syslog.return_value.send.side_effect = lambda message, level: sent.append(message)
        with mock.patch.object(P, 'Syslog', syslog):
            self.processor(opensearch=False, syslog=True).process_browser_history(browser_packet())
        self.assertEqual(len(sent), 1)
        self.assertNotIn('q=symptoms', sent[0])
        self.assertIn('https://www.google.com/search', sent[0])

    def test_opensearch_is_sent_the_trimmed_event(self):
        client = mock.Mock()
        with mock.patch('sys.stderr'), mock.patch.object(P, 'opensearch_client',
                                                         return_value=client):
            self.processor(opensearch=True, syslog=False).process_browser_history(browser_packet())
        body = client.index.call_args.kwargs['body']
        self.assertNotIn('q=symptoms', json.dumps(body))
        self.assertEqual(body['bite']['url'], 'https://www.google.com/search')


class LogLineTest(Wiring, unittest.TestCase):
    """The per-event log line keeps no more of a URL than the event does."""

    def test_describe_trims_to_the_mode_it_is_given(self):
        packet = browser_packet()
        self.assertIn('https://www.google.com/search - vertor', describe(packet, 'Queued',
                                                                          PV.TRIMMED))
        self.assertNotIn('q=symptoms', describe(packet, 'Queued', PV.TRIMMED))
        self.assertIn(': https://www.google.com - ', describe(packet, 'Queued', PV.HOST))
        self.assertIn(SEARCH, describe(packet, 'Queued', PV.FULL))

    def test_describe_fails_closed_when_not_told(self):
        line = describe(browser_packet(), 'Queued')
        self.assertIn('https://www.google.com/search', line)
        self.assertNotIn('q=symptoms', line)

    def consume(self, privacy=None):
        processor = self.processor(privacy)
        filters = mock.Mock(should_process=mock.Mock(return_value=True))
        consumer = Consumer(mock.Mock(consumer='c1'), filters, processor)
        out = io.StringIO()
        with redirect_stdout(out):
            consumer.handle_batch([json.dumps(browser_packet())])
        return out.getvalue()

    def test_the_consumer_logs_the_url_as_the_event_keeps_it(self):
        line = self.consume()
        self.assertIn('https://www.google.com/search', line)
        self.assertNotIn('q=symptoms', line)

    def test_with_full_urls_the_log_line_is_as_before(self):
        # The control for the test above
        self.assertIn(SEARCH, self.consume({'urls': 'full'}))


class FakeQueue(object):
    """Stands in for rq.Queue and keeps what was enqueued."""

    def __init__(self, connection=None):
        self.jobs = []
        FakeQueue.last = self

    def enqueue(self, func, *args, **kwargs):
        self.jobs.append((func, args, kwargs))


class FakeSubscription(object):

    def __init__(self, payloads):
        self.payloads = payloads

    def subscribe(self, channel):
        pass

    def listen(self):
        for payload in self.payloads:
            yield {'type': 'message', 'data': payload}


class InletTest(Wiring, unittest.TestCase):
    """Under the rq pipeline an event waits in Valkey as a job, so it is trimmed first."""

    def enqueue(self, packet, privacy=None):
        processor = self.processor(privacy)
        redis = mock.Mock()
        redis.pubsub.return_value = FakeSubscription([json.dumps(packet).encode()])
        filters = mock.Mock(should_process=mock.Mock(return_value=True))
        with mock.patch.object(I, 'Redis', return_value=redis), \
                mock.patch.object(I, 'Queue', FakeQueue), redirect_stdout(io.StringIO()):
            Inlet({'host': 'valkey', 'port': 6379, 'db': 0, 'password': 'x',
                   'channel': 'turkeybite'}, filters, processor).open()
        self.assertEqual(len(FakeQueue.last.jobs), 1)
        return FakeQueue.last.jobs[0]

    def test_the_queued_event_is_trimmed(self):
        _, (queued,), _ = self.enqueue(browser_packet())
        entry = queued['data']['event']['data']['entry']
        self.assertEqual(entry['url'], 'https://www.google.com/search')
        self.assertEqual(entry['url_data']['RawQuery'], '')
        self.assertNotIn('hunter2', json.dumps(queued))

    def test_the_host_the_worker_reads_survives_it(self):
        _, (queued,), _ = self.enqueue(browser_packet(), {'urls': 'host'})
        processor = self.processor()
        processor.process_browser_history(queued)
        self.assertEqual(self.shipped[0]['bite']['requested'], ['www.google.com'])

    def test_with_full_urls_the_event_is_queued_as_it_came(self):
        # The control for the trimming above
        _, (queued,), _ = self.enqueue(browser_packet(), {'urls': 'full'})
        self.assertEqual(queued, browser_packet())

    def test_a_failed_job_is_not_kept_for_a_year(self):
        # RQ keeps a failed job, event and all, for a year unless told otherwise
        _, _, kwargs = self.enqueue(browser_packet())
        self.assertEqual(kwargs['failure_ttl'], 24 * 60 * 60)
        self.assertEqual(kwargs['result_ttl'], 600)


if __name__ == '__main__':
    unittest.main(verbosity=2)
