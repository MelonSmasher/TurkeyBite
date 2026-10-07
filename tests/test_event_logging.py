"""Tests for privacy-safe, tolerant per-packet consumer log lines."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))

from libtb.consumer import describe



def dns(name='www.example.com', client='10.0.0.5', status='OK'):
    return {'type': 'dns', 'status': status, 'resource': name,
            'dns': {'question': {'name': name}},
            'network': {'direction': 'ingress'}, 'client': {'ip': client},
            '@timestamp': '2026-10-04T12:00:00Z'}


def browser(url='https://www.example.com/page?q=private'):
    return {'type': 'browser.history',
            'data': {'@timestamp': '2026-10-04T12:00:00Z',
                     'event': {'data': {
                         'entry': {'url': url, 'url_data': {'Scheme': 'https',
                                                             'Host': 'www.example.com'}},
                         'client': {'user': 'vertor',
                                    'Hostname': {'hostname': 'LIB-1', 'short': 'LIB-1'}}}}}}




class DescribeTest(unittest.TestCase):
    """The per-packet log line, which once took the whole process down."""

    def test_a_dns_line(self):
        self.assertEqual(describe(dns(), 'Queued'),
                         '[Packetbeat][DNS] Queued: www.example.com - ingress')

    def test_a_browser_line(self):
        # The URL is trimmed unless the caller says otherwise, see test_privacy
        self.assertEqual(describe(browser(), 'Dropped'),
                         '[Browserbeat][History] Dropped : https://www.example.com/page'
                         ' - vertor - LIB-1')
        self.assertEqual(describe(browser(), 'Dropped', 'full'),
                         '[Browserbeat][History] Dropped : https://www.example.com/page?q=private'
                         ' - vertor - LIB-1')

    def test_nulls_where_dicts_were_expected_do_not_raise(self):
        # A null at any level used to escape the listen loop and exit the process
        for packet in ({'type': 'dns', 'resource': None},
                       {'type': 'dns', 'resource': 'x.example.com', 'network': None},
                       {'type': 'browser.history', 'data': None},
                       {'type': 'browser.history', 'data': {'event': None}},
                       {'type': 'browser.history', 'data': {'event': {'data': {
                           'entry': None, 'client': None}}}},
                       {'type': 'browser.history', 'data': {'event': {'data': {
                           'entry': {'url': 42}, 'client': {'Hostname': 'LIB-1'}}}}}):
            describe(packet, 'Queued')

    def test_what_there_is_nothing_to_say_about_says_nothing(self):
        for packet in ({}, {'type': 'flow'}, {'type': 'dns'}, {'type': 'dns', 'resource': 7},
                       None, [], 'dns'):
            self.assertIsNone(describe(packet, 'Queued'), packet)

    def test_partial_browser_packets_say_what_they_can(self):
        self.assertEqual(describe({'type': 'browser.history', 'data': None}, 'Queued'),
                         '[Browserbeat][History] Queued')


if __name__ == '__main__':
    unittest.main(verbosity=2)
