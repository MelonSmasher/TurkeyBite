"""Tests for the inlet, which reads the pub/sub channel under the rq pipeline.

Two promises in its comments. A packet the inlet cannot make sense of costs
that one packet: a payload that is not JSON, a subscription confirmation, a
sieve that raises, or a null where the log line expected a dict, none of which
may end the listen loop. And a dead job queue is the opposite case: enqueue
stays outside the net, so the process dies and is restarted rather than
dropping traffic in silence.

Redis and the RQ queue are replaced; no test touches the network.
"""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))
sys.path.insert(0, HERE)

from fakes import FakeRedis
from libtb import inlet as I
from libtb.inlet import Inlet, describe
from libtb.processor import Processor
from libtb.sieve import Filters

CONFIG = {'host': 'valkey', 'port': 6379, 'db': 0, 'password': 'secret',
          'channel': 'turkeybite'}


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


class FakeQueue(object):
    """Stands in for rq.Queue and keeps what was enqueued."""

    def __init__(self, connection=None):
        self.connection = connection
        self.jobs = []
        self.fail = None
        FakeQueue.last = self

    def enqueue(self, func, *args, **kwargs):
        if self.fail:
            raise self.fail
        self.jobs.append((func, args, kwargs))


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


class InletTest(unittest.TestCase):

    def setUp(self):
        self.redis = FakeRedis()
        patcher = mock.patch.object(I, 'Redis', return_value=self.redis)
        self.Redis = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(I, 'Queue', FakeQueue)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.processor = Processor({'dns': {'lookup_ips': False}}, {})
        self.filters = Filters({'drop_error_packets': True, 'drop_replies': True,
                                'ignore': {'clients': ['10.9.9.9'], 'domains': [], 'hosts': []},
                                'browserbeat': {'ignore': {'clients': [], 'users': [],
                                                           'domains': [], 'hosts': []}}})

    def publish(self, *payloads):
        for payload in payloads:
            if isinstance(payload, dict):
                payload = json.dumps(payload).encode('utf-8')
            self.redis.publish('turkeybite', payload)

    def open(self, filters=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            Inlet(CONFIG, filters or self.filters, self.processor).open()
        return FakeQueue.last, out.getvalue(), err.getvalue()

    def enqueued(self, queue):
        return [args[0].get('resource') for _, args, _ in queue.jobs]

    def test_it_subscribes_to_the_configured_channel_with_the_configured_redis(self):
        self.open()
        self.Redis.assert_called_once_with(host='valkey', port=6379, db=0, password='secret')
        self.assertEqual(self.redis.subscribers[0].channels, ['turkeybite'])

    def test_a_kept_packet_is_queued_for_the_processor(self):
        self.publish(dns())
        queue, out, _ = self.open()
        self.assertEqual(len(queue.jobs), 1)
        func, args, kwargs = queue.jobs[0]
        self.assertEqual(func, self.processor.process_packet)
        self.assertEqual(args, (dns(),))
        # A failed job keeps its event for a day, not RQ's default of a year
        self.assertEqual(kwargs, {'result_ttl': 600, 'failure_ttl': I.FAILURE_TTL})
        self.assertIn('Queued: www.example.com', out)

    def test_a_dropped_packet_is_logged_and_not_queued(self):
        self.publish(dns(client='10.9.9.9'))
        queue, out, _ = self.open()
        self.assertEqual(queue.jobs, [])
        self.assertIn('Dropped: www.example.com', out)

    def test_the_subscription_confirmation_is_not_a_packet(self):
        queue, out, err = self.open()
        self.assertEqual((queue.jobs, out, err), ([], '', ''))

    def test_unreadable_payloads_cost_only_themselves(self):
        self.publish(b'not json', b'\xff\xfe', b'', dns('a.example.com'))
        queue, _, _ = self.open()
        self.assertEqual(self.enqueued(queue), ['a.example.com'])

    def test_a_sieve_that_raises_costs_only_that_packet(self):
        real = self.filters.should_process
        self.filters.should_process = lambda data: (
            1 / 0 if data.get('resource') == 'bad.example.com' else real(data))
        self.publish(dns('bad.example.com'), dns('a.example.com'))
        queue, _, err = self.open()
        self.assertEqual(self.enqueued(queue), ['a.example.com'])
        self.assertIn('Skipped an unreadable packet', err)

    def test_json_that_is_not_a_packet_is_dropped_quietly(self):
        self.publish(b'[1, 2]', b'"text"', b'null', {'type': None}, dns('a.example.com'))
        queue, _, err = self.open()
        self.assertEqual(self.enqueued(queue), ['a.example.com'])
        self.assertEqual(err, '')

    def test_a_dead_queue_takes_the_process_down(self):
        # Deliberately outside the net: a restart beats dropping traffic silently
        self.publish(dns())
        original = FakeQueue.__init__

        def failing(queue, connection=None):
            original(queue, connection)
            queue.fail = ConnectionError('valkey went away')
        with mock.patch.object(FakeQueue, '__init__', failing):
            with self.assertRaises(ConnectionError):
                self.open()

    def test_the_log_line_keeps_no_more_of_a_url_than_the_event(self):
        self.publish(browser())
        _, out, _ = self.open()
        self.assertIn('https://www.example.com/page - vertor', out)
        self.assertNotIn('q=private', out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
