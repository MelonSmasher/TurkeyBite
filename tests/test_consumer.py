"""Tests for the consumer that drains the durable queue.

The ordering is the whole point of the consumer: claim, sieve and enrich,
flush to OpenSearch, and only then acknowledge. So what must not happen is an
acknowledgement before the flush, or after a flush that every OpenSearch host
refused, since either loses the batch for good. A batch that cannot be indexed
goes back to the head of the queue in its original order, and a consumer
killed part way through leaves its batch where its successor recovers it.

One bad packet must cost that packet and no more: undecodable JSON, a sieve
that raises, or an enrichment failure is counted and skipped, and the rest of
the batch is indexed and acknowledged.

The queue, the sieve and the processor are the real ones. Redis is
tests/fakes.py, and OpenSearch is a fake bulk call that each host can accept
or refuse. No test touches the network.
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
from libtb import processor as P
from libtb.consumer import Consumer
from libtb.processor import Processor
from libtb.queue import ListQueue
from libtb.sieve import Filters

KEY = 'turkeybite'
HOSTS = [{'uri': 'http://search-1:9200', 'username': 'admin', 'password': 'Not-the-default.1'},
         {'uri': 'http://search-2:9200', 'username': 'admin', 'password': 'Not-the-default.1'}]


def packet(name, client='10.0.0.5', status='OK'):
    return {'type': 'dns', 'status': status, 'resource': name,
            'dns': {'question': {'name': name}, 'response_code': 'NOERROR'},
            'network': {'direction': 'ingress'}, 'client': {'ip': client},
            '@timestamp': '2026-10-04T12:00:00Z'}


class Cluster(object):
    """Stands in for helpers.bulk. Each host accepts, refuses, or rejects documents."""

    def __init__(self, test, **answers):
        self.test = test
        self.answers = answers
        self.requests = []

    def bulk(self, client, docs, raise_on_error=False, stats_only=False):
        host = client
        # What the queue held when the documents went out: nothing may have
        # been acknowledged yet
        self.requests.append((host, list(docs), self.test.in_flight()))
        answer = self.answers.get(host, 'accept')
        if answer == 'refuse':
            raise ConnectionError(f'{host} refused the connection')
        if answer == 'reject':
            return 0, [{'index': {'error': {'type': 'mapper_parsing_exception'}}}] * len(docs)
        return len(docs), []


class ConsumerTest(unittest.TestCase):

    def setUp(self):
        for state in (P._bulk_buffers, P._opensearch_clients):
            state.clear()
            self.addCleanup(state.clear)
        # Flushing at exit and on SIGTERM is for a real worker, not a test run
        patcher = mock.patch.object(P, '_install_flush_hooks')
        patcher.start()
        self.addCleanup(patcher.stop)
        # One stand-in client per host, so the fake bulk knows which was asked
        patcher = mock.patch.object(P, 'opensearch_client', side_effect=lambda host: host['uri'])
        patcher.start()
        self.addCleanup(patcher.stop)

        self.redis = FakeRedis()
        self.queue = ListQueue(self.redis, KEY, 'worker1-01')
        self.cluster = Cluster(self)

    def in_flight(self):
        return self.redis.lrange(f'{KEY}:processing:worker1-01', 0, -1)

    def waiting(self):
        return self.redis.lrange(KEY, 0, -1)

    def push(self, *payloads):
        for payload in payloads:
            self.queue.push(payload if isinstance(payload, (bytes, str)) else json.dumps(payload))

    def consumer(self, processor=None, **kwargs):
        if processor is None:
            processor = self.processor()
        filters = Filters({'drop_error_packets': True, 'drop_replies': True,
                           'ignore': {'clients': ['10.9.9.9'], 'domains': [], 'hosts': []},
                           'browserbeat': {'ignore': {'clients': [], 'users': [],
                                                      'domains': [], 'hosts': []}}})
        # A small timeout, since the fake fails a 0, which in Redis blocks forever
        return Consumer(self.queue, filters, processor, batch_size=kwargs.pop('batch_size', 500),
                        block_seconds=0.01, name='worker1-01', **kwargs)

    def processor(self):
        processor = Processor({
            'dns': {'lookup_ips': False}, 'domain_index': {'mode': 'index'},
            'elastic': {'enable': True, 'index_prefix': 'tb-index', 'hosts': HOSTS,
                        'bulk': {'enable': True, 'size': 500, 'interval_sec': 3600}},
            'syslog': {'enable': False}}, {})
        processor.resolve_contexts = lambda searches, **kwargs: (['news'], {})
        processor.resolve_chain = lambda chain: ([], [], [])
        return processor

    def run_once(self, consumer):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), \
                mock.patch.object(P.opensearch_helpers, 'bulk', self.cluster.bulk):
            claimed = consumer.run_once()
        return claimed, out.getvalue(), err.getvalue()

    def indexed(self):
        return [doc['_source']['bite']['requested'][0]
                for _, docs, _ in self.cluster.requests for doc in docs]

    # -- the ordinary batch ------------------------------------------------

    def test_a_batch_is_sieved_indexed_in_one_request_and_then_acknowledged(self):
        self.push(packet('a.example.com'), packet('b.example.com'),
                  packet('ignored.example.com', client='10.9.9.9'), packet('c.example.com'))
        consumer = self.consumer()
        claimed, _, _ = self.run_once(consumer)
        self.assertEqual(claimed, 4)
        self.assertEqual(len(self.cluster.requests), 1)
        self.assertEqual(self.indexed(), ['a.example.com', 'b.example.com', 'c.example.com'])
        self.assertEqual((self.waiting(), self.in_flight()), ([], []))
        self.assertEqual(consumer.stats, {'claimed': 4, 'kept': 3, 'dropped': 1, 'unreadable': 0,
                                          'indexed': 3, 'requeued': 0, 'batches': 1})

    def test_nothing_is_acknowledged_until_the_flush(self):
        self.push(packet('a.example.com'), packet('b.example.com'))
        self.run_once(self.consumer())
        _, _, in_flight_at_flush = self.cluster.requests[0]
        self.assertEqual(len(in_flight_at_flush), 2)

    def test_documents_go_to_the_days_index(self):
        self.push(packet('a.example.com'))
        self.run_once(self.consumer())
        _, docs, _ = self.cluster.requests[0]
        self.assertRegex(docs[0]['_index'], r'^tb-index-\d{4}-\d{2}-\d{2}$')

    def test_an_empty_queue_claims_flushes_and_acknowledges_nothing(self):
        claimed, _, _ = self.run_once(self.consumer())
        self.assertEqual(claimed, 0)
        self.assertEqual(self.cluster.requests, [])
        self.assertNotIn('ltrim', [command for command, _ in self.redis.calls])

    def test_the_batch_size_bounds_a_claim(self):
        self.push(*[packet(f'{n}.example.com') for n in range(5)])
        self.run_once(self.consumer(batch_size=2))
        self.assertEqual(len(self.indexed()), 2)
        self.assertEqual(len(self.waiting()), 3)

    # -- when OpenSearch refuses -------------------------------------------

    def test_when_every_host_refuses_the_batch_is_requeued_in_order(self):
        self.cluster.answers = {'http://search-1:9200': 'refuse', 'http://search-2:9200': 'refuse'}
        payloads = [json.dumps(packet(f'{n}.example.com')).encode() for n in range(3)]
        self.push(*payloads)
        self.push(packet('later.example.com'))
        consumer = self.consumer(batch_size=3)
        _, _, err = self.run_once(consumer)
        self.assertEqual(self.waiting()[:3], payloads)
        self.assertEqual(len(self.waiting()), 4)
        self.assertEqual(self.in_flight(), [])
        self.assertEqual(consumer.stats['requeued'], 3)
        self.assertEqual(consumer.stats['indexed'], 0)
        self.assertIn('batch not indexed, requeueing 3 items', err)

    def test_each_host_is_tried_before_giving_up(self):
        self.cluster.answers = {'http://search-1:9200': 'refuse', 'http://search-2:9200': 'refuse'}
        self.push(packet('a.example.com'))
        self.run_once(self.consumer())
        self.assertEqual([host for host, _, _ in self.cluster.requests],
                         ['http://search-1:9200', 'http://search-2:9200'])

    def test_a_second_host_that_accepts_is_enough(self):
        # The control for the requeue: one host answering means the batch is
        # indexed and acknowledged
        self.cluster.answers = {'http://search-1:9200': 'refuse'}
        self.push(packet('a.example.com'), packet('b.example.com'))
        consumer = self.consumer()
        self.run_once(consumer)
        self.assertEqual((self.waiting(), self.in_flight()), ([], []))
        self.assertEqual(consumer.stats['indexed'], 2)

    def test_documents_a_host_rejects_are_logged_not_retried(self):
        # A document OpenSearch will never accept, such as one that conflicts
        # with the mapping, would otherwise come back round forever
        self.cluster.answers = {'http://search-1:9200': 'reject'}
        self.push(packet('a.example.com'))
        _, _, err = self.run_once(self.consumer())
        self.assertIn('OpenSearch rejected a document', err)
        self.assertEqual((self.waiting(), self.in_flight()), ([], []))

    # -- one bad packet ----------------------------------------------------

    def test_unreadable_payloads_cost_only_themselves(self):
        self.push('not json', b'\xff\xfe', packet('a.example.com'))
        consumer = self.consumer()
        self.run_once(consumer)
        self.assertEqual(self.indexed(), ['a.example.com'])
        self.assertEqual(consumer.stats['unreadable'], 2)
        self.assertEqual(self.in_flight(), [])

    def test_a_sieve_that_raises_costs_only_that_packet(self):
        consumer = self.consumer()
        real = consumer.filters.should_process
        consumer.filters.should_process = lambda data: (
            1 / 0 if data.get('resource') == 'bad.example.com' else real(data))
        self.push(packet('bad.example.com'), packet('a.example.com'))
        _, _, err = self.run_once(consumer)
        self.assertEqual(self.indexed(), ['a.example.com'])
        self.assertIn('skipped an unreadable packet', err)

    def test_an_enrichment_failure_costs_only_that_packet(self):
        processor = self.processor()
        real = processor.process_packet
        processor.process_packet = lambda data: (
            1 / 0 if data.get('resource') == 'bad.example.com' else real(data))
        self.push(packet('bad.example.com'), packet('a.example.com'))
        consumer = self.consumer(processor)
        _, _, err = self.run_once(consumer)
        self.assertEqual(self.indexed(), ['a.example.com'])
        self.assertEqual(consumer.stats['unreadable'], 1)
        self.assertIn('failed to process a packet', err)
        self.assertEqual(self.in_flight(), [])

    # -- stopping and recovering -------------------------------------------

    def test_a_consumer_killed_mid_batch_leaves_the_batch_for_its_successor(self):
        processor = self.processor()

        def killed(data):
            raise SystemExit('killed')
        processor.process_packet = killed
        self.push(packet('a.example.com'), packet('b.example.com'))
        with self.assertRaises(SystemExit):
            self.run_once(self.consumer(processor))
        self.assertEqual(len(self.in_flight()), 2)
        self.assertEqual(self.cluster.requests, [])

        successor = self.consumer()
        successor.stop()
        with redirect_stdout(io.StringIO()), \
                mock.patch.object(P.opensearch_helpers, 'bulk', self.cluster.bulk):
            successor.run()
        self.assertEqual(self.indexed(), ['a.example.com', 'b.example.com'])
        self.assertEqual((self.waiting(), self.in_flight()), ([], []))

    def test_recovered_work_that_cannot_be_indexed_is_requeued(self):
        self.cluster.answers = {'http://search-1:9200': 'refuse', 'http://search-2:9200': 'refuse'}
        self.redis.rpush(f'{KEY}:processing:worker1-01', json.dumps(packet('a.example.com')))
        consumer = self.consumer()
        consumer.stop()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                mock.patch.object(P.opensearch_helpers, 'bulk', self.cluster.bulk):
            consumer.run()
        self.assertEqual(len(self.waiting()), 1)
        self.assertEqual(self.in_flight(), [])

    def test_stop_finishes_the_batch_in_hand_then_exits(self):
        self.push(*[packet(f'{n}.example.com') for n in range(4)])
        processor = self.processor()
        consumer = self.consumer(processor, batch_size=2)
        real = processor.process_packet

        def then_stop(data):
            consumer.stop()
            return real(data)
        processor.process_packet = then_stop
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(P.opensearch_helpers, 'bulk',
                                                     self.cluster.bulk):
            consumer.run()
        self.assertEqual(len(self.indexed()), 2)
        self.assertEqual(len(self.waiting()), 2)
        self.assertEqual(self.in_flight(), [])
        self.assertIn('[worker1-01] stopped.', out.getvalue())

    # -- logging -----------------------------------------------------------

    def test_each_event_is_logged_unless_quiet(self):
        self.push(packet('a.example.com'), packet('b.example.com', client='10.9.9.9'))
        _, out, _ = self.run_once(self.consumer())
        self.assertIn('[Packetbeat][DNS] Queued: a.example.com - ingress', out)
        self.assertIn('[Packetbeat][DNS] Dropped: b.example.com - ingress', out)

        self.push(packet('c.example.com'))
        _, out, _ = self.run_once(self.consumer(log_events=False))
        self.assertEqual(out, '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
