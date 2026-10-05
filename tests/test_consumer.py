"""Tests for the consumer that drains the durable queue.

The ordering is the whole point of the consumer: claim, sieve and enrich,
flush to OpenSearch, and only then acknowledge. So what must not happen is an
acknowledgement before the flush, or after a flush that every OpenSearch host
refused, since either loses the batch for good. A batch that cannot be indexed
goes back to the head of the queue in its original order, and a consumer
killed part way through leaves its batch where its successor recovers it.

That has to hold whatever the bulk settings say. With buffering off, the
shipped default, the processor sends each event as it goes; with it on, it
flushes by itself when the buffer reaches bulk.size or interval_sec passes.
Either way a refusal has to reach the consumer, which used to acknowledge the
batch and lose it, so every delivery test here runs under each of those
settings, and none of them under settings that would never flush early.
OpenSearch asking for a document to be retried, as it does with a 429, also
requeues the batch, as does any refusal about the cluster rather than the
document: a 401, 403, 404 or 5xx. Only a refusal about the document itself,
a 400, 409 or 413, is logged and acknowledged.

One bad packet must cost that packet and no more: undecodable JSON, a sieve
that raises, or an enrichment failure is counted and skipped, and the rest of
the batch is indexed and acknowledged.

The queue, the sieve and the processor are the real ones. Redis is
tests/fakes.py, and OpenSearch is a fake that answers both the per-event index
call and the bulk call, each host accepting, refusing, rejecting a document
for good or asking for it to be retried. No test touches the network.
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

from opensearchpy.exceptions import TransportError

from fakes import FakeRedis
from libtb import processor as P
from libtb.consumer import Consumer
from libtb.processor import Processor
from libtb.queue import ListQueue
from libtb.sieve import Filters

KEY = 'turkeybite'
HOSTS = [{'uri': 'http://search-1:9200', 'username': 'admin', 'password': 'Not-the-default.1'},
         {'uri': 'http://search-2:9200', 'username': 'admin', 'password': 'Not-the-default.1'}]
BOTH_DOWN = {'http://search-1:9200': 'refuse', 'http://search-2:9200': 'refuse'}

# The bulk settings delivery is tested under. None is the shipped default.
BULK_OFF = None
BULK_FULL = {'enable': True, 'size': 2, 'interval_sec': 3600}    # flushes at 2
BULK_DUE = {'enable': True, 'size': 500, 'interval_sec': 0}      # flushes every event
BULK_AT_END = {'enable': True, 'size': 500, 'interval_sec': 3600}  # flushes at batch end
EVERY_SETTING = {'bulk off': BULK_OFF, 'bulk.size reached': BULK_FULL,
                 'interval_sec passed': BULK_DUE, 'flushed at batch end': BULK_AT_END}


def packet(name, client='10.0.0.5', status='OK'):
    return {'type': 'dns', 'status': status, 'resource': name,
            'dns': {'question': {'name': name}, 'response_code': 'NOERROR'},
            'network': {'direction': 'ingress'}, 'client': {'ip': client},
            '@timestamp': '2026-10-04T12:00:00Z'}


class Host(object):
    """Stands in for one host's OpenSearch client."""

    def __init__(self, cluster, uri):
        self.cluster = cluster
        self.uri = uri

    def index(self, index, body):
        self.cluster.answer(self.uri, [{'_index': index, '_source': body}], bulk=False)


class Cluster(object):
    """OpenSearch as the processor sees it, through index calls and helpers.bulk.

    Each host accepts, refuses the connection, rejects documents for good
    (`reject`, a 400), asks for them to be retried (`retry`, a 429), or answers
    with any other status given as a number.
    """

    KINDS = {400: 'mapper_parsing_exception', 401: 'security_exception',
             403: 'cluster_block_exception', 404: 'index_not_found_exception',
             409: 'version_conflict_engine_exception', 413: 'content_too_long',
             429: 'es_rejected_execution_exception', 500: 'exception'}

    def __init__(self, test, **answers):
        self.test = test
        self.answers = answers
        self.requests = []
        self.accepted = []
        self.bulk_kwargs = []

    def bulk(self, client, docs, raise_on_error=False, stats_only=False, **kwargs):
        self.bulk_kwargs.append(kwargs)
        return self.answer(client.uri, list(docs), bulk=True)

    def answer(self, host, docs, bulk):
        # What the queue held when the documents went out: nothing may have
        # been acknowledged yet
        self.requests.append((host, docs, self.test.in_flight()))
        answer = self.answers.get(host, 'accept')
        if answer == 'refuse':
            raise ConnectionError(f'{host} refused the connection')
        if answer in ('reject', 'retry') or isinstance(answer, int):
            status = {'reject': 400, 'retry': 429}.get(answer, answer)
            kind = self.KINDS.get(status, 'exception')
            if not bulk:
                raise TransportError(status, kind, {'error': {'type': kind}})
            # The first document refused, the rest taken
            self.accepted += docs[1:]
            return len(docs) - 1, [{'index': {'status': status, 'error': {'type': kind}}}]
        self.accepted += docs
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
        self.redis = FakeRedis()
        self.queue = ListQueue(self.redis, KEY, 'worker1-01')
        # The rests a consumer would have served, recorded instead of slept
        self.rested = []
        self.cluster = Cluster(self)
        # One stand-in client per host, so the fake knows which was asked
        patcher = mock.patch.object(P, 'opensearch_client',
                                    side_effect=lambda host: Host(self.cluster, host['uri']))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(P.opensearch_helpers, 'bulk', self.cluster.bulk)
        patcher.start()
        self.addCleanup(patcher.stop)

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
        kwargs.setdefault('sleep', self.rested.append)
        return Consumer(self.queue, filters, processor, batch_size=kwargs.pop('batch_size', 500),
                        block_seconds=0.01, name='worker1-01', **kwargs)

    def processor(self, bulk=BULK_AT_END):
        elastic = {'enable': True, 'index_prefix': 'tb-index', 'hosts': HOSTS}
        if bulk is not None:
            elastic['bulk'] = bulk
        processor = Processor({
            'dns': {'lookup_ips': False}, 'domain_index': {'mode': 'index'},
            'elastic': elastic, 'syslog': {'enable': False}}, {})
        processor.resolve_contexts = lambda searches, **kwargs: (['news'], {})
        processor.resolve_chain = lambda chain: ([], [], [])
        return processor

    def run_once(self, consumer):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            claimed = consumer.run_once()
        return claimed, out.getvalue(), err.getvalue()

    def indexed(self):
        return [doc['_source']['bite']['requested'][0] for doc in self.cluster.accepted]

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

    # -- when OpenSearch does not take the batch, under every bulk setting --

    def deliver(self, answers, events=4, bulk=BULK_OFF, strict=True):
        """Pushes events, sets the hosts' answers and runs one cycle."""
        self.cluster.answers = dict(answers)
        payloads = [json.dumps(packet(f'{n}.example.com')).encode() for n in range(events)]
        self.push(*payloads)
        consumer = self.consumer(self.processor(bulk), batch_size=events)
        if not strict:
            # Only the control overrides it; otherwise the consumer's own setting holds
            consumer.processor.strict_delivery = False
        _, _, err = self.run_once(consumer)
        return consumer, payloads, err

    def test_when_every_host_refuses_the_batch_is_requeued_in_order(self):
        for name, bulk in EVERY_SETTING.items():
            with self.subTest(name):
                self.setUp()
                consumer, payloads, err = self.deliver(BOTH_DOWN, bulk=bulk)
                self.assertEqual(self.waiting(), payloads)
                self.assertEqual(self.in_flight(), [])
                self.assertEqual(consumer.stats['requeued'], 4)
                self.assertEqual(consumer.stats['indexed'], 0)
                self.assertIn('batch not indexed, requeueing 4 items', err)

    def test_without_strict_delivery_the_batch_would_be_lost(self):
        # The control: the processor surfacing the failure is what saves it
        for name, bulk in EVERY_SETTING.items():
            if bulk is BULK_AT_END:
                continue   # the consumer's own flush at batch end always raised
            with self.subTest(name):
                self.setUp()
                self.deliver(BOTH_DOWN, bulk=bulk, strict=False)
                self.assertEqual((self.waiting(), self.in_flight()), ([], []))

    def test_a_second_host_that_accepts_is_enough(self):
        # The control for the requeue
        for name, bulk in EVERY_SETTING.items():
            with self.subTest(name):
                self.setUp()
                consumer, _, _ = self.deliver({'http://search-1:9200': 'refuse'}, bulk=bulk)
                self.assertEqual((self.waiting(), self.in_flight()), ([], []))
                self.assertEqual(len(self.indexed()), 4)

    def test_a_document_opensearch_asks_to_retry_requeues_the_batch(self):
        for name, bulk in EVERY_SETTING.items():
            with self.subTest(name):
                self.setUp()
                # With buffering off a 429 sends the event to the next host,
                # so both have to ask; a bulk response answers for the cluster
                consumer, payloads, err = self.deliver(
                    {'http://search-1:9200': 'retry', 'http://search-2:9200': 'retry'}, bulk=bulk)
                self.assertEqual(self.waiting(), payloads)
                self.assertEqual(self.in_flight(), [])

    def test_a_document_refused_for_good_is_logged_and_acknowledged(self):
        # Retrying a mapping error would requeue the same document forever
        for name, bulk in EVERY_SETTING.items():
            with self.subTest(name):
                self.setUp()
                _, _, err = self.deliver({'http://search-1:9200': 'reject'}, bulk=bulk)
                self.assertIn('OpenSearch rejected a document', err)
                self.assertEqual((self.waiting(), self.in_flight()), ([], []))

    def test_a_refusal_about_the_cluster_requeues_the_batch(self):
        # A rotated password, a write block, a missing index, a node failing:
        # each clears when the cluster does, so the events must wait, not go
        for status in (401, 403, 404, 500):
            for name, bulk in EVERY_SETTING.items():
                with self.subTest(status=status, setting=name):
                    self.setUp()
                    _, payloads, _ = self.deliver(
                        {'http://search-1:9200': status, 'http://search-2:9200': status},
                        bulk=bulk)
                    self.assertEqual(self.waiting(), payloads)
                    self.assertEqual(self.in_flight(), [])

    def test_counting_every_4xx_as_permanent_would_lose_them(self):
        # The control: the classification this replaced acknowledged a 401
        old = frozenset(range(400, 500)) - {408, 429}
        with mock.patch.object(P, 'PERMANENT_STATUSES', old):
            self.deliver({'http://search-1:9200': 401, 'http://search-2:9200': 401})
        self.assertEqual((self.waiting(), self.in_flight()), ([], []))

    def test_a_refusal_about_the_document_is_acknowledged(self):
        for status in (400, 409, 413):
            for name, bulk in EVERY_SETTING.items():
                with self.subTest(status=status, setting=name):
                    self.setUp()
                    _, _, err = self.deliver({'http://search-1:9200': status}, bulk=bulk)
                    self.assertIn('OpenSearch rejected a document', err)
                    self.assertEqual((self.waiting(), self.in_flight()), ([], []))

    def test_a_bulk_request_resends_what_a_full_queue_refused(self):
        # Within the request, so only those documents are sent again
        self.deliver({}, bulk=BULK_AT_END)
        self.assertEqual(self.cluster.bulk_kwargs[0]['max_retries'], P.BULK_RETRIES)

    def test_each_host_is_tried_before_giving_up(self):
        self.deliver(BOTH_DOWN, events=1)
        self.assertEqual([host for host, _, _ in self.cluster.requests],
                         ['http://search-1:9200', 'http://search-2:9200'])

    def test_a_failed_flush_stops_the_batch_and_leaves_nothing_buffered(self):
        # Two of the batch are sent and refused, so the rest are not tried,
        # and nothing buffered is sent with the next batch to be indexed twice
        consumer, _, _ = self.deliver(BOTH_DOWN, events=3, bulk=BULK_FULL)
        self.assertEqual(consumer.stats['requeued'], 3)
        self.assertNotIn(os.getpid(), P._bulk_buffers)
        self.cluster.answers = {}
        self.run_once(consumer)
        self.assertEqual(sorted(self.indexed()), ['0.example.com', '1.example.com',
                                                  '2.example.com'])

    def test_the_rq_path_still_logs_and_drops(self):
        # A job has nothing to requeue to, so its processor raises nothing
        self.cluster.answers = dict(BOTH_DOWN)
        for bulk in EVERY_SETTING.values():
            processor = self.processor(bulk)
            err = io.StringIO()
            with redirect_stderr(err):
                processor.process_packet(packet('a.example.com'))
                processor.flush_bulk()
            self.assertIn('OpenSearch', err.getvalue())

    def test_the_consumer_installs_no_flush_hooks_of_its_own_making(self):
        # They would replace its SIGTERM handler, which finishes the batch first
        self.deliver({}, bulk=BULK_AT_END)
        P._install_flush_hooks.assert_not_called()

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
        with redirect_stdout(io.StringIO()):
            successor.run()
        self.assertEqual(self.indexed(), ['a.example.com', 'b.example.com'])
        self.assertEqual((self.waiting(), self.in_flight()), ([], []))

    def test_recovered_work_that_cannot_be_indexed_is_requeued(self):
        self.cluster.answers = dict(BOTH_DOWN)
        self.redis.rpush(f'{KEY}:processing:worker1-01', json.dumps(packet('a.example.com')))
        consumer = self.consumer()
        consumer.stop()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            consumer.run()
        self.assertEqual(len(self.waiting()), 1)
        self.assertEqual(self.in_flight(), [])

    # -- resting after a batch OpenSearch did not take --------------------

    def failing_cycles(self, consumer, cycles):
        """The rest due after each of several cycles that all fail, in seconds."""
        due = []
        for _ in range(cycles):
            before = len(self.rested)
            self.run_once(consumer)
            due.append(sum(self.rested[before:]))
        return due

    def test_a_requeued_batch_is_followed_by_a_rest_that_doubles(self):
        self.cluster.answers = dict(BOTH_DOWN)
        self.push(packet('a.example.com'))
        consumer = self.consumer(self.processor(BULK_OFF))
        self.assertEqual(self.failing_cycles(consumer, 8), [1, 2, 4, 8, 16, 32, 60, 60])
        # Each cycle claimed the requeued batch again and nothing was lost
        self.assertEqual(len(self.waiting()), 1)

    def test_without_the_rest_an_outage_is_a_tight_loop(self):
        # The control: what the rest replaces is a cycle that waits for nothing
        self.cluster.answers = dict(BOTH_DOWN)
        self.push(packet('a.example.com'))
        consumer = self.consumer(self.processor(BULK_OFF))
        consumer.rest = lambda: 0
        self.assertEqual(self.failing_cycles(consumer, 3), [0, 0, 0])

    def test_a_batch_that_is_taken_ends_the_rests(self):
        self.cluster.answers = dict(BOTH_DOWN)
        self.push(packet('a.example.com'))
        consumer = self.consumer(self.processor(BULK_OFF))
        self.failing_cycles(consumer, 2)
        self.cluster.answers = {}
        self.assertEqual(self.failing_cycles(consumer, 1), [0])
        self.cluster.answers = dict(BOTH_DOWN)
        self.push(packet('b.example.com'))
        self.assertEqual(self.failing_cycles(consumer, 1), [1])

    def test_stop_cuts_a_rest_short(self):
        self.cluster.answers = dict(BOTH_DOWN)
        self.push(packet('a.example.com'))
        consumer = None

        def stop_while_resting(seconds):
            self.rested.append(seconds)
            consumer.stop()
        consumer = self.consumer(self.processor(BULK_OFF), sleep=stop_while_resting)
        self.failing_cycles(consumer, 3)   # due 1, then 2, then 4 seconds
        self.assertEqual(self.rested, [0.5])

    def test_an_empty_queue_never_rests(self):
        consumer = self.consumer()
        self.run_once(consumer)
        self.assertEqual(self.rested, [])

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
        with redirect_stdout(out):
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
