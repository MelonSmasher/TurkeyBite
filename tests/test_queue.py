"""Tests for the durable queue the consume pipeline reads.

The queue exists because pub/sub lost whatever was in flight on every
restart, so what must not happen is an event leaving the processing list
before it is indexed: an acknowledgement that removes too much, a requeue
that loses or reorders items, or a recovery sweep that takes another host's
in-flight work. Each of those is tested from the Redis lists themselves, not
from what the queue object reports.

No test touches the network. Redis is tests/fakes.py, which is checked here
against the Redis behaviour the queue relies on.
"""

import importlib.machinery
import importlib.util
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))
sys.path.insert(0, HERE)

from fakes import Blocked, FakeRedis
from libtb.queue import ListQueue, NotOwner, recover_orphans

KEY = 'turkeybite'


def items(*names):
    return [name.encode('utf-8') for name in names]


class FakeRedisTest(unittest.TestCase):
    """The fake has to be right where the queue depends on it, or it hides bugs."""

    def test_an_emptied_list_no_longer_exists(self):
        redis = FakeRedis()
        redis.rpush('l', 'a')
        redis.lmove('l', 'm', 'LEFT', 'RIGHT')
        self.assertNotIn('l', redis.data)
        redis.ltrim('m', 1, -1)
        self.assertNotIn('m', redis.data)

    def test_ranges_are_inclusive_and_count_back_from_the_end(self):
        redis = FakeRedis()
        redis.rpush('l', 'a', 'b', 'c', 'd')
        self.assertEqual(redis.lrange('l', 0, -1), items('a', 'b', 'c', 'd'))
        self.assertEqual(redis.lrange('l', 1, 2), items('b', 'c'))
        self.assertEqual(redis.lrange('l', -2, -1), items('c', 'd'))
        self.assertEqual(redis.lrange('l', 3, 1), [])
        self.assertEqual(redis.lrange('missing', 0, -1), [])

    def test_lpush_of_several_values_reverses_them(self):
        # Which is why the queue pushes in reverse to restore order
        redis = FakeRedis()
        redis.lpush('l', 'a', 'b', 'c')
        self.assertEqual(redis.lrange('l', 0, -1), items('c', 'b', 'a'))

    def test_a_blocking_move_that_would_wait_forever_fails_instead(self):
        # BLMOVE with a timeout of 0 never returns on an empty list in Redis
        redis = FakeRedis()
        with self.assertRaises(Blocked):
            redis.blmove('empty', 'other', 0)
        self.assertIsNone(redis.blmove('empty', 'other', 0.01))
        redis.rpush('l', 'a')
        self.assertEqual(redis.blmove('l', 'm', 0), b'a')

    def test_published_messages_are_bytes(self):
        redis = FakeRedis()
        redis.publish('c', 'text')
        redis.publish('c', b'raw')
        self.assertEqual([m['data'] for m in redis.published], [b'text', b'raw'])

    def test_a_scan_can_repeat_keys(self):
        redis = FakeRedis(scan_repeats=True)
        redis.set('k', 'v')
        self.assertEqual(list(redis.scan_iter(match='*')), [b'k', b'k'])

    def test_globs_are_case_sensitive(self):
        redis = FakeRedis()
        redis.set('Key', 'v')
        self.assertEqual(list(redis.scan_iter(match='key*')), [])

    def test_values_come_back_as_bytes(self):
        redis = FakeRedis()
        redis.set('k', 'v')
        redis.rpush('l', 'x')
        self.assertEqual((redis.get('k'), redis.lrange('l', 0, 0)), (b'v', [b'x']))
        self.assertEqual(list(redis.scan_iter(match='*')), [b'k', b'l'])


class ListQueueTest(unittest.TestCase):

    def setUp(self):
        self.redis = FakeRedis()
        self.queue = ListQueue(self.redis, KEY, 'worker1-01')
        self.processing = f'{KEY}:processing:worker1-01'

    def waiting(self):
        return self.redis.lrange(KEY, 0, -1)

    def in_flight(self):
        return self.redis.lrange(self.processing, 0, -1)

    def push(self, *names):
        for name in names:
            self.queue.push(name)

    # -- claiming ---------------------------------------------------------

    def test_a_claim_moves_items_into_this_consumers_processing_list(self):
        self.push('a', 'b', 'c')
        self.assertEqual(self.queue.claim(2), items('a', 'b'))
        self.assertEqual(self.waiting(), items('c'))
        self.assertEqual(self.in_flight(), items('a', 'b'))
        self.assertEqual((self.queue.depth(), self.queue.in_flight()), (1, 2))

    def test_items_are_claimed_in_the_order_the_beat_pushed_them(self):
        self.push('a', 'b', 'c')
        self.assertEqual(self.queue.claim(10), items('a', 'b', 'c'))

    def test_only_the_first_item_is_waited_for(self):
        # A quiet queue must not hold back a partial batch
        self.push('a', 'b')
        self.assertEqual(self.queue.claim(500, block_seconds=3), items('a', 'b'))
        self.assertEqual(self.redis.blocked_for, [3])

    def test_an_empty_queue_claims_nothing(self):
        self.assertEqual(self.queue.claim(10), [])
        self.assertEqual(self.in_flight(), [])

    def test_the_batch_size_is_respected(self):
        self.push(*'abcdef')
        self.assertEqual(len(self.queue.claim(4)), 4)
        self.assertEqual(self.queue.depth(), 2)

    # -- acknowledging ----------------------------------------------------

    def test_an_ack_removes_only_the_acknowledged_items(self):
        # Anything claimed after this batch has not been indexed yet
        self.push(*'abcde')
        self.queue.claim(3)
        self.queue.claim(2)
        self.queue.ack(3)
        self.assertEqual(self.in_flight(), items('d', 'e'))

    def test_an_ack_of_nothing_removes_nothing(self):
        self.push('a', 'b')
        self.queue.claim(2)
        for count in (0, -1, -2):
            self.queue.ack(count)
            # LTRIM -1 -1 would keep only the last item; the guard prevents it
            self.assertEqual(self.in_flight(), items('a', 'b'), count)

    def test_until_it_is_acknowledged_a_claimed_item_can_be_recovered(self):
        self.push('a', 'b')
        self.queue.claim(2)
        restarted = ListQueue(self.redis, KEY, 'worker1-01')
        self.assertEqual(restarted.recover(), items('a', 'b'))

    def test_another_consumer_does_not_recover_it(self):
        self.push('a')
        self.queue.claim(1)
        self.assertEqual(ListQueue(self.redis, KEY, 'worker1-02').recover(), [])

    # -- requeueing -------------------------------------------------------

    def test_a_requeued_batch_goes_back_to_the_head_in_order(self):
        self.push('a', 'b', 'c', 'd')
        claimed = self.queue.claim(2)
        self.push('e')
        self.queue.requeue(claimed)
        self.assertEqual(self.waiting(), items('a', 'b', 'c', 'd', 'e'))
        self.assertEqual(self.in_flight(), [])

    def test_a_requeue_cut_short_leaves_each_item_in_one_place(self):
        # The connection drops after the first move: what was moved is
        # waiting, the rest is still in flight for recovery, and nothing is
        # in both, which pushing copies before trimming could not promise
        self.push('a', 'b', 'c')
        claimed = self.queue.claim(3)

        def drops_after_one_write(command, key):
            if command in ('lpush', 'lmove', 'ltrim'):
                self.redis.on_command = None
                raise ConnectionError('Valkey went away')
        self.redis.on_command = drops_after_one_write
        with self.assertRaises(ConnectionError):
            self.queue.requeue(claimed)
        self.assertEqual(self.waiting(), items('c'))
        self.assertEqual(self.in_flight(), items('a', 'b'))
        self.assertEqual(self.queue.requeue(self.queue.recover()), 2)
        self.assertEqual(self.waiting(), items('a', 'b', 'c'))
        self.assertEqual(self.in_flight(), [])

    def test_requeueing_nothing_changes_nothing(self):
        self.push('a')
        self.queue.claim(1)
        self.queue.requeue([])
        self.assertEqual(self.in_flight(), items('a'))


class RecoverOrphansTest(unittest.TestCase):
    """Work stranded by a consumer whose name has changed."""

    def setUp(self):
        self.redis = FakeRedis()

    def strand(self, consumer, *names, key=KEY):
        self.redis.rpush(f'{key}:processing:{consumer}', *names)

    def left(self, consumer):
        return self.redis.lrange(f'{KEY}:processing:{consumer}', 0, -1)

    def test_stranded_work_is_requeued_in_order_ahead_of_the_rest(self):
        self.strand('old-01', 'a', 'b', 'c')
        self.redis.rpush(KEY, 'z')
        self.assertEqual(recover_orphans(self.redis, KEY), (1, 3))
        self.assertEqual(self.redis.lrange(KEY, 0, -1), items('a', 'b', 'c', 'z'))
        self.assertNotIn(f'{KEY}:processing:old-01', self.redis.data)

    def test_nothing_is_ever_deleted_only_moved(self):
        # LRANGE, LPUSH and DEL as separate steps lost anything claimed into
        # the list between the read and the delete
        self.strand('old-01', 'a', 'b')
        recover_orphans(self.redis, KEY)
        self.assertNotIn('delete', [command for command, _ in self.redis.calls])

    def test_an_item_claimed_into_the_list_meanwhile_is_requeued_too(self):
        self.strand('old-01', 'a', 'b')
        arrived = []

        def claim_part_way(command, key):
            if command == 'lmove' and not arrived:
                arrived.append(True)
                self.redis.rpush(f'{KEY}:processing:old-01', 'late')
        self.redis.on_command = claim_part_way
        self.assertEqual(recover_orphans(self.redis, KEY), (1, 3))
        self.assertEqual(sorted(self.redis.lrange(KEY, 0, -1)), items('a', 'b', 'late'))
        self.assertEqual(self.left('old-01'), [])

    def test_a_list_scan_returns_twice_is_swept_and_counted_once(self):
        self.redis = FakeRedis(scan_repeats=True)
        self.strand('old-01', 'a', 'b')
        self.strand('old-02', 'c')
        self.assertEqual(recover_orphans(self.redis, KEY), (2, 3))
        self.assertEqual(len(self.redis.lrange(KEY, 0, -1)), 3)

    def test_named_consumers_are_left_alone(self):
        self.strand('old-01', 'a')
        self.strand('live-01', 'b')
        self.assertEqual(recover_orphans(self.redis, KEY, keep_consumers=['live-01']), (1, 1))
        self.assertEqual(self.left('live-01'), items('b'))

    def test_a_prefix_takes_only_the_names_the_start_scripts_generate(self):
        for prefix, theirs in (('tb-worker', 'tb-worker-b-01'), ('worker1', 'worker10-01'),
                               ('host-a', 'host-a-b-01'), ('host', 'host-a-01')):
            with self.subTest(prefix):
                self.setUp()
                self.strand(f'{prefix}-01', 'mine')
                self.strand(f'{prefix}-102', 'mine too')
                self.strand(theirs, 'theirs')
                self.assertEqual(recover_orphans(self.redis, KEY, prefix=prefix), (2, 2))
                self.assertEqual(self.left(theirs), items('theirs'))

    def test_a_bare_prefix_match_would_have_taken_another_hosts_work(self):
        # The control: the shape check is what keeps tb-worker-b-01 safe
        self.strand('tb-worker-01', 'mine')
        self.strand('tb-worker-b-01', 'theirs')
        with mock.patch('libtb.queue.generated_names',
                        lambda prefix: __import__('re').compile('.*')):
            self.assertEqual(recover_orphans(self.redis, KEY, prefix='tb-worker'), (2, 2))

    def test_a_consumer_named_by_hand_is_left_to_be_named(self):
        self.strand('worker1', 'by hand')
        self.assertEqual(recover_orphans(self.redis, KEY, prefix='worker1'), (0, 0))
        self.assertEqual(recover_orphans(self.redis, KEY, consumers=['worker1']), (1, 1))
        self.assertEqual(self.redis.lrange(KEY, 0, -1), items('by hand'))

    def test_naming_a_consumer_with_nothing_stranded_sweeps_nothing(self):
        self.assertEqual(recover_orphans(self.redis, KEY, consumers=['gone']), (0, 0))

    def test_another_queues_lists_are_left_alone(self):
        self.strand('old-01', 'a', key='other')
        self.assertEqual(recover_orphans(self.redis, KEY), (0, 0))
        self.assertIn('other:processing:old-01', self.redis.data)

    def test_the_queue_itself_is_never_swept(self):
        self.redis.rpush(KEY, 'waiting')
        recover_orphans(self.redis, KEY)
        self.assertEqual(self.redis.lrange(KEY, 0, -1), items('waiting'))


class QueueRecoverCommandTest(unittest.TestCase):
    """`turkeybite queue-recover`, which every consume worker runs at start."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(os.path.dirname(HERE), 'src', 'turkeybite')
        loader = importlib.machinery.SourceFileLoader('turkeybite_queue_cli', path)
        spec = importlib.util.spec_from_loader('turkeybite_queue_cli', loader)
        cls.cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cls.cli)

    def sweep(self, args, expect=0, **env):
        from click.testing import CliRunner
        redis = FakeRedis()
        for consumer in ('tb-worker-01', 'tb-worker-b-01', 'worker1'):
            redis.rpush(f'{KEY}:processing:{consumer}', consumer)
        config = {'redis': {'host': 'valkey', 'port': 6379, 'db': 0, 'password': 'x',
                            'channel': KEY}}
        env.setdefault('TURKEYBITE_CONSUMER_PREFIX', '')
        with mock.patch.object(self.cli, 'read_config', return_value=config), \
                mock.patch('redis.Redis', return_value=redis), \
                mock.patch.dict(os.environ, env):
            result = CliRunner().invoke(self.cli.cli, ['queue-recover'] + args)
        self.assertEqual(result.exit_code, expect, result.output)
        return sorted(k.split(':')[-1] for k in redis.data if ':processing:' in k)

    def test_the_prefix_from_the_environment_and_the_flag_behave_the_same(self):
        left = ['tb-worker-b-01', 'worker1']
        self.assertEqual(self.sweep([], TURKEYBITE_CONSUMER_PREFIX='tb-worker'), left)
        self.assertEqual(self.sweep(['--prefix', 'tb-worker']), left)

    def test_a_consumer_named_by_hand_is_recovered_by_name(self):
        self.assertEqual(self.sweep(['--consumer', 'worker1']), ['tb-worker-01', 'tb-worker-b-01'])

    def test_all_sweeps_everything(self):
        self.assertEqual(self.sweep(['--all']), [])

    def test_no_scope_is_refused(self):
        self.assertEqual(self.sweep([], expect=2), ['tb-worker-01', 'tb-worker-b-01', 'worker1'])

    def test_two_scopes_are_refused(self):
        self.sweep(['--all', '--prefix', 'tb-worker'], expect=2)

    def test_the_start_script_passes_the_bare_prefix(self):
        with open(os.path.join(os.path.dirname(HERE), 'docker', 'worker', 'run-worker.sh')) as fh:
            self.assertIn('queue-recover --prefix "${TURKEYBITE_CONSUMER_PREFIX}" ', fh.read())


if __name__ == '__main__':
    unittest.main(verbosity=2)


class OwnershipTest(unittest.TestCase):
    """One process per consumer name, so no two share a processing list."""

    def setUp(self):
        self.redis = FakeRedis()

    def test_a_second_consumer_with_the_same_name_cannot_start(self):
        first, second = ListQueue(self.redis, KEY, 'worker1'), ListQueue(self.redis, KEY, 'worker1')
        self.assertTrue(first.reserve())
        self.assertFalse(second.reserve())
        self.assertTrue(first.renew())
        first.release()
        self.assertTrue(second.reserve(), 'free again once released')

    def test_a_consumer_that_lost_its_name_finds_out_at_its_next_batch(self):
        first, second = ListQueue(self.redis, KEY, 'worker1'), ListQueue(self.redis, KEY, 'worker1')
        first.reserve()
        # The reservation lapsed while it hung, and another took the name
        self.redis.delete(first.owner_key)
        self.assertTrue(second.reserve())
        self.assertFalse(first.renew())
        first.release()
        self.assertTrue(second.renew(), 'releasing a lost name leaves the new owner alone')

    def test_a_name_that_lapsed_and_nobody_took_is_taken_again(self):
        # As when Valkey was down for longer than the reservation lasts
        queue = ListQueue(self.redis, KEY, 'worker1')
        queue.reserve()
        self.redis.delete(queue.owner_key)
        self.assertTrue(queue.renew())
        self.assertEqual(self.redis.get(queue.owner_key), queue.owner.encode())
        self.assertFalse(ListQueue(self.redis, KEY, 'worker1').reserve())

    def test_a_consumer_that_lost_its_name_cannot_settle_its_successors_items(self):
        # It stalled past its reservation after its last check, and another
        # took the name and claimed: its acknowledgement and requeue change nothing
        old, new = ListQueue(self.redis, KEY, 'worker1'), ListQueue(self.redis, KEY, 'worker1')
        old.reserve()
        self.redis.delete(old.owner_key)
        new.reserve()
        new.push(b'a')
        new.push(b'b')
        new.claim(2, block_seconds=0)
        self.assertRaises(NotOwner, old.ack, 2)
        self.assertRaises(NotOwner, old.requeue, [b'a', b'b'])
        self.assertEqual(new.in_flight(), 2)
        # The owner settles as before
        self.assertEqual(new.requeue([b'b']), 1)
        new.ack(1)
        self.assertEqual((new.in_flight(), new.depth()), (0, 1))

    def test_a_sweep_leaves_a_running_consumers_list_alone(self):
        running = ListQueue(self.redis, KEY, 'host-01')
        running.reserve()
        running.push(b'a')
        running.claim(1, block_seconds=0)
        dead = ListQueue(self.redis, KEY, 'host-02')
        dead.push(b'b')
        dead.claim(1, block_seconds=0)
        swept, requeued = recover_orphans(self.redis, KEY, prefix='host')
        self.assertEqual((swept, requeued), (1, 1))
        self.assertEqual(running.in_flight(), 1)
