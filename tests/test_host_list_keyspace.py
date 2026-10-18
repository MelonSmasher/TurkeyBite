"""Tests for the Valkey host list keyspace: reading it, and retiring it.

Two things can go wrong in retiring it and both are quiet. Sweeping too widely
takes the domain index manifest and chunks with it, because they share the
turkey-bite: prefix. Gating too widely stops populating the keyspace that
`compare` mode reads as authoritative, which turns a comparison into a false
agreement.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))
sys.path.insert(0, HERE)

from fakes import FakeRedis
from libtb import processor as P
from libtb.processor import Processor
from libtb.util import (TAGGED_KEY, VALKEY_BACKED_MODES, purge_tagged_keyspace,
                        unlink_matching)


def holding(keys, **options):
    """The shared fake Redis, holding these keys."""
    redis = FakeRedis(**options)
    for key in keys:
        redis.set(key, 'v')
    return redis


class TaggedKeyPatternTest(unittest.TestCase):

    def test_a_tagged_domain_key_matches(self):
        self.assertTrue(TAGGED_KEY.match('turkey-bite:1787333025:example.com'))

    def test_the_index_manifest_does_not_match(self):
        self.assertFalse(TAGGED_KEY.match('turkey-bite:index:manifest'))

    def test_an_index_chunk_does_not_match_despite_its_digits(self):
        # The chunk key carries a generation number, so a pattern that looked
        # for digits anywhere would eat the whole published index
        self.assertFalse(TAGGED_KEY.match('turkey-bite:index:1787333025:4'))

    def test_bookkeeping_keys_do_not_match(self):
        for key in ('turkey-bite:tags', 'turkey-bite:current-tag',
                    'turkey-bite:old-tag'):
            self.assertFalse(TAGGED_KEY.match(key), key)

    def test_an_unrelated_namespace_does_not_match(self):
        self.assertFalse(TAGGED_KEY.match('turkeybite:processing:fritos-01'))


class PurgeTaggedKeyspaceTest(unittest.TestCase):

    def keyspace(self):
        return [
            'turkey-bite:1787333025:example.com',
            'turkey-bite:1787333025:evil.example.net',
            'turkey-bite:1787200000:stale.example.org',
            'turkey-bite:index:manifest',
            'turkey-bite:index:1787333025:0',
            'turkey-bite:index:1787333025:1',
            'turkey-bite:tags',
            'turkey-bite:current-tag',
            'turkey-bite:old-tag',
        ]

    def test_tagged_domain_keys_are_removed(self):
        r = holding(self.keyspace())
        removed = purge_tagged_keyspace(r)
        self.assertEqual(removed, 3)
        self.assertNotIn('turkey-bite:1787333025:example.com', r.data)
        self.assertNotIn('turkey-bite:1787200000:stale.example.org', r.data)

    def test_the_published_index_survives(self):
        r = holding(self.keyspace())
        purge_tagged_keyspace(r)
        self.assertIn('turkey-bite:index:manifest', r.data)
        self.assertIn('turkey-bite:index:1787333025:0', r.data)
        self.assertIn('turkey-bite:index:1787333025:1', r.data)

    def test_bookkeeping_is_cleared_so_lookups_degrade_instead_of_lying(self):
        r = holding(self.keyspace())
        purge_tagged_keyspace(r)
        self.assertEqual(sorted(r.direct_unlinks),
                         ['turkey-bite:current-tag', 'turkey-bite:old-tag',
                          'turkey-bite:tags'])
        self.assertNotIn('turkey-bite:current-tag', r.data)

    def test_an_empty_keyspace_is_a_no_op(self):
        r = holding(['turkey-bite:index:manifest'])
        self.assertEqual(purge_tagged_keyspace(r), 0)
        self.assertIn('turkey-bite:index:manifest', r.data)

    def test_work_is_batched_rather_than_one_round_trip_per_key(self):
        keys = [f'turkey-bite:1787333025:h{i}.example.com' for i in range(2500)]
        r = holding(keys)
        removed = purge_tagged_keyspace(r, batch=1000)
        self.assertEqual(removed, 2500)
        self.assertEqual(r.executions, [1000, 1000, 500])

    def test_a_partial_final_batch_is_flushed(self):
        keys = [f'turkey-bite:1787333025:h{i}.example.com' for i in range(7)]
        r = holding(keys)
        self.assertEqual(purge_tagged_keyspace(r, batch=1000), 7)
        self.assertEqual(r.executions, [7])
        self.assertEqual([k for k in r.data if TAGGED_KEY.match(k)], [])

    def test_str_key_names_are_accepted_too(self):
        # What redis-py returns with decode_responses on
        r = holding(self.keyspace(), decoded_keys=True)
        self.assertEqual(purge_tagged_keyspace(r), 3)
        self.assertIn('turkey-bite:index:manifest', r.data)


class UnlinkMatchingTest(unittest.TestCase):
    """The batched sweep used to retire a superseded tag."""

    def test_only_the_named_tag_is_swept(self):
        r = holding(['turkey-bite:1787200000:a.example.com',
                       'turkey-bite:1787200000:b.example.com',
                       'turkey-bite:1787333025:keep.example.com',
                       'turkey-bite:index:manifest'])
        removed = unlink_matching(r, 'turkey-bite:1787200000:*')
        self.assertEqual(removed, 2)
        self.assertIn('turkey-bite:1787333025:keep.example.com', r.data)
        self.assertIn('turkey-bite:index:manifest', r.data)

    def test_it_batches(self):
        keys = [f'turkey-bite:1787200000:h{i}.example.com' for i in range(2200)]
        r = holding(keys)
        self.assertEqual(unlink_matching(r, 'turkey-bite:1787200000:*', batch=1000),
                         2200)
        self.assertEqual(r.executions, [1000, 1000, 200])

    def test_no_match_is_a_no_op(self):
        r = holding(['turkey-bite:index:manifest'])
        self.assertEqual(unlink_matching(r, 'turkey-bite:1787200000:*'), 0)
        self.assertEqual(r.executions, [])
        self.assertIn('turkey-bite:index:manifest', r.data)


class ModeGateTest(unittest.TestCase):

    def test_valkey_mode_still_populates(self):
        self.assertIn('valkey', VALKEY_BACKED_MODES)

    def test_compare_mode_still_populates(self):
        # compare keeps Valkey authoritative. Without the keyspace it would
        # report agreement against nothing.
        self.assertIn('compare', VALKEY_BACKED_MODES)

    def test_index_mode_does_not_populate(self):
        self.assertNotIn('index', VALKEY_BACKED_MODES)


class ValkeyLookupTest(unittest.TestCase):
    """What valkey mode reads for an event, and how many times it asks."""

    SEARCHES = ['ads.example.com', 'example.com', '*.example.com', '*.com']

    def setUp(self):
        self.redis = FakeRedis()
        self.redis.set('turkey-bite:current-tag', '1787333025')
        self.redis.set('turkey-bite:1787333025:example.com', '{"categories": ["news", "ads"]}')
        self.redis.set('turkey-bite:1787333025:*.example.com', '{"categories": ["ads", "tracking"]}')
        self.redis.set('turkey-bite:1787333025:*.com', 'not json')
        self.made = []
        patcher = mock.patch.object(P, 'Redis', side_effect=self.connect)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.processor = Processor({'domain_index': {'mode': 'valkey'}},
                                   {'host': 'valkey', 'port': 6379, 'password': 'x', 'host_list_db': 1})

    def connect(self, **kwargs):
        self.made.append(kwargs)
        return self.redis

    def test_every_key_is_read_and_merged_in_order(self):
        with redirect_stderr(io.StringIO()) as err:
            contexts = self.processor.valkey_contexts(self.SEARCHES)
        self.assertEqual(sorted(contexts[:2]), ['ads', 'news'])
        self.assertEqual(contexts[2:], ['tracking'])
        self.assertIn('Malformed host list entry at turkey-bite:1787333025:*.com', err.getvalue())
        self.assertEqual([key for command, key in self.redis.calls if command == 'get'],
                         ['turkey-bite:current-tag']
                         + [f'turkey-bite:1787333025:{search}' for search in self.SEARCHES])

    def test_the_keys_go_together_on_one_connection_for_the_process(self):
        # A new connection for every event cost the connection, and the
        # commands redis-py sends on each, before a key was read
        with redirect_stderr(io.StringIO()):
            for _ in range(3):
                self.processor.valkey_contexts(self.SEARCHES)
        self.assertEqual(self.made, [{'host': 'valkey', 'port': 6379, 'password': 'x', 'db': 1}])
        # The tag, then the four keys in one round trip, for each event
        self.assertEqual(self.redis.executions, [4, 4, 4])

    def test_a_forked_child_makes_its_own(self):
        # A socket must not be shared across a fork
        with redirect_stderr(io.StringIO()):
            self.processor.valkey_contexts(self.SEARCHES)
            with mock.patch.object(P.os, 'getpid', return_value=os.getpid() + 1):
                self.processor.valkey_contexts(self.SEARCHES)
        self.assertEqual(len(self.made), 2)

    def test_without_a_current_tag_nothing_else_is_read(self):
        self.redis.delete('turkey-bite:current-tag')
        self.assertEqual(self.processor.valkey_contexts(self.SEARCHES), [])
        self.assertEqual(self.redis.executions, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
