"""Tests for retiring the Valkey host list keyspace.

Two things can go wrong here and both are quiet. Sweeping too widely takes the
domain index manifest and chunks with it, because they share the turkey-bite:
prefix. Gating too widely stops populating the keyspace that `compare` mode
reads as authoritative, which turns a comparison into a false agreement.
"""

import fnmatch
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from libtb.util import (TAGGED_KEY, VALKEY_BACKED_MODES, purge_tagged_keyspace,
                        unlink_matching)


class StubPipeline(object):

    def __init__(self, store, executions):
        self.store = store
        self.executions = executions
        self.queued = []

    def unlink(self, name):
        self.queued.append(name)

    def execute(self):
        for name in self.queued:
            self.store.pop(name, None)
        self.executions.append(len(self.queued))
        self.queued = []


class StubRedis(object):
    """Enough of redis-py for this sweep, with keys returned as bytes."""

    def __init__(self, keys):
        self.store = {k: b'v' for k in keys}
        self.executions = []
        self.direct_unlinks = []

    def scan_iter(self, match=None, count=None):
        # A snapshot, which is what SCAN approximates and what makes deleting
        # while iterating safe
        for name in list(self.store):
            if match is None or fnmatch.fnmatch(name, match):
                yield name.encode('utf-8')

    def pipeline(self, transaction=True):
        return StubPipeline(self.store, self.executions)

    def unlink(self, key):
        self.direct_unlinks.append(key)
        self.store.pop(key, None)


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
        r = StubRedis(self.keyspace())
        removed = purge_tagged_keyspace(r)
        self.assertEqual(removed, 3)
        self.assertNotIn('turkey-bite:1787333025:example.com', r.store)
        self.assertNotIn('turkey-bite:1787200000:stale.example.org', r.store)

    def test_the_published_index_survives(self):
        r = StubRedis(self.keyspace())
        purge_tagged_keyspace(r)
        self.assertIn('turkey-bite:index:manifest', r.store)
        self.assertIn('turkey-bite:index:1787333025:0', r.store)
        self.assertIn('turkey-bite:index:1787333025:1', r.store)

    def test_bookkeeping_is_cleared_so_lookups_degrade_instead_of_lying(self):
        r = StubRedis(self.keyspace())
        purge_tagged_keyspace(r)
        self.assertEqual(sorted(r.direct_unlinks),
                         ['turkey-bite:current-tag', 'turkey-bite:old-tag',
                          'turkey-bite:tags'])
        self.assertNotIn('turkey-bite:current-tag', r.store)

    def test_an_empty_keyspace_is_a_no_op(self):
        r = StubRedis(['turkey-bite:index:manifest'])
        self.assertEqual(purge_tagged_keyspace(r), 0)
        self.assertIn('turkey-bite:index:manifest', r.store)

    def test_work_is_batched_rather_than_one_round_trip_per_key(self):
        keys = [f'turkey-bite:1787333025:h{i}.example.com' for i in range(2500)]
        r = StubRedis(keys)
        removed = purge_tagged_keyspace(r, batch=1000)
        self.assertEqual(removed, 2500)
        self.assertEqual(r.executions, [1000, 1000, 500])

    def test_a_partial_final_batch_is_flushed(self):
        keys = [f'turkey-bite:1787333025:h{i}.example.com' for i in range(7)]
        r = StubRedis(keys)
        self.assertEqual(purge_tagged_keyspace(r, batch=1000), 7)
        self.assertEqual(r.executions, [7])
        self.assertEqual([k for k in r.store if TAGGED_KEY.match(k)], [])

    def test_str_key_names_are_accepted_too(self):
        class StrRedis(StubRedis):
            def scan_iter(self, match=None, count=None):
                for name in list(self.store):
                    if match is None or fnmatch.fnmatch(name, match):
                        yield name

        r = StrRedis(self.keyspace())
        self.assertEqual(purge_tagged_keyspace(r), 3)
        self.assertIn('turkey-bite:index:manifest', r.store)


class UnlinkMatchingTest(unittest.TestCase):
    """The batched sweep used to retire a superseded tag."""

    def test_only_the_named_tag_is_swept(self):
        r = StubRedis(['turkey-bite:1787200000:a.example.com',
                       'turkey-bite:1787200000:b.example.com',
                       'turkey-bite:1787333025:keep.example.com',
                       'turkey-bite:index:manifest'])
        removed = unlink_matching(r, 'turkey-bite:1787200000:*')
        self.assertEqual(removed, 2)
        self.assertIn('turkey-bite:1787333025:keep.example.com', r.store)
        self.assertIn('turkey-bite:index:manifest', r.store)

    def test_it_batches(self):
        keys = [f'turkey-bite:1787200000:h{i}.example.com' for i in range(2200)]
        r = StubRedis(keys)
        self.assertEqual(unlink_matching(r, 'turkey-bite:1787200000:*', batch=1000),
                         2200)
        self.assertEqual(r.executions, [1000, 1000, 200])

    def test_no_match_is_a_no_op(self):
        r = StubRedis(['turkey-bite:index:manifest'])
        self.assertEqual(unlink_matching(r, 'turkey-bite:1787200000:*'), 0)
        self.assertEqual(r.executions, [])
        self.assertIn('turkey-bite:index:manifest', r.store)


class ModeGateTest(unittest.TestCase):

    def test_valkey_mode_still_populates(self):
        self.assertIn('valkey', VALKEY_BACKED_MODES)

    def test_compare_mode_still_populates(self):
        # compare keeps Valkey authoritative. Without the keyspace it would
        # report agreement against nothing.
        self.assertIn('compare', VALKEY_BACKED_MODES)

    def test_index_mode_does_not_populate(self):
        self.assertNotIn('index', VALKEY_BACKED_MODES)


if __name__ == '__main__':
    unittest.main(verbosity=2)
