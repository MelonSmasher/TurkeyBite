"""Tests for shipping the domain index from the librarian to remote workers.

A worker on another host reads the index the librarian published through
Valkey, so the failures that matter are the ones that would leave a worker
with a broken index or none. Publishing must flip the manifest only once every
chunk is in place, and delete the previous generation only after the flip, so
a worker fetching meanwhile sees one complete generation or the other. And a
fetch that goes wrong, with a chunk missing or the wrong size or checksum,
must leave the worker's existing copy and its generation marker exactly as
they were, and no partial download behind.

Redis is tests/fakes.py, which records every command so the order can be
checked. No test touches the network.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))
sys.path.insert(0, HERE)

from fakes import FakeRedis
from libtb.index import transport as T


def chunk(built_at, n):
    return f'{T.CHUNK_PREFIX}{built_at}:{n}'


class Transport(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-transport-')
        self.addCleanup(shutil.rmtree, self.root, True)
        self.redis = FakeRedis()
        self.worker = os.path.join(self.root, 'worker', 'domains.tbidx')

    def built(self, content, name='built.tbidx'):
        path = os.path.join(self.root, name)
        with open(path, 'wb') as fh:
            fh.write(content)
        return path

    def publish(self, content, built_at, chunk_bytes=10):
        return T.publish(self.redis, self.built(content), built_at, chunk_bytes=chunk_bytes)

    def local(self, path=None):
        with open(path or self.worker, 'rb') as fh:
            return fh.read()

    def position(self, command, key):
        return self.redis.calls.index((command, key))


class PublishTest(Transport):

    def test_the_file_is_split_into_chunks_of_the_given_size(self):
        content = bytes(range(25))
        manifest = self.publish(content, 1000)
        self.assertEqual([self.redis.data[chunk(1000, n)] for n in range(3)],
                         [content[:10], content[10:20], content[20:]])
        self.assertEqual(manifest, {'built_at': 1000, 'bytes': 25, 'chunks': 3, 'chunk_bytes': 10,
                                    'sha256': hashlib.sha256(content).hexdigest()})
        self.assertEqual(json.loads(self.redis.data[T.MANIFEST_KEY]), manifest)

    def test_an_exact_multiple_makes_no_empty_chunk(self):
        self.assertEqual(self.publish(b'x' * 20, 1000)['chunks'], 2)
        self.assertNotIn(chunk(1000, 2), self.redis.data)

    def test_the_manifest_flips_only_after_every_chunk_is_written(self):
        self.publish(b'x' * 25, 1000)
        flip = self.position('set', T.MANIFEST_KEY)
        for n in range(3):
            self.assertLess(self.position('set', chunk(1000, n)), flip)

    def test_the_old_generation_goes_only_after_the_flip(self):
        self.publish(b'a' * 30, 1000)
        self.redis.calls.clear()
        self.publish(b'b' * 5, 2000)
        flip = self.position('set', T.MANIFEST_KEY)
        for n in range(3):
            self.assertGreater(self.position('delete', chunk(1000, n)), flip)
            self.assertNotIn(chunk(1000, n), self.redis.data)
        self.assertEqual(self.redis.data[chunk(2000, 0)], b'b' * 5)

    def test_republishing_a_generation_keeps_its_chunks(self):
        self.publish(b'a' * 15, 1000)
        self.publish(b'a' * 15, 1000)
        self.assertEqual([self.redis.data.get(chunk(1000, n)) for n in range(2)],
                         [b'a' * 10, b'a' * 5])

    def test_a_worker_fetching_mid_publish_gets_a_whole_generation(self):
        self.publish(b'old' * 10, 1000)
        seen = []

        def fetch_part_way(command, key):
            if command == 'set' and key == chunk(2000, 1) and not seen:
                seen.append(T.fetch_if_stale(self.redis, self.worker))
        self.redis.on_command = fetch_part_way
        self.publish(b'new' * 10, 2000)
        self.redis.on_command = None
        self.assertEqual(seen[0]['built_at'], 1000)
        self.assertEqual(self.local(), b'old' * 10)
        T.fetch_if_stale(self.redis, self.worker)
        self.assertEqual(self.local(), b'new' * 10)


class ManifestTest(Transport):

    def test_no_manifest_is_none(self):
        self.assertIsNone(T.read_manifest(self.redis))

    def test_a_manifest_that_is_not_json_is_none(self):
        for raw in (b'not json', b'', b'\xff'):
            self.redis.data[T.MANIFEST_KEY] = raw
            self.assertIsNone(T.read_manifest(self.redis), raw)

    def test_a_decoded_manifest_is_read_too(self):
        self.redis.data[T.MANIFEST_KEY] = '{"built_at": 7}'
        self.assertEqual(T.read_manifest(self.redis), {'built_at': 7})

    def test_the_local_generation_is_read_from_its_marker(self):
        self.assertIsNone(T.local_generation(self.worker))
        os.makedirs(os.path.dirname(self.worker))
        for text, expected in (('1000\n', 1000), ('garbage', None), ('', None)):
            with open(self.worker + '.generation', 'w') as fh:
                fh.write(text)
            self.assertEqual(T.local_generation(self.worker), expected, text)


class FetchTest(Transport):

    def setUp(self):
        super().setUp()
        self.content = bytes(range(256)) * 3
        self.publish(self.content, 2000, chunk_bytes=100)

    def install_old_copy(self):
        os.makedirs(os.path.dirname(self.worker), exist_ok=True)
        with open(self.worker, 'wb') as fh:
            fh.write(b'the working old index')
        with open(self.worker + '.generation', 'w') as fh:
            fh.write('1000')

    def assert_old_copy_untouched(self):
        self.assertEqual(self.local(), b'the working old index')
        self.assertEqual(T.local_generation(self.worker), 1000)
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.worker))),
                         ['domains.tbidx', 'domains.tbidx.generation'])

    def test_a_stale_copy_is_replaced_and_its_marker_updated(self):
        self.install_old_copy()
        manifest = T.fetch_if_stale(self.redis, self.worker)
        self.assertEqual(manifest['built_at'], 2000)
        self.assertEqual(self.local(), self.content)
        self.assertEqual(T.local_generation(self.worker), 2000)

    def test_a_worker_with_no_copy_gets_one_and_its_directory(self):
        T.fetch_if_stale(self.redis, self.worker)
        self.assertEqual(self.local(), self.content)

    def test_a_current_copy_is_not_downloaded_again(self):
        T.fetch_if_stale(self.redis, self.worker)
        self.redis.calls.clear()
        self.assertIsNone(T.fetch_if_stale(self.redis, self.worker))
        self.assertEqual([key for _, key in self.redis.calls if key != T.MANIFEST_KEY], [])

    def test_nothing_published_means_nothing_fetched(self):
        self.redis = FakeRedis()
        self.assertIsNone(T.fetch_if_stale(self.redis, self.worker))
        self.assertFalse(os.path.exists(os.path.dirname(self.worker)))

    def test_a_checksum_mismatch_leaves_the_local_copy_alone(self):
        self.install_old_copy()
        corrupt = bytearray(self.redis.data[chunk(2000, 3)])
        corrupt[0] ^= 0xff
        self.redis.data[chunk(2000, 3)] = bytes(corrupt)
        with self.assertRaisesRegex(ValueError, 'checksum'):
            T.fetch_if_stale(self.redis, self.worker)
        self.assert_old_copy_untouched()

    def test_a_size_mismatch_leaves_the_local_copy_alone(self):
        self.install_old_copy()
        self.redis.data[chunk(2000, 7)] = self.redis.data[chunk(2000, 7)][:-1]
        with self.assertRaisesRegex(ValueError, 'size mismatch'):
            T.fetch_if_stale(self.redis, self.worker)
        self.assert_old_copy_untouched()

    def test_a_missing_chunk_leaves_the_local_copy_alone(self):
        self.install_old_copy()
        del self.redis.data[chunk(2000, 4)]
        with self.assertRaisesRegex(ValueError, 'chunk 4 of 8 is missing'):
            T.fetch_if_stale(self.redis, self.worker)
        self.assert_old_copy_untouched()

    def test_the_marker_moves_only_once_the_file_is_in_place(self):
        # A crash between the two must leave the marker on the older
        # generation, so the next sync downloads again
        self.install_old_copy()
        with mock.patch.object(T.os, 'replace', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                T.fetch_if_stale(self.redis, self.worker)
        self.assert_old_copy_untouched()

    def test_after_a_failure_the_next_sync_recovers(self):
        self.install_old_copy()
        saved = self.redis.data.pop(chunk(2000, 0))
        with self.assertRaises(ValueError):
            T.fetch_if_stale(self.redis, self.worker)
        self.redis.data[chunk(2000, 0)] = saved
        T.fetch_if_stale(self.redis, self.worker)
        self.assertEqual(self.local(), self.content)


if __name__ == '__main__':
    unittest.main(verbosity=2)
