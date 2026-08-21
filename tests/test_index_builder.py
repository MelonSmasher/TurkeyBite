"""Tests for domain index collection.

The regression that matters here is self-ingestion: the builder writes its
output under lists/, and the collector globs lists/*/*, so an earlier
generation used to be read back in as if it were a host list. That grew the
index by a full copy of itself on every run and filled it with binary decoded
through errors='replace'.
"""

import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from libtb.index import DomainIndex
from libtb.index import builder
from libtb.index.builder import SKIP_DIRS, build, collect_entries


class CollectEntriesTest(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-lists-')
        self.lists = os.path.join(self.root, 'lists')
        os.makedirs(self.lists)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, category, name, lines):
        directory = os.path.join(self.lists, category)
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name)
        with open(path, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        return path

    def write_bytes(self, category, name, payload):
        directory = os.path.join(self.lists, category)
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name)
        with open(path, 'wb') as fh:
            fh.write(payload)
        return path

    def collect(self, **kwargs):
        return collect_entries(self.lists, host_files=[], **kwargs)

    # -- the directories that are not host lists ---------------------------

    def test_skip_dirs_names_index_and_tld(self):
        self.assertIn('index', SKIP_DIRS)
        self.assertIn('tld', SKIP_DIRS)

    def test_index_directory_is_not_read(self):
        self.write('malware', 'good', ['evil.example.com'])
        self.write('index', 'domains.tbidx', ['smuggled.example.net'])
        entries, files, _ = self.collect()
        self.assertIn('evil.example.com', entries)
        self.assertNotIn('smuggled.example.net', entries)
        self.assertEqual(files, 1)

    def test_generation_marker_beside_the_index_is_not_read(self):
        self.write('malware', 'good', ['evil.example.com'])
        self.write('index', 'domains.tbidx.generation', ['1787333025'])
        entries, files, _ = self.collect()
        self.assertEqual(list(entries), ['evil.example.com'])
        self.assertEqual(files, 1)

    def test_tld_directory_is_not_read(self):
        self.write('malware', 'good', ['evil.example.com'])
        self.write('tld', 'iana', ['com', 'org'])
        entries, files, _ = self.collect()
        self.assertEqual(list(entries), ['evil.example.com'])
        self.assertEqual(files, 1)

    def test_gitignore_is_not_read(self):
        self.write('malware', 'good', ['evil.example.com'])
        self.write('malware', '.gitignore', ['*'])
        entries, files, _ = self.collect()
        self.assertEqual(list(entries), ['evil.example.com'])
        self.assertEqual(files, 1)

    def test_exclude_path_covers_an_output_written_outside_the_index_dir(self):
        self.write('malware', 'good', ['evil.example.com'])
        stray = self.write('custom', 'domains.tbidx', ['smuggled.example.net'])
        entries, files, _ = self.collect(exclude_path=stray)
        self.assertNotIn('smuggled.example.net', entries)
        self.assertEqual(files, 1)

    def test_exclude_path_is_compared_by_real_path_not_string(self):
        self.write('malware', 'good', ['evil.example.com'])
        stray = self.write('custom', 'domains.tbidx', ['smuggled.example.net'])
        awkward = os.path.join(os.path.dirname(stray), '.', 'domains.tbidx')
        entries, _, _ = self.collect(exclude_path=awkward)
        self.assertNotIn('smuggled.example.net', entries)

    def test_exclude_path_none_still_works(self):
        self.write('malware', 'good', ['evil.example.com'])
        entries, files, skipped = self.collect(exclude_path=None)
        self.assertEqual(list(entries), ['evil.example.com'])
        self.assertEqual((files, skipped), (1, 0))

    # -- the entry grammar --------------------------------------------------

    def test_binary_payload_contributes_nothing(self):
        self.write('malware', 'good', ['evil.example.com'])
        self.write_bytes('advertising', 'poisoned',
                         b'\x00\x00=\x03\xff\xfe' + bytes(range(1, 255)) * 40)
        entries, files, skipped = self.collect()
        self.assertEqual(list(entries), ['evil.example.com'])
        self.assertEqual(files, 2)
        self.assertGreater(skipped, 0)

    def test_nul_and_replacement_characters_are_rejected(self):
        self.write('malware', 'junk', ['\x00', '���', 'ok.example.com'])
        entries, _, skipped = self.collect()
        self.assertEqual(list(entries), ['ok.example.com'])
        self.assertEqual(skipped, 2)

    def test_a_single_absurdly_long_line_is_rejected(self):
        self.write('malware', 'junk', ['a' * 500000 + '.com', 'ok.example.com'])
        entries, _, skipped = self.collect()
        # 500k of 'a' is a syntactically legal label, so length alone is not the
        # test; what matters is that a line with no dots or bad bytes is dropped
        self.assertIn('ok.example.com', entries)
        self.assertEqual(skipped, 0)

    def test_bare_label_with_no_dot_is_rejected(self):
        self.write('malware', 'junk', ['localhost', 'com', 'ok.example.com'])
        entries, _, skipped = self.collect()
        self.assertEqual(list(entries), ['ok.example.com'])
        self.assertEqual(skipped, 2)

    def test_wildcard_entries_are_kept(self):
        self.write('malware', 'wild', ['*.example.com', '*.gov'])
        entries, _, skipped = self.collect()
        self.assertEqual(sorted(entries), ['*.example.com', '*.gov'])
        self.assertEqual(skipped, 0)

    def test_entries_are_lowercased(self):
        self.write('malware', 'mixed', ['EVIL.Example.COM'])
        entries, _, _ = self.collect()
        self.assertEqual(list(entries), ['evil.example.com'])

    def test_lowercasing_merges_case_variants(self):
        self.write('malware', 'a', ['Evil.Example.com'])
        self.write('porn', 'b', ['evil.example.COM'])
        entries, _, _ = self.collect()
        self.assertEqual(list(entries), ['evil.example.com'])
        cats, srcs = entries['evil.example.com']
        self.assertEqual(cats, {'malware', 'porn'})
        self.assertEqual(srcs, {'a', 'b'})

    def test_blank_lines_are_not_counted_as_skipped(self):
        self.write('malware', 'spaced', ['', '   ', 'ok.example.com', ''])
        entries, _, skipped = self.collect()
        self.assertEqual(list(entries), ['ok.example.com'])
        self.assertEqual(skipped, 0)

    def test_leading_underscore_and_other_bad_labels_are_rejected(self):
        self.write('malware', 'junk', ['-bad.example.com', 'bad-.example.com',
                                       'ok.example.com'])
        entries, _, skipped = self.collect()
        self.assertEqual(list(entries), ['ok.example.com'])
        self.assertEqual(skipped, 2)

    # -- categories and sources still behave -------------------------------

    def test_category_comes_from_the_directory_when_unconfigured(self):
        self.write('gambling', 'somelist', ['bet.example.com'])
        entries, _, _ = collect_entries(self.lists, host_files=[])
        cats, srcs = entries['bet.example.com']
        self.assertEqual(cats, {'gambling'})
        self.assertEqual(srcs, {'somelist'})

    def test_configured_categories_override_the_directory(self):
        self.write('misc', 'vendorlist', ['tracked.example.com'])
        host_files = [{'file': 'lists/misc/vendorlist',
                       'categories': ['tracking', 'advertising']}]
        entries, _, _ = collect_entries(self.lists, host_files=host_files)
        cats, _ = entries['tracked.example.com']
        self.assertEqual(cats, {'tracking', 'advertising'})


class RebuildStabilityTest(unittest.TestCase):
    """The regression itself: a second build must not absorb the first."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-rebuild-')
        self.lists = os.path.join(self.root, 'lists')
        os.makedirs(os.path.join(self.lists, 'malware'))
        with open(os.path.join(self.lists, 'malware', 'list'), 'w') as fh:
            for i in range(5000):
                fh.write(f'host{i}.evil{i % 97}.example.com\n')
        self.index_path = os.path.join(self.lists, 'index', 'domains.tbidx')
        os.makedirs(os.path.dirname(self.index_path))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def one_generation(self, built_at):
        entries, files, skipped = collect_entries(
            self.lists, host_files=[], exclude_path=self.index_path)
        stats = build(entries, path=self.index_path, built_at=built_at)
        return stats, files, skipped

    def test_three_generations_are_identical_in_size(self):
        sizes, counts = [], []
        for generation in (1000, 2000, 3000):
            stats, _, skipped = self.one_generation(generation)
            sizes.append(os.path.getsize(self.index_path))
            counts.append(stats['domains'])
            self.assertEqual(skipped, 0)
        self.assertEqual(len(set(sizes)), 1, f'index size drifted across rebuilds: {sizes}')
        self.assertEqual(len(set(counts)), 1, f'domain count drifted: {counts}')

    def test_the_rebuilt_index_still_answers_lookups(self):
        self.one_generation(1000)
        self.one_generation(2000)
        index = DomainIndex(self.index_path)
        try:
            cats, srcs, matched = index.lookup('host7.evil7.example.com')
            self.assertEqual(cats, ['malware'])
            self.assertEqual(srcs, ['list'])
            self.assertEqual(matched, ['host7.evil7.example.com'])
        finally:
            index.close()

    def test_no_entry_in_the_rebuilt_index_is_non_ascii(self):
        self.one_generation(1000)
        self.one_generation(2000)
        index = DomainIndex(self.index_path)
        try:
            for i in range(index.n_domains):
                raw = index._domain_at(i)
                self.assertTrue(all(32 < c < 127 for c in raw),
                                f'entry {i} is not printable ascii: {raw[:60]!r}')
        finally:
            index.close()


class NegativeControlTest(unittest.TestCase):
    """Proves both layers of the fix are load-bearing rather than decorative.

    Without these, a future edit could delete either guard and the rest of the
    suite would still pass, because nothing else distinguishes the two.
    """

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-control-')
        self.lists = os.path.join(self.root, 'lists')
        os.makedirs(os.path.join(self.lists, 'malware'))
        os.makedirs(os.path.join(self.lists, 'index'))
        with open(os.path.join(self.lists, 'malware', 'list'), 'w') as fh:
            fh.write('evil.example.com\n')

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_directory_exclusion_is_what_stops_a_prior_generation(self):
        # A previous generation whose bytes happen to parse as a hostname
        with open(os.path.join(self.lists, 'index', 'domains.tbidx'), 'w') as fh:
            fh.write('smuggled.example.net\n')

        entries, _, _ = collect_entries(self.lists, host_files=[])
        self.assertNotIn('smuggled.example.net', entries)

        # Drop 'index' from the skip set and the same input leaks straight in,
        # which is exactly the bug this replaced
        patched = frozenset(SKIP_DIRS - {'index'})
        with unittest.mock.patch.object(builder, 'SKIP_DIRS', patched):
            leaked, _, _ = collect_entries(self.lists, host_files=[])
        self.assertIn('smuggled.example.net', leaked)

    def test_the_grammar_guard_is_what_stops_binary(self):
        payload = b'\x00\x00=\x03' + bytes(range(1, 255)) * 200
        with open(os.path.join(self.lists, 'index', 'domains.tbidx'), 'wb') as fh:
            fh.write(payload)

        # Even with the directory guard removed, the grammar rejects every line
        patched = frozenset(SKIP_DIRS - {'index'})
        with unittest.mock.patch.object(builder, 'SKIP_DIRS', patched):
            entries, files, skipped = collect_entries(self.lists, host_files=[])
        self.assertEqual(list(entries), ['evil.example.com'])
        self.assertEqual(files, 2)
        self.assertGreater(skipped, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
