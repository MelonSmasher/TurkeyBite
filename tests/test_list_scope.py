"""Tests for how far a list entry reaches.

Two faults made the lists over-apply, and both produced false positives at
scale. Every entry was treated as covering its subdomains, though a hosts file
can only ever name one host. And an entry was allowed to speak for names above
the registrable domain, so one list naming workers.dev or com.cn labelled every
unrelated site hosted under them.
"""

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))

from libtb import psl
from libtb.evidence import ownership_boundary
from libtb.index import DomainIndex, Source
from libtb.index.builder import build, collect_entries, load_sources, source_table
from libtb.util import clean_list_file, valkey_host

FIXTURE = os.path.join(HERE, 'fixture_public_suffix_list.dat')
TLDS = ['com', 'net', 'org', 'dev', 'edu', 'uk', 'cn']


def downloaded(name, trust='medium'):
    return Source(name, name, trust, False, ())


def local(name='turkeybite'):
    return Source(name, 'local', 'high', True, ())


class Workspace(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-scope-')

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def index(self, entries, sources=None):
        path = os.path.join(self.root, 'domains.tbidx')
        build(entries, path=path, built_at=1000, sources=sources)
        index = DomainIndex(path)
        self.addCleanup(index.close)
        return index

    def categories(self, index, host, boundary=None):
        return sorted({c for _, _, c in index.match(host, boundary)})


class CleanerScopeTest(Workspace):
    """What each list format says about its reach survives cleaning."""

    def clean(self, *lines):
        path = os.path.join(self.root, 'list')
        with open(path, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        clean_list_file(path, TLDS)
        with open(path) as fh:
            return [line.strip() for line in fh if line.strip()]

    def test_a_hosts_file_line_names_one_host(self):
        self.assertEqual(self.clean('0.0.0.0 ads.example.com'), ['ads.example.com'])

    def test_an_adblock_domain_rule_covers_subdomains(self):
        self.assertEqual(self.clean('||example.com^'), ['*.example.com'])

    def test_adblock_options_do_not_change_the_reach(self):
        self.assertEqual(self.clean('||example.com^$third-party'), ['*.example.com'])

    def test_a_start_anchored_adblock_rule_names_one_host(self):
        self.assertEqual(self.clean('|example.com^'), ['example.com'])

    def test_a_squid_leading_dot_covers_subdomains(self):
        self.assertEqual(self.clean('.example.com'), ['*.example.com'])

    def test_a_wildcard_line_is_kept_as_written(self):
        self.assertEqual(self.clean('*.example.com', '||*.example.net^'),
                         ['*.example.com', '*.example.net'])

    def test_a_plain_domain_is_left_for_the_source_to_interpret(self):
        self.assertEqual(self.clean('example.com'), ['example.com'])

    def test_a_single_label_adblock_rule_is_still_rejected(self):
        # Checked before the wildcard is added, or this would become '*.com'
        self.assertEqual(self.clean('||com^', '||example.com^'), ['*.example.com'])

    def test_the_two_reaches_of_one_name_are_both_kept(self):
        self.assertEqual(self.clean('0.0.0.0 example.com', '||example.com^'),
                         ['example.com', '*.example.com'])


class ValkeyKeyspaceTest(unittest.TestCase):
    """The Valkey mode matches exact names, so it has to keep getting them."""

    def test_a_downloaded_wildcard_is_stored_bare(self):
        # Otherwise '*.ads.example.com' would never match ads.example.com
        self.assertEqual(valkey_host('*.ads.example.com\n', downloaded=True), 'ads.example.com')

    def test_a_local_wildcard_is_kept(self):
        # '*.' plus the TLD is a name valkey_contexts synthesises
        self.assertEqual(valkey_host('*.edu\n', downloaded=False), '*.edu')

    def test_a_bare_line_is_unchanged(self):
        self.assertEqual(valkey_host(' Ads.Example.com \n', downloaded=True), 'ads.example.com')


class CollectorScopeTest(Workspace):
    """How a bare line is read depends on who published it."""

    def setUp(self):
        super().setUp()
        self.lists = os.path.join(self.root, 'lists')

    def write(self, category, name, lines):
        directory = os.path.join(self.lists, category)
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, name), 'w') as fh:
            fh.write('\n'.join(lines) + '\n')

    def configured(self, name, **settings):
        return [dict({'file': f'lists/porn/{name}', 'categories': ['porn']}, **settings)]

    def test_a_bare_line_in_a_download_names_one_host(self):
        self.write('porn', 'dl', ['example.com'])
        entries, _, _ = collect_entries(self.lists, host_files=self.configured('dl'))
        self.assertEqual(list(entries), ['example.com'])

    def test_a_download_can_declare_its_bare_lines_cover_subdomains(self):
        self.write('porn', 'dl', ['example.com'])
        entries, _, _ = collect_entries(
            self.lists, host_files=self.configured('dl', match='subtree'))
        self.assertEqual(list(entries), ['*.example.com'])

    def test_a_wildcard_line_covers_subdomains_whatever_the_source_says(self):
        self.write('porn', 'dl', ['*.example.com'])
        entries, _, _ = collect_entries(self.lists, host_files=self.configured('dl'))
        self.assertEqual(list(entries), ['*.example.com'])

    def test_a_local_list_covers_whole_domains(self):
        self.write('news', 'turkeybite', ['example.com'])
        entries, _, _ = collect_entries(self.lists, host_files=[])
        self.assertEqual(list(entries), ['*.example.com'])

    def test_an_unknown_match_is_refused(self):
        with self.assertRaises(ValueError):
            load_sources(host_files=self.configured('dl', match='everything'))

    def test_an_unknown_trust_is_refused(self):
        with self.assertRaises(ValueError):
            load_sources(host_files=self.configured('dl', trust='certain'))

    def test_an_undeclared_download_needs_corroboration(self):
        sources = source_table(load_sources(host_files=self.configured('dl')))
        self.assertEqual(sources['dl'].trust, 'medium')
        self.assertEqual(sources['dl'].publisher, 'dl')
        self.assertFalse(sources['dl'].local)

    def test_declared_metadata_is_carried(self):
        sources = source_table(load_sources(host_files=self.configured(
            'dl', trust='low', publisher='pub', derived_from=['up'])))
        self.assertEqual(sources['dl'], Source('dl', 'pub', 'low', False, ('up',)))


class ExactAndSubtreeTest(Workspace):
    """The two kinds of key, and how far each one reaches."""

    def test_an_exact_entry_matches_its_own_host(self):
        index = self.index({'ads.example.com': {'dl': {'advertising'}}})
        self.assertEqual(self.categories(index, 'ads.example.com'), ['advertising'])

    def test_an_exact_entry_does_not_cover_subdomains(self):
        # The hosts-file fault: x.com on a list used to label api.x.com too
        index = self.index({'example.com': {'dl': {'porn'}}})
        self.assertEqual(self.categories(index, 'api.example.com'), [])

    def test_the_same_name_as_a_subtree_entry_does_cover_them(self):
        # The control for the test above: only the key differs
        index = self.index({'*.example.com': {'dl': {'porn'}}})
        self.assertEqual(self.categories(index, 'api.example.com'), ['porn'])

    def test_a_subtree_entry_covers_its_apex(self):
        index = self.index({'*.example.com': {'dl': {'porn'}}})
        self.assertEqual(self.categories(index, 'example.com'), ['porn'])

    def test_an_exact_entry_is_the_same_site_with_or_without_www(self):
        index = self.index({'example.com': {'dl': {'porn'}},
                            'www.example.org': {'dl': {'porn'}}})
        self.assertEqual(self.categories(index, 'www.example.com'), ['porn'])
        self.assertEqual(self.categories(index, 'example.org'), ['porn'])

    def test_the_www_alias_is_only_www(self):
        index = self.index({'example.com': {'dl': {'porn'}}})
        self.assertEqual(self.categories(index, 'ww.example.com'), [])

    def test_matches_report_the_key_that_matched(self):
        index = self.index({'*.example.com': {'dl': {'porn'}}})
        self.assertEqual([key for key, _, _ in index.match('a.example.com')],
                         ['*.example.com'])


class OwnershipBoundaryTest(Workspace):
    """Above the registrable domain, names belong to someone else."""

    def test_a_downloaded_entry_cannot_speak_for_a_public_suffix(self):
        index = self.index({'*.workers.dev': {'dl': {'malicious'}}},
                           {'dl': downloaded('dl')})
        self.assertEqual(self.categories(index, 'shop.workers.dev', 'shop.workers.dev'), [])

    def test_without_a_boundary_it_would(self):
        # Proves the boundary is what stops it, not something else
        index = self.index({'*.workers.dev': {'dl': {'malicious'}}},
                           {'dl': downloaded('dl')})
        self.assertEqual(self.categories(index, 'shop.workers.dev'), ['malicious'])

    def test_a_local_list_may_categorise_a_whole_suffix(self):
        # How '*.edu' and '*.gov' keep working
        index = self.index({'*.edu': {'turkeybite': {'education'}}},
                           {'turkeybite': local()})
        self.assertEqual(self.categories(index, 'www.mit.edu', 'mit.edu'), ['education'])

    def test_below_the_boundary_a_parent_still_speaks_for_its_children(self):
        index = self.index({'*.example.com': {'dl': {'porn'}}}, {'dl': downloaded('dl')})
        self.assertEqual(self.categories(index, 'a.b.example.com', 'example.com'), ['porn'])

    def test_a_parent_that_is_not_itself_a_suffix_is_still_above_the_owner(self):
        # bucket.s3.amazonaws.com is somebody's bucket; Amazon's own entry for
        # amazonaws.com says nothing about it
        index = self.index({'*.amazonaws.com': {'dl': {'malicious'}}},
                           {'dl': downloaded('dl')})
        self.assertEqual(self.categories(index, 'bucket.s3.amazonaws.com',
                                         'bucket.s3.amazonaws.com'), [])

    def test_the_www_alias_respects_the_boundary(self):
        index = self.index({'github.io': {'dl': {'malicious'}}}, {'dl': downloaded('dl')})
        self.assertEqual(self.categories(index, 'www.github.io', 'www.github.io'), [])

    def test_a_name_that_is_a_suffix_can_still_be_named_directly(self):
        index = self.index({'workers.dev': {'dl': {'malicious'}}}, {'dl': downloaded('dl')})
        self.assertEqual(self.categories(index, 'workers.dev', 'workers.dev'), ['malicious'])


class BoundaryFromThePslTest(unittest.TestCase):
    """The boundary the worker computes, against the real list."""

    def tearDown(self):
        psl.forget()

    def test_shared_platforms_end_at_the_tenant(self):
        self.assertEqual(ownership_boundary('a.b.workers.dev', FIXTURE), 'b.workers.dev')
        self.assertEqual(ownership_boundary('www.sina.com.cn', FIXTURE), 'sina.com.cn')
        self.assertEqual(ownership_boundary('bucket.s3.amazonaws.com', FIXTURE),
                         'bucket.s3.amazonaws.com')

    def test_an_ordinary_domain_ends_at_its_registrable_name(self):
        self.assertEqual(ownership_boundary('news.bbc.co.uk', FIXTURE), 'bbc.co.uk')

    def test_a_suffix_is_its_own_boundary(self):
        self.assertEqual(ownership_boundary('github.io', FIXTURE), 'github.io')


class FormatTest(Workspace):

    def test_source_metadata_survives_a_round_trip(self):
        source = Source('dl', 'pub', 'low', False, ('up1', 'up2'))
        index = self.index({'example.com': {'dl': {'porn'}}}, {'dl': source})
        self.assertEqual(index.sources['dl'], source)

    def test_an_unlisted_source_is_written_as_local(self):
        index = self.index({'example.com': {'turkeybite': {'news'}}})
        self.assertEqual(index.sources['turkeybite'], Source('turkeybite', 'local', 'high', True, ()))

    def test_claims_keep_who_said_what(self):
        index = self.index({'example.com': {'a': {'porn'}, 'b': {'malware'}}})
        claims = sorted((source.name, category) for _, source, category in index.match('example.com'))
        self.assertEqual(claims, [('a', 'porn'), ('b', 'malware')])

    def test_an_entry_with_no_claims_is_not_written(self):
        index = self.index({'example.com': {'a': set()}, 'other.example.org': {'a': {'news'}}})
        self.assertEqual(index.n_domains, 1)

    def test_an_older_format_is_refused_by_name(self):
        path = os.path.join(self.root, 'old.tbidx')
        with open(path, 'wb') as fh:
            fh.write(b'TBIDX\x00\x00\x02' + bytes(32))
        with self.assertRaisesRegex(ValueError, 'rebuild'):
            DomainIndex(path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
