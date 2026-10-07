"""Recorded beat events, run the whole way through to the document OpenSearch gets.

Every other suite tests a piece. This one takes a Packetbeat DNS event and a
Browserbeat history event shaped as the beats publish them, see
tests/fixtures, and runs each through what a worker runs: config.yaml read by
read_config, the sieve, the processor, and the OpenSearch client, which is the
only thing replaced. The worker's directory is laid out as the containers lay
it out, with list files, host_files.json, the Public Suffix List and an index
built from them as the librarian builds it, and config.yaml is the shipped
example with only what a test cannot have changed: no reverse DNS, and the
index rather than Valkey.

The fixtures' shapes come from what the code reads and from the beats
themselves: Packetbeat 8's DNS output, which trims the trailing dot from
names and reports a query reaching the server as ingress, and Browserbeat,
whose url_data is Go's net/url.URL as libbeat 7.4 serialises it.

So what this catches is the pieces disagreeing: a field the sieve reads that
the processor does not, a setting the example ships that breaks the wiring,
or privacy trimming that a later step undoes. No test touches the network.
"""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'src'))

import yaml

from libtb import opensearch, psl
from libtb import processor as P
from libtb.index.builder import build, collect_entries, load_sources, source_table
from libtb.processor import Processor
from libtb.sieve import Filters
from libtb.util import read_config

FIXTURES = os.path.join(HERE, 'fixtures')

# Cleaned list files, as the librarian leaves them after a download: an adblock
# ||domain^ rule becomes *.domain. The names are real entries in
# host_files.example.json, so each is weighed with its real trust and publisher.
LISTS = {
    'gambling/hagezi-gambling': ['*.casino-example.co.uk', 'bet-example.com'],
    'gambling/PheeLeep-barikada': ['*.casino-example.co.uk'],
    'tracking/Easyprivacy': ['*.collect.tracker-example.net'],
    'tracking/notrack-blocklist': ['casino-example.collect.tracker-example.net'],
}


def fixture(name):
    with open(os.path.join(FIXTURES, name)) as fh:
        return json.load(fh)


class EndToEndTest(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-worker-')
        self.addCleanup(shutil.rmtree, self.root, True)
        cwd = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, cwd)
        for state in (P._index_handles, P._opensearch_clients, P._bulk_buffers,
                      opensearch._warned):
            state.clear()
            self.addCleanup(state.clear)
        psl.forget()
        self.addCleanup(psl.forget)
        self.addCleanup(self.close_indexes)

        self.lay_out_lists()
        self.config = self.read_config()
        self.filters = Filters(self.config['sieve'])
        with redirect_stderr(io.StringIO()) as err:
            self.processor = Processor(self.config['processor'], self.config['redis'])
        self.startup = err.getvalue()
        # The OpenSearch client, the one thing replaced; it keeps what it is sent
        self.client = mock.Mock()
        patcher = mock.patch.object(P, 'opensearch_client', return_value=self.client)
        patcher.start()
        self.addCleanup(patcher.stop)

    def close_indexes(self):
        for index in P._index_handles.values():
            index.close()

    def lay_out_lists(self):
        """lists/ as the librarian leaves it: lists, sources, PSL and the built index."""
        for name, lines in LISTS.items():
            os.makedirs(os.path.join('lists', os.path.dirname(name)), exist_ok=True)
            with open(os.path.join('lists', name), 'w') as fh:
                fh.write('\n'.join(lines) + '\n')
        shutil.copy(os.path.join(ROOT, 'vols', 'lists', 'host_files.example.json'),
                    os.path.join('lists', 'host_files.json'))
        os.makedirs(os.path.join('lists', 'tld'))
        shutil.copy(os.path.join(HERE, 'fixture_public_suffix_list.dat'),
                    os.path.join('lists', 'tld', 'public_suffix_list.dat'))
        entries, files, skipped = collect_entries('lists')
        self.assertEqual((files, skipped), (len(LISTS), 0))
        os.makedirs(os.path.join('lists', 'index'))
        build(entries, path='lists/index/domains.tbidx', built_at=1791100000,
              sources=source_table(load_sources('lists')))

    def read_config(self):
        """The shipped example, with only what a test cannot have changed."""
        with open(os.path.join(ROOT, 'src', 'support', 'config.example.yaml')) as fh:
            config = yaml.safe_load(fh)
        with open('valkey_password', 'w') as fh:
            fh.write('not-used\n')
        config['redis']['password_file'] = os.path.abspath('valkey_password')
        # The reverse lookup would query a resolver, and Valkey mode would
        # query Valkey; everything else is as shipped
        config['processor']['dns']['lookup_ips'] = False
        config['processor']['domain_index']['mode'] = 'index'
        config['processor']['elastic']['hosts'][0]['password'] = 'Not-the-default.1'
        with open('config.yaml', 'w') as fh:
            yaml.safe_dump(config, fh)
        return read_config('config.yaml')

    def ship(self, name):
        """Runs one recorded event through the sieve and the processor."""
        packet = fixture(name)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            self.assertTrue(self.filters.should_process(packet))
            self.processor.process_packet(packet)
        self.assertEqual(err.getvalue(), '')
        self.client.index.assert_called_once()
        call = self.client.index.call_args.kwargs
        self.assertRegex(call['index'], r'^tb-index-\d{4}-\d{2}-\d{2}$')
        return call['body']

    def test_the_shipped_example_starts_as_documented(self):
        # Unverified https is reported once at start, and nothing else is said
        self.assertIn('WARNING: OpenSearch at https://opensearch:9200 is used without '
                      'verifying', self.startup)
        self.assertEqual(self.startup.count('WARNING'), 1)

    def test_a_dns_lookup(self):
        doc = self.ship('packetbeat_dns.json')
        bite = doc['bite']
        self.assertEqual(doc['@timestamp'], '2026-10-04T15:58:40.912Z')
        self.assertEqual(bite['type'], 'dns')
        self.assertEqual(bite['request'], 'query')
        self.assertEqual(bite['requested'], ['metrics.casino-example.co.uk'])
        # The client, and no reverse lookup since lookups are off
        self.assertEqual(bite['client'], '10.100.45.140')
        self.assertEqual((bite['ptr_status'], bite['client_hosts']), ('skipped', []))
        # Two independent medium lists agree on gambling for the name itself,
        # and two more on the tracker its CNAME points at
        self.assertEqual(bite['contexts'], ['gambling', 'tracking'])
        self.assertEqual(bite['match_source'], ['question', 'cname'])
        self.assertEqual(bite['claims'], ['gambling:PheeLeep-barikada', 'gambling:hagezi-gambling'])
        self.assertEqual(bite['matched_on'], ['*.casino-example.co.uk'])
        self.assertEqual(bite['cname_chain'], ['casino-example.collect.tracker-example.net'])
        self.assertEqual(bite['cname_contexts'], ['tracking'])
        self.assertEqual(bite['cname_matched_on'], ['casino-example.collect.tracker-example.net',
                                                    '*.collect.tracker-example.net'])
        self.assertEqual(bite['sources'], ['Easyprivacy', 'PheeLeep-barikada', 'hagezi-gambling',
                                           'notrack-blocklist'])
        self.assertEqual(bite['index_built_at'], 1791100000)
        # The facets, from the taxonomy
        self.assertEqual(bite['purpose'], ['adult.gambling'])
        self.assertEqual(bite['risk'], ['privacy.tracking'])
        self.assertNotIn('service', bite)
        # The owner, from the Public Suffix List rather than the last two labels
        self.assertEqual(bite['registrable_domain'], 'casino-example.co.uk')
        self.assertNotIn('psl_fallback', bite)
        self.assertEqual(bite['resolved_ips'], ['203.0.113.24'])
        self.assertEqual(bite['response_code'], 'NOERROR')
        for private in ('_corrected', 'contexts_candidate', 'contexts_suppressed', 'incidental'):
            self.assertNotIn(private, bite)
        # A lookup carries no URL, so the packet is kept exactly as it came
        self.assertEqual(doc['packet'], fixture('packetbeat_dns.json'))

    def test_a_browser_visit(self):
        doc = self.ship('browserbeat_history.json')
        bite = doc['bite']
        self.assertEqual(bite['type'], 'browser.history')
        self.assertEqual(bite['request'], 'https')
        self.assertEqual(bite['requested'], ['www.casino-example.co.uk'])
        # Chrome records UTC, so the event's time is the visit's, unchanged.
        # event_time_local is not checked: it comes out in the worker's own
        # time zone rather than the client's, so it differs between machines.
        self.assertEqual(doc['@timestamp'], '2026-10-04T15:58:41Z')
        self.assertEqual(bite['event_time_utc'], '2026-10-04T15:58:41Z')
        # Who: the identity Browserbeat reports, folded, with only the
        # addresses that can identify a machine
        self.assertEqual(bite['client_hostname'], 'lib-1-01-23-a')
        self.assertEqual(bite['client_hostname_short'], 'lib-1-01-23-a')
        self.assertEqual(bite['client_user'], 'vertor')
        self.assertEqual((bite['client_platform'], bite['client_browser']), ('windows', 'chrome'))
        self.assertEqual(bite['client_ips'], ['10.100.45.140'])
        # What: the visit is categorised by its host
        self.assertEqual(bite['contexts'], ['gambling'])
        self.assertEqual(bite['claims'], ['gambling:PheeLeep-barikada', 'gambling:hagezi-gambling'])
        self.assertEqual(bite['purpose'], ['adult.gambling'])
        self.assertEqual(bite['registrable_domain'], 'casino-example.co.uk')
        self.assertNotIn('resolvers', bite)

    def test_a_browser_visit_keeps_no_query_fragment_or_password(self):
        doc = self.ship('browserbeat_history.json')
        self.assertEqual(doc['bite']['url'], 'https://www.casino-example.co.uk/slots/play')
        entry = doc['packet']['data']['event']['data']['entry']
        self.assertEqual(entry['url'], 'https://www.casino-example.co.uk/slots/play')
        self.assertEqual(entry['url_data'], {
            'Scheme': 'https', 'Opaque': '', 'User': None, 'Host': 'www.casino-example.co.uk',
            'Path': '/slots/play', 'RawPath': '', 'ForceQuery': False, 'RawQuery': '',
            'Fragment': ''})
        self.assertEqual(entry['title'], 'Play slots - Casino Example')
        text = json.dumps(doc)
        for secret in ('8f3a2c91d4', 'hunter2', 'vertor%40example.edu', 'deposit'):
            self.assertNotIn(secret, text)

    def test_with_full_urls_the_visit_is_stored_as_recorded(self):
        # The control for the trimming above, through the same path
        self.config['processor']['privacy'] = {'urls': 'full', 'packet': 'keep'}
        with redirect_stderr(io.StringIO()):
            self.processor = Processor(self.config['processor'], self.config['redis'])
        doc = self.ship('browserbeat_history.json')
        self.assertEqual(doc['bite']['url'], fixture('browserbeat_history.json')
                         ['data']['event']['data']['entry']['url'])
        self.assertIn('8f3a2c91d4', json.dumps(doc))


if __name__ == '__main__':
    unittest.main(verbosity=2)
