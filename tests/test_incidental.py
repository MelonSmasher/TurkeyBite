"""Tests for hosts marked incidental.

A lookup of connect.facebook.net usually means a page with a Facebook pixel was
open, not that anyone used Facebook, and a lookup of msftconnecttest.com means
Windows joined a network. The curated `incidental` list marks such hosts, and on
them only risk categories are asserted.

The risks run both ways. The mark must not erase a risk: the pixel tracks the
person whether or not they use Facebook. And it must not be undone by the back
door, which here is the CNAME chain: connect.facebook.net is hosted on
scontent.xx.fbcdn.net, which every Facebook list names.
"""

import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'src'))

from libtb.evidence import resolve
from libtb.index import INCIDENTAL, DomainIndex, Source
from libtb.index.builder import apply_ignorelist, build, local_source
from libtb.processor import Processor
from libtb.util import VALID_HOST

LISTS = os.path.join(ROOT, 'vols', 'lists')


def source(name, trust='high', publisher=None):
    return Source(name, publisher or name, trust, False, ())


LOCAL = local_source('turkeybite')
FACEBOOK = source('gieljnssns-facebook')
EASYPRIVACY = source('easyprivacy')


def claims(*pairs):
    return [('connect.facebook.net', src, category) for src, category in pairs]


class ResolveTest(unittest.TestCase):

    def test_purpose_and_service_become_candidates(self):
        verdict = resolve(claims((FACEBOOK, 'facebook'), (FACEBOOK, 'social'),
                                 (LOCAL, INCIDENTAL)))
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(verdict['candidate'], ['facebook', 'social'])
        self.assertTrue(verdict['incidental'])

    def test_the_same_claims_unmarked_are_asserted(self):
        # The control for the one above
        verdict = resolve(claims((FACEBOOK, 'facebook'), (FACEBOOK, 'social')))
        self.assertEqual(verdict['asserted'], ['facebook', 'social'])
        self.assertFalse(verdict['incidental'])

    def test_a_risk_stays(self):
        verdict = resolve(claims((FACEBOOK, 'facebook'), (EASYPRIVACY, 'tracking'),
                                 (source('vendor'), 'malware'), (LOCAL, INCIDENTAL)))
        self.assertEqual(verdict['asserted'], ['malware', 'tracking'])
        self.assertEqual(verdict['candidate'], ['facebook'])

    def test_a_vendor_that_also_names_a_service_is_demoted(self):
        # expressvpn is an anonymiser and a service. Kept, it would put the
        # service on the event through bite.service, which the mark exists to stop
        verdict = resolve(claims((source('vendor'), 'expressvpn'), (LOCAL, INCIDENTAL)))
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(verdict['candidate'], ['expressvpn'])

    def test_a_pure_risk_from_the_same_vendor_list_stays(self):
        verdict = resolve(claims((source('vendor'), 'expressvpn'), (source('vendor'), 'vpn'),
                                 (LOCAL, INCIDENTAL)))
        self.assertEqual(verdict['asserted'], ['vpn'])

    def test_a_navigation_is_never_demoted(self):
        verdict = resolve(claims((FACEBOOK, 'facebook'), (LOCAL, INCIDENTAL)),
                          navigation=True)
        self.assertEqual(verdict['asserted'], ['facebook'])
        self.assertFalse(verdict['incidental'])

    def test_an_unknown_category_is_demoted(self):
        verdict = resolve(claims((source('vendor'), 'politics'), (LOCAL, INCIDENTAL)))
        self.assertEqual(verdict['candidate'], ['politics'])

    def test_the_mark_is_never_reported_as_a_category(self):
        for extra in ((), ((source('ignorelist'), '!' + INCIDENTAL),)):
            verdict = resolve(claims((FACEBOOK, 'social'), (LOCAL, INCIDENTAL), *extra))
            for field in ('asserted', 'candidate', 'suppressed'):
                self.assertNotIn(INCIDENTAL, verdict[field])

    def test_the_ignorelist_can_lift_the_mark(self):
        verdict = resolve(claims((FACEBOOK, 'social'), (LOCAL, INCIDENTAL),
                                 (source('ignorelist'), '!' + INCIDENTAL)))
        self.assertEqual(verdict['asserted'], ['social'])
        self.assertFalse(verdict['incidental'])

    def test_one_broad_list_cannot_mark_a_host(self):
        # The mark is weighed like any claim, so a downloaded list calling a
        # host incidental would need corroboration before it erased anything
        verdict = resolve(claims((FACEBOOK, 'social'), (source('broad', 'medium'), INCIDENTAL)))
        self.assertEqual(verdict['asserted'], ['social'])
        self.assertFalse(verdict['incidental'])


class EventTest(unittest.TestCase):
    """What lands on the event, over a real index."""

    SOURCES = {
        'turkeybite': LOCAL,
        'gieljnssns-facebook': FACEBOOK,
        'easyprivacy': EASYPRIVACY,
    }

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-incidental-')
        self.path = os.path.join(self.root, 'domains.tbidx')
        entries = {
            'connect.facebook.net': {'gieljnssns-facebook': {'facebook', 'social'},
                                     'easyprivacy': {'tracking'}},
            '*.connect.facebook.net': {'turkeybite': {INCIDENTAL}},
            '*.xx.fbcdn.net': {'gieljnssns-facebook': {'facebook', 'social'}},
            '*.unmarked.example': {'turkeybite': {'news'}},
            '*.shop.example': {'turkeybite': {'shopping'}},
            '*.relabelled.example': {'turkeybite': {'social', INCIDENTAL}},
        }
        apply_ignorelist(entries, ignorelist={INCIDENTAL: ['*.relabelled.example']})
        build(entries, path=self.path, built_at=1000, sources=self.SOURCES)
        self.index = DomainIndex(self.path)

    def tearDown(self):
        self.index.close()
        shutil.rmtree(self.root, ignore_errors=True)

    def processor(self, mode='index'):
        processor = Processor({'dns': {'lookup_ips': False},
                               'domain_index': {'mode': mode, 'path': self.path}}, {})
        shipped = []
        processor.ship_bite = shipped.append
        processor.valkey_contexts = lambda searches: ['legacy']
        return processor, shipped

    def bite(self, name, chain=(), mode='index'):
        processor, shipped = self.processor(mode)
        answers = [{'type': 'CNAME', 'data': target} for target in chain]
        processor.process_dns_packet({
            'type': 'dns', 'resource': name,
            'dns': {'question': {'name': name}, 'answers': answers},
            'network': {'direction': 'ingress'}, 'client': {'ip': '10.0.0.5'},
            '@timestamp': '2026-10-04T12:00:00Z'})
        return shipped[0]['bite']

    def test_the_event_says_the_lookup_was_incidental(self):
        bite = self.bite('connect.facebook.net')
        self.assertTrue(bite['incidental'])
        self.assertEqual(bite['contexts'], ['tracking'])
        self.assertEqual(bite['contexts_candidate'], ['facebook', 'social'])
        self.assertEqual(bite['risk'], ['privacy.tracking'])
        self.assertNotIn('purpose', bite)
        self.assertNotIn('service', bite)

    def test_an_unmarked_event_carries_no_flag(self):
        self.assertNotIn('incidental', self.bite('www.unmarked.example'))

    def test_the_chain_cannot_bring_the_service_back(self):
        bite = self.bite('connect.facebook.net', chain=['scontent.xx.fbcdn.net'])
        self.assertEqual(bite['cname_contexts'], ['facebook', 'social'])
        self.assertEqual(bite['contexts'], ['tracking'])
        self.assertEqual(bite['contexts_candidate'], ['facebook', 'social'])
        self.assertEqual(bite['match_source'], ['question'])
        self.assertNotIn('purpose', bite)

    def test_without_the_guard_the_chain_would_bring_it_back(self):
        # Proves the demotion in the merge is load-bearing: resolve() alone
        # never sees the chain's claims alongside the mark
        keep_all = lambda categories: (list(categories), [])
        with mock.patch('libtb.processor.demote_incidental', keep_all):
            bite = self.bite('connect.facebook.net', chain=['scontent.xx.fbcdn.net'])
        self.assertEqual(bite['contexts'], ['facebook', 'social', 'tracking'])

    def test_the_chain_still_adds_to_an_unmarked_name(self):
        # The control for the one above
        bite = self.bite('www.unmarked.example', chain=['scontent.xx.fbcdn.net'])
        self.assertEqual(bite['contexts'], ['facebook', 'news', 'social'])
        self.assertEqual(bite['match_source'], ['question', 'cname'])

    def test_a_marked_link_in_the_chain_adds_nothing_to_purpose(self):
        # A first-party name aliased to a pixel host is the pixel host
        bite = self.bite('cdn.shop.example', chain=['connect.facebook.net'])
        self.assertEqual(bite['contexts'], ['shopping', 'tracking'])
        self.assertNotIn('facebook', bite['contexts'])

    def test_a_marked_link_leaves_the_name_asked_for_alone(self):
        bite = self.bite('cdn.shop.example', chain=['connect.facebook.net'])
        self.assertNotIn('incidental', bite)
        self.assertIn('shopping', bite['contexts'])

    def test_the_ignorelist_lifts_the_mark_on_the_event(self):
        bite = self.bite('www.relabelled.example')
        self.assertNotIn('incidental', bite)
        self.assertEqual(bite['contexts'], ['social'])

    def test_compare_mode_leaves_valkey_alone(self):
        bite = self.bite('connect.facebook.net', mode='compare')
        self.assertEqual(bite['contexts'], ['legacy'])
        self.assertEqual(bite['contexts_index'], ['tracking'])

    def history_bite(self, host):
        processor, shipped = self.processor()
        processor.process_browser_history({
            'type': 'browser.history',
            'data': {'@timestamp': '2026-10-04T12:00:00Z',
                     'event': {'data': {'entry': {
                         'url': f'https://{host}/',
                         'url_data': {'Scheme': 'https', 'Host': host}}}}}})
        return shipped[0]['bite']

    def test_a_page_someone_opened_is_not_incidental(self):
        # A history entry is a navigation. The mark is about lookups made on
        # someone else's behalf, so it does not apply
        bite = self.history_bite('connect.facebook.net')
        self.assertNotIn('incidental', bite)
        self.assertEqual(bite['contexts'], ['facebook', 'social', 'tracking'])

    def test_the_same_host_looked_up_is_incidental(self):
        # The control: only the kind of event differs
        bite = self.bite('connect.facebook.net')
        self.assertTrue(bite['incidental'])
        self.assertEqual(bite['contexts'], ['tracking'])


class ShippedListTest(unittest.TestCase):
    """The curated list itself."""

    def entries(self):
        with open(os.path.join(LISTS, INCIDENTAL, 'turkeybite')) as fh:
            return [line.strip() for line in fh if line.strip()]

    def test_every_line_is_a_host(self):
        for entry in self.entries():
            self.assertTrue(VALID_HOST.match(entry), entry)

    def test_no_line_is_a_site_another_curated_list_names(self):
        # A main site belongs in a purpose list, and marking it incidental
        # would demote the very lookups that do show someone using it
        named = {}
        for category in os.listdir(LISTS):
            path = os.path.join(LISTS, category, 'turkeybite')
            if category == INCIDENTAL or not os.path.isfile(path):
                continue
            with open(path) as fh:
                for line in fh:
                    named.setdefault(line.strip(), category)
        for entry in self.entries():
            self.assertNotIn(entry, named, f'{entry} is in the {named.get(entry)} list')


class ValkeyLoaderTest(unittest.TestCase):
    """The mark is an index rule. Valkey mode would store it as a category."""

    def test_the_incidental_folder_is_not_loaded_into_valkey(self):
        from libtb import util

        root = tempfile.mkdtemp(prefix='tb-incidental-valkey-')
        self.addCleanup(shutil.rmtree, root, True)
        for category, host in ((INCIDENTAL, 'connect.facebook.net'), ('social', 'facebook.com')):
            os.makedirs(os.path.join(root, 'lists', category))
            with open(os.path.join(root, 'lists', category, 'turkeybite'), 'w') as fh:
                fh.write(host + '\n')

        stored = {}
        redis = mock.Mock()
        redis.get.side_effect = lambda key: None
        redis.set.side_effect = lambda key, value: stored.__setitem__(key, value)
        redis.hgetall.return_value = {}
        config = {'redis': {'host': 'h', 'port': 1, 'password': 'p', 'host_list_db': 1}}

        cwd = os.getcwd()
        os.chdir(root)
        self.addCleanup(os.chdir, cwd)
        with mock.patch.object(util, 'get_host_files', return_value=[]), \
                mock.patch.object(util, 'pull_tld_list', return_value=[]), \
                mock.patch.object(util, 'read_config', return_value=config), \
                mock.patch.object(util, 'index_config', return_value={'mode': 'valkey'}), \
                mock.patch.object(util, 'Redis', return_value=redis), \
                mock.patch.object(util, 'process_ignorelist'), \
                mock.patch.object(util, 'build_domain_index'), \
                contextlib.redirect_stdout(io.StringIO()):
            util.pull_host_lists()

        hosts = {key.rsplit(':', 1)[-1] for key in stored if key.startswith('turkey-bite:1')}
        self.assertIn('facebook.com', hosts)
        self.assertNotIn('connect.facebook.net', hosts)


if __name__ == '__main__':
    unittest.main(verbosity=2)
