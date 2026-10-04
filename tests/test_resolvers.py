"""Tests for public filtering resolvers as a second opinion.

Two things must never happen. A resolver must not assert a category on its own,
including two resolvers agreeing with each other with no list behind them: they
are there to corroborate the lists, not to replace them. And a resolver must
not slow or fail an event: a timeout, a SERVFAIL or a firewall dropping the
query has to land in a status, and must not be remembered, or one bad minute
would pin the answer for the cache's whole TTL.

No test touches the network. The resolver is replaced by a function returning
the answers measured from the real ones.
"""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))

import dns.exception

from libtb.audit import audit
from libtb.evidence import resolve
from libtb.evidence import resolvers as R
from libtb.index import DomainIndex, Source
from libtb.index.builder import apply_ignorelist, build, local_source
from libtb.processor import Processor

FIXTURE = os.path.join(HERE, 'fixture_public_suffix_list.dat')

# What each resolver was measured to answer, see the module docstring
RESOLVES = R.Answer('NOERROR', frozenset(), False, ('192.0.2.1',), True, False)
NO_SUCH_NAME = R.Answer('NXDOMAIN', frozenset(), False, (), True, True)
QUAD9_BLOCK = R.Answer('NXDOMAIN', frozenset({17}), False, (), False, False)
QUAD9_BLOCK_NO_EDE = R.Answer('NXDOMAIN', frozenset(), False, (), False, False)
CLOUDFLARE_SECURITY_BLOCK = R.Answer('NOERROR', frozenset({16}), True, ('0.0.0.0',), True, False)
CLOUDFLARE_ADULT_BLOCK = R.Answer('NOERROR', frozenset({17}), True, ('0.0.0.0',), True, False)
ZERO_NO_EDE = R.Answer('NOERROR', frozenset(), True, ('0.0.0.0',), True, False)
SERVFAIL = R.Answer('SERVFAIL', frozenset({22}), False, (), True, False)

ADDRESS = {address: role for role, address in R.DEFAULT_ADDRESSES.items()}


class Fake(object):
    """A resolver per role: answers[role] is an Answer, or an exception to raise."""

    def __init__(self, **answers):
        self.answers = answers
        self.asked = []

    def __call__(self, address, host, timeout):
        role = ADDRESS[address]
        self.asked.append((role, host))
        answer = self.answers.get(role, RESOLVES)
        if isinstance(answer, Exception):
            raise answer
        return answer


class Clock(object):

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def checker(fake, **conf):
    clock = Clock()
    settings = R.settings(dict({'enable': True}, **conf))
    return R.Checker(settings, query=fake, clock=clock), clock


class StatusTest(unittest.TestCase):
    """What each answer means."""

    def status(self, provider, **answers):
        fake = Fake(**answers)
        return checker(fake)[0].status(provider, 'host.example'), fake.asked

    def test_quad9_blocks_with_nxdomain_and_ede(self):
        status, asked = self.status(R.QUAD9, quad9=QUAD9_BLOCK)
        self.assertEqual(status, 'blocked')
        self.assertEqual(asked, [('quad9', 'host.example')])

    def test_quad9_resolving_is_clear(self):
        self.assertEqual(self.status(R.QUAD9, quad9=RESOLVES)[0], 'clear')

    def test_a_name_that_does_not_exist_is_not_a_block(self):
        # The control for the block above: NXDOMAIN alone proves nothing
        status, asked = self.status(R.QUAD9, quad9=NO_SUCH_NAME)
        self.assertEqual(status, 'nxdomain')
        self.assertEqual(len(asked), 1)

    def test_a_block_without_ede_is_settled_by_the_unfiltered_resolver(self):
        status, asked = self.status(R.QUAD9, quad9=QUAD9_BLOCK_NO_EDE, quad9_unfiltered=RESOLVES)
        self.assertEqual(status, 'blocked')
        self.assertEqual([role for role, _ in asked], ['quad9', 'quad9_unfiltered'])

    def test_nxdomain_on_both_is_not_a_block(self):
        status, _ = self.status(R.QUAD9, quad9=QUAD9_BLOCK_NO_EDE, quad9_unfiltered=NO_SUCH_NAME)
        self.assertEqual(status, 'nxdomain')

    def test_cloudflare_blocks_with_zero_and_ede(self):
        status, _ = self.status(R.CLOUDFLARE_SECURITY, cloudflare_security=CLOUDFLARE_SECURITY_BLOCK)
        self.assertEqual(status, 'blocked')

    def test_a_published_zero_address_is_not_a_block(self):
        status, asked = self.status(R.CLOUDFLARE_SECURITY, cloudflare_security=ZERO_NO_EDE,
                                    cloudflare_unfiltered=ZERO_NO_EDE)
        self.assertEqual(status, 'clear')
        self.assertEqual([role for role, _ in asked],
                         ['cloudflare_security', 'cloudflare_unfiltered'])

    def test_cloudflare_nxdomain_is_settled(self):
        self.assertEqual(self.status(R.CLOUDFLARE_SECURITY, cloudflare_security=NO_SUCH_NAME)[0],
                         'nxdomain')

    def test_the_family_resolver_reports_adult_content_by_its_ede(self):
        status, asked = self.status(R.CLOUDFLARE_FAMILY, cloudflare_family=CLOUDFLARE_ADULT_BLOCK)
        self.assertEqual(status, 'blocked')
        self.assertEqual(len(asked), 1)

    def test_a_family_block_1112_shares_is_security_not_adult(self):
        status, _ = self.status(R.CLOUDFLARE_FAMILY, cloudflare_family=CLOUDFLARE_SECURITY_BLOCK)
        self.assertEqual(status, 'security')

    def test_without_ede_the_family_block_is_compared_with_1112(self):
        shared, _ = self.status(R.CLOUDFLARE_FAMILY, cloudflare_family=ZERO_NO_EDE,
                                cloudflare_security=CLOUDFLARE_SECURITY_BLOCK)
        self.assertEqual(shared, 'security')
        adult, _ = self.status(R.CLOUDFLARE_FAMILY, cloudflare_family=ZERO_NO_EDE,
                               cloudflare_security=RESOLVES)
        self.assertEqual(adult, 'blocked')

    def test_a_timeout_is_reported_not_raised(self):
        self.assertEqual(self.status(R.QUAD9, quad9=dns.exception.Timeout())[0], 'timeout')

    def test_servfail_is_reported(self):
        self.assertEqual(self.status(R.QUAD9, quad9=SERVFAIL)[0], 'servfail')
        self.assertEqual(self.status(R.CLOUDFLARE_FAMILY, cloudflare_family=SERVFAIL)[0], 'servfail')

    def test_a_firewalled_resolver_is_reported_not_raised(self):
        status, _ = self.status(R.CLOUDFLARE_SECURITY,
                                cloudflare_security=OSError('Network is unreachable'))
        self.assertEqual(status, 'error')

    def test_anything_else_is_reported_not_raised(self):
        self.assertEqual(self.status(R.QUAD9, quad9=RuntimeError('odd'))[0], 'error')

    def test_a_failure_in_the_fallback_is_reported_too(self):
        status, _ = self.status(R.QUAD9, quad9=QUAD9_BLOCK_NO_EDE,
                                quad9_unfiltered=dns.exception.Timeout())
        self.assertEqual(status, 'timeout')


class CacheTest(unittest.TestCase):

    def test_a_settled_answer_is_remembered(self):
        for answer, expected in ((QUAD9_BLOCK, 'blocked'), (RESOLVES, 'clear'),
                                 (NO_SUCH_NAME, 'nxdomain')):
            fake = Fake(quad9=answer)
            chk, _ = checker(fake)
            self.assertEqual(chk.status(R.QUAD9, 'a.example'), expected)
            self.assertEqual(chk.status(R.QUAD9, 'a.example'), expected)
            self.assertEqual(len(fake.asked), 1, expected)

    def test_a_transient_failure_is_asked_again(self):
        for failure in (dns.exception.Timeout(), SERVFAIL, OSError('unreachable')):
            fake = Fake(quad9=failure)
            chk, _ = checker(fake)
            chk.status(R.QUAD9, 'a.example')
            chk.status(R.QUAD9, 'a.example')
            self.assertEqual(len(fake.asked), 2, failure)

    def test_remembering_failures_would_pin_them(self):
        # Proves the guard is load-bearing: let a timeout be remembered and the
        # second call never asks, so a recovery would go unseen for the TTL
        fake = Fake(quad9=dns.exception.Timeout())
        chk, _ = checker(fake)
        with mock.patch.object(R, 'SETTLED', R.SETTLED | {'timeout'}):
            chk.status(R.QUAD9, 'a.example')
            chk.status(R.QUAD9, 'a.example')
        self.assertEqual(len(fake.asked), 1)

    def test_an_answer_expires(self):
        fake = Fake(quad9=QUAD9_BLOCK)
        chk, clock = checker(fake, cache={'ttl_sec': 60})
        chk.status(R.QUAD9, 'a.example')
        clock.now += 61
        chk.status(R.QUAD9, 'a.example')
        self.assertEqual(len(fake.asked), 2)

    def test_the_cache_is_bounded_and_drops_the_oldest(self):
        fake = Fake(quad9=RESOLVES)
        chk, _ = checker(fake, cache={'max_entries': 2})
        for host in ('a.example', 'b.example', 'c.example'):
            chk.status(R.QUAD9, host)
        self.assertEqual(len(chk.cache), 2)
        self.assertNotIn((R.QUAD9, 'a.example'), chk.cache)

    def test_providers_are_remembered_separately(self):
        fake = Fake(quad9=QUAD9_BLOCK, cloudflare_security=RESOLVES)
        chk, _ = checker(fake)
        self.assertEqual(chk.status(R.QUAD9, 'a.example'), 'blocked')
        self.assertEqual(chk.status(R.CLOUDFLARE_SECURITY, 'a.example'), 'clear')

    def test_the_audit_is_throttled(self):
        fake = Fake()
        chk = R.Checker(R.settings({'enable': True}), query=fake, rate=20)
        with mock.patch.object(R.time, 'sleep') as sleep:
            for host in ('a.example', 'b.example', 'c.example'):
                chk.status(R.QUAD9, host)
        self.assertTrue(sleep.called)
        self.assertTrue(all(0 < call.args[0] <= 0.05 for call in sleep.call_args_list))


def source(name, trust='medium', publisher=None):
    return Source(name, publisher or name, trust, False, ())


ARMY = source('phishing_army')
PORN_LIST = source('hagezi-nsfw')
VENDOR = source('vendor', 'high')
NOISY = source('leftover', 'low')


def claims(host, *pairs):
    return [(host, src, category) for src, category in pairs]


class CorroborateTest(unittest.TestCase):
    """When the resolvers are asked, and what their votes do."""

    def run_it(self, host_claims, fake, min_publishers=2):
        chk, _ = checker(fake)
        verdict = resolve(host_claims, min_publishers)
        return R.corroborate('h.example', host_claims, verdict, min_publishers, chk)

    def test_a_vote_corroborates_a_medium_list(self):
        fake = Fake(quad9=QUAD9_BLOCK)
        found, verdict, statuses = self.run_it(
            claims('h.example', (ARMY, 'malicious'), (ARMY, 'phishing')), fake)
        self.assertEqual(verdict['asserted'], ['malicious'])
        # The resolver says the host is bad, not what kind of bad
        self.assertEqual(verdict['candidate'], ['phishing'])
        self.assertEqual(statuses, {'quad9': 'blocked', 'cloudflare-security': 'clear'})
        self.assertIn(('h.example', R.SOURCES['quad9'], 'malicious'), found)

    def test_clear_resolvers_change_nothing(self):
        found, verdict, statuses = self.run_it(claims('h.example', (ARMY, 'malicious')), Fake())
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(verdict['candidate'], ['malicious'])
        self.assertEqual(statuses, {'quad9': 'clear', 'cloudflare-security': 'clear'})

    def test_one_vote_alone_asserts_nothing(self):
        # What the guard below protects: a resolver is a medium source
        verdict = resolve(claims('h.example', (R.SOURCES['quad9'], 'malicious')))
        self.assertEqual(verdict['asserted'], [])

    def test_not_asked_without_a_candidate(self):
        fake = Fake(quad9=QUAD9_BLOCK)
        self.assertEqual(self.run_it([], fake)[2], {})
        self.assertEqual(fake.asked, [])

    def test_not_asked_when_the_list_already_settled_it(self):
        fake = Fake(quad9=QUAD9_BLOCK)
        _, verdict, statuses = self.run_it(claims('h.example', (VENDOR, 'malicious')), fake)
        self.assertEqual(verdict['asserted'], ['malicious'])
        self.assertEqual((statuses, fake.asked), ({}, []))

    def test_not_asked_for_a_low_trust_list(self):
        # Both resolvers would otherwise agree with each other and assert with
        # no list that counts behind them
        fake = Fake(quad9=QUAD9_BLOCK, cloudflare_security=CLOUDFLARE_SECURITY_BLOCK)
        _, verdict, statuses = self.run_it(claims('h.example', (NOISY, 'malicious')), fake)
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(fake.asked, [])

    def test_without_that_guard_two_resolvers_would_assert_alone(self):
        # Proves it is load-bearing
        fake = Fake(quad9=QUAD9_BLOCK, cloudflare_security=CLOUDFLARE_SECURITY_BLOCK)
        with mock.patch.object(R, 'qualifies', lambda provider, found, verdict: True):
            _, verdict, _ = self.run_it(claims('h.example', (NOISY, 'malicious')), fake)
        self.assertIn('malicious', verdict['asserted'])

    def test_not_asked_when_the_list_names_a_path_the_vote_does_not(self):
        # A vote for `malicious` cannot corroborate `malware`, and with no list
        # on threat.malicious the two resolvers would be the whole evidence
        fake = Fake(quad9=QUAD9_BLOCK, cloudflare_security=CLOUDFLARE_SECURITY_BLOCK)
        _, verdict, statuses = self.run_it(claims('h.example', (ARMY, 'malware')), fake)
        self.assertEqual((verdict['asserted'], statuses), ([], {}))

    def test_a_porn_candidate_asks_only_the_family_resolver(self):
        fake = Fake(cloudflare_family=CLOUDFLARE_ADULT_BLOCK)
        _, verdict, statuses = self.run_it(claims('h.example', (PORN_LIST, 'porn')), fake)
        self.assertEqual(verdict['asserted'], ['porn'])
        self.assertEqual(statuses, {'cloudflare-family': 'blocked'})

    def test_a_security_block_on_1113_is_not_a_porn_vote(self):
        fake = Fake(cloudflare_family=CLOUDFLARE_SECURITY_BLOCK)
        _, verdict, statuses = self.run_it(claims('h.example', (PORN_LIST, 'porn')), fake)
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(statuses, {'cloudflare-family': 'security'})

    def test_both_cloudflare_resolvers_are_one_publisher(self):
        # A threat and a porn candidate, both Cloudflare resolvers blocking:
        # they must not corroborate each other on anything
        votes = claims('h.example', (R.SOURCES['cloudflare-security'], 'malicious'),
                       (R.SOURCES['cloudflare-family'], 'malicious'))
        self.assertEqual(resolve(votes)['asserted'], [])

    def test_quad9_and_cloudflare_need_the_bar_like_any_source(self):
        fake = Fake(quad9=QUAD9_BLOCK, cloudflare_security=CLOUDFLARE_SECURITY_BLOCK)
        _, verdict, _ = self.run_it(claims('h.example', (ARMY, 'malicious')), fake,
                                    min_publishers=3)
        self.assertEqual(verdict['asserted'], ['malicious'])
        fake = Fake(quad9=QUAD9_BLOCK)
        _, verdict, _ = self.run_it(claims('h.example', (ARMY, 'malicious')), fake,
                                    min_publishers=3)
        self.assertEqual(verdict['asserted'], [])

    def test_porn_is_not_asked_about_on_an_incidental_host(self):
        fake = Fake(cloudflare_family=CLOUDFLARE_ADULT_BLOCK)
        found = claims('h.example', (PORN_LIST, 'porn'), (local_source('turkeybite'), 'incidental'))
        self.assertEqual(self.run_it(found, fake)[2], {})


class SettingsTest(unittest.TestCase):

    def test_off_by_default(self):
        self.assertFalse(R.settings(None).enable)
        self.assertIsNone(R.checker_for(R.settings(None)))

    def test_defaults(self):
        conf = R.settings({'enable': True})
        self.assertEqual(conf.addresses, R.DEFAULT_ADDRESSES)
        self.assertEqual((conf.timeout, conf.ttl, conf.max_entries),
                         (R.DEFAULT_TIMEOUT, R.DEFAULT_TTL, R.DEFAULT_MAX_ENTRIES))

    def test_addresses_can_be_overridden(self):
        conf = R.settings({'enable': True, 'addresses': {'quad9': '149.112.112.112'}})
        self.assertEqual(conf.addresses['quad9'], '149.112.112.112')
        self.assertEqual(conf.addresses['cloudflare_security'], '1.1.1.2')

    def test_mistakes_are_refused(self):
        for bad in ({'enabled': True}, {'enable': 'yes'}, {'timeout_sec': 0},
                    {'timeout_sec': 30}, {'timeout_sec': 'fast'},
                    {'cache': {'ttl': 60}}, {'cache': {'max_entries': 1.5}},
                    {'addresses': {'quad9': 'dns.quad9.net'}},
                    {'addresses': {'google': '8.8.8.8'}}, ['enable']):
            with self.assertRaises(ValueError, msg=bad):
                R.settings(bad)


class ProcessorTest(unittest.TestCase):
    """What lands on the event."""

    SOURCES = {'phishing_army': ARMY, 'hagezi-nsfw': PORN_LIST}

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-resolvers-')
        self.path = os.path.join(self.root, 'domains.tbidx')
        entries = {'bad.example.com': {'phishing_army': {'malicious', 'phishing'}},
                   'fixed.example.com': {'phishing_army': {'malicious'}},
                   'adult.example.com': {'hagezi-nsfw': {'porn'}}}
        apply_ignorelist(entries, ignorelist={'malicious': ['fixed.example.com']})
        build(entries, path=self.path, built_at=1000, sources=self.SOURCES)
        R._checkers.clear()
        self.addCleanup(R._checkers.clear)
        self.addCleanup(shutil.rmtree, self.root, True)

    def bite(self, name, evidence=None, mode='index', fake=None):
        config = {'dns': {'lookup_ips': False},
                  'domain_index': {'mode': mode, 'path': self.path}}
        if evidence is not None:
            config['evidence'] = evidence
        processor = Processor(config, {})
        shipped = []
        processor.ship_bite = shipped.append
        processor.valkey_contexts = lambda searches: ['legacy']
        fake = fake or Fake(quad9=QUAD9_BLOCK)
        with mock.patch.object(R, 'query', fake):
            processor.process_dns_packet({
                'type': 'dns', 'resource': name, 'dns': {'question': {'name': name}},
                'network': {'direction': 'ingress'}, 'client': {'ip': '10.0.0.5'},
                '@timestamp': '2026-10-04T12:00:00Z'})
        return shipped[0]['bite'], fake

    ON = {'resolvers': {'enable': True}}

    def test_nothing_is_asked_by_default(self):
        bite, fake = self.bite('bad.example.com')
        self.assertEqual(fake.asked, [])
        self.assertNotIn('resolvers', bite)
        self.assertEqual(bite['contexts'], [])

    def test_a_vote_reaches_the_event(self):
        bite, fake = self.bite('bad.example.com', evidence=self.ON)
        self.assertEqual(bite['contexts'], ['malicious'])
        self.assertEqual(bite['contexts_candidate'], ['phishing'])
        self.assertIn('malicious:quad9', bite['claims'])
        self.assertIn('quad9', bite['sources'])
        self.assertEqual(bite['resolvers'], {'quad9': 'blocked', 'cloudflare-security': 'clear'})
        self.assertEqual(bite['risk'], ['threat.malicious'])

    def test_a_page_opened_in_a_browser_is_not_sent(self):
        config = {'domain_index': {'mode': 'index', 'path': self.path}, 'evidence': self.ON}
        processor = Processor(config, {})
        shipped = []
        processor.ship_bite = shipped.append
        fake = Fake(quad9=QUAD9_BLOCK)
        with mock.patch.object(R, 'query', fake):
            processor.process_browser_history({
                'type': 'browser.history',
                'data': {'@timestamp': '2026-10-04T12:00:00Z',
                         'event': {'data': {'entry': {
                             'url': 'https://bad.example.com/x',
                             'url_data': {'Scheme': 'https', 'Host': 'bad.example.com'}}}}}})
        self.assertEqual(fake.asked, [])
        self.assertNotIn('resolvers', shipped[0]['bite'])
        self.assertEqual(shipped[0]['bite']['contexts_candidate'], ['malicious', 'phishing'])

    def test_a_corrected_host_is_not_sent_and_the_correction_stays_private(self):
        bite, fake = self.bite('fixed.example.com', evidence=self.ON)
        self.assertEqual(fake.asked, [])
        self.assertEqual(bite['contexts_suppressed'], ['malicious'])
        self.assertNotIn('_corrected', bite)
        bite, _ = self.bite('bad.example.com', evidence=self.ON)
        self.assertNotIn('_corrected', bite)

    def test_only_the_name_is_sent(self):
        _, fake = self.bite('bad.example.com', evidence=self.ON)
        self.assertEqual({host for _, host in fake.asked}, {'bad.example.com'})

    def test_a_failure_is_recorded_and_costs_nothing(self):
        fake = Fake(quad9=dns.exception.Timeout(), cloudflare_security=OSError('unreachable'))
        bite, _ = self.bite('bad.example.com', evidence=self.ON, fake=fake)
        self.assertEqual(bite['resolvers'], {'quad9': 'timeout', 'cloudflare-security': 'error'})
        self.assertEqual(bite['contexts'], [])

    def test_no_candidate_no_question(self):
        bite, fake = self.bite('www.unlisted.example', evidence=self.ON)
        self.assertEqual(fake.asked, [])
        self.assertNotIn('resolvers', bite)

    def test_compare_mode_does_not_ask(self):
        bite, fake = self.bite('bad.example.com', evidence=self.ON, mode='compare')
        self.assertEqual(fake.asked, [])
        self.assertNotIn('resolvers', bite)

    def test_a_bad_setting_stops_the_processor_at_start(self):
        with self.assertRaises(ValueError):
            Processor({'evidence': {'resolvers': {'enable': True, 'timeout': 1}}}, {})

    def test_the_audit_asks_through_the_same_path(self):
        index = DomainIndex(self.path)
        self.addCleanup(index.close)
        chk, _ = checker(Fake(quad9=QUAD9_BLOCK))
        report = audit(index, ['bad.example.com'], psl_path=FIXTURE, checker=chk)
        self.assertEqual([d for _, d, _ in report['asserted']['malicious']], ['bad.example.com'])
        self.assertIn('quad9', report['asserted']['malicious'][0][2])
        # The control: no checker, no vote
        report = audit(index, ['bad.example.com'], psl_path=FIXTURE)
        self.assertNotIn('malicious', report['asserted'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
