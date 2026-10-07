"""Tests for public filtering resolvers as a second opinion.

Three things must never happen. A resolver must not assert a category on its
own, including two resolvers agreeing with each other with no list behind
them: they are there to corroborate the lists, not to replace them. Something
that is not the provider's own security verdict must not count as one: a name
genuinely published as 0.0.0.0, a box on the local network that intercepts
port 53, or a court-ordered block. And a resolver must not slow or fail an
event: a timeout, a SERVFAIL or a firewall dropping the query has to land in a
status, must not be remembered, and must not be paid for over and over.

No test touches the network. The resolver is replaced by a function returning
the answers measured from the real ones.
"""

import importlib.machinery
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'src'))

import dns.exception

from libtb.audit import audit, format_report
from libtb.evidence import categorise, resolve
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
# What these providers were never seen to send, and local blockers do
LOCAL_BLOCKER = R.Answer('NOERROR', frozenset({15}), True, ('0.0.0.0',), True, False)
LOCAL_BLOCKER_NXDOMAIN = R.Answer('NXDOMAIN', frozenset({15}), False, (), True, False)
# A court-ordered block, which the unfiltered resolver applies too
LEGAL_BLOCK = R.Answer('NOERROR', frozenset({16}), True, ('0.0.0.0',), True, False)

ADDRESS = {address: role for role, address in R.DEFAULT_ADDRESSES.items()}


class Clock(object):

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Fake(object):
    """A resolver per role: answers[role] is an Answer, or an exception to raise.

    With a clock, a raised Timeout first spends the whole timeout it was given,
    as a real one does.
    """

    def __init__(self, clock=None, **answers):
        self.answers = answers
        self.clock = clock
        self.asked = []
        self.timeouts = []

    def __call__(self, address, host, timeout):
        role = ADDRESS[address]
        self.asked.append((role, host))
        self.timeouts.append(timeout)
        answer = self.answers.get(role, RESOLVES)
        if isinstance(answer, Exception):
            if self.clock is not None and isinstance(answer, dns.exception.Timeout):
                self.clock.now += timeout
            raise answer
        return answer

    def roles(self):
        return [role for role, _ in self.asked]


def checker(fake, clock=None, rate=None, **conf):
    clock = clock or Clock()
    settings = R.settings(dict({'enable': True}, **conf))
    return R.Checker(settings, ask=fake, rate=rate, clock=clock), clock


class StatusTest(unittest.TestCase):
    """What each answer means."""

    def status(self, provider, **answers):
        fake = Fake(**answers)
        return checker(fake)[0].status(provider, 'host.example'), fake.roles()

    def test_quad9_blocks_with_nxdomain_and_ede_confirmed_unfiltered(self):
        status, asked = self.status(R.QUAD9, quad9=QUAD9_BLOCK)
        self.assertEqual(status, 'blocked')
        self.assertEqual(asked, ['quad9', 'quad9_unfiltered'])

    def test_quad9_resolving_is_clear_in_one_question(self):
        self.assertEqual(self.status(R.QUAD9, quad9=RESOLVES), ('clear', ['quad9']))

    def test_a_name_that_does_not_exist_is_not_a_block(self):
        # The control for the block above: NXDOMAIN alone proves nothing
        self.assertEqual(self.status(R.QUAD9, quad9=NO_SUCH_NAME), ('nxdomain', ['quad9']))

    def test_a_block_without_its_ede_is_not_counted(self):
        # The EDE was on every block measured, so its absence means no block
        self.assertEqual(self.status(R.QUAD9, quad9=QUAD9_BLOCK_NO_EDE), ('nxdomain', ['quad9']))

    def test_a_dead_name_still_gets_its_vote(self):
        status, _ = self.status(R.QUAD9, quad9=QUAD9_BLOCK, quad9_unfiltered=NO_SUCH_NAME)
        self.assertEqual(status, 'blocked')

    def test_a_block_the_unfiltered_resolver_shares_is_not_a_vote(self):
        status, _ = self.status(R.CLOUDFLARE_SECURITY, cloudflare_security=CLOUDFLARE_SECURITY_BLOCK,
                                cloudflare_unfiltered=LEGAL_BLOCK)
        self.assertEqual(status, 'censored')
        status, _ = self.status(R.QUAD9, quad9=QUAD9_BLOCK, quad9_unfiltered=LOCAL_BLOCKER_NXDOMAIN)
        self.assertEqual(status, 'censored')

    def test_cloudflare_blocks_with_zero_and_ede_confirmed_unfiltered(self):
        status, asked = self.status(R.CLOUDFLARE_SECURITY,
                                    cloudflare_security=CLOUDFLARE_SECURITY_BLOCK)
        self.assertEqual(status, 'blocked')
        self.assertEqual(asked, ['cloudflare_security', 'cloudflare_unfiltered'])

    def test_a_published_zero_address_is_not_a_block(self):
        status, asked = self.status(R.CLOUDFLARE_SECURITY, cloudflare_security=ZERO_NO_EDE)
        self.assertEqual((status, asked), ('clear', ['cloudflare_security']))

    def test_a_local_blocker_on_the_path_is_not_a_vote(self):
        # An intercepting Pi-hole or AdGuard answers with EDE 15, which these
        # providers were never seen to use
        self.assertEqual(self.status(R.CLOUDFLARE_SECURITY, cloudflare_security=LOCAL_BLOCKER)[0],
                         'clear')
        self.assertEqual(self.status(R.QUAD9, quad9=LOCAL_BLOCKER_NXDOMAIN)[0], 'nxdomain')
        self.assertEqual(self.status(R.CLOUDFLARE_FAMILY, cloudflare_family=LOCAL_BLOCKER)[0],
                         'clear')

    def test_cloudflare_nxdomain_is_settled(self):
        self.assertEqual(self.status(R.CLOUDFLARE_SECURITY, cloudflare_security=NO_SUCH_NAME)[0],
                         'nxdomain')

    def test_the_family_resolver_reports_adult_content_by_its_ede(self):
        status, asked = self.status(R.CLOUDFLARE_FAMILY, cloudflare_family=CLOUDFLARE_ADULT_BLOCK)
        self.assertEqual(status, 'blocked')
        self.assertEqual(asked, ['cloudflare_family', 'cloudflare_unfiltered'])

    def test_a_family_block_1112_shares_is_security_not_adult(self):
        status, asked = self.status(R.CLOUDFLARE_FAMILY,
                                    cloudflare_family=CLOUDFLARE_SECURITY_BLOCK)
        self.assertEqual((status, asked), ('security', ['cloudflare_family']))

    def test_a_published_zero_address_is_not_adult_either(self):
        # The case that once became a porn vote: 0.0.0.0 everywhere, no EDE
        status, asked = self.status(R.CLOUDFLARE_FAMILY, cloudflare_family=ZERO_NO_EDE,
                                    cloudflare_security=ZERO_NO_EDE,
                                    cloudflare_unfiltered=ZERO_NO_EDE)
        self.assertEqual((status, asked), ('clear', ['cloudflare_family']))

    def test_a_timeout_is_reported_not_raised(self):
        self.assertEqual(self.status(R.QUAD9, quad9=dns.exception.Timeout())[0], 'timeout')

    def test_servfail_is_reported(self):
        self.assertEqual(self.status(R.QUAD9, quad9=SERVFAIL)[0], 'servfail')
        self.assertEqual(self.status(R.CLOUDFLARE_FAMILY, cloudflare_family=SERVFAIL)[0], 'servfail')

    def test_a_firewalled_resolver_is_reported_not_raised(self):
        status, _ = self.status(R.CLOUDFLARE_SECURITY,
                                cloudflare_security=OSError('Network is unreachable'))
        self.assertEqual(status, 'error')

    def test_a_malformed_reply_is_reported_not_raised(self):
        status, _ = self.status(R.QUAD9, quad9=dns.exception.FormError('bad'))
        self.assertEqual(status, 'error')

    def test_a_failure_confirming_a_block_is_reported_too(self):
        status, _ = self.status(R.QUAD9, quad9=QUAD9_BLOCK,
                                quad9_unfiltered=dns.exception.Timeout())
        self.assertEqual(status, 'timeout')

    def test_a_fault_in_this_code_is_not_hidden(self):
        with self.assertRaises(RuntimeError):
            self.status(R.QUAD9, quad9=RuntimeError('a bug'))



class CacheTest(unittest.TestCase):

    def test_a_settled_answer_is_remembered(self):
        for answers, expected in (({'quad9': QUAD9_BLOCK}, 'blocked'),
                                  ({'quad9': RESOLVES}, 'clear'),
                                  ({'quad9': NO_SUCH_NAME}, 'nxdomain'),
                                  ({'quad9': QUAD9_BLOCK, 'quad9_unfiltered': LOCAL_BLOCKER_NXDOMAIN},
                                   'censored')):
            fake = Fake(**answers)
            chk, _ = checker(fake)
            self.assertEqual(chk.status(R.QUAD9, 'a.example'), expected)
            asked = len(fake.asked)
            self.assertEqual(chk.status(R.QUAD9, 'a.example'), expected)
            self.assertEqual(len(fake.asked), asked, expected)

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
        fake = Fake(quad9=RESOLVES)
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
        chk = R.Checker(R.settings({'enable': True}), ask=fake, rate=20)
        with mock.patch.object(R.time, 'sleep') as sleep:
            for host in ('a.example', 'b.example', 'c.example'):
                chk.status(R.QUAD9, host)
        self.assertTrue(sleep.called)
        self.assertTrue(all(0 < call.args[0] <= 0.05 for call in sleep.call_args_list))


class BackoffTest(unittest.TestCase):
    """A resolver that keeps failing is left alone for a while."""

    def test_three_failures_in_a_row_stop_the_asking(self):
        fake = Fake(quad9=dns.exception.Timeout())
        chk, _ = checker(fake)
        found = [chk.status(R.QUAD9, f'{n}.example') for n in range(5)]
        self.assertEqual(found, ['timeout'] * 3 + ['unavailable'] * 2)
        self.assertEqual(len(fake.asked), 3)

    def test_without_the_back_off_every_event_would_pay(self):
        # The control
        fake = Fake(quad9=dns.exception.Timeout())
        chk, _ = checker(fake)
        with mock.patch.object(R, 'FAILURES_TO_BACK_OFF', 10 ** 6):
            for n in range(5):
                chk.status(R.QUAD9, f'{n}.example')
        self.assertEqual(len(fake.asked), 5)

    def test_it_is_asked_again_once_the_rest_is_over_and_recovers(self):
        fake = Fake(quad9=OSError('unreachable'))
        chk, clock = checker(fake, backoff_sec=60)
        for n in range(3):
            chk.status(R.QUAD9, f'{n}.example')
        clock.now += 61
        fake.answers['quad9'] = RESOLVES
        self.assertEqual(chk.status(R.QUAD9, 'later.example'), 'clear')
        self.assertEqual(chk.status(R.QUAD9, 'later2.example'), 'clear')

    def test_failing_again_doubles_the_rest(self):
        fake = Fake(quad9=dns.exception.Timeout())
        chk, clock = checker(fake, backoff_sec=60)
        for n in range(3):
            chk.status(R.QUAD9, f'{n}.example')
        clock.now += 61
        self.assertEqual(chk.status(R.QUAD9, 'again.example'), 'timeout')
        clock.now += 61
        self.assertEqual(chk.status(R.QUAD9, 'still.example'), 'unavailable')
        clock.now += 60
        self.assertEqual(chk.status(R.QUAD9, 'then.example'), 'timeout')

    def test_an_answer_between_failures_resets_the_count(self):
        fake = Fake(quad9=dns.exception.Timeout())
        chk, _ = checker(fake)
        chk.status(R.QUAD9, 'a.example')
        chk.status(R.QUAD9, 'b.example')
        fake.answers['quad9'] = RESOLVES
        chk.status(R.QUAD9, 'c.example')
        fake.answers['quad9'] = dns.exception.Timeout()
        chk.status(R.QUAD9, 'd.example')
        chk.status(R.QUAD9, 'e.example')
        self.assertEqual(chk.status(R.QUAD9, 'f.example'), 'timeout')

    def test_one_resolver_down_leaves_the_other_asked(self):
        fake = Fake(quad9=dns.exception.Timeout())
        chk, _ = checker(fake)
        for n in range(3):
            chk.status(R.QUAD9, f'{n}.example')
        self.assertEqual(chk.status(R.CLOUDFLARE_SECURITY, 'x.example'), 'clear')

    def test_a_rest_is_not_remembered_as_an_answer(self):
        fake = Fake(quad9=dns.exception.Timeout())
        chk, _ = checker(fake)
        for n in range(4):
            chk.status(R.QUAD9, 'same.example')
        self.assertNotIn((R.QUAD9, 'same.example'), chk.cache)


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

    def run_it(self, host_claims, fake, min_publishers=2, **conf):
        chk, _ = checker(fake, **conf)
        verdict = resolve(host_claims, min_publishers)
        return chk.corroborate('h.example', host_claims, verdict, min_publishers)

    def test_a_vote_corroborates_a_medium_list(self):
        fake = Fake(quad9=QUAD9_BLOCK)
        found, verdict, statuses = self.run_it(
            claims('h.example', (ARMY, 'malicious'), (ARMY, 'phishing')), fake)
        self.assertEqual(verdict['asserted'], ['malicious'])
        # The resolver says the host is bad, not what kind of bad
        self.assertEqual(verdict['candidate'], ['phishing'])
        self.assertIn((None, R.SOURCES['quad9'], 'malicious'), found)

    def test_a_settled_name_is_not_sent_to_the_next_resolver(self):
        fake = Fake(quad9=QUAD9_BLOCK)
        _, _, statuses = self.run_it(claims('h.example', (ARMY, 'malicious')), fake)
        self.assertEqual(statuses, {'quad9': 'blocked'})
        self.assertEqual(fake.roles(), ['quad9', 'quad9_unfiltered'])

    def test_without_weighing_again_cloudflare_would_be_asked_too(self):
        # The control: keep the verdict from before the vote, and the name goes
        # to Cloudflare although Quad9 already settled it
        fake = Fake(quad9=QUAD9_BLOCK)
        original = resolve(claims('h.example', (ARMY, 'malicious')))
        with mock.patch.object(R, 'resolve', lambda found, bar: original):
            self.run_it(claims('h.example', (ARMY, 'malicious')), fake)
        self.assertIn('cloudflare_security', fake.roles())

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
        _, verdict, _ = self.run_it(claims('h.example', (NOISY, 'malicious')), fake)
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

    def test_the_adult_vote_is_off_unless_asked_for(self):
        fake = Fake(cloudflare_family=CLOUDFLARE_ADULT_BLOCK)
        _, verdict, statuses = self.run_it(claims('h.example', (PORN_LIST, 'porn')), fake)
        self.assertEqual((verdict['asserted'], statuses, fake.asked), ([], {}, []))

    def test_a_porn_candidate_asks_only_the_family_resolver(self):
        fake = Fake(cloudflare_family=CLOUDFLARE_ADULT_BLOCK)
        _, verdict, statuses = self.run_it(claims('h.example', (PORN_LIST, 'porn')), fake,
                                           adult=True)
        self.assertEqual(verdict['asserted'], ['porn'])
        self.assertEqual(statuses, {'cloudflare-family': 'blocked'})

    def test_a_published_zero_address_never_becomes_a_porn_vote(self):
        fake = Fake(cloudflare_family=ZERO_NO_EDE, cloudflare_security=ZERO_NO_EDE,
                    cloudflare_unfiltered=ZERO_NO_EDE)
        _, verdict, statuses = self.run_it(claims('h.example', (PORN_LIST, 'porn')), fake,
                                           adult=True)
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(statuses, {'cloudflare-family': 'clear'})

    def test_a_security_block_on_1113_is_not_a_porn_vote(self):
        fake = Fake(cloudflare_family=CLOUDFLARE_SECURITY_BLOCK)
        _, verdict, statuses = self.run_it(claims('h.example', (PORN_LIST, 'porn')), fake,
                                           adult=True)
        self.assertEqual(verdict['asserted'], [])
        self.assertEqual(statuses, {'cloudflare-family': 'security'})

    def test_both_cloudflare_resolvers_are_one_publisher(self):
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
        self.assertEqual(self.run_it(found, fake, adult=True)[2], {})


class DeadlineTest(unittest.TestCase):
    """One lookup waits at most timeout_sec on the resolvers, however many it asks."""

    def test_a_slow_first_resolver_leaves_no_time_for_the_second(self):
        clock = Clock()
        fake = Fake(clock=clock, quad9=dns.exception.Timeout())
        chk, _ = checker(fake, clock=clock, timeout_sec=0.5)
        verdict = resolve(claims('h.example', (ARMY, 'malicious')))
        _, _, statuses = chk.corroborate('h.example', claims('h.example', (ARMY, 'malicious')),
                                         verdict, 2)
        self.assertEqual(statuses, {'quad9': 'timeout', 'cloudflare-security': 'deadline'})
        self.assertEqual(fake.roles(), ['quad9'])
        self.assertEqual(clock.now, 1000.5)

    def test_a_question_is_never_given_more_than_is_left(self):
        clock = Clock()
        fake = Fake(clock=clock, quad9=QUAD9_BLOCK, quad9_unfiltered=dns.exception.Timeout())
        chk, _ = checker(fake, clock=clock, timeout_sec=0.5)
        clock_before = clock.now
        chk.status(R.QUAD9, 'h.example', deadline=clock_before + 0.2)
        self.assertTrue(all(t <= 0.2 + 1e-9 for t in fake.timeouts), fake.timeouts)

    def test_the_audit_has_no_budget(self):
        # Throttled and waiting by design, so every question is asked
        clock = Clock()
        fake = Fake(clock=clock, quad9=dns.exception.Timeout())
        chk, _ = checker(fake, clock=clock, rate=20)
        verdict = resolve(claims('h.example', (ARMY, 'malicious')))
        with mock.patch.object(R.time, 'sleep'):
            _, _, statuses = chk.corroborate(
                'h.example', claims('h.example', (ARMY, 'malicious')), verdict, 2)
        self.assertEqual(statuses, {'quad9': 'timeout', 'cloudflare-security': 'clear'})

    def test_running_out_is_not_remembered(self):
        clock = Clock()
        chk, _ = checker(Fake(), clock=clock)
        self.assertEqual(chk.status(R.QUAD9, 'h.example', deadline=clock.now), 'deadline')
        self.assertNotIn((R.QUAD9, 'h.example'), chk.cache)


class SettingsTest(unittest.TestCase):

    def test_off_by_default(self):
        self.assertFalse(R.settings(None).enable)
        self.assertIsNone(R.checker_for(R.settings(None)))

    def test_defaults(self):
        conf = R.settings({'enable': True})
        self.assertEqual(conf.addresses, R.DEFAULT_ADDRESSES)
        self.assertFalse(conf.adult)
        self.assertEqual((conf.timeout, conf.backoff, conf.ttl, conf.max_entries),
                         (R.DEFAULT_TIMEOUT, R.DEFAULT_BACKOFF, R.DEFAULT_TTL,
                          R.DEFAULT_MAX_ENTRIES))

    def test_addresses_can_be_overridden(self):
        conf = R.settings({'enable': True, 'addresses': {'quad9': '149.112.112.112'}})
        self.assertEqual(conf.addresses['quad9'], '149.112.112.112')
        self.assertEqual(conf.addresses['cloudflare_security'], '1.1.1.2')

    def test_the_shipped_example_config_is_valid(self):
        # setup.py builds every new config.yaml from it, so a mistake in it is a
        # worker that will not start, or a default nobody meant
        import yaml
        from libtb.evidence import evidence_settings
        with open(os.path.join(ROOT, 'src', 'support', 'config.example.yaml')) as fh:
            evidence = yaml.safe_load(fh)['processor']['evidence']
        _, disabled = evidence_settings(evidence)
        self.assertEqual(disabled, frozenset({'editorial'}))
        conf = R.settings(evidence.get('resolvers'))
        self.assertFalse(conf.enable)
        self.assertFalse(conf.adult)

    def test_mistakes_are_refused(self):
        for bad in ({'enabled': True}, {'enable': 'yes'}, {'adult': 'yes'},
                    {'timeout_sec': 0}, {'timeout_sec': 30}, {'timeout_sec': 'fast'},
                    {'timeout_sec': float('nan')}, {'backoff_sec': 0},
                    {'backoff_sec': 100000}, {'cache': {'ttl': 60}},
                    {'cache': {'max_entries': 1.5}}, {'cache': {'ttl_sec': float('inf')}},
                    {'cache': 0}, {'addresses': []},
                    {'addresses': {'quad9': 'dns.quad9.net'}},
                    {'addresses': {'google': '8.8.8.8'}}, ['enable'], False):
            with self.assertRaises(ValueError, msg=bad):
                R.settings(bad)


class ProcessorTest(unittest.TestCase):
    """What lands on the event."""

    SOURCES = {'phishing_army': ARMY, 'hagezi-nsfw': PORN_LIST}

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-resolvers-')
        self.path = os.path.join(self.root, 'domains.tbidx')
        entries = {'bad.example.com': {'phishing_army': {'malicious', 'phishing'}},
                   '*.wild.example.com': {'phishing_army': {'malicious'}},
                   'fixed.example.com': {'phishing_army': {'malicious'}},
                   'adult.example.com': {'hagezi-nsfw': {'porn'}}}
        apply_ignorelist(entries, ignorelist={'malicious': ['fixed.example.com']})
        build(entries, path=self.path, built_at=1000, sources=self.SOURCES)
        R._checkers.clear()
        self.addCleanup(R._checkers.clear)
        self.addCleanup(shutil.rmtree, self.root, True)

    def processor(self, evidence=None, mode='index'):
        config = {'dns': {'lookup_ips': False},
                  'domain_index': {'mode': mode, 'path': self.path}}
        if evidence is not None:
            config['evidence'] = evidence
        processor = Processor(config, {})
        shipped = []
        processor.ship_bite = shipped.append
        processor.valkey_contexts = lambda searches: ['legacy']
        return processor, shipped

    def bite(self, name, evidence=None, mode='index', fake=None):
        processor, shipped = self.processor(evidence, mode)
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
        self.assertEqual(bite['resolvers'], {'quad9': 'blocked'})
        self.assertEqual(bite['risk'], ['threat.malicious'])

    def test_a_vote_is_not_reported_as_an_index_match(self):
        # matched_on names index entries, which is what a correction is aimed
        # at, and the vote matched none
        bite, _ = self.bite('x.wild.example.com', evidence=self.ON)
        self.assertEqual(bite['contexts'], ['malicious'])
        self.assertEqual(bite['matched_on'], ['*.wild.example.com'])

    def test_a_page_opened_in_a_browser_is_not_sent(self):
        processor, shipped = self.processor(self.ON)
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

    def test_only_the_name_is_sent(self):
        _, fake = self.bite('bad.example.com', evidence=self.ON)
        self.assertEqual({host for _, host in fake.asked}, {'bad.example.com'})

    def test_a_failure_is_recorded_and_costs_nothing(self):
        fake = Fake(quad9=dns.exception.Timeout(), cloudflare_security=OSError('unreachable'))
        bite, _ = self.bite('bad.example.com', evidence=self.ON, fake=fake)
        self.assertEqual(bite['resolvers'], {'quad9': 'timeout', 'cloudflare-security': 'error'})
        self.assertEqual(bite['contexts'], [])

    def test_a_resolver_fault_is_not_answered_from_valkey(self):
        # The vote must run outside the broken-index fallback guard.
        with self.assertRaises(RuntimeError):
            self.bite('bad.example.com', evidence=self.ON,
                      fake=Fake(quad9=RuntimeError('resolver fault')))

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
        # Asked about the bare name and the www spelling, as the audit checks both
        self.assertEqual(report['resolvers'][('quad9', 'blocked')], 2)
        # The control: no checker, no vote
        report = audit(index, ['bad.example.com'], psl_path=FIXTURE)
        self.assertNotIn('malicious', report['asserted'])

    def test_the_audit_says_when_the_resolvers_did_not_answer(self):
        index = DomainIndex(self.path)
        self.addCleanup(index.close)
        chk, _ = checker(Fake(quad9=dns.exception.Timeout(),
                              cloudflare_security=dns.exception.Timeout()))
        report = audit(index, ['bad.example.com'], psl_path=FIXTURE, checker=chk)
        text = '\n'.join(format_report(report, 1))
        self.assertIn('got no answer', text)
        self.assertRegex(text, r'quad9\s+timeout')

    def test_categorise_votes_only_for_a_lookup(self):
        index = DomainIndex(self.path)
        self.addCleanup(index.close)
        chk, _ = checker(Fake(quad9=QUAD9_BLOCK))
        _, looked_up = categorise(index, 'bad.example.com', psl_path=FIXTURE, checker=chk)
        _, opened = categorise(index, 'bad.example.com', psl_path=FIXTURE, checker=chk,
                               navigation=True)
        self.assertEqual(looked_up['asserted'], ['malicious'])
        self.assertEqual(opened['asserted'], [])
        self.assertNotIn('resolvers', opened)


class AuditCommandTest(unittest.TestCase):
    """`turkeybite audit --resolvers` with everything else given needs no config.yaml."""

    def test_it_runs_without_reading_the_configuration(self):
        from click.testing import CliRunner
        path = os.path.join(ROOT, 'src', 'turkeybite')
        loader = importlib.machinery.SourceFileLoader('turkeybite_cli', path)
        spec = importlib.util.spec_from_loader('turkeybite_cli', loader)
        cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cli)

        root = tempfile.mkdtemp(prefix='tb-audit-cli-')
        self.addCleanup(shutil.rmtree, root, True)
        index_path = os.path.join(root, 'domains.tbidx')
        build({'bad.example.com': {'army': {'malicious'}}}, path=index_path, built_at=1,
              sources={'army': ARMY})
        reference = os.path.join(root, 'ref.csv')
        with open(reference, 'w') as fh:
            fh.write('1,bad.example.com\n')

        with mock.patch.object(cli, 'read_config', side_effect=AssertionError('read config')), \
                mock.patch.object(R, 'query', Fake(quad9=QUAD9_BLOCK)), \
                mock.patch.object(R.time, 'sleep'):
            result = CliRunner().invoke(cli.cli, [
                'audit', reference, '--index', index_path, '--min-publishers', '2',
                '--disable', '', '--resolvers'])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn('What the resolvers said', result.output)


if __name__ == '__main__':
    unittest.main(verbosity=2)
