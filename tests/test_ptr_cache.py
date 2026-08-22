"""Tests for the reverse DNS cache.

The risk is not a cache miss, it is remembering the wrong thing. Caching a
transient resolver failure would pin it for the whole TTL and hide the recovery,
and handing the same list object to every caller would let one event's mutation
rewrite the cache for every later one.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from dns import exception, resolver

from libtb import processor as P


class FakeAnswer(object):
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text


class FakeResolver(object):
    """Counts queries so a cache hit is observable, and can be told to fail."""

    def __init__(self):
        self.queries = []
        self.answers = {}
        self.raise_with = None

    def resolve(self, name, rdtype):
        self.queries.append(str(name))
        if self.raise_with is not None:
            raise self.raise_with
        return [FakeAnswer(a) for a in self.answers.get(str(name), [])]


class PtrCacheTest(unittest.TestCase):

    def setUp(self):
        P._ptr_cache.clear()
        P._ptr_resolvers.clear()
        self.fake = FakeResolver()
        self.real_resolver = P.ptr_resolver
        P.ptr_resolver = lambda nameservers, timeout=1: self.fake

    def tearDown(self):
        P.ptr_resolver = self.real_resolver
        P._ptr_cache.clear()
        P._ptr_resolvers.clear()

    def lookup(self, client, **kwargs):
        return P.ptr_lookup(client, ['192.0.2.1'], **kwargs)

    # -- the happy path -----------------------------------------------------

    def test_a_successful_lookup_is_returned(self):
        self.fake.answers['1.2.0.192.in-addr.arpa.'] = ['host-a.example.com.']
        hosts, name, status = self.lookup('192.0.2.1', now=100)
        self.assertEqual(hosts, ['host-a.example.com'])
        self.assertEqual(name, '1.2.0.192.in-addr.arpa.')
        self.assertEqual(status, 'ok')

    def test_a_second_lookup_inside_the_ttl_asks_nothing(self):
        self.fake.answers['1.2.0.192.in-addr.arpa.'] = ['host-a.example.com.']
        self.lookup('192.0.2.1', ttl=300, now=100)
        self.lookup('192.0.2.1', ttl=300, now=399)
        self.assertEqual(len(self.fake.queries), 1)

    def test_the_ttl_expires(self):
        self.fake.answers['1.2.0.192.in-addr.arpa.'] = ['host-a.example.com.']
        self.lookup('192.0.2.1', ttl=300, now=100)
        self.lookup('192.0.2.1', ttl=300, now=401)
        self.assertEqual(len(self.fake.queries), 2)

    def test_distinct_clients_do_not_share_an_answer(self):
        self.fake.answers['1.2.0.192.in-addr.arpa.'] = ['host-a.example.com.']
        self.fake.answers['2.2.0.192.in-addr.arpa.'] = ['host-b.example.com.']
        a, _, _ = self.lookup('192.0.2.1', now=100)
        b, _, _ = self.lookup('192.0.2.2', now=100)
        self.assertEqual((a, b), (['host-a.example.com'], ['host-b.example.com']))

    def test_multiple_ptr_records_are_all_returned(self):
        self.fake.answers['1.2.0.192.in-addr.arpa.'] = ['a.example.com.', 'b.example.com.']
        hosts, _, _ = self.lookup('192.0.2.1', now=100)
        self.assertEqual(hosts, ['a.example.com', 'b.example.com'])

    # -- the mutation trap --------------------------------------------------

    def test_the_caller_cannot_poison_the_cache_by_mutating_the_result(self):
        self.fake.answers['1.2.0.192.in-addr.arpa.'] = ['host-a.example.com.']
        first, _, _ = self.lookup('192.0.2.1', now=100)
        first.append('injected.example.net')
        second, _, _ = self.lookup('192.0.2.1', now=101)
        self.assertEqual(second, ['host-a.example.com'])

    def test_each_call_returns_a_distinct_list_object(self):
        self.fake.answers['1.2.0.192.in-addr.arpa.'] = ['host-a.example.com.']
        first, _, _ = self.lookup('192.0.2.1', now=100)
        second, _, _ = self.lookup('192.0.2.1', now=101)
        self.assertIsNot(first, second)

    # -- what must not be cached -------------------------------------------

    def test_nxdomain_is_cached_because_it_is_a_real_answer(self):
        self.fake.raise_with = resolver.NXDOMAIN()
        _, _, status = self.lookup('192.0.2.1', ttl=300, now=100)
        self.assertEqual(status, 'nxdomain')
        self.lookup('192.0.2.1', ttl=300, now=200)
        self.assertEqual(len(self.fake.queries), 1)

    def test_a_transient_resolver_failure_is_not_cached(self):
        self.fake.raise_with = resolver.NoNameservers()
        _, _, status = self.lookup('192.0.2.1', ttl=300, now=100)
        self.assertEqual(status, 'NoNameservers')
        self.lookup('192.0.2.1', ttl=300, now=101)
        self.assertEqual(len(self.fake.queries), 2)

    def test_a_timeout_is_not_cached(self):
        self.fake.raise_with = exception.Timeout()
        _, _, status = self.lookup('192.0.2.1', ttl=300, now=100)
        self.assertEqual(status, 'Timeout')
        self.lookup('192.0.2.1', ttl=300, now=101)
        self.assertEqual(len(self.fake.queries), 2)

    def test_recovery_is_visible_immediately_after_a_failure(self):
        # The point of not caching failures: the fix must take effect at once
        self.fake.raise_with = resolver.NoNameservers()
        _, _, first = self.lookup('192.0.2.1', ttl=300, now=100)
        self.fake.raise_with = None
        self.fake.answers['1.2.0.192.in-addr.arpa.'] = ['host-a.example.com.']
        hosts, _, second = self.lookup('192.0.2.1', ttl=300, now=101)
        self.assertEqual(first, 'NoNameservers')
        self.assertEqual((hosts, second), (['host-a.example.com'], 'ok'))

    def test_only_stable_outcomes_are_listed_as_cacheable(self):
        self.assertEqual(sorted(P.PTR_CACHEABLE),
                         ['bad_client_address', 'nxdomain', 'ok'])

    # -- bad input ----------------------------------------------------------

    def test_an_unparseable_address_is_reported_not_raised(self):
        hosts, name, status = self.lookup('not-an-address', now=100)
        self.assertEqual((hosts, name, status), ([], '', 'bad_client_address'))
        self.assertEqual(self.fake.queries, [])

    def test_an_unparseable_address_is_cached(self):
        self.lookup('not-an-address', ttl=300, now=100)
        self.assertIn('not-an-address', P._ptr_cache)

    def test_every_malformed_address_shape_lands_on_the_same_status(self):
        for bad in ('not-an-address', '', '999.1.1.1', '10.0.0', 'x::y', '10.0.0.1 '):
            _, _, status = self.lookup(bad, now=100)
            self.assertEqual(status, 'bad_client_address', bad)

    def test_a_non_string_client_does_not_raise(self):
        # A malformed packet can put anything in client.ip, and a dict is both
        # truthy and unhashable, so it would break the cache lookup itself
        for bad in ({'ip': '10.0.0.1'}, ['10.0.0.1'], 10, None, 1.5):
            hosts, name, status = self.lookup(bad, now=100)
            self.assertEqual((hosts, name, status), ([], '', 'bad_client_address'), repr(bad))

    def test_an_unhashable_client_is_not_cached(self):
        self.lookup({'ip': '10.0.0.1'}, now=100)
        self.assertEqual(P._ptr_cache, {})

    # -- bounds -------------------------------------------------------------

    def test_the_cache_is_bounded(self):
        for i in range(1, 60):
            self.fake.answers[f'{i}.2.0.192.in-addr.arpa.'] = [f'h{i}.example.com.']
            self.lookup(f'192.0.2.{i}', max_entries=10, now=100)
        self.assertEqual(len(P._ptr_cache), 10)

    def test_eviction_drops_the_least_recently_refreshed(self):
        for i in (1, 2, 3):
            self.fake.answers[f'{i}.2.0.192.in-addr.arpa.'] = [f'h{i}.example.com.']
            self.lookup(f'192.0.2.{i}', ttl=300, max_entries=3, now=100)
        # Refresh the oldest so it is no longer the eviction candidate
        self.lookup('192.0.2.1', ttl=300, max_entries=3, now=500)
        self.fake.answers['4.2.0.192.in-addr.arpa.'] = ['h4.example.com.']
        self.lookup('192.0.2.4', ttl=300, max_entries=3, now=501)
        self.assertIn('192.0.2.1', P._ptr_cache)
        self.assertNotIn('192.0.2.2', P._ptr_cache)

    # -- the resolver itself ------------------------------------------------

    def test_one_resolver_is_built_per_nameserver_set(self):
        P.ptr_resolver = self.real_resolver
        first = P.ptr_resolver(['192.0.2.1'])
        second = P.ptr_resolver(['192.0.2.1'])
        third = P.ptr_resolver(['192.0.2.9'])
        self.assertIs(first, second)
        self.assertIsNot(first, third)
        self.assertEqual(first.nameservers, ['192.0.2.1'])

    def test_the_resolver_carries_the_timeout_through(self):
        P.ptr_resolver = self.real_resolver
        built = P.ptr_resolver(['192.0.2.1'], timeout=1)
        self.assertEqual(built.timeout, 1)
        self.assertEqual(built.lifetime, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
