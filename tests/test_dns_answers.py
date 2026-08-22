"""Tests for lifting the DNS answer section into bite.

Packetbeat has already parsed the answers, so the risk is not parsing. It is
what the CNAME chain does to a category: a chain hit and a question hit mean
quite different things when a human reviews a finding, so the event has to say
which it was.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from libtb.processor import Processor, cname_chain, resolved_addresses


class CnameChainTest(unittest.TestCase):

    def packet(self, answers):
        return {'dns': {'answers': answers}}

    def test_cname_targets_are_collected_in_order(self):
        chain = cname_chain(self.packet([
            {'type': 'CNAME', 'data': 'a.example.com'},
            {'type': 'CNAME', 'data': 'b.example.net'},
            {'type': 'A', 'data': '93.184.216.34'},
        ]))
        self.assertEqual(chain, ['a.example.com', 'b.example.net'])

    def test_non_cname_records_are_ignored(self):
        chain = cname_chain(self.packet([
            {'type': 'A', 'data': '93.184.216.34'},
            {'type': 'AAAA', 'data': '2606:2800:220:1::1'},
            {'type': 'TXT', 'data': 'v=spf1'},
        ]))
        self.assertEqual(chain, [])

    def test_targets_are_normalised(self):
        chain = cname_chain(self.packet([{'type': 'CNAME', 'data': 'A.Example.COM.'}]))
        self.assertEqual(chain, ['a.example.com'])

    def test_duplicate_targets_collapse(self):
        chain = cname_chain(self.packet([
            {'type': 'CNAME', 'data': 'a.example.com'},
            {'type': 'CNAME', 'data': 'a.example.com'},
        ]))
        self.assertEqual(chain, ['a.example.com'])

    def test_malformed_records_are_skipped(self):
        chain = cname_chain(self.packet([
            None, 'a string', 7, [],
            {'type': 'CNAME'},
            {'type': 'CNAME', 'data': None},
            {'type': 'CNAME', 'data': ''},
            {'type': 'CNAME', 'data': 'good.example.com'},
        ]))
        self.assertEqual(chain, ['good.example.com'])

    def test_no_answer_section_is_an_empty_chain(self):
        for packet in ({}, {'dns': {}}, {'dns': {'answers': None}},
                       {'dns': {'answers': []}}):
            self.assertEqual(cname_chain(packet), [])


class ResolvedAddressesTest(unittest.TestCase):

    def test_addresses_are_canonicalised_and_deduplicated(self):
        self.assertEqual(
            resolved_addresses(['93.184.216.34', '93.184.216.34',
                                '2606:0:0:0:0:0:0:1']),
            ['93.184.216.34', '2606::1'])

    def test_a_sinkhole_address_is_kept_because_it_is_a_signal(self):
        # Unlike a client address, nothing here is dropped for being unusable:
        # a name resolving to loopback or 0.0.0.0 has been sinkholed
        self.assertEqual(resolved_addresses(['127.0.0.1', '0.0.0.0', '::']),
                         ['127.0.0.1', '0.0.0.0', '::'])

    def test_unparseable_entries_are_skipped(self):
        self.assertEqual(resolved_addresses(['not-an-ip', '', '10.0.0.1']),
                         ['10.0.0.1'])

    def test_non_list_input_does_not_raise(self):
        for bad in (None, 7, '10.0.0.1', {'a': 1}):
            self.assertEqual(resolved_addresses(bad), [])


class DnsPacketWiringTest(unittest.TestCase):
    """What actually lands on the event."""

    def setUp(self):
        self.processor = Processor({'dns': {'lookup_ips': False},
                                   'domain_index': {'mode': 'index'}}, {})
        self.shipped = []
        self.processor.ship_bite = self.shipped.append

    def stub_lookups(self, question=(), chain=()):
        self.processor.resolve_contexts = lambda s: (list(question), {})
        self.processor.resolve_chain = lambda c: (list(chain), [], list(c))

    def packet(self, answers=None, resolved=None, rcode='NOERROR'):
        dns = {'question': {'name': 'www.example.com',
                            'etld_plus_one': 'example.com'}}
        if answers is not None:
            dns['answers'] = answers
        if resolved is not None:
            dns['resolved_ip'] = resolved
        if rcode is not None:
            dns['response_code'] = rcode
        return {'type': 'dns', 'resource': 'www.example.com', 'dns': dns,
                'network': {'direction': 'ingress'}, 'client': {'ip': '10.0.0.5'},
                '@timestamp': '2026-08-22T04:00:00Z'}

    def bite(self):
        self.assertEqual(len(self.shipped), 1)
        return self.shipped[0]['bite']

    # -- the chain ----------------------------------------------------------

    def test_the_chain_is_recorded_even_when_it_categorises_nothing(self):
        self.stub_lookups(question=['news'], chain=[])
        self.processor.process_dns_packet(self.packet(
            answers=[{'type': 'CNAME', 'data': 'edge.example.net'}]))
        bite = self.bite()
        self.assertEqual(bite['cname_chain'], ['edge.example.net'])
        self.assertEqual(bite['contexts'], ['news'])
        self.assertEqual(bite['match_source'], ['question'])

    def test_a_chain_category_is_merged_into_contexts(self):
        self.stub_lookups(question=[], chain=['tracking'])
        self.processor.process_dns_packet(self.packet(
            answers=[{'type': 'CNAME', 'data': 'metrics.vendor.example'}]))
        bite = self.bite()
        self.assertEqual(bite['contexts'], ['tracking'])
        self.assertEqual(bite['match_source'], ['cname'])

    def test_both_sources_are_recorded_when_both_match(self):
        self.stub_lookups(question=['news'], chain=['tracking'])
        self.processor.process_dns_packet(self.packet(
            answers=[{'type': 'CNAME', 'data': 'metrics.vendor.example'}]))
        bite = self.bite()
        self.assertEqual(bite['contexts'], ['news', 'tracking'])
        self.assertEqual(bite['match_source'], ['question', 'cname'])

    def test_the_chain_entry_that_matched_is_recorded(self):
        # Without this the event says a category came from somewhere in the
        # chain but not from where, which a reviewer cannot act on
        self.stub_lookups(question=[], chain=['tracking'])
        self.processor.process_dns_packet(self.packet(
            answers=[{'type': 'CNAME', 'data': 'metrics.vendor.example'}]))
        bite = self.bite()
        self.assertEqual(bite['cname_matched_on'], ['metrics.vendor.example'])
        self.assertEqual(bite['cname_contexts'], ['tracking'])

    def test_duplicate_categories_do_not_duplicate_in_contexts(self):
        self.stub_lookups(question=['tracking'], chain=['tracking'])
        self.processor.process_dns_packet(self.packet(
            answers=[{'type': 'CNAME', 'data': 'metrics.vendor.example'}]))
        self.assertEqual(self.bite()['contexts'], ['tracking'])

    def test_no_chain_means_no_chain_fields(self):
        self.stub_lookups(question=['news'])
        self.processor.process_dns_packet(self.packet(answers=[
            {'type': 'A', 'data': '93.184.216.34'}]))
        bite = self.bite()
        self.assertNotIn('cname_chain', bite)
        self.assertNotIn('cname_matched_on', bite)

    def test_no_match_at_all_means_no_match_source(self):
        self.stub_lookups(question=[], chain=[])
        self.processor.process_dns_packet(self.packet(
            answers=[{'type': 'CNAME', 'data': 'edge.example.net'}]))
        self.assertNotIn('match_source', self.bite())

    # -- resolved addresses and response code -------------------------------

    def test_resolved_addresses_are_lifted(self):
        self.stub_lookups(question=['news'])
        self.processor.process_dns_packet(self.packet(
            resolved=['93.184.216.34', '2606:2800:220:1::1']))
        self.assertEqual(self.bite()['resolved_ips'],
                         ['93.184.216.34', '2606:2800:220:1::1'])

    def test_no_resolved_addresses_means_no_field(self):
        self.stub_lookups(question=['news'])
        self.processor.process_dns_packet(self.packet(resolved=[]))
        self.assertNotIn('resolved_ips', self.bite())

    def test_the_response_code_is_lifted_and_upper_cased(self):
        self.stub_lookups(question=['news'])
        self.processor.process_dns_packet(self.packet(rcode='nxdomain'))
        self.assertEqual(self.bite()['response_code'], 'NXDOMAIN')

    def test_a_missing_response_code_means_no_field(self):
        self.stub_lookups(question=['news'])
        self.processor.process_dns_packet(self.packet(rcode=None))
        self.assertNotIn('response_code', self.bite())

    def test_existing_fields_are_untouched(self):
        self.stub_lookups(question=['news'])
        self.processor.process_dns_packet(self.packet(
            answers=[{'type': 'CNAME', 'data': 'edge.example.net'}],
            resolved=['93.184.216.34']))
        bite = self.bite()
        self.assertEqual(bite['type'], 'dns')
        self.assertEqual(bite['client'], '10.0.0.5')
        self.assertEqual(bite['requested'], ['www.example.com'])
        self.assertEqual(bite['request'], 'query')


class CompareModeTest(unittest.TestCase):
    """compare mode records the chain without merging it."""

    def setUp(self):
        self.processor = Processor({'dns': {'lookup_ips': False},
                                   'domain_index': {'mode': 'compare'}}, {})
        self.shipped = []
        self.processor.ship_bite = self.shipped.append
        self.processor.resolve_contexts = lambda s: (['news'], {})
        self.processor.resolve_chain = lambda c: (['tracking'], [], list(c))

    def packet(self):
        return {'type': 'dns', 'resource': 'www.example.com',
                'dns': {'question': {'name': 'www.example.com'},
                        'answers': [{'type': 'CNAME', 'data': 'v.example.net'}]},
                'network': {'direction': 'ingress'}, 'client': {'ip': '10.0.0.5'},
                '@timestamp': '2026-08-22T04:00:00Z'}

    def test_contexts_are_not_enriched(self):
        self.processor.process_dns_packet(self.packet())
        self.assertEqual(self.shipped[0]['bite']['contexts'], ['news'])

    def test_what_merging_would_add_is_still_recorded(self):
        self.processor.process_dns_packet(self.packet())
        bite = self.shipped[0]['bite']
        self.assertEqual(bite['cname_contexts'], ['tracking'])
        self.assertEqual(bite['cname_chain'], ['v.example.net'])

    def test_cname_is_not_claimed_as_a_match_source(self):
        self.processor.process_dns_packet(self.packet())
        self.assertEqual(self.shipped[0]['bite']['match_source'], ['question'])


class ChainLookupModeTest(unittest.TestCase):
    """The chain is only categorised where it is affordable."""

    def test_valkey_mode_does_not_categorise_the_chain(self):
        processor = Processor({'domain_index': {'mode': 'valkey'}}, {})
        self.assertEqual(processor.resolve_chain(['a.example.com']), ([], [], []))

    def test_an_empty_chain_is_never_looked_up(self):
        processor = Processor({'domain_index': {'mode': 'index'}}, {})
        self.assertEqual(processor.resolve_chain([]), ([], [], []))

    def test_an_unreadable_index_is_not_fatal(self):
        processor = Processor(
            {'domain_index': {'mode': 'index', 'path': '/nonexistent/x.tbidx'}}, {})
        self.assertEqual(processor.resolve_chain(['a.example.com']), ([], [], []))


if __name__ == '__main__':
    unittest.main(verbosity=2)
