"""Who held an address, from Windows NPS's RADIUS accounting log.

The lines are shaped as NPS writes them in DTS format, one accounting request
to a line, with made-up people, devices and access points.
"""

import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from fakes import FakeRedis
from libtb import radius
from libtb.consumer import describe
from libtb.processor import Processor
from libtb.radius import MAX_SESSIONS, Sessions
from libtb.sieve import Filters


# 22:19:32 UTC on 7 October 2026, the Event-Timestamp of the line below
EVENT = datetime(2026, 10, 7, 22, 19, 32, tzinfo=timezone.utc).timestamp()
RECEIVED = '2026-10-07T22:19:34.500Z'


def nps_line(status='3', user='jsmith@example.edu', address='10.212.16.219', mac='BA-F7-F8-00-00-01',
             session_id='88322DF2520E596E', nas='ap-hall-11', event='10/07/2026 22:19:32',
             session_time='600', packet_type='4', delay='0'):
    """One accounting request as NPS logs it. None leaves an attribute out."""
    attributes = [
        ('Timestamp', 4, '10/07/2026 18:19:34.212'), ('Computer-Name', 1, 'NPS-1'),
        ('Event-Source', 1, 'IAS'), ('Acct-Status-Type', 0, status), ('Event-Timestamp', 4, event),
        ('NAS-IP-Address', 3, '10.200.89.77'), ('User-Name', 1, user), ('NAS-Identifier', 1, nas),
        ('Called-Station-Id', 1, '80-95-62-00-00-E5:Example Wireless'),
        ('Vendor-Specific', 2, '000069300106000002BD'), ('Framed-IP-Address', 3, address),
        ('Vendor-Specific', 2, '00006930060600000001'), ('Calling-Station-Id', 1, mac),
        ('Acct-Session-Id', 1, session_id), ('Acct-Delay-Time', 0, delay),
        ('Acct-Session-Time', 0, session_time), ('Packet-Type', 0, packet_type), ('Reason-Code', 0, '0'),
    ]
    return '<Event>' + ''.join(f'<{name} data_type="{kind}">{value}</{name}>'
                               for name, kind, value in attributes if value is not None) + '</Event>'


def nps_event(**kwargs):
    """The line as Filebeat sends it, with `type: nps` set under the event's root."""
    return {'@timestamp': RECEIVED, 'message': nps_line(**kwargs), 'type': 'nps',
            'input': {'type': 'filestream'}, 'host': {'name': 'NPS-1'}}


def dns_event(client='10.212.16.219', at='2026-10-07T22:25:00Z'):
    return {'type': 'dns', 'resource': 'www.example.com',
            'dns': {'question': {'name': 'www.example.com', 'etld_plus_one': 'example.com'}},
            'network': {'direction': 'ingress'}, 'client': {'ip': client}, '@timestamp': at}


class AttributesTest(unittest.TestCase):

    def test_a_line_is_read_by_attribute_name(self):
        got = radius.attributes(nps_line())
        self.assertEqual(got['User-Name'], 'jsmith@example.edu')
        self.assertEqual(got['Framed-IP-Address'], '10.212.16.219')
        self.assertEqual(got['Calling-Station-Id'], 'BA-F7-F8-00-00-01')
        self.assertEqual(got['Acct-Status-Type'], '3')

    def test_a_repeated_attribute_keeps_its_first_value(self):
        self.assertEqual(radius.attributes(nps_line())['Vendor-Specific'], '000069300106000002BD')

    def test_xml_escapes_are_undone(self):
        got = radius.attributes('<Event><User-Name data_type="1">o&apos;brien&amp;co</User-Name></Event>')
        self.assertEqual(got['User-Name'], "o'brien&co")

    def test_what_is_not_a_line_reads_as_nothing(self):
        for bad in (None, 42, {'a': 1}, '', 'not xml at all', '<Event>' + 'x' * radius.MAX_LINE + '</Event>'):
            self.assertEqual(radius.attributes(bad), {})


class PartsTest(unittest.TestCase):

    def test_own_realms_are_taken_off(self):
        realms = ('example.edu', 'example')
        self.assertEqual(radius.username('JSmith@Example.edu', realms), 'jsmith')
        self.assertEqual(radius.username('EXAMPLE\\jsmith', realms), 'jsmith')

    def test_other_realms_are_kept(self):
        # An eduroam visitor is someone else's jsmith
        self.assertEqual(radius.username('jsmith@other.edu', ('example.edu',)), 'jsmith@other.edu')
        self.assertEqual(radius.username('OTHER\\jsmith', ('example',)), 'other\\jsmith')
        self.assertEqual(radius.username('jsmith@example.edu'), 'jsmith@example.edu')

    def test_a_computer_or_nobody_is_not_a_person(self):
        for name in ('host/LAB-12.example.edu', '', '   ', None, 7, 'x' * 300):
            self.assertIsNone(radius.username(name, ('example.edu',)), name)

    def test_mac_addresses_in_any_usual_form(self):
        for form in ('BA-F7-F8-00-00-01', 'ba:f7:f8:00:00:01', 'baf7f8000001', 'baf7.f800.0001'):
            self.assertEqual(radius.mac(form), 'ba:f7:f8:00:00:01', form)

    def test_what_is_not_a_mac_address(self):
        for bad in ('BA-F7-F8-00-00', 'BA-F7-F8-00-00-01-02', 'not a mac', '', None, 12):
            self.assertIsNone(radius.mac(bad), bad)

    def test_addresses_a_device_can_have(self):
        self.assertEqual(radius.address(' 10.212.16.219 '), '10.212.16.219')
        self.assertEqual(radius.address('2001:db8::1'), '2001:db8::1')
        for bad in ('0.0.0.0', '255.255.255.254', '255.255.255.255', '127.0.0.1', '169.254.1.2',  # nosec B104
                    '224.0.0.1', '10.0.0.0/8', 'nonsense', '', None):
            self.assertIsNone(radius.address(bad), bad)


class SessionTest(unittest.TestCase):

    def session(self, received=RECEIVED, **kwargs):
        return radius.session(radius.attributes(nps_line(**kwargs)), radius.iso_seconds(received),
                              ('example.edu',))

    def test_an_interim_update_reports_who_held_the_address_since_when(self):
        got = self.session()
        self.assertEqual(got.address, '10.212.16.219')
        self.assertEqual(got.user, 'jsmith')
        self.assertEqual(got.mac, 'ba:f7:f8:00:00:01')
        self.assertEqual(got.seen, EVENT)
        self.assertEqual(got.start, EVENT - 600)
        self.assertEqual(got.key, 'ap-hall-11|88322DF2520E596E')

    def test_a_start_and_a_stop_report_it_too(self):
        self.assertEqual(self.session(status='1', session_time=None).start, EVENT)
        self.assertEqual(self.session(status='2', session_time='14').start, EVENT - 14)

    def test_requests_that_say_nothing_about_a_session(self):
        # Accounting on and off, an authentication request, and lines that
        # name no address, no person or no session
        for kwargs in ({'status': '7'}, {'status': '8'}, {'status': None}, {'packet_type': '1'},
                       {'address': None}, {'address': '0.0.0.0'}, {'user': None},  # nosec B104
                       {'user': 'host/lab-12.example.edu'}, {'session_id': None}):
            self.assertIsNone(self.session(**kwargs), kwargs)

    def test_a_device_without_a_readable_mac_is_still_a_session(self):
        self.assertIsNone(self.session(mac='unknown').mac)

    def test_the_access_points_clock_is_believed(self):
        # A stop it was slow to send happened when it says, not when it came
        late = self.session(event='10/07/2026 20:37:35', session_time='115')
        when = datetime(2026, 10, 7, 20, 37, 35, tzinfo=timezone.utc).timestamp()
        self.assertEqual((late.start, late.seen), (when - 115, when))

    def test_but_not_from_the_future(self):
        got = self.session(event='10/08/2026 22:19:32', delay='5')
        self.assertEqual(got.seen, radius.iso_seconds(RECEIVED) - 5)

    def test_without_its_clock_the_line_is_dated_when_read(self):
        got = self.session(event=None, delay='3')
        self.assertEqual(got.seen, radius.iso_seconds(RECEIVED) - 3)
        self.assertIsNone(self.session(event=None, received=None))
        self.assertEqual(self.session(received=None).seen, EVENT)

    def test_a_session_too_long_to_believe_counts_from_its_report(self):
        self.assertEqual(self.session(session_time=str(10 ** 9)).start, EVENT)


class SettingsTest(unittest.TestCase):

    def test_off_unless_turned_on(self):
        self.assertEqual(radius.settings(None), radius.DEFAULT)
        self.assertFalse(radius.settings({}).enable)

    def test_what_is_set(self):
        got = radius.settings({'enable': True, 'realms': ['Example.EDU', 'EXAMPLE'], 'grace_sec': 900,
                               'keep_hours': 48, 'cache_sec': 0})
        self.assertEqual(got, radius.Settings(True, ('example.edu', 'example'), 900, 48 * 3600, 0))

    def test_mistakes_stop_the_worker(self):
        for bad in ([], {'enabled': True}, {'enable': 'yes'}, {'realms': 'example.edu'},
                    {'realms': ['']}, {'grace_sec': 10}, {'grace_sec': True}, {'keep_hours': 0},
                    {'keep_hours': '24'}, {'cache_sec': -1}):
            with self.assertRaises(ValueError, msg=bad):
                radius.settings(bad)

    def test_the_processor_checks_them_as_it_starts(self):
        with self.assertRaises(ValueError):
            Processor({'radius': {'enable': 'on'}}, {})


class SessionsTest(unittest.TestCase):

    def setUp(self):
        self.redis = FakeRedis()
        self.now = 0.0
        self.sessions = Sessions(self.redis, 'turkeybite', radius.settings({'enable': True}),
                                 monotonic=lambda: self.now)

    def record(self, user='jsmith', start=1000.0, seen=1600.0, key='ap|1', where='10.0.0.5', mac=None):
        self.sessions.record(radius.Session(where, key, user, mac, start, seen))

    def test_a_session_holds_its_address_from_start_until_grace_after_its_last_report(self):
        self.record()
        for when in (1000 - radius.CLOCK_SLACK, 1000, 1600, 1600 + 1200):
            self.assertEqual(self.sessions.holder('10.0.0.5', when)['u'], 'jsmith', when)
        self.sessions._cache.clear()
        for when in (1000 - radius.CLOCK_SLACK - 1, 1600 + 1200 + 1):
            self.assertIsNone(self.sessions.holder('10.0.0.5', when), when)
        self.assertIsNone(self.sessions.holder('10.0.0.6', 1200))

    def test_the_later_session_wins(self):
        self.record(user='jsmith', start=1000, seen=1600, key='ap|1')
        self.record(user='adoe', start=1500, seen=1700, key='ap|2')
        self.assertEqual(self.sessions.holder('10.0.0.5', 1550)['u'], 'adoe')
        self.assertEqual(self.sessions.holder('10.0.0.5', 1200)['u'], 'jsmith')

    def test_a_later_report_extends_the_same_session(self):
        self.record(seen=1600)
        self.record(seen=2200)
        self.assertEqual(self.redis.hlen('turkeybite:radius:10.0.0.5'), 1)
        self.assertEqual(self.sessions.holder('10.0.0.5', 2200 + 1200)['l'], 2200)

    def test_it_is_kept_in_valkey_for_keep_hours(self):
        self.record()
        self.assertEqual(self.redis.ttls['turkeybite:radius:10.0.0.5'], 24 * 3600)

    def test_an_address_keeps_its_latest_sessions(self):
        for n in range(MAX_SESSIONS + 3):
            self.record(user=f'user{n}', key=f'ap|{n}', start=n * 100, seen=n * 100 + 50)
        held = self.redis.hgetall('turkeybite:radius:10.0.0.5')
        self.assertEqual(len(held), MAX_SESSIONS)
        self.assertNotIn(b'ap|0', held)
        self.assertIn(f'ap|{MAX_SESSIONS + 2}'.encode(), held)

    def test_what_valkey_holds_that_cannot_be_read_is_left_out(self):
        self.redis.hset('turkeybite:radius:10.0.0.5', 'ap|bad', 'not json')
        self.redis.hset('turkeybite:radius:10.0.0.5', 'ap|odd', '{"u": 5, "s": 1, "l": 2}')
        self.record()
        self.assertEqual(self.sessions.holder('10.0.0.5', 1200)['u'], 'jsmith')

    def test_a_worker_reuses_what_it_read_for_cache_sec(self):
        self.record()
        self.sessions.holder('10.0.0.5', 1200)
        self.sessions.holder('10.0.0.5', 1200)
        self.assertEqual(self.redis.calls.count(('hgetall', 'turkeybite:radius:10.0.0.5')), 1)
        self.now += 31
        self.sessions.holder('10.0.0.5', 1200)
        self.assertEqual(self.redis.calls.count(('hgetall', 'turkeybite:radius:10.0.0.5')), 2)

    def test_its_own_report_is_seen_at_once(self):
        self.assertIsNone(self.sessions.holder('10.0.0.5', 1200))
        self.record()
        self.assertEqual(self.sessions.holder('10.0.0.5', 1200)['u'], 'jsmith')


class ProcessorTest(unittest.TestCase):
    """The lines recorded, and DNS events naming the person."""

    def processor(self, conf):
        processor = Processor({'dns': {'lookup_ips': False}, 'domain_index': {'mode': 'index'},
                               'radius': conf}, {})
        processor.ship_bite = self.shipped.append
        processor.resolve_contexts = lambda s, **kwargs: ([], {})
        processor.resolve_chain = lambda c: ([], [], list(c))
        return processor

    def setUp(self):
        self.shipped = []
        self.redis = FakeRedis()
        self.on = self.processor({'enable': True, 'realms': ['example.edu']})
        self.on.sessions = Sessions(self.redis, 'turkeybite', self.on._radius)

    def test_a_dns_event_names_who_held_its_address(self):
        self.on.process_packet(nps_event())
        self.on.process_packet(dns_event())
        bite = self.shipped[0]['bite']
        self.assertEqual(bite['client'], '10.212.16.219')
        self.assertEqual(bite['client_user'], 'jsmith')
        self.assertEqual(bite['client_mac'], 'ba:f7:f8:00:00:01')

    def test_an_accounting_line_is_not_indexed(self):
        self.on.process_packet(nps_event())
        self.assertEqual(self.shipped, [])
        self.assertIn('turkeybite:radius:10.212.16.219', self.redis.data)

    def test_an_address_nobody_held_then_is_left_as_it_was(self):
        self.on.process_packet(nps_event())
        self.on.process_packet(dns_event(at='2026-10-08T09:00:00Z'))
        self.on.process_packet(dns_event(client='10.212.16.220'))
        for shipped in self.shipped:
            self.assertNotIn('client_user', shipped['bite'])
            self.assertNotIn('client_mac', shipped['bite'])

    def test_a_session_without_a_mac_names_only_the_person(self):
        self.on.process_packet(nps_event(mac=None))
        self.on.process_packet(dns_event())
        self.assertEqual(self.shipped[0]['bite']['client_user'], 'jsmith')
        self.assertNotIn('client_mac', self.shipped[0]['bite'])

    def test_an_event_whose_time_cannot_be_read_is_matched_against_now(self):
        self.on.sessions.record(radius.Session('10.212.16.219', 'ap|1', 'jsmith', None,
                                               radius.iso_seconds(RECEIVED), 4102444800.0))
        self.on.process_packet(dns_event(at='yesterday'))
        self.assertEqual(self.shipped[0]['bite']['client_user'], 'jsmith')

    def test_off_it_does_nothing(self):
        off = self.processor(None)
        self.assertIsNone(off.radius_sessions())
        off.process_packet(nps_event())
        off.process_packet(dns_event())
        self.assertNotIn('client_user', self.shipped[0]['bite'])

    def test_on_it_connects_to_the_queues_valkey_once_a_process(self):
        on = Processor({'radius': {'enable': True}},
                       {'host': 'valkey', 'port': 6379, 'password': 'x', 'db': 0,  # nosec B105
                        'channel': 'turkeybite'})
        first = on.radius_sessions()
        self.assertIs(on.radius_sessions(), first)
        self.assertEqual(first.key('10.0.0.5'), 'turkeybite:radius:10.0.0.5')
        self.assertEqual(first.redis.connection_pool.connection_kwargs['db'], 0)


class QueueTest(unittest.TestCase):
    """Through the sieve, and in the worker's log."""

    def test_the_sieve_lets_accounting_lines_through(self):
        filters = Filters({})
        self.assertTrue(filters.should_process(nps_event()))
        self.assertFalse(filters.should_process({'type': 'nps'}))
        self.assertFalse(filters.should_process({'type': 'nps', 'message': {'not': 'a line'}}))

    def test_the_log_line_says_whose_address_it_was(self):
        self.assertEqual(describe(nps_event(), 'Queued'),
                         '[NPS][Accounting] Queued: 10.212.16.219 - jsmith@example.edu')
        self.assertEqual(describe({'type': 'nps', 'message': 7}, 'Dropped'), '[NPS][Accounting] Dropped')


if __name__ == '__main__':
    unittest.main()
