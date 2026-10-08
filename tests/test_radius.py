"""Who held an address, from Windows NPS's RADIUS accounting log.

The lines are shaped as NPS writes them in DTS format, one request to a line,
with made-up people, devices and access points. Times are New York's, as the
NPS servers log them.

The suites run against the in-memory Valkey in fakes.py, which does what
RECORD_SCRIPT does in Python. RealValkeyTest runs the same story against a
real one, to hold the two together: set TB_TEST_VALKEY=redis://host:port/db to
run it, on a database it may empty.
"""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from fakes import FakeRedis
from libtb import radius
from libtb.consumer import Consumer, describe_accounting
from libtb.processor import Processor
from libtb.queue import ListQueue
from libtb.radius import CLOCK_SLACK, MAX_SESSIONS, Sessions
from libtb.sieve import Filters
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError

NEW_YORK = 'America/New_York'
# 22:19:34.212 UTC on 7 October 2026: 18:19:34.212 in New York, which keeps
# summer time until 1 November
LOGGED = datetime(2026, 10, 7, 22, 19, 34, 212000, tzinfo=timezone.utc).timestamp()
RECEIVED = '2026-10-07T22:19:35.000Z'


def nps_line(status='3', user='jsmith@example.edu', address='10.212.16.219', mac='BA-F7-F8-00-00-01',
             session_id='88322DF2520E596E', nas='ap-hall-11', logged='10/07/2026 18:19:34.212',
             event='10/07/2026 22:19:32', session_time='600', packet_type='4', delay='0',
             klass='311 1 10.0.0.10 09/10/2026 07:32:43 9428172', account=None):
    """One request as NPS logs it. None leaves an attribute out."""
    attributes = [
        ('Timestamp', 4, logged), ('Computer-Name', 1, 'NPS-1'), ('Event-Source', 1, 'IAS'),
        ('Acct-Status-Type', 0, status), ('Event-Timestamp', 4, event), ('NAS-IP-Address', 3, '10.200.89.77'),
        ('User-Name', 1, user), ('NAS-Identifier', 1, nas),
        ('Called-Station-Id', 1, '80-95-62-00-00-E5:Example Wireless'),
        ('Vendor-Specific', 2, '000069300106000002BD'), ('Framed-IP-Address', 3, address),
        ('Vendor-Specific', 2, '00006930060600000001'), ('Calling-Station-Id', 1, mac),
        ('Acct-Session-Id', 1, session_id), ('Class', 1, klass), ('Acct-Delay-Time', 0, delay),
        ('Acct-Session-Time', 0, session_time), ('SAM-Account-Name', 1, account),
        ('Packet-Type', 0, packet_type), ('Reason-Code', 0, '0'),
    ]
    return '<Event>' + ''.join(f'<{name} data_type="{kind}">{value}</{name}>'
                               for name, kind, value in attributes if value is not None) + '</Event>'


def accept_line(account='EXAMPLE\\jsmith', user='anonymous@example.edu',
                klass='311 1 10.0.0.10 09/10/2026 07:32:43 9428172'):
    """The Access-Accept NPS logs for a sign-in."""
    return nps_line(status=None, user=user, address=None, session_id=None, session_time=None, delay=None,
                    packet_type='2', klass=klass, account=account)


def nps_event(**kwargs):
    """A line as Filebeat sends it."""
    return {'@timestamp': RECEIVED, 'message': nps_line(**kwargs), 'input': {'type': 'filestream'},
            'host': {'name': 'NPS-1'}}


def dns_event(client='10.212.16.219', when='2026-10-07T22:25:00Z'):
    return {'type': 'dns', 'resource': 'www.example.com',
            'dns': {'question': {'name': 'www.example.com', 'etld_plus_one': 'example.com'}},
            'network': {'direction': 'ingress'}, 'client': {'ip': client}, '@timestamp': when}


def sessions_for(redis, radius_conf, **hooks):
    """Sessions, with the clock at LOGGED unless the test says otherwise."""
    found = Sessions(redis, 'turkeybite', radius_conf)
    for name, value in {'clock': lambda: LOGGED, **hooks}.items():
        setattr(found, name, value)
    return found


def conf(**kwargs):
    """Settings as most of these suites want them, with sessions named by the name given.

    So a test of when an address was held need not sign each session in
    first. DefaultNamesTest has the default.
    """
    return radius.settings({'enable': True, 'timezone': NEW_YORK, 'realms': ['example.edu', 'example'],
                            'trust_given_names': True, **kwargs})


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

    def test_what_is_not_a_person(self):
        # A computer on its own account, a device signing in by its MAC
        # address, an anonymous outer identity, nothing, and what would forge
        # a log line
        for name in ('host/LAB-12.example.edu', 'EXAMPLE\\LAB-12$', 'lab-12$', 'baf7f8000001',
                     'BA-F7-F8-00-00-01', 'anonymous', 'anonymous@example.edu', 'anon@other.edu',
                     '@example.edu', 'EXAMPLE\\', '', '   ', None, 7, 'x' * 300, 'jsmith\nforged'):
            self.assertIsNone(radius.username(name, ('example.edu', 'example')), name)

    def test_the_account_nps_authenticated(self):
        realms = ('example.edu', 'example')
        self.assertEqual(radius.authenticated({'SAM-Account-Name': 'EXAMPLE\\JSmith'}, realms), 'jsmith')
        # NPS spells it without the i
        self.assertEqual(radius.authenticated({'Fully-Qualifed-User-Name': 'EXAMPLE\\jsmith'}, realms), 'jsmith')
        self.assertIsNone(radius.authenticated({'User-Name': 'jsmith@example.edu'}, realms))

    def test_mac_addresses_in_any_usual_form(self):
        for form in ('BA-F7-F8-00-00-01', 'ba:f7:f8:00:00:01', 'baf7f8000001', 'baf7.f800.0001'):
            self.assertEqual(radius.mac(form), 'ba:f7:f8:00:00:01', form)

    def test_what_is_not_a_mac_address(self):
        for bad in ('BA-F7-F8-00-00', 'BA-F7-F8-00-00-01-02', 'not a mac', '', None, 12):
            self.assertIsNone(radius.mac(bad), bad)

    def test_addresses_a_device_can_have(self):
        self.assertEqual(radius.address(' 10.212.16.219 '), '10.212.16.219')
        self.assertEqual(radius.address('::ffff:10.212.16.219'), '10.212.16.219')
        self.assertEqual(radius.address('2001:db8::1'), '2001:db8::1')
        for bad in ('0.0.0.0', '255.255.255.254', '255.255.255.255', '127.0.0.1', '169.254.1.2',  # nosec B104
                    '224.0.0.1', '10.0.0.0/8', 'nonsense', '', None):
            self.assertIsNone(radius.address(bad), bad)

    def test_text_is_made_safe_to_log(self):
        self.assertEqual(radius.printable('jsmith\n[NPS] forged\x1b[0m'), 'jsmith[NPS] forged[0m')
        self.assertEqual(radius.printable(None), '')
        self.assertEqual(len(radius.printable('x' * 1000)), 256)


class LoggedAtTest(unittest.TestCase):
    """NPS's own clock, in its own zone."""

    zone = conf().zone

    def logged(self, logged, event=None, received=None):
        return radius.logged_at({'Timestamp': logged, 'Event-Timestamp': event}, self.zone, received)

    def test_in_summer_time(self):
        self.assertEqual(self.logged('10/07/2026 18:19:34.212'), LOGGED)

    def test_in_winter_time(self):
        self.assertEqual(self.logged('12/07/2026 18:19:34'),
                         datetime(2026, 12, 7, 23, 19, 34, tzinfo=timezone.utc).timestamp())

    def test_without_the_read_time_the_repeated_hour_is_read_by_the_access_points_clock(self):
        # 1:30 comes twice on 1 November 2026: at 05:30 and 06:30 UTC
        first = datetime(2026, 11, 1, 5, 30, tzinfo=timezone.utc).timestamp()
        second = datetime(2026, 11, 1, 6, 30, tzinfo=timezone.utc).timestamp()
        self.assertEqual(self.logged('11/01/2026 01:30:00', '11/01/2026 05:29:58'), first)
        self.assertEqual(self.logged('11/01/2026 01:30:00', '11/01/2026 06:29:58'), second)
        self.assertEqual(self.logged('11/01/2026 01:30:00'), first)

    def test_but_first_by_when_filebeat_read_it(self):
        first = datetime(2026, 11, 1, 5, 30, tzinfo=timezone.utc).timestamp()
        second = datetime(2026, 11, 1, 6, 30, tzinfo=timezone.utc).timestamp()
        self.assertEqual(self.logged('11/01/2026 01:30:00', received=second + 2), second)
        self.assertEqual(self.logged('11/01/2026 01:30:00', received=first + 2), first)
        # Whatever an access point's clock an hour and three-quarters out says
        self.assertEqual(self.logged('11/01/2026 01:30:00', '11/01/2026 04:48:00', received=second + 2), second)
        # But Filebeat catching up hours later leaves it to the access point's
        self.assertEqual(self.logged('11/01/2026 01:30:00', '11/01/2026 05:29:58', received=second + 4 * 3600),
                         first)

    def test_the_access_points_clock_is_not_otherwise_believed(self):
        # One was seen to be an hour and three-quarters out
        self.assertEqual(self.logged('10/07/2026 18:19:34.212', '10/07/2026 20:37:35'), LOGGED)

    def test_without_its_own_time_or_zone_a_line_has_none(self):
        self.assertIsNone(self.logged(None, '10/07/2026 22:19:32'))
        self.assertIsNone(self.logged('7 October 2026'))
        self.assertIsNone(radius.logged_at({'Timestamp': '10/07/2026 18:19:34'}, None))


class SessionTest(unittest.TestCase):

    def session(self, **kwargs):
        return radius.session(radius.attributes(nps_line(**kwargs)), conf().zone, None, ('example.edu',))

    def test_an_interim_update_reports_who_held_the_address_since_when(self):
        got = self.session()
        self.assertEqual(got.address, '10.212.16.219')
        self.assertEqual(got.user, 'jsmith')
        self.assertEqual(got.mac, 'ba:f7:f8:00:00:01')
        self.assertEqual((got.start, got.seen, got.stopped), (LOGGED - 600, LOGGED, None))
        self.assertEqual(got.key, 'ap-hall-11|88322DF2520E596E')
        self.assertEqual(got.klass, '311 1 10.0.0.10 09/10/2026 07:32:43 9428172')

    def test_a_late_report_is_dated_when_it_was_sent(self):
        got = self.session(delay='30')
        self.assertEqual((got.start, got.seen), (LOGGED - 630, LOGGED - 30))

    def test_a_start_and_a_stop(self):
        self.assertEqual(self.session(status='1', session_time=None).start, LOGGED)
        stop = self.session(status='2', session_time='14')
        self.assertEqual((stop.start, stop.stopped), (LOGGED - 14, LOGGED))

    def test_a_report_without_an_address_still_names_the_device(self):
        got = self.session(status='1', address=None)
        self.assertEqual((got.address, got.mac), (None, 'ba:f7:f8:00:00:01'))

    def test_a_name_that_is_not_a_person_is_left_for_the_sign_in_to_say(self):
        self.assertIsNone(self.session(user='anonymous@example.edu').user)

    def test_requests_that_say_nothing_about_a_session(self):
        # Accounting on and off, an authentication request, and lines with no
        # session, no time, or neither an address nor a device
        for kwargs in ({'status': '7'}, {'status': '8'}, {'status': None}, {'packet_type': '1'},
                       {'packet_type': None}, {'session_id': None}, {'logged': None},
                       {'address': None, 'mac': None}, {'address': '0.0.0.0', 'mac': 'unknown'}):  # nosec B104
            self.assertIsNone(self.session(**kwargs), kwargs)

    def test_a_session_too_long_to_believe_counts_from_its_report(self):
        self.assertEqual(self.session(session_time=str(10 ** 9)).start, LOGGED)


class SettingsTest(unittest.TestCase):

    def test_off_unless_turned_on(self):
        self.assertEqual(radius.settings(None), radius.DEFAULT)
        self.assertFalse(radius.settings({}).enable)

    def test_what_is_set(self):
        got = radius.settings({'enable': True, 'timezone': NEW_YORK, 'realms': ['Example.EDU', 'EXAMPLE'],
                               'grace_sec': 900, 'keep_hours': 48, 'cache_sec': 0, 'trust_given_names': True})
        self.assertEqual(got._replace(zone=None), radius.Settings(True, None, ('example.edu', 'example'), 900,
                                                                  48 * 3600, 0, True))
        self.assertFalse(radius.settings({'enable': True, 'timezone': NEW_YORK}).trust_names)
        self.assertEqual(radius.settings({}).cache_sec, 5)
        self.assertIsNotNone(got.zone)

    def test_mistakes_stop_the_worker(self):
        for bad in ([], {'enabled': True}, {1: True}, {'enable': 'yes'}, {'enable': True},
                    {'enable': True, 'timezone': 'Mars/Olympus'}, {'timezone': ''},
                    {'realms': 'example.edu'}, {'realms': ['']}, {'grace_sec': 10}, {'grace_sec': True},
                    {'keep_hours': 0}, {'keep_hours': '24'}, {'cache_sec': -1},
                    {'grace_sec': 7200, 'keep_hours': 1}, {'trust_given_names': 'yes'}):
            with self.assertRaises(ValueError, msg=bad):
                radius.settings(bad)

    def test_the_processor_checks_them_as_it_starts(self):
        with self.assertRaises(ValueError):
            Processor({'radius': {'enable': True}}, {})


class SessionsTest(unittest.TestCase):
    """What a worker records, and who it says held an address."""

    def setUp(self):
        self.redis = FakeRedis()
        self.now = 0.0
        self.warned = []
        self.sessions = sessions_for(self.redis, conf(), monotonic=lambda: self.now, warn=self.warned.append)

    def take(self, line, received=None):
        self.sessions._nobody.clear()
        return self.sessions.take(line, received)

    def holder(self, when, where='10.212.16.219'):
        self.sessions._nobody.clear()
        held = self.sessions.holder(where, when)
        return held and held['u']

    def test_a_session_holds_its_address_from_start_until_grace_after_its_last_report(self):
        self.take(nps_line())
        for when in (LOGGED - 600 - CLOCK_SLACK, LOGGED - 600, LOGGED, LOGGED + 1200):
            self.assertEqual(self.holder(when), 'jsmith', when)
        for when in (LOGGED - 600 - CLOCK_SLACK - 1, LOGGED + 1200 + 1):
            self.assertIsNone(self.holder(when), when)
        self.assertIsNone(self.holder(LOGGED, '10.212.16.220'))

    def test_once_stopped_the_address_is_nobodys(self):
        # Alice stops; DHCP gives the address to Bob, whose access point
        # reports it only at his first interim update. Until then his
        # lookups are nobody's, not Alice's.
        self.take(nps_line(user='alice@example.edu', status='2', session_time='300', klass=None))
        self.assertEqual(self.holder(LOGGED), 'alice')
        self.assertIsNone(self.holder(LOGGED + 1))
        self.assertIsNone(self.holder(LOGGED + 8 * 60))

    def test_a_roaming_phone_keeps_its_address_and_its_person(self):
        self.take(nps_line(status='2', logged='10/07/2026 18:19:34.212', klass=None))
        # The new access point's start comes without an address
        roamed = self.take(nps_line(status='1', address=None, nas='ap-hall-12', session_id='AA01',
                                    logged='10/07/2026 18:19:36.000', session_time=None, klass=None))
        self.assertEqual(roamed.address, '10.212.16.219')
        self.assertEqual(self.holder(LOGGED + 8 * 60), 'jsmith')

    def test_a_phone_back_after_its_address_went_to_another_is_not_given_it(self):
        # Alice stops; Bob gets her address and is reported with it; Alice
        # comes back, her start without an address. Bob's lookups stay Bob's.
        self.take(nps_line(user='alice@example.edu', status='2', klass=None))
        self.take(nps_line(user='bob@example.edu', mac='BA-F7-F8-00-00-02', session_id='B1', session_time='30',
                           logged='10/07/2026 18:20:30.000', klass=None))
        self.assertIsNone(self.take(nps_line(user='alice@example.edu', status='1', address=None,
                                             session_id='A2', session_time=None,
                                             logged='10/07/2026 18:21:00.000', klass=None)))
        self.assertEqual(self.holder(LOGGED + 5 * 60), 'bob')

    def test_another_device_reported_with_the_address_since_beats_a_roam(self):
        record = self.sessions.record
        record(radius.Session('10.0.0.5', 'ap|1', 'bob', 'b', 1000, 1600, None, None))
        record(radius.Session('10.0.0.5', 'ap|2', 'alice', 'a', 1500, 1500, None, None, bridged=True,
                              reported=1400))
        self.assertEqual(self.holder(1550, '10.0.0.5'), 'bob')
        # Until the roamed session reports the address itself: from then, the later start wins
        record(radius.Session('10.0.0.5', 'ap|2', 'alice', 'a', 1500, 1700, None, None))
        self.assertEqual(self.holder(1690, '10.0.0.5'), 'alice')

    def test_but_a_stale_session_from_before_does_not(self):
        # Bob's last report on the address is at 18:19 and he never stops;
        # Alice reports it until 18:25, then roams at 18:31
        self.take(nps_line(user='bob@example.edu', mac='BA-F7-F8-00-00-02', session_id='B1', session_time='600',
                           klass=None))
        self.take(nps_line(user='alice@example.edu', session_id='A1', session_time='60', status='2', klass=None,
                           logged='10/07/2026 18:25:34.212'))
        self.take(nps_line(user='alice@example.edu', session_id='A2', address=None, status='1',
                           session_time=None, klass=None, logged='10/07/2026 18:27:00.000'))
        self.assertEqual(self.holder(LOGGED + 14 * 60), 'alice')

    def test_a_roam_keeps_its_device_and_starts_either_side_of_the_last_report(self):
        self.take(nps_line(status='2', klass=None))
        device = 'turkeybite:radius:mac:ba:f7:f8:00:00:01'
        self.redis.ttls[device] = 5
        # A make-before-break roam: the new session started before the old stopped
        roamed = self.take(nps_line(status='1', address=None, session_id='AA01', session_time=None, klass=None,
                                    logged='10/07/2026 18:19:34.212', delay='100'))
        self.assertEqual(roamed.address, '10.212.16.219')
        self.assertEqual(self.redis.ttls[device], 1200)

    def test_a_phone_roaming_again_keeps_its_person(self):
        self.take(nps_line(status='2', klass=None))
        # Through a second access point that never reports the address, to a third
        self.take(nps_line(status='1', address=None, nas='ap-hall-12', session_id='AA01', session_time=None,
                           logged='10/07/2026 18:19:36.212', klass=None))
        self.take(nps_line(status='2', address=None, nas='ap-hall-12', session_id='AA01', session_time='900',
                           logged='10/07/2026 18:34:36.212', klass=None))
        third = self.take(nps_line(status='1', address=None, nas='ap-hall-13', session_id='AA02',
                                   session_time=None, logged='10/07/2026 18:34:40.212', klass=None))
        self.assertEqual(third.address, '10.212.16.219')
        self.assertEqual(self.holder(LOGGED + 16 * 60), 'jsmith')

    def test_a_roam_stays_overruled_after_the_device_that_took_the_address_stops(self):
        record = self.sessions.record
        record(radius.Session('10.0.0.5', 'ap|2', 'alice', 'a', 1000, 1000, None, None, bridged=True,
                              reported=950))
        # Bob is reported with the address after Alice's device last was, then stops
        record(radius.Session('10.0.0.5', 'ap|1', 'bob', 'b', 1100, 1200, 1200, None))
        self.assertIsNone(self.holder(1500, '10.0.0.5'))

    def test_but_not_one_seen_too_long_ago(self):
        self.take(nps_line(status='2', klass=None))
        self.assertIsNone(self.take(nps_line(status='1', address=None, session_id='AA01', session_time=None,
                                             logged='10/07/2026 18:49:34.212', klass=None)))
        self.assertIsNone(self.take(nps_line(status='1', address=None, mac=None, session_id='AA02',
                                             session_time=None, klass=None)))

    def test_the_account_nps_signed_in_is_believed_over_the_name_given(self):
        # The outer identity is anonymous, or set to someone else's name
        self.take(accept_line(account='EXAMPLE\\jsmith'))
        self.assertEqual(self.take(nps_line(user='anonymous@example.edu')).user, 'jsmith')
        self.assertEqual(self.take(nps_line(user='dean@example.edu', session_id='B2')).user, 'jsmith')

    def test_once_signed_in_no_name_a_device_gives_replaces_the_account(self):
        self.take(accept_line(account='EXAMPLE\\jsmith'))
        self.take(nps_line(user='anonymous@example.edu', logged='10/07/2026 18:09:34.212', session_time='0'))
        # The sign-in is forgotten, and the device now says it is the dean
        self.redis.delete('turkeybite:radius:class:311 1 10.0.0.10 09/10/2026 07:32:43 9428172')
        self.take(nps_line(user='dean@example.edu'))
        self.assertEqual(self.holder(LOGGED), 'jsmith')
        self.assertEqual(self.holder(LOGGED - 600), 'jsmith')

    def test_a_sign_in_in_use_is_kept(self):
        self.take(accept_line())
        key = 'turkeybite:radius:class:311 1 10.0.0.10 09/10/2026 07:32:43 9428172'
        self.redis.ttls[key] = 5
        self.take(nps_line())
        self.assertEqual(self.redis.ttls[key], 24 * 3600)

    def test_lines_without_a_class_are_said_to_be_named_by_the_device(self):
        self.take(nps_line(klass=None))
        self.assertIn('carry no Class', self.warned[0])
        self.assertEqual(self.holder(LOGGED), 'jsmith')

    def test_a_line_dated_after_it_was_read_says_the_timezone_is_wrong(self):
        # NPS in Berlin, read as New York's: six hours in the future
        said = []
        self.sessions.warn = lambda message: None if message in said else said.append(message)
        for minute in range(3):
            self.assertIsNone(self.take(nps_line(logged=f'10/08/2026 00:1{minute}:34.212'), received=LOGGED + 1))
        self.warned = said
        self.assertEqual(len(said), 1)
        self.assertIn('processor.radius.timezone', self.warned[0])
        self.assertEqual(self.redis.data, {})

    def test_a_zone_west_of_the_servers_is_said_too(self):
        # NPS in Chicago, read as New York's: an hour early, and recorded
        self.assertIsNotNone(self.take(nps_line(logged='10/07/2026 17:19:34.212', event='10/07/2026 22:19:33'),
                                       received=LOGGED + 1))
        self.assertIn('whole number of hours', self.warned[0])

    def test_an_access_point_merely_out_is_not(self):
        self.take(nps_line(event='10/07/2026 20:37:35'), received=LOGGED + 1)
        self.assertEqual(self.warned, [])

    def test_nor_one_that_held_its_accounting_an_hour(self):
        self.assertIsNotNone(self.take(nps_line(delay='3600', event='10/07/2026 21:19:34'), received=LOGGED + 1))
        self.assertEqual(self.warned, [])

    def test_a_session_id_reused_after_its_stop_is_a_new_session(self):
        self.take(nps_line(user='alice@example.edu', status='2', session_time='300', klass=None,
                           logged='10/07/2026 18:09:34.212'))
        self.take(nps_line(user='bob@example.edu', session_time='0', klass=None))
        self.assertEqual(self.holder(LOGGED + 60), 'bob')

    def test_a_devices_address_is_its_newest_report(self):
        self.take(nps_line(klass=None))
        self.take(nps_line(address='10.212.16.220', logged='10/07/2026 18:09:34.212', session_time='0',
                           session_id='OLD', klass=None))
        self.assertEqual(json.loads(self.redis.get('turkeybite:radius:mac:ba:f7:f8:00:00:01'))['a'],
                         '10.212.16.219')

    def test_without_the_sign_in_the_name_given_is_used_if_a_persons(self):
        self.assertEqual(self.take(nps_line(klass=None)).user, 'jsmith')
        self.assertIsNone(self.take(nps_line(user='anonymous@example.edu', session_id='B2')).user)
        self.assertIsNone(self.take(accept_line(account=None)))

    def test_reports_handled_out_of_order_do_not_move_a_session_back(self):
        self.take(nps_line(logged='10/07/2026 18:29:34.212', session_time='1200'))
        self.take(nps_line(status='2', logged='10/07/2026 18:31:34.212', session_time='1320'))
        # A replayed interim from before both
        self.take(nps_line(logged='10/07/2026 18:19:34.212', session_time='600'))
        held = self.sessions.holder('10.212.16.219', LOGGED)
        self.assertEqual((held['s'], held['l'], held['e']), (LOGGED - 600, LOGGED + 720, LOGGED + 720))

    def test_lines_older_than_keep_hours_are_not_recorded(self):
        self.assertIsNone(self.take(nps_line(logged='10/05/2026 18:19:34.212')))
        self.assertEqual(self.redis.data, {})

    def test_it_is_kept_in_valkey_for_keep_hours_and_the_device_for_grace(self):
        self.take(nps_line())
        self.assertEqual(self.redis.ttls['turkeybite:radius:ip:10.212.16.219'], 24 * 3600)
        self.assertEqual(self.redis.ttls['turkeybite:radius:mac:ba:f7:f8:00:00:01'], 1200)
        self.assertEqual(self.take(accept_line()), 'jsmith')
        self.assertEqual(self.redis.ttls['turkeybite:radius:class:311 1 10.0.0.10 09/10/2026 07:32:43 9428172'],
                         24 * 3600)

    def test_an_address_keeps_its_latest_sessions(self):
        for n in range(MAX_SESSIONS + 3):
            self.sessions.record(radius.Session('10.0.0.5', f'ap|{n}', f'user{n}', None, n * 100, n * 100 + 50,
                                                None, None))
        held = self.redis.hgetall('turkeybite:radius:ip:10.0.0.5')
        self.assertEqual(len(held), MAX_SESSIONS)
        self.assertNotIn(b'ap|0', held)
        self.assertIn(f'ap|{MAX_SESSIONS + 2}'.encode(), held)

    def test_the_later_session_wins_and_ties_go_one_way(self):
        record = self.sessions.record
        record(radius.Session('10.0.0.5', 'ap|1', 'jsmith', None, 1000, 1600, None, None))
        record(radius.Session('10.0.0.5', 'ap|2', 'adoe', None, 1500, 1700, None, None))
        self.assertEqual(self.holder(1690, '10.0.0.5'), 'adoe')
        self.assertEqual(self.holder(1200, '10.0.0.5'), 'jsmith')
        record(radius.Session('10.0.0.5', 'ap|3', 'bkim', None, 1500, 1700, None, None))
        self.assertEqual(self.holder(1690, '10.0.0.5'), 'bkim')

    def test_a_session_past_its_last_report_loses_to_the_new_holder(self):
        # Alice's last report is at 18:19:34 and her stop was lost; Bob's
        # first report, at 18:34:34, says his session started at 18:24:34
        self.take(nps_line(user='alice@example.edu', klass=None))
        self.take(nps_line(user='bob@example.edu', mac='BA-F7-F8-00-00-02', session_id='B1', klass=None,
                           logged='10/07/2026 18:34:34.212', session_time='600'))
        self.assertEqual(self.holder(LOGGED + 6 * 60), 'bob')
        self.assertEqual(self.holder(LOGGED + 10 * 60), 'bob')
        self.assertEqual(self.holder(LOGGED), 'alice')

    def test_old_sessions_are_dropped_as_new_ones_are_recorded(self):
        record = self.sessions.record
        record(radius.Session('10.0.0.5', 'ap|old', 'old', None, 1000, 1000, None, None))
        record(radius.Session('10.0.0.5', 'ap|new', 'new', None, 100000, 100000, None, None))
        self.assertEqual(list(self.redis.hgetall('turkeybite:radius:ip:10.0.0.5')), [b'ap|new'])

    def test_a_hold_only_inferred_from_its_start_loses_to_one_reported(self):
        # Bob was reported with the address at 1600; Alice's session started
        # at 1500 but was first reported with it at 1700
        record = self.sessions.record
        record(radius.Session('10.0.0.5', 'ap|1', 'bob', 'b', 1000, 1600, None, None))
        record(radius.Session('10.0.0.5', 'ap|2', 'alice', 'a', 1500, 1700, None, None))
        self.assertEqual(self.holder(1550, '10.0.0.5'), 'bob')
        # Alone, an inferred hold still counts, for a backlog of DNS events
        record(radius.Session('10.0.0.6', 'ap|3', 'carol', 'c', 1500, 1700, None, None))
        self.assertEqual(self.holder(1550, '10.0.0.6'), 'carol')

    def test_what_valkey_holds_that_cannot_be_read_is_left_out(self):
        self.redis.hset('turkeybite:radius:ip:10.212.16.219', 'ap|bad', 'not json')
        self.redis.hset('turkeybite:radius:ip:10.212.16.219', 'ap|odd', '{"u": 5, "s": 1, "l": 2}')
        self.take(nps_line())
        self.assertEqual(self.holder(LOGGED), 'jsmith')

    def test_a_worker_remembers_only_that_nobody_held_an_address(self):
        key = ('hgetall', 'turkeybite:radius:ip:10.212.16.219')
        self.sessions.holder('10.212.16.219', LOGGED)
        self.sessions.holder('::ffff:10.212.16.219', LOGGED)
        self.assertEqual(self.redis.calls.count(key), 1)
        self.now += 31
        self.sessions.holder('10.212.16.219', LOGGED)
        self.assertEqual(self.redis.calls.count(key), 2)
        # Who did hold it is asked every time, so another worker's stop counts at once
        self.take(nps_line())
        other = sessions_for(self.redis, conf())
        self.assertEqual(other.holder('10.212.16.219', LOGGED)['u'], 'jsmith')
        self.take(nps_line(status='2', logged='10/07/2026 18:20:34.212', session_time='660'))
        self.assertIsNone(other.holder('10.212.16.219', LOGGED + 120))

    def test_its_own_report_is_seen_at_once(self):
        self.assertIsNone(self.sessions.holder('10.212.16.219', LOGGED))
        self.sessions.take(nps_line())
        self.assertEqual(self.sessions.holder('10.212.16.219', LOGGED)['u'], 'jsmith')


class DefaultNamesTest(unittest.TestCase):
    """As configured by default: only the account NPS signed in names a session."""

    def setUp(self):
        self.redis = FakeRedis()
        self.sessions = sessions_for(self.redis, conf(trust_given_names=False), warn=lambda message: None)

    def holder(self, when, where='10.212.16.219'):
        held = self.sessions.holder(where, when)
        return held and held['u']

    def test_a_session_is_named_only_by_its_sign_in(self):
        # The name the device gives could be anyone's: until the sign-in is
        # seen, the address is held by someone unnamed
        self.assertIsNone(self.sessions.take(nps_line(user='dean@example.edu')).user)
        self.assertEqual(self.holder(LOGGED), '')
        self.sessions.take(accept_line())
        self.sessions.take(nps_line(user='dean@example.edu', logged='10/07/2026 18:29:34.212', session_time='1200'))
        self.assertEqual(self.holder(LOGGED), 'jsmith')

    def test_someone_unnamed_still_holds_the_address_from_the_last_holder(self):
        # Alice's stop was lost; Bob's sign-in was not seen
        self.sessions.take(accept_line())
        self.sessions.take(nps_line())
        self.sessions.take(nps_line(user='bob@example.edu', mac='BA-F7-F8-00-00-02', session_id='B1', klass='B',
                                    logged='10/07/2026 18:34:34.212', session_time='600'))
        self.assertEqual(self.holder(LOGGED + 6 * 60), '')

    def test_a_machine_signing_in_after_logoff_is_not_the_last_user(self):
        # The laptop's user logs off; Windows signs the machine in, under a new Class
        self.sessions.take(accept_line(klass='C1'))
        self.sessions.take(nps_line(klass='C1'))
        self.sessions.take(accept_line(account='EXAMPLE\\LAB-12$', klass='C2'))
        self.sessions.take(nps_line(klass='C2', logged='10/07/2026 18:29:34.212', session_time='1200'))
        self.assertEqual(self.holder(LOGGED + 15 * 60), '')
        # A stop under the session's own Class keeps its name
        self.sessions.take(accept_line(account='EXAMPLE\\jsmith', klass='C3'))
        self.sessions.take(nps_line(klass='C3', session_id='S3', address='10.212.16.230'))
        self.redis.delete('turkeybite:radius:class:C3')
        self.sessions.take(nps_line(klass='C3', session_id='S3', address='10.212.16.230', status='2',
                                    user='anonymous', logged='10/07/2026 18:21:34.212', session_time='720'))
        self.assertEqual(self.holder(LOGGED + 60, '10.212.16.230'), 'jsmith')

    def test_the_same_device_under_the_same_sign_in_is_the_same_person(self):
        # Roamed to a second access point under the same Class, whose account has expired
        self.sessions.take(accept_line(klass='C1'))
        self.sessions.take(nps_line(klass='C1'))
        self.redis.delete('turkeybite:radius:class:C1')
        self.sessions.take(nps_line(klass='C1', nas='ap-hall-12', session_id='N2', logged='10/07/2026 18:21:34.212',
                                    session_time='60'))
        self.assertEqual(self.holder(LOGGED + 3 * 60), 'jsmith')

    def test_a_stop_before_its_sign_in_still_counts(self):
        # The stop is handled first, then the sign-in and an earlier report
        self.sessions.take(nps_line(status='2', logged='10/07/2026 18:21:34.212', session_time='720'))
        self.sessions.take(accept_line())
        self.sessions.take(nps_line())
        self.assertEqual(self.holder(LOGGED + 60), 'jsmith')
        self.assertIsNone(self.holder(LOGGED + 121))

    def test_an_inferred_stop_older_than_a_report_since_is_ignored(self):
        # Another worker recorded a report at the old address after the move was read
        self.sessions.take(accept_line())
        self.sessions.take(nps_line(logged='10/07/2026 18:29:34.212', session_time='1200'))
        self.sessions.record(radius.Session('10.212.16.219', 'ap-hall-11|88322DF2520E596E', None,
                                            'ba:f7:f8:00:00:01', LOGGED - 600, LOGGED, LOGGED + 300, None,
                                            timed=False, moved=True), device=False)
        self.assertEqual(self.holder(LOGGED + 700), 'jsmith')

    def test_a_stop_naming_nobody_still_ends_the_session(self):
        self.sessions.take(accept_line())
        self.sessions.take(nps_line())
        # The sign-in is forgotten, and the stop's outer identity is anonymous
        self.redis.delete('turkeybite:radius:class:311 1 10.0.0.10 09/10/2026 07:32:43 9428172')
        self.sessions.take(nps_line(status='2', user='anonymous@example.edu', logged='10/07/2026 18:21:34.212',
                                    session_time='720'))
        self.assertEqual(self.holder(LOGGED + 60), 'jsmith')
        self.assertIsNone(self.holder(LOGGED + 121))

    def test_and_one_with_no_address_finds_where_the_session_is(self):
        # A session hours old, whose stop gives no address
        self.sessions.take(accept_line())
        self.sessions.take(nps_line(session_time='7200'))
        self.sessions.take(nps_line(status='2', address=None, logged='10/07/2026 18:29:34.212',
                                    session_time='7800'))
        self.assertIsNone(self.holder(LOGGED + 601))

    def test_a_device_given_a_new_address_leaves_its_old_one(self):
        self.sessions.take(accept_line())
        self.sessions.take(nps_line())
        self.sessions.take(nps_line(address='10.212.16.220', logged='10/07/2026 18:24:34.212', session_time='900'))
        self.assertEqual(self.holder(LOGGED + 300, '10.212.16.220'), 'jsmith')
        self.assertEqual(self.holder(LOGGED + 299), 'jsmith')
        self.assertIsNone(self.holder(LOGGED + 301))

    def test_a_device_moved_and_back_holds_its_first_address_again(self):
        self.sessions.take(accept_line())
        self.sessions.take(nps_line())
        self.sessions.take(nps_line(address='10.212.16.220', logged='10/07/2026 18:24:34.212', session_time='900'))
        self.sessions.take(nps_line(logged='10/07/2026 18:29:34.212', session_time='1200'))
        self.assertEqual(self.holder(LOGGED + 720), 'jsmith')
        self.assertIsNone(self.holder(LOGGED + 720, '10.212.16.220'))

    def test_a_late_stop_at_the_old_address_does_not_lengthen_the_hold(self):
        # Moved to .220 at 18:24; the old access point's stop for .219 lands at 18:34
        self.sessions.take(accept_line())
        self.sessions.take(nps_line())
        self.sessions.take(nps_line(address='10.212.16.220', logged='10/07/2026 18:24:34.212', session_time='900'))
        self.sessions.take(nps_line(status='2', logged='10/07/2026 18:34:34.212', session_time='1500'))
        held = self.sessions.holder('10.212.16.219', LOGGED)
        self.assertEqual((held['e'], held['l']), (LOGGED + 300, LOGGED))
        self.assertIsNone(self.holder(LOGGED + 11 * 60))

    def test_a_late_stop_from_the_access_point_it_left_does_not_move_it_back(self):
        # Walking between buildings: the new access point reports .220 at 18:21,
        # the old one's idle-timeout stop for .219 lands at 18:34
        self.sessions.take(accept_line())
        self.sessions.take(nps_line())
        self.sessions.take(nps_line(address='10.212.16.220', nas='ap-hall-12', session_id='N2',
                                    logged='10/07/2026 18:21:34.212', session_time='60'))
        self.sessions.take(nps_line(status='2', logged='10/07/2026 18:34:34.212', session_time='1500'))
        self.assertEqual(self.holder(LOGGED + 17 * 60, '10.212.16.220'), 'jsmith')
        self.assertEqual(json.loads(self.redis.get('turkeybite:radius:mac:ba:f7:f8:00:00:01'))['a'],
                         '10.212.16.220')
        # Nor one that does not say how long its session was
        self.sessions.take(nps_line(status='2', logged='10/07/2026 18:35:34.212', session_time=None,
                                    session_id='OLD2'))
        self.assertEqual(self.holder(LOGGED + 17 * 60, '10.212.16.220'), 'jsmith')
        self.assertEqual(json.loads(self.redis.get('turkeybite:radius:mac:ba:f7:f8:00:00:01'))['a'],
                         '10.212.16.220')

    def test_a_short_session_whose_only_address_is_in_its_stop_moves_the_device(self):
        # Walking through buildings, each access point's session shorter than
        # the interim interval: a start without an address, then a stop with one
        self.sessions.take(accept_line())
        self.sessions.take(nps_line(status='2'))
        self.sessions.take(nps_line(status='1', address=None, nas='ap-hall-12', session_id='N2', session_time=None,
                                    logged='10/07/2026 18:19:40.212'))
        self.sessions.take(nps_line(status='2', address='10.212.16.220', nas='ap-hall-12', session_id='N2',
                                    session_time='300', logged='10/07/2026 18:24:40.212'))
        third = self.sessions.take(nps_line(status='1', address=None, nas='ap-hall-13', session_id='N3',
                                            session_time=None, logged='10/07/2026 18:24:45.212'))
        self.assertEqual(third.address, '10.212.16.220')
        self.assertEqual(self.holder(LOGGED + 8 * 60, '10.212.16.220'), 'jsmith')
        self.assertIsNone(self.holder(LOGGED + 8 * 60))

    def test_a_start_handled_after_an_interim_without_session_time_is_kept(self):
        self.sessions.take(accept_line())
        self.sessions.take(nps_line(session_time=None, logged='10/07/2026 18:29:34.212'))
        self.sessions.take(nps_line(status='1', session_time=None))
        self.assertEqual(self.sessions.holder('10.212.16.219', LOGGED + 600)['s'], LOGGED)

    def test_a_stop_without_its_session_time_still_ends_the_session(self):
        self.sessions.take(accept_line())
        self.sessions.take(nps_line())
        self.redis.delete('turkeybite:radius:class:311 1 10.0.0.10 09/10/2026 07:32:43 9428172')
        self.sessions.take(nps_line(status='2', user='anonymous@example.edu', session_time=None,
                                    logged='10/07/2026 18:24:34.212'))
        self.assertIsNone(self.holder(LOGGED + 301))

    def test_a_late_report_from_an_earlier_session_with_the_id_is_ignored(self):
        self.sessions.take(accept_line(account='EXAMPLE\\carol', klass='C2'))
        self.sessions.take(nps_line(klass='C2', logged='10/07/2026 18:19:34.212', session_time='60'))
        # Bob's stop, from when the id was his, arrives after
        self.sessions.take(accept_line(account='EXAMPLE\\bob', klass='C1'))
        self.sessions.take(nps_line(klass='C1', status='2', logged='10/07/2026 17:00:00.000', session_time='600'))
        held = self.sessions.holder('10.212.16.219', LOGGED)
        self.assertEqual(held['u'], 'carol')
        self.assertNotIn('e', held)

    def test_a_session_id_reused_after_a_lost_stop_is_a_new_session(self):
        self.sessions.take(accept_line(account='EXAMPLE\\bob', klass='C1'))
        self.sessions.take(nps_line(klass='C1', logged='10/07/2026 17:00:00.000', session_time='600'))
        self.sessions.take(accept_line(account='EXAMPLE\\carol', klass='C2'))
        self.sessions.take(nps_line(klass='C2', session_time='60'))
        held = self.sessions.holder('10.212.16.219', LOGGED)
        self.assertEqual((held['u'], held['s']), ('carol', LOGGED - 60))


class ProcessorTest(unittest.TestCase):
    """DNS events naming the person."""

    def processor(self, radius_conf):
        processor = Processor({'dns': {'lookup_ips': False}, 'domain_index': {'mode': 'index'},
                               'radius': radius_conf}, {'channel': 'turkeybite'})
        processor.ship_bite = self.shipped.append
        processor.resolve_contexts = lambda s, **kwargs: ([], {})
        processor.resolve_chain = lambda c: ([], [], list(c))
        return processor

    def setUp(self):
        self.shipped = []
        self.redis = FakeRedis()
        self.on = self.processor({'enable': True, 'timezone': NEW_YORK, 'realms': ['example.edu', 'example']})
        self.on.sessions = sessions_for(self.redis, self.on._radius)

    def test_a_dns_event_names_who_held_its_address(self):
        self.assertTrue(self.on.process_nps({'message': accept_line()}))
        self.assertTrue(self.on.process_nps(nps_event()))
        self.on.process_packet(dns_event())
        bite = self.shipped[0]['bite']
        self.assertEqual(bite['client'], '10.212.16.219')
        self.assertEqual(bite['client_user'], 'jsmith')
        self.assertEqual(bite['client_mac'], 'ba:f7:f8:00:00:01')

    def test_a_session_nobody_was_named_for_gives_the_device_only(self):
        self.on.process_nps(nps_event())
        self.on.process_packet(dns_event())
        bite = self.shipped[0]['bite']
        self.assertNotIn('client_user', bite)
        self.assertEqual(bite['client_mac'], 'ba:f7:f8:00:00:01')

    def test_an_address_nobody_held_then_is_left_as_it_was(self):
        self.on.process_nps(nps_event())
        self.on.process_packet(dns_event(when='2026-10-08T09:00:00Z'))
        self.on.process_packet(dns_event(client='10.212.16.220'))
        for shipped in self.shipped:
            self.assertNotIn('client_user', shipped['bite'])
            self.assertNotIn('client_mac', shipped['bite'])

    def test_a_session_without_a_mac_names_only_the_person(self):
        self.on.process_nps({'message': accept_line()})
        self.on.process_nps(nps_event(mac=None))
        self.on.process_packet(dns_event())
        self.assertEqual(self.shipped[0]['bite']['client_user'], 'jsmith')
        self.assertNotIn('client_mac', self.shipped[0]['bite'])

    def test_an_event_whose_time_cannot_be_read_gets_nobody(self):
        # The address may have changed hands since
        self.on.sessions.record(radius.Session('10.212.16.219', 'ap|1', 'jsmith', None, LOGGED, 4102444800.0,
                                               None, None))
        self.on.process_packet(dns_event(when='yesterday'))
        self.assertNotIn('client_user', self.shipped[0]['bite'])

    def test_valkey_refusing_costs_the_user_not_the_event(self):
        self.on.sessions.holder = mock.Mock(side_effect=ResponseError('NOPERM'))
        with redirect_stderr(io.StringIO()), mock.patch('libtb.processor.report_once') as said:
            self.on.process_packet(dns_event())
        self.assertNotIn('client_user', self.shipped[0]['bite'])
        self.assertTrue(said.call_args[0][0].endswith('without a user: ResponseError'))

    def test_valkey_not_answering_is_left_to_the_consumer(self):
        self.on.sessions.holder = mock.Mock(side_effect=RedisConnectionError('gone'))
        with self.assertRaises(RedisConnectionError):
            self.on.process_packet(dns_event())

    def test_off_it_does_nothing(self):
        off = self.processor(None)
        self.assertIsNone(off.radius_sessions())
        self.assertFalse(off.process_nps(nps_event()))
        off.process_packet(dns_event())
        self.assertNotIn('client_user', self.shipped[0]['bite'])

    def test_on_it_connects_to_the_queues_valkey_once_a_process(self):
        on = Processor({'radius': {'enable': True, 'timezone': NEW_YORK}},
                       {'host': 'valkey', 'port': 6379, 'password': 'x', 'db': 0,  # nosec B105
                        'channel': 'turkeybite'})
        first = on.radius_sessions()
        self.assertIs(on.radius_sessions(), first)
        self.assertEqual(first.key('ip', '10.0.0.5'), 'turkeybite:radius:ip:10.0.0.5')
        self.assertEqual(first.redis.connection_pool.connection_kwargs['db'], 0)
        # A forked child makes its own
        with mock.patch('libtb.processor.os.getpid', return_value=os.getpid() + 1):
            self.assertIsNot(on.radius_sessions(), first)


class ConsumerTest(unittest.TestCase):
    """The accounting list, drained before each batch."""

    def setUp(self):
        self.redis = FakeRedis()
        self.queue = ListQueue(self.redis, 'turkeybite', 'worker1-01')
        self.shipped = []

    def consumer(self, radius_conf):
        processor = Processor({'dns': {'lookup_ips': False}, 'domain_index': {'mode': 'index'},
                               'radius': radius_conf}, {'channel': 'turkeybite'})
        processor.ship_bite = self.shipped.append
        processor.resolve_contexts = lambda s, **kwargs: ([], {})
        processor.resolve_chain = lambda c: ([], [], list(c))
        processor.flush_bulk = lambda **kwargs: 0
        if radius_conf:
            processor.sessions = sessions_for(self.redis, processor._radius)
        return Consumer(self.queue, Filters({'drop_error_packets': False, 'drop_replies': True,
                                             'ignore': {'clients': [], 'domains': [], 'hosts': []}}),
                        processor, block_seconds=0.01, name='worker1-01', sleep=lambda s: None)

    def run_once(self, consumer):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            consumer.run_once()
        return out.getvalue()

    def test_lines_are_recorded_before_the_dns_events_they_name(self):
        self.redis.rpush('turkeybite:nps', json.dumps({'message': accept_line()}), json.dumps(nps_event()),
                         'not json')
        self.queue.push(json.dumps(dns_event()))
        consumer = self.consumer({'enable': True, 'timezone': NEW_YORK, 'realms': ['example.edu', 'example']})
        log = self.run_once(consumer)
        self.assertEqual(self.shipped[0]['bite']['client_user'], 'jsmith')
        self.assertEqual((consumer.stats['accounting'], consumer.stats['unreadable']), (3, 1))
        self.assertIn('[NPS][Accept] Recorded\n', log)
        self.assertIn('[NPS][Accounting] Recorded: 10.212.16.219\n', log)
        self.assertNotIn('jsmith', log)
        self.assertNotIn('turkeybite:nps', self.redis.data)

    def test_off_the_list_is_left_to_workers_with_it_on_and_kept_short(self):
        self.redis.rpush('turkeybite:nps', *(json.dumps(nps_event(session_id=f'S{n}')) for n in range(3)))
        consumer = self.consumer(None)
        with mock.patch('libtb.consumer.ACCOUNTING_KEEP', 2):
            self.run_once(consumer)
        self.assertEqual(consumer.stats['accounting'], 0)
        waiting = [json.loads(raw)['message'] for raw in self.redis.lrange('turkeybite:nps', 0, -1)]
        self.assertEqual(len(waiting), 2)
        self.assertIn('S2', waiting[-1])
        self.assertNotIn('turkeybite:radius:ip:10.212.16.219', self.redis.data)

    def test_valkey_refusing_the_list_does_not_stop_the_dns_events(self):
        self.queue.push(json.dumps(dns_event()))
        consumer = self.consumer({'enable': True, 'timezone': NEW_YORK})
        with mock.patch.object(self.redis, 'lpop', side_effect=ResponseError('WRONGTYPE')), \
                mock.patch('libtb.consumer.report_once') as said:
            self.run_once(consumer)
        self.assertEqual(said.call_args[0][0], 'The accounting list turkeybite:nps could not be read: ResponseError')
        self.assertEqual(len(self.shipped), 1)

    def test_lines_sent_to_the_dns_queue_are_said_to_be_misrouted(self):
        self.queue.push(json.dumps(nps_event()))
        consumer = self.consumer({'enable': True, 'timezone': NEW_YORK})
        with mock.patch('libtb.consumer.report_once') as said:
            self.run_once(consumer)
        self.assertIn('turkeybite:nps', said.call_args[0][0])
        self.assertEqual(consumer.stats['dropped'], 1)

    def test_the_log_line_names_nobody_and_cannot_be_forged(self):
        event = {'message': nps_line(user='jsmith&#10;[NPS][Accounting] Recorded: 10.0.0.1',
                                     address='not an address')}
        self.assertEqual(describe_accounting(event, 'Dropped'), '[NPS][Accounting] Dropped')
        self.assertEqual(describe_accounting({'message': accept_line()}, 'Recorded'), '[NPS][Accept] Recorded')
        self.assertEqual(describe_accounting({'message': nps_line()}, 'Recorded'),
                         '[NPS][Accounting] Recorded: 10.212.16.219')
        # An Access-Accept remembered is recorded, not dropped
        processor = self.consumer({'enable': True, 'timezone': NEW_YORK, 'realms': ['example']}).processor
        self.assertTrue(processor.process_nps({'message': accept_line()}))
        self.assertEqual(describe_accounting([], 'Dropped'), '[NPS][Accounting] Dropped')

    def test_valkey_not_answering_leaves_the_dns_batch_in_flight(self):
        self.queue.push(json.dumps(dns_event()))
        consumer = self.consumer({'enable': True, 'timezone': NEW_YORK})
        consumer.processor.sessions.holder = mock.Mock(side_effect=RedisConnectionError('gone'))
        with self.assertRaises(RedisConnectionError), redirect_stdout(io.StringIO()):
            consumer.run_once()
        self.assertEqual(len(self.queue.recover()), 1)


@unittest.skipUnless(os.environ.get('TB_TEST_VALKEY'), 'set TB_TEST_VALKEY to run against a real Valkey')
class RealValkeyTest(unittest.TestCase):
    """RECORD_SCRIPT in Lua, as the fake does it in Python."""

    def setUp(self):
        from redis import Redis  # pylint: disable=import-outside-toplevel
        self.redis = Redis.from_url(os.environ['TB_TEST_VALKEY'])
        self.redis.flushdb()
        self.addCleanup(self.redis.flushdb)

    @staticmethod
    def story(redis):
        sessions = sessions_for(redis, conf(), warn=lambda message: None)
        # Signed in, out of order, stopped, and the name kept once the sign-in is gone
        sessions.take(accept_line())
        sessions.take(nps_line(user='anonymous@example.edu', logged='10/07/2026 18:29:34.212',
                               session_time='1200'))
        sessions.take(nps_line(status='2', logged='10/07/2026 18:31:34.212', session_time='1320'))
        sessions.take(nps_line(logged='10/07/2026 18:19:34.212', session_time='600'))
        redis.delete('turkeybite:radius:class:311 1 10.0.0.10 09/10/2026 07:32:43 9428172')
        sessions.take(nps_line(user='dean@example.edu', logged='10/07/2026 18:30:34.212', session_time='1260'))
        # A session id reused after its stop
        sessions.take(nps_line(user='bob@example.edu', session_id='R1', status='2', session_time='60',
                               klass=None, mac='BA-F7-F8-00-00-02', logged='10/07/2026 18:00:00.000'))
        sessions.take(nps_line(user='carol@example.edu', session_id='R1', session_time='0', klass=None,
                               mac='BA-F7-F8-00-00-03', logged='10/07/2026 18:20:00.000'))
        # A roam, then the roamed session reporting the address itself
        sessions.take(nps_line(user='dana@example.edu', address='10.212.16.230', status='2', klass=None,
                               mac='BA-F7-F8-00-00-04', session_id='D1'))
        sessions.take(nps_line(user='dana@example.edu', address=None, status='1', session_time=None,
                               klass=None, mac='BA-F7-F8-00-00-04', session_id='D2',
                               logged='10/07/2026 18:20:00.000'))
        bridged = json.loads(redis.hget('turkeybite:radius:ip:10.212.16.230', 'ap-hall-11|D2'))
        bridged['ttl'] = redis.ttl('turkeybite:radius:mac:ba:f7:f8:00:00:04') if hasattr(redis, 'ttl') else 1200
        sessions.take(nps_line(user='dana@example.edu', address='10.212.16.230', session_time='600',
                               klass=None, mac='BA-F7-F8-00-00-04', session_id='D2',
                               logged='10/07/2026 18:30:00.000'))
        # An older report does not move a device's address back
        sessions.take(nps_line(user='dana@example.edu', address='10.212.16.231', session_time='0', klass=None,
                               mac='BA-F7-F8-00-00-04', session_id='D0', logged='10/07/2026 18:10:00.000'))
        for n in range(MAX_SESSIONS + 2):
            sessions.record(radius.Session('10.0.0.5', f'ap|{n}', f'user{n}', None, n * 100, n * 100 + 50,
                                           None, None))
        # Naming nobody: an update to a session recorded, and nothing for one not
        strict = sessions_for(redis, conf(trust_given_names=False), warn=lambda message: None)
        strict.take(accept_line(account='EXAMPLE\\erin', klass='E1'))
        strict.take(nps_line(klass='E1', address='10.212.16.240', mac='BA-F7-F8-00-00-05', session_id='E1'))
        strict.take(nps_line(klass=None, status='2', address='10.212.16.240', mac='', session_id='E1',
                             logged='10/07/2026 18:22:34.212', session_time='780'))
        strict.take(nps_line(klass=None, address='10.212.16.241', session_id='NOBODY'))
        # A late report from an earlier session with the id
        strict.take(nps_line(klass='E1', address='10.212.16.240', session_id='E1', status='2',
                             logged='10/07/2026 17:00:00.000', session_time='60'))
        # Moving to a new address ends the old
        strict.take(accept_line(account='EXAMPLE\\finn', klass='F1'))
        strict.take(nps_line(klass='F1', address='10.212.16.250', mac='BA-F7-F8-00-00-06', session_id='F1'))
        strict.take(nps_line(klass='F1', address='10.212.16.251', mac='BA-F7-F8-00-00-06', session_id='F1',
                             logged='10/07/2026 18:24:34.212', session_time='900'))
        moved = {(k.decode() if isinstance(k, bytes) else k): json.loads(v)
                 for k, v in redis.hgetall('turkeybite:radius:ip:10.212.16.250').items()}
        strict.take(nps_line(klass='F1', address='10.212.16.250', mac='BA-F7-F8-00-00-06', session_id='F1',
                             logged='10/07/2026 18:29:34.212', session_time='1200'))
        strict.take(nps_line(klass=None, status='2', address='10.212.16.250', mac='BA-F7-F8-00-00-06',
                             session_id='F1', user='anonymous', session_time=None,
                             logged='10/07/2026 18:31:34.212'))
        # A late real stop at the old address, and a start after an untimed interim
        strict.take(accept_line(account='EXAMPLE\\gail', klass='G1'))
        strict.take(nps_line(klass='G1', address='10.212.16.252', mac='BA-F7-F8-00-00-07', session_id='G1'))
        strict.take(nps_line(klass='G1', address='10.212.16.253', mac='BA-F7-F8-00-00-07', session_id='G1',
                             logged='10/07/2026 18:24:34.212', session_time='900'))
        strict.take(nps_line(klass='G1', status='2', address='10.212.16.252', mac='BA-F7-F8-00-00-07',
                             session_id='G1', logged='10/07/2026 18:34:34.212', session_time='1500'))
        strict.take(nps_line(klass='G1', address='10.212.16.255', mac='BA-F7-F8-00-00-07', session_id='G2',
                             nas='ap-hall-12', logged='10/07/2026 18:25:34.212', session_time='60'))
        strict.take(nps_line(klass='G1', status='2', address='10.212.16.253', mac='BA-F7-F8-00-00-07',
                             session_id='G1', logged='10/07/2026 18:36:34.212', session_time='1620'))
        # A machine signing in after its user logs off, under a new Class
        strict.take(accept_line(account='EXAMPLE\\hana', klass='M1'))
        strict.take(nps_line(klass='M1', address='10.212.16.202', mac='BA-F7-F8-00-00-0A', session_id='M'))
        strict.take(accept_line(account='EXAMPLE\\LAB-12$', klass='M2'))
        strict.take(nps_line(klass='M2', address='10.212.16.202', mac='BA-F7-F8-00-00-0A', session_id='M',
                             logged='10/07/2026 18:29:34.212', session_time='1200'))
        # A short session whose only address is in its stop moves the device
        strict.take(nps_line(klass='G1', status='2', address='10.212.16.200', mac='BA-F7-F8-00-00-09',
                             session_id='K1'))
        strict.take(nps_line(klass='G1', status='1', address=None, mac='BA-F7-F8-00-00-09', session_id='K2',
                             nas='ap-hall-12', session_time=None, logged='10/07/2026 18:19:40.212'))
        strict.take(nps_line(klass='G1', status='2', address='10.212.16.201', mac='BA-F7-F8-00-00-09',
                             session_id='K2', nas='ap-hall-12', session_time='300',
                             logged='10/07/2026 18:24:40.212'))
        strict.take(nps_line(klass='G1', address='10.212.16.254', mac='BA-F7-F8-00-00-08', session_id='H1',
                             session_time=None, logged='10/07/2026 18:29:34.212'))
        strict.take(nps_line(klass='G1', status='1', address='10.212.16.254', mac='BA-F7-F8-00-00-08',
                             session_id='H1', session_time=None))

        def text(value):
            return value.decode() if isinstance(value, bytes) else value

        def dump(key):
            return {text(k): json.loads(v) for k, v in redis.hgetall(key).items()}
        return (dump('turkeybite:radius:ip:10.212.16.219'), dump('turkeybite:radius:ip:10.212.16.230'), bridged,
                json.loads(redis.get('turkeybite:radius:mac:ba:f7:f8:00:00:04')),
                sorted(text(k) for k in redis.hgetall('turkeybite:radius:ip:10.0.0.5')),
                sessions.holder('10.212.16.219', LOGGED),
                dump('turkeybite:radius:ip:10.212.16.240'), dump('turkeybite:radius:ip:10.212.16.241'),
                moved, dump('turkeybite:radius:ip:10.212.16.250'), dump('turkeybite:radius:ip:10.212.16.251'),
                json.loads(redis.get('turkeybite:radius:mac:ba:f7:f8:00:00:06')),
                dump('turkeybite:radius:ip:10.212.16.252'), dump('turkeybite:radius:ip:10.212.16.254'),
                dump('turkeybite:radius:ip:10.212.16.255'),
                json.loads(redis.get('turkeybite:radius:mac:ba:f7:f8:00:00:07')),
                json.loads(redis.get('turkeybite:radius:mac:ba:f7:f8:00:00:09')),
                dump('turkeybite:radius:ip:10.212.16.200'), dump('turkeybite:radius:ip:10.212.16.202'))

    def test_the_lua_does_what_the_fake_does(self):
        real = self.story(self.redis)
        self.assertEqual(real, self.story(FakeRedis()))
        held = real[0]['ap-hall-11|88322DF2520E596E']
        self.assertEqual((held['u'], held['s'], held['l'], held['e'], held['a']),
                         ('jsmith', LOGGED - 600, LOGGED + 720, LOGGED + 720, 1))
        self.assertEqual(real[0]['ap-hall-11|R1']['u'], 'carol')
        self.assertNotIn('e', real[0]['ap-hall-11|R1'])
        self.assertEqual((real[2].get('b'), real[2].get('r'), real[2]['ttl']), (1, LOGGED, 1200))
        self.assertNotIn('b', real[1]['ap-hall-11|D2'])
        self.assertEqual(real[3]['a'], '10.212.16.230')
        erin = real[6]['ap-hall-11|E1']
        self.assertEqual((erin['u'], erin['e'], erin['m'], erin['a']), ('erin', LOGGED + 180, 'ba:f7:f8:00:00:05', 1))
        self.assertEqual(real[7]['ap-hall-11|NOBODY']['u'], '')
        self.assertEqual((real[8]['ap-hall-11|F1']['e'], real[8]['ap-hall-11|F1']['x']), (LOGGED + 300, 1))
        self.assertEqual((real[9]['ap-hall-11|F1']['e'], real[9]['ap-hall-11|F1']['u']), (LOGGED + 720, 'finn'))
        self.assertNotIn('x', real[9]['ap-hall-11|F1'])
        self.assertEqual(real[10]['ap-hall-11|F1']['x'], 1)
        self.assertEqual(real[11]['a'], '10.212.16.250')
        gail = real[12]['ap-hall-11|G1']
        self.assertEqual((gail['e'], gail['l']), (LOGGED + 300, LOGGED))
        self.assertNotIn('x', gail)
        self.assertEqual((real[13]['ap-hall-11|H1']['s'], real[13]['ap-hall-11|H1']['k']), (LOGGED, 1))
        self.assertNotIn('e', real[14]['ap-hall-12|G2'])
        self.assertEqual(real[15]['a'], '10.212.16.255')
        self.assertEqual(real[16]['a'], '10.212.16.201')
        self.assertEqual(real[17]['ap-hall-12|K2']['x'], 1)
        machine = real[18]['ap-hall-11|M']
        self.assertEqual((machine['u'], machine['c']), ('', 'M2'))
        self.assertNotIn('a', machine)
        self.assertEqual(self.redis.ttl('turkeybite:radius:ip:10.212.16.219'), 24 * 3600)


if __name__ == '__main__':
    unittest.main()
