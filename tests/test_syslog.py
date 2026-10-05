"""Tests for the syslog client and the processor's syslog output.

A syslog receiver reads the priority in front of each message to decide where
it goes, so the arithmetic has to be right: facility times eight plus level.
And syslog is a second copy of the event, so a syslog failure must cost that
copy and nothing else, not the event's OpenSearch copy and not the process.

The socket is replaced, so nothing is sent anywhere; no test touches the
network.
"""

import io
import json
import os
import socket
import sys
import unittest
from contextlib import redirect_stderr
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'src'))

from libtb import processor as P
from libtb import tbsyslog
from libtb.processor import Processor
from libtb.tbsyslog import Facility, Level, Syslog


class FakeSocket(object):
    """Records what would have been sent, or fails as told."""

    made = []

    def __init__(self, family, kind):
        self.family = family
        self.kind = kind
        self.sent = []
        self.fail = None
        FakeSocket.made.append(self)

    def sendto(self, data, address):
        if self.fail:
            raise self.fail
        self.sent.append((data, address))
        return len(data)


class SyslogTest(unittest.TestCase):

    def setUp(self):
        FakeSocket.made = []
        patcher = mock.patch.object(tbsyslog.socket, 'socket', FakeSocket)
        patcher.start()
        self.addCleanup(patcher.stop)

    def sent(self, log):
        return log.socket.sent

    def test_it_sends_one_udp_datagram_to_the_host_and_port(self):
        log = Syslog(host='graylog.example.edu', port=1514)
        log.send('hello', Level.INFO)
        self.assertEqual((log.socket.family, log.socket.kind),
                         (socket.AF_INET, socket.SOCK_DGRAM))
        self.assertEqual(self.sent(log), [(b'<30>hello', ('graylog.example.edu', 1514))])

    def test_the_defaults_are_localhost_514_and_daemon(self):
        log = Syslog()
        log.send('x', Level.DEBUG)
        self.assertEqual(self.sent(log), [(b'<31>x', ('localhost', 514))])

    def test_the_priority_is_facility_times_eight_plus_level(self):
        for facility, level, priority in ((Facility.KERN, Level.EMERG, 0),
                                          (Facility.DAEMON, Level.INFO, 30),
                                          (Facility.AUTH, Level.CRIT, 34),
                                          (Facility.LOCAL0, Level.INFO, 134),
                                          (Facility.LOCAL7, Level.DEBUG, 191)):
            log = Syslog(facility=facility)
            log.send('m', level)
            self.assertEqual(self.sent(log)[0][0], f'<{priority}>m'.encode(), (facility, level))

    def test_the_shorthand_levels(self):
        log = Syslog()
        log.warn('w')
        log.notice('n')
        log.error('e')
        self.assertEqual([data for data, _ in self.sent(log)], [b'<28>w', b'<29>n', b'<27>e'])

    def test_text_that_is_not_ascii_is_sent_as_utf8(self):
        log = Syslog()
        log.send('café ☕', Level.INFO)
        self.assertEqual(self.sent(log)[0][0], '<30>café ☕'.encode('utf-8'))


class SyslogOutputTest(unittest.TestCase):
    """What the processor sends, and what a failure costs."""

    def setUp(self):
        FakeSocket.made = []
        patcher = mock.patch.object(tbsyslog.socket, 'socket', FakeSocket)
        patcher.start()
        self.addCleanup(patcher.stop)

    def processor(self, opensearch=False):
        return Processor({
            'dns': {'lookup_ips': False},
            'elastic': {'enable': opensearch, 'index_prefix': 'tb-index',
                        'hosts': [{'uri': 'http://search-1:9200', 'username': 'admin',
                                   'password': 'Not-the-default.1'}]},
            'syslog': {'enable': True, 'host': 'graylog.example.edu', 'port': 514}}, {})

    def bite(self):
        return {'@timestamp': '2026-10-04T12:00:00Z', 'bite': {'contexts': ['news']}}

    def test_the_event_is_sent_as_json_at_info(self):
        self.processor().ship_bite(self.bite())
        data, address = FakeSocket.made[-1].sent[0]
        self.assertEqual(address, ('graylog.example.edu', 514))
        self.assertTrue(data.startswith(b'<30>'))
        self.assertEqual(json.loads(data[4:]), self.bite())

    def test_a_failed_send_costs_the_syslog_copy_and_nothing_else(self):
        # A datagram larger than UDP allows is the likeliest real failure
        original = FakeSocket.__init__

        def oversized(sock, family, kind):
            original(sock, family, kind)
            sock.fail = OSError(90, 'Message too long')
        client = mock.Mock()
        err = io.StringIO()
        with mock.patch.object(FakeSocket, '__init__', oversized), \
                mock.patch.object(P, 'opensearch_client', return_value=client), \
                redirect_stderr(err):
            self.processor(opensearch=True).ship_bite(self.bite())
        self.assertIn('Error sending to Syslog', err.getvalue())
        client.index.assert_called_once()

    def test_an_unresolvable_host_is_reported_not_raised(self):
        original = FakeSocket.__init__

        def unresolvable(sock, family, kind):
            original(sock, family, kind)
            sock.fail = socket.gaierror(-2, 'Name or service not known')
        err = io.StringIO()
        with mock.patch.object(FakeSocket, '__init__', unresolvable), redirect_stderr(err):
            self.processor().ship_bite(self.bite())
        self.assertIn('Error sending to Syslog', err.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
