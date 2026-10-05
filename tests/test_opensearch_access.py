"""Tests for how TurkeyBite reaches OpenSearch.

Verification has to stay off unless a host asks for it, since the bundled
cluster's demo certificates verify against nothing and turning it on by
default would stop every existing install shipping. So what must not happen
is the opposite mistake: a host that asks for verification being connected to
without it, or a host used unverified without anybody being told.

No test touches the network. The client class is replaced by a recorder, and
the librarian's script runs against a fake curl that writes down what it was
asked to do.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'src'))

from libtb import opensearch as O
from libtb import processor as P
from libtb.processor import Processor

TEMPLATE_SCRIPT = os.path.join(ROOT, 'docker', 'librarian', 'setup-opensearch-template.sh')


class Recorder(object):
    """Stands in for opensearchpy.OpenSearch and keeps what it was built with."""

    built = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        Recorder.built.append(kwargs)


def elastic(*hosts, enable=True):
    return {'enable': enable, 'index_prefix': 'tb-index', 'hosts': list(hosts)}


class Isolated(unittest.TestCase):
    """Clears the per-process state these tests read, before and after."""

    def setUp(self):
        for state in (O._warned, P._opensearch_clients):
            state.clear()
            self.addCleanup(state.clear)
        Recorder.built = []
        self.root = tempfile.mkdtemp(prefix='tb-opensearch-')
        self.addCleanup(shutil.rmtree, self.root, True)
        self.ca = os.path.join(self.root, 'root-ca.pem')
        with open(self.ca, 'w') as fh:
            fh.write('-----BEGIN CERTIFICATE-----\n')

    def processor(self, *hosts, enable=True):
        """A Processor over these hosts, and the warnings it logged."""
        with mock.patch('sys.stderr') as stderr:
            processor = Processor({'elastic': elastic(*hosts, enable=enable)}, {})
        logged = ''.join(call.args[0] for call in stderr.write.call_args_list)
        return processor, logged


class ClientSettingsTest(Isolated):
    """What reaches the OpenSearch client."""

    def client(self, host):
        with mock.patch.object(P, 'OpenSearch', Recorder):
            P.opensearch_client(host)
        return Recorder.built[-1]

    def test_a_host_that_asks_for_verification_gets_it(self):
        kwargs = self.client({'uri': 'https://opensearch:9200', 'username': 'admin',
                              'password': 'x', 'verify_certs': True, 'ca_certs': self.ca})
        self.assertIs(kwargs['verify_certs'], True)
        self.assertEqual(kwargs['ca_certs'], self.ca)
        self.assertEqual(kwargs['hosts'], [{'host': 'opensearch', 'port': 9200}])
        self.assertEqual(kwargs['http_auth'], ('admin', 'x'))

    def test_verification_without_a_ca_uses_the_system_store(self):
        # A cluster with a publicly trusted certificate needs no CA file
        kwargs = self.client({'uri': 'https://search.example.edu', 'verify_certs': True})
        self.assertIs(kwargs['verify_certs'], True)
        self.assertNotIn('ca_certs', kwargs)
        self.assertEqual(kwargs['hosts'], [{'host': 'search.example.edu', 'port': 443}])

    def test_a_host_that_says_nothing_behaves_as_before(self):
        kwargs = self.client({'uri': 'https://opensearch:9200', 'username': 'admin',
                              'password': 'x'})
        self.assertIs(kwargs['verify_certs'], False)
        self.assertNotIn('ca_certs', kwargs)
        self.assertIs(kwargs['ssl_show_warn'], False)
        self.assertIs(kwargs['use_ssl'], True)

    def test_a_ca_alone_does_not_switch_verification_on(self):
        # The two are separate settings, and the warning says so; quietly
        # verifying would be a behaviour nobody asked for
        kwargs = self.client({'uri': 'https://opensearch:9200', 'ca_certs': self.ca})
        self.assertIs(kwargs['verify_certs'], False)
        self.assertNotIn('ca_certs', kwargs)

    def test_plain_http_is_not_tls(self):
        kwargs = self.client({'uri': 'http://opensearch:9200'})
        self.assertIs(kwargs['use_ssl'], False)
        self.assertEqual(kwargs['hosts'], [{'host': 'opensearch', 'port': 9200}])


class WarningTest(Isolated):
    """An unverified host is reported once per process, and only then."""

    UNVERIFIED = {'uri': 'https://opensearch:9200', 'username': 'admin', 'password': 'x'}

    def test_an_unverified_host_is_named_with_the_fix(self):
        _, logged = self.processor(self.UNVERIFIED)
        self.assertIn('https://opensearch:9200', logged)
        self.assertIn('without verifying', logged)
        self.assertIn('verify_certs: true', logged)

    def test_it_is_said_once_per_process(self):
        _, first = self.processor(self.UNVERIFIED)
        _, second = self.processor(self.UNVERIFIED)
        self.assertEqual(first.count('WARNING'), 1)
        self.assertEqual(second, '')

    def test_each_unverified_host_is_named(self):
        _, logged = self.processor(self.UNVERIFIED, {'uri': 'https://replica:9200'})
        self.assertEqual(logged.count('WARNING'), 2)
        self.assertIn('https://replica:9200', logged)

    def test_a_verified_host_is_not_reported(self):
        # The control: without it the tests above would pass if every host
        # were reported regardless
        _, logged = self.processor({'uri': 'https://opensearch:9200', 'verify_certs': True,
                                    'ca_certs': self.ca})
        self.assertEqual(logged, '')

    def test_plain_http_is_not_reported(self):
        _, logged = self.processor({'uri': 'http://opensearch:9200'})
        self.assertEqual(logged, '')

    def test_a_ca_without_verification_is_pointed_out(self):
        _, logged = self.processor({'uri': 'https://opensearch:9200', 'ca_certs': self.ca})
        self.assertIn('ca_certs is set, but has no effect', logged)

    def test_nothing_is_said_when_opensearch_output_is_off(self):
        _, logged = self.processor(self.UNVERIFIED, enable=False)
        self.assertEqual(logged, '')


class SettingsTest(Isolated):
    """A mistake stops the process at start, not at the first event."""

    def test_mistakes_are_refused(self):
        for bad in ({'uri': 'https://o:9200', 'verify_certs': 'yes'},
                    {'uri': 'https://o:9200', 'verify_certs': 1},
                    {'uri': 'https://o:9200', 'ca_certs': ''},
                    {'uri': 'https://o:9200', 'ca_certs': 42},
                    {'uri': 'https://o:9200', 'verify_certs': True,
                     'ca_certs': '/nonexistent/root-ca.pem'},
                    {'verify_certs': True},
                    'https://o:9200'):
            with self.assertRaises(ValueError, msg=bad):
                Processor({'elastic': elastic(bad)}, {})

    def test_a_missing_ca_is_named(self):
        with self.assertRaisesRegex(ValueError, r'hosts\[0\] ca_certs .*not a file'):
            Processor({'elastic': elastic({'uri': 'https://o:9200', 'verify_certs': True,
                                           'ca_certs': '/nonexistent/root-ca.pem'})}, {})

    def test_good_settings_are_accepted(self):
        self.processor({'uri': 'https://o:9200', 'verify_certs': True, 'ca_certs': self.ca},
                       {'uri': 'https://o:9200', 'verify_certs': False})

    def test_hosts_are_not_read_when_output_is_off(self):
        # A syslog-only deployment is not stopped by settings it never uses
        Processor({'elastic': elastic({'uri': 'https://o:9200', 'verify_certs': 'yes'},
                                      enable=False)}, {})

    def test_a_processor_with_no_elastic_section_still_starts(self):
        Processor({}, {})

    def test_the_shipped_example_config_is_valid(self):
        import yaml
        with open(os.path.join(ROOT, 'src', 'support', 'config.example.yaml')) as fh:
            config = yaml.safe_load(fh)
        hosts = config['processor']['elastic']['hosts']
        self.assertIs(hosts[0]['verify_certs'], False)
        with mock.patch('sys.stderr'):
            O.check_hosts(config['processor']['elastic'])


class Librarian(object):
    """Runs the librarian's OpenSearch script against a fake curl.

    The fake answers 200 to everything and writes each call's arguments to a
    log, one line per call, so a test can see which TLS option every call used.
    """

    def __init__(self, test):
        self.root = tempfile.mkdtemp(prefix='tb-librarian-')
        test.addCleanup(shutil.rmtree, self.root, True)
        self.bin = os.path.join(self.root, 'bin')
        os.mkdir(self.bin)
        self.log = os.path.join(self.root, 'calls.log')
        # The template body spans lines, so newlines are folded to keep one
        # call per line
        self.fake('curl', 'echo "$*" | tr "\\n" " " >> "$FAKE_LOG"\n'
                          'echo >> "$FAKE_LOG"\necho 200\n')

    def fake(self, name, body):
        path = os.path.join(self.bin, name)
        with open(path, 'w') as fh:
            fh.write('#!/bin/sh\n' + body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)

    def run(self, **env):
        base = {'PATH': self.bin + os.pathsep + '/usr/bin' + os.pathsep + '/bin',
                'FAKE_LOG': self.log, 'OPENSEARCH_HOST': 'opensearch',
                'OPENSEARCH_USERNAME': 'admin', 'OPENSEARCH_PASSWORD': 'Not-the-default.1'}
        base.update({k: v for k, v in env.items() if v is not None})
        for name in [k for k, v in env.items() if v is None]:
            base.pop(name, None)
        result = subprocess.run(['sh', TEMPLATE_SCRIPT], env=base, cwd=self.root,
                                capture_output=True, text=True, timeout=60)
        calls = []
        if os.path.exists(self.log):
            with open(self.log) as fh:
                calls = fh.read().splitlines()
        return result, calls


class LibrarianTlsTest(unittest.TestCase):

    def setUp(self):
        self.librarian = Librarian(self)
        self.ca = os.path.join(self.librarian.root, 'root-ca.pem')
        with open(self.ca, 'w') as fh:
            fh.write('-----BEGIN CERTIFICATE-----\n')

    def test_with_a_ca_every_call_verifies(self):
        result, calls = self.librarian.run(OPENSEARCH_CA_CERT=self.ca)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(calls)
        for call in calls:
            self.assertIn('--cacert ' + self.ca, call)
            self.assertNotIn('--insecure', call)
        self.assertNotIn('WARNING', result.stderr)

    def test_without_a_ca_it_falls_back_and_says_so(self):
        result, calls = self.librarian.run(OPENSEARCH_CA_CERT=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(calls)
        for call in calls:
            self.assertIn('--insecure', call)
        self.assertIn('WARNING: OPENSEARCH_CA_CERT is not set', result.stderr)

    def test_a_ca_that_is_not_there_stops_it_before_any_call(self):
        result, calls = self.librarian.run(OPENSEARCH_CA_CERT='/nonexistent/root-ca.pem')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assertIn('not a file', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
