"""Tests for how TurkeyBite reaches OpenSearch.

Verification has to stay off unless a host asks for it, since the bundled
cluster's demo certificates verify against nothing and turning it on by
default would stop every existing install shipping. So what must not happen
is the opposite mistake: a host that asks for verification being connected to
without it, or a host used unverified without anybody being told.

The password TurkeyBite used to ship with must not get through anywhere it
could be used: a worker, the librarian's script, or a new install set up by
setup.py. The escape hatch for a disposable test install must open only when
asked for exactly, and must not be silent when it is.

No test touches the network. The client class is replaced by a recorder, and
the librarian's script runs against a fake curl that writes down what it was
asked to do.
"""

import importlib.util
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


class DefaultPasswordTest(Isolated):
    """The shipped default is refused wherever a worker would use it."""

    def host(self, password):
        return {'uri': 'https://opensearch:9200', 'username': 'admin', 'password': password,
                'verify_certs': True, 'ca_certs': self.ca}

    def test_the_default_is_refused_at_start(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(O.ALLOW_DEFAULT_PASSWORD, None)
            with self.assertRaises(ValueError) as caught:
                Processor({'elastic': elastic(self.host('Changeit12345!'))}, {})
        message = str(caught.exception)
        self.assertIn('hosts[0] password', message)
        self.assertIn('Changing the OpenSearch admin password', message)
        self.assertIn('TURKEYBITE_ALLOW_DEFAULT_PASSWORD=yes', message)

    def test_any_host_with_it_is_refused(self):
        with mock.patch.dict(os.environ, {O.ALLOW_DEFAULT_PASSWORD: ''}):
            with self.assertRaisesRegex(ValueError, r'hosts\[1\] password'):
                Processor({'elastic': elastic(self.host('Another-one.7'),
                                              self.host('Changeit12345!'))}, {})

    def test_surrounding_whitespace_does_not_disguise_it(self):
        with mock.patch.dict(os.environ, {O.ALLOW_DEFAULT_PASSWORD: ''}):
            with self.assertRaises(ValueError):
                Processor({'elastic': elastic(self.host(' Changeit12345! '))}, {})

    def test_another_password_starts_and_says_nothing(self):
        # The control: without it the refusal tests would pass if every
        # password were refused
        with mock.patch.dict(os.environ, {O.ALLOW_DEFAULT_PASSWORD: ''}):
            _, logged = self.processor(self.host('Another-one.7'))
        self.assertEqual(logged, '')

    def test_the_escape_hatch_lets_it_start_loudly(self):
        with mock.patch.dict(os.environ, {O.ALLOW_DEFAULT_PASSWORD: 'yes'}):
            _, logged = self.processor(self.host('Changeit12345!'))
        self.assertIn('WARNING', logged)
        self.assertIn('disposable test install', logged)

    def test_the_escape_hatch_warns_once_per_process(self):
        with mock.patch.dict(os.environ, {O.ALLOW_DEFAULT_PASSWORD: 'yes'}):
            self.processor(self.host('Changeit12345!'))
            _, again = self.processor(self.host('Changeit12345!'))
        self.assertEqual(again, '')

    def test_only_yes_opens_the_escape_hatch(self):
        for value in ('YES', 'true', '1', 'y', 'on', 'yes please'):
            with mock.patch.dict(os.environ, {O.ALLOW_DEFAULT_PASSWORD: value}):
                with self.assertRaises(ValueError, msg=value):
                    Processor({'elastic': elastic(self.host('Changeit12345!'))}, {})

    def test_a_syslog_only_deployment_is_not_stopped(self):
        # setup.py leaves the example host in config.yaml when OpenSearch output
        # is off, and a password nothing uses protects nothing
        with mock.patch.dict(os.environ, {O.ALLOW_DEFAULT_PASSWORD: ''}):
            Processor({'elastic': elastic(self.host('Changeit12345!'), enable=False)}, {})

    def test_the_shipped_examples_do_not_carry_it(self):
        import yaml
        with open(os.path.join(ROOT, 'src', 'support', 'config.example.yaml')) as fh:
            hosts = yaml.safe_load(fh)['processor']['elastic']['hosts']
        self.assertNotIn('Changeit12345!', [h.get('password') for h in hosts])
        with open(os.path.join(ROOT, 'src', 'support', 'example.env')) as fh:
            settings = [line.strip() for line in fh if not line.lstrip().startswith('#')]
        self.assertFalse([line for line in settings if 'Changeit12345!' in line])


class Librarian(object):
    """Runs the librarian's OpenSearch script against a fake curl and python.

    The fake curl answers 200 to everything. Both write each call's arguments to
    a log, one line per call, so a test can see which TLS option every request
    used and whether the retention step ran.
    """

    def __init__(self, test):
        self.root = tempfile.mkdtemp(prefix='tb-librarian-')
        test.addCleanup(shutil.rmtree, self.root, True)
        self.bin = os.path.join(self.root, 'bin')
        os.mkdir(self.bin)
        self.log = os.path.join(self.root, 'calls.log')
        # The template body spans lines, so newlines are folded to keep one
        # call per line
        self.fake('curl', 'echo "curl $*" | tr "\\n" " " >> "$FAKE_LOG"\n'
                          'echo >> "$FAKE_LOG"\necho 200\n')
        self.fake('python', 'echo "python $*" >> "$FAKE_LOG"\n')

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
        self.python = [call for call in calls if call.startswith('python ')]
        return result, [call for call in calls if call.startswith('curl ')]


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


class LibrarianPasswordTest(unittest.TestCase):
    """The librarian's script has no fallback password and refuses the default."""

    def setUp(self):
        self.librarian = Librarian(self)

    def test_no_password_stops_it_before_any_call(self):
        result, calls = self.librarian.run(OPENSEARCH_PASSWORD=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((calls, self.librarian.python), ([], []))
        self.assertIn('OPENSEARCH_PASSWORD is not set', result.stderr)

    def test_the_default_stops_it_before_any_call(self):
        result, calls = self.librarian.run(OPENSEARCH_PASSWORD='Changeit12345!',
                                           TURKEYBITE_ALLOW_DEFAULT_PASSWORD=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((calls, self.librarian.python), ([], []))
        self.assertIn('Refusing to run', result.stderr)

    def test_the_escape_hatch_lets_it_run_loudly(self):
        result, calls = self.librarian.run(OPENSEARCH_PASSWORD='Changeit12345!',
                                           TURKEYBITE_ALLOW_DEFAULT_PASSWORD='yes')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(calls)
        self.assertIn('disposable test install', result.stderr)

    def test_another_password_runs_and_is_sent(self):
        # The control for the two refusals above
        result, calls = self.librarian.run(OPENSEARCH_PASSWORD='Not-the-default.1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('-u admin:Not-the-default.1', calls[0])


class LibrarianRetentionTest(unittest.TestCase):
    """The script applies the retention policy, through the tested Python."""

    def test_the_policy_follows_the_template_to_the_same_cluster(self):
        librarian = Librarian(self)
        result, calls = librarian.run(OPENSEARCH_HOST='search.example.edu')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('_index_template', calls[-1])
        self.assertEqual(librarian.python,
                         ['python turkeybite retention --url https://search.example.edu:9200'])

    def test_a_failed_retention_step_fails_the_script(self):
        librarian = Librarian(self)
        librarian.fake('python', 'exit 1\n')
        result, _ = librarian.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('setup complete', result.stdout)


def load_setup():
    """setup.py as a module, without running it. Nothing happens at import."""
    spec = importlib.util.spec_from_file_location('tb_setup', os.path.join(ROOT, 'setup.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SetupPasswordTest(unittest.TestCase):
    """setup.py never offers the default, and generates what OpenSearch accepts."""

    @classmethod
    def setUpClass(cls):
        cls.setup = load_setup()

    def test_a_generated_password_meets_the_rules(self):
        seen = set()
        for _ in range(200):
            password = self.setup.generate_opensearch_password()
            self.assertIsNone(self.setup.opensearch_password_problem(password), password)
            self.assertEqual(len(password), 32)
            seen.add(password)
        self.assertEqual(len(seen), 200)

    def test_the_default_is_refused(self):
        self.assertIn('ship', self.setup.opensearch_password_problem('Changeit12345!'))

    def test_what_opensearch_would_refuse_is_refused(self):
        for bad in ('Sh0rt!', 'alllower-case.1', 'ALLUPPER-CASE.1', 'No-Digits-Here!',
                    'NoSymbols123'):
            self.assertIsNotNone(self.setup.opensearch_password_problem(bad), bad)

    def test_symbols_that_env_or_the_healthcheck_would_change_are_refused(self):
        for bad in ('Has-a-dollar$1', 'Has a space-1A', 'Amp&ersand-1A', "Quote'd-1A",
                    'Hash#tag-1Aa'):
            self.assertIn('cannot contain', self.setup.opensearch_password_problem(bad), bad)

    def test_a_good_password_is_accepted(self):
        # The control for the refusals above
        self.assertIsNone(self.setup.opensearch_password_problem('Tb.new-Pass_9%@:^!,+=x'))

    def run_prompt(self, answers, components=('opensearch',), env=None):
        """Runs setup_opensearch_password with typed answers. Returns (setup, asked)."""
        root = tempfile.mkdtemp(prefix='tb-setup-')
        self.addCleanup(shutil.rmtree, root, True)
        if env is not None:
            with open(os.path.join(root, '.env'), 'w') as fh:
                fh.write(env)
        with mock.patch.object(self.setup.TurkeyBiteSetup, 'ensure_directories'):
            setup = self.setup.TurkeyBiteSetup()
        setup.base_dir = self.setup.Path(root)
        setup.components = list(components)
        answers = list(answers)
        asked = []

        def answer(message, options=None):
            asked.append(message)
            return answers.pop(0)
        setup.prompt = answer
        setup.prompt_yes_no = lambda message, default=True: answers.pop(0)
        with mock.patch('builtins.print'):
            setup.setup_opensearch_password()
        self.assertEqual(answers, [], 'not every answer was used')
        return setup, asked

    def test_there_is_no_default_to_fall_back_to(self):
        with mock.patch.object(self.setup.TurkeyBiteSetup, 'ensure_directories'):
            self.assertIsNone(self.setup.TurkeyBiteSetup().opensearch_admin_password)

    def test_pressing_enter_generates_one(self):
        setup, _ = self.run_prompt([''])
        self.assertIsNone(self.setup.opensearch_password_problem(setup.opensearch_admin_password))

    def test_typing_the_default_is_refused_and_asked_again(self):
        setup, asked = self.run_prompt(['Changeit12345!', 'Tb.new-Pass_9x', 'Tb.new-Pass_9x'])
        self.assertEqual(setup.opensearch_admin_password, 'Tb.new-Pass_9x')
        self.assertEqual(len(asked), 3)

    def test_a_remote_password_is_not_generated(self):
        # Another node's OpenSearch already has a password; a random one here
        # would only lock this node out
        setup, asked = self.run_prompt(['', 'Their-Pass.1', 'Their-Pass.1'],
                                       components=('worker',))
        self.assertEqual(setup.opensearch_admin_password, 'Their-Pass.1')
        self.assertIn('search node', asked[0])

    def test_a_remote_default_is_refused_too(self):
        setup, _ = self.run_prompt(['Changeit12345!', 'Their-Pass.1', 'Their-Pass.1'],
                                   components=('worker',))
        self.assertEqual(setup.opensearch_admin_password, 'Their-Pass.1')

    def test_a_rerun_keeps_the_password_the_cluster_has(self):
        setup, asked = self.run_prompt([True], env='OPENSEARCH_PASSWORD=Live-Pass.42\n')
        self.assertEqual(setup.opensearch_admin_password, 'Live-Pass.42')
        self.assertEqual(asked, [])

    def test_a_rerun_does_not_keep_the_default(self):
        setup, _ = self.run_prompt([''], env='OPENSEARCH_INITIAL_ADMIN_PASSWORD=Changeit12345!\n')
        self.assertNotEqual(setup.opensearch_admin_password, 'Changeit12345!')


if __name__ == '__main__':
    unittest.main(verbosity=2)
