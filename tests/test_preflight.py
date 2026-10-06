"""Tests for checking config.yaml before a worker or the core starts.

Under the default rq pipeline a worker process never builds a processor of
its own, so it never checks the settings: the core does, in its container, and
a CA file present there but missing from a worker's container showed only as
every event failing to ship. What must not happen is a container starting
with settings it cannot use, or such a failure being reported once per event
and burying the log, or not being reported at all.

The checks are the real ones. The start scripts run against fake commands,
and nothing touches the network.
"""

import importlib.machinery
import importlib.util
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# The shell by its full path, rather than whatever PATH finds first
SH = shutil.which('sh') or '/bin/sh'
sys.path.insert(0, os.path.join(ROOT, 'src'))

import yaml

from libtb import opensearch as O
from libtb import processor as P
from libtb.processor import Processor


def load_cli():
    path = os.path.join(ROOT, 'src', 'turkeybite')
    loader = importlib.machinery.SourceFileLoader('turkeybite_check_cli', path)
    spec = importlib.util.spec_from_loader('turkeybite_check_cli', loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli


class Workdir(unittest.TestCase):
    """A container's working directory: config.yaml, its secret and a CA file."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-preflight-')
        self.addCleanup(shutil.rmtree, self.root, True)
        for state in (O._warned, P._opensearch_clients):
            state.clear()
            self.addCleanup(state.clear)
        patcher = mock.patch.object(O, 'REPORTED_DIR', os.path.join(self.root, 'reported'))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.ca = os.path.join(self.root, 'root-ca.pem')
        with open(self.ca, 'w') as fh:
            fh.write('-----BEGIN CERTIFICATE-----\n')
        with open(os.path.join(self.root, 'valkey_password'), 'w') as fh:
            fh.write('secret\n')
        with open(os.path.join(ROOT, 'src', 'support', 'config.example.yaml')) as fh:
            self.config = yaml.safe_load(fh)
        self.config['redis']['password_file'] = os.path.join(self.root, 'valkey_password')
        self.host().update(password='Not-the-default.1', verify_certs=True, ca_certs=self.ca)

    def host(self):
        return self.config['processor']['elastic']['hosts'][0]

    def write_config(self):
        path = os.path.join(self.root, 'config.yaml')
        with open(path, 'w') as fh:
            yaml.safe_dump(self.config, fh)
        return path


class CheckCommandTest(Workdir):
    """`turkeybite check`, which the start scripts run."""

    @classmethod
    def setUpClass(cls):
        cls.cli = load_cli()

    def check(self):
        from click.testing import CliRunner
        path = self.write_config()
        real = self.cli.read_config
        with mock.patch.object(self.cli, 'read_config', lambda: real(path)), \
                mock.patch.dict(os.environ, {O.ALLOW_DEFAULT_PASSWORD: ''}):
            return CliRunner(mix_stderr=False).invoke(self.cli.cli, ['check'])

    def assert_refused(self, *expected):
        result = self.check()
        self.assertEqual(result.exit_code, 1, result.stdout)
        self.assertIn('CONFIGURATION ERROR', result.stderr)
        for text in expected:
            self.assertIn(text, result.stderr)

    def test_a_good_configuration_passes(self):
        # The control for every refusal below
        result = self.check()
        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertIn('config.yaml checked', result.stdout)

    def test_a_ca_file_missing_from_this_container_is_refused(self):
        os.remove(self.ca)
        self.assert_refused('ca_certs', 'not a file')

    def test_the_default_password_is_refused(self):
        self.host()['password'] = 'Changeit12345!'
        self.assert_refused('Changing the OpenSearch admin password')

    def test_a_bad_privacy_setting_is_refused(self):
        self.config['processor']['privacy'] = {'urls': 'all'}
        self.assert_refused('processor.privacy.urls')

    def test_a_bad_evidence_setting_is_refused(self):
        self.config['processor']['evidence']['disabled_categories'] = ['fakenews']
        self.assert_refused('disabled_categories')

    def test_a_bad_resolver_setting_is_refused(self):
        self.config['processor']['evidence']['resolvers'] = {'enable': 'yes'}
        self.assert_refused('resolvers enable')

    def test_a_missing_section_is_refused(self):
        del self.config['processor']
        self.assert_refused("missing setting 'processor'")

    def test_a_missing_secret_is_refused(self):
        os.remove(os.path.join(self.root, 'valkey_password'))
        self.assert_refused('not found')


class StartScriptTest(unittest.TestCase):
    """The core, and a consume worker, check before they start anything."""

    def run_script(self, script, check_exit, pipeline=None):
        root = tempfile.mkdtemp(prefix='tb-start-')
        self.addCleanup(shutil.rmtree, root, True)
        bin_dir = os.path.join(root, 'bin')
        os.mkdir(bin_dir)
        log = os.path.join(root, 'calls.log')
        for name, body in (('python', f'echo "python $*" >> "{log}"\n'
                                      f'[ "$2" = check ] && exit {check_exit}\nexit 0\n'),
                           ('envsubst', f'echo "envsubst" >> "{log}"\ncat\n')):
            path = os.path.join(bin_dir, name)
            with open(path, 'w') as fh:
                fh.write('#!/bin/sh\n' + body)
            os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        env = {'PATH': bin_dir + os.pathsep + '/usr/bin' + os.pathsep + '/bin', 'TMPDIR': root}
        if pipeline:
            env['TURKEYBITE_PIPELINE'] = pipeline
        # The repository's own script, with stand-ins on PATH: nothing here
        # comes from outside the test
        result = subprocess.run([SH, os.path.join(ROOT, script)], cwd=root, env=env,  # nosec B603
                                capture_output=True, text=True, timeout=60)
        calls = open(log).read().splitlines() if os.path.exists(log) else []
        return result, calls

    def test_a_failed_check_stops_a_consume_worker_before_anything_starts(self):
        result, calls = self.run_script('docker/worker/run-worker.sh', 1, 'consume')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, ['python turkeybite check'])
        self.assertIn('Refusing to start the worker', result.stderr)

    def test_an_rq_worker_leaves_the_check_to_the_core(self):
        # Its jobs carry the core's settings, so its own copy decides nothing
        _, calls = self.run_script('docker/worker/run-worker.sh', 1, 'rq')
        self.assertNotIn('python turkeybite check', calls)

    def test_a_failed_check_stops_the_core(self):
        result, calls = self.run_script('docker/core/run-core.sh', 1)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, ['python turkeybite check'])

    def test_a_passing_check_lets_the_start_go_on(self):
        # The control: the same scripts carry on past a passing check
        _, calls = self.run_script('docker/worker/run-worker.sh', 0, 'consume')
        self.assertEqual(calls[0], 'python turkeybite check')
        self.assertIn('envsubst', calls)
        _, calls = self.run_script('docker/core/run-core.sh', 0)
        self.assertEqual(calls, ['python turkeybite check', 'python turkeybite run'])


class ShipTimeTest(Workdir):
    """A configuration fault that still reaches an event is reported once."""

    def setUp(self):
        super().setUp()
        # Reverse DNS would query a resolver
        self.config['processor']['dns']['lookup_ips'] = False

    def processor(self):
        """A processor checked at start, whose CA file is then lost."""
        processor = Processor(self.config['processor'], self.config['redis'])
        processor.resolve_contexts = lambda searches, **kwargs: (['news'], {})
        os.remove(self.ca)
        return processor

    def packet(self):
        return {'type': 'dns', 'resource': 'www.example.com',
                'dns': {'question': {'name': 'www.example.com'}},
                'network': {'direction': 'ingress'}, 'client': {'ip': '10.0.0.5'},
                '@timestamp': '2026-10-04T12:00:00Z'}

    def ship(self, processor, events):
        """Ships `events`, as RQ would run that many jobs.

        Returns stderr. The jobs that failed, rather than completed, are
        counted in self.failed.
        """
        err = io.StringIO()
        self.failed = 0
        with redirect_stderr(err):
            for _ in range(events):
                try:
                    processor.process_packet(self.packet())
                except O.ConfigurationError:
                    self.failed += 1
        return err.getvalue()

    def test_it_is_reported_once_not_once_per_event(self):
        logged = self.ship(self.processor(), 5)
        self.assertEqual(logged.count('CONFIGURATION ERROR'), 1)
        self.assertIn('ca_certs', logged)
        self.assertIn('turkeybite check', logged)

    def test_every_job_fails_so_rq_keeps_it_rather_than_dropping_its_event(self):
        # Under the rq pipeline a worker missing the CA file the core has would
        # otherwise complete each job with its event lost
        self.ship(self.processor(), 4)
        self.assertEqual(self.failed, 4)

    def test_once_per_container_even_when_every_event_is_a_new_process(self):
        # Under the forking rq.Worker each event is a process of its own
        processor = self.processor()
        logged = ''
        for _ in range(3):
            O._warned.clear()
            P._opensearch_clients.clear()
            logged += self.ship(processor, 1)
        self.assertEqual(logged.count('CONFIGURATION ERROR'), 1)

    def test_a_host_that_is_down_is_still_reported_each_time(self):
        # The control: only configuration errors are held back
        processor = Processor(self.config['processor'], self.config['redis'])
        processor.resolve_contexts = lambda searches, **kwargs: (['news'], {})
        client = mock.Mock()
        client.index.side_effect = ConnectionError('connection refused')
        with mock.patch.object(P, 'opensearch_client', return_value=client):
            logged = self.ship(processor, 3)
        self.assertEqual(logged.count('Error sending to OpenSearch'), 3)
        self.assertNotIn('CONFIGURATION ERROR', logged)

    def test_with_bulk_on_it_is_reported_once_too(self):
        self.config['processor']['elastic']['bulk'] = {'enable': True, 'size': 1,
                                                        'interval_sec': 0}
        with mock.patch.object(P, '_install_flush_hooks'):
            logged = self.ship(self.processor(), 3)
        # Each failed, and the documents wait in the buffer for the next flush
        self.assertEqual(self.failed, 3)
        self.assertEqual(len(P._bulk_buffers[os.getpid()]['docs']), 3)
        P._bulk_buffers.clear()
        self.assertEqual(logged.count('CONFIGURATION ERROR'), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
