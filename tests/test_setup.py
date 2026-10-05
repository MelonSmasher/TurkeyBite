"""Tests for running setup.py again over an existing install.

A rerun must change only what it asks about. Regenerating config.yaml and .env
from the examples used to drop everything an operator had set by hand, such as
processor.privacy, a host's verify_certs and ca_certs, or OPENSEARCH_CA_CERT,
and silently undo it. And the OpenSearch admin password lives in both files,
so a new one must reach both or neither: one file holding the new password and
the other the old leaves the workers and the librarian disagreeing about it.

setup.py runs on the host, not in a container, and nothing here touches the
network or Docker. Each test works in a temporary directory.
"""

import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

import yaml

spec = importlib.util.spec_from_file_location('tb_setup_reruns', os.path.join(ROOT, 'setup.py'))
SETUP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SETUP)

OLD = 'Old-Pass.42x'
NEW = 'New-Pass.42x'


class Rerun(unittest.TestCase):
    """A setup run in a temporary directory, as a development install."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='tb-setup-')
        self.addCleanup(shutil.rmtree, self.root, True)

    def setup(self, answers=(), yes_no=()):
        with mock.patch.object(SETUP.TurkeyBiteSetup, 'ensure_directories'):
            setup = SETUP.TurkeyBiteSetup()
        setup.base_dir = SETUP.Path(self.root)
        setup.components = ['core', 'librarian', 'worker', 'valkey', 'opensearch']
        setup.node_type = 'dev'
        answers, yes_no = list(answers), list(yes_no)
        setup.prompt = lambda message, options=None: answers.pop(0)
        setup.prompt_yes_no = lambda message, default=True: yes_no.pop(0)
        self.addCleanup(lambda: self.assertEqual((answers, yes_no), ([], []),
                                                 'not every answer was used'))
        return setup

    def write(self, name, text):
        with open(os.path.join(self.root, name), 'w') as fh:
            fh.write(text)

    def read(self, name):
        with open(os.path.join(self.root, name)) as fh:
            return fh.read()

    def config(self):
        return yaml.safe_load(self.read('config.yaml'))

    def env(self):
        return dict(line.rstrip('\n').split('=', 1) for line in self.read('.env').splitlines()
                    if '=' in line and not line.startswith('#'))

    def existing_install(self):
        """An install a previous run made, then an operator changed by hand."""
        with open(os.path.join(ROOT, 'src', 'support', 'config.example.yaml')) as fh:
            config = yaml.safe_load(fh)
        config['processor']['privacy'] = {'urls': 'host', 'packet': 'none'}
        config['processor']['elastic']['hosts'][0].update(
            uri='https://node-0.example.com:9200', password=OLD, verify_certs=True,
            ca_certs='/turkey-bite/opensearch-root-ca.pem')
        config['processor']['evidence']['min_publishers'] = 3
        config['operator_note'] = 'kept'
        with open(os.path.join(self.root, 'config.yaml'), 'w') as fh:
            yaml.safe_dump(config, fh)
        self.write('.env', '# TurkeyBite Environment Variables\n'
                           'TZ=America/New_York\n'
                           f'OPENSEARCH_PASSWORD={OLD}\n'
                           f'OPENSEARCH_INITIAL_ADMIN_PASSWORD={OLD}\n'
                           '# Verifying the bundled cluster, see the README\n'
                           'OPENSEARCH_CA_CERT=/turkey-bite/opensearch-root-ca.pem\n'
                           'TURKEYBITE_WORKER_PROCS=8\n'
                           'TURKEYBITE_RETENTION_DAYS=365\n')

    def write_both(self, setup, previous):
        with mock.patch('builtins.print'):
            changed = setup.keep_password_in_step(previous)
            setup.setup_config()
            setup.setup_env()
        return changed


class ConfigRerunTest(Rerun):

    def test_what_an_operator_set_is_kept(self):
        self.existing_install()
        setup = self.setup()
        setup.opensearch_admin_password = NEW
        self.write_both(setup, OLD)
        config = self.config()
        self.assertEqual(config['processor']['privacy'], {'urls': 'host', 'packet': 'none'})
        host = config['processor']['elastic']['hosts'][0]
        self.assertEqual((host['uri'], host['verify_certs'], host['ca_certs']),
                         ('https://node-0.example.com:9200', True,
                          '/turkey-bite/opensearch-root-ca.pem'))
        self.assertEqual(config['processor']['evidence']['min_publishers'], 3)
        self.assertEqual(config['operator_note'], 'kept')

    def test_what_setup_asks_about_is_changed(self):
        self.existing_install()
        setup = self.setup()
        setup.opensearch_admin_password = NEW
        setup.valkey_host = 'valkey.example.edu'
        setup.use_syslog, setup.syslog_host, setup.syslog_port = True, 'graylog.example.edu', 1514
        self.write_both(setup, OLD)
        config = self.config()
        self.assertEqual(config['processor']['elastic']['hosts'][0]['password'], NEW)
        self.assertEqual(config['redis']['host'], 'valkey.example.edu')
        self.assertEqual(config['processor']['syslog'],
                         {'enable': True, 'port': 1514, 'host': 'graylog.example.edu'})

    def test_a_new_install_starts_from_the_example(self):
        setup = self.setup()
        setup.opensearch_admin_password = NEW
        self.write_both(setup, None)
        config = self.config()
        self.assertEqual(config['processor']['privacy'], {'urls': 'trimmed', 'packet': 'keep'})
        self.assertEqual(config['processor']['elastic']['hosts'][0]['password'], NEW)


class EnvRerunTest(Rerun):

    def test_lines_setup_does_not_manage_are_kept(self):
        self.existing_install()
        setup = self.setup()
        setup.opensearch_admin_password = NEW
        setup.retention_days = 365
        self.write_both(setup, OLD)
        env = self.env()
        self.assertEqual(env['OPENSEARCH_CA_CERT'], '/turkey-bite/opensearch-root-ca.pem')
        self.assertEqual(env['TZ'], 'America/New_York')
        self.assertEqual(env['TURKEYBITE_WORKER_PROCS'], '8')
        self.assertIn('# Verifying the bundled cluster, see the README\n', self.read('.env'))

    def test_managed_settings_change_and_missing_ones_are_added_once(self):
        self.existing_install()
        setup = self.setup()
        setup.opensearch_admin_password = NEW
        setup.retention_days = 30
        self.write_both(setup, OLD)
        env = self.env()
        self.assertEqual((env['OPENSEARCH_PASSWORD'], env['OPENSEARCH_INITIAL_ADMIN_PASSWORD']),
                         (NEW, NEW))
        self.assertEqual(env['TURKEYBITE_RETENTION_DAYS'], '30')
        self.assertEqual(env['VALKEY_HOST'], 'valkey')
        self.assertEqual(env['OPENSEARCH_PORT'], '9200')
        self.assertEqual(self.read('.env').count('OPENSEARCH_PASSWORD='), 1)

    def test_a_new_install_gets_every_setting(self):
        setup = self.setup()
        setup.opensearch_admin_password = NEW
        self.write_both(setup, None)
        env = self.env()
        for key in ('TZ', 'OPENSEARCH_PASSWORD', 'VALKEY_HOST', 'TURKEYBITE_RETENTION_DAYS',
                    'OPENSEARCH_INITIAL_ADMIN_PASSWORD', 'OPENSEARCH_JAVA_OPTS'):
            self.assertIn(key, env)
        self.assertTrue(self.read('.env').startswith('# TurkeyBite Environment Variables\n'))


class PasswordInStepTest(Rerun):
    """A new password reaches every file that holds it, or none."""

    def test_both_files_get_a_new_password(self):
        self.existing_install()
        setup = self.setup(yes_no=[True, True])
        setup.opensearch_admin_password = NEW
        with mock.patch('builtins.print'):
            setup.decide_updates()
        self.assertTrue(self.write_both(setup, OLD))
        self.assertEqual(self.env()['OPENSEARCH_PASSWORD'], NEW)
        self.assertEqual(self.config()['processor']['elastic']['hosts'][0]['password'], NEW)

    def test_a_host_signing_in_as_another_account_keeps_its_password(self):
        # Setup only knows the admin password; overwriting a writer account's
        # with it would leave the pair mismatched and every event refused
        self.existing_install()
        config = self.config()
        config['processor']['elastic']['hosts'].append(
            {'uri': 'https://search-2:9200', 'username': 'tb_writer', 'password': 'writer-pw'})
        with open(os.path.join(self.root, 'config.yaml'), 'w') as fh:
            yaml.safe_dump(config, fh)
        setup = self.setup(yes_no=[True, True])
        setup.opensearch_admin_password = NEW
        with mock.patch('builtins.print'):
            setup.decide_updates()
        self.assertTrue(self.write_both(setup, OLD))
        hosts = self.config()['processor']['elastic']['hosts']
        self.assertEqual([(h['username'], h['password']) for h in hosts],
                         [('admin', NEW), ('tb_writer', 'writer-pw')])

    def test_declining_either_file_abandons_the_change(self):
        for config_answer, env_answer in ((False, True), (True, False), (False, False)):
            self.existing_install()
            setup = self.setup(yes_no=[config_answer, env_answer])
            setup.opensearch_admin_password = NEW
            with mock.patch('builtins.print'):
                setup.decide_updates()
            self.assertFalse(self.write_both(setup, OLD))
            self.assertEqual(setup.opensearch_admin_password, OLD)
            self.assertEqual(self.env()['OPENSEARCH_PASSWORD'], OLD, (config_answer, env_answer))
            self.assertEqual(self.config()['processor']['elastic']['hosts'][0]['password'], OLD,
                             (config_answer, env_answer))

    def test_a_kept_password_needs_no_both_or_neither(self):
        # The control: declining a file is fine when the password is not changing
        self.existing_install()
        setup = self.setup(yes_no=[False, True])
        setup.opensearch_admin_password = OLD
        with mock.patch('builtins.print'):
            setup.decide_updates()
        self.assertFalse(self.write_both(setup, OLD))
        self.assertEqual(self.config()['processor']['elastic']['hosts'][0]['password'], OLD)

    def test_the_operator_is_told_to_change_it_in_opensearch_too(self):
        self.existing_install()
        setup = self.setup(answers=['Development (all components on one machine)'],
                           yes_no=[True, True])
        setup.setup_development = lambda: None
        setup.configure_output_options = lambda: None
        setup.setup_valkey = lambda: None
        setup.setup_docker_compose = lambda: None
        setup.setup_retention = lambda: None
        setup.use_opensearch = True

        def choose_new():
            setup.opensearch_admin_password = NEW
        setup.setup_opensearch_password = choose_new
        printed = []
        with mock.patch('builtins.print', side_effect=lambda *a, **k: printed.append(
                ' '.join(map(str, a)))):
            setup.run()
        self.assertTrue(any("change it in OpenSearch too" in line for line in printed))
        self.assertEqual(self.env()['OPENSEARCH_PASSWORD'], NEW)

    def test_the_existing_password_is_read_from_config_yaml_when_env_lacks_it(self):
        self.existing_install()
        self.write('.env', 'TZ=UTC\n')
        self.assertEqual(self.setup().existing_password(), OLD)


class RetentionPromptTest(Rerun):
    """A rerun offers the period already in .env, never the suggestion for a new install."""

    def ask(self, answers):
        setup = self.setup(answers=answers)
        with mock.patch('builtins.print'):
            setup.setup_retention()
        return setup.retention_days

    def test_enter_keeps_the_period_already_set(self):
        self.write('.env', 'TURKEYBITE_RETENTION_DAYS=365\n')
        self.assertEqual(self.ask(['']), 365)

    def test_enter_keeps_forever_too(self):
        self.write('.env', 'TURKEYBITE_RETENTION_DAYS=0\n')
        self.assertEqual(self.ask(['']), 0)

    def test_without_one_it_suggests_ninety(self):
        # The control: a new install, or an upgraded .env that never had one
        self.write('.env', 'TZ=UTC\n')
        self.assertEqual(self.ask(['']), 90)

    def test_a_value_it_cannot_read_is_not_offered(self):
        self.write('.env', 'TURKEYBITE_RETENTION_DAYS=90d\n')
        self.assertEqual(self.ask(['']), 90)


if __name__ == '__main__':
    unittest.main(verbosity=2)
