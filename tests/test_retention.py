"""Tests for the retention policy that deletes old TurkeyBite indices.

The one thing that must never happen is an upgrade deleting a deployment's
history on its own. OpenSearch only attaches a policy's template to indices
created after it, and the librarian must not undo that by attaching the policy
to what is already there: only `--attach-existing` may, and only to daily
indices nothing else manages. Each test of what is left alone has a control
showing the same indices are attached when the operator asks.

Nor may a change in the period be half applied. ISM pins each managed index to
the policy version it started with, so updating the policy without moving the
indices onto it would leave a longer period protecting nothing.

No test touches the network. The ISM API is replaced by an in-memory fake whose
answers have the shape a real opensearch:3 (3.9.0) gave, including the fields
OpenSearch adds to a stored policy, the 409 for an update without a sequence
number, and the failures it reports per index.
"""

import fnmatch
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

from opensearchpy.exceptions import ConflictError, NotFoundError

from libtb import retention as R

NOW = 1_800_000_000.0
DAY = 86400


def ms(days_ago):
    """An index creation time, as _cat/indices reports it, `days_ago` before NOW."""
    return int((NOW - days_ago * DAY) * 1000)


class FakeOpenSearch(object):
    """The ISM endpoints retention uses, held in memory.

    Called as opensearchpy's Transport.perform_request is. Every write is
    recorded in `writes`, so a test can assert that nothing was changed.
    """

    def __init__(self):
        self.policy = None
        self.seq_no = -1
        self.indices = {}
        self.writes = []
        self.requests = []

    def index(self, name, days_ago, policy=None):
        self.indices[name] = {'created': ms(days_ago), 'policy': policy}

    def managed_by(self, policy):
        return sorted(n for n, i in self.indices.items() if i['policy'] == policy)

    def __call__(self, method, path, params=None, body=None):
        self.requests.append((method, path))
        if method != 'GET':
            self.writes.append((method, path, params, body))
        parts = path.strip('/').split('/')
        if parts[:3] == ['_plugins', '_ism', 'policies']:
            return self.policies(method, params, body)
        if parts[:2] == ['_cat', 'indices']:
            return [{'index': name, 'creation.date': str(i['created'])}
                    for name, i in sorted(self.indices.items())
                    if fnmatch.fnmatch(name, parts[2])]
        names = parts[3].split(',')
        if parts[:3] == ['_plugins', '_ism', 'explain']:
            answer = {}
            for name in names:
                policy = self.indices[name]['policy']
                if policy:
                    answer[name] = {'index.plugins.index_state_management.policy_id': policy,
                                    'index.opendistro.index_state_management.policy_id': policy,
                                    'index': name, 'policy_id': policy, 'enabled': True}
                else:
                    answer[name] = {'index.plugins.index_state_management.policy_id': None,
                                    'index.opendistro.index_state_management.policy_id': None,
                                    'enabled': None}
            answer['total_managed_indices'] = sum(1 for n in names if self.indices[n]['policy'])
            return answer
        return self.act(parts[2], names, body)

    def policies(self, method, params, body):
        if method == 'GET':
            if self.policy is None:
                raise NotFoundError(404, 'index_not_found_exception', {})
            return {'_id': R.POLICY_ID, '_version': self.seq_no + 1, '_seq_no': self.seq_no,
                    '_primary_term': 1, 'policy': self.policy}
        if method == 'DELETE':
            self.policy = None
            return {'result': 'deleted'}
        if self.policy is not None:
            if not params:
                raise ConflictError(409, 'version_conflict_engine_exception',
                                    {'reason': 'document already exists'})
            if (params.get('if_seq_no'), params.get('if_primary_term')) != (self.seq_no, 1):
                raise ConflictError(409, 'version_conflict_engine_exception',
                                    {'reason': 'required seqNo does not match'})
        self.policy = self.stored(body['policy'])
        self.seq_no += 1
        return {'_id': R.POLICY_ID, '_seq_no': self.seq_no, '_primary_term': 1}

    @staticmethod
    def stored(sent):
        """What OpenSearch hands back: the policy with fields of its own added."""
        import copy
        policy = copy.deepcopy(sent)
        policy.update({'policy_id': R.POLICY_ID, 'last_updated_time': 1791164226671,
                       'schema_version': 31, 'error_notification': None})
        for state in policy['states']:
            for action in state['actions']:
                action['retry'] = {'count': 3, 'backoff': 'exponential', 'delay': '1m'}
        for template in policy.get('ism_template') or []:
            template['last_updated_time'] = 1791164226671
        return policy

    def act(self, verb, names, body):
        updated, failed = 0, []
        for name in names:
            index = self.indices[name]
            if verb == 'add':
                if index['policy']:
                    failed.append((name, 'This index already has a policy, use the update '
                                         'policy API to update index policies'))
                    continue
                index['policy'] = body['policy_id']
            elif verb == 'change_policy':
                if not index['policy']:
                    failed.append((name, 'This index is not being managed'))
                    continue
                index['policy'] = body['policy_id']
                index['moved'] = True
            elif verb == 'remove':
                if not index['policy']:
                    failed.append((name, 'This index does not have a policy'))
                    continue
                index['policy'] = None
            updated += 1
        return {'updated_indices': updated, 'failures': bool(failed),
                'failed_indices': [{'index_name': n, 'index_uuid': 'x', 'reason': r}
                                   for n, r in failed]}


class Setting(object):
    """Collects log lines, and runs ensure or attach_existing over a fake."""

    def setUp(self):
        self.os = FakeOpenSearch()
        self.lines = []

    def cluster(self, dry_run=False):
        return R.Cluster(self.os, dry_run=dry_run, log=self.lines.append)

    def ensure(self, days=90, prefix='tb-index', dry_run=False):
        return R.ensure(self.cluster(dry_run), days, prefix, log=self.lines.append, now=NOW)

    def attach(self, days=90, prefix='tb-index', dry_run=False):
        return R.attach_existing(self.cluster(dry_run), days, prefix, log=self.lines.append,
                                 now=NOW)

    def log(self):
        return '\n'.join(self.lines)

    def stored_age(self):
        hot = [s for s in self.os.policy['states'] if s['name'] == 'hot'][0]
        return hot['transitions'][0]['conditions']['min_index_age']


class PolicyTest(unittest.TestCase):
    """The policy body, and the settings it is built from."""

    def test_the_default_deletes_after_ninety_days(self):
        body = R.policy(R.retention_days(None), 'tb-index')['policy']
        hot, delete = body['states']
        self.assertEqual(body['default_state'], 'hot')
        self.assertEqual(hot['transitions'], [{'state_name': 'delete',
                                               'conditions': {'min_index_age': '90d'}}])
        self.assertEqual(delete['actions'], [{'delete': {}}])

    def test_new_indices_get_it_from_the_template(self):
        body = R.policy(30, 'tb-index')['policy']
        self.assertEqual(body['ism_template'], [{'index_patterns': ['tb-index-*'],
                                                 'priority': R.TEMPLATE_PRIORITY}])

    def test_the_pattern_follows_the_configured_prefix(self):
        body = R.policy(30, 'campus')['policy']
        self.assertEqual(body['ism_template'][0]['index_patterns'], ['campus-*'])

    def test_one_day_is_the_shortest_policy(self):
        self.assertEqual(R.policy(1, 'tb-index')['policy']['states'][0]['transitions'][0]
                         ['conditions']['min_index_age'], '1d')
        with self.assertRaises(ValueError):
            R.policy(0, 'tb-index')

    def test_days_are_read_from_the_variable(self):
        for value, days in ((None, 90), ('', 90), ('  ', 90), ('0', 0), (' 30 ', 30),
                            ('365', 365), ('0090', 90)):
            self.assertEqual(R.retention_days(value), days, value)

    def test_days_that_are_not_a_whole_number_are_refused(self):
        # Deleting data on a misread setting is not a guess worth making
        for bad in ('-1', '1.5', '90d', 'ninety', '+5', '1e3', '٣', 'yes'):
            with self.assertRaises(ValueError, msg=bad):
                R.retention_days(bad)

    def test_a_prefix_that_reaches_beyond_turkeybite_is_refused(self):
        for bad in ('', ' ', '*', 'tb*', 'tb,other', 'tb index', None, 7):
            with self.assertRaises(ValueError, msg=bad):
                R.index_pattern(bad)

    def test_only_daily_names_count_as_turkeybite_indices(self):
        self.assertTrue(R.is_daily('tb-index-2026-01-01', 'tb-index'))
        for name in ('tb-index-other', 'tb-index-2026-01-01-restored', 'xtb-index-2026-01-01',
                     'tb-index-2026-1-1', 'tb-index-'):
            self.assertFalse(R.is_daily(name, 'tb-index'), name)
        # The prefix is a name, not a pattern
        self.assertFalse(R.is_daily('tbXindex-2026-01-01', 'tb.index'))


class PlanTest(unittest.TestCase):
    """When the stored policy needs changing."""

    def stored(self, days=90, prefix='tb-index'):
        return {'_seq_no': 4, '_primary_term': 1,
                'policy': FakeOpenSearch.stored(R.policy(days, prefix)['policy'])}

    def test_a_stored_policy_that_says_the_same_is_current(self):
        # OpenSearch adds retry settings and timestamps, which must not make
        # every start rewrite the policy
        self.assertEqual(R.plan(90, self.stored(), 'tb-index'), R.CURRENT)

    def test_no_policy_is_created(self):
        self.assertEqual(R.plan(90, None, 'tb-index'), R.CREATE)

    def test_a_different_period_or_prefix_is_updated(self):
        self.assertEqual(R.plan(30, self.stored(90), 'tb-index'), R.UPDATE)
        self.assertEqual(R.plan(90, self.stored(90, 'old'), 'tb-index'), R.UPDATE)

    def test_an_edit_made_elsewhere_is_put_back(self):
        stored = self.stored()
        stored['policy']['states'][0]['actions'].append({'snapshot': {'repository': 'x'}})
        self.assertEqual(R.plan(90, stored, 'tb-index'), R.UPDATE)

    def test_zero_removes_a_policy_or_does_nothing(self):
        self.assertEqual(R.plan(0, self.stored(), 'tb-index'), R.REMOVE)
        self.assertEqual(R.plan(0, None, 'tb-index'), R.OFF)


class EnsureTest(Setting, unittest.TestCase):
    """What the librarian does at every start."""

    def test_the_policy_is_created(self):
        result = self.ensure(90)
        self.assertEqual(result['action'], R.CREATE)
        self.assertEqual(self.stored_age(), '90d')
        method, path, params, _ = self.os.writes[0]
        self.assertEqual((method, path, params),
                         ('PUT', '/_plugins/_ism/policies/' + R.POLICY_ID, None))

    def test_existing_indices_are_not_attached_on_upgrade(self):
        self.os.index('tb-index-2025-01-01', 400)
        self.os.index('tb-index-2026-09-30', 5)
        result = self.ensure(90)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), [])
        self.assertEqual([w for w in self.os.writes if w[0] == 'POST'], [])
        self.assertEqual(result['unmanaged'], ['tb-index-2025-01-01', 'tb-index-2026-09-30'])
        self.assertEqual(result['overdue'], ['tb-index-2025-01-01'])

    def test_the_log_says_how_many_are_uncovered_and_how_to_opt_in(self):
        self.os.index('tb-index-2025-01-01', 400)
        self.os.index('tb-index-2026-09-30', 5)
        self.ensure(90)
        self.assertIn('2 existing TurkeyBite indices are not under the retention policy',
                      self.log())
        self.assertIn('1 of them are already older than 90 days', self.log())
        self.assertIn(R.ATTACH_COMMAND, self.log())

    def test_nothing_is_said_about_opting_in_when_everything_is_covered(self):
        self.os.index('tb-index-2026-09-30', 5, policy=R.POLICY_ID)
        self.ensure(90)
        self.assertNotIn('--attach-existing', self.log())

    def test_a_second_start_changes_nothing(self):
        self.ensure(90)
        writes = len(self.os.writes)
        result = self.ensure(90)
        self.assertEqual(result['action'], R.CURRENT)
        self.assertEqual(len(self.os.writes), writes)

    def test_a_new_period_updates_the_policy_with_its_sequence_number(self):
        self.ensure(90)
        seq_no = self.os.seq_no
        self.ensure(30)
        self.assertEqual(self.stored_age(), '30d')
        update = [w for w in self.os.writes if w[0] == 'PUT'][-1]
        self.assertEqual(update[2], {'if_seq_no': seq_no, 'if_primary_term': 1})

    def test_a_new_period_moves_only_the_indices_this_policy_manages(self):
        self.ensure(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID)
        self.os.index('tb-index-2026-09-02', 32, policy='someone-elses')
        self.os.index('tb-index-2025-01-01', 400)
        result = self.ensure(365)
        self.assertEqual(result['moved'], 1)
        self.assertTrue(self.os.indices['tb-index-2026-09-01'].get('moved'))
        self.assertEqual(self.os.indices['tb-index-2026-09-02']['policy'], 'someone-elses')
        self.assertIsNone(self.os.indices['tb-index-2025-01-01']['policy'])

    def test_without_moving_them_a_longer_period_would_not_apply(self):
        # The control for the test above: the move is a separate request, and
        # nothing else puts the managed index on the new version
        self.ensure(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID)
        with mock.patch.object(R.Cluster, 'move_to_latest', return_value=(0, [])):
            self.ensure(365)
        self.assertFalse(self.os.indices['tb-index-2026-09-01'].get('moved'))

    def test_a_concurrent_edit_is_refused_not_overwritten(self):
        self.ensure(90)
        real = self.os.policies

        def edited_meanwhile(method, params, body):
            if method == 'PUT':
                self.os.seq_no += 1
            return real(method, params, body)
        self.os.policies = edited_meanwhile
        with self.assertRaises(ConflictError):
            self.ensure(30)

    def test_zero_with_no_policy_writes_nothing_and_says_so_loudly(self):
        self.os.index('tb-index-2025-01-01', 400)
        result = self.ensure(0)
        self.assertEqual(result['action'], R.OFF)
        self.assertEqual(self.os.writes, [])
        self.assertIn('RETENTION IS OFF', self.log())
        self.assertIn('kept forever', self.log())

    def test_zero_takes_an_existing_policy_off_its_indices_and_deletes_it(self):
        self.ensure(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID)
        self.os.index('tb-index-2026-09-02', 32, policy='someone-elses')
        result = self.ensure(0)
        self.assertEqual(result['action'], R.REMOVE)
        self.assertEqual(result['detached'], 1)
        self.assertIsNone(self.os.policy)
        self.assertIsNone(self.os.indices['tb-index-2026-09-01']['policy'])
        self.assertEqual(self.os.indices['tb-index-2026-09-02']['policy'], 'someone-elses')
        self.assertIn('RETENTION IS OFF', self.log())

    def test_an_index_under_another_policy_is_reported_and_left_alone(self):
        self.os.index('tb-index-2026-09-02', 32, policy='someone-elses')
        result = self.ensure(90)
        self.assertEqual(result['other_policy'], ['tb-index-2026-09-02'])
        self.assertEqual(result['unmanaged'], [])
        self.assertIn('managed by another ISM policy', self.log())

    def test_an_index_that_only_shares_the_prefix_is_not_counted(self):
        self.os.index('tb-index-other', 400)
        result = self.ensure(90)
        self.assertEqual(result['unmanaged'], [])

    def test_a_dry_run_writes_nothing(self):
        self.os.index('tb-index-2025-01-01', 400)
        self.ensure(90, dry_run=True)
        self.assertEqual(self.os.writes, [])
        self.assertIn('Dry run: would create', self.log())


class AttachExistingTest(Setting, unittest.TestCase):
    """The explicit opt-in for indices that existed before the policy."""

    def history(self):
        self.os.index('tb-index-2025-01-01', 400)
        self.os.index('tb-index-2026-09-30', 5)
        self.os.index('tb-index-2026-09-02', 32, policy='someone-elses')
        self.os.index('tb-index-other', 400)

    def test_it_attaches_the_unmanaged_daily_indices(self):
        self.history()
        result = self.attach(90)
        self.assertEqual(result['attached'], 2)
        self.assertEqual(self.os.managed_by(R.POLICY_ID),
                         ['tb-index-2025-01-01', 'tb-index-2026-09-30'])
        self.assertIn('1 of them are older than 90 days', self.log())

    def test_the_librarian_alone_would_not_have(self):
        # The control: the same history, and ensure() leaves it all unmanaged
        self.history()
        self.ensure(90)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), [])

    def test_another_policy_and_other_indices_are_left_alone(self):
        self.history()
        self.attach(90)
        self.assertEqual(self.os.indices['tb-index-2026-09-02']['policy'], 'someone-elses')
        self.assertIsNone(self.os.indices['tb-index-other']['policy'])

    def test_it_creates_the_policy_first_if_the_librarian_has_not(self):
        self.history()
        self.attach(30)
        self.assertEqual(self.stored_age(), '30d')
        kinds = [w[0] for w in self.os.writes]
        self.assertLess(kinds.index('PUT'), kinds.index('POST'))

    def test_a_dry_run_lists_them_and_writes_nothing(self):
        self.history()
        result = self.attach(90, dry_run=True)
        self.assertEqual(self.os.writes, [])
        self.assertEqual(result['attached'], 2)
        self.assertIn("tb-index-2025-01-01  created 400 days ago, deleted at ISM's next check",
                      self.log())
        self.assertIn('tb-index-2026-09-30  created 5 days ago', self.log())
        self.assertIn('Dry run: would attach the policy to 2', self.log())

    def test_there_is_nothing_to_attach_when_retention_is_off(self):
        self.history()
        with self.assertRaises(ValueError):
            self.attach(0)
        self.assertEqual(self.os.writes, [])

    def test_nothing_unmanaged_means_nothing_attached(self):
        self.os.index('tb-index-2026-09-30', 5, policy=R.POLICY_ID)
        result = self.attach(90)
        self.assertEqual(result['attached'], 0)
        self.assertEqual([w for w in self.os.writes if w[0] == 'POST'], [])

    def test_years_of_indices_go_in_batches(self):
        for day in range(120):
            self.os.index(f'tb-index-2026-{day // 28 + 1:02d}-{day % 28 + 1:02d}', 300 - day)
        result = self.attach(90)
        self.assertEqual(result['attached'], 120)
        adds = [w for w in self.os.writes if w[1].startswith('/_plugins/_ism/add/')]
        self.assertEqual(len(adds), 3)
        for _, path, _, _ in adds:
            self.assertLessEqual(len(path.rsplit('/', 1)[1].split(',')), R.BATCH)


class FakeClient(object):
    """Stands in for opensearchpy.OpenSearch in the command."""

    built = []
    cluster = None

    def __init__(self, **kwargs):
        FakeClient.built.append(kwargs)
        self.transport = mock.Mock(perform_request=FakeClient.cluster)


class CommandTest(unittest.TestCase):
    """`turkeybite retention`, as the librarian and an operator run it."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(ROOT, 'src', 'turkeybite')
        loader = importlib.machinery.SourceFileLoader('turkeybite_retention_cli', path)
        spec = importlib.util.spec_from_loader('turkeybite_retention_cli', loader)
        cls.cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cls.cli)

    def setUp(self):
        from libtb import opensearch
        opensearch._warned.clear()
        self.addCleanup(opensearch._warned.clear)
        self.os = FakeOpenSearch()
        self.os.index('tb-index-2025-01-01', 400)
        FakeClient.built = []
        FakeClient.cluster = self.os

    def run_cli(self, args, read_config=None, **env):
        from click.testing import CliRunner
        base = {'OPENSEARCH_HOST': 'opensearch', 'OPENSEARCH_USERNAME': 'admin',
                'OPENSEARCH_PASSWORD': 'Not-the-default.1', 'OPENSEARCH_CA_CERT': '',
                'TURKEYBITE_RETENTION_DAYS': '', 'TURKEYBITE_ALLOW_DEFAULT_PASSWORD': ''}
        base.update(env)
        config = read_config or mock.Mock(side_effect=AssertionError('read config'))
        with mock.patch('opensearchpy.OpenSearch', FakeClient), \
                mock.patch.object(self.cli, 'read_config', config), \
                mock.patch.dict(os.environ, base):
            return CliRunner().invoke(self.cli.cli, ['retention'] + args)

    def test_it_creates_the_policy_and_leaves_history_alone(self):
        result = self.run_cli(['--prefix', 'tb-index'])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIsNotNone(self.os.policy)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), [])
        self.assertIn('--attach-existing', result.output)
        self.assertEqual(FakeClient.built[0]['hosts'], [{'host': 'opensearch', 'port': 9200}])

    def test_the_prefix_comes_from_config_yaml(self):
        config = mock.Mock(return_value={'processor': {'elastic': {'index_prefix': 'campus'}}})
        result = self.run_cli([], read_config=config)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.os.policy['ism_template'][0]['index_patterns'], ['campus-*'])

    def test_the_period_comes_from_the_variable(self):
        result = self.run_cli(['--prefix', 'tb-index'], TURKEYBITE_RETENTION_DAYS='30')
        self.assertEqual(result.exit_code, 0, result.output)
        hot = self.os.policy['states'][0]
        self.assertEqual(hot['transitions'][0]['conditions']['min_index_age'], '30d')

    def test_attach_existing_is_the_opt_in(self):
        result = self.run_cli(['--prefix', 'tb-index', '--attach-existing'])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), ['tb-index-2025-01-01'])

    def test_a_dry_run_changes_nothing(self):
        result = self.run_cli(['--prefix', 'tb-index', '--attach-existing', '--dry-run'])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.os.writes, [])
        self.assertIn('tb-index-2025-01-01', result.output)

    def test_a_bad_period_stops_it_before_connecting(self):
        result = self.run_cli(['--prefix', 'tb-index'], TURKEYBITE_RETENTION_DAYS='90d')
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn('whole number of days', result.output)
        self.assertEqual(FakeClient.built, [])

    def test_the_default_password_is_refused_before_connecting(self):
        result = self.run_cli(['--prefix', 'tb-index'], OPENSEARCH_PASSWORD='Changeit12345!')
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn('Changing the OpenSearch admin password', result.output)
        self.assertEqual(FakeClient.built, [])

    def test_the_escape_hatch_opens_it(self):
        # The control for the refusal above
        result = self.run_cli(['--prefix', 'tb-index'], OPENSEARCH_PASSWORD='Changeit12345!',
                              TURKEYBITE_ALLOW_DEFAULT_PASSWORD='yes')
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(len(FakeClient.built), 1)

    def test_no_password_is_refused(self):
        result = self.run_cli(['--prefix', 'tb-index'], OPENSEARCH_PASSWORD='')
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn('OPENSEARCH_PASSWORD is not set', result.output)

    def test_the_ca_reaches_the_client(self):
        root = tempfile.mkdtemp(prefix='tb-retention-')
        self.addCleanup(shutil.rmtree, root, True)
        ca = os.path.join(root, 'root-ca.pem')
        with open(ca, 'w') as fh:
            fh.write('-----BEGIN CERTIFICATE-----\n')
        result = self.run_cli(['--prefix', 'tb-index', '--url', 'https://node-0.example.com:9200'],
                              OPENSEARCH_CA_CERT=ca)
        self.assertEqual(result.exit_code, 0, result.output)
        kwargs = FakeClient.built[0]
        self.assertIs(kwargs['verify_certs'], True)
        self.assertEqual(kwargs['ca_certs'], ca)
        self.assertEqual(kwargs['hosts'], [{'host': 'node-0.example.com', 'port': 9200}])
        self.assertNotIn('without verifying', result.output)

    def test_without_a_ca_it_says_so(self):
        result = self.run_cli(['--prefix', 'tb-index'])
        self.assertIs(FakeClient.built[0]['verify_certs'], False)
        self.assertIn('without verifying', result.output)

    def test_an_opensearch_failure_is_reported_not_raised(self):
        def refuses(*args, **kwargs):
            raise ConflictError(409, 'version_conflict_engine_exception', {})
        FakeClient.cluster = refuses
        result = self.run_cli(['--prefix', 'tb-index'])
        self.assertEqual(result.exit_code, 1)
        self.assertIn('OpenSearch refused the retention change', result.output)


class SetupRetentionTest(unittest.TestCase):
    """setup.py asks for the period, and writes it where the librarian reads it."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('tb_setup_retention',
                                                      os.path.join(ROOT, 'setup.py'))
        cls.setup = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.setup)

    def make(self, answers):
        self.root = tempfile.mkdtemp(prefix='tb-setup-')
        self.addCleanup(shutil.rmtree, self.root, True)
        with mock.patch.object(self.setup.TurkeyBiteSetup, 'ensure_directories'):
            setup = self.setup.TurkeyBiteSetup()
        setup.base_dir = self.setup.Path(self.root)
        answers = list(answers)
        setup.prompt = lambda message, options=None: answers.pop(0)
        return setup

    def test_the_default_matches_the_librarians(self):
        self.assertEqual(self.setup.DEFAULT_RETENTION_DAYS, R.DEFAULT_DAYS)

    def test_enter_takes_the_default_and_zero_means_forever(self):
        for answers, days in (([''], 90), (['0'], 0), (['30'], 30), (['ninety', '-1', '7'], 7)):
            setup = self.make(answers)
            with mock.patch('builtins.print'):
                setup.setup_retention()
            self.assertEqual(setup.retention_days, days, answers)

    def test_it_reaches_the_librarians_environment(self):
        setup = self.make(['14'])
        setup.components = ['librarian']
        with mock.patch('builtins.print'):
            setup.setup_retention()
            setup.setup_env()
        with open(os.path.join(self.root, '.env')) as fh:
            self.assertIn('TURKEYBITE_RETENTION_DAYS=14\n', fh.read())


if __name__ == '__main__':
    unittest.main(verbosity=2)
