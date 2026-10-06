"""Tests for the retention policy that deletes old TurkeyBite indices.

Deleting an index cannot be undone, so what must never happen is the librarian
deleting sooner than the current state would without an operator asking it to.
An unset variable changes nothing. A shorter period, a typo of 9 for 90 say, is
refused until confirmed. An upgrade never attaches the policy to the indices a
deployment already holds. Each of those has a control showing the same change
does happen once the operator asks for it.

Nor may the policy be left half applied, or claim to be off while it can still
delete. A managed index left on an older version of the policy is moved at
every start until it is not, and turning retention off deletes the policy only
once no index is left under it. An operator's own policy is never overridden.

No test touches the network. The ISM API is replaced by an in-memory fake that
answers as a real opensearch:3 (3.9.0) was measured to: lists of 20 unless a
size is given, the version a managed index is on reported by explain once ISM
has initialised it, a whole batch refused when one index in it is gone, and an
overlapping template at the same priority rejected.
"""

import fnmatch
import importlib.machinery
import importlib.util
import math
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'src'))

from opensearchpy.exceptions import ConflictError, NotFoundError, TransportError

from libtb import retention as R

NOW = 1_800_000_000.0
DAY = 86400

# OpenSearch's own overlap check, held apart from the one the code under test
# uses, so a test can switch the code's off without switching OpenSearch's off
OPENSEARCH_OVERLAP = R.patterns_overlap


def ms(days_ago):
    """An index creation time, as OpenSearch reports it, `days_ago` before NOW."""
    return int((NOW - days_ago * DAY) * 1000)


class FakeOpenSearch(object):
    """The ISM endpoints retention uses, held in memory.

    Called as opensearchpy's Transport.perform_request is. Every write is
    recorded in `writes`, every read in `reads`, and `refuse` names indices an
    action fails for, as OpenSearch reports such a failure.
    """

    def __init__(self):
        self.policies = {}
        self.seq_no = 0
        self.indices = {}
        self.writes = []
        self.reads = []
        self.refuse = {}
        # Indices explain leaves out of its next answer, as a real cluster
        # does for about a second after attaching one
        self.unlisted = set()

    # -- arranging --------------------------------------------------------

    def index(self, name, days_ago, policy=None, initialised=True, version=None):
        self.indices[name] = {'created': ms(days_ago), 'policy': policy, 'version': None}
        if policy and initialised:
            self.indices[name]['version'] = version or self.version(policy)

    def operator_policy(self, policy_id, patterns, priority=None):
        template = {'index_patterns': list(patterns)}
        if priority is not None:
            template['priority'] = priority
        self.store(policy_id, {'description': 'theirs', 'default_state': 'a',
                               'states': [{'name': 'a', 'actions': [], 'transitions': []}],
                               'ism_template': [template]})

    def version(self, policy_id):
        stored = self.policies.get(policy_id)
        return (stored['_seq_no'], 1) if stored else None

    def managed_by(self, policy_id):
        return sorted(n for n, i in self.indices.items() if i['policy'] == policy_id)

    def store(self, policy_id, body):
        import copy
        policy = copy.deepcopy(body)
        policy.update({'policy_id': policy_id, 'last_updated_time': 1791164226671,
                       'schema_version': 31, 'error_notification': None})
        for state in policy['states']:
            for action in state['actions']:
                action['retry'] = {'count': 3, 'backoff': 'exponential', 'delay': '1m'}
        for template in policy.get('ism_template') or []:
            template.setdefault('priority', 0)
            template['last_updated_time'] = 1791164226671
        self.seq_no += 7
        self.policies[policy_id] = {'_id': policy_id, '_seq_no': self.seq_no,
                                    '_primary_term': 1, 'policy': policy}
        return self.policies[policy_id]

    # -- answering --------------------------------------------------------

    def __call__(self, method, path, params=None, body=None):
        (self.reads if method == 'GET' else self.writes).append((method, path, params, body))
        parts = path.strip('/').split('/')
        if parts[:3] == ['_plugins', '_ism', 'policies']:
            return self.answer_policies(method, parts[3] if len(parts) > 3 else None,
                                        params or {}, body)
        if parts == ['_cat', 'indices']:
            return [{'index': n, 'creation.date': str(i['created'])}
                    for n, i in sorted(self.indices.items())]
        if parts == ['_plugins', '_ism', 'explain']:
            return self.explain(params or {})
        return self.act(parts[2], parts[3].split(','), body)

    def page(self, items, params):
        start, size = int(params.get('from', 0)), int(params.get('size', 20))
        return items[start:start + size]

    def answer_policies(self, method, policy_id, params, body):
        if policy_id is None:
            listed = [self.policies[k] for k in sorted(self.policies)]
            return {'policies': self.page(listed, params), 'total_policies': len(listed)}
        if method == 'GET':
            if policy_id not in self.policies:
                raise NotFoundError(404, 'index_not_found_exception', {})
            return dict(self.policies[policy_id])
        if method == 'DELETE':
            del self.policies[policy_id]
            return {'result': 'deleted'}
        if policy_id in self.policies:
            current = (self.policies[policy_id]['_seq_no'], 1)
            if (params.get('if_seq_no'), params.get('if_primary_term')) != current:
                raise ConflictError(409, 'version_conflict_engine_exception', {})
        for template in body['policy'].get('ism_template') or []:
            for other_id, other in self.policies.items():
                for theirs in other['policy'].get('ism_template') or []:
                    if other_id != policy_id and theirs['priority'] == template.get('priority', 0) \
                            and any(OPENSEARCH_OVERLAP(a, b) for a in template['index_patterns']
                                    for b in theirs['index_patterns']):
                        raise TransportError(400, 'index_management_exception',
                                             {'error': {'reason': 'matching existing policy '
                                                                  'templates'}})
        stored = self.store(policy_id, body['policy'])
        return {'_id': policy_id, '_seq_no': stored['_seq_no'], '_primary_term': 1}

    def explain(self, params):
        managed = sorted(n for n, i in self.indices.items()
                         if i['policy'] and n not in self.unlisted)
        self.unlisted = set()
        answer = {}
        for name in self.page(managed, params):
            index = self.indices[name]
            entry = {'index.plugins.index_state_management.policy_id': index['policy'],
                     'index.opendistro.index_state_management.policy_id': index['policy'],
                     'index': name, 'policy_id': index['policy'], 'enabled': True}
            if index['version']:
                entry.update(policy_seq_no=index['version'][0],
                             policy_primary_term=index['version'][1],
                             index_creation_date=index['created'])
            answer[name] = entry
        answer['total_managed_indices'] = len(managed)
        return answer

    def act(self, verb, names, body):
        missing = [n for n in names if n not in self.indices]
        if missing:
            raise NotFoundError(404, 'index_not_found_exception',
                                {'error': {'reason': f'no such index [{missing[0]}]'}})
        updated, failed = 0, []
        for name in names:
            index = self.indices[name]
            if name in self.refuse.get(verb, ()):
                failed.append((name, 'refused for the test'))
            elif verb == 'add':
                if index['policy']:
                    failed.append((name, 'This index already has a policy'))
                    continue
                index.update(policy=body['policy_id'], version=None)
                updated += 1
            elif verb == 'change_policy':
                if not index['policy']:
                    failed.append((name, 'This index is not being managed'))
                    continue
                # Applied at ISM's next check; the fake applies it at once
                index['version'] = self.version(body['policy_id'])
                updated += 1
            elif verb == 'remove':
                if not index['policy']:
                    failed.append((name, 'This index does not have a policy'))
                    continue
                index.update(policy=None, version=None)
                updated += 1
        return {'updated_indices': updated, 'failures': bool(failed),
                'failed_indices': [{'index_name': n, 'index_uuid': 'x', 'reason': r}
                                   for n, r in failed]}


class Setting(object):
    """Runs a start, reconcile over a fake, and collects what it logged."""

    def setUp(self):
        self.os = FakeOpenSearch()
        self.lines = []
        self.waited = []

    def start(self, days=90, prefix='tb-index', dry_run=False, **kwargs):
        cluster = R.Cluster(self.os, dry_run=dry_run, log=self.lines.append,
                            wait=self.waited.append)
        return R.reconcile(cluster, days, prefix, log=self.lines.append, now=NOW, **kwargs)

    def log(self):
        return '\n'.join(self.lines)

    def stored_days(self):
        return R.period_days(self.os.policies[R.POLICY_ID]['policy'])

    def puts(self):
        return [w for w in self.os.writes if w[0] == 'PUT']

    def posts(self, verb=''):
        return [w for w in self.os.writes if w[0] == 'POST' and f'/_ism/{verb}' in w[1]]

    def policy_at(self, days):
        """A policy already in place at `days`, as an earlier start left it."""
        self.start(days)
        self.os.writes.clear()
        self.lines.clear()


class PolicyTest(unittest.TestCase):
    """The policy body, and the settings it is built from."""

    def test_the_body_deletes_after_the_period(self):
        body = R.policy(90, 'tb-index')['policy']
        hot, delete = body['states']
        self.assertEqual(body['default_state'], 'hot')
        self.assertEqual(hot['transitions'], [{'state_name': 'delete',
                                               'conditions': {'min_index_age': '90d'}}])
        self.assertEqual(delete['actions'], [{'delete': {}}])

    def test_the_template_names_daily_indices_and_sets_no_priority(self):
        body = R.policy(30, 'tb-index')['policy']
        self.assertEqual(body['ism_template'], [{'index_patterns': ['tb-index-2*']}])

    def test_a_policy_can_be_kept_without_its_template(self):
        self.assertNotIn('ism_template', R.policy(30, 'tb-index', template=False)['policy'])

    def test_the_pattern_matches_daily_indices_only(self):
        pattern = R.index_pattern('tb-index')
        self.assertTrue(fnmatch.fnmatchcase('tb-index-2026-10-04', pattern))
        for name in ('tb-index-incident-4711', 'tb-index-archive-2025', 'tb-index-other'):
            self.assertFalse(fnmatch.fnmatchcase(name, pattern), name)

    def test_one_day_is_the_shortest_policy(self):
        self.assertEqual(R.period_days(R.policy(1, 'tb-index')['policy']), 1)
        with self.assertRaises(ValueError):
            R.policy(0, 'tb-index')

    def test_unset_is_not_a_period(self):
        for value in (None, '', '  '):
            self.assertIsNone(R.retention_days(value), repr(value))

    def test_days_are_read_from_the_variable(self):
        for value, days in (('0', 0), (' 30 ', 30), ('365', 365), ('0090', 90)):
            self.assertEqual(R.retention_days(value), days, value)

    def test_days_that_are_not_a_whole_number_are_refused(self):
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
        self.assertFalse(R.is_daily('tbXindex-2026-01-01', 'tb.index'))

    def test_the_period_in_force_is_read_from_a_stored_policy(self):
        stored = FakeOpenSearch().store('p', R.policy(90, 'tb-index')['policy'])['policy']
        self.assertEqual(R.period_days(stored), 90)
        hours = R.policy(1, 'tb-index')['policy']
        hours['states'][0]['transitions'][0]['conditions']['min_index_age'] = '36h'
        self.assertEqual(R.period_days(hours), 1.5)

    def test_a_policy_that_deletes_nothing_has_no_limit(self):
        # Any period that does delete is then shorter, and needs confirming
        kept = R.policy(90, 'tb-index')['policy']
        kept['states'][1]['actions'] = []
        self.assertEqual(R.period_days(kept), math.inf)
        odd = R.policy(90, 'tb-index')['policy']
        odd['states'][0]['transitions'][0]['conditions'] = {'min_doc_count': 5}
        self.assertEqual(R.period_days(odd), math.inf)

    def test_patterns_overlap_when_one_name_can_match_both(self):
        for a, b in (('tb-index-2*', 'tb-*'), ('tb-index-2*', '*'), ('tb-index-2*', 'tb-index-*'),
                     ('tb-index-2*', '*-2026-*'), ('tb-index-2*', 'tb-index-2026-01-01'),
                     ('*a', 'b*')):
            self.assertTrue(R.patterns_overlap(a, b), (a, b))
            self.assertTrue(R.patterns_overlap(b, a), (b, a))

    def test_patterns_that_share_no_name_do_not_overlap(self):
        for a, b in (('tb-index-2*', 'logs-*'), ('tb-index-2*', 'tb-index-incident-*'),
                     ('tb-index-2*', 'tb-index'), ('a*b', 'a*c')):
            self.assertFalse(R.patterns_overlap(a, b), (a, b))


class UnsetTest(Setting, unittest.TestCase):
    """An unset variable means nothing is done, whatever is already there."""

    def test_nothing_is_created(self):
        result = self.start(None)
        self.assertEqual(result['action'], R.UNCONFIGURED)
        self.assertEqual(self.os.writes, [])
        self.assertIn('RETENTION IS NOT CONFIGURED', self.log())
        self.assertIn('nothing deletes TurkeyBite indices', self.log())

    def test_indices_holding_a_copy_of_a_deleted_policy_are_not_called_safe(self):
        # ISM runs its copy of a policy after the policy is deleted
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID)
        self.start(None)
        self.assertEqual(self.os.writes, [])
        self.assertIn('ISM can still delete them', self.log())
        self.assertNotIn('nothing deletes', self.log())

    def test_an_existing_policy_is_left_alone_and_described(self):
        self.policy_at(365)
        self.os.index('tb-index-2025-01-01', 400, policy=R.POLICY_ID)
        self.start(None)
        self.assertEqual(self.os.writes, [])
        self.assertEqual(self.stored_days(), 365)
        self.assertIn('left as it is: it deletes indices after 365 days, and manages 1 '
                      'indices', self.log())

    def test_set_it_is_applied(self):
        # The control for the two tests above
        self.start(90)
        self.assertEqual(self.stored_days(), 90)


class CreateTest(Setting, unittest.TestCase):
    """The first start with a period, and the starts after it."""

    def test_the_policy_is_created(self):
        result = self.start(90)
        self.assertEqual(result['action'], R.CREATE)
        self.assertTrue(result['ok'])
        self.assertEqual(self.stored_days(), 90)
        self.assertEqual(self.puts()[0][2], None)

    def test_existing_indices_are_not_attached_on_upgrade(self):
        self.os.index('tb-index-2025-01-01', 400)
        self.os.index('tb-index-2026-09-30', 5)
        result = self.start(90)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), [])
        self.assertEqual(self.posts(), [])
        self.assertEqual(result['unmanaged'], ['tb-index-2025-01-01', 'tb-index-2026-09-30'])
        self.assertEqual(result['overdue'], ['tb-index-2025-01-01'])
        self.assertIn('2 existing TurkeyBite indices are not under the retention policy',
                      self.log())
        self.assertIn(R.ATTACH_COMMAND, self.log())

    def test_a_second_start_changes_nothing(self):
        self.policy_at(90)
        result = self.start(90)
        self.assertEqual(result['action'], R.CURRENT)
        self.assertEqual(self.os.writes, [])

    def test_a_dry_run_writes_nothing(self):
        self.start(90, dry_run=True)
        self.assertEqual(self.os.writes, [])
        self.assertIn('Dry run: would have created', self.log())


class LengthenTest(Setting, unittest.TestCase):
    """A longer period is applied at start, to the indices already under it too."""

    def test_it_is_applied_with_the_sequence_number(self):
        self.policy_at(90)
        seq_no = self.os.policies[R.POLICY_ID]['_seq_no']
        result = self.start(365)
        self.assertEqual(result['action'], R.UPDATE)
        self.assertTrue(result['ok'])
        self.assertEqual(self.stored_days(), 365)
        self.assertEqual(self.puts()[0][2], {'if_seq_no': seq_no, 'if_primary_term': 1})

    def test_the_indices_it_manages_are_moved_onto_it(self):
        self.policy_at(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID)
        self.os.index('tb-index-2026-09-02', 32, policy='someone-elses')
        self.os.index('tb-index-2025-01-01', 400)
        result = self.start(365)
        self.assertEqual(result['moved'], 1)
        self.assertEqual(self.os.indices['tb-index-2026-09-01']['version'],
                         self.os.version(R.POLICY_ID))
        self.assertEqual(self.os.indices['tb-index-2026-09-02']['policy'], 'someone-elses')
        self.assertIsNone(self.os.indices['tb-index-2025-01-01']['policy'])

    def test_a_concurrent_edit_is_refused_not_overwritten(self):
        self.policy_at(90)
        real = self.os.answer_policies

        def edited_meanwhile(method, policy_id, params, body):
            if method == 'PUT':
                self.os.policies[R.POLICY_ID]['_seq_no'] += 1
            return real(method, policy_id, params, body)
        self.os.answer_policies = edited_meanwhile
        with self.assertRaises(ConflictError):
            self.start(365)


class ShortenTest(Setting, unittest.TestCase):
    """A shorter period deletes sooner, so it waits for the operator."""

    def history(self):
        self.policy_at(90)
        for days_ago in (5, 20, 40, 60, 89):
            self.os.index(f'tb-index-2026-x{days_ago:02d}', days_ago, policy=R.POLICY_ID)

    def test_it_is_refused_at_start(self):
        self.history()
        result = self.start(9)
        self.assertEqual(result['action'], R.REFUSED)
        self.assertFalse(result['ok'])
        self.assertEqual(self.puts(), [])
        self.assertEqual(self.stored_days(), 90)
        self.assertEqual(len(self.os.managed_by(R.POLICY_ID)), 5)

    def test_the_log_says_what_it_would_delete_and_how_to_confirm(self):
        self.history()
        self.start(9)
        self.assertIn('would delete 4 more of the 5 indices it manages', self.log())
        self.assertIn(R.CONFIRM_COMMAND.format(days=9), self.log())
        self.assertIn('--dry-run', self.log())

    def test_with_only_a_copy_of_a_deleted_policy_it_counts_what_is_old_enough(self):
        # The copy's period cannot be read, so how many more would go is not
        # known; how many are old enough for the new period is
        for days_ago in (5, 20, 40, 60, 89):
            self.os.index(f'tb-index-2026-x{days_ago:02d}', days_ago, policy=R.POLICY_ID)
        self.start(9)
        self.assertIn('4 of the 5 indices it manages are 9 days old or more', self.log())
        self.assertNotIn('more of the', self.log())

    def test_a_dry_run_lists_them(self):
        self.history()
        self.start(9, dry_run=True)
        self.assertIn('tb-index-2026-x60  created 60 days ago', self.log())
        self.assertNotIn('tb-index-2026-x05', self.log())
        self.assertEqual(self.os.writes, [])

    def test_confirming_the_period_applies_it(self):
        # The control for the refusal
        self.history()
        result = self.start(9, confirm_days=9)
        self.assertEqual(result['action'], R.UPDATE)
        self.assertTrue(result['ok'])
        self.assertEqual(self.stored_days(), 9)
        self.assertEqual(result['moved'], 5)

    def test_a_dry_run_of_the_confirmation_says_what_it_would_move(self):
        self.history()
        result = self.start(9, dry_run=True, confirm_days=9)
        self.assertEqual(self.os.writes, [])
        self.assertEqual(result['moved'], 5)
        self.assertIn('Dry run: would move 5 of the 5 indices', self.log())

    def test_confirming_another_number_changes_nothing(self):
        self.history()
        result = self.start(9, confirm_days=90)
        self.assertEqual(result['action'], R.REFUSED)
        self.assertEqual(self.puts(), [])
        self.assertIn('--confirm-days 90 does not match', self.log())

    def test_a_policy_edited_to_delete_nothing_counts_as_longer_than_any(self):
        self.policy_at(90)
        self.os.policies[R.POLICY_ID]['policy']['states'][1]['actions'] = []
        result = self.start(365)
        self.assertEqual(result['action'], R.REFUSED)

    def test_recreating_a_deleted_policy_under_old_indices_needs_confirming(self):
        # Indices still pointing at the policy resume once it exists again
        self.os.index('tb-index-2025-01-01', 400, policy=R.POLICY_ID, initialised=False)
        result = self.start(90)
        self.assertEqual(result['action'], R.REFUSED)
        self.assertEqual(self.puts(), [])

    def test_recreating_over_indices_too_young_to_delete_still_needs_confirming(self):
        # Their copy of the deleted policy may have kept them longer than 90
        # days, and creating it again would move them onto 90 days unasked
        self.os.index('tb-index-2026-x20', 20, policy=R.POLICY_ID, initialised=False)
        result = self.start(90)
        self.assertEqual(result['action'], R.REFUSED)
        self.assertEqual(self.puts(), [])
        self.assertIn('copy of an earlier', self.log())

    def test_confirming_the_recreation_creates_it_and_moves_them(self):
        # The control for the refusal above
        self.os.index('tb-index-2026-x20', 20, policy=R.POLICY_ID, initialised=False)
        result = self.start(90, confirm_days=90)
        self.assertEqual(result['action'], R.CREATE)
        self.assertTrue(result['ok'])

    def test_nothing_is_attached_while_it_is_refused(self):
        self.history()
        self.os.index('tb-index-2024-01-01', 700)
        result = self.start(9, attach_existing=True)
        self.assertEqual(result['attached'], 0)
        self.assertIsNone(self.os.indices['tb-index-2024-01-01']['policy'])


class ConvergeTest(Setting, unittest.TestCase):
    """Indices left on an older version are moved at every start until none are."""

    def test_a_lagging_index_is_moved_even_when_the_policy_is_current(self):
        self.policy_at(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID, version=(1, 1))
        self.os.index('tb-index-2026-09-02', 32, policy=R.POLICY_ID)
        result = self.start(90)
        self.assertEqual(result['action'], R.CURRENT)
        self.assertEqual(result['moved'], 1)
        self.assertEqual(self.os.indices['tb-index-2026-09-01']['version'],
                         self.os.version(R.POLICY_ID))
        moves = self.posts('change_policy')
        self.assertEqual(moves[0][1], '/_plugins/_ism/change_policy/tb-index-2026-09-01')

    def test_a_move_that_fails_fails_the_start_and_is_retried(self):
        self.policy_at(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID, version=(1, 1))
        self.os.refuse['change_policy'] = {'tb-index-2026-09-01'}
        result = self.start(90)
        self.assertFalse(result['ok'])
        self.assertIn('still on an older version', self.log())
        self.os.refuse.clear()
        result = self.start(90)
        self.assertTrue(result['ok'])
        self.assertEqual(result['moved'], 1)

    def test_an_index_ism_has_not_started_is_left_to_start_on_the_current_version(self):
        self.policy_at(90)
        self.os.index('tb-index-2026-10-04', 0, policy=R.POLICY_ID, initialised=False)
        result = self.start(90)
        self.assertEqual(result['moved'], 0)
        self.assertEqual(self.posts(), [])

    def test_indices_under_another_policy_are_never_moved(self):
        self.policy_at(90)
        self.os.index('tb-index-2026-09-02', 32, policy='someone-elses', version=(1, 1))
        self.start(90)
        self.assertEqual(self.posts(), [])


class TurnOffTest(Setting, unittest.TestCase):
    """0 takes the policy off everything it manages before it is deleted."""

    def test_every_index_it_manages_is_detached_under_any_prefix(self):
        self.policy_at(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID)
        self.os.index('old-prefix-2025-01-01', 400, policy=R.POLICY_ID)
        self.os.index('tb-index-2026-09-02', 32, policy='someone-elses')
        result = self.start(0)
        self.assertTrue(result['ok'])
        self.assertEqual(result['detached'], 2)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), [])
        self.assertNotIn(R.POLICY_ID, self.os.policies)
        self.assertEqual(self.os.indices['tb-index-2026-09-02']['policy'], 'someone-elses')
        self.assertIn('RETENTION IS OFF', self.log())

    def test_a_failed_detach_keeps_the_policy_and_says_it_can_still_delete(self):
        self.policy_at(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID)
        self.os.index('tb-index-2026-09-03', 31, policy=R.POLICY_ID)
        self.os.refuse['remove'] = {'tb-index-2026-09-01'}
        result = self.start(0)
        self.assertFalse(result['ok'])
        self.assertIn(R.POLICY_ID, self.os.policies)
        self.assertIn('can still delete them', self.log())
        self.assertNotIn('deleted it', self.log())

    def test_an_index_gone_meanwhile_fails_its_batch_and_is_retried(self):
        # OpenSearch refuses a whole batch naming an index that no longer exists
        self.policy_at(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID)
        real = self.os.explain

        def with_a_ghost(params):
            answer = real(params)
            answer['tb-index-2026-08-01'] = {'policy_id': R.POLICY_ID}
            return answer
        self.os.explain = with_a_ghost
        result = self.start(0)
        self.assertFalse(result['ok'])
        self.assertIn(R.POLICY_ID, self.os.policies)
        self.os.explain = real
        self.assertTrue(self.start(0)['ok'])
        self.assertNotIn(R.POLICY_ID, self.os.policies)

    def test_indices_left_pointing_at_a_deleted_policy_are_detached(self):
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID, initialised=False)
        result = self.start(0)
        self.assertEqual(result['detached'], 1)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), [])

    def test_the_template_goes_before_anything_is_taken_off(self):
        # Otherwise a new index could be attached while the others are detached
        self.policy_at(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID)
        self.start(0)
        kinds = [(method, path.split('/')[3]) for method, path, _, _ in self.os.writes]
        self.assertEqual(kinds, [('PUT', 'policies'), ('POST', 'remove'),
                                 ('DELETE', 'policies')])
        self.assertEqual(self.os.writes[0][3]['policy'].get('ism_template'), None)

    def test_an_index_attached_a_moment_ago_is_found_before_the_policy_goes(self):
        # A real cluster lists a just-attached index about a second later, and
        # that index would go on running ISM's copy of a deleted policy
        self.policy_at(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID)
        self.os.index('tb-index-2026-10-04', 0, policy=R.POLICY_ID, initialised=False)
        self.os.unlisted = {'tb-index-2026-10-04'}
        result = self.start(0)
        self.assertTrue(result['ok'])
        self.assertEqual(result['detached'], 2)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), [])
        self.assertNotIn(R.POLICY_ID, self.os.policies)
        self.assertEqual(self.waited, [R.SETTLE_SECONDS, R.SETTLE_SECONDS])

    def test_without_looking_again_it_would_have_been_missed(self):
        # The control: one look, as the snapshot alone gives, leaves it behind
        self.policy_at(90)
        self.os.index('tb-index-2026-10-04', 0, policy=R.POLICY_ID, initialised=False)
        self.os.unlisted = {'tb-index-2026-10-04'}
        with mock.patch.object(R, 'SETTLE_ROUNDS', 0):
            self.start(0)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), ['tb-index-2026-10-04'])

    def test_an_index_that_keeps_appearing_keeps_the_policy(self):
        self.policy_at(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID)
        real = self.os.act

        def reattached(verb, names, body):
            answer = real(verb, names, body)
            if verb == 'remove':
                self.os.indices['tb-index-2026-09-01'].update(policy=R.POLICY_ID)
            return answer
        self.os.act = reattached
        result = self.start(0)
        self.assertFalse(result['ok'])
        self.assertIn(R.POLICY_ID, self.os.policies)
        self.assertIn('can still delete them', self.log())

    def test_with_nothing_there_nothing_is_written(self):
        result = self.start(0)
        self.assertEqual(result['action'], R.OFF)
        self.assertEqual(self.os.writes, [])
        self.assertIn('RETENTION IS OFF', self.log())


class ConflictTest(Setting, unittest.TestCase):
    """An operator's own policy for the same indices is never overridden."""

    def test_an_overlapping_template_keeps_ours_off_new_indices(self):
        self.os.operator_policy('campus-retention', ['tb-*'], priority=5)
        result = self.start(90)
        self.assertFalse(result['ok'])
        self.assertEqual(result['conflicts'], ['campus-retention'])
        self.assertNotIn('ism_template', self.os.policies[R.POLICY_ID]['policy'])
        self.assertIn('RETENTION CONFLICT: the ISM policy campus-retention', self.log())

    def test_an_existing_template_of_ours_is_taken_off(self):
        self.policy_at(90)
        self.os.operator_policy('campus-retention', ['*'], priority=5)
        self.start(90)
        self.assertNotIn('ism_template', self.os.policies[R.POLICY_ID]['policy'])

    def test_without_that_check_ours_would_be_refused_or_compete(self):
        # The control: an equal-priority overlap is what OpenSearch rejects
        self.os.operator_policy('campus-retention', ['tb-*'], priority=0)
        with mock.patch.object(R, 'patterns_overlap', return_value=False):
            with self.assertRaises(TransportError):
                self.start(90)

    def test_a_policy_for_other_indices_is_no_conflict(self):
        self.os.operator_policy('logs-retention', ['logs-*', 'tb-index-incident-*'], priority=5)
        result = self.start(90)
        self.assertTrue(result['ok'])
        self.assertEqual(self.os.policies[R.POLICY_ID]['policy']['ism_template'][0]
                         ['index_patterns'], ['tb-index-2*'])


class AttachExistingTest(Setting, unittest.TestCase):
    """The explicit opt-in for indices that existed before the policy."""

    def history(self):
        self.os.index('tb-index-2025-01-01', 400)
        self.os.index('tb-index-2026-09-30', 5)
        self.os.index('tb-index-2026-09-02', 32, policy='someone-elses')
        self.os.index('tb-index-incident-4711', 400)
        self.os.index('tb-index-archive-2025', 400)

    def test_it_attaches_the_unmanaged_daily_indices(self):
        self.history()
        result = self.start(90, attach_existing=True)
        self.assertEqual(result['attached'], 2)
        self.assertEqual(self.os.managed_by(R.POLICY_ID),
                         ['tb-index-2025-01-01', 'tb-index-2026-09-30'])
        self.assertIn('1 of them are older than 90 days', self.log())

    def test_the_librarian_alone_would_not_have(self):
        # The control: the same history, and a start leaves it all unmanaged
        self.history()
        self.start(90)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), [])

    def test_other_policies_and_indices_that_are_not_daily_are_left_alone(self):
        self.history()
        self.start(90, attach_existing=True)
        self.assertEqual(self.os.indices['tb-index-2026-09-02']['policy'], 'someone-elses')
        for name in ('tb-index-incident-4711', 'tb-index-archive-2025'):
            self.assertIsNone(self.os.indices[name]['policy'], name)

    def test_it_creates_the_policy_first(self):
        self.history()
        self.start(30, attach_existing=True)
        kinds = [w[0] for w in self.os.writes]
        self.assertLess(kinds.index('PUT'), kinds.index('POST'))

    def test_a_dry_run_lists_them_and_writes_nothing(self):
        self.history()
        result = self.start(90, dry_run=True, attach_existing=True)
        self.assertEqual(self.os.writes, [])
        self.assertEqual(result['attached'], 2)
        self.assertIn("tb-index-2025-01-01  created 400 days ago, deleted at ISM's next check",
                      self.log())
        self.assertIn('Dry run: would attach the policy to 2', self.log())

    def test_years_of_indices_go_in_batches(self):
        for day in range(120):
            self.os.index(f'tb-index-2026-{day // 28 + 1:02d}-{day % 28 + 1:02d}', 300 - day)
        result = self.start(90, attach_existing=True)
        self.assertEqual(result['attached'], 120)
        adds = self.posts('add')
        self.assertEqual(len(adds), 3)
        for _, path, _, _ in adds:
            self.assertLessEqual(len(path.rsplit('/', 1)[1].split(',')), R.BATCH)


class OnePassTest(Setting, unittest.TestCase):
    """Each start reads the cluster once and works from that."""

    def test_policies_managed_indices_and_indices_are_each_read_once(self):
        self.policy_at(90)
        self.os.index('tb-index-2026-09-01', 33, policy=R.POLICY_ID, version=(1, 1))
        self.os.index('tb-index-2025-01-01', 400)
        self.os.reads.clear()
        self.start(365)
        paths = [path for _, path, _, _ in self.os.reads]
        self.assertEqual(sorted(paths), ['/_cat/indices', '/_plugins/_ism/explain',
                                         '/_plugins/_ism/policies'])

    def test_long_lists_are_read_page_by_page(self):
        # Both APIs return 20 unless asked; past a page, the rest must be read
        with mock.patch.object(R, 'PAGE', 2):
            self.policy_at(90)
            for n in range(5):
                self.os.index(f'tb-index-2026-09-{n + 1:02d}', 40, policy=R.POLICY_ID,
                              version=(1, 1))
                self.os.operator_policy(f'other-{n}', [f'logs-{n}-*'])
            self.os.reads.clear()
            result = self.start(90)
        self.assertEqual(result['moved'], 5)
        paths = [path for _, path, _, _ in self.os.reads]
        self.assertEqual(paths.count('/_plugins/_ism/explain'), 3)
        self.assertEqual(paths.count('/_plugins/_ism/policies'), 3)


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
                'TURKEYBITE_RETENTION_DAYS': '90', 'TURKEYBITE_ALLOW_DEFAULT_PASSWORD': ''}
        base.update(env)
        config = read_config or mock.Mock(side_effect=AssertionError('read config'))
        with mock.patch('opensearchpy.OpenSearch', FakeClient), \
                mock.patch.object(self.cli, 'read_config', config), \
                mock.patch.dict(os.environ, base):
            return CliRunner().invoke(self.cli.cli, ['retention', '--prefix', 'tb-index'] + args)

    def test_it_creates_the_policy_and_leaves_history_alone(self):
        result = self.run_cli([])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(R.POLICY_ID, self.os.policies)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), [])
        self.assertEqual(FakeClient.built[0]['hosts'], [{'host': 'opensearch', 'port': 9200}])

    def test_unset_does_nothing_and_succeeds(self):
        result = self.run_cli([], TURKEYBITE_RETENTION_DAYS='')
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.os.writes, [])
        self.assertIn('RETENTION IS NOT CONFIGURED', result.output)

    def test_the_prefix_comes_from_config_yaml(self):
        from click.testing import CliRunner
        config = mock.Mock(return_value={'processor': {'elastic': {'index_prefix': 'campus'}}})
        with mock.patch('opensearchpy.OpenSearch', FakeClient), \
                mock.patch.object(self.cli, 'read_config', config), \
                mock.patch.dict(os.environ, {'OPENSEARCH_PASSWORD': 'Not-the-default.1',
                                             'TURKEYBITE_RETENTION_DAYS': '90',
                                             'OPENSEARCH_CA_CERT': ''}):
            result = CliRunner().invoke(self.cli.cli, ['retention'])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.os.policies[R.POLICY_ID]['policy']['ism_template'][0]
                         ['index_patterns'], ['campus-2*'])

    def test_a_refused_shortening_exits_non_zero_and_confirming_applies_it(self):
        self.assertEqual(self.run_cli([], TURKEYBITE_RETENTION_DAYS='90').exit_code, 0)
        refused = self.run_cli([], TURKEYBITE_RETENTION_DAYS='9')
        self.assertEqual(refused.exit_code, 1, refused.output)
        self.assertIn('--apply --confirm-days 9', refused.output)
        applied = self.run_cli(['--apply', '--confirm-days', '9'], TURKEYBITE_RETENTION_DAYS='9')
        self.assertEqual(applied.exit_code, 0, applied.output)
        self.assertEqual(R.period_days(self.os.policies[R.POLICY_ID]['policy']), 9)

    def test_confirm_days_needs_apply(self):
        result = self.run_cli(['--confirm-days', '9'])
        self.assertEqual(result.exit_code, 2)
        self.assertEqual(self.os.writes, [])

    def test_attach_existing_is_the_opt_in(self):
        result = self.run_cli(['--attach-existing'])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.os.managed_by(R.POLICY_ID), ['tb-index-2025-01-01'])

    def test_attaching_or_applying_needs_a_period(self):
        for args, days in ((['--attach-existing'], ''), (['--apply'], ''),
                           (['--attach-existing'], '0')):
            result = self.run_cli(args, TURKEYBITE_RETENTION_DAYS=days)
            self.assertEqual(result.exit_code, 1, (args, days))
        self.assertEqual(FakeClient.built, [])

    def test_a_dry_run_changes_nothing(self):
        result = self.run_cli(['--attach-existing', '--dry-run'])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.os.writes, [])
        self.assertIn('tb-index-2025-01-01', result.output)

    def test_a_bad_period_stops_it_before_connecting(self):
        result = self.run_cli([], TURKEYBITE_RETENTION_DAYS='90d')
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn('whole number of days', result.output)
        self.assertEqual(FakeClient.built, [])

    def test_the_default_password_is_refused_before_connecting(self):
        result = self.run_cli([], OPENSEARCH_PASSWORD='Changeit12345!')
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn('Changing the OpenSearch admin password', result.output)
        self.assertEqual(FakeClient.built, [])

    def test_the_escape_hatch_opens_it(self):
        # The control for the refusal above
        result = self.run_cli([], OPENSEARCH_PASSWORD='Changeit12345!',
                              TURKEYBITE_ALLOW_DEFAULT_PASSWORD='yes')
        self.assertEqual(result.exit_code, 0, result.output)

    def test_no_password_is_refused(self):
        result = self.run_cli([], OPENSEARCH_PASSWORD='')
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn('OPENSEARCH_PASSWORD is not set', result.output)

    def test_the_ca_reaches_the_client(self):
        root = tempfile.mkdtemp(prefix='tb-retention-')
        self.addCleanup(shutil.rmtree, root, True)
        ca = os.path.join(root, 'root-ca.pem')
        with open(ca, 'w') as fh:
            fh.write('-----BEGIN CERTIFICATE-----\n')
        result = self.run_cli(['--url', 'https://node-0.example.com:9200'], OPENSEARCH_CA_CERT=ca)
        self.assertEqual(result.exit_code, 0, result.output)
        kwargs = FakeClient.built[0]
        self.assertIs(kwargs['verify_certs'], True)
        self.assertEqual(kwargs['ca_certs'], ca)
        self.assertEqual(kwargs['hosts'], [{'host': 'node-0.example.com', 'port': 9200}])
        self.assertNotIn('without verifying', result.output)

    def test_without_a_ca_it_says_so(self):
        result = self.run_cli([])
        self.assertIs(FakeClient.built[0]['verify_certs'], False)
        self.assertIn('without verifying', result.output)

    def test_an_opensearch_failure_is_reported_not_raised(self):
        def refuses(*args, **kwargs):
            raise ConflictError(409, 'version_conflict_engine_exception', {})
        FakeClient.cluster = refuses
        result = self.run_cli([])
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

    def test_the_suggestion_matches_the_librarians(self):
        self.assertEqual(self.setup.DEFAULT_RETENTION_DAYS, R.SUGGESTED_DAYS)

    def test_enter_takes_the_suggestion_and_zero_means_forever(self):
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
