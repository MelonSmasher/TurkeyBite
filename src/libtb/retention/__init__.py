"""How long TurkeyBite keeps what it indexes, enforced by OpenSearch itself.

Every daily index holds per-user browsing data, and nothing ever deleted one.
An Index State Management policy now does: an index older than
TURKEYBITE_RETENTION_DAYS, 90 by default, is deleted by OpenSearch's own ISM
job, which checks every few minutes, so retention holds whether or not any
TurkeyBite container is running. The age is counted from when OpenSearch
created the index, which for a daily index is its day.

The policy carries an ism_template, so OpenSearch attaches it to each new
index as it is created. OpenSearch applies a template only to indices created
after it, and that is the right answer here too: the indices a deployment
already holds are deliberately not attached on upgrade. Attaching them would
delete every one older than the period within minutes, irreversibly, and an
upgrade is not the moment to make that decision on someone's behalf.
`turkeybite retention --attach-existing` makes it explicitly, and the
librarian says at every start how many indices the policy does not cover.

0 keeps everything forever. Nothing is created, an existing policy is taken
off the indices it manages and deleted, since leaving it would go on deleting
what the operator has just asked to keep, and the log says so loudly.

The librarian owns the policy. Changing the period updates it in place,
guarded by its sequence number so a concurrent edit is refused rather than
overwritten, and moves the indices it already manages onto the new version:
ISM pins each managed index to the version of the policy it started with, so
without that a longer period would not save the indices already counting down
under the shorter one. A policy of an operator's own belongs under another
name.
"""

import re
import time

from opensearchpy.exceptions import NotFoundError

POLICY_ID = 'turkeybite-retention'
DAYS_ENV = 'TURKEYBITE_RETENTION_DAYS'
DEFAULT_DAYS = 90

# Above a template another policy might carry for the same indices, which
# OpenSearch's default of 0 would tie with
TEMPLATE_PRIORITY = 100

# Index names per request. The names go in the URL, and a deployment that has
# kept years of daily indices has thousands of them.
BATCH = 50

ATTACH_COMMAND = ('docker compose exec turkeybite-librarian '
                  'python turkeybite retention --attach-existing')

# What the plan for the policy can be
CREATE, UPDATE, CURRENT, REMOVE, OFF = 'create', 'update', 'current', 'remove', 'off'


def retention_days(value):
    """TURKEYBITE_RETENTION_DAYS as a whole number of days, checked.

    Unset or empty means DEFAULT_DAYS. 0 means keep forever. Raises ValueError
    for anything else that is not a whole number, such as 90d, 1.5 or -1,
    rather than guessing what deleting data on a misread setting should mean.
    """
    if value is None or not str(value).strip():
        return DEFAULT_DAYS
    text = str(value).strip()
    if not re.fullmatch(r'[0-9]+', text):
        raise ValueError(f'{DAYS_ENV} must be a whole number of days, or 0 to keep '
                         f'TurkeyBite indices forever, not {value!r}')
    return int(text)


def index_pattern(prefix):
    """The pattern TurkeyBite's daily indices match, from processor.elastic.index_prefix.

    Raises ValueError for a prefix that would make the pattern reach further
    than TurkeyBite's own indices: an empty one would match every index whose
    name starts with a hyphen, and a wildcard or a comma could match anything.
    """
    if not isinstance(prefix, str) or not prefix.strip():
        raise ValueError(f'the index prefix must be a name, not {prefix!r}')
    if re.search(r'[*?,\s]', prefix):
        raise ValueError(f'the index prefix {prefix!r} cannot contain a wildcard, a comma '
                         f'or whitespace')
    return f'{prefix}-*'


def is_daily(name, prefix):
    """True for an index named as a worker names them: <prefix>-YYYY-MM-DD.

    Only these are counted as unmanaged or attached by --attach-existing, so an
    unrelated index that happens to share the prefix is never deleted by an
    operator's one-off decision about TurkeyBite's history.
    """
    return re.fullmatch(re.escape(prefix) + r'-\d{4}-\d{2}-\d{2}', name) is not None


def policy(days, prefix):
    """The ISM policy body for `days`, as PUT to _plugins/_ism/policies."""
    if days < 1:
        raise ValueError('a retention policy needs at least 1 day; 0 means no policy')
    return {'policy': {
        'description': f'TurkeyBite: delete {index_pattern(prefix)} indices '
                       f'{days} days after they are created. Managed by the librarian '
                       f'from {DAYS_ENV}; edits here are overwritten.',
        'default_state': 'hot',
        'states': [
            {'name': 'hot', 'actions': [],
             'transitions': [{'state_name': 'delete',
                              'conditions': {'min_index_age': f'{days}d'}}]},
            {'name': 'delete', 'actions': [{'delete': {}}], 'transitions': []},
        ],
        'ism_template': [{'index_patterns': [index_pattern(prefix)],
                          'priority': TEMPLATE_PRIORITY}],
    }}


def summarise(body):
    """The parts of a policy that decide what it deletes and when.

    OpenSearch hands a policy back with fields of its own added, such as retry
    settings on each action and timestamps on the template, so a stored policy
    never equals the body that was sent. This keeps only what TurkeyBite sets,
    in a form that compares equal when the two say the same thing.
    """
    body = body or {}
    states = [s for s in body.get('states') or [] if isinstance(s, dict)]
    transitions = sorted(
        (str(state.get('name')), str(t.get('state_name')),
         str((t.get('conditions') or {}).get('min_index_age')))
        for state in states for t in state.get('transitions') or [] if isinstance(t, dict))
    deleting = sorted(str(state.get('name')) for state in states
                      if any(isinstance(a, dict) and 'delete' in a
                             for a in state.get('actions') or []))
    other_actions = sorted(str(state.get('name')) for state in states
                           for a in state.get('actions') or []
                           if not (isinstance(a, dict) and 'delete' in a))
    templates = sorted((tuple(t.get('index_patterns') or ()), t.get('priority'))
                       for t in body.get('ism_template') or [] if isinstance(t, dict))
    return (body.get('description'), body.get('default_state'), tuple(transitions),
            tuple(deleting), tuple(other_actions), tuple(templates))


def plan(days, existing, prefix):
    """What to do to the policy: CREATE, UPDATE, CURRENT, REMOVE or OFF.

    `existing` is the stored policy as GET returns it, or None.
    """
    if days == 0:
        return REMOVE if existing else OFF
    if existing is None:
        return CREATE
    if summarise(existing.get('policy')) == summarise(policy(days, prefix)['policy']):
        return CURRENT
    return UPDATE


def _batches(names):
    for i in range(0, len(names), BATCH):
        yield names[i:i + BATCH]


class Cluster(object):
    """The ISM calls retention needs, over any function shaped like
    opensearchpy's Transport.perform_request.

    Kept this thin so the decisions above can be tested against a fake. With
    dry_run, nothing is written: each write is logged as what would be done.
    """

    def __init__(self, request, dry_run=False, log=print):
        self.request = request
        self.dry_run = dry_run
        self.log = log

    # -- reading ----------------------------------------------------------

    def get_policy(self):
        """The stored policy as GET returns it, or None when there is none."""
        try:
            return self.request('GET', f'/_plugins/_ism/policies/{POLICY_ID}')
        except NotFoundError:
            # Also what OpenSearch answers before any ISM policy exists at all,
            # when the index holding them has not been created yet
            return None

    def indices(self, prefix):
        """{name: creation time in epoch milliseconds} for every index the pattern matches."""
        found = self.request('GET', f'/_cat/indices/{index_pattern(prefix)}',
                             params={'format': 'json', 'h': 'index,creation.date'})
        return {row['index']: int(row.get('creation.date') or 0) for row in found or []}

    def policies(self, names):
        """{name: the ISM policy managing it, or None} for these indices."""
        managing = {}
        for batch in _batches(sorted(names)):
            explained = self.request('GET', '/_plugins/_ism/explain/' + ','.join(batch))
            for name in batch:
                entry = (explained or {}).get(name) or {}
                managing[name] = (entry.get('index.plugins.index_state_management.policy_id')
                                  or entry.get('policy_id'))
        return managing

    # -- writing ----------------------------------------------------------

    def put_policy(self, body, seq_no=None, primary_term=None):
        params = None
        if seq_no is not None:
            # Without these OpenSearch refuses to overwrite a policy, and with
            # them it refuses when someone else changed it since it was read
            params = {'if_seq_no': seq_no, 'if_primary_term': primary_term}
        if self.dry_run:
            self.log(f'Dry run: would {"update" if params else "create"} the ISM policy '
                     f'{POLICY_ID}')
            return None
        return self.request('PUT', f'/_plugins/_ism/policies/{POLICY_ID}',
                            params=params, body=body)

    def delete_policy(self):
        if self.dry_run:
            self.log(f'Dry run: would delete the ISM policy {POLICY_ID}')
            return None
        return self.request('DELETE', f'/_plugins/_ism/policies/{POLICY_ID}')

    def _each(self, verb, names, body=None):
        """POSTs an ISM index action in batches. Returns (changed, failures)."""
        changed, failures = 0, []
        for batch in _batches(sorted(names)):
            if self.dry_run:
                changed += len(batch)
                continue
            answer = self.request('POST', f'/_plugins/_ism/{verb}/' + ','.join(batch),
                                  body=body) or {}
            changed += int(answer.get('updated_indices') or 0)
            failures += [f'{f.get("index_name")}: {f.get("reason")}'
                         for f in answer.get('failed_indices') or []]
        return changed, failures

    def attach(self, names):
        return self._each('add', names, {'policy_id': POLICY_ID})

    def move_to_latest(self, names):
        return self._each('change_policy', names, {'policy_id': POLICY_ID})

    def detach(self, names):
        return self._each('remove', names)


def _age_days(created_ms, now):
    return (now - created_ms / 1000.0) / 86400.0


def _report_failures(failures, log):
    for failure in failures:
        log(f'Retention: {failure}')


def apply_policy(cluster, days, prefix, log=print):
    """Makes the stored policy say `days`. Returns {'action', 'moved', 'detached'}.

    Never attaches the policy to an index it does not already manage; see the
    module docstring.
    """
    existing = cluster.get_policy()
    action = plan(days, existing, prefix)
    result = {'action': action, 'moved': 0, 'detached': 0}
    would = 'Dry run: would have ' if cluster.dry_run else ''
    pattern = index_pattern(prefix)

    if action in (OFF, REMOVE):
        log('!' * 78)
        log(f'RETENTION IS OFF: {DAYS_ENV}=0, so TurkeyBite indices are kept forever. '
            f'Every one holds per-user browsing data. Set {DAYS_ENV} to a number of '
            f'days to have OpenSearch delete indices older than that.')
        log('!' * 78)

    ours = []
    if action in (UPDATE, REMOVE):
        # Only indices this policy manages: change_policy and remove act on
        # whatever policy an index has, and another policy is not ours to touch
        ours = [name for name, managing in cluster.policies(cluster.indices(prefix)).items()
                if managing == POLICY_ID]

    if action == CREATE:
        cluster.put_policy(policy(days, prefix))
        log(f'Retention: {would or ""}created the ISM policy {POLICY_ID}: new {pattern} '
            f'indices are deleted {days} days after they are created.')
    elif action == UPDATE:
        cluster.put_policy(policy(days, prefix), existing.get('_seq_no'),
                           existing.get('_primary_term'))
        result['moved'], failures = cluster.move_to_latest(ours)
        _report_failures(failures, log)
        log(f'Retention: {would or ""}updated the ISM policy {POLICY_ID} to delete {pattern} '
            f'indices {days} days after they are created, and moved the '
            f'{result["moved"]} indices it manages onto it. ISM applies the change at its '
            f'next check of each index.')
    elif action == CURRENT:
        log(f'Retention: the ISM policy {POLICY_ID} deletes {pattern} indices {days} days '
            f'after they are created.')
    elif action == REMOVE:
        result['detached'], failures = cluster.detach(ours)
        _report_failures(failures, log)
        cluster.delete_policy()
        log(f'Retention: {would or ""}{"taken" if would else "took"} the ISM policy '
            f'{POLICY_ID} off the {result["detached"]} indices it managed and deleted it. '
            f'Nothing deletes them now.')
    return result


def survey(cluster, days, prefix, now=None):
    """Which daily indices the policy does not cover.

    Returns {'created': {name: epoch ms}, 'unmanaged': [...], 'overdue': [...],
    'other_policy': [...]}, where overdue are the unmanaged indices already
    older than `days`, which attaching the policy would delete at once.
    """
    now = time.time() if now is None else now
    created = {name: when for name, when in cluster.indices(prefix).items()
               if is_daily(name, prefix)}
    managing = cluster.policies(created) if created else {}
    found = {'created': created, 'unmanaged': [], 'overdue': [], 'other_policy': []}
    for name in sorted(created):
        if managing.get(name) is None:
            found['unmanaged'].append(name)
            if _age_days(created[name], now) >= days:
                found['overdue'].append(name)
        elif managing[name] != POLICY_ID:
            found['other_policy'].append(name)
    return found


def ensure(cluster, days, prefix, log=print, now=None):
    """What the librarian runs at every start: the policy, then what it does not cover.

    Returns the dicts apply_policy and survey return, merged.
    """
    result = apply_policy(cluster, days, prefix, log)
    if days == 0:
        return result
    result.update(survey(cluster, days, prefix, now))
    if result['other_policy']:
        log(f'Retention: {len(result["other_policy"])} TurkeyBite indices are managed by '
            f'another ISM policy, which is left alone.')
    if result['unmanaged']:
        log(f'Retention: {len(result["unmanaged"])} existing TurkeyBite indices are not '
            f'under the retention policy, so they are kept until you decide otherwise. '
            f'{len(result["overdue"])} of them are already older than {days} days and '
            f'would be deleted within minutes of attaching it. To attach it: '
            f'{ATTACH_COMMAND} (run it with --dry-run first to list them).')
    return result


def attach_existing(cluster, days, prefix, log=print, now=None):
    """Brings the indices a deployment already holds under the policy.

    The explicit decision ensure() never makes. Only daily indices that no ISM
    policy manages are attached; one under another policy is left alone.
    Raises ValueError when retention is off, since there is no policy to
    attach. Returns what ensure() returns, with `attached`.
    """
    if days == 0:
        raise ValueError(f'{DAYS_ENV} is 0, so there is no retention policy to attach')
    now = time.time() if now is None else now
    result = apply_policy(cluster, days, prefix, log)
    result.update(survey(cluster, days, prefix, now))
    if result['other_policy']:
        log(f'Retention: leaving {len(result["other_policy"])} TurkeyBite indices alone, '
            f'since another ISM policy manages them.')
    unmanaged = result['unmanaged']
    overdue = set(result['overdue'])
    if not unmanaged:
        log('Retention: every existing TurkeyBite index is already under a policy.')
        result['attached'] = 0
        return result

    if cluster.dry_run:
        for name in unmanaged:
            age = int(_age_days(result['created'][name], now))
            note = ", deleted at ISM's next check" if name in overdue else ''
            log(f'  {name}  created {age} days ago{note}')
    result['attached'], failures = cluster.attach(unmanaged)
    _report_failures(failures, log)
    verb = 'Dry run: would attach' if cluster.dry_run else 'Attached'
    log(f'Retention: {verb} the policy to {result["attached"]} existing TurkeyBite '
        f'indices. {len(overdue)} of them are older than {days} days, and ISM deletes '
        f'those at its next check, within minutes.')
    return result
