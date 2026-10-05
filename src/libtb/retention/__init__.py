"""How long TurkeyBite keeps what it indexes, enforced by OpenSearch itself.

Every daily index holds per-user browsing data, and nothing ever deleted one.
An Index State Management policy, turkeybite-retention, now does: once an
index is older than TURKEYBITE_RETENTION_DAYS, OpenSearch's own ISM job, which
checks every few minutes, deletes it, whether or not any TurkeyBite container
is running. The age is counted from when OpenSearch created the index, which
for a daily index is its day.

Deleting an index cannot be undone, so the librarian, which applies the policy
at every start, never does anything that deletes sooner than the current state
would without an explicit act by the operator:

    unset    TURKEYBITE_RETENTION_DAYS absent means nothing is created,
             changed or removed, and the log says so loudly. An upgraded
             deployment's generated docker-compose.yml does not pass the
             variable, so a default here would silently override whatever
             the operator put in .env.
    longer   a longer period, or the first policy, is applied at start
    shorter  a shorter period is refused at start: the policy is left as it
             is, and the log says how many indices the shorter one would
             delete and the command that confirms it,
             `turkeybite retention --apply --confirm-days N`
    0        keeps indices forever: every index the policy manages, under
             any prefix, is taken off it, and the policy is deleted only once
             none is left under it, so nothing is left that can still delete
             them. Deleting the policy alone would not do: ISM gives each
             index it manages a copy of the policy, and goes on running that
             copy after the policy itself is gone, as a real cluster showed.

The policy carries an ism_template for <prefix>-2*, the daily indices, whose
names start with the year, so OpenSearch attaches it to each new one as it is
created. OpenSearch applies a template only to indices created after it, and
the librarian never attaches the policy to indices that already exist. Doing
so would delete every one older than the period within minutes, and an
upgrade is not the moment to make that decision on anyone's behalf.
`turkeybite retention --attach-existing` makes it explicitly, for daily
indices no other policy manages, and the librarian says at every start how
many indices the policy does not cover.

An operator's own policy always wins. If another policy's ism_template
overlaps ours, ours is kept without a template, so it attaches to nothing new,
and the conflict is reported for the operator to settle; no priority is set
that could outrank theirs.

ISM pins each managed index to the policy version it started with, so a new
period applies to an existing index only once the index is moved onto the new
version. Every start compares each managed index's version, as ISM explain
reports it, with the policy's own, and moves any that lag. A move that fails
is retried at the next start, and the command exits non-zero until none do.

Each start lists the policies, the managed indices and the indices once, and
works from that one snapshot.
"""

import math
import re
import time

from opensearchpy.exceptions import NotFoundError, TransportError

POLICY_ID = 'turkeybite-retention'
DAYS_ENV = 'TURKEYBITE_RETENTION_DAYS'

# What setup.py offers a new install. Not a default here: unset means nothing
# is done, see the module docstring.
SUGGESTED_DAYS = 90

# Index names per request. The names go in the URL, and a deployment that has
# kept years of daily indices has thousands of them.
BATCH = 50

# Entries per page when listing policies and managed indices. Both APIs return
# 20 unless asked, and a page beyond the first is asked for with `from`.
PAGE = 1000

# ISM lists an index it has just attached only once its own config index has
# refreshed, about a second later, so turning retention off looks again after
# this long before it deletes the policy, and gives up after this many looks
SETTLE_SECONDS = 2
SETTLE_ROUNDS = 5

COMMAND = 'docker compose exec turkeybite-librarian python turkeybite retention'
ATTACH_COMMAND = COMMAND + ' --attach-existing'
CONFIRM_COMMAND = COMMAND + ' --apply --confirm-days {days}'

# What can happen to the policy
UNCONFIGURED, CREATE, UPDATE, CURRENT, REFUSED, REMOVE, OFF = (
    'unconfigured', 'create', 'update', 'current', 'refused', 'remove', 'off')

# What a dry run's write stands in for: a version no managed index is on yet
NEW_VERSION = ('a new version', None)

_AGE_UNITS = {'d': 1.0, 'h': 1 / 24, 'm': 1 / 1440, 's': 1 / 86400, 'ms': 1 / 86400000}


def retention_days(value):
    """TURKEYBITE_RETENTION_DAYS as a whole number of days, or None when unset.

    Unset or empty means not configured, and nothing is done. 0 means keep
    forever. Raises ValueError for anything else that is not a whole number,
    such as 90d, 1.5 or -1, rather than guessing what deleting data on a
    misread setting should mean.
    """
    if value is None or not str(value).strip():
        return None
    text = str(value).strip()
    if not re.fullmatch(r'[0-9]+', text):
        raise ValueError(f'{DAYS_ENV} must be a whole number of days, or 0 to keep '
                         f'TurkeyBite indices forever, not {value!r}')
    return int(text)


def index_pattern(prefix):
    """The pattern TurkeyBite's daily indices match, from processor.elastic.index_prefix.

    <prefix>-2*, since a daily index is <prefix>-YYYY-MM-DD, so an index such
    as tb-index-incident-4711 or tb-index-archive-2025 is never attached.
    Raises ValueError for a prefix that would make the pattern reach further:
    an empty one, or one with a wildcard, a comma or whitespace.
    """
    if not isinstance(prefix, str) or not prefix.strip():
        raise ValueError(f'the index prefix must be a name, not {prefix!r}')
    if re.search(r'[*?,\s]', prefix):
        raise ValueError(f'the index prefix {prefix!r} cannot contain a wildcard, a comma '
                         f'or whitespace')
    return f'{prefix}-2*'


def is_daily(name, prefix):
    """True for an index named as a worker names them: <prefix>-YYYY-MM-DD."""
    return re.fullmatch(re.escape(prefix) + r'-\d{4}-\d{2}-\d{2}', name) is not None


def policy(days, prefix, template=True):
    """The ISM policy body for `days`, as PUT to _plugins/_ism/policies.

    Without `template` the policy attaches to nothing new by itself, which is
    how it is kept when another policy's template overlaps.
    """
    if days < 1:
        raise ValueError('a retention policy needs at least 1 day; 0 means no policy')
    body = {
        'description': f'TurkeyBite: delete {index_pattern(prefix)} indices {days} days '
                       f'after they are created. Managed by the librarian from '
                       f'{DAYS_ENV}; edits here are overwritten.',
        'default_state': 'hot',
        'states': [
            {'name': 'hot', 'actions': [],
             'transitions': [{'state_name': 'delete',
                              'conditions': {'min_index_age': f'{days}d'}}]},
            {'name': 'delete', 'actions': [{'delete': {}}], 'transitions': []},
        ],
    }
    if template:
        # No priority: OpenSearch's default of 0, so an operator's own template
        # with any priority set is never outranked
        body['ism_template'] = [{'index_patterns': [index_pattern(prefix)]}]
    return {'policy': body}


def summarise(body):
    """The parts of a policy that decide what it deletes and when.

    OpenSearch hands a policy back with fields of its own added, such as retry
    settings on each action, timestamps, and a template priority of 0 when none
    was given, so a stored policy never equals the body sent. This keeps only
    what TurkeyBite sets, in a form that compares equal when the two say the
    same thing.
    """
    body = body or {}
    states = [s for s in body.get('states') or [] if isinstance(s, dict)]
    transitions = sorted(
        (str(state.get('name')), str(t.get('state_name')),
         str((t.get('conditions') or {}).get('min_index_age')))
        for state in states for t in state.get('transitions') or [] if isinstance(t, dict))
    actions = sorted((str(state.get('name')), sorted(k for k in a if k != 'retry'))
                     for state in states for a in state.get('actions') or []
                     if isinstance(a, dict))
    templates = sorted((tuple(t.get('index_patterns') or ()), t.get('priority') or 0)
                       for t in body.get('ism_template') or [] if isinstance(t, dict))
    return (body.get('description'), body.get('default_state'), tuple(transitions),
            str(actions), tuple(templates))


def _age_in_days(text):
    match = re.fullmatch(r'\s*([0-9]+(?:\.[0-9]+)?)\s*(ms|d|h|m|s)\s*', str(text or ''))
    if not match:
        return None
    return float(match.group(1)) * _AGE_UNITS[match.group(2)]


def period_days(body):
    """How old an index gets before this policy deletes it, in days.

    math.inf when the policy, perhaps edited by hand, deletes nothing or says
    so in a way this cannot read, so any period that does delete counts as
    shorter and needs confirming.
    """
    states = {s.get('name'): s for s in (body or {}).get('states') or [] if isinstance(s, dict)}
    deleting = {name for name, s in states.items()
                if any(isinstance(a, dict) and 'delete' in a for a in s.get('actions') or [])}
    ages = []
    for state in states.values():
        for transition in state.get('transitions') or []:
            if isinstance(transition, dict) and transition.get('state_name') in deleting:
                age = _age_in_days((transition.get('conditions') or {}).get('min_index_age'))
                if age is None:
                    return math.inf if not ages else min(ages)
                ages.append(age)
    return min(ages) if ages else math.inf


def patterns_overlap(a, b):
    """True when some index name matches both of two ISM index patterns.

    Patterns use * as their only wildcard. Two patterns overlap when their
    remainders can be made to match one string: a * may match nothing, or
    absorb a character of the other pattern.
    """
    seen = {}

    def match(i, j):
        if (i, j) in seen:
            return seen[(i, j)]
        seen[(i, j)] = False
        if i == len(a) and j == len(b):
            result = True
        elif i < len(a) and a[i] == '*':
            result = match(i + 1, j) or (j < len(b) and match(i, j + 1))
        elif j < len(b) and b[j] == '*':
            result = match(i, j + 1) or (i < len(a) and match(i + 1, j))
        else:
            result = i < len(a) and j < len(b) and a[i] == b[j] and match(i + 1, j + 1)
        seen[(i, j)] = result
        return result

    return match(0, 0)


def managing(entry):
    """The id of the policy an explain entry says manages its index, or None."""
    if not isinstance(entry, dict):
        return None
    return entry.get('index.plugins.index_state_management.policy_id') or entry.get('policy_id')


def _batches(names):
    names = sorted(names)
    for i in range(0, len(names), BATCH):
        yield names[i:i + BATCH]


def _reason(error):
    info = getattr(error, 'info', None)
    if isinstance(info, dict):
        reason = (info.get('error') or {}).get('reason') if isinstance(info.get('error'), dict) \
            else info.get('error')
        if reason:
            return str(reason)
    return str(error)


class Cluster(object):
    """The ISM calls retention needs, over any function shaped like
    opensearchpy's Transport.perform_request.

    Kept this thin so the decisions below can be tested against a fake. With
    dry_run, nothing is written: each write is logged as what would be done.
    """

    def __init__(self, request, dry_run=False, log=print, wait=time.sleep):
        self.request = request
        self.dry_run = dry_run
        self.log = log
        self.wait = wait

    # -- reading ----------------------------------------------------------

    def get_policy(self):
        """The stored policy as GET returns it, or None when there is none."""
        try:
            return self.request('GET', f'/_plugins/_ism/policies/{POLICY_ID}')
        except NotFoundError:
            # Also what OpenSearch answers before any ISM policy exists at all,
            # when the index holding them has not been created yet
            return None

    def _pages(self, path, items, total):
        found, start = {}, 0
        while True:
            answer = self.request('GET', path, params={'from': start, 'size': PAGE}) or {}
            page = items(answer)
            found.update(page)
            start += PAGE
            if not page or len(found) >= int(answer.get(total) or 0):
                return found

    def policies(self):
        """{id: policy as listed, with _seq_no and _primary_term} for every ISM policy."""
        return self._pages('/_plugins/_ism/policies',
                           lambda answer: {p['_id']: p for p in answer.get('policies') or []},
                           'total_policies')

    def managed(self):
        """{index: explain entry} for every index any ISM policy manages, under any name."""
        return self._pages('/_plugins/_ism/explain',
                           lambda answer: {k: v for k, v in answer.items()
                                           if isinstance(v, dict)},
                           'total_managed_indices')

    def indices(self):
        """{name: creation time in epoch milliseconds} for every index."""
        found = self.request('GET', '/_cat/indices',
                             params={'format': 'json', 'h': 'index,creation.date'})
        return {row['index']: int(row.get('creation.date') or 0) for row in found or []}

    # -- writing ----------------------------------------------------------

    def put_policy(self, body, seq_no=None, primary_term=None):
        """Writes the policy. Returns (seq_no, primary_term) of what was written.

        A dry run returns NEW_VERSION, standing for the version a write would
        have made, which no managed index is on yet.
        """
        params = None
        if seq_no is not None:
            # Without these OpenSearch refuses to overwrite a policy, and with
            # them it refuses when someone else changed it since it was read
            params = {'if_seq_no': seq_no, 'if_primary_term': primary_term}
        if self.dry_run:
            return NEW_VERSION
        answer = self.request('PUT', f'/_plugins/_ism/policies/{POLICY_ID}',
                              params=params, body=body) or {}
        return answer.get('_seq_no'), answer.get('_primary_term')

    def delete_policy(self):
        if not self.dry_run:
            self.request('DELETE', f'/_plugins/_ism/policies/{POLICY_ID}')

    def _each(self, verb, names, body=None):
        """POSTs an ISM index action in batches. Returns (changed, failures).

        A batch OpenSearch refuses as a whole, as it does when one index in it
        has been deleted meanwhile, counts every index in it as failed, so the
        caller retries rather than assuming they changed.
        """
        changed, failures = 0, []
        for batch in _batches(names):
            if self.dry_run:
                changed += len(batch)
                continue
            try:
                answer = self.request('POST', f'/_plugins/_ism/{verb}/' + ','.join(batch),
                                      body=body) or {}
            except TransportError as e:
                failures += [f'{name}: {_reason(e)}' for name in batch]
                continue
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


def _days(value):
    if value == math.inf:
        return 'no limit'
    return f'{value:g} days'


def _banner(log, *lines):
    log('!' * 78)
    for line in lines:
        log(line)
    log('!' * 78)


def unconfigured(cluster, log=print):
    """What the librarian does when TURKEYBITE_RETENTION_DAYS is unset: nothing.

    Reads the policy and the indices under it only to say truthfully what is
    in force, including indices left holding ISM's copy of a policy that has
    since been deleted, which ISM goes on running.
    """
    existing = cluster.get_policy()
    under = sorted(name for name, entry in cluster.managed().items()
                   if managing(entry) == POLICY_ID)
    if existing:
        state = (f'The existing policy {POLICY_ID} is left as it is: it deletes indices '
                 f'after {_days(period_days(existing.get("policy")))}, and manages '
                 f'{len(under)} indices.')
    elif under:
        state = (f'No policy {POLICY_ID} exists, but {len(under)} indices still hold the '
                 f'copy of it ISM gave them, and ISM can still delete them; set {DAYS_ENV}=0 '
                 f'to take them off it.')
    else:
        state = 'No retention policy exists, so nothing deletes TurkeyBite indices.'
    _banner(log,
            f'RETENTION IS NOT CONFIGURED: {DAYS_ENV} is not set, so the librarian '
            f'creates, changes and removes nothing. {state}',
            f'Every index holds per-user browsing data. Set {DAYS_ENV} in .env, pass it '
            f'to the turkeybite-librarian service in docker-compose.yml, and recreate the '
            f'librarian; 0 keeps indices forever. See "Data retention" in the README.')
    return {'action': UNCONFIGURED, 'ok': True, 'managed': under}


def reconcile(cluster, days, prefix, log=print, now=None, confirm_days=None,
              attach_existing=False):
    """Brings the policy and the indices it manages in line with `days`.

    What the librarian runs at every start, and what the command runs when an
    operator confirms a shorter period with `confirm_days` or attaches the
    indices that existed before the policy with `attach_existing`. Returns a
    dict saying what was done and found, with `ok` False when something was
    refused or failed and the command should exit non-zero.
    """
    if days is None:
        return unconfigured(cluster, log)
    now = time.time() if now is None else now
    pattern = index_pattern(prefix)
    would = 'Dry run: would have ' if cluster.dry_run else ''

    # One snapshot of the cluster for the whole start
    policies = cluster.policies()
    managed = cluster.managed()
    created = cluster.indices()
    ours = policies.get(POLICY_ID)
    ours_managed = sorted(name for name, entry in managed.items()
                          if managing(entry) == POLICY_ID)

    def age(name):
        when = (managed.get(name) or {}).get('index_creation_date') or created.get(name)
        return None if not when else (now - int(when) / 1000.0) / 86400.0

    result = {'action': None, 'ok': True, 'moved': 0, 'detached': 0, 'attached': 0,
              'would_delete': [], 'unmanaged': [], 'overdue': [], 'other_policy': [],
              'conflicts': [], 'failures': []}

    if days == 0:
        return _turn_off(cluster, ours, ours_managed, log, result)

    # Another policy's template overlapping ours wins, see the module docstring
    for policy_id, listed in sorted(policies.items()):
        if policy_id == POLICY_ID:
            continue
        for template in (listed.get('policy') or {}).get('ism_template') or []:
            if any(patterns_overlap(p, pattern) for p in template.get('index_patterns') or []):
                result['conflicts'].append(policy_id)
                break
    if result['conflicts']:
        result['ok'] = False
        _banner(log,
                f'RETENTION CONFLICT: the ISM policy {", ".join(result["conflicts"])} has a '
                f'template matching {pattern}, which {POLICY_ID} would use. Yours is left '
                f'to decide which new indices it manages, so {POLICY_ID} is kept without '
                f'a template and new TurkeyBite indices are not attached to it.',
                f'Change that policy\'s index_patterns, or set {DAYS_ENV}=0 if it is meant '
                f'to manage TurkeyBite\'s indices instead.')

    desired = policy(days, prefix, template=not result['conflicts'])
    current_days = period_days((ours or {}).get('policy')) if ours else None
    if ours is None:
        action = CREATE
    elif summarise(ours.get('policy')) == summarise(desired['policy']):
        action = CURRENT
    else:
        action = UPDATE
    # What this period deletes that the policy in force does not
    limit = current_days if current_days is not None else math.inf
    result['would_delete'] = [name for name in ours_managed
                              if age(name) is not None and days <= age(name) < limit]
    shorter = (action == UPDATE and days < limit) or (action == CREATE and result['would_delete'])

    version = (ours.get('_seq_no'), ours.get('_primary_term')) if ours else None
    if shorter and confirm_days != days:
        action = REFUSED
        result['ok'] = False
        if confirm_days is not None:
            log(f'Retention: --confirm-days {confirm_days} does not match {DAYS_ENV}='
                f'{days}, so nothing is changed.')
        _banner(log,
                f'RETENTION NOT SHORTENED: {DAYS_ENV} is {days}, shorter than the '
                f'{_days(limit)} the policy {POLICY_ID} applies now. That would delete '
                f'{len(result["would_delete"])} more of the {len(ours_managed)} indices it '
                f'manages at ISM\'s next check, and deleting cannot be undone, so the policy '
                f'is left as it is.',
                f'If {days} days is meant, confirm it with: '
                f'{CONFIRM_COMMAND.format(days=days)}',
                f'Add --dry-run to list the indices it would delete first.')
        if cluster.dry_run:
            for name in result['would_delete']:
                log(f'  {name}  created {int(age(name))} days ago')
    elif action == CREATE:
        version = cluster.put_policy(desired)
        log(f'Retention: {would}created the ISM policy {POLICY_ID}: new {pattern} indices '
            f'are deleted {days} days after they are created.')
    elif action == UPDATE:
        version = cluster.put_policy(desired, ours.get('_seq_no'), ours.get('_primary_term'))
        log(f'Retention: {would}updated the ISM policy {POLICY_ID} from '
            f'{_days(limit)} to {days} days.')
        if shorter and result['would_delete']:
            log(f'Retention: as confirmed, ISM deletes {len(result["would_delete"])} '
                f'indices older than {days} days at its next check.')
            if cluster.dry_run:
                for name in result['would_delete']:
                    log(f'  {name}  created {int(age(name))} days ago')
    else:
        log(f'Retention: the ISM policy {POLICY_ID} deletes {pattern} indices {days} days '
            f'after they are created.')
    result['action'] = action

    _converge(cluster, managed, ours_managed, version, log, result)
    _survey(cluster, managed, created, days, prefix, age, log, result,
            attach_existing and action != REFUSED)
    if attach_existing and action == REFUSED:
        log('Retention: nothing attached, since the policy is not yet at the configured '
            'period.')
    return result


def _without_template(stored):
    """A stored policy as a body to PUT back, without its template or OpenSearch's own fields."""
    body = {k: v for k, v in (stored or {}).items()
            if k not in ('policy_id', 'last_updated_time', 'schema_version', 'ism_template')}
    return {'policy': body}


def _turn_off(cluster, ours, ours_managed, log, result):
    """0: takes the policy off every index it manages, then deletes it.

    Its template goes first, so no new index is attached meanwhile. The policy
    is deleted only once a fresh look finds no index left under it: an index
    attached in the second before this ran is not listed yet, and would go on
    running ISM's copy of the policy after the policy itself was deleted. With
    any failure the policy is kept, and the log says it can still delete.
    """
    result['action'] = REMOVE if (ours or ours_managed) else OFF
    lines = [f'RETENTION IS OFF: {DAYS_ENV}=0, so TurkeyBite indices are meant to be kept '
             f'forever. Every one holds per-user browsing data. Set {DAYS_ENV} to a number '
             f'of days to have OpenSearch delete indices older than that.']
    if ours and (ours.get('policy') or {}).get('ism_template'):
        cluster.put_policy(_without_template(ours['policy']), ours.get('_seq_no'),
                           ours.get('_primary_term'))
    pending = list(ours_managed)
    remaining = []
    for _ in range(SETTLE_ROUNDS):
        if pending:
            detached, failures = cluster.detach(pending)
            result['detached'] += detached
            if failures:
                result['failures'] += failures
                break
        if cluster.dry_run or not (ours or ours_managed):
            break
        cluster.wait(SETTLE_SECONDS)
        pending = sorted(name for name, entry in cluster.managed().items()
                         if managing(entry) == POLICY_ID)
        if not pending:
            break
    else:
        remaining = pending

    if result['failures'] or remaining:
        result['ok'] = False
        for failure in result['failures']:
            log(f'Retention: could not take the policy off {failure}')
        for name in remaining:
            log(f'Retention: {name} is still under the policy')
        lines.append(f'The ISM policy {POLICY_ID} still manages '
                     f'{len(result["failures"]) + len(remaining)} indices, and can still '
                     f'delete them, so it has been kept. This is retried at the next start.')
    elif ours:
        cluster.delete_policy()
        lines.append(f'{"Dry run: would have taken" if cluster.dry_run else "Took"} the ISM '
                     f'policy {POLICY_ID} off the {result["detached"]} indices it managed '
                     f'and deleted it.')
    elif ours_managed:
        lines.append(f'Took {result["detached"]} indices off the copy of {POLICY_ID} ISM '
                     f'kept for them after the policy was deleted.')
    else:
        lines.append(f'There is no ISM policy {POLICY_ID}, and no index is under it.')
    _banner(log, *lines)
    return result


def _converge(cluster, managed, ours_managed, version, log, result):
    """Moves managed indices that lag behind the policy's version onto it.

    An index ISM has not initialised yet reports no version, and starts on
    whatever version is current when it does, so it is left alone.
    """
    if not version or version[0] is None:
        return
    lagging = []
    for name in ours_managed:
        entry = managed.get(name) or {}
        if entry.get('policy_seq_no') is None:
            continue
        if (entry.get('policy_seq_no'), entry.get('policy_primary_term')) != tuple(version):
            lagging.append(name)
    if not lagging:
        return
    result['moved'], failures = cluster.move_to_latest(lagging)
    result['failures'] += failures
    for failure in failures:
        log(f'Retention: could not move {failure}')
    verb = 'Dry run: would move' if cluster.dry_run else 'Moved'
    log(f'Retention: {verb} {result["moved"]} of the {len(lagging)} indices on an older '
        f'version of {POLICY_ID} onto the current one; ISM applies it at its next check '
        f'of each.')
    if failures:
        result['ok'] = False
        log(f'Retention: {len(failures)} indices are still on an older version. This is '
            f'retried at the next start.')


def _survey(cluster, managed, created, days, prefix, age, log, result, attach):
    """Reports, or with `attach` attaches, the daily indices no policy manages."""
    for name in sorted(n for n in created if is_daily(n, prefix)):
        policy_id = managing(managed.get(name))
        if policy_id is None:
            result['unmanaged'].append(name)
            if age(name) is not None and age(name) >= days:
                result['overdue'].append(name)
        elif policy_id != POLICY_ID:
            result['other_policy'].append(name)
    if result['other_policy']:
        log(f'Retention: {len(result["other_policy"])} TurkeyBite indices are managed by '
            f'another ISM policy, which is left alone.')
    unmanaged, overdue = result['unmanaged'], result['overdue']
    if not unmanaged:
        if attach:
            log('Retention: every existing TurkeyBite index is already under a policy.')
        return
    if not attach:
        log(f'Retention: {len(unmanaged)} existing TurkeyBite indices are not under the '
            f'retention policy, so they are kept until you decide otherwise. '
            f'{len(overdue)} of them are already older than {days} days and would be '
            f'deleted within minutes of attaching it. To attach it: {ATTACH_COMMAND} '
            f'(run it with --dry-run first to list them).')
        return
    if cluster.dry_run:
        for name in unmanaged:
            note = ", deleted at ISM's next check" if name in overdue else ''
            log(f'  {name}  created {int(age(name) or 0)} days ago{note}')
    result['attached'], failures = cluster.attach(unmanaged)
    result['failures'] += failures
    for failure in failures:
        log(f'Retention: could not attach {failure}')
    if failures:
        result['ok'] = False
    verb = 'Dry run: would attach' if cluster.dry_run else 'Attached'
    log(f'Retention: {verb} the policy to {result["attached"]} existing TurkeyBite '
        f'indices. {len(overdue)} of them are older than {days} days, and ISM deletes '
        f'those at its next check, within minutes.')
