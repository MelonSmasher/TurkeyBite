"""An in-memory Redis for the suites that need one.

Only the commands the code under test uses are here, and each behaves as
Redis does in the ways that code relies on: values come back as bytes, as
redis-py returns them without decode_responses, published messages included;
a list emptied by a pop or a trim stops existing; LRANGE and LTRIM take
inclusive, possibly negative, indexes; and SCAN yields keys from a snapshot,
so deleting while scanning is safe. SCAN may also return a key more than
once, as Redis's can while the keyspace is rehashing, which `scan_repeats`
reproduces.

Nothing blocks. BLMOVE on an empty list returns None at once, as if its
timeout had passed, except with a timeout of 0, which in Redis waits forever:
there it raises, so code that would hang fails the test instead. `listen()`
ends when the queued messages run out, so a test can drive a loop that would
otherwise run forever.

Every command is recorded in `calls` as (command, key), so a test can assert
the order things happened in, and `on_command`, when set, is called after
each one, so a test can act part way through a sequence: fetch while a
publish is half done, say.
"""

import fnmatch
import json

from libtb.queue import ACK_SCRIPT, RELEASE_SCRIPT, RENEW_SCRIPT, REQUEUE_SCRIPT
from libtb.radius import RECORD_SCRIPT


def _bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value).encode('ascii')
    raise TypeError(f'Redis takes bytes, str or numbers, not {type(value).__name__}')


def _number(value):
    """What Lua's type() calls a number: JSON's true and false are not."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _key(key):
    return key.decode('utf-8') if isinstance(key, bytes) else key


def _span(length, start, end):
    """Redis's inclusive start and end as a Python slice, negatives counted from the end."""
    if start < 0:
        start = max(length + start, 0)
    if end < 0:
        end = length + end
    end = min(end, length - 1)
    if start > end:
        return 0, 0
    return start, end + 1


class Blocked(AssertionError):
    """Raised where Redis would block forever."""


class FakeRedis(object):

    def __init__(self, scan_repeats=False, decoded_keys=False):
        self.data = {}
        # Expiries asked for, in seconds; kept, not enforced
        self.ttls = {}
        self.calls = []
        self.on_command = None
        self.blocked_for = []
        self.subscribers = []
        self.published = []
        # Sizes of each pipeline's execution, and keys unlinked one at a time
        self.executions = []
        self.direct_unlinks = []
        self.scan_repeats = scan_repeats
        # redis-py hands keys back as str when decode_responses is on
        self.decoded_keys = decoded_keys

    def _did(self, command, key=None):
        self.calls.append((command, _key(key)))
        if self.on_command is not None:
            self.on_command(command, _key(key))

    def _list(self, key):
        value = self.data.get(_key(key))
        if value is None:
            return []
        if not isinstance(value, list):
            raise TypeError('WRONGTYPE Operation against a key holding the wrong kind of value')
        return value

    def _store_list(self, key, items):
        if items:
            self.data[_key(key)] = items
        else:
            self.data.pop(_key(key), None)

    # -- strings ----------------------------------------------------------

    def get(self, key):
        value = self.data.get(_key(key))
        self._did('get', key)
        if isinstance(value, list):
            raise TypeError('WRONGTYPE Operation against a key holding the wrong kind of value')
        return value

    def set(self, key, value, nx=False, ex=None):
        """Set a string; with nx, only if the key is free.

        Expiry is recorded, not enforced: a test that needs a lapsed key
        deletes it.
        """
        self._did('set', key)
        if nx and _key(key) in self.data:
            return None
        self.data[_key(key)] = _bytes(value)
        if ex is not None:
            self.ttls[_key(key)] = ex
        return True

    def getex(self, key, ex=None):
        """Get a string, renewing its expiry."""
        value = self.get(key)
        if value is not None and ex is not None:
            self.ttls[_key(key)] = ex
        return value

    def expire(self, key, seconds):
        """Record an expiry for a key that exists."""
        self._did('expire', key)
        if _key(key) not in self.data:
            return False
        self.ttls[_key(key)] = seconds
        return True

    def eval(self, script, numkeys, *keys_and_args):
        """Run the queue's Lua scripts, and libtb.radius's, in Python."""
        keys, args = keys_and_args[:numkeys], keys_and_args[numkeys:]
        self._did('eval', keys[0])
        if script == RECORD_SCRIPT:
            return self._record(keys, *args)
        held = self.data.get(_key(keys[0]))
        mine = held == _bytes(args[0])
        if script == RENEW_SCRIPT:
            if mine:
                return int(self.expire(keys[0], int(args[1])))
            if held is None:
                self.set(keys[0], args[0], ex=int(args[1]))
                return 1
            return 0
        if script == RELEASE_SCRIPT:
            return self.delete(keys[0]) if mine else 0
        if script in (ACK_SCRIPT, REQUEUE_SCRIPT) and not mine:
            return -1
        if script == ACK_SCRIPT:
            self.ltrim(keys[1], int(args[1]), -1)
            return 1
        if script == REQUEUE_SCRIPT:
            moved = 0
            while moved < int(args[1]) and self.lmove(keys[1], keys[2], 'RIGHT', 'LEFT') is not None:
                moved += 1
            return moved
        raise NotImplementedError('a script the fake does not know')

    def _record(self, keys, field, user, device, start, seen, stopped, keep_sec, keep, signed, bridged,
                slack, device_sec, where, reported, moved, timed):
        """libtb.radius.RECORD_SCRIPT, as the Lua does it."""
        stopped = float(stopped) if stopped not in ('', b'') else None
        value = self._merged(keys[0], field, {
            'u': user, 'm': device, 's': float(start), 'l': float(seen), 'e': stopped,
            'x': stopped is not None and str(moved) == '1', 'k': str(timed) == '1',
            'a': str(signed) == '1', 'b': str(bridged) == '1',
            'r': float(reported) if reported not in ('', b'') else None,
            'f': None if str(bridged) == '1' else float(seen)}, float(slack), str(timed) == '1')
        if value is None or value['u'] == '':
            return 0
        stored = {'u': value['u'], 's': value['s'], 'l': value['l']}
        for name in ('m', 'e', 'f'):
            if value[name] not in (None, ''):
                stored[name] = value[name]
        if value['x']:
            stored['x'] = 1
        if value['k']:
            stored['k'] = 1
        if value['a']:
            stored['a'] = 1
        if value['b']:
            stored['b'] = 1
            if value['r'] is not None:
                stored['r'] = value['r']
        self.hset(keys[0], field, json.dumps(stored))
        self.expire(keys[0], int(keep_sec))
        self._trim(keys[0], int(keep), float(seen) - int(keep_sec))
        if len(keys) > 1:
            stop = stopped is not None and str(moved) != '1'
            self._remember_device(keys[1], where, float(seen), int(device_sec), value['b'],
                                  float(start) if stop else None, float(slack))
        return 1

    def _merged(self, key, field, value, slack, timed):
        """A report merged into what the hash holds for its session, or None to ignore it."""
        try:
            old = json.loads(self._hash(key).get(_bytes(field)) or 'null')
        except ValueError:
            old = None
        if not (isinstance(old, dict) and _number(old.get('s')) and _number(old.get('l'))):
            return value
        if old.get('k') == 1 and value['l'] < old['s'] - slack:
            return None
        if timed and value['s'] > old['l'] + slack:
            return value
        reported_at = value['l']
        if not (timed and old.get('k') != 1 and value['s'] < old['s']):
            value['s'] = old['s']
        value['k'] = timed or old.get('k') == 1
        value['l'] = max(value['l'], old['l'])
        self._merge_stop(value, old, reported_at)
        if value['u'] == '':
            if isinstance(old.get('u'), str):
                value['u'] = old['u']
            value['a'] = old.get('a') == 1
        elif old.get('a') == 1 and not value['a'] and isinstance(old.get('u'), str):
            value['u'], value['a'] = old['u'], True
        if value['m'] == '' and isinstance(old.get('m'), str):
            value['m'] = old['m']
        if old.get('b') is None:
            value['b'] = False
        if value['r'] is None and _number(old.get('r')):
            value['r'] = old['r']
        if _number(old.get('f')) and (value['f'] is None or old['f'] < value['f']):
            value['f'] = old['f']
        return value

    @staticmethod
    def _merge_stop(value, old, reported_at):
        """A real stop stays; one inferred from a move gives way to a later report of the session."""
        if not _number(old.get('e')):
            return
        old_moved = old.get('x') == 1
        if value['e'] is None:
            if not (old_moved and reported_at > old['e']):
                value['e'], value['x'] = old['e'], old_moved
        elif value['x']:
            if not old_moved:
                value['e'], value['x'] = old['e'], False
            elif old['e'] < value['e']:
                value['e'] = old['e']
        elif old_moved:
            if value['e'] > old['e']:
                value['e'], value['l'] = old['e'], old['l']
            value['x'] = False
        elif old['e'] > value['e']:
            value['e'] = old['e']

    def _trim(self, key, keep, cutoff):
        """Drops sessions last reported before `cutoff`, then keeps the `keep` most recent."""
        if self.hlen(key) <= 1:
            return
        rows = []
        for name, raw in self.hgetall(key).items():
            try:
                held = json.loads(raw)
            except ValueError:
                held = None
            last = held['l'] if isinstance(held, dict) and _number(held.get('l')) else -1
            if last < cutoff:
                self.hdel(key, name)
            else:
                rows.append((last, name))
        rows.sort(key=lambda row: row[0])
        for _, name in rows[:max(0, len(rows) - keep)]:
            self.hdel(key, name)

    def _remember_device(self, key, where, seen, seconds, roamed, stop_started=None, slack=0.0):
        """A device's last address: moved by a newer report that gave it, only its t by a roam.

        A stop at another address than the one held, from a session that
        started before the device was last reported there, does not move it.
        """
        try:
            last = json.loads(self.data.get(_key(key)) or 'null')
        except ValueError:
            last = None
        if not isinstance(last, dict):
            last = None
        if roamed:
            if last is not None:
                if not _number(last.get('t')) or last['t'] < seen:
                    last['t'] = seen
                self.set(key, json.dumps(last), ex=seconds)
        elif not (last is not None and _number(last.get('l')) and last['l'] > seen) \
                and not (stop_started is not None and last is not None and last.get('a') != where
                         and _number(last.get('l')) and stop_started < last['l'] - slack):
            latest = last['t'] if last is not None and _number(last.get('t')) and last['t'] > seen else seen
            self.set(key, json.dumps({'a': where, 'l': seen, 't': latest}), ex=seconds)

    def delete(self, *keys):
        removed = 0
        for key in keys:
            if self.data.pop(_key(key), None) is not None:
                removed += 1
            self._did('delete', key)
        return removed

    # -- lists ------------------------------------------------------------

    def rpush(self, key, *values):
        items = self._list(key) + [_bytes(v) for v in values]
        self._store_list(key, items)
        self._did('rpush', key)
        return len(items)

    def lpush(self, key, *values):
        items = list(self._list(key))
        for value in values:
            items.insert(0, _bytes(value))
        self._store_list(key, items)
        self._did('lpush', key)
        return len(items)

    def lpop(self, key, count=None):
        """Pops from the head; with a count, a list of up to that many, or None when empty."""
        self._did('lpop', key)
        items = self._list(key)
        taken = items[:1 if count is None else count]
        self._store_list(key, items[len(taken):])
        if count is None:
            return taken[0] if taken else None
        return taken or None

    def llen(self, key):
        self._did('llen', key)
        return len(self._list(key))

    def lrange(self, key, start, end):
        items = self._list(key)
        self._did('lrange', key)
        first, last = _span(len(items), start, end)
        return list(items[first:last])

    def ltrim(self, key, start, end):
        items = self._list(key)
        first, last = _span(len(items), start, end)
        self._store_list(key, list(items[first:last]))
        self._did('ltrim', key)
        return True

    def lmove(self, first_list, second_list, src='LEFT', dest='RIGHT'):
        source = list(self._list(first_list))
        if not source:
            self._did('lmove', first_list)
            return None
        value = source.pop(0 if src == 'LEFT' else -1)
        self._store_list(first_list, source)
        target = list(self._list(second_list))
        if dest == 'LEFT':
            target.insert(0, value)
        else:
            target.append(value)
        self._store_list(second_list, target)
        self._did('lmove', first_list)
        return value

    def blmove(self, first_list, second_list, timeout, src='LEFT', dest='RIGHT'):
        # Real Redis would wait up to timeout for an item; nothing else can
        # push while a test is waiting, so this answers at once. A timeout of
        # 0 waits forever in Redis, so here it fails rather than pretending.
        self.blocked_for.append(timeout)
        if not timeout and not self._list(first_list):
            raise Blocked(f'BLMOVE {first_list} with a timeout of 0 would wait forever')
        return self.lmove(first_list, second_list, src, dest)

    def unlink(self, *keys):
        removed = 0
        for key in keys:
            self.direct_unlinks.append(_key(key))
            if self.data.pop(_key(key), None) is not None:
                removed += 1
            self._did('unlink', key)
        return removed

    def pipeline(self, transaction=True):
        return FakePipeline(self)

    # -- hashes -----------------------------------------------------------

    def _hash(self, key):
        value = self.data.get(_key(key))
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TypeError('WRONGTYPE Operation against a key holding the wrong kind of value')
        return value

    def hset(self, key, field, value):
        self._did('hset', key)
        held = self._hash(key)
        added = int(_bytes(field) not in held)
        held[_bytes(field)] = _bytes(value)
        self.data[_key(key)] = held
        return added

    def hget(self, key, field):
        self._did('hget', key)
        return self._hash(key).get(_bytes(field))

    def hgetall(self, key):
        self._did('hgetall', key)
        return dict(self._hash(key))

    def hdel(self, key, *fields):
        """Removes fields; a hash left empty stops existing."""
        self._did('hdel', key)
        held = self._hash(key)
        removed = sum(1 for field in fields if held.pop(_bytes(field), None) is not None)
        if not held:
            self.data.pop(_key(key), None)
        return removed

    def hlen(self, key):
        self._did('hlen', key)
        return len(self._hash(key))

    # -- keys -------------------------------------------------------------

    def scan_iter(self, match=None, count=None):
        for key in sorted(self.data):
            if match is None or fnmatch.fnmatchcase(key, match):
                for _ in range(2 if self.scan_repeats else 1):
                    yield key if self.decoded_keys else key.encode('utf-8')

    # -- pub/sub ----------------------------------------------------------

    def publish(self, channel, data):
        """Queues a message for the subscriber the code under test will open.

        Real Redis delivers only to a subscriber that already exists, which a
        test cannot arrange around a loop that blocks, so the message waits.
        """
        self.published.append({'type': 'message', 'pattern': None,
                               'channel': _bytes(channel), 'data': _bytes(data)})
        self._did('publish', channel)

    def pubsub(self):
        subscriber = FakePubSub(self.published)
        self.subscribers.append(subscriber)
        return subscriber


class FakePipeline(object):
    """Queues UNLINKs and runs them on execute, recording how many each time."""

    def __init__(self, redis):
        self.redis = redis
        self.queued = []

    def unlink(self, *keys):
        self.queued.extend(_key(key) for key in keys)
        return self

    def execute(self):
        results = [1 if self.redis.data.pop(key, None) is not None else 0
                   for key in self.queued]
        self.redis.executions.append(len(self.queued))
        self.queued = []
        return results


class FakePubSub(object):
    """A subscription that yields what was published, then ends."""

    def __init__(self, published=()):
        self.channels = []
        self.pending = list(published)
        self.confirmations = 0

    def subscribe(self, *channels):
        for channel in channels:
            self.channels.append(_key(channel))
            # What redis-py yields first: a confirmation whose data is the
            # number of channels subscribed, an int rather than a payload
            self.pending.insert(self.confirmations, {
                'type': 'subscribe', 'pattern': None, 'channel': _bytes(channel),
                'data': len(self.channels)})
            self.confirmations += 1

    def listen(self):
        while self.pending:
            yield self.pending.pop(0)
