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

from libtb.queue import RELEASE_SCRIPT, RENEW_SCRIPT


def _bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value).encode('ascii')
    raise TypeError(f'Redis takes bytes, str or numbers, not {type(value).__name__}')


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

    def expire(self, key, seconds):
        """Record an expiry for a key that exists."""
        self._did('expire', key)
        if _key(key) not in self.data:
            return False
        self.ttls[_key(key)] = seconds
        return True

    def eval(self, script, numkeys, *keys_and_args):
        """Run the queue's Lua scripts, in Python."""
        keys, args = keys_and_args[:numkeys], keys_and_args[numkeys:]
        self._did('eval', keys[0])
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
        raise NotImplementedError('a script the fake does not know')

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
