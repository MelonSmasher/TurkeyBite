"""An in-memory Redis for the suites that need one.

Only the commands the code under test uses are here, and each behaves as
Redis does in the ways that code relies on: values come back as bytes, as
redis-py returns them without decode_responses; a list emptied by a pop or a
trim stops existing; LRANGE and LTRIM take inclusive, possibly negative,
indexes; and SCAN yields keys from a snapshot, so deleting while scanning is
safe. Nothing blocks: BLMOVE on an empty list returns None at once, and
`listen()` ends when the queued messages run out, so a test can drive a loop
that would otherwise run forever.

Every command is recorded in `calls` as (command, key), so a test can assert
the order things happened in, and `on_command`, when set, is called after
each one, so a test can act part way through a sequence: fetch while a
publish is half done, say.
"""

import fnmatch


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


class FakeRedis(object):

    def __init__(self):
        self.data = {}
        self.calls = []
        self.on_command = None
        self.blocked_for = []
        self.subscribers = []
        self.published = []

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

    def set(self, key, value):
        self.data[_key(key)] = _bytes(value)
        self._did('set', key)
        return True

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
        # push while a test is waiting, so this answers at once
        self.blocked_for.append(timeout)
        return self.lmove(first_list, second_list, src, dest)

    # -- keys -------------------------------------------------------------

    def scan_iter(self, match=None, count=None):
        for key in sorted(self.data):
            if match is None or fnmatch.fnmatchcase(key, match):
                yield key.encode('utf-8')

    # -- pub/sub ----------------------------------------------------------

    def publish(self, channel, data):
        """Queues a message for the subscriber the code under test will open.

        Real Redis delivers only to a subscriber that already exists, which a
        test cannot arrange around a loop that blocks, so the message waits.
        """
        self.published.append({'type': 'message', 'pattern': None,
                               'channel': _bytes(channel), 'data': data})
        self._did('publish', channel)

    def pubsub(self):
        subscriber = FakePubSub(self.published)
        self.subscribers.append(subscriber)
        return subscriber


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
