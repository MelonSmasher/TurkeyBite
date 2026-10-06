"""A durable work queue built on a Redis list.

Replaces the pub/sub channel. Pub/sub is fire-and-forget: no persistence, no
acknowledgement, no backpressure. Every container restart dropped whatever was
in flight, and when the single subscriber fell behind a burst Valkey disconnected
it at the 32 MB output-buffer limit and everything published during the gap was
gone with no error and no counter.

Why a list rather than a stream. Packetbeat's redis output supports only
`data_type: list` (RPUSH) and `channel` (PUBLISH). It cannot XADD. Using streams
would mean running a shim to read pub/sub and write to the stream, and that shim
would be exactly the single point of failure this is meant to remove. A list is
written natively by the beat, survives a restart, and supports the reliable-queue
pattern below.

Delivery is at-least-once:

    BLMOVE queue processing:<consumer> LEFT RIGHT   claim, atomically
    ... sieve, enrich, index ...
    LTRIM processing:<consumer> <n> -1              acknowledge

An item is only removed from `processing` once it has been indexed, so a consumer
that dies mid-batch leaves its work visible rather than losing it. Consumer names
are stable under supervisor, so on startup a consumer recovers its own leftovers.

At-least-once means a document can be indexed twice after a crash. Callers should
give OpenSearch a deterministic `_id` so a replay overwrites rather than
duplicates.

Depth is `LLEN` on the queue, which is the backpressure signal pub/sub could not
provide at all.
"""

import os
import re
import socket
import uuid

PROCESSING_PREFIX = 'processing:'

# A consumer that requeues a stranded list moves one item at a time, so it
# stops after this many more than the list held when it began, rather than
# chasing a consumer that is still claiming into it
REQUEUE_SLACK = 10000


def generated_names(prefix):
    """The consumer names the start scripts generate for a prefix: <prefix>-NN.

    tb-consume.template names each consumer TURKEYBITE_CONSUMER_PREFIX, a
    dash and a process number, and `turkeybite consume` without --consumer
    uses the host name, a dash and a pid. Matching exactly that shape is what
    keeps one host's sweep off another's work when one prefix starts another:
    tb-worker would otherwise take tb-worker-b-01, and worker1 worker10-01.
    """
    return re.compile(re.escape(prefix) + r'-\d+')


def requeue_list(redis, key, name):
    """Moves a processing list's items back to the head of the queue. Returns how many.

    One atomic LMOVE at a time, from the list's tail to the queue's head, so
    they arrive in the order they were claimed and none is ever in neither
    place. Nothing is deleted: a list Redis empties stops existing by itself,
    and an item claimed into it meanwhile is moved like the rest.
    """
    moved = 0
    limit = redis.llen(name) + REQUEUE_SLACK
    while moved < limit and redis.lmove(name, key, 'RIGHT', 'LEFT') is not None:
        moved += 1
    return moved


def recover_orphans(redis, key, keep_consumers=(), prefix=None, consumers=None):
    """Requeues work stranded in processing lists whose consumer is gone.

    A consumer recovers its own list when it starts again under the same
    name. A name that changes, for instance because it was derived from a
    container id, leaves its list holding claimed events nothing will
    acknowledge.

    Which lists: with `prefix`, those of consumers named as the start scripts
    name them, <prefix>-NN, see generated_names; with `consumers`, exactly
    those consumers; with neither, every processing list of this queue, which
    is only safe when no consumer is running anywhere. `keep_consumers` are
    left alone in every case. Call this before any consumer it could match
    starts.

    Returns (lists_swept, events_requeued), each list counted once however
    often SCAN returns it.
    """
    base = f'{key}:{PROCESSING_PREFIX}'
    if consumers is not None:
        names = {base + consumer for consumer in consumers}
    else:
        pattern = base + (f'{prefix}-*' if prefix else '*')
        names = {raw.decode('utf-8') if isinstance(raw, bytes) else raw
                 for raw in redis.scan_iter(match=pattern, count=100)}
        if prefix:
            shape = generated_names(prefix)
            names = {name for name in names if shape.fullmatch(name[len(base):])}
    names -= {base + consumer for consumer in keep_consumers}
    # A consumer that holds its name now is running, and its list is its own
    names = {name for name in names
             if not redis.get(f'{key}:owner:{name[len(base):]}')}

    swept = requeued = 0
    for name in sorted(names):
        moved = requeue_list(redis, key, name)
        if moved or consumers is None:
            swept += 1
        requeued += moved
    return swept, requeued


# A consumer's reservation of its name, renewed and released only by the
# process holding it: compared and changed in one step, in Valkey
RENEW_SCRIPT = """
local held = redis.call('GET', KEYS[1])
if held == ARGV[1] then
    return redis.call('EXPIRE', KEYS[1], ARGV[2])
end
if not held then
    redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
    return 1
end
return 0
"""
RELEASE_SCRIPT = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"""


class ListQueue(object):

    # How long a consumer's name stays reserved without being renewed. A
    # consumer renews it every batch, and a rest is at most a minute
    OWNER_TTL = 90

    def __init__(self, redis, key, consumer):
        self.redis = redis
        self.key = key
        self.consumer = consumer
        self.processing_key = f'{key}:{PROCESSING_PREFIX}{consumer}'
        self.owner_key = f'{key}:owner:{consumer}'
        self.owner = f'{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex}'
        self.reserved = False

    # -- owning the name --------------------------------------------------

    def reserve(self):
        """Takes this consumer's name for this process.

        Returns False if another running consumer has it. Two consumers
        given one name share one processing list, and a requeue, which moves
        items from the list's tail, could then take the other's items while
        its own were acknowledged and lost. So a name is held by one process
        at a time: reserved here, renewed while running, and released at the
        end, or lapsing OWNER_TTL seconds after a process dies without
        releasing it.
        """
        self.reserved = bool(self.redis.set(self.owner_key, self.owner, nx=True, ex=self.OWNER_TTL))
        return self.reserved

    def renew(self):
        """Keeps the name reserved.

        Returns False if another process has it now, and True when it was
        never reserved, as by a test driving a queue. A reservation that
        lapsed, while Valkey was down say, and that nobody took, is taken
        again. Checked and extended in one step, in Valkey, so a reservation
        that lapses in between cannot be extended for its new owner.
        """
        if not self.reserved:
            return True
        return bool(self.redis.eval(RENEW_SCRIPT, 1, self.owner_key, self.owner, self.OWNER_TTL))

    def release(self):
        """Gives the name up, if it is still this process's."""
        if not self.reserved:
            return
        self.redis.eval(RELEASE_SCRIPT, 1, self.owner_key, self.owner)
        self.reserved = False

    # -- producing, used by tests and by any local shim ---------------------

    def push(self, payload):
        """Appends to the tail, which is what Packetbeat's RPUSH does."""
        return self.redis.rpush(self.key, payload)

    # -- consuming ---------------------------------------------------------

    def depth(self):
        return self.redis.llen(self.key)

    def in_flight(self):
        return self.redis.llen(self.processing_key)

    def recover(self):
        """Returns anything stranded in this consumer's processing list.

        Called at startup. A consumer that was killed mid-batch left its claimed
        items here, and since the consumer name is stable it can pick them up
        again rather than stranding them forever.
        """
        return self.redis.lrange(self.processing_key, 0, -1)

    def claim(self, max_items, block_seconds=1):
        """Moves up to max_items from the queue into this consumer's processing
        list and returns them.

        Blocks up to block_seconds waiting for the first item, then takes the
        rest without blocking so a partial batch is not delayed by a quiet queue.
        """
        claimed = []
        first = self.redis.blmove(self.key, self.processing_key, block_seconds, 'LEFT', 'RIGHT')
        if first is None:
            return claimed
        claimed.append(first)
        while len(claimed) < max_items:
            item = self.redis.lmove(self.key, self.processing_key, 'LEFT', 'RIGHT')
            if item is None:
                break
            claimed.append(item)
        return claimed

    def ack(self, count):
        """Drops the first `count` claimed items from the processing list.

        Only called once those items are durably indexed. LTRIM keeps the range
        from `count` onwards, so anything claimed after this batch survives.
        """
        if count <= 0:
            return
        self.redis.ltrim(self.processing_key, count, -1)

    def requeue(self, items):
        """Puts items back at the head of the queue, preserving order.

        Used when a batch cannot be indexed and should be retried rather than
        dropped. One atomic LMOVE per item, from the processing list's tail to
        the queue's head, so an item is never in both places or in neither:
        pushing copies and then trimming the originals left the whole batch in
        both if the connection dropped in between, and a restart replayed it.
        A consumer claims its next batch only once this one is settled, so the
        batch is all its processing list holds, and the tail is its end.
        Returns how many were moved.
        """
        moved = 0
        while moved < len(items) and self.redis.lmove(
                self.processing_key, self.key, 'RIGHT', 'LEFT') is not None:
            moved += 1
        return moved
