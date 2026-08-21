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

PROCESSING_PREFIX = 'processing:'


def recover_orphans(redis, key, keep_consumers=(), match=None):
    """Requeues work stranded in processing lists whose consumer is gone.

    A consumer only recovers its own list on startup, which relies on the
    consumer name being stable. When a name changes, for instance because it was
    derived from a container id, the old list is left holding claimed events that
    nothing will ever acknowledge.

    Call this before any consumer starts, so no live consumer owns a list being
    swept. `keep_consumers` names lists to leave alone. `match` limits the sweep
    to names starting with a prefix, which is how one host avoids reclaiming
    another host's in-flight work.

    Returns (lists_swept, events_requeued).
    """
    pattern = f'{key}:{PROCESSING_PREFIX}{match or ""}*'
    keep = {f'{key}:{PROCESSING_PREFIX}{c}' for c in keep_consumers}
    swept = requeued = 0
    for raw in redis.scan_iter(match=pattern, count=100):
        name = raw.decode('utf-8') if isinstance(raw, bytes) else raw
        if name in keep:
            continue
        items = redis.lrange(name, 0, -1)
        if items:
            # LPUSH reverses, so push in reverse to restore the original order
            for payload in reversed(items):
                redis.lpush(key, payload)
            requeued += len(items)
        redis.delete(name)
        swept += 1
    return swept, requeued


class ListQueue(object):

    def __init__(self, redis, key, consumer):
        self.redis = redis
        self.key = key
        self.consumer = consumer
        self.processing_key = f'{key}:{PROCESSING_PREFIX}{consumer}'

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
        dropped. The processing list is cleared for exactly those items.
        """
        if not items:
            return
        # LPUSH reverses, so push in reverse to restore the original order
        for payload in reversed(items):
            self.redis.lpush(self.key, payload)
        self.ack(len(items))
