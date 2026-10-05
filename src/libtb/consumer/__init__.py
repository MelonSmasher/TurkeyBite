"""One process that drains the durable queue and indexes what survives.

Replaces the Inlet plus RQ plus the RQ worker for the new path. Previously an
event made two trips through Redis: in on pub/sub, then out again through the RQ
queue with a pickle in between. Here it makes one.

The ordering is the point:

    claim a batch          items move to this consumer's processing list
    sieve and enrich       in memory
    flush to OpenSearch    one bulk request
    acknowledge            only now do the items leave the processing list

Because the acknowledgement happens after the flush, bulk buffering stops being
a loss window and becomes free. That is the trade O2 could not make under RQ,
which marked a job finished the moment the processor returned.

A batch OpenSearch does not take is requeued whole rather than acknowledged,
whether bulk buffering is on or off: when every host refuses, or when it asks
for any document to be retried later, as it does with a 429 when its queues
are full. Documents that were indexed before the failure are indexed again
when the batch is replayed, and its syslog copies are sent again. A document
refused for good, by a mapping error say, is logged and acknowledged, since
retrying it would requeue it forever.

After a batch is requeued the consumer rests before claiming the next one, one
second at first and doubling with each failure in a row up to a minute, and a
batch that is taken ends the rest. Without it an OpenSearch outage turns every
consumer into a loop that claims, fails and requeues as fast as Valkey answers,
logging each time. The rest is cut short by stop(), so a restart is not held up.

When Valkey stops answering the consumer rests the same way and tries again,
rather than exiting: supervisor gives up on a program that keeps failing as it
starts, so a Valkey restart longer than its retries would leave the consumer
stopped for good. Once Valkey answers, whatever this consumer's processing
list holds is handled again before anything new is claimed, since nothing says
whether the batch in hand was acknowledged or requeued before it went away.

Delivery is at-least-once. A crash between flush and ack replays that batch, so
a small number of documents can be indexed twice. Documents are given
auto-generated ids rather than a content hash, deliberately: two identical DNS
queries in the same millisecond produce byte-identical payloads, and a content
hash would silently collapse them, which undercounts real traffic. Occasional
duplicates after a crash are the lesser problem. If exactly-once matters more,
add libbeat's `add_id` processor at the beat and key on that.
"""

import json
import signal
import sys
import time

from redis.exceptions import ConnectionError as ValkeyConnectionError
from redis.exceptions import TimeoutError as ValkeyTimeoutError

from libtb.inlet import describe
from libtb.processor import DeliveryError

# The rest after a batch OpenSearch did not take: the first, the longest, and
# the slice it is served in, which is how quickly stop() is honoured during one
BACKOFF_START = 1.0
BACKOFF_MAX = 60.0
BACKOFF_SLICE = 0.5

# Valkey not answering, which the consumer waits out instead of exiting
VALKEY_ERRORS = (ValkeyConnectionError, ValkeyTimeoutError)


class Consumer(object):

    def __init__(self, queue, filters, processor, batch_size=500, block_seconds=1,
                 name=None, log_events=True, sleep=time.sleep):
        # Every consumer writes to the same container stdout, so each line has to
        # identify which one wrote it
        self.name = name or getattr(queue, 'consumer', 'consumer')
        self.queue = queue
        self.filters = filters
        self.processor = processor
        self.batch_size = batch_size
        self.block_seconds = block_seconds
        # A batch is acknowledged only once indexed, so the processor must say
        # when an event was not, rather than log and drop it as the RQ path does
        processor.strict_delivery = True
        # The Inlet logged every packet it saw, queued or dropped. This path
        # replaces the Inlet, so it keeps that behaviour rather than silently
        # removing the only per-event visibility there was. Turn it off with
        # --quiet when the volume is not worth the log lines.
        self.log_events = log_events
        # Replaceable so tests can see the rests without serving them
        self.sleep = sleep
        self.failures = 0
        self.running = True
        self.stats = {'claimed': 0, 'kept': 0, 'dropped': 0, 'unreadable': 0,
                      'indexed': 0, 'requeued': 0, 'batches': 0}

    def stop(self, *_):
        """Finish the batch in hand, then exit. Supervisor stops us with TERM."""
        self.running = False

    def install_signal_handlers(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self.stop)
            except (ValueError, OSError):
                pass

    def handle_batch(self, items):
        """Sieves, enriches and indexes one claimed batch.

        Returns the number of items that may be acknowledged, or None if the
        batch could not be indexed and should be requeued.
        """
        kept = 0
        for raw in items:
            try:
                data = json.loads(raw.decode('utf-8') if isinstance(raw, bytes) else raw)
            except (UnicodeDecodeError, ValueError):
                self.stats['unreadable'] += 1
                continue
            try:
                keep = self.filters.should_process(data)
            except Exception as e:
                # A packet we cannot read costs that packet and no more
                print(f'[{self.name}] skipped an unreadable packet: {e}', file=sys.stderr)
                self.stats['unreadable'] += 1
                continue
            if self.log_events:
                line = describe(data, 'Queued' if keep else 'Dropped',
                                self.processor.privacy().urls)
                if line:
                    print(line)
            if not keep:
                self.stats['dropped'] += 1
                continue
            try:
                self.processor.process_packet(data)
                kept += 1
            except DeliveryError as e:
                # OpenSearch is down or asked for a retry, so the rest would
                # fare no better: requeue the whole batch now. What is still
                # buffered goes too, or the replay would index it twice more.
                self.processor.discard_bulk()
                print(f'[{self.name}] batch not indexed, requeueing {len(items)} items: {e}',
                      file=sys.stderr)
                return None
            except VALKEY_ERRORS:
                # The valkey lookup mode reads the host lists from Valkey, so
                # this is not the event's fault and must not cost it: run()
                # waits for Valkey and handles the batch again
                self.processor.discard_bulk()
                raise
            except Exception as e:
                # An enrichment failure is this event's problem, not the batch's
                print(f'[{self.name}] failed to process a packet: {e}', file=sys.stderr)
                self.stats['unreadable'] += 1

        try:
            self.stats['indexed'] += self.processor.flush_bulk(
                force=True, raise_on_total_failure=True) or 0
        except Exception as e:
            print(f'[{self.name}] batch not indexed, requeueing {len(items)} items: {e}',
                  file=sys.stderr)
            return None

        self.stats['kept'] += kept
        return len(items)

    def rest(self):
        """Waits after a batch was requeued or Valkey did not answer, longer
        each time in a row.

        Returns the length of the rest it was due, whether or not stop() cut it
        short.
        """
        self.failures += 1
        # The exponent is capped, or a long enough outage would overflow the float
        due = min(BACKOFF_MAX, BACKOFF_START * 2 ** min(self.failures - 1, 16))
        print(f'[{self.name}] resting {due:g}s before the next batch, '
              f'{self.failures} failed in a row', file=sys.stderr)
        served = 0.0
        while self.running and served < due:
            step = min(BACKOFF_SLICE, due - served)
            self.sleep(step)
            served += step
        return due

    def settle(self, items, acked):
        """Acknowledges a handled batch, or requeues it and rests."""
        if acked is None:
            self.queue.requeue(items)
            self.stats['requeued'] += len(items)
            self.rest()
        else:
            self.queue.ack(acked)
            self.failures = 0

    def run_once(self):
        """One claim, handle, acknowledge cycle. Returns items claimed."""
        items = self.queue.claim(self.batch_size, self.block_seconds)
        if not items:
            return 0
        self.stats['claimed'] += len(items)
        self.stats['batches'] += 1
        self.settle(items, self.handle_batch(items))
        return len(items)

    def settle_stranded(self, why):
        """Handles whatever this consumer's processing list holds."""
        stranded = self.queue.recover()
        if stranded:
            print(f'[{self.name}] recovering {len(stranded)} items {why}')
            self.settle(stranded, self.handle_batch(stranded))

    def run(self, report_seconds=60):
        """Drains the queue until stopped."""
        recovering = 'left in flight by a previous run'
        last_report = time.monotonic()
        while True:
            try:
                if recovering:
                    self.settle_stranded(recovering)
                    recovering = None
                if not self.running:
                    break
                self.run_once()
                now = time.monotonic()
                if now - last_report >= report_seconds:
                    last_report = now
                    print('[{0}] queue depth {1}, in flight {2}, {3}'.format(
                        self.name, self.queue.depth(), self.queue.in_flight(),
                        ', '.join(f'{k}={v}' for k, v in sorted(self.stats.items()))))
            except VALKEY_ERRORS as e:
                print(f'[{self.name}] Valkey did not answer: {e}', file=sys.stderr)
                # A claim, an acknowledgement or a requeue may have been cut
                # short, leaving items in the processing list ahead of the
                # next batch, whose acknowledgement trims from the head: so
                # handle all of it again before claiming more
                recovering = 'in flight when Valkey stopped answering'
                if not self.running:
                    break
                self.rest()

        # A clean stop must not leave a batch buffered
        try:
            self.processor.flush_bulk(force=True)
        except Exception as e:
            print(f'[{self.name}] final flush failed: {e}', file=sys.stderr)
        print(f'[{self.name}] stopped. ' + ', '.join(
            f'{k}={v}' for k, v in sorted(self.stats.items())))
