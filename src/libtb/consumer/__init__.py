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

from libtb.inlet import describe


class Consumer(object):

    def __init__(self, queue, filters, processor, batch_size=500, block_seconds=1,
                 name=None, log_events=True):
        # Every consumer writes to the same container stdout, so each line has to
        # identify which one wrote it
        self.name = name or getattr(queue, 'consumer', 'consumer')
        self.queue = queue
        self.filters = filters
        self.processor = processor
        self.batch_size = batch_size
        self.block_seconds = block_seconds
        # The Inlet logged every packet it saw, queued or dropped. This path
        # replaces the Inlet, so it keeps that behaviour rather than silently
        # removing the only per-event visibility there was. Turn it off with
        # --quiet when the volume is not worth the log lines.
        self.log_events = log_events
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
                line = describe(data, 'Queued' if keep else 'Dropped')
                if line:
                    print(line)
            if not keep:
                self.stats['dropped'] += 1
                continue
            try:
                self.processor.process_packet(data)
                kept += 1
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

    def run_once(self):
        """One claim, handle, acknowledge cycle. Returns items claimed."""
        items = self.queue.claim(self.batch_size, self.block_seconds)
        if not items:
            return 0
        self.stats['claimed'] += len(items)
        self.stats['batches'] += 1
        acked = self.handle_batch(items)
        if acked is None:
            self.queue.requeue(items)
            self.stats['requeued'] += len(items)
        else:
            self.queue.ack(acked)
        return len(items)

    def run(self, report_seconds=60):
        """Drains the queue until stopped."""
        stranded = self.queue.recover()
        if stranded:
            print(f'[{self.name}] recovering {len(stranded)} items left in flight '
                  f'by a previous run')
            acked = self.handle_batch(stranded)
            if acked is None:
                self.queue.requeue(stranded)
            else:
                self.queue.ack(acked)

        last_report = time.monotonic()
        while self.running:
            self.run_once()
            now = time.monotonic()
            if now - last_report >= report_seconds:
                last_report = now
                print('[{0}] queue depth {1}, in flight {2}, {3}'.format(
                    self.name, self.queue.depth(), self.queue.in_flight(),
                    ', '.join(f'{k}={v}' for k, v in sorted(self.stats.items()))))

        # A clean stop must not leave a batch buffered
        try:
            self.processor.flush_bulk(force=True)
        except Exception as e:
            print(f'[{self.name}] final flush failed: {e}', file=sys.stderr)
        print(f'[{self.name}] stopped. ' + ', '.join(
            f'{k}={v}' for k, v in sorted(self.stats.items())))
