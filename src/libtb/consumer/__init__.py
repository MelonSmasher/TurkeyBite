"""One process that drains the durable queue and indexes what survives.


The ordering is the point:

    claim a batch          items move to this consumer's processing list
    sieve and enrich       in memory
    flush to OpenSearch    one bulk request
    acknowledge            only now do the items leave the processing list

Because acknowledgement happens after the flush, bulk buffering introduces no
loss window: an interrupted batch remains in its processing list for replay.

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
from redis.exceptions import RedisError
from redis.exceptions import TimeoutError as ValkeyTimeoutError

from libtb.privacy import TRIMMED, trim_url
from libtb.opensearch import report_once
from libtb.radius import ACCESS_ACCEPT, address, attributes, misrouted
from libtb.util import dig
from libtb.processor import DeliveryError
from libtb.queue import NotOwner

# The rest after a batch OpenSearch did not take: the first, the longest, and
# the slice it is served in, which is how quickly stop() is honoured during one
BACKOFF_START = 1.0
BACKOFF_MAX = 60.0
BACKOFF_SLICE = 0.5

# Valkey not answering, which the consumer waits out instead of exiting
VALKEY_ERRORS = (ValkeyConnectionError, ValkeyTimeoutError)

# How often a batch being handled renews the consumer's name, well inside
# ListQueue.OWNER_TTL, so a slow batch cannot outlast the reservation
RENEW_SECONDS = 20.0

# The most lines of NPS's log taken from the accounting list at a time, and
# the most kept on it while this worker has processor.radius off
ACCOUNTING_BATCH = 500
ACCOUNTING_KEEP = 10000


def describe(data, verdict, urls=TRIMMED):
    """Builds the log line for an observed packet.

    Fields are read through dig() or checked for their type first, so a
    malformed packet cannot terminate the consumer while building its log.

    `urls` is processor.privacy.urls. The log keeps no more of a URL than the
    event does: a container log is a store too, and a trimmed event beside a
    log holding the full URL would protect nothing. It defaults to trimmed, so
    a caller that forgets to pass it fails closed.

    Returns None for a packet we have nothing to say about.
    """
    packet_type = dig(data, 'type')

    if packet_type == 'dns':
        resource = dig(data, 'resource')
        if not isinstance(resource, str):
            return None
        line = '[Packetbeat][DNS] ' + verdict + ': ' + resource
        direction = dig(data, 'network', 'direction')
        if isinstance(direction, str):
            line = line + ' - ' + direction
        return line

    if packet_type == 'browser.history':
        line = '[Browserbeat][History] ' + verdict
        url = dig(data, 'data', 'event', 'data', 'entry', 'url')
        if isinstance(url, str):
            line = line + ' : ' + trim_url(url, urls)
        user = dig(data, 'data', 'event', 'data', 'client', 'user')
        if isinstance(user, str):
            line = line + ' - ' + user
        short_hostname = dig(data, 'data', 'event', 'data', 'client', 'Hostname', 'short')
        if isinstance(short_hostname, str):
            line = line + ' - ' + short_hostname
        return line

    return None


def describe_accounting(data, verdict):
    """Builds the log line for a line of NPS's log, taken from the accounting list.

    Only what libtb.radius would accept as an address, so a line cannot
    forge another in the log, and no names: every sign-in on the network
    would otherwise be in the container's log.
    """
    fields = attributes(dig(data, 'message'))
    kind = 'Accept' if fields.get('Packet-Type') == ACCESS_ACCEPT else 'Accounting'
    line = f'[NPS][{kind}] {verdict}'
    where = address(fields.get('Framed-IP-Address'))
    if where:
        line = line + ': ' + where
    return line


class NameLost(Exception):
    """Another process has this consumer's name, so its processing list."""


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
        # A batch is acknowledged only once indexed, so delivery failures must
        # reach the consumer instead of being logged and dropped.
        processor.strict_delivery = True
        # Per-event visibility includes queued and dropped packets. Turn it off
        # with --quiet when the volume is not worth the log lines.
        self.log_events = log_events
        # Replaceable so tests can see the rests without serving them
        self.sleep = sleep
        self.failures = 0
        self.running = True
        # Set when another process took this consumer's name, so it stopped
        self.name_lost = False
        self.stats = {'claimed': 0, 'kept': 0, 'dropped': 0, 'unreadable': 0,
                      'indexed': 0, 'requeued': 0, 'batches': 0, 'accounting': 0}

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
        renewed = time.monotonic()
        for raw in items:
            if time.monotonic() - renewed >= RENEW_SECONDS:
                try:
                    self.hold_name()
                except VALKEY_ERRORS:
                    # The batch is handled again from the start once Valkey
                    # answers: what it buffered goes, or it would be sent twice
                    self.processor.discard_bulk()
                    raise
                renewed = time.monotonic()
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
                self.drop(data)
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

    def drop(self, data):
        """Counts a packet the sieve dropped, and says where NPS's lines should go if it is one."""
        self.stats['dropped'] += 1
        if misrouted(data):
            report_once(f'Lines of NPS\'s log are arriving on {getattr(self.queue, "key", "the queue")}, '
                        f'which drops them: send them to the accounting list, '
                        f'{self.processor.accounting_list() or "<channel>:nps"}')

    def rest(self):
        """Waits after a batch was requeued or Valkey did not answer.

        Each rest in a row is longer than the one before. Returns the length of
        the rest it was due, whether or not stop() cut it short.
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

    def hold_name(self):
        """Renews this consumer's name, or raises NameLost if another has it."""
        if not self.queue.renew():
            raise NameLost(self.name)

    def settle(self, items, acked):
        """Acknowledges a handled batch, or requeues it and rests.

        Only while the name is still this process's: otherwise the list is
        another's, whose items an acknowledgement or a requeue would take.
        """
        self.hold_name()
        try:
            self._settle(items, acked)
        except NotOwner as e:
            # Lost between the check above and the change, in a stall
            raise NameLost(self.name) from e

    def _settle(self, items, acked):
        """Acknowledges or requeues, as settle() says."""
        if acked is None:
            self.queue.requeue(items)
            self.stats['requeued'] += len(items)
            self.rest()
        else:
            self.queue.ack(acked)
            self.failures = 0

    def take_accounting(self):
        """Records what waits on the accounting list, see libtb.radius. Returns lines taken.

        Taken at most once, with LPOP: lines in hand when a worker dies are
        lost, which costs no more than the next interim update puts back.
        With processor.radius off here, the lines are left for workers that
        have it on, and the list is only kept to its newest ACCOUNTING_KEEP
        lines, so it cannot grow without end while nobody takes them.
        """
        key = self.processor.accounting_list()
        redis = getattr(self.queue, 'redis', None)
        if not key or redis is None:
            return 0
        try:
            if not self.processor.radius_on():
                redis.ltrim(key, -ACCOUNTING_KEEP, -1)
                return 0
            items = redis.lpop(key, ACCOUNTING_BATCH) or []
        except RedisError as e:
            if isinstance(e, VALKEY_ERRORS):
                raise
            # Valkey refusing the list must not stop the DNS events too
            report_once(f'The accounting list {key} could not be read: {type(e).__name__}')
            return 0
        for raw in items:
            try:
                data = json.loads(raw.decode('utf-8') if isinstance(raw, bytes) else raw)
                recorded = self.processor.process_nps(data)
            except Exception as e:
                if isinstance(e, VALKEY_ERRORS):
                    raise
                # A line we cannot read costs that line and no more
                print(f'[{self.name}] skipped an unreadable accounting line: {e}', file=sys.stderr)
                self.stats['unreadable'] += 1
                continue
            if self.log_events:
                print(describe_accounting(data, 'Recorded' if recorded else 'Dropped'))
        self.stats['accounting'] += len(items)
        return len(items)

    def run_once(self):
        """One claim, handle, acknowledge cycle. Returns items claimed."""
        self.take_accounting()
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
                # Before the processing list is touched, recovery included:
                # another process that has this consumer's name has the list
                self.hold_name()
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
            except NameLost:
                print(f'[{self.name}] stopping: another consumer has taken the name '
                      f'{self.name}', file=sys.stderr)
                self.name_lost = True
                self.running = False
                break
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

        if self.name_lost:
            # What is buffered belongs to items the new owner now has, and
            # will index itself
            self.processor.discard_bulk()
        else:
            # A clean stop must not leave a batch buffered
            try:
                self.processor.flush_bulk(force=True)
            except Exception as e:
                print(f'[{self.name}] final flush failed: {e}', file=sys.stderr)
        print(f'[{self.name}] stopped. ' + ', '.join(
            f'{k}={v}' for k, v in sorted(self.stats.items())))
