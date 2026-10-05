import json
import sys
from rq import Queue
from redis import Redis
from libtb.privacy import TRIMMED, redact_packet, trim_url
from libtb.util import dig

# How long RQ keeps a job that failed, with the event it was given. RQ's own
# default is a year, which would make the failed job registry a year-long store
# of whatever events failed. A day is long enough to see a failure and requeue
# it the next morning, and the event in it is already trimmed, see open().
FAILURE_TTL = 24 * 60 * 60


def describe(data, verdict, urls=TRIMMED):
    """Builds the log line for an observed packet.

    Every field is read through dig() or checked for its type first. This code
    used to reach straight into nested keys, and since the caller only catches
    JSONDecodeError, one packet with a null where a dict was expected escaped
    the listen loop and exited the process.

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


class Inlet(object):

    def __init__(self, config, filters, processor):
        """Inlet class responsible for reading the Redis channel and passing incoming messages to the Sieve."""
        # Store our config
        self.config = config
        # Initialize a filter class
        self.filters = filters
        # Initialize a processor class
        self.processor = processor

    # Open the flood gate
    def open(self):
        # Initialize the connection to the redis queue
        queue = Redis(
            host=self.config['host'],
            port=self.config['port'],
            db=self.config['db'],
            password=self.config['password']
        )
        # Create a worker queue
        worker_queue = Queue(connection=queue)
        # Subscribe to the packet channel
        stream = queue.pubsub()
        stream.subscribe(self.config['channel'])
        # For each message observed in the channel
        for message in stream.listen():
            payload = dig(message, 'data')
            # Subscription confirmations carry an int rather than a packet
            if not isinstance(payload, bytes):
                continue

            # Try to convert the message data from a JSON string to a Python dict
            try:
                data = json.loads(payload.decode('utf-8'))
            except (UnicodeDecodeError, json.JSONDecodeError):
                # Ignore json errors
                continue

            # Filter superfluous packets. A packet we cannot make sense of must
            # cost us that one packet, not the whole pipeline, so this is where
            # the net is wide. Note that enqueue() below stays outside it: a
            # dead queue should still take the process down and get it
            # restarted rather than drop traffic in silence.
            try:
                keep = self.filters.should_process(data)
                urls = self.processor.privacy().urls
                line = describe(data, 'Queued' if keep else 'Dropped', urls)
                # Trimmed before it is queued, since a job holds its event in
                # Valkey until it expires, and its description repeats it. The
                # worker reads only the host, so nothing is lost by it.
                data = redact_packet(data, urls)
            except Exception as e:
                print('Skipped an unreadable packet: ' + str(e), file=sys.stderr)
                continue

            if line:
                print(line)

            if keep:
                # Send job to worker queue
                worker_queue.enqueue(self.processor.process_packet, data, result_ttl=600,
                                     failure_ttl=FAILURE_TTL)
