import json
from rq import Queue
from redis import Redis


class Inlet(object):

    def __init__(self, config, filters, processor):
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
            # If the data in the message is encoded as bytes
            if isinstance(message['data'], bytes):
                # Start a try catch
                try:
                    # Try to convert the message data from a JSON string to a Python dict
                    data = json.loads(message['data'].decode('utf-8'))
                    # Filter superfluous packets
                    if self.filters.should_process(data):
                        # Send job to worker queue
                        worker_queue.enqueue(self.processor.process_packet, data)
                except json.JSONDecodeError:
                    # Ignore json errors
                    pass
