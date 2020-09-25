import json
from rq import Queue
from redis import Redis


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
            # If the data in the message is encoded as bytes
            if isinstance(message['data'], bytes):
                # Start a try catch
                try:
                    # Try to convert the message data from a JSON string to a Python dict
                    data = json.loads(message['data'].decode('utf-8'))
                    # Filter superfluous packets
                    if self.filters.should_process(data):
                        # Send job to worker queue
                        if 'type' in data.keys():
                            if data['type'] == 'dns':
                                if 'resource' in data.keys():
                                    if 'network' in data.keys():
                                        if 'direction' in data['network'].keys():
                                            print('Packetbeat][DNS] Queued: ' + data['resource'] + ' - ' +
                                                  data['network']['direction'])
                                        else:
                                            print('Packetbeat][DNS] Queued: ' + data['resource'])
                                    else:
                                        print('Packetbeat][DNS] Queued: ' + data['resource'])
                            if data['type'] == 'browser.history':
                                message = '[Browserbeat][History] Queued'
                                if 'data' in data.keys():
                                    if 'event' in data['data'].keys():
                                        if 'data' in data['data']['event'].keys():
                                            if 'entry' in data['data']['event']['data'].keys():
                                                if 'url' in data['data']['event']['data']['entry'].keys():
                                                    message = ' '.join([
                                                        message,
                                                        ':',
                                                        data['data']['event']['data']['entry']['url']
                                                    ])
                                            if 'client' in data['data']['event']['data'].keys():
                                                if 'user' in data['data']['event']['data']['client'].keys():
                                                    message = ' '.join([
                                                        message,
                                                        '-',
                                                        data['data']['event']['data']['client']['user']
                                                    ])
                                                if 'Hostname' in data['data']['event']['data']['client'].keys():
                                                    if 'short' in data['data']['event']['data']['client'][
                                                        'Hostname'].keys():
                                                        message = ' '.join([
                                                            message,
                                                            '-',
                                                            data['data']['event']['data']['client']['Hostname']['short']
                                                        ])
                                print(message)

                        worker_queue.enqueue(self.processor.process_packet, data, result_ttl=600)
                    else:
                        if 'type' in data.keys():
                            if data['type'] == 'dns':
                                if 'resource' in data.keys():
                                    if 'network' in data.keys():
                                        if 'direction' in data['network'].keys():
                                            print('[Packetbeat][DNS] Dropped: ' + data['resource'] + ' - ' +
                                                  data['network']['direction'])
                                        else:
                                            print('Packetbeat][DNS] Dropped: ' + data['resource'])
                                    else:
                                        print('Packetbeat][DNS] Dropped: ' + data['resource'])
                            if data['type'] == 'browser.history':
                                message = '[Browserbeat][History] Dropped'
                                if 'data' in data.keys():
                                    if 'event' in data['data'].keys():
                                        if 'data' in data['data']['event'].keys():
                                            if 'entry' in data['data']['event']['data'].keys():
                                                if 'url' in data['data']['event']['data']['entry'].keys():
                                                    message = ' '.join([
                                                        message,
                                                        ':',
                                                        data['data']['event']['data']['entry']['url']
                                                    ])
                                            if 'client' in data['data']['event']['data'].keys():
                                                if 'user' in data['data']['event']['data']['client'].keys():
                                                    message = ' '.join([
                                                        message,
                                                        '-',
                                                        data['data']['event']['data']['client']['user']
                                                    ])
                                                if 'Hostname' in data['data']['event']['data']['client'].keys():
                                                    if 'short' in data['data']['event']['data']['client'][
                                                        'Hostname'].keys():
                                                        message = ' '.join([
                                                            message,
                                                            '-',
                                                            data['data']['event']['data']['client']['Hostname']['short']
                                                        ])
                                print(message)
                except json.JSONDecodeError:
                    # Ignore json errors
                    pass
