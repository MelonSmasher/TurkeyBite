from _datetime import datetime
import json
from elasticsearch import Elasticsearch
from redis import Redis
from dns import reversename, resolver, exception


class Processor(object):

    def __init__(self, config, redis_conf):
        self.config = config
        self.redis_conf = redis_conf

    def process_packet(self, data):
        if data['type'] == 'dns':
            self.process_dns_packet(data)
        else:
            return False

    def process_dns_packet(self, data):
        # Related context from lists
        contexts = []
        # Domain names to search
        searches = []
        # Set the client IP
        client = None
        # The request direction
        request = None
        # Reverse DNS add
        reversed_dns = None
        rev_name = None
        # Redis DB with host lists
        r = Redis(
            host=self.redis_conf['host'],
            port=self.redis_conf['port'],
            password=self.redis_conf['password'],
            db=self.redis_conf['host_list_db']
        )

        # For inbound requests
        if data['network']['direction'] == 'inbound':
            request = 'query'
            if 'ip' in data['client'].keys():
                client = data['client']['ip']

        # For outbound requests
        if data['network']['direction'] == 'outbound':
            request = 'reply'
            if 'ip' in data['destination'].keys():
                client = data['destination']['ip']

        # Try to grab the full host entry e.g. www.google.com
        if 'resource' in data.keys():
            # Do we have a resource?
            searches.append(data['resource'].strip().lower())
        elif 'name' in data['dns']['question'].keys():
            # Do we have a name?
            searches.append(data['dns']['question']['name'].strip().lower())

        # Try to grab the domain only e.g. google.com
        if 'etld_plus_one' in data['dns']['question'].keys():
            # Do we have an etld_plus_one?
            searches.append(data['dns']['question']['etld_plus_one'].strip().lower())
        elif 'registered_domain' in data['dns']['question'].keys():
            # Do we have a registered_domain?
            searches.append(data['dns']['question']['registered_domain'].strip().lower())

        # Get the current tag
        tag = r.get('turkey-bite:current-tag')
        if tag:
            tag = tag.decode('utf-8')
            for entry in searches:
                # Build the redis key
                key = 'turkey-bite:' + tag + ':' + entry
                # Search redis for the queried domain
                result = r.get(key)
                if result:
                    result = json.loads(result.decode('utf-8'))
                    # Add any unique categories to the context array
                    contexts = contexts + list(set(result['categories']) - set(contexts))

        # Reverse client lookup
        if self.config['dns']['lookup_ips']:
            if client:
                try:
                    rev_name = reversename.from_address(client)
                    tb_resolver = resolver.Resolver(configure=False)
                    tb_resolver.nameservers = ['resolvers']
                    tb_resolver.timeout = 1
                    tb_resolver.lifetime = 1
                    reversed_dns = tb_resolver.query(rev_name, "PTR")
                    rev_name = rev_name.to_text()
                except exception.Timeout:
                    rev_name = rev_name.to_text()
                    pass

        # Build the dataset to ship
        bite = {
            '@timestamp': data['@timestamp'],
            '@metadata': {
                'beat': 'turkeybite',
                'type': '_doc',
                'version': '0.1.0'
            },
            'bite': {
                'processed': datetime.now().isoformat(),
                'client': client,
                'client_hosts': reversed_dns,
                'ptr': rev_name,
                'requested': searches,
                'contexts': contexts,
                'request': request,
                'type': 'dns'
            },
            'packet': data
        }

        # Ship the turkey bite to elastic
        self.ship_bite(bite)

    def ship_bite(self, bite):
        es = Elasticsearch(self.config['elastic']['hosts'])
        es.index(index="tb-index", doc_type='bite', body=bite)
