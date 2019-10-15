import os.path
from _datetime import datetime
import json
from elasticsearch import Elasticsearch
from redis import Redis


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

        # Do we have a registered domain key?
        if 'registered_domain' in data['dns']['question'].keys():
            searches.append(data['dns']['question']['registered_domain'].strip().lower())

        # Do we have a etld_plus_one key?
        if 'etld_plus_one' in data['dns']['question'].keys():
            # Do we have a registered domain key?
            if 'registered_domain' in data['dns']['question'].keys():
                # Are the registered_domain and etld_plus_one values the same?
                if data['dns']['question']['registered_domain'] != data['dns']['question']['etld_plus_one']:
                    # Different values add etld_plus_one
                    searches.append(data['dns']['question']['etld_plus_one'].strip().lower())
            else:
                # We have etld_plus_one but don't have registered_domain so add etld_plus_one
                searches.append(data['dns']['question']['etld_plus_one'].strip().lower())

        # Do we have a name key?
        if 'registered_domain' not in data['dns']['question'].keys() and 'etld_plus_one' not in data['dns'][
            'question'].keys():
            # Only search `name` if we don't have registered_domain AND we don't have etld_plus_one
            if 'name' in data['dns']['question'].keys():
                searches.append(data['dns']['question']['name'].strip().lower())

        # Get the current tag
        tag = r.get('turkey-bite:current-tag')
        if tag:
            for entry in searches:
                # Build the redis key
                key = 'turkey-bite:' + tag + ':' + entry
                # Search redis for the queried domain
                result = r.get(key)
                if result:
                    result = json.loads(result)
                    # Add any unique categories to the context array
                    contexts = contexts + list(set(result['categories']) - set(contexts))

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
