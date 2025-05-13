import json
import sys
from libtb.tbsyslog import Syslog, Level
from _datetime import datetime
from dateutil import *
from dateutil.parser import parse
from redis import Redis
from opensearchpy import OpenSearch
from dns import reversename, resolver, exception


class Processor(object):

    def __init__(self, config, redis_conf):
        """Inlet class responsible for taking queued jobs from the Redis queue and processing their context."""
        self.config = config
        self.redis_conf = redis_conf

    def process_packet(self, data):
        if data['type'] == 'dns':
            self.process_dns_packet(data)
        if data['type'] == 'browser.history':
            self.process_browser_history(data)
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
        reversed_dns = []
        rev_name = None
        # Redis DB with host lists
        r = Redis(
            host=self.redis_conf['host'],
            port=self.redis_conf['port'],
            password=self.redis_conf['password'],
            db=self.redis_conf['host_list_db']
        )

        # For inbound requests
        if data['network']['direction'] in ['inbound', 'ingress']:
            request = 'query'
            if 'ip' in data['client'].keys():
                client = data['client']['ip']

        # For outbound requests
        if data['network']['direction'] in ['outbound', 'egress']:
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
            etld_plus_one = data['dns']['question']['etld_plus_one'].strip().lower()
            # add domain.tld to searches
            searches.append(etld_plus_one)
            # add *.domain.tld to searches
            searches.append("*." + etld_plus_one)
            # grab only tld
            tld = etld_plus_one.split('.')[-1]
            # add *.tld to searches
            searches.append("*." + tld)
        elif 'registered_domain' in data['dns']['question'].keys():
            # Do we have a registered_domain?
            registered_domain = data['dns']['question']['registered_domain'].strip().lower()
            searches.append(registered_domain)
            # add *.registered_domain to searches
            searches.append("*." + registered_domain)
            # grab only tld
            tld = registered_domain.split('.')[-1]
            # add *.tld to searches
            searches.append("*." + tld)

        # Get the current tag
        print(f"DEBUG: searches={searches}")  # Print what domains we're looking up
        tag = r.get('turkey-bite:current-tag')
        print(f"DEBUG: Redis tag key='turkey-bite:current-tag', result={tag}")  # Debug the tag
        if tag:
            tag = tag.decode('utf-8')
            print(f"DEBUG: Decoded tag={tag}")
            for entry in searches:
                # Build the redis key
                key = 'turkey-bite:' + tag + ':' + entry
                print(f"DEBUG: Looking for Redis key={key}")
                # Search redis for the queried domain
                result = r.get(key)
                print(f"DEBUG: Redis lookup result for {key}={result is not None}")
                if result:
                    try:
                        result = json.loads(result.decode('utf-8'))
                        print(f"DEBUG: JSON parsed, 'categories' in result={'categories' in result}, categories={result.get('categories', [])}")
                        # Add any unique categories to the context array
                        contexts = contexts + list(set(result['categories']) - set(contexts))
                        print(f"DEBUG: Updated contexts={contexts}")
                    except Exception as e:
                        print(f"DEBUG: Error parsing JSON: {str(e)}")

        # Reverse client lookup
        if self.config['dns']['lookup_ips']:
            if client:
                try:
                    rev_name = reversename.from_address(client)
                    tb_resolver = resolver.Resolver(configure=False)
                    tb_resolver.nameservers = self.config['dns']['resolvers']
                    tb_resolver.timeout = 1
                    tb_resolver.lifetime = 1
                    for a in tb_resolver.query(rev_name, "PTR"):
                        reversed_dns.append(str(a).rstrip('.'))
                    rev_name = rev_name.to_text()
                except exception.Timeout:
                    rev_name = rev_name.to_text()
                    pass
                except resolver.NXDOMAIN:
                    rev_name = ''
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
                'requested': [searches[0]],
                'searches': searches,
                'contexts': contexts,
                'request': request,
                'type': 'dns'
            },
            'packet': data
        }

        # Print final contexts before shipping
        print(f"DEBUG: Final contexts for {searches} = {contexts}")
        
        # Ship the turkey bite to elastic
        self.ship_bite(bite)

    def process_browser_history(self, data):
        # Related context from lists
        contexts = []
        # Domain names to search
        searches = []
        # The request direction
        request = None
        # The request timestamp
        timestamp = data['data']['@timestamp']
        localtime = data['data']['@timestamp']
        # Redis DB with host lists
        r = Redis(
            host=self.redis_conf['host'],
            port=self.redis_conf['port'],
            password=self.redis_conf['password'],
            db=self.redis_conf['host_list_db']
        )

        if 'data' in data.keys():

            if '@processed' in data['data'].keys():
                if data['data']['event']['data']['client']['browser'] == 'safari':
                    # safari stores data in local time not UTC we need to convert
                    # From the processed time we can tell the local time zone of the client
                    # '%Y-%m-%dT%H:%M:%S.%f%z'
                    processed = parse(data['data']['@processed'])
                    # Create a datetime object from the local time
                    # '%Y-%m-%dT%H:%M:%SZ'
                    local = parse(data['data']['@timestamp'])
                    # Set the timezone on the localtime object from the processed time
                    local = local.replace(tzinfo=tz.gettz(str(processed.tzinfo)))
                    localtime = local.strftime('%Y-%m-%dT%H:%M:%S%Z')
                    # Convert to UTC
                    utc_time = local.astimezone(tz.tzutc())
                    # Set the UTC time to match other browsers
                    timestamp = utc_time.strftime('%Y-%m-%dT%H:%M:%SZ')
                    data['data']['@timestamp'] = timestamp
                elif data['data']['event']['data']['client']['browser'] in ['chrome', 'firefox']:
                    # Chrome & Firefox do not provide the local time
                    # From the processed time we can tell the local time zone of the client
                    # '%Y-%m-%dT%H:%M:%S.%f%z'
                    processed = parse(data['data']['@processed'])
                    # Parse the UTC time
                    # '%Y-%m-%dT%H:%M:%SZ'
                    utc = parse(data['data']['@timestamp'])
                    utc.replace(tzinfo=tz.tzutc())
                    # Convert the UTC time to the local timezone found in @processed
                    local = utc.astimezone(tz.gettz(str(processed.tzinfo)))
                    localtime = local.strftime('%Y-%m-%dT%H:%M:%S%Z')

            if 'event' in data['data'].keys():
                if 'data' in data['data']['event'].keys():
                    if 'entry' in data['data']['event']['data'].keys():
                        if 'url_data' in data['data']['event']['data']['entry'].keys():
                            if 'Scheme' in data['data']['event']['data']['entry']['url_data'].keys():
                                request = data['data']['event']['data']['entry']['url_data']['Scheme']
                            if 'Host' in data['data']['event']['data']['entry']['url_data'].keys():
                                host = data['data']['event']['data']['entry']['url_data']['Host'].strip().lower()
                                if host:
                                    if ':' in host:
                                        # Deal with hosts that have a port in the string
                                        host = host.split(':')[0]
                                searches.append(host)
                                searches.append("*." + host)
                                searches.append("*." + host.split('.')[-1])
                                domain = host
                                if '.' in domain:
                                    parts = domain.split('.')
                                    domain = '.'.join([parts[len(parts) - 2], parts[len(parts) - 1]])
                                if domain != host:
                                    searches.append(domain)
                                    searches.append("*." + domain)
                                   
        # Get the current tag
        print(f"DEBUG: searches={searches}")  # Print what domains we're looking up
        tag = r.get('turkey-bite:current-tag')
        print(f"DEBUG: Redis tag key='turkey-bite:current-tag', result={tag}")  # Debug the tag
        if tag:
            tag = tag.decode('utf-8')
            print(f"DEBUG: Decoded tag={tag}")
            for entry in searches:
                # Build the redis key
                key = 'turkey-bite:' + tag + ':' + entry
                print(f"DEBUG: Looking for Redis key={key}")
                # Search redis for the queried domain
                result = r.get(key)
                print(f"DEBUG: Redis lookup result for {key}={result is not None}")
                if result:
                    try:
                        result = json.loads(result.decode('utf-8'))
                        print(f"DEBUG: JSON parsed, 'categories' in result={'categories' in result}, categories={result.get('categories', [])}")
                        # Add any unique categories to the context array
                        contexts = contexts + list(set(result['categories']) - set(contexts))
                        print(f"DEBUG: Updated contexts={contexts}")
                    except Exception as e:
                        print(f"DEBUG: Error parsing JSON: {str(e)}")

        bite = {
            '@timestamp': timestamp,
            '@metadata': {
                'beat': 'turkeybite',
                'type': '_doc',
                'version': '0.1.0'
            },
            'bite': {
                'processed': datetime.now().isoformat(),
                'event_time_utc': timestamp,
                'event_time_local': localtime,
                'url': data['data']['event']['data']['entry']['url'],
                'requested': [searches[0]],
                'searches': searches,
                'contexts': contexts,
                'request': request,
                'type': 'browser.history'
            },
            'packet': data
        }
        self.ship_bite(bite)

    def ship_bite(self, bite):
        if self.config['elastic']['enable']:
            index = ''.join([self.config['elastic']['index_prefix'], '-', datetime.now().strftime("%Y-%m-%d")])
            for host in self.config['elastic']['hosts']:
                try:
                    # Configure the OpenSearch client based on URI and auth
                    if host['username'] and host['password']:
                        # URI parsing to get host and port
                        from urllib.parse import urlparse
                        parsed_url = urlparse(host['uri'])
                        use_ssl = parsed_url.scheme == 'https'
                        host_name = parsed_url.hostname
                        port = parsed_url.port or (443 if use_ssl else 80)
                        
                        # Create OpenSearch client
                        os_client = OpenSearch(
                            hosts=[{'host': host_name, 'port': port}],
                            http_auth=(host['username'], host['password']),
                            use_ssl=use_ssl,
                            verify_certs=False,
                            ssl_show_warn=False,
                            request_timeout=30,  # Add timeout
                            retry_on_timeout=True  # Enable retries
                        )
                    else:
                        # URI parsing to get host and port
                        from urllib.parse import urlparse
                        parsed_url = urlparse(host['uri'])
                        use_ssl = parsed_url.scheme == 'https'
                        host_name = parsed_url.hostname
                        port = parsed_url.port or (443 if use_ssl else 80)
                        
                        # Create OpenSearch client
                        os_client = OpenSearch(
                            hosts=[{'host': host_name, 'port': port}],
                            use_ssl=use_ssl,
                            verify_certs=False,
                            ssl_show_warn=False,
                            request_timeout=30,  # Add timeout
                            retry_on_timeout=True  # Enable retries
                        )
                    
                    # Attempt to index the document
                    os_client.index(index=index, body=bite)
                    print(f"Successfully sent data to OpenSearch at {host['uri']}")
                    # If successful, break the loop
                    break
                except Exception as e:
                    # Log the error to stderr but continue processing
                    print(f"Error sending to OpenSearch at {host['uri']}: {str(e)}", file=sys.stderr)
                    # Continue to the next host if available, or fall back to syslog
                    continue

        if self.config['syslog']['enable']:
            try:
                log = Syslog(host=self.config['syslog']['host'], port=self.config['syslog']['port'])
                log.send(json.dumps(bite), Level.INFO)
            except Exception as e:
                print(f"Error sending to Syslog: {str(e)}", file=sys.stderr)
                # No fallback for syslog errors
