import json
import os
import sys
from libtb.tbsyslog import Syslog, Level
from libtb.index import DomainIndex
from datetime import datetime, timezone
from dateutil import *
from dateutil.parser import parse
from redis import Redis
from opensearchpy import OpenSearch
from dns import reversename, resolver, exception


# One index handle per process. A read-only mmap survives fork safely, unlike a
# redis-py connection, so a forked job inherits the parent's map for free. Keyed
# on pid anyway so a child that opens its own does not hand it back to a sibling.
_index_handles = {}


def domain_index(path):
    """Returns a per-process DomainIndex, reopening it if the file was swapped."""
    key = (os.getpid(), path)
    index = _index_handles.get(key)
    if index is None:
        for stale in [k for k in _index_handles if k[0] != key[0]]:
            del _index_handles[stale]
        index = DomainIndex(path)
        _index_handles[key] = index
    else:
        index.reload_if_changed()
    return index


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

    def index_settings(self):
        """Domain index configuration, defaulted so an old config still works."""
        settings = self.config.get('domain_index') or {}
        return (
            settings.get('mode', 'valkey'),
            settings.get('path', 'lists/index/domains.tbidx'),
        )

    def valkey_contexts(self, searches):
        """The original lookup: one Valkey GET per synthesised key."""
        contexts = []
        r = Redis(
            host=self.redis_conf['host'],
            port=self.redis_conf['port'],
            password=self.redis_conf['password'],
            db=self.redis_conf['host_list_db']
        )
        tag = r.get('turkey-bite:current-tag')
        if not tag:
            return contexts
        tag = tag.decode('utf-8')
        for entry in searches:
            key = 'turkey-bite:' + tag + ':' + entry
            result = r.get(key)
            if not result:
                continue
            try:
                result = json.loads(result.decode('utf-8'))
                contexts = contexts + list(set(result['categories']) - set(contexts))
            except Exception as e:
                print(f"Malformed host list entry at {key}: {e}", file=sys.stderr)
        return contexts

    def resolve_contexts(self, searches):
        """Categories for a set of search terms.

        Returns (contexts, extra) where extra carries index-only fields. Three
        modes, so the index can be validated against Valkey on live traffic
        before it takes over:

          valkey   the original behaviour, one GET per synthesised key
          index    the memory-mapped index only, no Valkey round trips at all
          compare  both, with the Valkey answer authoritative and the index
                   answer recorded alongside it for measurement
        """
        mode, path = self.index_settings()
        host = searches[0]

        if mode == 'valkey':
            return self.valkey_contexts(searches), {}

        try:
            index = domain_index(path)
            cats, srcs, matched = index.lookup(host)
        except Exception as e:
            # A missing or corrupt index must not cost the event. Fall back.
            print(f"Domain index unavailable at {path}: {e}", file=sys.stderr)
            return self.valkey_contexts(searches), {'index_error': str(e)}

        extra = {
            'sources': srcs,
            'matched_on': matched,
            'index_built_at': index.built_at,
        }
        if mode == 'index':
            return cats, extra

        # compare: Valkey stays authoritative while the index is on trial
        legacy = self.valkey_contexts(searches)
        extra['contexts_index'] = cats
        extra['context_match'] = sorted(legacy) == sorted(cats)
        return legacy, extra

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

        # Nothing to look up means nothing worth shipping
        if not searches:
            return False

        contexts, extra = self.resolve_contexts(searches)

        # Reverse client lookup. This enriches the event with the client's
        # hostname and is never worth failing the event over, so every failure
        # mode has to land somewhere. The status goes in the document instead
        # of the log, so a resolver that stops working shows up in a query
        # rather than in a wall of per-event log lines.
        ptr_status = 'skipped'
        if self.config['dns']['lookup_ips']:
            if client:
                ptr_status = 'ok'
                try:
                    rev_name = reversename.from_address(client)
                    tb_resolver = resolver.Resolver(configure=False)
                    tb_resolver.nameservers = self.config['dns']['resolvers']
                    tb_resolver.timeout = 1
                    tb_resolver.lifetime = 1
                    for a in tb_resolver.resolve(rev_name, 'PTR'):
                        reversed_dns.append(str(a).rstrip('.'))
                    rev_name = rev_name.to_text()
                except resolver.NXDOMAIN:
                    # The client has no reverse record, which is normal
                    ptr_status = 'nxdomain'
                    rev_name = rev_name.to_text() if rev_name else ''
                except exception.DNSException as e:
                    # Everything dnspython raises subclasses DNSException,
                    # including NoNameservers, which is what a resolver
                    # answering SERVFAIL produces. Catching only Timeout and
                    # NXDOMAIN here discarded every DNS event for 15 months.
                    ptr_status = type(e).__name__
                    rev_name = rev_name.to_text() if rev_name else ''
                except ValueError:
                    # from_address rejects an address it cannot parse
                    ptr_status = 'bad_client_address'
                    rev_name = ''

        # Build the dataset to ship
        bite = {
            '@timestamp': data['@timestamp'],
            '@metadata': {
                'beat': 'turkeybite',
                'type': '_doc',
                'version': '0.1.0'
            },
            'bite': {
                'processed': datetime.now(timezone.utc).isoformat(),
                'client': client,
                'client_hosts': reversed_dns,
                'ptr': rev_name,
                'ptr_status': ptr_status,
                'requested': [searches[0]],
                'searches': searches,
                'contexts': contexts,
                'request': request,
                'type': 'dns',
                **extra
            },
            'packet': data
        }

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
                                host = data['data']['event']['data']['entry']['url_data']['Host']
                                host = host.strip().lower() if isinstance(host, str) else ''
                                if ':' in host:
                                    # Deal with hosts that have a port in the string
                                    host = host.split(':')[0]
                                if host:
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
                                   
        # Nothing to look up means nothing worth shipping
        if not searches:
            return False

        contexts, extra = self.resolve_contexts(searches)

        bite = {
            '@timestamp': timestamp,
            '@metadata': {
                'beat': 'turkeybite',
                'type': '_doc',
                'version': '0.1.0'
            },
            'bite': {
                'processed': datetime.now(timezone.utc).isoformat(),
                'event_time_utc': timestamp,
                'event_time_local': localtime,
                'url': data['data']['event']['data']['entry']['url'],
                'requested': [searches[0]],
                'searches': searches,
                'contexts': contexts,
                'request': request,
                'type': 'browser.history',
                **extra
            },
            'packet': data
        }
        self.ship_bite(bite)

    def ship_bite(self, bite):
        if self.config['elastic']['enable']:
            # Deliberately local time, not UTC. The index name is the ingestion
            # day as the operator experiences it, which is what the retention
            # policy is reasoning about. Only bite.processed needs to be UTC,
            # because OpenSearch parses that one as a date.
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
