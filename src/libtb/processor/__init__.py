import atexit
import ipaddress
import json
import os
import signal
import sys
import time
from libtb.tbsyslog import Syslog, Level
from libtb.util import dig
from libtb.index import DomainIndex
from datetime import datetime, timezone
from dateutil import *
from dateutil.parser import parse
from redis import Redis
from opensearchpy import OpenSearch
from opensearchpy import helpers as opensearch_helpers
from dns import reversename, resolver, exception
from urllib.parse import urlparse


# One OpenSearch client per process, per host. Unlike the read-only mmap above,
# a socket is not fork-safe, so this must never be shared across a fork. Keyed on
# pid so a forked child builds its own rather than reusing a parent's connection.
#
# Under the default RQ worker, which forks a job per event, this saves nothing:
# the child is discarded after one document. It is worth having anyway because
# ship_bite previously built a client and completed a TLS handshake per document,
# and because with rq.SimpleWorker the process persists and the connection is
# genuinely reused.
_opensearch_clients = {}


# Reverse DNS answers, keyed on client address. The same handful of clients
# recur constantly, so most events can be answered without a query at all.
#
# Worth having only when the process outlives a job. Under the consume path or
# rq.SimpleWorker it does; under the forking rq.Worker each child is discarded
# after one event and this stays empty, which is harmless. Unlike the OpenSearch
# socket above this needs no pid key: a child inherits a copy of the dict and
# can read it without corrupting the parent's.
_ptr_cache = {}

# Resolver objects hold configuration, not a socket, so one per nameserver set
# is enough and it is safe across a fork.
_ptr_resolvers = {}

# Outcomes stable enough to remember. Transient failures are deliberately absent:
# caching NoNameservers or a Timeout would pin a resolver blip for the whole TTL
# and hide the recovery, and an unnoticed reverse DNS failure is exactly what
# went undiagnosed for 15 months.
PTR_CACHEABLE = frozenset(('ok', 'nxdomain', 'bad_client_address'))

# Each consumer process keeps its own cache, and there are dozens of them, so a
# given process only ever sees a fraction of the traffic. A short TTL expires an
# address before that process happens to see it again, which is why the first
# measured hit rate at 300s was far below the repeat ratio in the traffic itself.
# Fifteen minutes is long enough to accumulate a useful share of the client
# population and short enough that a reassigned address is not misattributed for
# long. Raise it for a higher hit rate, at the cost of staleness.
PTR_CACHE_TTL = 900
PTR_CACHE_MAX = 20000


def ptr_resolver(nameservers, timeout=1):
    key = (tuple(nameservers), timeout)
    found = _ptr_resolvers.get(key)
    if found is None:
        found = resolver.Resolver(configure=False)
        found.nameservers = list(nameservers)
        found.timeout = timeout
        found.lifetime = timeout
        _ptr_resolvers[key] = found
    return found


def _ptr_remember(client, entry, expires, max_entries):
    # Reinserting rather than assigning keeps dict order meaningful, so the
    # eviction below drops the least recently refreshed entry
    _ptr_cache.pop(client, None)
    _ptr_cache[client] = (expires, entry)
    while len(_ptr_cache) > max_entries:
        _ptr_cache.pop(next(iter(_ptr_cache)))


def ptr_lookup(client, nameservers, ttl=PTR_CACHE_TTL, max_entries=PTR_CACHE_MAX,
               timeout=1, now=None):
    """Resolves a client address to hostnames. Returns (hosts, ptr_name, status).

    Never raises. Every failure mode lands in `status`, which goes in the
    document rather than the log so a resolver that stops working shows up in a
    query instead of a wall of per-event lines.
    """
    if not isinstance(client, str):
        # A malformed packet can put anything in client.ip. A dict or a list is
        # truthy, so the guard upstream lets it through, and an unhashable value
        # would fail the cache lookup below before any DNS handler could catch it.
        return [], '', 'bad_client_address'

    now = time.monotonic() if now is None else now
    hit = _ptr_cache.get(client)
    if hit is not None:
        expires, entry = hit
        if expires > now:
            hosts, name, status = entry
            # A fresh list every time: the caller puts this in the document and
            # a shared list would let one event's mutation poison the cache
            return list(hosts), name, status
        _ptr_cache.pop(client, None)

    hosts = []
    name = ''
    try:
        reverse = reversename.from_address(client)
        # Recorded before the query so a failure still reports what was asked
        name = reverse.to_text().lower()
        for record in ptr_resolver(nameservers, timeout).resolve(reverse, 'PTR'):
            # Lower-cased because DNS names are case-insensitive by definition,
            # so the case carries no meaning, while the field is a case-sensitive
            # keyword. Resolvers here return the same name in several cases, and
            # without folding one machine counts as two in any aggregation and
            # produces two rows in the identity table these feed.
            hosts.append(str(record).rstrip('.').lower())
        status = 'ok'
    except resolver.NXDOMAIN:
        # The client has no reverse record, which is normal
        status = 'nxdomain'
    except exception.SyntaxError:
        # from_address rejects an address it cannot parse, and dnspython raises
        # its own SyntaxError rather than ValueError. That is a DNSException, so
        # this has to come before the handler below or a permanently bad address
        # is reported as a resolver fault and re-queried on every single event.
        status = 'bad_client_address'
    except exception.DNSException as e:
        # Everything else dnspython raises subclasses DNSException, including
        # NoNameservers, which is what a resolver answering SERVFAIL produces
        status = type(e).__name__
    except ValueError:
        # Kept for a dnspython that reports a bad address this way instead
        status = 'bad_client_address'

    if status in PTR_CACHEABLE:
        _ptr_remember(client, (tuple(hosts), name, status), now + ttl, max_entries)
    return hosts, name, status


def opensearch_client(host):
    # Username is part of the key so rotated credentials are not served by a
    # client still holding the old ones
    key = (os.getpid(), host['uri'], host.get('username'))
    # Drop anything belonging to another pid first. After a fork the child holds
    # the parent's client object and its socket fd; using it would interleave two
    # processes on one connection, and keeping it just leaks the fd.
    for stale in [k for k in _opensearch_clients if k[0] != key[0]]:
        del _opensearch_clients[stale]
    client = _opensearch_clients.get(key)
    if client is not None:
        return client

    parsed = urlparse(host['uri'])
    use_ssl = parsed.scheme == 'https'
    kwargs = {
        'hosts': [{'host': parsed.hostname, 'port': parsed.port or (443 if use_ssl else 80)}],
        'use_ssl': use_ssl,
        'verify_certs': False,
        'ssl_show_warn': False,
        'request_timeout': 30,
        'retry_on_timeout': True,
    }
    if host.get('username') and host.get('password'):
        kwargs['http_auth'] = (host['username'], host['password'])
    client = OpenSearch(**kwargs)
    _opensearch_clients[key] = client
    return client


# Documents waiting to be flushed as one bulk request, keyed by pid for the same
# reason. Only useful when the worker process outlives a single job.
_bulk_buffers = {}
_flush_hooks_installed = set()


def _install_flush_hooks(flush):
    """Flush on exit and on SIGTERM, since supervisor stops workers with TERM."""
    pid = os.getpid()
    if pid in _flush_hooks_installed:
        return
    _flush_hooks_installed.add(pid)
    atexit.register(flush)

    def on_term(signum, frame):
        flush()
        raise SystemExit(0)

    try:
        signal.signal(signal.SIGTERM, on_term)
    except (ValueError, OSError):
        # Not the main thread, or signals unavailable. atexit still applies.
        pass


# Index handles, keyed on path alone and deliberately not on pid. A read-only
# mmap is fork-safe, so a child inherits the parent's map and reuses it for free
# rather than paying to close and reopen. This is the opposite of the right
# answer for the OpenSearch client above, where the object owns a socket.
_index_handles = {}


def domain_index(path):
    """Returns the process's DomainIndex, reopening it if the file was swapped."""
    index = _index_handles.get(path)
    if index is None:
        index = DomainIndex(path)
        _index_handles[path] = index
    else:
        index.reload_if_changed()
    return index


# Where each flat bite field comes from in the raw browser packet. Browserbeat
# reports Hostname as a nested object with identical hostname and short values,
# so only the first is lifted.
BROWSER_IDENTITY_FIELDS = (
    ('client_hostname', ('Hostname', 'hostname')),
    ('client_user', ('user',)),
    ('client_platform', ('platform',)),
    ('client_browser', ('browser',)),
)


def routable_addresses(values):
    """Keeps the client addresses that can actually identify a machine.

    Browserbeat reports every interface. On Windows most of them are 169.254
    link-local autoconfiguration addresses, which identify nothing and can never
    match a DNS client, so they are the bulk of what arrives and none of it is
    usable.

    Private ranges are kept deliberately: those are the campus addresses DNS
    events carry, so they are the whole point. Only addresses that cannot be a
    client are dropped.

    Order is preserved and duplicates collapse, so the primary interface stays
    first.
    """
    # JSON puts whatever the beat sent here. A bare int is not iterable at all,
    # and a string would iterate character by character, so the type is checked
    # rather than assumed. Matches how the sieve reads the same field.
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []

    kept = []
    seen = set()
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            continue
        if (address.is_link_local or address.is_loopback or address.is_multicast
                or address.is_unspecified or address.is_reserved):
            continue
        text = str(address)
        if text in seen:
            continue
        seen.add(text)
        kept.append(text)
    return kept


def client_identity(event_data):
    """Lifts the browser client identity into flat bite fields.

    The raw packet carries hostname, user, platform, browser and every interface
    address, and none of it reached bite, where the rest of the document lives. A
    browser event could say what was visited but not by whom, and a DNS event has
    the opposite problem: an address with no identity.

    Names are lower-cased. These are identity keys on a case-sensitive keyword
    field, so one machine reporting a different case would become two machines to
    every aggregation and to the identity table this feeds. Live events already
    mix cases across hosts, and nothing is lost by folding, because the packet
    retains the value exactly as reported.

    Fields with no value are left out rather than set null, so a query can tell
    absent from empty.
    """
    client = dig(event_data, 'client')
    if not isinstance(client, dict):
        return {}

    identity = {}
    for field, path in BROWSER_IDENTITY_FIELDS:
        value = dig(client, *path)
        if isinstance(value, str) and value.strip():
            identity[field] = value.strip().lower()

    addresses = routable_addresses(client.get('ip_addresses'))
    if addresses:
        identity['client_ips'] = addresses
    return identity


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
        if self.config['dns']['lookup_ips'] and client:
            cache = (self.config['dns'] or {}).get('cache') or {}
            reversed_dns, rev_name, ptr_status = ptr_lookup(
                client,
                self.config['dns']['resolvers'],
                ttl=int(cache.get('ttl_sec', PTR_CACHE_TTL)),
                max_entries=int(cache.get('max_entries', PTR_CACHE_MAX)),
            )

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
                # dig rather than chained subscripts: the sieve guarantees
                # event.data is a dict but not that a client is attached, and a
                # KeyError here would lose the event
                browser = dig(data, 'data', 'event', 'data', 'client', 'browser')
                if browser == 'safari':
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
                elif browser in ['chrome', 'firefox']:
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
        identity = client_identity(dig(data, 'data', 'event', 'data'))

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
                **identity,
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

    def bulk_settings(self):
        """Bulk buffering settings. Off by default, deliberately.

        Batching only helps when a worker process handles more than one job,
        which needs rq.SimpleWorker. It also introduces a loss window: RQ marks
        a job finished when process_packet returns, so anything still sitting in
        the buffer when a worker dies uncleanly is gone with no record. Flush
        hooks cover a clean stop and a SIGTERM from supervisor, not a SIGKILL.

        That window closes properly with Redis Streams, where the ack happens
        after the flush. Until then this stays opt-in.
        """
        settings = (self.config['elastic'].get('bulk') or {})
        return (
            bool(settings.get('enable', False)),
            int(settings.get('size', 500)),
            float(settings.get('interval_sec', 2)),
        )

    def index_name(self):
        # Deliberately local time, not UTC. The index name is the ingestion
        # day as the operator experiences it, which is what the retention
        # policy is reasoning about. Only bite.processed needs to be UTC,
        # because OpenSearch parses that one as a date.
        return ''.join([self.config['elastic']['index_prefix'], '-',
                        datetime.now().strftime("%Y-%m-%d")])

    def flush_bulk(self, force=True, raise_on_total_failure=False):
        """Sends buffered documents as one bulk request.

        Returns the number accepted. With raise_on_total_failure the caller is
        told when every host refused, so a consumer that acknowledges after the
        flush can requeue instead of losing the batch. The RQ path leaves it off
        because it has nothing to requeue to.
        """
        buffer = _bulk_buffers.get(os.getpid())
        if not buffer or not buffer['docs']:
            return 0
        _, size, interval = self.bulk_settings()
        if not force and len(buffer['docs']) < size and (time.monotonic() - buffer['since']) < interval:
            return 0
        docs = buffer['docs']
        buffer['docs'] = []
        buffer['since'] = time.monotonic()
        for host in self.config['elastic']['hosts']:
            try:
                ok, errors = opensearch_helpers.bulk(
                    opensearch_client(host), docs, raise_on_error=False, stats_only=False)
                for error in errors or []:
                    print(f"OpenSearch rejected a document: {error}", file=sys.stderr)
                return ok
            except Exception as e:
                print(f"Error bulk sending to OpenSearch at {host['uri']}: {str(e)}",
                      file=sys.stderr)
                continue
        if raise_on_total_failure:
            raise RuntimeError(f'every OpenSearch host refused {len(docs)} documents')
        print(f"Dropped {len(docs)} documents: every OpenSearch host failed", file=sys.stderr)
        return 0

    def ship_bite(self, bite):
        if self.config['elastic']['enable']:
            bulk_enabled, size, _ = self.bulk_settings()
            if bulk_enabled:
                buffer = _bulk_buffers.setdefault(
                    os.getpid(), {'docs': [], 'since': time.monotonic()})
                if not buffer['docs']:
                    _install_flush_hooks(self.flush_bulk)
                buffer['docs'].append({'_index': self.index_name(), '_source': bite})
                self.flush_bulk(force=False)
            else:
                index = self.index_name()
                for host in self.config['elastic']['hosts']:
                    try:
                        opensearch_client(host).index(index=index, body=bite)
                        break
                    except Exception as e:
                        print(f"Error sending to OpenSearch at {host['uri']}: {str(e)}",
                              file=sys.stderr)
                        continue

        if self.config['syslog']['enable']:
            try:
                log = Syslog(host=self.config['syslog']['host'], port=self.config['syslog']['port'])
                log.send(json.dumps(bite), Level.INFO)
            except Exception as e:
                print(f"Error sending to Syslog: {str(e)}", file=sys.stderr)
                # No fallback for syslog errors
