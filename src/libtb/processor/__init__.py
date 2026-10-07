import atexit
import ipaddress
import json
import os
import signal
import sys
import time
from libtb.tbsyslog import Syslog, Level
from libtb.util import dig
from libtb.sieve import normalize_host
from libtb.taxonomy import classify
from libtb.psl import DEFAULT_PATH as PSL_PATH, registrable_domain, using_psl
from libtb.index import DomainIndex
from libtb.evidence import (cancels, categorise, claims_for, demote_incidental,
                            describe, drop_disabled, evidence_settings,
                            matched_keys, resolve, sources_of)
from libtb.evidence import second_opinion
from libtb.evidence.resolvers import checker_for
from libtb.evidence.resolvers import settings as resolver_settings
from libtb.opensearch import ConfigurationError, check_hosts, client_kwargs, report_once
from libtb.privacy import redact
from libtb.privacy import settings as privacy_settings
from datetime import datetime, timezone
from dateutil import *
from dateutil.parser import parse
from redis import Redis
from opensearchpy import OpenSearch
from opensearchpy import helpers as opensearch_helpers
from dns import reversename, resolver, exception


# The key resolve_contexts uses to hand the ignorelist's corrections on the asked
# name to its caller. Never part of an event: both callers pop it before
# shipping, and it is underscored so an oversight is obvious in a document.
CORRECTED = '_corrected'


# One OpenSearch client per process, per host. Unlike the read-only mmap above,
# a socket is not fork-safe, so this must never be shared across a fork. Keyed on
# pid so a forked child builds its own rather than reusing a parent's connection.
_opensearch_clients = {}


# Reverse DNS answers, keyed on client address. The same handful of clients
# recur constantly, so most events can be answered without a query at all.
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

    try:
        kwargs = client_kwargs(host)
    except ValueError as e:
        # Settings were checked at start, but a CA file may have gone since.
        raise ConfigurationError(str(e)) from e
    client = OpenSearch(**kwargs)
    _opensearch_clients[key] = client
    return client


def _report_host_error(host, error, action):
    """Logs a failure to use a host: a configuration error once, anything else each time."""
    if isinstance(error, ConfigurationError):
        report_once(f"CONFIGURATION ERROR: OpenSearch at {host.get('uri')} cannot be used, "
                    f"so no event reaches it: {error}. Run `python turkeybite check` in this "
                    f"container, fix config.yaml and restart. Reported once; it applies to "
                    f"every event until fixed.")
    else:
        print(f"Error {action} to OpenSearch at {host.get('uri')}: {str(error)}",
              file=sys.stderr)


class DeliveryError(RuntimeError):
    """OpenSearch did not take an event, and it is worth trying again later."""


# Statuses that say the document itself is the problem, so sending it again
# can never succeed: it does not fit the mapping (400), conflicts with a
# version already there (409), or is too large (413). Every other refusal is
# about the cluster rather than the document and clears when the cluster
# does: a full queue (429), a write block or a missing permission (403), a
# rotated password (401), an index that may not be created (404), a node
# failing (5xx). Retrying those is the point of acknowledging after the flush.
PERMANENT_STATUSES = frozenset((400, 409, 413))

# How often opensearch-py resends the documents a bulk request had refused
# with a 429 before giving up on them, and its first and longest wait. Within
# the request, so only those documents are resent, rather than the batch being
# replayed and everything else in it indexed twice.
BULK_RETRIES = 3
BULK_INITIAL_BACKOFF = 1
BULK_MAX_BACKOFF = 8


def _statuses(error):
    """The statuses in one per-document bulk error, {operation: {status, error}}."""
    if not isinstance(error, dict):
        return []
    return [item.get('status') for item in error.values() if isinstance(item, dict)]


def retryable_rejection(error):
    """True when one per-document bulk error may succeed if sent again later."""
    return any(isinstance(status, int) and status not in PERMANENT_STATUSES
               for status in _statuses(error))


def permanent_refusal(error):
    """True when OpenSearch refused one document for good, see PERMANENT_STATUSES."""
    status = getattr(error, 'status_code', None)
    return isinstance(status, int) and status in PERMANENT_STATUSES


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


def domain_fields(host, path=PSL_PATH):
    """The registrable domain for an event, and a flag when it was guessed.

    This is the unit that means "one owner", so it is what a top-domains panel or
    a per-domain finding has to group on. co.uk and github.io yield nothing,
    because neither is a website.

    psl_fallback marks an event whose domain came from the last-two-labels rule
    because no list was loaded yet, which is true of a container that has not
    finished its first fetch. Absent means the answer is authoritative, and the
    difference matters: the fallback is the wrong answer this replaced, so an
    aggregation over a window containing it is not comparable with one that does
    not.
    """
    domain = registrable_domain(host, path)
    if not domain:
        return {}
    fields = {'registrable_domain': domain}
    if not using_psl(path):
        fields['psl_fallback'] = True
    return fields


def taxonomy_fields(contexts):
    """Facet fields for the categories on an event.

    Emitted alongside bite.contexts rather than instead of it, so nothing that
    reads the flat array breaks while the facets are proven against live data.
    """
    facets = classify(contexts)
    fields = {}
    for key in ('purpose', 'service', 'risk'):
        if facets.get(key):
            fields[key] = facets[key]
    if facets.get('risk_severity'):
        fields['risk_severity'] = facets['risk_severity']
    if facets.get('unmapped'):
        # Named on the event so a newly added list source shows up as a gap in
        # the taxonomy rather than quietly contributing to no facet at all
        fields['unmapped_contexts'] = facets['unmapped']
    return fields


def cname_chain(data):
    """CNAME targets from the answer section, in order, de-duplicated.

    Packetbeat has already parsed the answers, so this is a lifting exercise
    rather than a parsing one. The chain matters because a tracker pointed at a
    first-party subdomain of the site being visited never appears on a blocklist:
    the first-party name differs for every customer, while the target does not.
    """
    chain = []
    for record in dig(data, 'dns', 'answers') or []:
        if not isinstance(record, dict) or record.get('type') != 'CNAME':
            continue
        target = normalize_host(record.get('data'))
        if target and target not in chain:
            chain.append(target)
    return chain


def resolved_addresses(values):
    """Canonical addresses from the answer section, de-duplicated, order kept.

    Unlike a client address, nothing here is filtered for being unusable. A name
    resolving to a loopback or unspecified address is a sinkhole, which is a
    signal worth keeping rather than noise worth dropping. Values are still
    reparsed, so an ip-typed field cannot be handed something it will reject.
    """
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
        text = str(address)
        if text in seen:
            continue
        seen.add(text)
        kept.append(text)
    return kept


def short_hostname(name):
    """The first label of a hostname, or '' if there is nothing to take.

    Browserbeat reports a bare machine name and PTR returns an FQDN, so neither
    feed alone can be matched against the other. Carrying both forms lets a query
    join on the short name and still report the full one.

    The short form is not a unique key: distinct FQDNs in different subdomains
    can share a first label. It is a convenience for display and for matching
    against a source that has no domain, not an identifier, which is why the
    FQDN is kept alongside rather than replaced.
    """
    if not isinstance(name, str):
        return ''
    return name.strip().rstrip('.').split('.')[0].lower()


def short_hostnames(names):
    """Short forms for a list of hostnames, de-duplicated, order preserved."""
    shorts = []
    seen = set()
    for name in names or []:
        short = short_hostname(name)
        if not short or short in seen:
            continue
        seen.add(short)
        shorts.append(short)
    return shorts


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

    # Browserbeat reports a bare machine name with no domain, so this usually
    # equals client_hostname. It is emitted regardless so one query works across
    # both feeds, where the DNS side genuinely has a domain to strip.
    short = short_hostname(identity.get('client_hostname'))
    if short:
        identity['client_hostname_short'] = short

    addresses = routable_addresses(client.get('ip_addresses'))
    if addresses:
        identity['client_ips'] = addresses
    return identity


class Processor(object):

    # Set by the consumer, which acknowledges a batch only after it is indexed
    # and so can requeue one that is not. When OpenSearch does not take an
    # event, process_packet then raises DeliveryError rather than dropping it.
    strict_delivery = False

    def __init__(self, config, redis_conf):
        """Enrich consumer packets and ship their context to enabled outputs."""
        self.config = config
        self.redis_conf = redis_conf
        # Read once here so a mistake in the evidence settings stops the process
        # at start, and so no event pays to parse them again
        self._evidence = evidence_settings(config.get('evidence'))
        self._resolvers = resolver_settings((config.get('evidence') or {}).get('resolvers'))
        # The same for the OpenSearch hosts. This is also where a host with the
        # default admin password is refused, and where a host used without
        # verifying its certificate is reported.
        check_hosts(config.get('elastic'))
        self._privacy = privacy_settings(config.get('privacy'))

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

    def min_publishers(self):
        """Independent publishers a medium trust category needs, see libtb.evidence.

        One number, or a mapping from taxonomy branches or paths to numbers.
        """
        return self._evidence[0]

    def resolver_conf(self):
        """Public filtering resolvers as a second opinion, see libtb.evidence.resolvers.

        Off unless processor.evidence.resolvers.enable is true. Parsed once,
        with the other evidence settings, when the processor starts.
        """
        return self._resolvers

    def privacy(self):
        """What events keep of their URLs and the raw packet, see libtb.privacy.

        Trimmed URLs and the packet kept, unless processor.privacy says
        otherwise. Parsed once, when the processor starts.
        """
        return self._privacy

    def disabled_categories(self):
        """Taxonomy branches or paths switched off, see libtb.evidence.

        Absent means libtb.evidence.DEFAULT_DISABLED, the editorial branch.
        """
        return self._evidence[1]

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

    def resolve_contexts(self, searches, navigation=False):
        """Categories for a set of search terms.

        Returns (contexts, extra) where extra carries index-only fields. Three
        modes, so the index can be validated against Valkey on live traffic
        before it takes over:

          valkey   the original behaviour, one GET per synthesised key
          index    the memory-mapped index only, no Valkey round trips at all
          compare  both, with the Valkey answer authoritative and the index
                   answer recorded alongside it for measurement

        Only the index weighs its evidence. Valkey holds a bare category list
        per key, so it cannot tell one noisy list from three that agree, and in
        compare mode a disagreement is now mostly the index declining a
        category Valkey would have asserted. Switched-off categories are taken
        out of every mode's answer, Valkey's included, since keeping them in one
        mode would store the label the switch exists to keep off the event.

        `navigation` says the host is a page someone opened, which the
        incidental mark does not apply to. In index mode extra also carries
        CORRECTED, the ignorelist's corrections on the host, for the caller to
        hold over a CNAME chain and then pop before the event is shipped.
        """
        mode, path = self.index_settings()
        host = searches[0]
        disabled = self.disabled_categories()

        if mode == 'valkey':
            return drop_disabled(self.valkey_contexts(searches), disabled), {}

        try:
            index = domain_index(path)
            claims, verdict = categorise(index, host, self.min_publishers(),
                                         disabled=disabled, navigation=navigation)
        except Exception as e:
            # A missing or corrupt index must not cost the event. Fall back.
            print(f"Domain index unavailable at {path}: {e}", file=sys.stderr)
            return (drop_disabled(self.valkey_contexts(searches), disabled),
                    {'index_error': str(e)})

        # Asked only in index mode, since compare mode measures the lists
        # against Valkey and a vote from outside both would muddy that. Outside
        # the guard above, so a resolver fault is not mistaken for a broken
        # index and answered from Valkey.
        if mode == 'index':
            claims, verdict = second_opinion(host, claims, verdict, self.min_publishers(),
                                             checker_for(self.resolver_conf()), navigation)

        contexts = verdict['asserted']
        extra = {
            'sources': sources_of(claims),
            'matched_on': matched_keys(claims),
            'index_built_at': index.built_at,
        }
        if claims:
            extra['claims'] = describe(claims)
        if mode == 'index':
            # Named on the event rather than dropped, so a category the bar
            # held back can still be searched for and audited
            if verdict['candidate']:
                extra['contexts_candidate'] = verdict['candidate']
            if verdict['suppressed']:
                extra['contexts_suppressed'] = verdict['suppressed']
            if verdict['incidental']:
                extra['incidental'] = True
            if verdict['corrected']:
                extra[CORRECTED] = verdict['corrected']
            if verdict.get('resolvers'):
                # Which resolvers were asked and what each said, so one that
                # stops answering shows up in a query, as ptr_status does
                extra['resolvers'] = verdict['resolvers']
            return contexts, extra

        # compare: Valkey stays authoritative while the index is on trial
        legacy = drop_disabled(self.valkey_contexts(searches), disabled)
        extra['contexts_index'] = contexts
        extra['context_match'] = sorted(legacy) == sorted(contexts)
        return legacy, extra

    def resolve_chain(self, chain):
        """Categories found by running CNAME targets through the same lookup.

        Returns (contexts, sources, matched). Only the memory-mapped index is
        used: this multiplies lookups per event by the chain length, which is
        microseconds in memory and several network round trips each against
        Valkey. In valkey mode the chain is still recorded on the event, it is
        just not categorised, so nothing regresses for a deployment that has not
        switched over.
        """
        mode, path = self.index_settings()
        if mode == 'valkey' or not chain:
            return [], [], []
        try:
            index = domain_index(path)
        except Exception:
            # resolve_contexts already reported the same failure and recorded
            # index_error; a second complaint per event would add nothing
            return [], [], []

        # Weighed together, so two publishers agreeing about different links
        # of one chain still corroborate each other. A link marked incidental
        # demotes what the chain contributes, but leaves the name that was
        # asked for alone: that name was not marked.
        claims = []
        disabled = self.disabled_categories()
        for target in chain:
            claims.extend(claims_for(index, target, disabled=disabled))
        verdict = resolve(claims, self.min_publishers())
        return verdict['asserted'], sources_of(claims), matched_keys(claims)

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
        corrected = extra.pop(CORRECTED, ())

        # The answer section, which Packetbeat has already parsed and which bite
        # has never carried. Merged after resolve_contexts so compare mode keeps
        # measuring question-for-question agreement rather than comparing a
        # chain-enriched answer against one that never had a chain.
        chain = cname_chain(data)
        match_source = ['question'] if contexts else []
        if chain:
            extra['cname_chain'] = chain
            chain_contexts, chain_sources, chain_matched = self.resolve_chain(chain)
            if chain_contexts:
                extra['cname_matched_on'] = chain_matched
                extra['cname_contexts'] = chain_contexts
                # In compare mode Valkey stays authoritative and the chain is
                # recorded without being merged, so that mode measures the index
                # rather than an index-enriched answer. It doubles as a dry run:
                # cname_contexts shows what merging would add before it does.
                if self.index_settings()[0] == 'index':
                    # A correction on the name that was asked for holds over
                    # whatever that name happens to be hosted on, read
                    # through the taxonomy as resolve() reads it. These are
                    # the corrections themselves, not what they suppressed on
                    # the name, since the name may have had no such claim.
                    cancelled = {c for c in chain_contexts if cancels(corrected, c)}
                    added = set(chain_contexts) - cancelled
                    if cancelled:
                        extra['contexts_suppressed'] = sorted(
                            set(extra.get('contexts_suppressed') or []) | cancelled)
                    demoted = set()
                    if extra.get('incidental'):
                        # So does the incidental mark. connect.facebook.net is
                        # hosted on scontent.xx.fbcdn.net, which the lists call
                        # Facebook, and merging that back would undo the mark.
                        kept, demoted = demote_incidental(added)
                        added, demoted = set(kept), set(demoted)
                    if added:
                        match_source.append('cname')
                    contexts = sorted(set(contexts) | added)
                    held_back = sorted((set(extra.get('contexts_candidate') or []) | demoted)
                                       - added)
                    if held_back:
                        extra['contexts_candidate'] = held_back
                    else:
                        extra.pop('contexts_candidate', None)
                    if chain_sources:
                        extra['sources'] = sorted(set(extra.get('sources') or [])
                                                  | set(chain_sources))
        if match_source:
            extra['match_source'] = match_source

        # After the chain merge, so a category the chain contributed is faceted
        # like any other
        extra.update(taxonomy_fields(contexts))
        extra.update(domain_fields(searches[0]))

        resolved = resolved_addresses(dig(data, 'dns', 'resolved_ip'))
        if resolved:
            extra['resolved_ips'] = resolved

        response_code = dig(data, 'dns', 'response_code')
        if isinstance(response_code, str) and response_code.strip():
            extra['response_code'] = response_code.strip().upper()

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
                'client_hosts_short': short_hostnames(reversed_dns),
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
                                    # The registrable domain, not the last two
                                    # labels. Only used by valkey mode, since the
                                    # index walks ancestors itself, but wrong is
                                    # wrong: news.bbc.co.uk reduced to co.uk.
                                    domain = registrable_domain(host)
                                    if domain and domain != host:
                                        searches.append(domain)
                                        searches.append("*." + domain)
                                   
        # Nothing to look up means nothing worth shipping
        if not searches:
            return False

        # A history entry is a page the person opened, so the incidental mark,
        # which is about lookups made on someone else's behalf, does not apply
        contexts, extra = self.resolve_contexts(searches, navigation=True)
        extra.pop(CORRECTED, None)
        extra.update(taxonomy_fields(contexts))
        extra.update(domain_fields(searches[0]))
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

        Consumers acknowledge their processing lists only after flushing, so
        buffered events remain recoverable if the worker stops uncleanly.
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

    def flush_bulk(self, force=True, raise_on_total_failure=None):
        """Sends buffered documents as one bulk request.

        Returns the number accepted. With raise_on_total_failure, which
        defaults to strict_delivery, the caller is told with DeliveryError
        when every host refused, or when any document was refused for a
        reason that may clear, so a consumer that acknowledges after the flush
        can requeue the batch instead of losing it. Documents refused with a
        429 are first resent within the request, a few times with a backoff,
        so a briefly full queue costs those documents a wait rather than the
        batch a replay. A batch that is requeued is requeued whole, so
        documents indexed in it are indexed again: at-least-once delivery
        already allows that, and losing the rest does not. A document refused
        for good, by a mapping error say, is logged and not retried.
        """
        if raise_on_total_failure is None:
            raise_on_total_failure = self.strict_delivery
        buffer = _bulk_buffers.get(os.getpid())
        if not buffer or not buffer['docs']:
            return 0
        _, size, interval = self.bulk_settings()
        if not force and len(buffer['docs']) < size and (time.monotonic() - buffer['since']) < interval:
            return 0
        docs = buffer['docs']
        buffer['docs'] = []
        buffer['since'] = time.monotonic()
        misconfigured = None
        for host in self.config['elastic']['hosts']:
            try:
                ok, errors = opensearch_helpers.bulk(
                    opensearch_client(host), docs, raise_on_error=False, stats_only=False,
                    max_retries=BULK_RETRIES, initial_backoff=BULK_INITIAL_BACKOFF,
                    max_backoff=BULK_MAX_BACKOFF)
            except Exception as e:
                _report_host_error(host, e, 'bulk sending')
                if isinstance(e, ConfigurationError):
                    misconfigured = e
                continue
            retry = []
            for error in errors or []:
                if retryable_rejection(error):
                    retry.append(error)
                else:
                    print(f"OpenSearch rejected a document: {error}", file=sys.stderr)
            if retry and raise_on_total_failure:
                raise DeliveryError(f'OpenSearch refused {len(retry)} of {len(docs)} '
                                    f'documents for a reason that may clear: {retry[0]}')
            for error in retry:
                print(f"Dropped a document OpenSearch may take later: {error}", file=sys.stderr)
            return ok
        if raise_on_total_failure:
            raise DeliveryError(f'every OpenSearch host refused {len(docs)} documents')
        if misconfigured is not None:
            # Keep earlier documents for the next flush. ship_bite removes the
            # current failed event so retrying it does not index it twice.
            buffer['docs'] = docs + buffer['docs']
            raise misconfigured
        print(f"Dropped {len(docs)} documents: every OpenSearch host failed", file=sys.stderr)
        return 0

    def discard_bulk(self):
        """Forgets anything buffered, for a caller about to requeue the events it came from."""
        _bulk_buffers.pop(os.getpid(), None)

    def ship_bite(self, bite):
        """Sends one event to every enabled output.

        The one place an event leaves the processor, so it is also the one
        place processor.privacy is applied: OpenSearch and syslog get the same
        document, and an event type added later cannot skip it.
        """
        bite = redact(bite, self.privacy())
        if self.config['elastic']['enable']:
            bulk_enabled, size, _ = self.bulk_settings()
            if bulk_enabled:
                buffer = _bulk_buffers.setdefault(
                    os.getpid(), {'docs': [], 'since': time.monotonic()})
                if not buffer['docs'] and not self.strict_delivery:
                    # The consumer flushes, and handles signals, itself
                    _install_flush_hooks(self.flush_bulk)
                doc = {'_index': self.index_name(), '_source': bite}
                buffer['docs'].append(doc)
                try:
                    # Raises DeliveryError for the consumer when this flush fails
                    self.flush_bulk(force=False)
                except ConfigurationError:
                    # This event failed; remove its buffered copy before the
                    # caller retries it after fixing the configuration.
                    buffer['docs'] = [kept for kept in buffer['docs'] if kept is not doc]
                    raise
            else:
                index = self.index_name()
                delivered = refused = False
                misconfigured = None
                for host in self.config['elastic']['hosts']:
                    try:
                        opensearch_client(host).index(index=index, body=bite)
                        delivered = True
                        break
                    except Exception as e:
                        if permanent_refusal(e):
                            # The document is the problem, so another host of
                            # the same cluster would refuse it too
                            print(f"OpenSearch rejected a document: {e}", file=sys.stderr)
                            refused = True
                            break
                        _report_host_error(host, e, 'sending')
                        if isinstance(e, ConfigurationError):
                            misconfigured = e
                        continue
                if not (delivered or refused) and self.strict_delivery:
                    raise DeliveryError('every OpenSearch host failed to take an event')
                if not (delivered or refused) and misconfigured is not None:
                    # A host this worker cannot set up, such as a missing CA
                    # file, must surface rather than silently drop the event.
                    raise misconfigured

        if self.config['syslog']['enable']:
            try:
                log = Syslog(host=self.config['syslog']['host'], port=self.config['syslog']['port'])
                log.send(json.dumps(bite), Level.INFO)
            except Exception as e:
                print(f"Error sending to Syslog: {str(e)}", file=sys.stderr)
                # No fallback for syslog errors
