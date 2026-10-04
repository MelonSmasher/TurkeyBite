"""Public filtering resolvers as a second opinion on what one list claims.

The threat lists barely overlap, so most real threats stop at a candidate: one
list names them and no second publisher agrees. Quad9 and Cloudflare run
filtering resolvers on commercial threat intelligence, maintained daily and
separate from the community lists. Asking whether they block a host one list
already flags gives that host a second, independent opinion.

What each resolver says when it blocks was measured, not assumed:

    Quad9 9.9.9.9          NXDOMAIN, with Extended DNS Error 17 (Filtered),
                           no recursion-available flag and no SOA. A name that
                           genuinely does not exist comes back NXDOMAIN with
                           an SOA and the flag set, and no EDE.
    Cloudflare 1.1.1.2     0.0.0.0 or ::, with EDE 16 (Censored), for malware
                           and phishing
    Cloudflare 1.1.1.3     the same with EDE 16 for those, and with EDE 17
                           (Filtered) for adult content

Over 873 hosts the EDE was present on every block and absent on every genuine
answer, so it is what decides. Quad9 blocks a name even when it does not exist,
and so does Cloudflare, so a dead phishing domain still gets its vote. Each provider also has a comparison to fall back
on if a block ever arrives without one: Quad9's unfiltered 9.9.9.10, Cloudflare's
1.1.1.1, and for adult content 1.1.1.2, since 1.1.1.3 blocks malware too and only
a block 1.1.1.2 does not share is about adult content.

The resolvers corroborate and never assert. One is asked only when a medium
trust list already claims the category it would vote for and that category is
still a candidate, so its vote can only complete a pair a list has started. A
vote is a claim like any other, from a medium trust source whose publisher is
the resolver's operator, and the verdict is weighed again under the normal
rules. Quad9 and Cloudflare vote the generic `malicious`, and Cloudflare's
adult filter votes `porn`: a resolver's block says the host is bad, not
whether it phishes or serves malware, so a specific category like `phishing`
still needs two lists.

Only DNS lookups are checked, not browser history, and only the name asked
for, not its CNAME targets. A resolver
answers for the name as a whole, chain included, and the targets are mostly
CDN hosts shared by thousands of sites, where a block would say little about
this lookup and a query per link would multiply the traffic. The one chain
seen in testing went the other way: Cloudflare blocked www.isuzi.com while
leaving its target, overdue.aliyun.com, alone.

Only the name is sent, never the client's address, and nothing is sent unless
an operator turns this on.
"""

import ipaddress
import threading
import time
from collections import namedtuple

from libtb.evidence import is_risk, resolve, statements
from libtb.index import Source

QUAD9 = 'quad9'
CLOUDFLARE_SECURITY = 'cloudflare-security'
CLOUDFLARE_FAMILY = 'cloudflare-family'

# What a provider is asked about, and what its block is a vote for. The order
# is the order they are asked in.
Provider = namedtuple('Provider', 'name publisher vote')
PROVIDERS = (
    Provider(QUAD9, 'quad9', 'malicious'),
    Provider(CLOUDFLARE_SECURITY, 'cloudflare', 'malicious'),
    Provider(CLOUDFLARE_FAMILY, 'cloudflare', 'porn'),
)

# The source a vote is recorded under. Medium, like a broad list: it counts
# only alongside another independent publisher. Both Cloudflare resolvers are
# one publisher, so they never corroborate each other.
SOURCES = {provider.name: Source(provider.name, provider.publisher, 'medium', False, ())
           for provider in PROVIDERS}

DEFAULT_ADDRESSES = {
    'quad9': '9.9.9.9',
    'quad9_unfiltered': '9.9.9.10',
    'cloudflare_security': '1.1.1.2',
    'cloudflare_family': '1.1.1.3',
    'cloudflare_unfiltered': '1.1.1.1',
}

# Extended DNS Error codes that mean the resolver refused the name on purpose
EDE_BLOCKED, EDE_CENSORED, EDE_FILTERED = 15, 16, 17
BLOCK_CODES = frozenset((EDE_BLOCKED, EDE_CENSORED, EDE_FILTERED))

# Outcomes worth remembering. A timeout, a SERVFAIL or a network error is the
# resolver or the path to it having a bad moment, and remembering one would
# hide the recovery for the whole TTL, as with the reverse DNS cache.
BLOCKED, CLEAR, NXDOMAIN, SECURITY = 'blocked', 'clear', 'nxdomain', 'security'
SETTLED = frozenset((BLOCKED, CLEAR, NXDOMAIN, SECURITY))

DEFAULT_TIMEOUT = 0.5
DEFAULT_TTL = 3600
DEFAULT_MAX_ENTRIES = 50000

# Queries per second `turkeybite audit --resolvers` sends at most. A worker
# asks about one host per event; the audit asks about thousands in a row.
AUDIT_RATE = 20

Settings = namedtuple('Settings', 'enable timeout ttl max_entries addresses')

# The shape of the answer the checker needs, so tests can supply one directly
Answer = namedtuple('Answer', 'rcode ede zero addresses recursion soa')


def _number(value, name, kind=float, low=0, high=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f'resolvers {name} must be a number, not {value!r}')
    if kind is int and value != int(value):
        raise ValueError(f'resolvers {name} must be a whole number, not {value!r}')
    value = kind(value)
    if value <= low or (high is not None and value > high):
        bound = f' and at most {high}' if high is not None else ''
        raise ValueError(f'resolvers {name} must be more than {low}{bound}, not {value!r}')
    return value


def _only(mapping, allowed, where):
    if not isinstance(mapping, dict):
        raise ValueError(f'{where} must be a mapping, not {mapping!r}')
    unknown = sorted(set(mapping) - set(allowed))
    if unknown:
        raise ValueError(f'{where} has unknown keys {", ".join(map(str, unknown))}; '
                         f'it takes {", ".join(sorted(allowed))}')


def settings(value=None):
    """processor.evidence.resolvers as Settings, validated.

    Absent means off. Raises ValueError for an unknown key or a bad value, so
    a mistake stops the worker at start rather than quietly sending nothing,
    or sending names somewhere unintended.
    """
    value = {} if value is None else value
    _only(value, ('enable', 'timeout_sec', 'cache', 'addresses'), 'resolvers')
    enable = value.get('enable', False)
    if not isinstance(enable, bool):
        raise ValueError(f'resolvers enable must be true or false, not {enable!r}')
    timeout = _number(value.get('timeout_sec', DEFAULT_TIMEOUT), 'timeout_sec', high=5)
    cache = value.get('cache') or {}
    _only(cache, ('ttl_sec', 'max_entries'), 'resolvers cache')
    ttl = _number(cache.get('ttl_sec', DEFAULT_TTL), 'cache ttl_sec', int)
    max_entries = _number(cache.get('max_entries', DEFAULT_MAX_ENTRIES), 'cache max_entries', int)
    given = value.get('addresses') or {}
    _only(given, DEFAULT_ADDRESSES, 'resolvers addresses')
    addresses = dict(DEFAULT_ADDRESSES)
    for role, address in given.items():
        try:
            addresses[role] = str(ipaddress.ip_address(str(address)))
        except ValueError:
            raise ValueError(f'resolvers addresses {role} must be an IP address, not {address!r}')
    return Settings(enable, timeout, ttl, max_entries, addresses)


def query(address, host, timeout):
    """One A query, as an Answer. Raises whatever dnspython raises."""
    import dns.edns
    import dns.flags
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype

    request = dns.message.make_query(host, 'A', use_edns=0, payload=1232)
    response = dns.query.udp(request, address, timeout=timeout)
    if response.flags & dns.flags.TC:
        response = dns.query.tcp(request, address, timeout=timeout)
    ede = frozenset(option.code for option in response.options
                    if isinstance(option, dns.edns.EDEOption))
    addresses = [rd.address for rrset in response.answer
                 if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA) for rd in rrset]
    return Answer(dns.rcode.to_text(response.rcode()), ede,
                  bool(addresses) and all(a in ('0.0.0.0', '::') for a in addresses),
                  tuple(addresses), bool(response.flags & dns.flags.RA),
                  any(rr.rdtype == dns.rdatatype.SOA for rr in response.authority))


def _transient(answer):
    """The status for an answer that settles nothing, or None if it settles."""
    if answer.rcode == 'SERVFAIL':
        return 'servfail'
    if answer.rcode not in ('NOERROR', 'NXDOMAIN'):
        return answer.rcode.lower()
    return None


class Checker(object):
    """Asks the resolvers, and remembers settled answers for the process.

    Never raises. Every outcome lands in a status string, which goes on the
    event so a resolver that stops answering shows up in a query.

    `query` is replaceable so tests need no network. `rate` caps queries per
    second, for the audit, which asks about thousands of hosts in a row.
    Workers leave it unset: they ask about one host per event.
    """

    def __init__(self, conf, query=None, rate=None, clock=time.monotonic):
        self.conf = conf
        # Looked up at call time rather than bound here, so a test can patch
        # the module's query and every checker, including a worker's, uses it
        self.query = query or (lambda address, host, timeout:
                               globals()['query'](address, host, timeout))
        self.clock = clock
        self.interval = 1.0 / rate if rate else 0.0
        self.cache = {}
        self.queries = 0
        self._last = 0.0
        self._lock = threading.Lock()

    # -- cache, following ptr_lookup in libtb.processor ---------------------

    def _cached(self, key):
        hit = self.cache.get(key)
        if hit is None:
            return None
        expires, status = hit
        if expires > self.clock():
            return status
        self.cache.pop(key, None)
        return None

    def _remember(self, key, status):
        # Reinserting keeps dict order meaningful, so eviction drops the
        # least recently refreshed entry
        self.cache.pop(key, None)
        self.cache[key] = (self.clock() + self.conf.ttl, status)
        while len(self.cache) > self.conf.max_entries:
            self.cache.pop(next(iter(self.cache)))

    # -- asking -------------------------------------------------------------

    def _ask(self, role, host):
        """An Answer from the resolver in this role, or a transient status string."""
        if self.interval:
            with self._lock:
                wait = self._last + self.interval - self.clock()
                if wait > 0:
                    time.sleep(wait)
                self._last = self.clock()
        self.queries += 1
        try:
            return self.query(self.conf.addresses[role], host, self.conf.timeout)
        except Exception as e:
            # dnspython's Timeout, an OSError when outbound DNS is firewalled,
            # a malformed reply: none of them may cost the event
            return 'timeout' if type(e).__name__ == 'Timeout' else 'error'

    def _quad9(self, host):
        answer = self._ask('quad9', host)
        if isinstance(answer, str):
            return answer
        transient = _transient(answer)
        if transient:
            return transient
        if answer.rcode == 'NOERROR':
            return CLEAR
        if answer.ede & BLOCK_CODES:
            return BLOCKED
        if answer.recursion and answer.soa:
            # Shaped like a name that does not exist
            return NXDOMAIN
        # Shaped like a block but without the EDE that says so. The
        # unfiltered resolver tells the two apart.
        unfiltered = self._ask('quad9_unfiltered', host)
        if isinstance(unfiltered, str):
            return unfiltered
        if unfiltered.rcode == 'NOERROR':
            return BLOCKED
        return _transient(unfiltered) or NXDOMAIN

    def _cloudflare(self, host, role):
        """(status, answer). The answer comes back only for a blocked-shaped
        reply, 0.0.0.0 or ::, which the caller reads further."""
        answer = self._ask(role, host)
        if isinstance(answer, str):
            return answer, None
        transient = _transient(answer)
        if transient:
            return transient, None
        if answer.rcode == 'NXDOMAIN':
            return NXDOMAIN, None
        if not answer.zero:
            return CLEAR, None
        return BLOCKED, answer

    def _cloudflare_security(self, host):
        status, answer = self._cloudflare(host, 'cloudflare_security')
        if status != BLOCKED or answer.ede & BLOCK_CODES:
            return status
        # 0.0.0.0 without an EDE: some names really are published that way,
        # so ask the unfiltered resolver whether this one is
        unfiltered = self._ask('cloudflare_unfiltered', host)
        if isinstance(unfiltered, str):
            return unfiltered
        return _transient(unfiltered) or (CLEAR if unfiltered.zero else BLOCKED)

    def _cloudflare_family(self, host):
        status, answer = self._cloudflare(host, 'cloudflare_family')
        if status != BLOCKED:
            return status
        # 1.1.1.3 says which filter fired: 17 for adult content, 16 for the
        # malware and phishing it shares with 1.1.1.2
        if EDE_FILTERED in answer.ede:
            return BLOCKED
        if answer.ede & BLOCK_CODES:
            return SECURITY
        # Without an EDE, a block 1.1.1.2 shares is a security block
        security = self.status(CLOUDFLARE_SECURITY, host)
        if security == BLOCKED:
            return SECURITY
        return BLOCKED if security in (CLEAR, NXDOMAIN) else security

    def status(self, provider, host):
        """What one provider says about one host: blocked, clear, nxdomain or
        security, which are remembered, or a transient failure, which is not."""
        key = (provider, host)
        cached = self._cached(key)
        if cached is not None:
            return cached
        try:
            found = {QUAD9: self._quad9, CLOUDFLARE_SECURITY: self._cloudflare_security,
                     CLOUDFLARE_FAMILY: self._cloudflare_family}[provider](host)
        except Exception:
            found = 'error'
        if found in SETTLED:
            self._remember(key, found)
        return found


def qualifies(provider, claims, verdict):
    """True when a vote from this provider could settle something.

    That is when the category it votes for is a candidate a medium trust list
    claims. Anything less and its vote would be the evidence rather than a
    second opinion on it: with no list on that path, Quad9 and Cloudflare
    agreeing would assert on their own, and a low trust list counts for
    nothing by design.
    """
    vote = set(statements(provider.vote))
    if verdict.get('incidental') and not is_risk(provider.vote):
        # Demoted whatever the evidence, so a vote would change nothing
        return False
    candidates = verdict['candidate']
    return any(source.trust == 'medium' and category in candidates
               and vote <= set(statements(category))
               for _, source, category in claims)


def corroborate(host, claims, verdict, min_publishers, checker):
    """Adds resolver votes where they could settle a candidate, and weighs again.

    Returns (claims, verdict, statuses). statuses maps each provider asked to
    what it said, and is empty when none was asked.
    """
    statuses = {}
    votes = []
    for provider in PROVIDERS:
        if not qualifies(provider, claims, verdict):
            continue
        status = checker.status(provider.name, host)
        statuses[provider.name] = status
        if status == BLOCKED:
            votes.append((host, SOURCES[provider.name], provider.vote))
    if not votes:
        return claims, verdict, statuses
    claims = list(claims) + votes
    return claims, resolve(claims, min_publishers), statuses


# One checker per process and per settings, so its cache lasts as long as the
# process does. Under the forking rq.Worker that is one event, as with the
# reverse DNS cache, and every qualifying event asks again.
_checkers = {}


def checker_for(conf):
    """The process-wide Checker for these settings, or None when they are off."""
    if conf is None or not conf.enable:
        return None
    key = (conf.timeout, conf.ttl, conf.max_entries, tuple(sorted(conf.addresses.items())))
    found = _checkers.get(key)
    if found is None:
        found = _checkers[key] = Checker(conf)
    return found
