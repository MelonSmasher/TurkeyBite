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
answer. So a block counts only in exactly the shape measured, EDE included.
Anything else is not a vote: a name genuinely published as 0.0.0.0, a block
code these providers were never seen to use, or an answer from a box on the
local network that intercepts port 53, as Pi-hole and AdGuard can.

A block is then confirmed against the provider's own unfiltered resolver,
Quad9's 9.9.9.10 and Cloudflare's 1.1.1.1. A name blocked there too was
blocked for a reason that is not a security verdict, a court order or an
intercepting box on the path, and is reported as censored rather than counted.
That costs one more query, only when there is a block to confirm. A dead
phishing domain still gets its vote: both providers block names that no longer
exist, and the unfiltered resolver answering NXDOMAIN is not a block.

The resolvers corroborate and never assert. One is asked only when a medium
trust list already claims the category it would vote for and that category is
still a candidate, so its vote can only complete a pair a list has started.
After each vote the verdict is weighed again, so a second resolver is not
asked about a name the first one has already settled. A vote is a claim like
any other, from a medium trust source whose publisher is the resolver's
operator. Quad9 and Cloudflare vote the generic `malicious`, and Cloudflare's
adult filter votes `porn`: a resolver's block says the host is bad, not
whether it phishes or serves malware, so a specific category like `phishing`
still needs two lists. The adult vote has its own switch and is off unless
asked for, since Cloudflare's family filter also covers piracy and gore.

A lookup never waits on the resolvers for more than `timeout_sec` in all,
however many are asked. A resolver that keeps failing, as one behind a
firewall that drops port 53 does, is left alone for `backoff_sec` after three
failures in a row, doubling while it stays down, so a blocked path costs a few
timeouts and then nothing. Both live in the process, so they last only as
long as it does: under the forking rq.Worker that is one event, and every
qualifying event can wait up to the budget. The consume pipeline keeps both.

Only DNS lookups are checked, not browser history, and only the name asked
for, not its CNAME targets. A resolver answers for the name as a whole, chain
included, and the targets are mostly CDN hosts shared by thousands of sites,
where a block would say little about this lookup and a query per link would
multiply the traffic. The one chain seen in testing went the other way:
Cloudflare blocked www.isuzi.com while leaving its target, overdue.aliyun.com,
alone.

Only the name is sent, never the client's address, and nothing is sent unless
an operator turns this on.
"""

import ipaddress
import math
import threading
import time
from collections import namedtuple

import dns.exception

from libtb.evidence import is_risk, resolve, statements
from libtb.index import Source

QUAD9 = 'quad9'
CLOUDFLARE_SECURITY = 'cloudflare-security'
CLOUDFLARE_FAMILY = 'cloudflare-family'

# Extended DNS Error codes. 15 (Blocked) was never seen from either provider,
# which is why it does not count: it is what local blockers send.
EDE_BLOCKED, EDE_CENSORED, EDE_FILTERED = 15, 16, 17
BLOCK_CODES = frozenset((EDE_BLOCKED, EDE_CENSORED, EDE_FILTERED))

# What a provider is asked about and what its block is a vote for, where its
# filtered and unfiltered resolvers live, and the exact shape of its block: the
# EDE code, and whether the name comes back NXDOMAIN or as 0.0.0.0. The order
# is the order they are asked in.
Provider = namedtuple('Provider', 'name publisher vote role unfiltered ede shape')
PROVIDERS = (
    Provider(QUAD9, 'quad9', 'malicious', 'quad9', 'quad9_unfiltered',
             EDE_FILTERED, 'nxdomain'),
    Provider(CLOUDFLARE_SECURITY, 'cloudflare', 'malicious', 'cloudflare_security',
             'cloudflare_unfiltered', EDE_CENSORED, 'zero'),
    Provider(CLOUDFLARE_FAMILY, 'cloudflare', 'porn', 'cloudflare_family',
             'cloudflare_unfiltered', EDE_FILTERED, 'zero'),
)
BY_NAME = {provider.name: provider for provider in PROVIDERS}

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

# Outcomes worth remembering, all of them answers. A timeout, a SERVFAIL, a
# network error, a resolver being backed off or the lookup's time running out
# are the path having a bad moment, and remembering one would hide the
# recovery for the whole TTL, as with the reverse DNS cache.
BLOCKED, CLEAR, NXDOMAIN = 'blocked', 'clear', 'nxdomain'
SECURITY = 'security'      # 1.1.1.3 blocked for malware, not adult content
CENSORED = 'censored'      # the unfiltered resolver blocks the name too
SETTLED = frozenset((BLOCKED, CLEAR, NXDOMAIN, SECURITY, CENSORED))
TIMEOUT, ERROR = 'timeout', 'error'
UNAVAILABLE = 'unavailable'  # backed off after repeated failures, not asked
DEADLINE = 'deadline'        # the lookup's time budget was spent, not asked

DEFAULT_TIMEOUT = 0.5
DEFAULT_BACKOFF = 60
MAX_BACKOFF = 900
FAILURES_TO_BACK_OFF = 3
DEFAULT_TTL = 3600
DEFAULT_MAX_ENTRIES = 50000

# Queries per second `turkeybite audit --resolvers` sends at most. A worker
# asks about one host per event; the audit asks about thousands in a row.
AUDIT_RATE = 20

Settings = namedtuple('Settings', 'enable adult timeout backoff ttl max_entries addresses')

# The shape of the answer the checker needs, so tests can supply one directly
Answer = namedtuple('Answer', 'rcode ede zero addresses recursion soa')


def _number(value, name, kind=float, low=0, high=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f'resolvers {name} must be a number, not {value!r}')
    if not math.isfinite(value):
        raise ValueError(f'resolvers {name} must be a finite number, not {value!r}')
    if kind is int and value != int(value):
        raise ValueError(f'resolvers {name} must be a whole number, not {value!r}')
    value = kind(value)
    if value <= low or (high is not None and value > high):
        bound = f' and at most {high}' if high is not None else ''
        raise ValueError(f'resolvers {name} must be more than {low}{bound}, not {value!r}')
    return value


def _mapping(value, allowed, where):
    """A sub-setting as a dict, {} when absent, refused when not a mapping."""
    value = {} if value is None else value
    if not isinstance(value, dict):
        raise ValueError(f'{where} must be a mapping, not {value!r}')
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise ValueError(f'{where} has unknown keys {", ".join(map(str, unknown))}; '
                         f'it takes {", ".join(sorted(allowed))}')
    return value


def _switch(value, name):
    if not isinstance(value, bool):
        raise ValueError(f'resolvers {name} must be true or false, not {value!r}')
    return value


def settings(value=None):
    """processor.evidence.resolvers as Settings, validated.

    Absent means off. Raises ValueError for an unknown key or a bad value, so
    a mistake stops the worker at start rather than quietly sending nothing,
    or sending names somewhere unintended.
    """
    value = _mapping(value, ('enable', 'adult', 'timeout_sec', 'backoff_sec', 'cache',
                             'addresses'), 'resolvers')
    enable = _switch(value.get('enable', False), 'enable')
    adult = _switch(value.get('adult', False), 'adult')
    timeout = _number(value.get('timeout_sec', DEFAULT_TIMEOUT), 'timeout_sec', high=5)
    backoff = _number(value.get('backoff_sec', DEFAULT_BACKOFF), 'backoff_sec', high=MAX_BACKOFF)
    cache = _mapping(value.get('cache'), ('ttl_sec', 'max_entries'), 'resolvers cache')
    ttl = _number(cache.get('ttl_sec', DEFAULT_TTL), 'cache ttl_sec', int, high=86400)
    max_entries = _number(cache.get('max_entries', DEFAULT_MAX_ENTRIES), 'cache max_entries',
                          int, high=10_000_000)
    given = _mapping(value.get('addresses'), DEFAULT_ADDRESSES, 'resolvers addresses')
    addresses = dict(DEFAULT_ADDRESSES)
    for role, address in given.items():
        try:
            addresses[role] = str(ipaddress.ip_address(str(address)))
        except ValueError:
            raise ValueError(f'resolvers addresses {role} must be an IP address, not {address!r}')
    return Settings(enable, adult, timeout, backoff, ttl, max_entries, addresses)


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


def _blocked(provider, answer):
    """True when the answer has exactly the shape this provider's block was measured in."""
    if provider.ede not in answer.ede:
        return False
    if provider.shape == 'nxdomain':
        return answer.rcode == 'NXDOMAIN'
    return answer.rcode == 'NOERROR' and answer.zero


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


class Checker(object):
    """Asks the resolvers, and remembers settled answers for the process.

    Every answer, failure and refusal to ask lands in a status string, which
    goes on the event, so a resolver that stops answering shows up in a query.
    Only DNS and network errors are turned into a status: anything else is a
    fault in this code, and so is RQ stopping a job that ran too long, and
    both have to surface rather than be filed as a resolver error.

    `ask` replaces the network, for tests. `rate` caps queries per second, for
    the audit, which asks about thousands of hosts in a row. Workers leave it
    unset: they ask about one host per event, within a time budget.
    """

    def __init__(self, conf, ask=None, rate=None, clock=time.monotonic):
        self.conf = conf
        self.ask = ask
        self.clock = clock
        self.interval = 1.0 / rate if rate else 0.0
        self.providers = tuple(provider for provider in PROVIDERS
                               if conf.adult or provider.vote != 'porn')
        self.cache = {}
        self.queries = 0
        self._last = 0.0
        self._lock = threading.Lock()
        # Per address: failures in a row, how many times it has been backed
        # off in a row, and when it may be asked again
        self._failures = {}
        self._backoffs = {}
        self._resting_until = {}

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

    # -- back-off -----------------------------------------------------------

    def _resting(self, address):
        return self.clock() < self._resting_until.get(address, 0.0)

    def _succeeded(self, address):
        self._failures.pop(address, None)
        self._backoffs.pop(address, None)

    def _failed(self, address):
        failures = self._failures.get(address, 0) + 1
        self._failures[address] = failures
        if failures >= FAILURES_TO_BACK_OFF:
            backoffs = self._backoffs.get(address, 0) + 1
            self._backoffs[address] = backoffs
            rest = min(MAX_BACKOFF, self.conf.backoff * 2 ** (backoffs - 1))
            self._resting_until[address] = self.clock() + rest

    # -- asking -------------------------------------------------------------

    def _ask(self, role, host, deadline):
        """An Answer from the resolver in this role, or a status string."""
        address = self.conf.addresses[role]
        if self._resting(address):
            return UNAVAILABLE
        timeout = self.conf.timeout
        if deadline is not None:
            timeout = min(timeout, deadline - self.clock())
            if timeout <= 0:
                return DEADLINE
        if self.interval:
            with self._lock:
                wait = self._last + self.interval - self.clock()
                if wait > 0:
                    time.sleep(wait)
                self._last = self.clock()
        self.queries += 1
        try:
            answer = (self.ask or query)(address, host, timeout)
        except (dns.exception.DNSException, OSError, EOFError) as e:
            # A timeout, an OSError when outbound DNS is firewalled, a
            # malformed reply: none of them may cost the event
            self._failed(address)
            return TIMEOUT if isinstance(e, dns.exception.Timeout) else ERROR
        self._succeeded(address)
        return answer

    def _status(self, provider, host, deadline):
        answer = self._ask(provider.role, host, deadline)
        if isinstance(answer, str):
            return answer
        transient = _transient(answer)
        if transient:
            return transient
        if not _blocked(provider, answer):
            if provider.name == CLOUDFLARE_FAMILY and answer.zero and EDE_CENSORED in answer.ede:
                # 1.1.1.3 blocking for the malware and phishing it shares with 1.1.1.2
                return SECURITY
            return NXDOMAIN if answer.rcode == 'NXDOMAIN' else CLEAR
        # A block, so confirm it is the provider's filter and not something
        # every resolver on this path would say
        unfiltered = self._ask(provider.unfiltered, host, deadline)
        if isinstance(unfiltered, str):
            return unfiltered
        transient = _transient(unfiltered)
        if transient:
            return transient
        if unfiltered.ede & BLOCK_CODES:
            return CENSORED
        return BLOCKED

    def status(self, provider, host, deadline=None):
        """What one provider, by name, says about one host. Settled answers
        are remembered; failures and refusals to ask are not."""
        key = (provider, host)
        cached = self._cached(key)
        if cached is not None:
            return cached
        found = self._status(BY_NAME[provider], host, deadline)
        if found in SETTLED:
            self._remember(key, found)
        return found

    def corroborate(self, host, claims, verdict, min_publishers):
        """Adds resolver votes where they could settle a candidate.

        Returns (claims, verdict, statuses). statuses maps each provider asked
        to what it said, and is empty when none was asked. A vote's key is
        None, since it matched nothing in the index.
        """
        statuses = {}
        # A worker's lookup waits at most timeout_sec in all. The audit, which
        # is throttled and waits by design, gets no budget.
        deadline = None if self.interval else self.clock() + self.conf.timeout
        for provider in self.providers:
            # Against the verdict as it stands, so a name an earlier vote
            # settled is not sent to the next resolver
            if not qualifies(provider, claims, verdict):
                continue
            status = self.status(provider.name, host, deadline)
            statuses[provider.name] = status
            if status == BLOCKED:
                claims = list(claims) + [(None, SOURCES[provider.name], provider.vote)]
                verdict = resolve(claims, min_publishers)
        return claims, verdict, statuses


# One checker per process and per settings, so its cache and back-off last as
# long as the process does. Under the forking rq.Worker that is one event, as
# with the reverse DNS cache, and every qualifying event asks again.
_checkers = {}


def checker_for(conf):
    """The process-wide Checker for these settings, or None when they are off."""
    if conf is None or not conf.enable:
        return None
    key = (conf.adult, conf.timeout, conf.backoff, conf.ttl, conf.max_entries,
           tuple(sorted(conf.addresses.items())))
    found = _checkers.get(key)
    if found is None:
        found = _checkers[key] = Checker(conf)
    return found
