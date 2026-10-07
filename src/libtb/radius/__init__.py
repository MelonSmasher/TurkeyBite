"""Who held an address, from Windows NPS's RADIUS accounting log.

A DNS event carries only the address that asked. On Wi-Fi that is a phone or
a laptop whose reverse DNS name, when it has one, is whatever the device
called itself, and every iPhone calls itself iPhone: one "machine" with the
traffic of hundreds of people. The RADIUS server knows better. For every
802.1X session, each access point reports the user who signed in, the
device's MAC address and, once the device has one, its address: when the
session starts, every interim interval while it lasts, and when it stops.

NPS writes those requests to its log. In DTS format each is one line of flat
XML, of which this reads, from accounting requests (Packet-Type 4):

    Timestamp           when NPS logged it, in the NPS server's time zone
    Acct-Status-Type    1 start, 3 interim update, 2 stop
    Acct-Delay-Time     how long the access point had been trying to send it
    User-Name           the name the device gave, jsmith@example.edu
    Framed-IP-Address   the device's address
    Calling-Station-Id  the device's MAC address, BA-F7-F8-3B-6D-36
    Acct-Session-Id     with NAS-Identifier, which session this is
    Acct-Session-Time   seconds since the session started
    Class               which sign-in the session belongs to

and from the Access-Accepts NPS sends (Packet-Type 2), the account NPS
authenticated, SAM-Account-Name, under the same Class. User-Name is only what
the device said, which for many profiles is "anonymous" and which anyone can
set to someone else's name; the account behind the Class is who actually
signed in, so it is used whenever its Access-Accept has been seen.

Filebeat on each NPS server pushes the lines onto their own Valkey list,
`<channel>:nps`. Each worker takes what is waiting there before each batch of
DNS events, and records the session in Valkey under its address: who, which
device, from when, when last reported, and when it stopped. A worker
enriching a DNS event asks who held the event's address at the event's time,
and writes that person as bite.client_user and the device as bite.client_mac.

A session holds its address from its start until it stops, or, while it has
not, until `grace_sec` after it was last reported: interim updates keep a
connected device inside that window. Once stopped, the address is nobody's,
because DHCP may give it to another device, and a lookup credited to the
wrong person is worse than one credited to nobody. A phone that roams to
another access point stops one session and starts another, often before the
new one reports an address; a session reported without one takes the
address its device last had, if that was within `grace_sec`. When two
sessions cover an event, the one that started later wins.

What it cannot do: a session is only known once an access point reports it
with an address. Lookups a device makes before then, on joining the network,
are recorded without a user. Lines are taken at most once, so those in hand
when a worker dies are lost, which costs no more than the next interim update
puts back. IPv6 addresses are not reported, so lookups over IPv6 get no user.
And anyone who can write to Valkey can claim an address for anyone, as they
can already write events.
"""

import html
import ipaddress
import json
import re
import time
from collections import namedtuple
from datetime import datetime, timezone

from dateutil import tz

# processor.radius
Settings = namedtuple('Settings', 'enable zone realms grace_sec keep_sec cache_sec')
DEFAULT = Settings(False, None, (), 1200, 24 * 3600, 30)
KEYS = frozenset(('enable', 'timezone', 'realms', 'grace_sec', 'keep_hours', 'cache_sec'))

# One accounting request. `address` is None when it reported none, `user`
# when the name it gave is not a person's; `start`, `seen` and `stopped` are
# epoch seconds, `stopped` None while the session lasts.
Session = namedtuple('Session', 'address key user mac start seen stopped klass')

ACCESS_ACCEPT, ACCOUNTING_REQUEST = '2', '4'
START, STOP, INTERIM = '1', '2', '3'

# How far apart two clocks may be: NPS's and the DNS sensor's. An event this
# far outside a session still counts as in it.
CLOCK_SLACK = 60

# Sessions kept per address, the most recently reported; a lab machine's
# address can see a new one every class
MAX_SESSIONS = 8

# A session longer than this, or a delay, is not believed
MAX_SECONDS = 31 * 24 * 3600

# The most of a line read. A DTS accounting line is about 2 KB.
MAX_LINE = 64 * 1024

# Each consumer process remembers what it last read for an address
CACHE_MAX = 20000

# Names a device gives that are not a person's: an anonymous outer identity
ANONYMOUS = frozenset(('anonymous', 'anon'))

_ATTRIBUTE = re.compile(r'<([A-Za-z][A-Za-z0-9-]*) data_type="\d+">([^<]*)</\1>')
_MAC = re.compile(r'^[0-9a-f]{2}([-:.]?[0-9a-f]{2}){5}$')
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f]')

# Merges one report into an address's sessions, atomically, since workers
# take reports in parallel and a replayed batch hands them over out of order.
# The start is the first reported, the last report the latest, and a stop,
# once seen, stays. Then the hash's expiry is renewed and only the
# MAX_SESSIONS most recently reported sessions are kept.
#   KEYS[1] the address's hash
#   ARGV    session key, user, MAC or "", start, seen, stopped or "",
#           seconds to keep, sessions to keep
RECORD_SCRIPT = """
local start, seen = tonumber(ARGV[4]), tonumber(ARGV[5])
local stopped = tonumber(ARGV[6])
local held = redis.call('HGET', KEYS[1], ARGV[1])
if held then
  local ok, old = pcall(cjson.decode, held)
  if ok and type(old) == 'table' then
    if type(old.s) == 'number' then start = old.s end
    if type(old.l) == 'number' and old.l > seen then seen = old.l end
    if type(old.e) == 'number' and (stopped == nil or old.e > stopped) then stopped = old.e end
  end
end
local value = {u = ARGV[2], s = start, l = seen}
if ARGV[3] ~= '' then value.m = ARGV[3] end
if stopped then value.e = stopped end
redis.call('HSET', KEYS[1], ARGV[1], cjson.encode(value))
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[7]))
local keep = tonumber(ARGV[8])
if redis.call('HLEN', KEYS[1]) > keep then
  local all = redis.call('HGETALL', KEYS[1])
  local rows = {}
  for i = 1, #all, 2 do
    local ok, v = pcall(cjson.decode, all[i + 1])
    local last = -1
    if ok and type(v) == 'table' and type(v.l) == 'number' then last = v.l end
    rows[#rows + 1] = {all[i], last}
  end
  table.sort(rows, function(a, b) return a[2] < b[2] end)
  for i = 1, #rows - keep do redis.call('HDEL', KEYS[1], rows[i][1]) end
end
return 1
"""


def settings(conf):
    r"""processor.radius, checked: unknown keys or bad values stop the worker at start.

    enable      false unless set; with it off the accounting list is emptied
                and DNS events are left as they were
    timezone    the NPS servers' time zone, such as America/New_York, which
                they write each line's Timestamp in. Needed when enabled.
    realms      the organisation's own realms and NetBIOS domain, such as
                [example.edu, example]: jsmith@example.edu and EXAMPLE\jsmith
                are recorded as jsmith, as Browserbeat reports a person.
                Anyone else's realm, an eduroam visitor's, is kept.
    grace_sec   how long after a session was last reported its address is
                still taken as that person's, unless it stopped. Above the
                access points' interim interval, or a connected device drops
                out between updates.
    keep_hours  how long Valkey keeps an address's sessions after the last
                report, for a backlog of DNS events to be matched against.
                Lines older than this are not recorded.
    cache_sec   how long each worker process reuses what it read for an
                address before asking Valkey again
    """
    if conf is None:
        return DEFAULT
    if not isinstance(conf, dict):
        raise ValueError('processor.radius must be a mapping')
    unknown = set(map(str, conf)) - KEYS
    if unknown:
        raise ValueError(f'processor.radius: unknown keys {", ".join(sorted(unknown))}')
    enable = conf.get('enable', DEFAULT.enable)
    if not isinstance(enable, bool):
        raise ValueError('processor.radius.enable must be true or false')
    zone = None
    name = conf.get('timezone')
    if name is not None or enable:
        zone = tz.gettz(name) if isinstance(name, str) and name.strip() else None
        if zone is None:
            raise ValueError('processor.radius.timezone must name the NPS servers\' time zone, '
                             'such as America/New_York')
    realms = conf.get('realms') or []
    if not isinstance(realms, list) or not all(isinstance(r, str) and r.strip() for r in realms):
        raise ValueError('processor.radius.realms must be a list of realm names')
    grace = _bounded(conf, 'grace_sec', DEFAULT.grace_sec, 60, 86400)
    keep_hours = _bounded(conf, 'keep_hours', DEFAULT.keep_sec // 3600, 1, 24 * 14)
    if keep_hours * 3600 < grace:
        raise ValueError('processor.radius.keep_hours must be at least grace_sec')
    cache = _bounded(conf, 'cache_sec', DEFAULT.cache_sec, 0, 600)
    return Settings(enable, zone, tuple(r.strip().lower() for r in realms), grace, keep_hours * 3600, cache)


def _bounded(conf, name, default, low, high):
    value = conf.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f'processor.radius.{name} must be a whole number from {low} to {high}')
    return value


def attributes(line):
    """The attributes of one DTS line, by name. A repeated one keeps its first value."""
    found = {}
    if not isinstance(line, str) or len(line) > MAX_LINE:
        return found
    for name, value in _ATTRIBUTE.findall(line):
        found.setdefault(name, html.unescape(value).strip())
    return found


def printable(value, limit=256):
    """Text from a line that is safe to log or store: no control characters, and not too long."""
    return _CONTROL.sub('', value)[:limit] if isinstance(value, str) else ''


def username(value, realms=()):
    r"""The person a name names, lower-cased, or None.

    Not a person: a computer signing in on its own account,
    host/LAB-12.example.edu or EXAMPLE\LAB-12$; a device signing in by its
    MAC address; and an anonymous outer identity.
    """
    if not isinstance(value, str) or _CONTROL.search(value):
        return None
    name = value.strip().lower()
    if not name or len(name) > 256 or name.startswith('host/') or name.endswith('$') or mac(name):
        return None
    if '\\' in name:
        domain, _, bare = name.partition('\\')
        local = bare
        if domain in realms:
            name = bare
    else:
        local, _, realm = name.rpartition('@') if '@' in name else (name, '', '')
        if realm in realms:
            name = local
    if not local or local in ANONYMOUS:
        return None
    return name


def authenticated(fields, realms=()):
    """The account an Access-Accept says NPS authenticated, or None."""
    for name in ('SAM-Account-Name', 'Fully-Qualifed-User-Name', 'Fully-Qualified-User-Name'):
        found = username(fields.get(name), realms)
        if found:
            return found
    return None


def mac(value):
    """A Calling-Station-Id as aa:bb:cc:dd:ee:ff, or None if it is not a MAC address."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not _MAC.match(text):
        return None
    digits = re.sub('[^0-9a-f]', '', text)
    return ':'.join(digits[i:i + 2] for i in range(0, 12, 2))


def address(value):
    """An address a device can have, written one way, or None.

    255.255.255.254 and 255.255.255.255 are RADIUS's own values for "the NAS
    chooses" and "the user chooses", not addresses. An IPv4 address written
    as IPv6, ::ffff:10.0.0.5, is the IPv4 address.
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if getattr(parsed, 'ipv4_mapped', None):
        parsed = parsed.ipv4_mapped
    if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast or parsed.is_link_local \
            or str(parsed) in ('255.255.255.254', '255.255.255.255'):
        return None
    return str(parsed)


def iso_seconds(value):
    """An ISO 8601 time, as Filebeat and Packetbeat write @timestamp, as epoch seconds, or None."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _clock(value):
    """A time as NPS writes it, 10/07/2026 18:19:34.212, as a naive datetime, or None."""
    if not isinstance(value, str):
        return None
    for form in ('%m/%d/%Y %H:%M:%S.%f', '%m/%d/%Y %H:%M:%S'):
        try:
            return datetime.strptime(value.strip(), form)
        except ValueError:
            continue
    return None


def _seconds(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= MAX_SECONDS else None


def logged_at(fields, zone, received=None):
    """When NPS logged a line, as epoch seconds, or None.

    Timestamp is in the NPS server's zone, which its time and Windows keep
    right. In the hour a change back from summer time repeats, the reading
    nearer the access point's Event-Timestamp, which is UTC, or the time
    Filebeat read the line, is taken. The access point's clock is not used
    otherwise: one was seen to be an hour and three-quarters out.
    """
    local = _clock(fields.get('Timestamp'))
    if local is None or zone is None:
        return None
    readings = {tz.enfold(local, fold=fold).replace(tzinfo=zone).timestamp() for fold in (0, 1)}
    near = _clock(fields.get('Event-Timestamp'))
    near = near.replace(tzinfo=timezone.utc).timestamp() if near is not None else received
    if near is None:
        return min(readings)
    return min(readings, key=lambda reading: abs(reading - near))


def session(fields, zone, received=None, realms=()):
    """The session an accounting request reports, or None if it reports none.

    It needs a session id, a time, and an address or a MAC address to find
    the address by. The user is the name the device gave, if a person's.
    """
    if fields.get('Packet-Type') != ACCOUNTING_REQUEST:
        return None
    status = fields.get('Acct-Status-Type')
    if status not in (START, STOP, INTERIM):
        return None
    sid = fields.get('Acct-Session-Id')
    when = logged_at(fields, zone, received)
    where = address(fields.get('Framed-IP-Address'))
    device = mac(fields.get('Calling-Station-Id'))
    if not sid or when is None or not (where or device):
        return None
    when -= _seconds(fields.get('Acct-Delay-Time')) or 0
    length = _seconds(fields.get('Acct-Session-Time'))
    start = when - length if length is not None else when
    nas = fields.get('NAS-Identifier') or fields.get('NAS-IP-Address') or ''
    return Session(where, printable(f'{nas}|{sid}', 200), username(fields.get('User-Name'), realms), device,
                   start, when, when if status == STOP else None, printable(fields.get('Class')) or None)


def _decode(held):
    """What HGETALL answered, as [{u, m, s, l, e}], leaving out what cannot be read."""
    out = []
    for raw in (held or {}).values():
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict) and isinstance(value.get('u'), str) \
                and isinstance(value.get('s'), (int, float)) and isinstance(value.get('l'), (int, float)):
            out.append(value)
    return out


class Sessions:
    """The sessions each address has had, in Valkey, shared by every worker.

    In the queue's database, since the librarian sweeps the host lists':

        <prefix>:radius:ip:<address>   hash, session key -> {u, m, s, l, e}
        <prefix>:radius:mac:<mac>      the address a device last had, {a, l}
        <prefix>:radius:class:<class>  the account an Access-Accept named

    The first expires `keep_hours` after its last report, the second
    `grace_sec`, the third `keep_hours` after its Access-Accept.
    """

    def __init__(self, redis, prefix, conf, monotonic=time.monotonic, clock=time.time):
        """Keys start with `prefix`, the queue's channel; `conf` is processor.radius."""
        self.redis = redis
        self.prefix = prefix
        self.conf = conf
        self.monotonic = monotonic
        self.clock = clock
        self._cache = {}

    def key(self, kind, name):
        """The key that holds an address's sessions, a device's address, or a sign-in's account."""
        return f'{self.prefix}:radius:{kind}:{name}'

    def take(self, line, received=None):
        """Records what one line of the log says. Returns the session recorded, or None.

        An Access-Accept is remembered by its Class, for the sessions it
        signs in. A line older than `keep_hours` is not recorded: Filebeat
        reads a log from its start when it first sees it.
        """
        fields = attributes(line)
        if fields.get('Packet-Type') == ACCESS_ACCEPT:
            account, klass = authenticated(fields, self.conf.realms), printable(fields.get('Class'))
            if account and klass:
                self.redis.set(self.key('class', klass), account, ex=self.conf.keep_sec)
            return None
        found = session(fields, self.conf.zone, received, self.conf.realms)
        if found is None or found.seen < self.clock() - self.conf.keep_sec:
            return None
        account = self.redis.get(self.key('class', found.klass)) if found.klass else None
        if account:
            found = found._replace(user=account.decode('utf-8', 'replace') if isinstance(account, bytes)
                                   else account)
        if not found.user:
            return None
        if found.address is None:
            found = found._replace(address=self.last_address(found.mac, found.seen))
            if found.address is None:
                return None
        self.record(found)
        return found

    def last_address(self, device, when):
        """The address a device was last reported with, if within `grace_sec` of `when`."""
        if not device:
            return None
        try:
            last = json.loads(self.redis.get(self.key('mac', device)) or 'null')
        except (TypeError, ValueError):
            return None
        if isinstance(last, dict) and isinstance(last.get('l'), (int, float)) \
                and when - self.conf.grace_sec <= last['l'] <= when + CLOCK_SLACK:
            return address(last.get('a'))
        return None

    def record(self, found):
        """Merges one report into its address's sessions."""
        self.redis.eval(RECORD_SCRIPT, 1, self.key('ip', found.address), found.key, found.user, found.mac or '',
                        found.start, found.seen, '' if found.stopped is None else found.stopped,
                        self.conf.keep_sec, MAX_SESSIONS)
        if found.mac:
            self.redis.set(self.key('mac', found.mac), json.dumps({'a': found.address, 'l': found.seen}),
                           ex=self.conf.grace_sec)
        # This process at least sees the change at once
        self._cache.pop(found.address, None)

    def _sessions(self, where):
        now = self.monotonic()
        hit = self._cache.get(where)
        if hit is not None and hit[0] > now:
            return hit[1]
        held = _decode(self.redis.hgetall(self.key('ip', where)))
        if self.conf.cache_sec:
            self._cache.pop(where, None)
            self._cache[where] = (now + self.conf.cache_sec, held)
            while len(self._cache) > CACHE_MAX:
                self._cache.pop(next(iter(self._cache)))
        return held

    def holder(self, where, when):
        """The session that held an address at a time, {u, m, s, l, e}, or None."""
        where = address(where)
        if where is None:
            return None
        covering = [held for held in self._sessions(where)
                    if held['s'] - CLOCK_SLACK <= when <= self._end(held)]
        # Ties go the same way in every worker
        return max(covering, key=lambda held: (held['s'], held['l'], held['u']), default=None)

    def _end(self, held):
        stopped = held.get('e')
        if isinstance(stopped, (int, float)):
            return stopped + CLOCK_SLACK
        return held['l'] + self.conf.grace_sec
