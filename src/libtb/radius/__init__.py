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
set to someone else's name. The account behind the Class is who actually
signed in. It is used whenever its Access-Accept has been seen, and once a
session has it, no name a device gives replaces it.

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
new one reports an address. A session that starts without one, within
ROAM_SEC of its device last being reported, takes the address the device had
then, unless another device has been reported with it since. Such a session
only holds the address until one reported with it covers the time. When two
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

from libtb.opensearch import report_once

# processor.radius
Settings = namedtuple('Settings', 'enable zone realms grace_sec keep_sec cache_sec')
DEFAULT = Settings(False, None, (), 1200, 24 * 3600, 30)
KEYS = frozenset(('enable', 'timezone', 'realms', 'grace_sec', 'keep_hours', 'cache_sec'))

# One accounting request. `address` is None when it reported none, `user`
# when the name it gave is not a person's; `start`, `seen` and `stopped` are
# epoch seconds, `stopped` None while the session lasts. `signed` says the
# user is the account NPS authenticated, `bridged` that the address is the
# one the device had before it roamed.
Session = namedtuple('Session', 'address key user mac start seen stopped klass signed bridged',
                     defaults=(False, False))

ACCESS_ACCEPT, ACCOUNTING_REQUEST = '2', '4'
START, STOP, INTERIM = '1', '2', '3'

# How far apart two clocks may be: NPS's, Filebeat's and the DNS sensor's. An
# event this far outside a session still counts as in it.
CLOCK_SLACK = 60

# How soon after its device was last reported a session that starts without
# an address must start, to take the address the device had: a roam
ROAM_SEC = 120

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
#   - The start is the first reported, the last report the latest, and a
#     stop, once seen, stays.
#   - A report that starts after the session it names stopped is a new
#     session that reused the id, and replaces it.
#   - A name NPS authenticated is not replaced by one a device gave.
#   - An address the session reported itself is not demoted to a roam's.
# Then the hash's expiry is renewed, only the MAX_SESSIONS most recently
# reported sessions are kept, and, for a report that gave its address, the
# device's last address is updated if this report is newer.
#   KEYS[1] the address's hash; KEYS[2], if given, the device's last address
#   ARGV    session key, user, MAC or "", start, seen, stopped or "",
#           seconds to keep, sessions to keep, signed 1/0, bridged 1/0,
#           clock slack, seconds to keep the device's address, the address
RECORD_SCRIPT = """
local start, seen = tonumber(ARGV[4]), tonumber(ARGV[5])
local stopped = tonumber(ARGV[6])
local user, signed, bridged = ARGV[2], ARGV[9] == '1', ARGV[10] == '1'
local held = redis.call('HGET', KEYS[1], ARGV[1])
if held then
  local ok, old = pcall(cjson.decode, held)
  if ok and type(old) == 'table'
      and not (type(old.e) == 'number' and start > old.e + tonumber(ARGV[11])) then
    if type(old.s) == 'number' then start = old.s end
    if type(old.l) == 'number' and old.l > seen then seen = old.l end
    if type(old.e) == 'number' and (stopped == nil or old.e > stopped) then stopped = old.e end
    if old.a == 1 and not signed and type(old.u) == 'string' then user, signed = old.u, true end
    if old.b == nil then bridged = false end
  end
end
local value = {u = user, s = start, l = seen}
if ARGV[3] ~= '' then value.m = ARGV[3] end
if stopped then value.e = stopped end
if signed then value.a = 1 end
if bridged then value.b = 1 end
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
if #KEYS > 1 and ARGV[10] ~= '1' then
  local newer = true
  local last = redis.call('GET', KEYS[2])
  if last then
    local ok, v = pcall(cjson.decode, last)
    if ok and type(v) == 'table' and type(v.l) == 'number' and v.l > tonumber(ARGV[5]) then newer = false end
  end
  if newer then
    redis.call('SET', KEYS[2], cjson.encode({a = ARGV[13], l = tonumber(ARGV[5])}), 'EX', tonumber(ARGV[12]))
  end
end
return 1
"""


def settings(conf):
    r"""processor.radius, checked: unknown keys or bad values stop the worker at start.

    enable      false unless set. Off, a worker leaves the accounting list to
                workers that have it on, and only keeps it from growing past
                ACCOUNTING_KEEP lines; DNS events are left as they were.
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


def misrouted(data):
    """True for a line of NPS's log that came on the DNS queue instead of its own list."""
    message = data.get('message') if isinstance(data, dict) and 'type' not in data else None
    return isinstance(message, str) and message.lstrip().startswith('<Event>')


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
    is taken that is nearest when Filebeat read the line, and not after it;
    without that, the one nearest the access point's Event-Timestamp, which
    is UTC. The access point's clock is not used otherwise: one was seen to
    be an hour and three-quarters out.
    """
    local = _clock(fields.get('Timestamp'))
    if local is None or zone is None:
        return None
    readings = sorted({tz.enfold(local, fold=fold).replace(tzinfo=zone).timestamp() for fold in (0, 1)})
    near = received
    if near is not None:
        readings = [reading for reading in readings if reading <= near + CLOCK_SLACK] or readings
    else:
        near = _clock(fields.get('Event-Timestamp'))
        near = near.replace(tzinfo=timezone.utc).timestamp() if near is not None else None
    if near is None:
        return readings[0]
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
    """What HGETALL answered, as [{u, m, s, l, e, a, b}], leaving out what cannot be read."""
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

        <prefix>:radius:ip:<address>   hash, session key -> {u, m, s, l, e, a, b}
        <prefix>:radius:mac:<mac>      the address a device last reported, {a, l}
        <prefix>:radius:class:<class>  the account an Access-Accept named

    The first expires `keep_hours` after its last report, the second
    `grace_sec`, and the third `keep_hours` after it was last used.
    """

    # The clock the cache is kept by, the time lines are judged old by, and how
    # a misconfiguration is said. Tests replace them.
    monotonic = staticmethod(time.monotonic)
    clock = staticmethod(time.time)
    warn = staticmethod(report_once)

    def __init__(self, redis, prefix, conf):
        """Keys start with `prefix`, the queue's channel; `conf` is processor.radius."""
        self.redis = redis
        self.prefix = prefix
        self.conf = conf
        self._cache = {}

    def key(self, kind, name):
        """The key that holds an address's sessions, a device's address, or a sign-in's account."""
        return f'{self.prefix}:radius:{kind}:{name}'

    def take(self, line, received=None):
        """Records what one line of the log says. Returns what it recorded, or None.

        An Access-Accept is remembered by its Class, for the sessions it signs
        in, and its account returned. An accounting request is recorded as a
        session, and returned. Not recorded: a line older than `keep_hours`,
        since Filebeat reads a log from its start when it first sees it, and
        one dated after Filebeat read it, which only a wrong timezone does.
        """
        fields = attributes(line)
        if fields.get('Packet-Type') == ACCESS_ACCEPT:
            account, klass = authenticated(fields, self.conf.realms), printable(fields.get('Class'))
            if not (account and klass):
                return None
            self.redis.set(self.key('class', klass), account, ex=self.conf.keep_sec)
            return account
        found = session(fields, self.conf.zone, received, self.conf.realms)
        if found is None or found.seen < self.clock() - self.conf.keep_sec:
            return None
        if received is not None and found.seen > received + CLOCK_SLACK:
            self.warn(f'NPS lines are dated after Filebeat read them, so they are not recorded: is '
                      f'processor.radius.timezone the NPS servers\' time zone? A line logged at '
                      f'{printable(fields.get("Timestamp"), 40)} was read at {_utc(received)}.')
            return None
        found = self._named(found)
        if not found.user:
            return None
        if found.address is None:
            found = self._roamed(found)
            if found is None:
                return None
        self.record(found)
        return found

    def _named(self, found):
        """The session with the account NPS authenticated, when its Access-Accept was seen."""
        if not found.klass:
            self.warn('NPS accounting lines carry no Class, so each session is named by the name '
                      'its device gives, which a device can set to anyone\'s. Have the access '
                      'points send Class back in accounting.')
            return found
        account = self.redis.getex(self.key('class', found.klass), ex=self.conf.keep_sec)
        if account:
            account = account.decode('utf-8', 'replace') if isinstance(account, bytes) else account
            return found._replace(user=account, signed=True)
        return found

    def _roamed(self, found):
        """The session at the address its device had before it roamed, or None.

        Only for a session that starts within ROAM_SEC of its device's last
        report, and only if no other device has been reported with the
        address since.
        """
        if not found.mac:
            return None
        try:
            last = json.loads(self.redis.get(self.key('mac', found.mac)) or 'null')
        except (TypeError, ValueError):
            return None
        if not (isinstance(last, dict) and isinstance(last.get('l'), (int, float))
                and last['l'] - CLOCK_SLACK <= found.start <= last['l'] + ROAM_SEC):
            return None
        where = address(last.get('a'))
        if where is None:
            return None
        for held in _decode(self.redis.hgetall(self.key('ip', where))):
            if held.get('m') != found.mac and not held.get('b') and held['l'] > last['l']:
                return None
        return found._replace(address=where, bridged=True)

    def record(self, found):
        """Merges one report into its address's sessions."""
        keys = [self.key('ip', found.address)]
        if found.mac:
            keys.append(self.key('mac', found.mac))
        self.redis.eval(RECORD_SCRIPT, len(keys), *keys, found.key, found.user, found.mac or '',
                        found.start, found.seen, '' if found.stopped is None else found.stopped,
                        self.conf.keep_sec, MAX_SESSIONS, int(bool(found.signed)), int(bool(found.bridged)),
                        CLOCK_SLACK, self.conf.grace_sec, found.address)
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
        """The session that held an address at a time, {u, m, s, l, e, a, b}, or None.

        One reported with the address beats one that took it on roaming; then
        the later start wins, and ties go the same way in every worker.
        """
        where = address(where)
        if where is None:
            return None
        covering = [held for held in self._sessions(where)
                    if held['s'] - CLOCK_SLACK <= when <= self._end(held)]
        return max(covering, key=lambda held: (not held.get('b'), held['s'], held['l'], held['u']),
                   default=None)

    def _end(self, held):
        stopped = held.get('e')
        if isinstance(stopped, (int, float)):
            return stopped + CLOCK_SLACK
        return held['l'] + self.conf.grace_sec


def _utc(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
