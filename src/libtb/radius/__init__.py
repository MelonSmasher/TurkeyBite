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
set to someone else's name, so a session is named only by the account behind
its Class, unless `trust_given_names` is on. Once a session has that account,
no name a device gives replaces it.

Filebeat on each NPS server pushes the lines onto their own Valkey list,
`<channel>:nps`. Each worker takes what is waiting there before each batch of
DNS events, and records the session in Valkey under its address: who, which
device, from when, when first and last reported with the address, and when it
stopped. A worker enriching a DNS event asks who held the event's address at
the event's time, and writes that person as bite.client_user and the device as
bite.client_mac.

Who held an address, and when:

  - A session holds its address from its start until it stops, or, while it
    has not, until `grace_sec` after it was last reported: interim updates
    keep a connected device inside that window. Once stopped, the address is
    nobody's, because DHCP may give it to another device, and a lookup
    credited to the wrong person is worse than one credited to nobody. A
    report that names nobody, a stop with an anonymous outer identity say,
    still ends or extends a session already recorded.
  - A device reported with a new address leaves its old one.
  - Before a session was first reported with an address, its hold on it is
    only inferred from its start; another session reported with the address
    at that time wins over it.
  - A phone that roams to another access point stops one session and starts
    another, often before the new one reports an address. A session that
    starts without one, within ROAM_SEC of its device last being reported,
    takes the address the device had then, unless another device has been
    reported with it since; and it loses it to any device reported with the
    address after its own last was.
  - Otherwise, when two sessions cover an event, the one that started later
    wins.

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
Settings = namedtuple('Settings', 'enable zone realms grace_sec keep_sec cache_sec trust_names')
DEFAULT = Settings(False, None, (), 1200, 24 * 3600, 30, False)
KEYS = frozenset(('enable', 'timezone', 'realms', 'grace_sec', 'keep_hours', 'cache_sec', 'trust_given_names'))

# One accounting request. `address` is None when it reported none, `user`
# when it names nobody; `start`, `seen` and `stopped` are epoch seconds,
# `stopped` None while the session lasts. `signed` says the user is the
# account NPS authenticated, `bridged` that the address is the one the device
# had before it roamed, and `reported` when the device was last reported with
# it.
Session = namedtuple('Session', 'address key user mac start seen stopped klass signed bridged reported',
                     defaults=(False, False, None))

ACCESS_ACCEPT, ACCOUNTING_REQUEST = '2', '4'
START, STOP, INTERIM = '1', '2', '3'

# How far apart two clocks may be: NPS's, Filebeat's and the DNS sensor's. An
# event this long before a session's start still counts as in it. A stop is
# taken exactly: the address may go to another device straight after.
CLOCK_SLACK = 60

# How soon after its device was last reported a session that starts without
# an address must start, to take the address the device had: a roam
ROAM_SEC = 120

# Sessions kept per address, the most recently reported, so a busy one still
# has the owners its backlog of DNS events needs
MAX_SESSIONS = 64

# A session longer than this, or a delay, is not believed
MAX_SECONDS = 31 * 24 * 3600

# The most of a line read. A DTS accounting line is about 2 KB.
MAX_LINE = 64 * 1024

# Each consumer process remembers, for cache_sec, the addresses nobody held
CACHE_MAX = 20000

# Names a device gives that are not a person's: an anonymous outer identity
ANONYMOUS = frozenset(('anonymous', 'anon'))

_ATTRIBUTE = re.compile(r'<([A-Za-z][A-Za-z0-9-]*) data_type="\d+">([^<]*)</\1>')
_MAC = re.compile(r'^[0-9a-f]{2}([-:.]?[0-9a-f]{2}){5}$')
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f]')

# Merges one report into an address's sessions, atomically, since workers
# take reports in parallel and a replayed batch hands them over out of order.
#   - A report from before the session recorded under its id started is from
#     an earlier session that used the id, and is ignored. One that starts
#     after the recorded session was last reported is a new session reusing
#     the id, and replaces it.
#   - Otherwise the start is the first reported, the last report the latest,
#     the first report with the address the earliest, and a stop, once seen,
#     stays.
#   - A report that names nobody (user "") only updates a session already
#     recorded, keeping its name. A name NPS authenticated is not replaced by
#     one a device gave.
#   - An address the session reported itself is not demoted to a roam's.
# Then the hash's expiry is renewed, and only the MAX_SESSIONS most recently
# reported sessions are kept. The device's key holds the address it was last
# reported with, when (l), and when it was last reported at all (t). A
# report that gave its address updates it if newer; a roam moves only t and
# renews its expiry, so the roam keeps it while the session lasts, and the
# next roam can follow on. Returns 1 if it recorded the report, 0 if not.
#   KEYS[1] the address's hash; KEYS[2], if given, the device's last address
#   ARGV    session key, user or "", MAC or "", start, seen, stopped or "",
#           seconds to keep, sessions to keep, signed 1/0, bridged 1/0,
#           clock slack, seconds to keep the device's address, the address,
#           for a roam when the device last reported the address or ""
RECORD_SCRIPT = """
local start, seen = tonumber(ARGV[4]), tonumber(ARGV[5])
local stopped = tonumber(ARGV[6])
local user, device = ARGV[2], ARGV[3]
local signed, bridged = ARGV[9] == '1', ARGV[10] == '1'
local slack, reported = tonumber(ARGV[11]), tonumber(ARGV[14])
local first = nil
if not bridged then first = seen end
local old = nil
local held = redis.call('HGET', KEYS[1], ARGV[1])
if held then
  local ok, v = pcall(cjson.decode, held)
  if ok and type(v) == 'table' and type(v.s) == 'number' and type(v.l) == 'number' then old = v end
end
if old and seen < old.s - slack then return 0 end
if old and start > old.l + slack then old = nil end
if old then
  start = old.s
  if old.l > seen then seen = old.l end
  if type(old.e) == 'number' and (stopped == nil or old.e > stopped) then stopped = old.e end
  if user == '' then
    if type(old.u) == 'string' then user = old.u end
    signed = old.a == 1
  elseif old.a == 1 and not signed and type(old.u) == 'string' then
    user, signed = old.u, true
  end
  if device == '' and type(old.m) == 'string' then device = old.m end
  if old.b == nil then bridged = false end
  if reported == nil and type(old.r) == 'number' then reported = old.r end
  if type(old.f) == 'number' and (first == nil or old.f < first) then first = old.f end
end
if user == '' then return 0 end
local value = {u = user, s = start, l = seen}
if device ~= '' then value.m = device end
if stopped then value.e = stopped end
if signed then value.a = 1 end
if first then value.f = first end
if bridged then
  value.b = 1
  if reported then value.r = reported end
end
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
if #KEYS > 1 then
  local now = tonumber(ARGV[5])
  local known = nil
  local last = redis.call('GET', KEYS[2])
  if last then
    local ok, v = pcall(cjson.decode, last)
    if ok and type(v) == 'table' then known = v end
  end
  if bridged then
    if known then
      if type(known.t) ~= 'number' or known.t < now then known.t = now end
      redis.call('SET', KEYS[2], cjson.encode(known), 'EX', tonumber(ARGV[12]))
    end
  elseif not (known and type(known.l) == 'number' and known.l > now) then
    local seen_last = now
    if known and type(known.t) == 'number' and known.t > now then seen_last = known.t end
    redis.call('SET', KEYS[2], cjson.encode({a = ARGV[13], l = now, t = seen_last}), 'EX', tonumber(ARGV[12]))
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
    cache_sec   how long each worker process remembers that nobody held an
                address before asking Valkey again. Who did hold one is
                always asked, so a stop recorded by another worker counts at
                once.
    trust_given_names
                false unless set: a session whose Access-Accept was not seen
                is not named, since the name a device gives can be anyone's.
                On, it is named by that name, when a person's.
    """
    if conf is None:
        return DEFAULT
    if not isinstance(conf, dict):
        raise ValueError('processor.radius must be a mapping')
    unknown = set(map(str, conf)) - KEYS
    if unknown:
        raise ValueError(f'processor.radius: unknown keys {", ".join(sorted(unknown))}')
    enable, trust = conf.get('enable', DEFAULT.enable), conf.get('trust_given_names', DEFAULT.trust_names)
    if not isinstance(enable, bool) or not isinstance(trust, bool):
        raise ValueError('processor.radius.enable and trust_given_names must be true or false')
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
    return Settings(enable, zone, tuple(r.strip().lower() for r in realms), grace, keep_hours * 3600, cache,
                    trust)


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
    without that, or when Filebeat read it over an hour after both, the one
    nearest the access point's Event-Timestamp, which is UTC. The access
    point's clock is not used otherwise: one was seen to be an hour and
    three-quarters out.
    """
    local = _clock(fields.get('Timestamp'))
    if local is None or zone is None:
        return None
    readings = sorted({tz.enfold(local, fold=fold).replace(tzinfo=zone).timestamp() for fold in (0, 1)})
    stamp = _clock(fields.get('Event-Timestamp'))
    stamp = stamp.replace(tzinfo=timezone.utc).timestamp() if stamp is not None else None
    near = received
    if near is not None:
        readings = [reading for reading in readings if reading <= near + CLOCK_SLACK] or readings
        # Filebeat catching up reads both readings well after either
        if stamp is not None and len(readings) > 1 and near - readings[-1] > 3600:
            near = stamp
    else:
        near = stamp
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
    """What HGETALL answered, as {session key: {u, m, s, l, e, a, b, r, f}}, leaving out what cannot be read."""
    out = {}
    for key, raw in (held or {}).items():
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict) and isinstance(value.get('u'), str) \
                and isinstance(value.get('s'), (int, float)) and isinstance(value.get('l'), (int, float)):
            out[key.decode('utf-8', 'replace') if isinstance(key, bytes) else key] = value
    return out


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


class Sessions:
    """The sessions each address has had, in Valkey, shared by every worker.

    In the queue's database, since the librarian sweeps the host lists':

        <prefix>:radius:ip:<address>   hash, session key -> {u, m, s, l, e, a, b, r, f}
        <prefix>:radius:mac:<mac>      the address a device last reported, {a, l, t}
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
        self._nobody = {}

    def key(self, kind, name):
        """The key that holds an address's sessions, a device's address, or a sign-in's account."""
        return f'{self.prefix}:radius:{kind}:{name}'

    def take(self, line, received=None):
        """Records what one line of the log says. Returns what it recorded, or None.

        An Access-Accept is remembered by its Class, for the sessions it signs
        in, and its account returned. An accounting request is recorded as a
        session, or as an update to one already recorded, and returned. Not
        recorded: a line older than `keep_hours`, since Filebeat reads a log
        from its start when it first sees it, and one dated after Filebeat
        read it, which only a wrong timezone does.
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
            self.warn('NPS lines are dated after Filebeat read them, so they are not recorded: is '
                      'processor.radius.timezone the NPS servers\' time zone?')
            return None
        if _whole_hours_out(fields, found.seen):
            self.warn('NPS lines are dated a whole number of hours from their access points\' clocks: '
                      'is processor.radius.timezone the NPS servers\' time zone?')
        found = self._named(found)
        if found.address is None:
            found = self._located(found)
            if found is None:
                return None
        if not found.bridged:
            self._left(found)
        return found if self.record(found) else None

    def _named(self, found):
        """The session with the account NPS authenticated, or with nobody if that was not seen.

        The name the device gave is kept instead only with trust_given_names.
        """
        account = None
        if found.klass:
            account = self.redis.getex(self.key('class', found.klass), ex=self.conf.keep_sec)
        else:
            self.warn('NPS accounting lines carry no Class, so sessions cannot be tied to the account '
                      'NPS signed in. Have the access points send Class back in accounting.')
        if account:
            account = account.decode('utf-8', 'replace') if isinstance(account, bytes) else account
            return found._replace(user=account, signed=True)
        return found if self.conf.trust_names else found._replace(user=None)

    def _device(self, device):
        """What the device's key holds, {a, l, t}, or None."""
        if not device:
            return None
        try:
            last = json.loads(self.redis.get(self.key('mac', device)) or 'null')
        except (TypeError, ValueError):
            return None
        return last if isinstance(last, dict) and _number(last.get('l')) else None

    def _located(self, found):
        """A report without an address, at the address its session is recorded under, or its roam's.

        A stop or an update of a session already recorded at the device's
        last address belongs there, however long the session has lasted.
        Otherwise it may be a roam.
        """
        last = self._device(found.mac)
        where = address(last.get('a')) if last else None
        if where is None:
            return None
        held = _decode(self.redis.hgetall(self.key('ip', where))).get(found.key)
        if held is not None:
            return found._replace(address=where, bridged=bool(held.get('b')), reported=held.get('r'))
        return self._roamed(found, last, where)

    def _roamed(self, found, last, where):
        """The session at the address its device had before it roamed, or None.

        Only for a session that starts within ROAM_SEC of its device's last
        report, with the address or on a roam before, and only if no other
        device has been reported with the address since.
        """
        moments = [last['l']] + ([last['t']] if _number(last.get('t')) else [])
        if not any(abs(found.start - moment) <= ROAM_SEC for moment in moments):
            return None
        for held in _decode(self.redis.hgetall(self.key('ip', where))).values():
            if held.get('m') != found.mac and not held.get('b') and held['l'] > last['l']:
                return None
        return found._replace(address=where, bridged=True, reported=last['l'])

    def _left(self, found):
        """Ends the device's sessions at the address it had, when this report gives it a new one."""
        last = self._device(found.mac)
        before = address(last.get('a')) if last else None
        if before is None or before == found.address or last['l'] > found.seen:
            return
        for key, held in _decode(self.redis.hgetall(self.key('ip', before))).items():
            if held.get('m') == found.mac and not _number(held.get('e')):
                self.record(Session(before, key, None, found.mac, held['s'], found.seen, found.seen, None,
                                    bridged=bool(held.get('b')), reported=held.get('r')), device=False)

    def record(self, found, device=True):
        """Merges one report into its address's sessions. Returns whether it was recorded.

        A report naming nobody only updates a session already recorded.
        `device` False leaves the device's last address alone.
        """
        keys = [self.key('ip', found.address)]
        if found.mac and device:
            keys.append(self.key('mac', found.mac))
        recorded = self.redis.eval(
            RECORD_SCRIPT, len(keys), *keys, found.key, found.user or '', found.mac or '', found.start,
            found.seen, '' if found.stopped is None else found.stopped, self.conf.keep_sec, MAX_SESSIONS,
            int(bool(found.signed)), int(bool(found.bridged)), CLOCK_SLACK, self.conf.grace_sec,
            found.address, '' if found.reported is None else found.reported)
        self._nobody.pop(found.address, None)
        return bool(recorded)

    def _sessions(self, where):
        """An address's sessions. Only that nobody held it is remembered, for cache_sec."""
        now = self.monotonic()
        if self._nobody.get(where, 0) > now:
            return []
        held = list(_decode(self.redis.hgetall(self.key('ip', where))).values())
        if not held and self.conf.cache_sec:
            self._nobody.pop(where, None)
            self._nobody[where] = now + self.conf.cache_sec
            while len(self._nobody) > CACHE_MAX:
                self._nobody.pop(next(iter(self._nobody)))
        return held

    def holder(self, where, when):
        """The session that held an address at a time, {u, m, s, l, e, a, b, r, f}, or None.

        A session that took the address on roaming loses it to another
        device reported with the address after its own device last was. Of
        the rest, one reported with the address by then, or whose device was
        before it roamed, beats one whose hold is only inferred from its
        start; then the later start wins, and ties go the same way in every
        worker.
        """
        where = address(where)
        if where is None:
            return None
        sessions = self._sessions(where)
        covering = [held for held in sessions if held['s'] - CLOCK_SLACK <= when <= self._end(held)]
        # Any device reported with it before the lookup, whether or not it still holds it
        reported = [held for held in sessions if not held.get('b') and held['s'] - CLOCK_SLACK <= when]

        def overruled(held):
            since = held.get('r', held['s'])
            return held.get('b') and any(other.get('m') != held.get('m') and other['l'] > since
                                         for other in reported)

        def confirmed(held):
            # Reported with the address by then: itself, or its device before a roam
            since = held.get('r') if held.get('b') else held.get('f')
            return _number(since) and when >= since - CLOCK_SLACK
        return max((held for held in covering if not overruled(held)),
                   key=lambda held: (confirmed(held), held['s'], held['l'], held['u']), default=None)

    def _end(self, held):
        stopped = held.get('e')
        if _number(stopped):
            return stopped
        return held['l'] + self.conf.grace_sec


def _whole_hours_out(fields, logged):
    """Whether NPS's time, less the delay, is a whole number of hours from the access point's.

    A wrong zone makes it so; an access point that held its accounting for an
    hour does not, since the delay is taken off.

    An access point's clock can be out by anything, so only an offset of whole
    hours, to within CLOCK_SLACK, is taken as the zone's.
    """
    stamp = _clock(fields.get('Event-Timestamp'))
    if stamp is None:
        return False
    out = abs(logged - stamp.replace(tzinfo=timezone.utc).timestamp())
    return out >= 3600 - CLOCK_SLACK and min(out % 3600, 3600 - out % 3600) <= CLOCK_SLACK
