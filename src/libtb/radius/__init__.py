"""Who held an address, from Windows NPS's RADIUS accounting log.

A DNS event carries only the address that asked. On Wi-Fi that is a phone or
a laptop whose reverse DNS name, when it has one, is whatever the device
called itself, and every iPhone calls itself iPhone: one "machine" with the
traffic of hundreds of people. The RADIUS server knows better. For every
802.1X session, each access point reports the user who signed in, the
device's MAC address and, once the device has one, its address: when the
session starts, every interim interval while it lasts, and when it stops.

NPS writes those accounting requests to its log. In DTS format each is one
line of flat XML, of which this reads

    Acct-Status-Type    1 start, 3 interim update, 2 stop
    User-Name           jsmith@example.edu
    Framed-IP-Address   the device's address
    Calling-Station-Id  the device's MAC address, BA-F7-F8-3B-6D-36
    Acct-Session-Id     with NAS-Identifier, which session this is
    Event-Timestamp     when, by the access point's clock, in UTC
    Acct-Session-Time   seconds since the session started

Filebeat on each NPS server pushes the lines onto the queue the beats already
use, as events of type `nps`. A worker that takes one records the session in
Valkey under its address: who, which device, from when, and when it was last
reported. A worker enriching a DNS event asks who held the event's address at
the event's time, and writes that person as bite.client_user and the device as
bite.client_mac, so findings and profiles name the person.

A session counts from its start until `grace_sec` after it was last reported,
stopped or not. Interim updates keep a connected device inside that window.
After a stop, the device's address stays its own for the same while: a phone
that roams to another access point stops one session and starts another, and
DHCP does not hand a just-used address to another device that soon. When two
sessions cover an event, the later one wins.

What it cannot do: a session is only known once an access point reports it
with an address, which for many access points is the first interim update,
not the start. Lookups a device makes before then are recorded without a user.
Records are written last write wins, so one handled out of order, as a
replayed batch can be, can only shorten a session, by one interim interval.
"""

import html
import ipaddress
import json
import re
import time
from collections import namedtuple
from datetime import datetime, timezone

# processor.radius
Settings = namedtuple('Settings', 'enable realms grace_sec keep_sec cache_sec')
DEFAULT = Settings(False, (), 1200, 24 * 3600, 30)
KEYS = frozenset(('enable', 'realms', 'grace_sec', 'keep_hours', 'cache_sec'))

# One session as an accounting request reports it. `key` tells it from the
# others an address has had; `start` and `seen` are epoch seconds.
Session = namedtuple('Session', 'address key user mac start seen')

# NPS logs authentication requests too when told to. Only accounting requests
# carry the address.
ACCOUNTING_REQUEST = '4'
STATUSES = frozenset(('1', '2', '3'))

# How far apart two clocks may be: the access point's, Filebeat's, and the DNS
# sensor's. An event this much before a session's start still counts as in it.
CLOCK_SLACK = 60

# Sessions kept per address, the most recently reported; a lab machine's
# address can see a new one every class
MAX_SESSIONS = 8

# A session longer than this is not believed, and is counted from its report
MAX_SESSION_SECONDS = 31 * 24 * 3600

# The most of a line read. A DTS accounting line is about 2 KB.
MAX_LINE = 64 * 1024

# Each consumer process remembers what it last read for an address
CACHE_MAX = 20000

_ATTRIBUTE = re.compile(r'<([A-Za-z][A-Za-z0-9-]*) data_type="\d+">([^<]*)</\1>')
_MAC = re.compile(r'^[0-9a-f]{2}([-:.]?[0-9a-f]{2}){5}$')


def settings(conf):
    r"""processor.radius, checked: unknown keys or bad values stop the worker at start.

    enable      false unless set; with it off `nps` events are dropped and DNS
                events are left as they were
    realms      the organisation's own realms, such as [example.edu], or the
                NetBIOS domain, such as [EXAMPLE]: jsmith@example.edu and
                EXAMPLE\jsmith are recorded as jsmith, as Browserbeat reports a
                person. Anyone else's realm, an eduroam visitor's, is kept.
    grace_sec   how long after a session was last reported its address is
                still taken as that person's. Above the access points' interim
                interval, or a connected device drops out between updates.
    keep_hours  how long Valkey keeps an address's sessions after the last
                report, for a backlog of DNS events to be matched against
    cache_sec   how long each worker process reuses what it read for an
                address before asking Valkey again
    """
    if conf is None:
        return DEFAULT
    if not isinstance(conf, dict):
        raise ValueError('processor.radius must be a mapping')
    unknown = set(conf) - KEYS
    if unknown:
        raise ValueError(f'processor.radius: unknown keys {", ".join(sorted(unknown))}')
    enable = conf.get('enable', DEFAULT.enable)
    if not isinstance(enable, bool):
        raise ValueError('processor.radius.enable must be true or false')
    realms = conf.get('realms') or []
    if not isinstance(realms, list) or not all(isinstance(r, str) and r.strip() for r in realms):
        raise ValueError('processor.radius.realms must be a list of realm names')
    grace = _bounded(conf, 'grace_sec', DEFAULT.grace_sec, 60, 86400)
    keep_hours = _bounded(conf, 'keep_hours', DEFAULT.keep_sec // 3600, 1, 24 * 14)
    cache = _bounded(conf, 'cache_sec', DEFAULT.cache_sec, 0, 600)
    return Settings(enable, tuple(r.strip().lower() for r in realms), grace, keep_hours * 3600, cache)


def _bounded(conf, name, default, low, high):
    value = conf.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f'processor.radius.{name} must be a whole number from {low} to {high}')
    return value


def attributes(line):
    """The attributes of one DTS accounting line, by name. A repeated one keeps its first value."""
    found = {}
    if not isinstance(line, str) or len(line) > MAX_LINE:
        return found
    for name, value in _ATTRIBUTE.findall(line):
        found.setdefault(name, html.unescape(value).strip())
    return found


def username(value, realms=()):
    """The person a User-Name names, lower-cased, or None.

    A computer signing in on its own account, host/LAB-12.example.edu, is not
    a person, and its reverse DNS name already names it.
    """
    if not isinstance(value, str):
        return None
    name = value.strip().lower()
    if not name or len(name) > 256 or name.startswith('host/'):
        return None
    if '\\' in name:
        domain, _, bare = name.partition('\\')
        if domain in realms and bare:
            return bare
    elif '@' in name:
        bare, _, realm = name.rpartition('@')
        if realm in realms and bare:
            return bare
    return name


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
    """A Framed-IP-Address a device can have, or None.

    255.255.255.254 and 255.255.255.255 are RADIUS's own values for "the NAS
    chooses" and "the user chooses", not addresses.
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
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


def _nps_utc(value):
    """The Event-Timestamp NPS logs, 10/07/2026 22:19:32, which is UTC, as epoch seconds, or None."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value.strip(), '%m/%d/%Y %H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _seconds(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def event_time(fields, received):
    """When an accounting request's event happened, as epoch seconds, or None.

    Event-Timestamp is the access point's own clock. One later than Filebeat
    read the line cannot be right, so then, or without one, it is the time
    the line was read less Acct-Delay-Time, which is how long the access
    point had been trying to send it.
    """
    stamp = _nps_utc(fields.get('Event-Timestamp'))
    if stamp is not None and (received is None or stamp <= received + CLOCK_SLACK):
        return stamp
    if received is None:
        return None
    delay = min(_seconds(fields.get('Acct-Delay-Time')) or 0, MAX_SESSION_SECONDS)
    return received - delay


def session(fields, received, realms=()):
    """The session an accounting request reports, or None if it names no address or no person."""
    if fields.get('Packet-Type', ACCOUNTING_REQUEST) != ACCOUNTING_REQUEST:
        return None
    if fields.get('Acct-Status-Type') not in STATUSES:
        return None
    where = address(fields.get('Framed-IP-Address'))
    who = username(fields.get('User-Name'), realms)
    sid = fields.get('Acct-Session-Id')
    if not (where and who and sid):
        return None
    when = event_time(fields, received)
    if when is None:
        return None
    length = _seconds(fields.get('Acct-Session-Time'))
    start = when - length if length is not None and length <= MAX_SESSION_SECONDS else when
    nas = fields.get('NAS-Identifier') or fields.get('NAS-IP-Address') or ''
    return Session(where, f'{nas}|{sid}'[:200], who, mac(fields.get('Calling-Station-Id')), start, when)


def _decode(held):
    """What HGETALL answered, as {session key: {u, m, s, l}}, leaving out what cannot be read."""
    out = {}
    for key, raw in (held or {}).items():
        try:
            value = json.loads(raw)
            if isinstance(value, dict) and isinstance(value.get('u'), str) \
                    and isinstance(value.get('s'), (int, float)) and isinstance(value.get('l'), (int, float)):
                out[key.decode('utf-8', 'replace') if isinstance(key, bytes) else key] = value
        except (TypeError, ValueError):
            continue
    return out


class Sessions:
    """The sessions each address has had, in Valkey, shared by every worker.

    One hash per address, `<channel>:radius:<address>`, in the queue's
    database, mapping each session to {u: user, m: MAC, s: start, l: last
    reported}. The host lists' database is swept by the librarian, so it is
    not used. Each hash expires `keep_hours` after its last report.
    """

    def __init__(self, redis, prefix, conf, monotonic=time.monotonic):
        """Keys start with `prefix`, the queue's channel; `conf` is processor.radius."""
        self.redis = redis
        self.prefix = prefix
        self.conf = conf
        self.monotonic = monotonic
        self._cache = {}

    def key(self, where):
        """The hash that holds an address's sessions."""
        return f'{self.prefix}:radius:{where}'

    def record(self, found):
        """Records a session as last reported."""
        key = self.key(found.address)
        value = json.dumps({'u': found.user, 'm': found.mac, 's': found.start, 'l': found.seen},
                           separators=(',', ':'))
        pipe = self.redis.pipeline(transaction=False)
        pipe.hset(key, found.key, value)
        pipe.expire(key, self.conf.keep_sec)
        pipe.hlen(key)
        count = pipe.execute()[-1]
        if count > MAX_SESSIONS:
            held = _decode(self.redis.hgetall(key))
            oldest = sorted(held, key=lambda k: held[k]['l'])[:len(held) - MAX_SESSIONS]
            if oldest:
                self.redis.hdel(key, *oldest)
        # This process at least sees the change at once
        self._cache.pop(found.address, None)

    def _sessions(self, where):
        now = self.monotonic()
        hit = self._cache.get(where)
        if hit is not None and hit[0] > now:
            return hit[1]
        held = list(_decode(self.redis.hgetall(self.key(where))).values())
        if self.conf.cache_sec:
            self._cache.pop(where, None)
            self._cache[where] = (now + self.conf.cache_sec, held)
            while len(self._cache) > CACHE_MAX:
                self._cache.pop(next(iter(self._cache)))
        return held

    def holder(self, where, when):
        """The session that held an address at a time, {u, m, s, l}, or None."""
        covering = [held for held in self._sessions(where)
                    if held['s'] - CLOCK_SLACK <= when <= held['l'] + self.conf.grace_sec]
        return max(covering, key=lambda held: held['s'], default=None)
