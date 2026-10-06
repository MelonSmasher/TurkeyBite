"""Time ranges and histogram intervals.

The UI sends a range as `from` and `to`, each either an ISO 8601 instant or a
relative expression such as `now-24h`. Everything is resolved to UTC instants
here, once, so every query that serves one screen counts the same window even
though they run a few milliseconds apart.

Rounding (`now/d`, today so far) happens in the caller's time zone, which the
app sends as an X-Timezone header, so "today" starts at their midnight, not
UTC's; daily histogram buckets follow the same zone. Without the header, UTC.
"""

import re
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_UNITS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 7 * 86400, 'M': 30 * 86400, 'y': 365 * 86400}
# Seconds per unit of a relative time, as TBQL's date math also counts them
UNIT_SECONDS = _UNITS
_RELATIVE = re.compile(r'^now(?:([+-])(\d+)([smhdwMy]))?(?:/([smhdwMy]))?$')

# Histogram bucket sizes, smallest first, and their OpenSearch names
INTERVALS = (
    (60, '1m'), (5 * 60, '5m'), (10 * 60, '10m'), (15 * 60, '15m'), (30 * 60, '30m'),
    (3600, '1h'), (3 * 3600, '3h'), (6 * 3600, '6h'), (12 * 3600, '12h'), (86400, '1d'),
    (7 * 86400, '7d'),
)

# The longest window one request may cover: index retention is 90 days by
# default, and a year of events in one aggregation is a cluster-wide outage
MAX_RANGE = timedelta(days=400)


class RangeError(ValueError):
    """A time or range from a request that cannot be used, in words for the caller."""


_zone: ContextVar[str] = ContextVar('tbconsole_zone', default='UTC')


def use_zone(name: str | None) -> None:
    """Rounds relative times in `name` for the rest of this request.

    An unknown or malformed zone is ignored rather than refused: it only shifts
    days.
    """
    if not name or len(name) > 64:
        return
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return
    _zone.set(name)


def zone_name() -> str:
    """The time zone this request rounds relative times in."""
    return _zone.get()


def utcnow() -> datetime:
    """The time now, in UTC."""
    return datetime.now(timezone.utc)


def _round_down(moment: datetime, unit: str) -> datetime:
    if unit == 's':
        return moment.replace(microsecond=0)
    if unit == 'm':
        return moment.replace(second=0, microsecond=0)
    if unit == 'h':
        return moment.replace(minute=0, second=0, microsecond=0)
    if unit == 'd':
        return moment.replace(hour=0, minute=0, second=0, microsecond=0)
    if unit == 'w':
        day = moment.replace(hour=0, minute=0, second=0, microsecond=0)
        return day - timedelta(days=day.weekday())
    if unit == 'M':
        return moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return moment.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)


def resolve(value: str | None, now: datetime, default: str) -> datetime:
    """An instant from an ISO string or a relative expression."""
    value = (value or default).strip()
    m = _RELATIVE.match(value)
    if m:
        sign, amount, unit, rounding = m.groups()
        moment = now
        if amount:
            if len(amount) > 9:
                raise RangeError(f'{value!r} reaches too far')
            try:
                delta = timedelta(seconds=int(amount) * _UNITS[unit])
                moment = moment - delta if sign == '-' else moment + delta
            except OverflowError as e:
                raise RangeError(f'{value!r} reaches too far') from e
            if not EARLIEST <= moment.year <= LATEST:
                raise RangeError(f'{value!r} reaches too far')
        if rounding:
            zone = ZoneInfo(_zone.get())
            moment = _round_down(moment.astimezone(zone), rounding).astimezone(timezone.utc)
        return moment
    try:
        return parse_moment(value)
    except RangeError as e:
        raise RangeError(f'{value!r} is neither a time nor a relative time such as now-24h') from e


# The years a time may fall in: anything else is a typing slip, and near the
# ends of what Python can hold, arithmetic on it overflows
EARLIEST, LATEST = 1970, 2200


def parse_moment(value: str) -> datetime:
    """An ISO 8601 time in UTC; one without a zone is taken as UTC."""
    try:
        moment = datetime.fromisoformat(str(value).strip().replace('Z', '+00:00'))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        moment = moment.astimezone(timezone.utc)
    except (ValueError, OverflowError) as e:
        raise RangeError(f'{value!r} is not a time') from e
    if not EARLIEST <= moment.year <= LATEST:
        raise RangeError(f'{value!r} is outside the years {EARLIEST} to {LATEST}')
    return moment


@dataclass(frozen=True)
class TimeRange:
    """A window of time in UTC, from `start` up to but not including `end`."""

    start: datetime
    end: datetime

    @property
    def seconds(self) -> float:
        """How long the range is, in seconds."""
        return (self.end - self.start).total_seconds()

    def previous(self) -> 'TimeRange':
        """The window of the same length just before this one, for comparisons."""
        span = self.end - self.start
        return TimeRange(self.start - span, self.start)

    def filter(self, field: str = '@timestamp') -> dict:
        """A query clause for the events in the range, by `field`."""
        return {'range': {field: {'gte': iso(self.start), 'lt': iso(self.end)}}}

    def public(self) -> dict:
        """The range as the API shows it."""
        return {'from': iso(self.start), 'to': iso(self.end)}


def parse_range(start: str | None, end: str | None, now: datetime | None = None,
                default_start: str = 'now-24h') -> TimeRange:
    """The range a request's from and to name, which has to run forwards and not be too long."""
    now = now or utcnow()
    tr = TimeRange(resolve(start, now, default_start), resolve(end, now, 'now'))
    if tr.end <= tr.start:
        raise RangeError('the end of the range has to come after its start')
    if tr.end - tr.start > MAX_RANGE:
        raise RangeError(f'a range can cover at most {MAX_RANGE.days} days')
    return tr


def iso(moment: datetime) -> str:
    """A time as ISO 8601 text in UTC, to the millisecond."""
    return moment.astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def auto_interval(tr: TimeRange, buckets: int = 90) -> tuple[int, str]:
    """The smallest interval that keeps a histogram at or under `buckets` bars."""
    for seconds, name in INTERVALS:
        if tr.seconds / seconds <= buckets:
            return seconds, name
    return INTERVALS[-1]


def interval_seconds(name: str) -> int:
    """The length of a named histogram interval, in seconds."""
    for seconds, label in INTERVALS:
        if label == name:
            return seconds
    raise RangeError(f'{name!r} is not an interval this console offers')
