"""Daily counts that outlive the indices they were counted from.

TurkeyBite's retention deletes daily indices after a set number of days, which
is right for records of what each person looked up. Trends over a year still
matter, and need none of that: how many events there were each day, of what
type, how many carried which risk, how many clients were active. Those counts
are kept here, in the console's database, and never anything per person.

An hourly job recounts today and yesterday, so late events are included,
and the first run backfills every day the indices still hold.
"""

import asyncio
import logging
import os
import socket
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from . import db as database
from .models import DailyStat, Lease
from .search.client import SearchClient, SearchError, total
from .search.timerange import TimeRange

log = logging.getLogger(__name__)

HOLDER = f'{socket.gethostname()}:{os.getpid()}'
BACKFILL_DAYS = 400

# dimension -> (field, how many keys to keep)
TERMS = {
    'type': ('bite.type', 10),
    'severity': ('bite.risk_severity', 10),
    'risk': ('bite.risk', 100),
    'purpose': ('bite.purpose', 100),
    'response_code': ('bite.response_code', 20),
}


async def acquire_lease(db: AsyncSession, name: str, seconds: int, holder: str = HOLDER) -> bool:
    """Takes a named lease if it is free or ours. True when we hold it."""
    now = datetime.now(timezone.utc)
    stmt = insert(Lease).values(name=name, holder=holder, expires_at=now + timedelta(seconds=seconds))
    stmt = stmt.on_conflict_do_update(
        index_elements=[Lease.name],
        set_={'holder': holder, 'expires_at': now + timedelta(seconds=seconds)},
        where=(Lease.expires_at < now) | (Lease.holder == holder),
    ).returning(Lease.holder)
    row = (await db.execute(stmt)).first()
    await db.commit()
    return row is not None and row[0] == holder


def day_range(day: date) -> TimeRange:
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return TimeRange(start, start + timedelta(days=1))


async def count_day(search: SearchClient, day: date) -> list[dict]:
    tr = day_range(day)
    aggs = {name: {'terms': {'field': field, 'size': size}} for name, (field, size) in TERMS.items()}
    aggs['clients'] = {'cardinality': {'field': 'bite.client'}}
    aggs['hosts'] = {'cardinality': {'field': 'bite.client_hostname_short'}}
    aggs['users'] = {'cardinality': {'field': 'bite.client_user'}}
    aggs['risky'] = {'filter': {'exists': {'field': 'bite.risk_severity'}}}
    result = await search.search({'size': 0, 'track_total_hits': True,
                                  'query': {'bool': {'filter': [tr.filter()]}}, 'aggs': aggs})
    found = total(result)
    rows = [{'day': day, 'dimension': 'total', 'key': '', 'count': found}]
    if not found:
        return rows
    a = result.get('aggregations') or {}
    for name in TERMS:
        for bucket in (a.get(name) or {}).get('buckets', []):
            rows.append({'day': day, 'dimension': name, 'key': str(bucket['key'])[:300],
                         'count': bucket['doc_count']})
    for name in ('clients', 'hosts', 'users'):
        rows.append({'day': day, 'dimension': 'unique', 'key': name,
                     'count': int((a.get(name) or {}).get('value') or 0)})
    rows.append({'day': day, 'dimension': 'risky', 'key': '',
                 'count': (a.get('risky') or {}).get('doc_count', 0)})
    return rows


async def store(db: AsyncSession, day: date, rows: list[dict]) -> None:
    # A day is replaced whole, so a key that disappeared from it goes too
    from sqlalchemy import delete
    await db.execute(delete(DailyStat).where(DailyStat.day == day))
    if rows:
        await db.execute(insert(DailyStat).values(rows))
    await db.commit()


async def oldest_event_day(search: SearchClient) -> date | None:
    result = await search.search({'size': 0, 'aggs': {'o': {'min': {'field': '@timestamp'}}}})
    value = ((result.get('aggregations') or {}).get('o') or {}).get('value')
    if value is None:
        return None
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).date()


async def run(search: SearchClient, backfill: bool = False) -> int:
    """Recounts today and yesterday, and with `backfill` every day not yet counted."""
    today = datetime.now(timezone.utc).date()
    days = {today, today - timedelta(days=1)}
    async with database.sessionmaker()() as db:
        if backfill:
            oldest = await oldest_event_day(search)
            if oldest is not None:
                have = set((await db.execute(select(DailyStat.day).where(
                    DailyStat.dimension == 'total').distinct())).scalars())
                start = max(oldest, today - timedelta(days=BACKFILL_DAYS))
                day = start
                while day < today:
                    if day not in have:
                        days.add(day)
                    day += timedelta(days=1)
        for day in sorted(days):
            await store(db, day, await count_day(search, day))
    return len(days)


async def has_any(db: AsyncSession) -> bool:
    return bool((await db.execute(select(func.count()).select_from(DailyStat))).scalar_one())


class Rollups:
    def __init__(self, search: SearchClient, every_seconds: int = 3600):
        self.search = search
        self.every_seconds = every_seconds
        self._task: asyncio.Task | None = None
        self.last_run: datetime | None = None
        self.last_error: str | None = None

    async def loop(self) -> None:
        first = True
        while True:
            try:
                async with database.sessionmaker()() as db:
                    mine = await acquire_lease(db, 'rollups', self.every_seconds - 60)
                if mine:
                    await run(self.search, backfill=first)
                    self.last_run = datetime.now(timezone.utc)
                    self.last_error = None
                first = False
            except asyncio.CancelledError:
                raise
            except SearchError as e:
                self.last_error = str(e)
                log.warning('daily rollups could not reach OpenSearch: %s', e)
            except Exception as e:
                self.last_error = f'{type(e).__name__}: {e}'
                log.exception('daily rollups failed')
            await asyncio.sleep(self.every_seconds if not self.last_error else 300)

    def start(self) -> None:
        self._task = asyncio.create_task(self.loop(), name='rollups')

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
