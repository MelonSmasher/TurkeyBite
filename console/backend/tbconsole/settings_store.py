"""Settings admins change in the console, kept as JSON documents by key."""

import time
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from .models import Setting

# The ranges a page may open on: the app's own presets
DEFAULT_RANGES = ('now-15m', 'now-1h', 'now-4h', 'now-24h', 'now/d', 'now-7d', 'now-14d', 'now-30d')

GENERAL_DEFAULTS = {
    'org_name': 'TurkeyBite',
    # Shown on the sign-in page, for an acceptable-use notice
    'login_banner': '',
    # The time range pages open on, until someone picks another
    'default_range': 'now-24h',
    # Local admins must have a second factor before they can do anything else
    'require_mfa_for_local_admins': False,
    # Mask people's identities everywhere until someone chooses to reveal them
    'privacy_mode_default': False,
    # Device lookup: where the console asks another system, such as a
    # security console, what its inventories know about an address, and the
    # webhook whose secret and headers sign the question. Both empty, off
    'device_lookup_url': '',
    'device_lookup_webhook_id': '',
}


async def get(db: AsyncSession, key: str, defaults: dict | None = None) -> dict:
    """The settings saved under `key`, over `defaults`."""
    row = await db.get(Setting, key)
    merged = dict(defaults or {})
    if row is not None:
        merged.update(row.value or {})
    return merged


async def put(db: AsyncSession, key: str, value: dict, user_id: uuid.UUID | None) -> None:
    """Saves `value` under `key`, noting who saved it; the caller commits."""
    forget_cache()
    row = await db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value, updated_by_id=user_id))
    else:
        row.value = value
        row.updated_by_id = user_id


async def general(db: AsyncSession) -> dict:
    """The general settings, with the defaults for any not saved."""
    return await get(db, 'general', GENERAL_DEFAULTS)


# The general settings are read on every request that checks the MFA policy,
# so they are cached briefly in each process
_CACHE_SECONDS = 15.0
_cache: tuple[float, dict] | None = None


def forget_cache() -> None:
    """Drops this process's cached general settings, so the next read is fresh."""
    global _cache
    _cache = None


async def general_cached(db: AsyncSession) -> dict:
    """The general settings, read at most every few seconds in each process."""
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < _CACHE_SECONDS:
        return _cache[1]
    value = await general(db)
    _cache = (now, value)
    return value
