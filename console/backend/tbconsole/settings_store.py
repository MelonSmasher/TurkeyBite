"""Settings admins change in the console, kept as JSON documents by key."""

import time
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from .models import Setting

GENERAL_DEFAULTS = {
    'org_name': 'TurkeyBite',
    # Shown on the sign-in page, for an acceptable-use notice
    'login_banner': '',
    'default_range': 'now-24h',
    # Local admins must have a second factor before they can do anything else
    'require_mfa_for_local_admins': False,
    # Mask people's identities everywhere until someone chooses to reveal them
    'privacy_mode_default': False,
}


async def get(db: AsyncSession, key: str, defaults: dict | None = None) -> dict:
    row = await db.get(Setting, key)
    merged = dict(defaults or {})
    if row is not None:
        merged.update(row.value or {})
    return merged


async def put(db: AsyncSession, key: str, value: dict, user_id: uuid.UUID | None) -> None:
    forget_cache()
    row = await db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value, updated_by_id=user_id))
    else:
        row.value = value
        row.updated_by_id = user_id


async def general(db: AsyncSession) -> dict:
    return await get(db, 'general', GENERAL_DEFAULTS)


# The general settings are read on every request that checks the MFA policy,
# so they are cached briefly in each process
_CACHE_SECONDS = 15.0
_cache: tuple[float, dict] | None = None


def forget_cache() -> None:
    global _cache
    _cache = None


async def general_cached(db: AsyncSession) -> dict:
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < _CACHE_SECONDS:
        return _cache[1]
    value = await general(db)
    _cache = (now, value)
    return value
