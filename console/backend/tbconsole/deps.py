"""Who is calling, and whether they may: the dependencies every route uses."""

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import settings_store
from .config import get_settings
from .db import get_session
from .models import ApiKey, User
from .search.client import SearchClient
from .security import apikeys, rbac, sessions

_SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}
_KEY_TOUCH_EVERY = timedelta(seconds=60)


@dataclass
class Principal:
    user: User
    kind: str                         # session or apikey
    permissions: frozenset[str]
    session_id: uuid.UUID | None = None
    api_key: ApiKey | None = None
    # A local admin who must set up a second factor before anything else
    mfa_setup_required: bool = False

    @property
    def name(self) -> str:
        if self.api_key is not None:
            return f'{self.user.username} (key {self.api_key.prefix})'
        return self.user.username

    def can(self, permission: str) -> bool:
        return permission in self.permissions


def _bearer(request: Request) -> str | None:
    header = request.headers.get('authorization') or ''
    if header[:7].lower() == 'bearer ':
        return header[7:].strip()
    return request.headers.get('x-api-key')


def origin_ok(request: Request) -> bool:
    """A cross-origin Origin on a cookie-authenticated write is refused outright."""
    origin = request.headers.get('origin')
    if not origin:
        return True
    allowed = {get_settings().public_url.lower(), str(request.base_url).rstrip('/').lower()}
    return origin.rstrip('/').lower() in allowed


async def _from_api_key(db: AsyncSession, request: Request, key: str) -> Principal:
    prefix = apikeys.parse(key)
    row = None
    if prefix:
        row = (await db.execute(select(ApiKey).where(ApiKey.prefix == prefix))).scalar_one_or_none()
    moment = datetime.now(timezone.utc)
    if (row is None or not apikeys.matches(key, row.key_hash) or row.revoked_at is not None
            or (row.expires_at is not None and row.expires_at <= moment) or row.user.disabled):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'invalid or expired API key',
                            headers={'WWW-Authenticate': 'Bearer'})
    if row.last_used_at is None or moment - row.last_used_at >= _KEY_TOUCH_EVERY:
        row.last_used_at = moment
        row.last_used_ip = sessions.client_ip(request)
        await db.commit()
    return Principal(user=row.user, kind='apikey',
                     permissions=rbac.permissions_for(row.user.role, row.scopes), api_key=row)


async def optional_principal(request: Request,
                             db: AsyncSession = Depends(get_session)) -> Principal | None:
    principal = await _principal(request, db)
    # End the transaction the lookup opened, so the connection goes back to
    # the pool now rather than when the response ends: a live tail or an
    # export would otherwise hold one for as long as it streams
    await db.commit()
    return principal


async def _principal(request: Request, db: AsyncSession) -> Principal | None:
    key = _bearer(request)
    if key:
        return await _from_api_key(db, request, key)
    token = request.cookies.get(sessions.SESSION_COOKIE)
    if not token:
        return None
    session = await sessions.lookup(db, token)
    if session is None:
        return None
    if request.method not in _SAFE_METHODS and not (sessions.csrf_ok(request)
                                                    and origin_ok(request)):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            'missing or wrong CSRF token; reload the page and try again')
    user = session.user
    policy = await settings_store.general_cached(db)
    return Principal(user=user, kind='session', permissions=rbac.permissions_for(user.role),
                     session_id=session.id,
                     mfa_setup_required=bool(policy.get('require_mfa_for_local_admins')
                                             and user.source == 'local' and user.role == 'admin'
                                             and not user.totp_enabled))


async def current_principal(principal: Principal | None = Depends(optional_principal)) -> Principal:
    if principal is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'sign in first',
                            headers={'WWW-Authenticate': 'Bearer'})
    return principal


async def session_principal(principal: Principal = Depends(current_principal)) -> Principal:
    """Someone signed in through the browser. An API key acts for integrations
    and has no business with its owner's password, second factor or sessions."""
    if principal.kind != 'session':
        raise HTTPException(status.HTTP_403_FORBIDDEN, 'API keys cannot manage accounts; sign in')
    return principal


def require(*permissions: str):
    """A dependency that admits only callers holding every one of `permissions`."""
    async def check(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.mfa_setup_required:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                'Set up two-factor authentication on your account first.')
        missing = [p for p in permissions if not principal.can(p)]
        if missing:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f'this needs the {", ".join(missing)} permission')
        return principal
    return check


def search_client(request: Request) -> SearchClient:
    return request.app.state.search
