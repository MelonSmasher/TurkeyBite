"""Browser sessions: an opaque token in an HttpOnly cookie, its hash in Postgres.

A session ends when it has been idle for session_idle_minutes, when it is
older than session_max_hours, when its user is disabled, when their password
changes, or when they sign out. A second cookie, readable by the page, holds
a CSRF token that every state-changing request must echo in a header: a
cross-site form can make the browser send the cookies but cannot read one to
copy it.
"""

import base64
import hmac
import ipaddress
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Request, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..models import User, UserSession
from .crypto import mac, sha256

SESSION_COOKIE = 'tbc_session'
CSRF_COOKIE = 'tbc_csrf'
CSRF_HEADER = 'x-csrf-token'
# last_seen_at is written at most this often, not on every request
TOUCH_EVERY = timedelta(seconds=60)
MFA_TOKEN_SECONDS = 300


def now() -> datetime:
    return datetime.now(timezone.utc)


def client_ip(request: Request) -> str | None:
    """The caller's address, if it is one. Behind a trusted proxy the address
    comes from a header that a client may have written, so anything that is
    not an IP address is dropped rather than stored or counted as given."""
    host = request.client.host if request.client else None
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host.split('%', 1)[0]))
    except ValueError:
        return None


async def create(db: AsyncSession, user: User, request: Request, response: Response,
                 method: str) -> UserSession:
    settings = get_settings()
    token = secrets.token_urlsafe(32)
    moment = now()
    session = UserSession(
        token_hash=sha256(token), user_id=user.id, created_at=moment, last_seen_at=moment,
        expires_at=moment + timedelta(hours=settings.session_max_hours),
        ip=client_ip(request), user_agent=(request.headers.get('user-agent') or '')[:400],
        method=method)
    db.add(session)
    set_cookies(response, token)
    return session


def set_cookies(response: Response, token: str) -> None:
    settings = get_settings()
    max_age = settings.session_max_hours * 3600
    response.set_cookie(SESSION_COOKIE, token, max_age=max_age, httponly=True,
                        secure=settings.cookie_secure, samesite='lax', path='/')
    response.set_cookie(CSRF_COOKIE, secrets.token_urlsafe(24), max_age=max_age, httponly=False,
                        secure=settings.cookie_secure, samesite='lax', path='/')


def clear_cookies(response: Response) -> None:
    settings = get_settings()
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path='/', secure=settings.cookie_secure, samesite='lax')


async def lookup(db: AsyncSession, token: str) -> UserSession | None:
    """The live session for a cookie's token, touched, or None."""
    if not token or len(token) > 200:
        return None
    session = (await db.execute(
        select(UserSession).where(UserSession.token_hash == sha256(token)))).scalar_one_or_none()
    if session is None:
        return None
    settings = get_settings()
    moment = now()
    user = session.user
    expired = (
        session.expires_at <= moment
        or session.last_seen_at + timedelta(minutes=settings.session_idle_minutes) <= moment
        or user.disabled
        or (user.password_changed_at is not None and session.created_at < user.password_changed_at)
    )
    if expired:
        await db.delete(session)
        await db.commit()
        return None
    if moment - session.last_seen_at >= TOUCH_EVERY:
        session.last_seen_at = moment
        await db.commit()
    return session


async def end_all(db: AsyncSession, user_id: uuid.UUID, keep: uuid.UUID | None = None) -> None:
    stmt = delete(UserSession).where(UserSession.user_id == user_id)
    if keep is not None:
        stmt = stmt.where(UserSession.id != keep)
    await db.execute(stmt)


def csrf_ok(request: Request) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE) or ''
    header = request.headers.get(CSRF_HEADER) or ''
    return bool(cookie) and hmac.compare_digest(cookie, header)


# -- the second step of a sign-in with a one-time password --------------------

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def mfa_token(user: User) -> str:
    """Proof that the password was right, good for five minutes, for one user."""
    issued = time.time()
    payload = json.dumps({'u': str(user.id), 'e': int(issued) + MFA_TOKEN_SECONDS, 'i': issued,
                          'p': user.password_hash[-16:] if user.password_hash else ''},
                         separators=(',', ':')).encode('utf-8')
    return _b64(payload) + '.' + _b64(mac('mfa', payload))


def read_mfa_token(token: str) -> tuple[uuid.UUID, str, float] | None:
    """(user id, password fingerprint, when issued) from a valid, unexpired
    token, else None."""
    try:
        body, signature = token.split('.', 1)
        payload = _unb64(body)
        if not hmac.compare_digest(_unb64(signature), mac('mfa', payload)):
            return None
        data = json.loads(payload)
        if int(data['e']) < time.time():
            return None
        return uuid.UUID(data['u']), data.get('p', ''), float(data.get('i', 0))
    except (ValueError, KeyError, TypeError):
        return None
