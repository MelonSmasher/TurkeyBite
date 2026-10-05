"""Signing in and out.

A username that belongs to a local account is checked here, against its
Argon2 hash, whether or not the directory is up: local accounts are the way
in when LDAP is down. Any other username goes to the directory when LDAP is
on. Service accounts cannot sign in at all; they exist to hold API keys.

Failures say the same thing whatever went wrong, so the sign-in page cannot be
used to find out which usernames exist. Five wrong passwords lock a local
account for fifteen minutes, and an address that fails often is slowed down.
"""

import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import __version__, audit, settings_store
from ..config import get_settings
from ..db import get_session
from ..deps import Principal, current_principal, optional_principal
from ..models import User, UserSession
from ..security import crypto, ldap, passwords, sessions, totp
from .common import user_out

router = APIRouter(prefix='/auth', tags=['auth'])

GENERIC = 'Invalid username or password.'

# Failed sign-ins per address, in memory: a coarse brake in front of the
# per-account lockout, which lives in the database and holds across replicas
_IP_WINDOW = 300
_IP_LIMIT = 30
_failures: dict[str, deque] = defaultdict(deque)


def _ip_limited(ip: str | None) -> bool:
    if not ip:
        return False
    window = _failures[ip]
    cutoff = time.monotonic() - _IP_WINDOW
    while window and window[0] < cutoff:
        window.popleft()
    return len(window) >= _IP_LIMIT


def _ip_failed(ip: str | None) -> None:
    if ip:
        _failures[ip].append(time.monotonic())


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)


class MfaBody(BaseModel):
    token: str = Field(max_length=2000)
    code: str = Field(max_length=20)


async def _ldap_config(db: AsyncSession) -> tuple[dict, str]:
    cfg = ldap.config_with_defaults(await settings_store.get(db, 'ldap'))
    secret = ''
    if cfg.get('bind_password_enc'):
        secret = crypto.decrypt(cfg['bind_password_enc'])
    return cfg, secret


@router.get('/config')
async def auth_config(db: AsyncSession = Depends(get_session)) -> dict:
    """What the sign-in page needs to know before anyone has signed in."""
    general = await settings_store.general(db)
    cfg = ldap.config_with_defaults(await settings_store.get(db, 'ldap'))
    return {'org_name': general['org_name'], 'login_banner': general['login_banner'],
            'ldap_enabled': bool(cfg.get('enabled')), 'version': __version__}


async def _finish(db: AsyncSession, user: User, request: Request, response: Response,
                  method: str) -> dict:
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = datetime.now(timezone.utc)
    await sessions.create(db, user, request, response, method)
    audit.record(db, 'auth.login', actor_type='session', actor_name=user.username,
                 actor_id=user.id, request=request, target_type='user', target_id=user.id,
                 details={'method': method})
    await db.commit()
    return {'ok': True, 'user': user_out(user, full=True)}


async def _fail(db: AsyncSession, request: Request, username: str, reason: str,
                user: User | None = None) -> None:
    _ip_failed(sessions.client_ip(request))
    settings = get_settings()
    if user is not None and user.source == 'local':
        user.failed_logins += 1
        if user.failed_logins >= settings.login_max_failures:
            user.locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=settings.login_lockout_minutes)
            user.failed_logins = 0
            reason += '; account locked'
    audit.record(db, 'auth.login', actor_name=username, request=request, outcome='failure',
                 details={'reason': reason})
    await db.commit()


@router.post('/login')
async def login(body: LoginBody, request: Request, response: Response,
                db: AsyncSession = Depends(get_session)) -> dict:
    ip = sessions.client_ip(request)
    if _ip_limited(ip):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            'Too many failed sign-ins from this address. Wait a few minutes.')
    username = body.username.strip()
    user = (await db.execute(select(User).where(
        func.lower(User.username) == username.lower()))).scalar_one_or_none()

    if user is not None and user.source == 'service':
        passwords.verify_password(None, body.password)
        await _fail(db, request, username, 'service accounts cannot sign in')
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC)

    if user is not None and user.source == 'local':
        now = datetime.now(timezone.utc)
        if user.locked_until and user.locked_until > now:
            passwords.verify_password(None, body.password)
            await _fail(db, request, username, 'account locked', None)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC)
        if not passwords.verify_password(user.password_hash, body.password) or user.disabled:
            await _fail(db, request, username, 'wrong password' if not user.disabled
                        else 'account disabled', user)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC)
        if passwords.needs_rehash(user.password_hash):
            user.password_hash = passwords.hash_password(body.password)
        if user.totp_enabled:
            await db.commit()
            return {'ok': False, 'mfa_required': True, 'token': sessions.mfa_token(user)}
        return await _finish(db, user, request, response, 'local')

    cfg, bind_password = await _ldap_config(db)
    if not cfg.get('enabled'):
        passwords.verify_password(None, body.password)
        await _fail(db, request, username, 'no such local account and LDAP is off')
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC)
    try:
        identity = await asyncio.to_thread(ldap.authenticate, cfg, bind_password, username,
                                           body.password)
    except ldap.LdapUnavailable as e:
        audit.record(db, 'auth.login', actor_name=username, request=request, outcome='failure',
                     details={'reason': 'directory unavailable', 'error': str(e)})
        await db.commit()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            'The directory cannot be reached right now. Local accounts can '
                            'still sign in.') from e
    except ldap.LdapNotPermitted as e:
        await _fail(db, request, username, 'no group grants a role')
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            'Your directory account has no access to the console. Ask an '
                            'administrator to add you to a group that does.') from e
    except ldap.LdapInvalidCredentials as e:
        await _fail(db, request, username, 'directory refused the credentials', user)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC) from e

    if user is None:
        user = User(username=identity.username, source='ldap', role=identity.role,
                    display_name=identity.display_name, email=identity.email,
                    ldap_dn=identity.dn, preferences={})
        db.add(user)
        await db.flush()
    else:
        if user.disabled:
            await _fail(db, request, username, 'account disabled')
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC)
        # The directory is the authority on who someone is and what they may do
        user.role = identity.role
        user.display_name = identity.display_name or user.display_name
        user.email = identity.email or user.email
        user.ldap_dn = identity.dn
    return await _finish(db, user, request, response, 'ldap')


@router.post('/mfa')
async def login_mfa(body: MfaBody, request: Request, response: Response,
                    db: AsyncSession = Depends(get_session)) -> dict:
    """The second step: a code from the authenticator app."""
    ip = sessions.client_ip(request)
    if _ip_limited(ip):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            'Too many failed sign-ins from this address. Wait a few minutes.')
    parsed = sessions.read_mfa_token(body.token)
    user = await db.get(User, parsed[0]) if parsed else None
    fingerprint = (user.password_hash or '')[-16:] if user else ''
    if (user is None or not user.totp_enabled or user.disabled or parsed[1] != fingerprint
            or not user.totp_secret_enc):
        _ip_failed(ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            'That sign-in has expired. Start again.')
    step = totp.verify(crypto.decrypt(user.totp_secret_enc), body.code, user.totp_last_step)
    if step is None:
        await _fail(db, request, user.username, 'wrong one-time code', user)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, 'That code is not right.')
    user.totp_last_step = step
    return await _finish(db, user, request, response, 'local+totp')


@router.post('/logout')
async def logout(request: Request, response: Response,
                 principal: Principal | None = Depends(optional_principal),
                 db: AsyncSession = Depends(get_session)) -> dict:
    if principal is not None and principal.session_id is not None:
        session = await db.get(UserSession, principal.session_id)
        if session is not None:
            await db.delete(session)
        audit.record(db, 'auth.logout', principal=principal, request=request)
        await db.commit()
    sessions.clear_cookies(response)
    return {'ok': True}


@router.get('/me')
async def me(principal: Principal = Depends(current_principal),
             db: AsyncSession = Depends(get_session)) -> dict:
    general = await settings_store.general(db)
    user = principal.user
    return {
        'user': user_out(user, full=True),
        'via': principal.kind,
        'permissions': sorted(principal.permissions),
        'preferences': user.preferences or {},
        'org_name': general['org_name'],
        'privacy_mode_default': general['privacy_mode_default'],
        'mfa_required': bool(general['require_mfa_for_local_admins'] and user.source == 'local'
                             and user.role == 'admin' and not user.totp_enabled),
        'version': __version__,
    }
