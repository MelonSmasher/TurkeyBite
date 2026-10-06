"""A person's own account: profile, preferences, password, second factor, sessions."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..db import get_session
from ..deps import Principal, session_principal
from ..models import UserSession
from ..security import crypto, limits, passwords, sessions, totp
from .common import parse_uuid, ts, user_out

router = APIRouter(prefix='/account', tags=['account'])

THEMES = ('light', 'dark', 'system')
ACCENTS = ('iris', 'ocean', 'forest', 'ember', 'rose', 'slate')
DENSITIES = ('comfortable', 'compact')


class ProfileBody(BaseModel):
    display_name: str | None = Field(None, max_length=200)
    email: str | None = Field(None, max_length=320)


class PreferencesBody(BaseModel):
    theme: str | None = None
    accent: str | None = None
    density: str | None = None
    timezone: str | None = Field(None, max_length=60)
    privacy_mode: bool | None = None
    sidebar_collapsed: bool | None = None
    columns: list[str] | None = None


class PasswordBody(BaseModel):
    current: str = Field(max_length=1024)
    new: str = Field(max_length=1024)


class CodeBody(BaseModel):
    code: str = Field(max_length=20)


class PasswordOnly(BaseModel):
    password: str = Field(max_length=1024)


DisableMfaBody = PasswordOnly


def _local_only(principal: Principal) -> None:
    if principal.user.source != 'local':
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            'This account is managed by the directory; change it there.')


@router.patch('')
async def update_profile(body: ProfileBody, request: Request,
                         principal: Principal = Depends(session_principal),
                         db: AsyncSession = Depends(get_session)) -> dict:
    _local_only(principal)
    user = await db.merge(principal.user)
    if body.display_name is not None:
        user.display_name = body.display_name.strip() or None
    if body.email is not None:
        user.email = body.email.strip() or None
    audit.record(db, 'account.update', principal=principal, request=request,
                 target_type='user', target_id=user.id)
    await db.commit()
    return user_out(user, full=True)


@router.put('/preferences')
async def update_preferences(body: PreferencesBody,
                             principal: Principal = Depends(session_principal),
                             db: AsyncSession = Depends(get_session)) -> dict:
    user = await db.merge(principal.user)
    prefs = dict(user.preferences or {})
    data = body.model_dump(exclude_none=True)
    if data.get('theme') and data['theme'] not in THEMES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'theme is one of {", ".join(THEMES)}')
    if data.get('accent') and data['accent'] not in ACCENTS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'accent is one of {", ".join(ACCENTS)}')
    if data.get('density') and data['density'] not in DENSITIES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f'density is one of {", ".join(DENSITIES)}')
    # Only what was sent changes: a tab that changes the theme cannot put back
    # a privacy setting another tab has since changed
    prefs.pop('updated_at', None)
    prefs.update(data)
    user.preferences = prefs
    await db.commit()
    return prefs


async def _check_password(db: AsyncSession, request: Request, principal: Principal, user,
                          password: str, action: str) -> None:
    """The account's own password, asked again before a sensitive change. A
    session left open on someone's desk is not a way to guess it: wrong answers
    count against the same brake as sign-ins."""
    ip = sessions.client_ip(request)
    if limits.limited(ip, user.username):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            'Too many wrong passwords. Wait a few minutes and try again.')
    if not await passwords.verify_async(user.password_hash, password):
        limits.failed(ip, user.username)
        audit.record(db, action, principal=principal, request=request,
                     outcome='failure', details={'reason': 'wrong password'})
        await db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'The password is not right.')


@router.post('/password')
async def change_password(body: PasswordBody, request: Request, response: Response,
                          principal: Principal = Depends(session_principal),
                          db: AsyncSession = Depends(get_session)) -> dict:
    _local_only(principal)
    user = await db.merge(principal.user)
    await _check_password(db, request, principal, user, body.current, 'account.password')
    problems = passwords.password_problems(body.new, user.username)
    if problems:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, ' '.join(problems))
    user.password_hash = await passwords.hash_async(body.new)
    # Every session from before ends, so a password someone else knew stops
    # working everywhere; this browser gets a new session in its place
    user.password_changed_at = datetime.now(timezone.utc)
    await sessions.end_all(db, user.id)
    await sessions.create(db, user, request, response, 'password')
    audit.record(db, 'account.password', principal=principal, request=request)
    await db.commit()
    return {'ok': True}


@router.post('/mfa/setup')
async def mfa_setup(body: PasswordOnly, request: Request,
                    principal: Principal = Depends(session_principal),
                    db: AsyncSession = Depends(get_session)) -> dict:
    """A new secret, pending until a code from it is confirmed.

    Asks for the password, so a borrowed session cannot bind the account to
    someone else's authenticator and lock its owner out.
    """
    _local_only(principal)
    user = await db.merge(principal.user)
    await _check_password(db, request, principal, user, body.password, 'account.mfa_setup')
    if user.totp_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            'Two-factor authentication is already on. Turn it off first.')
    secret = totp.new_secret()
    user.totp_secret_enc = crypto.encrypt(secret)
    user.totp_last_step = None
    audit.record(db, 'account.mfa_setup', principal=principal, request=request)
    await db.commit()
    return {'secret': secret, 'uri': totp.provisioning_uri(secret, user.username)}


@router.post('/mfa/enable')
async def mfa_enable(body: CodeBody, request: Request,
                     principal: Principal = Depends(session_principal),
                     db: AsyncSession = Depends(get_session)) -> dict:
    _local_only(principal)
    user = await db.merge(principal.user)
    if user.totp_enabled or not user.totp_secret_enc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Start setting it up first.')
    try:
        secret = crypto.decrypt(user.totp_secret_enc)
    except crypto.SecretUnreadable as e:
        raise HTTPException(status.HTTP_409_CONFLICT, 'Start setting it up again.') from e
    step = totp.verify(secret, body.code, None)
    if step is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            'That code is not right. Check the time on your phone and try again.')
    user.totp_enabled = True
    user.totp_last_step = step
    audit.record(db, 'account.mfa_enabled', principal=principal, request=request)
    await db.commit()
    return {'ok': True}


@router.post('/mfa/disable')
async def mfa_disable(body: DisableMfaBody, request: Request,
                      principal: Principal = Depends(session_principal),
                      db: AsyncSession = Depends(get_session)) -> dict:
    _local_only(principal)
    user = await db.merge(principal.user)
    await _check_password(db, request, principal, user, body.password, 'account.mfa_disabled')
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_last_step = None
    audit.record(db, 'account.mfa_disabled', principal=principal, request=request)
    await db.commit()
    return {'ok': True}


@router.get('/sessions')
async def list_sessions(principal: Principal = Depends(session_principal),
                        db: AsyncSession = Depends(get_session)) -> list[dict]:
    rows = (await db.execute(select(UserSession).where(UserSession.user_id == principal.user.id)
                             .order_by(UserSession.last_seen_at.desc()))).scalars().all()
    now = datetime.now(timezone.utc)
    return [{'id': str(s.id), 'created_at': ts(s.created_at), 'last_seen_at': ts(s.last_seen_at),
             'expires_at': ts(s.expires_at), 'ip': s.ip, 'user_agent': s.user_agent,
             'method': s.method, 'current': s.id == principal.session_id,
             'active': s.expires_at > now} for s in rows]


@router.delete('/sessions/{session_id}')
async def end_session(session_id: str, request: Request,
                      principal: Principal = Depends(session_principal),
                      db: AsyncSession = Depends(get_session)) -> dict:
    session = await db.get(UserSession, parse_uuid(session_id, 'That session'))
    if session is None or session.user_id != principal.user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That session does not exist')
    await db.delete(session)
    audit.record(db, 'account.session_ended', principal=principal, request=request,
                 target_type='session', target_id=session.id)
    await db.commit()
    return {'ok': True}
