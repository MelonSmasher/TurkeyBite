"""Signing in and out.

A username that belongs to a local account is checked here, against its
Argon2 hash, whether or not the directory is up: local accounts are the way
in when LDAP is down. Any other username goes to the directory when LDAP is
on. Service accounts cannot sign in at all; they exist to hold API keys.

Failures say the same thing whatever went wrong, so the sign-in page cannot be
used to find out which usernames exist. Five wrong passwords lock a local
account for fifteen minutes, and an address that fails often is slowed down.
"""

import unicodedata
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import __version__, audit, settings_store
from ..config import get_settings
from ..db import get_session
from ..deps import Principal, current_principal, optional_principal, origin_ok
from ..models import User, UserSession
from ..security import crypto, ldap, limits, lockout, passwords, sessions, totp
from .common import user_out

router = APIRouter(prefix='/auth', tags=['auth'])

GENERIC = 'Invalid username or password.'

TOO_MANY = 'Too many failed sign-ins. Wait a few minutes and try again.'


def _same_origin(request: Request) -> None:
    """A browser signing in from another site's page is refused, so no page
    can sign a visitor in to an account of its choosing."""
    if not origin_ok(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, 'Sign in from the console itself.')


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
    limits.failed(sessions.client_ip(request), username)
    if user is not None and user.source == 'local':
        if await lockout.count_failure(db, user.id):
            reason += '; account locked'
        # The count is committed on its own first, so nothing about the audit
        # row can undo it
        await db.commit()
    audit.record(db, 'auth.login', actor_name=username, request=request, outcome='failure',
                 details={'reason': reason})
    await db.commit()


class _NotTheSamePerson(Exception):
    """An account matched a directory entry by DN, but its lasting id says it
    was made for an entry that has since been deleted and its DN reused."""


async def _directory_account(db: AsyncSession, identity) -> User | None:
    """The console account for a directory entry: by its lasting id when the
    directory has one, else by its DN."""
    if identity.guid:
        found = (await db.execute(select(User).where(
            User.source == 'ldap', User.ldap_guid == identity.guid))).scalar_one_or_none()
        if found is not None:
            return found
    found = (await db.execute(select(User).where(
        User.source == 'ldap', func.lower(User.ldap_dn) == identity.dn.lower()))).scalar_one_or_none()
    if found is not None and found.ldap_guid and identity.guid and found.ldap_guid != identity.guid:
        raise _NotTheSamePerson('the DN belongs to a different directory entry now')
    return found


@router.post('/login')
async def login(body: LoginBody, request: Request, response: Response,
                db: AsyncSession = Depends(get_session)) -> dict:
    _same_origin(request)
    # In the form directories compare names in, so ｂｏｂ and bob are one name
    # here as they are there, and one count against the brake
    username = unicodedata.normalize('NFKC', body.username).strip()
    if not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC)
    if limits.limited(sessions.client_ip(request), username):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY)
    # A few at a time from one address, before anything costly, the database
    # included: a flood from one address queues behind itself
    try:
        async with limits.admitted(sessions.client_ip(request), username):
            return await _sign_in(db, body, request, response, username)
    except limits.Busy as e:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            'Too many sign-ins to this account are under way. Try again in a moment.'
                            if e.kind == 'name' else
                            'Too many sign-ins are under way from your network. Try again in a '
                            'moment.') from e


async def _sign_in(db: AsyncSession, body: LoginBody, request: Request, response: Response,
                   username: str) -> dict:
    user = (await db.execute(select(User).where(
        func.lower(User.username) == username.lower()))).scalar_one_or_none()
    # The pooled connection goes back while the password is checked, which
    # waits its turn and takes a while by design
    await db.commit()

    if user is not None and user.source == 'service':
        await passwords.verify_async(None, body.password)
        await _fail(db, request, username, 'service accounts cannot sign in')
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC)

    if user is not None and user.source == 'local':
        now = datetime.now(timezone.utc)
        if user.locked_until and user.locked_until > now:
            await passwords.verify_async(None, body.password)
            await _fail(db, request, username, 'account locked', None)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC)
        if not await passwords.verify_async(user.password_hash, body.password) or user.disabled:
            await _fail(db, request, username, 'wrong password' if not user.disabled
                        else 'account disabled', user)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC)
        if passwords.needs_rehash(user.password_hash):
            user.password_hash = await passwords.hash_async(body.password)
        if user.totp_enabled:
            await db.commit()
            return {'ok': False, 'mfa_required': True, 'token': sessions.mfa_token(user)}
        return await _finish(db, user, request, response, 'local')

    cfg, bind_password = await _ldap_config(db)
    # Back to the pool before the password check or the directory, both slow
    await db.commit()
    if not cfg.get('enabled'):
        await passwords.verify_async(None, body.password)
        await _fail(db, request, username, 'no such local account and LDAP is off')
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC)
    try:
        # One directory call at a time per address, so a few addresses cannot
        # take every turn the directory has
        async with limits.directory_turn(sessions.client_ip(request)):
            identity = await ldap.call(ldap.authenticate, cfg, bind_password, username, body.password)
    except ldap.LdapUnavailable as e:
        # Not counted against the name: the directory being away, or the
        # console turning sign-ins away while it is slow, is not a wrong
        # password, and the address's own queue already bounds a flood
        audit.look(db, 'auth.login', principal=None, request=request, key='directory-unavailable',
                   details={'reason': 'directory unavailable', 'error': str(e)},
                   actor_name=username, outcome='failure')
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

    # The directory's entry decides whose account this is: its lasting id, or
    # its DN. Never a name, which two people in two branches of the
    # directory can share; nor the account the typed name happened to find
    try:
        user = await _directory_account(db, identity)
    except _NotTheSamePerson as e:
        await _fail(db, request, username, str(e))
        raise HTTPException(status.HTTP_409_CONFLICT,
                            'The console already has an account for a different directory entry '
                            'with this name. Ask an administrator to sort it out.') from e
    if user is None:
        taken = (await db.execute(select(User.id).where(
            func.lower(User.username) == identity.username.lower()))).first()
        if taken:
            await _fail(db, request, username, 'another account has the directory name')
            raise HTTPException(status.HTTP_409_CONFLICT,
                                'A console account already has your directory name. Ask an '
                                'administrator to rename it.')
        user = User(username=identity.username, source='ldap', role=identity.role,
                    display_name=identity.display_name, email=identity.email,
                    ldap_dn=identity.dn, ldap_guid=identity.guid, preferences={},
                    directory_checked_at=datetime.now(timezone.utc))
        db.add(user)
        await db.flush()
    else:
        if user.disabled and user.disabled_reason != 'directory':
            await _fail(db, request, username, 'account disabled')
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC)
        # The directory is the authority on who someone is and what they may
        # do, so access it took away it can give back; an admin's disabling
        # stays until an admin undoes it
        user.disabled = False
        user.disabled_reason = None
        user.directory_checked_at = datetime.now(timezone.utc)
        user.role = identity.role
        user.display_name = identity.display_name or user.display_name
        user.email = identity.email or user.email
        user.ldap_dn = identity.dn
        user.ldap_guid = user.ldap_guid or identity.guid
    return await _finish(db, user, request, response, 'ldap')


@router.post('/mfa')
async def login_mfa(body: MfaBody, request: Request, response: Response,
                    db: AsyncSession = Depends(get_session)) -> dict:
    """The second step: a code from the authenticator app."""
    _same_origin(request)
    ip = sessions.client_ip(request)
    parsed = sessions.read_mfa_token(body.token)
    # Locked, so the same token sent several times at once is taken in turn,
    # and each after the first sees the sign-in it completed
    user = (await db.execute(select(User).where(User.id == parsed[0]).with_for_update()
                             .execution_options(populate_existing=True))).scalar_one_or_none() \
        if parsed else None
    # One token, one session: a sign-in completed since it was issued spends it
    if user is not None and user.last_login_at and user.last_login_at.timestamp() >= parsed[2]:
        user = None
    if limits.limited(ip, user.username if user else ''):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, TOO_MANY)
    fingerprint = (user.password_hash or '')[-16:] if user else ''
    now = datetime.now(timezone.utc)
    # A lockout that began after the password step, from guessed codes, holds
    # here too, or the five-minute token would allow guessing past it
    if (user is None or not user.totp_enabled or user.disabled or parsed[1] != fingerprint
            or not user.totp_secret_enc or (user.locked_until and user.locked_until > now)):
        limits.failed(ip, user.username if user else '')
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            'That sign-in has expired. Start again.')
    try:
        secret = crypto.decrypt(user.totp_secret_enc)
    except crypto.SecretUnreadable as e:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            'Your second factor was saved under a secret key the console no longer '
                            'has. An administrator can reset it with create-user --reset-mfa.') from e
    step = totp.verify(secret, body.code, user.totp_last_step)
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
        'default_range': general['default_range'] if general['default_range'] in settings_store.DEFAULT_RANGES
        else 'now-24h',
        'mfa_required': bool(general['require_mfa_for_local_admins'] and user.source == 'local'
                             and user.role == 'admin' and not user.totp_enabled),
        'version': __version__,
        'api_docs': get_settings().api_docs,
    }
