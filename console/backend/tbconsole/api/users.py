"""People and service accounts, for admins.

Local accounts have a password kept here; directory accounts are created the
first time someone signs in through LDAP, and their role comes from their
groups; service accounts have no password and exist to hold API keys. An
admin cannot lock themselves out: the last enabled admin cannot be demoted,
disabled or deleted.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..db import get_session
from ..deps import Principal, require
from ..models import ApiKey, User, UserSession
from ..security import passwords, rbac, sessions
from .common import parse_uuid, user_out

router = APIRouter(prefix='/users', tags=['users'])

USERNAME = r'^[A-Za-z0-9][A-Za-z0-9._@\-]{1,149}$'


class CreateUser(BaseModel):
    """A new local or service account; a local one needs a password."""

    username: str = Field(pattern=USERNAME)
    display_name: str | None = Field(None, max_length=200)
    email: str | None = Field(None, max_length=320)
    role: str = 'viewer'
    kind: str = 'local'            # local or service
    password: str | None = Field(None, max_length=1024)


class UpdateUser(BaseModel):
    """Changes to an account; those left out stay as they are."""

    display_name: str | None = Field(None, max_length=200)
    email: str | None = Field(None, max_length=320)
    role: str | None = None
    disabled: bool | None = None


class PasswordReset(BaseModel):
    """A new password for a local account, and whether to revoke its API keys too."""

    password: str = Field(max_length=1024)
    # A password reset for an account someone else got into wants their keys
    # gone as well, or what they made with the old password still works
    revoke_keys: bool = False


async def _get(db: AsyncSession, user_id: str) -> User:
    user = await db.get(User, parse_uuid(user_id, 'That user'))
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That user does not exist')
    return user


async def _other_admins(db: AsyncSession, user: User) -> int:
    return (await db.execute(select(func.count()).select_from(User).where(
        User.role == 'admin', User.disabled.is_(False), User.id != user.id,
        User.source != 'service'))).scalar_one()


@router.get('')
async def list_users(_: Principal = Depends(require(rbac.USERS_ADMIN)),
                     db: AsyncSession = Depends(get_session)) -> list[dict]:
    """Every account, with how many API keys and live sessions each holds."""
    users = (await db.execute(select(User).order_by(User.source, User.username))).scalars().all()
    keys = dict((await db.execute(select(ApiKey.user_id, func.count()).where(
        ApiKey.revoked_at.is_(None)).group_by(ApiKey.user_id))).all())
    now = datetime.now(timezone.utc)
    live = dict((await db.execute(select(UserSession.user_id, func.count()).where(
        UserSession.expires_at > now).group_by(UserSession.user_id))).all())
    return [{**user_out(u, full=True), 'api_keys': int(keys.get(u.id, 0)),
             'sessions': int(live.get(u.id, 0))} for u in users]


@router.post('', status_code=status.HTTP_201_CREATED)
async def create_user(body: CreateUser, request: Request,
                      principal: Principal = Depends(require(rbac.USERS_ADMIN)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    """Makes a local or service account. Directory accounts appear when their owner first signs in."""
    if body.role not in rbac.ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'role is one of {", ".join(rbac.ROLES)}')
    if body.kind not in ('local', 'service'):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            'Create local or service accounts; directory accounts appear when '
                            'their owner first signs in.')
    taken = (await db.execute(select(User).where(
        func.lower(User.username) == body.username.lower()))).scalar_one_or_none()
    if taken is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, 'That username is taken')
    user = User(username=body.username, display_name=body.display_name, email=body.email,
                role=body.role, source=body.kind, preferences={})
    if body.kind == 'local':
        problems = passwords.password_problems(body.password or '', body.username)
        if problems:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, ' '.join(problems))
        user.password_hash = passwords.hash_password(body.password or '')
    db.add(user)
    await db.flush()
    audit.record(db, 'user.create', principal=principal, request=request, target_type='user',
                 target_id=user.id, target_label=user.username,
                 details={'role': user.role, 'kind': user.source})
    await db.commit()
    await db.refresh(user)
    return user_out(user, full=True)


@router.patch('/{user_id}')
async def update_user(user_id: str, body: UpdateUser, request: Request,
                      principal: Principal = Depends(require(rbac.USERS_ADMIN)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    """Changes an account's name, email, role or whether it is disabled.

    Disabling an account ends its sessions. The last enabled admin cannot be
    demoted or disabled, and a directory account's role comes from its groups.
    """
    user = await _get(db, user_id)
    changes = {}
    if body.role is not None and body.role != user.role:
        if body.role not in rbac.ROLES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f'role is one of {", ".join(rbac.ROLES)}')
        if user.role == 'admin' and not await _other_admins(db, user):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'This is the last admin.')
        if user.source == 'ldap':
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                'A directory account\'s role comes from its groups; change the '
                                'mapping in Authentication instead.')
        changes['role'] = [user.role, body.role]
        user.role = body.role
    if body.disabled and user.disabled and user.disabled_reason == 'directory':
        # Already off because of the directory, which could turn it back on;
        # an admin's decision is one it cannot undo
        user.disabled_reason = 'admin'
        changes['disabled'] = True
    elif body.disabled is not None and body.disabled != user.disabled:
        if body.disabled and user.id == principal.user.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'You cannot disable yourself.')
        if body.disabled and user.role == 'admin' and not await _other_admins(db, user):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'This is the last admin.')
        changes['disabled'] = body.disabled
        user.disabled = body.disabled
        user.disabled_reason = 'admin' if body.disabled else None
        if body.disabled:
            await sessions.end_all(db, user.id)
    if body.display_name is not None:
        user.display_name = body.display_name.strip() or None
    if body.email is not None:
        user.email = body.email.strip() or None
    audit.record(db, 'user.update', principal=principal, request=request, target_type='user',
                 target_id=user.id, target_label=user.username, details=changes)
    await db.commit()
    await db.refresh(user)
    return user_out(user, full=True)


@router.post('/{user_id}/password')
async def reset_password(user_id: str, body: PasswordReset, request: Request,
                         principal: Principal = Depends(require(rbac.USERS_ADMIN)),
                         db: AsyncSession = Depends(get_session)) -> dict:
    """Sets a local account's password, unlocks it and ends its sessions, revoking its API keys if asked."""
    user = await _get(db, user_id)
    if user.source != 'local':
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Only local accounts have a password here.')
    problems = passwords.password_problems(body.password, user.username)
    if problems:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, ' '.join(problems))
    user.password_hash = passwords.hash_password(body.password)
    user.password_changed_at = datetime.now(timezone.utc)
    user.failed_logins = 0
    user.locked_until = None
    await sessions.end_all(db, user.id)
    revoked = 0
    if body.revoke_keys:
        revoked = (await db.execute(
            update(ApiKey).where(ApiKey.user_id == user.id, ApiKey.revoked_at.is_(None))
            .values(revoked_at=datetime.now(timezone.utc)))).rowcount
    audit.record(db, 'user.password_reset', principal=principal, request=request,
                 target_type='user', target_id=user.id, target_label=user.username,
                 details={'keys_revoked': revoked})
    await db.commit()
    return {'ok': True, 'keys_revoked': revoked}


@router.post('/{user_id}/unlock')
async def unlock(user_id: str, request: Request,
                 principal: Principal = Depends(require(rbac.USERS_ADMIN)),
                 db: AsyncSession = Depends(get_session)) -> dict:
    """Lifts the lock that wrong passwords put on an account."""
    user = await _get(db, user_id)
    user.locked_until = None
    user.failed_logins = 0
    audit.record(db, 'user.unlock', principal=principal, request=request, target_type='user',
                 target_id=user.id, target_label=user.username)
    await db.commit()
    return user_out(user, full=True)


@router.post('/{user_id}/mfa/reset')
async def reset_mfa(user_id: str, request: Request,
                    principal: Principal = Depends(require(rbac.USERS_ADMIN)),
                    db: AsyncSession = Depends(get_session)) -> dict:
    """Turns off an account's two-factor sign-in, for someone who lost their authenticator."""
    user = await _get(db, user_id)
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_last_step = None
    audit.record(db, 'user.mfa_reset', principal=principal, request=request, target_type='user',
                 target_id=user.id, target_label=user.username)
    await db.commit()
    return user_out(user, full=True)


@router.delete('/{user_id}')
async def delete_user(user_id: str, request: Request,
                      principal: Principal = Depends(require(rbac.USERS_ADMIN)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    """Deletes an account. Nobody can delete themselves, and the last enabled admin cannot be deleted."""
    user = await _get(db, user_id)
    if user.id == principal.user.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'You cannot delete yourself.')
    if user.role == 'admin' and not await _other_admins(db, user):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'This is the last admin.')
    audit.record(db, 'user.delete', principal=principal, request=request, target_type='user',
                 target_id=user.id, target_label=user.username)
    await db.delete(user)
    await db.commit()
    return {'ok': True}
