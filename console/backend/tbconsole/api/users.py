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
from sqlalchemy import func, select
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
    username: str = Field(pattern=USERNAME)
    display_name: str | None = Field(None, max_length=200)
    email: str | None = Field(None, max_length=320)
    role: str = 'viewer'
    kind: str = 'local'            # local or service
    password: str | None = Field(None, max_length=1024)


class UpdateUser(BaseModel):
    display_name: str | None = Field(None, max_length=200)
    email: str | None = Field(None, max_length=320)
    role: str | None = None
    disabled: bool | None = None


class PasswordReset(BaseModel):
    password: str = Field(max_length=1024)


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
    if body.disabled is not None and body.disabled != user.disabled:
        if body.disabled and user.id == principal.user.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'You cannot disable yourself.')
        if body.disabled and user.role == 'admin' and not await _other_admins(db, user):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, 'This is the last admin.')
        changes['disabled'] = body.disabled
        user.disabled = body.disabled
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
    audit.record(db, 'user.password_reset', principal=principal, request=request,
                 target_type='user', target_id=user.id, target_label=user.username)
    await db.commit()
    return {'ok': True}


@router.post('/{user_id}/unlock')
async def unlock(user_id: str, request: Request,
                 principal: Principal = Depends(require(rbac.USERS_ADMIN)),
                 db: AsyncSession = Depends(get_session)) -> dict:
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
