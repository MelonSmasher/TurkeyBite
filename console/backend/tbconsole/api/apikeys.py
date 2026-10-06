"""API keys for integrations.

Anyone with apikeys:self can hold keys of their own, scoped to some of what
their role allows. Admins can also make keys for service accounts, which is
how an integration gets access that does not end when a person leaves.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..db import get_session
from ..deps import Principal, require
from ..models import ApiKey, User
from ..security import apikeys, rbac
from .common import apikey_out, parse_uuid

router = APIRouter(prefix='/api-keys', tags=['api keys'])


class KeyBody(BaseModel):
    """A new key: its name, scopes and lifetime, and for an admin, the service account to own it."""

    name: str = Field(min_length=1, max_length=200)
    scopes: list[str] = Field(min_length=1, max_length=len(rbac.ALL))
    expires_days: int | None = Field(90, ge=1, le=730)
    user_id: str | None = None


@router.get('/scopes')
async def scopes(principal: Principal = Depends(require(rbac.APIKEYS_SELF))) -> list[dict]:
    """Every scope a key can hold, and whether the caller may grant it."""
    return [{'name': name, 'description': rbac.DESCRIPTIONS[name],
             'available': principal.can(name)} for name in rbac.ALL]


@router.get('')
async def list_keys(all_: bool = Query(default=False, alias='all'),
                    principal: Principal = Depends(require(rbac.APIKEYS_SELF)),
                    db: AsyncSession = Depends(get_session)) -> list[dict]:
    """The caller's own keys, newest first; with `all`, an admin sees everyone's."""
    stmt = select(ApiKey).order_by(ApiKey.created_at.desc())
    if all_:
        if not principal.can(rbac.USERS_ADMIN):
            raise HTTPException(status.HTTP_403_FORBIDDEN, 'Only admins can see every key.')
    else:
        stmt = stmt.where(ApiKey.user_id == principal.user.id)
    return [apikey_out(k) for k in (await db.execute(stmt)).scalars().all()]


@router.post('', status_code=status.HTTP_201_CREATED)
async def create_key(body: KeyBody, request: Request,
                     principal: Principal = Depends(require(rbac.APIKEYS_SELF)),
                     db: AsyncSession = Depends(get_session)) -> dict:
    """Makes a key, for the caller or a service account. The full key is in this response alone; only its hash is kept."""
    if principal.kind == 'apikey':
        raise HTTPException(status.HTTP_403_FORBIDDEN, 'An API key cannot make more API keys.')
    owner = principal.user
    if body.user_id and parse_uuid(body.user_id, 'That user') != principal.user.id:
        if not principal.can(rbac.USERS_ADMIN):
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                'Only admins can make keys for someone else.')
        owner = await db.get(User, parse_uuid(body.user_id, 'That user'))
        if owner is None or owner.source != 'service' or owner.disabled:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                'Keys for others can only be made for active service accounts.')
    unknown = set(body.scopes) - set(rbac.ALL)
    if unknown:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'Unknown scopes: {", ".join(sorted(unknown))}')
    beyond = set(body.scopes) - rbac.permissions_for(owner.role)
    if beyond:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f'The {owner.role} role does not allow: {", ".join(sorted(beyond))}')
    if owner.id == principal.user.id:
        # Nobody can mint a key that does more than they can
        over = set(body.scopes) - principal.permissions
        if over:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f'You do not hold: {", ".join(sorted(over))}')
    key, prefix, digest = apikeys.generate()
    expires = (datetime.now(timezone.utc) + timedelta(days=body.expires_days)
               if body.expires_days else None)
    row = ApiKey(user_id=owner.id, name=body.name.strip(), prefix=prefix, key_hash=digest,
                 scopes=sorted(set(body.scopes)), expires_at=expires,
                 created_by_id=principal.user.id)
    db.add(row)
    await db.flush()
    audit.record(db, 'apikey.create', principal=principal, request=request, target_type='apikey',
                 target_id=row.id, target_label=f'{row.name} (tbc_{prefix})',
                 details={'owner': owner.username, 'scopes': row.scopes})
    await db.commit()
    await db.refresh(row)
    # The full key is returned this once; only its hash is kept
    return {**apikey_out(row), 'key': key}


@router.delete('/{key_id}')
async def revoke_key(key_id: str, request: Request,
                     principal: Principal = Depends(require(rbac.APIKEYS_SELF)),
                     db: AsyncSession = Depends(get_session)) -> dict:
    """Revokes a key: the caller's own, or for an admin, anyone's."""
    row = await db.get(ApiKey, parse_uuid(key_id, 'That key'))
    if row is None or (row.user_id != principal.user.id and not principal.can(rbac.USERS_ADMIN)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, 'That key does not exist')
    if row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        audit.record(db, 'apikey.revoke', principal=principal, request=request,
                     target_type='apikey', target_id=row.id, target_label=f'{row.name} (tbc_{row.prefix})')
        await db.commit()
    return apikey_out(row)
