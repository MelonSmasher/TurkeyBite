"""Settings admins change at runtime: the LDAP directory and general options."""

from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit, settings_store
from ..db import get_session
from ..deps import Principal, require
from ..security import crypto, ldap, rbac

router = APIRouter(prefix='/settings', tags=['settings'])


class RoleMapping(BaseModel):
    """A directory group, and the console role its members get."""

    group: str = Field(min_length=1, max_length=1000)
    role: str


class LdapBody(BaseModel):
    """How to reach the directory, find people in it and turn their groups into roles."""

    enabled: bool = False
    urls: list[str] = Field(default_factory=list, max_length=10)
    start_tls: bool = False
    verify_certs: bool = True
    ca_cert_pem: str = Field('', max_length=20000)
    bind_dn: str = Field('', max_length=1000)
    # None keeps the saved password, '' clears it
    bind_password: str | None = Field(None, max_length=1024)
    user_base_dn: str = Field('', max_length=1000)
    user_filter: str = Field(ldap.DEFAULTS['user_filter'], max_length=2000)
    attr_username: str = Field('uid', max_length=100)
    attr_display_name: str = Field('displayName', max_length=100)
    attr_email: str = Field('mail', max_length=100)
    attr_groups: str = Field('memberOf', max_length=100)
    group_base_dn: str = Field('', max_length=1000)
    group_filter: str = Field('', max_length=2000)
    role_mappings: list[RoleMapping] = Field(default_factory=list, max_length=100)
    default_role: str | None = None
    timeout_sec: int = Field(5, ge=1, le=60)


class LdapTestBody(LdapBody):
    """Directory settings to try, saved or not, and if given, a person to sign in as."""

    username: str | None = Field(None, max_length=256)
    password: str | None = Field(None, max_length=1024)


class GeneralBody(BaseModel):
    """The organisation's name, the sign-in banner, and defaults for the whole console."""

    org_name: str = Field('TurkeyBite', min_length=1, max_length=100)
    login_banner: str = Field('', max_length=2000)
    default_range: Literal[settings_store.DEFAULT_RANGES] = 'now-24h'
    require_mfa_for_local_admins: bool = False
    privacy_mode_default: bool = False
    device_lookup_url: str = Field('', max_length=500)

    @field_validator('device_lookup_url')
    @classmethod
    def _lookup_url(cls, value: str) -> str:
        """An http(s) URL with {value} where the device's address goes, or nothing."""
        value = value.strip()
        if not value:
            return ''
        parts = urlsplit(value.replace('{value}', 'x'))
        if parts.scheme not in ('http', 'https') or not parts.hostname or '{value}' not in value \
                or any(c.isspace() for c in value):
            raise ValueError('the device lookup link is an http:// or https:// URL with {value} where the '
                             'address goes, such as https://sac.example.edu/respond/device/?q={value}')
        return value


def _public(cfg: dict) -> dict:
    out = {k: v for k, v in cfg.items() if k != 'bind_password_enc'}
    out['has_bind_password'] = bool(cfg.get('bind_password_enc'))
    return out


def _check(body: LdapBody) -> None:
    for url in body.urls:
        if not url.lower().startswith(('ldap://', 'ldaps://')):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f'{url!r} is not an ldap:// or ldaps:// URL')
    if body.enabled and not body.urls:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Name at least one directory server.')
    if '{username}' not in body.user_filter:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'The user filter has to contain {username}.')
    if body.group_filter and '{dn}' not in body.group_filter:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'The group filter has to contain {dn}.')
    for mapping in body.role_mappings:
        if mapping.role not in rbac.ROLES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f'role is one of {", ".join(rbac.ROLES)}')
    if body.default_role is not None and body.default_role not in rbac.ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f'role is one of {", ".join(rbac.ROLES)}')
    _check_tls(body, body.enabled)


def _check_tls(body: LdapBody, enforce: bool) -> None:
    if enforce and any(u.lower().startswith('ldap://') for u in body.urls) and not body.start_tls:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            'Passwords would cross the network in clear: use ldaps://, or turn on '
                            'StartTLS.')


def _merge(body: LdapBody, saved: dict) -> dict:
    cfg = body.model_dump(exclude={'bind_password', 'username', 'password'})
    cfg['role_mappings'] = [m.model_dump() for m in body.role_mappings]
    if body.bind_password is None:
        if saved.get('bind_password_enc'):
            # The saved password goes only where it was saved for: sending it
            # to a different server, or binding as someone else with it, needs
            # it typed again, or anyone with an admin session could have the
            # service account's password sent to a server of their choosing
            moved = (sorted(u.strip().lower() for u in body.urls)
                     != sorted(u.strip().lower() for u in saved.get('urls') or [])
                     or (body.bind_dn or '').strip().lower()
                     != (saved.get('bind_dn') or '').strip().lower())
            if moved:
                raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                    'Enter the bind password again when you change the servers '
                                    'or the bind DN.')
            cfg['bind_password_enc'] = saved['bind_password_enc']
    elif body.bind_password:
        cfg['bind_password_enc'] = crypto.encrypt(body.bind_password)
    return cfg


@router.get('/ldap')
async def get_ldap(_: Principal = Depends(require(rbac.SETTINGS_ADMIN)),
                   db: AsyncSession = Depends(get_session)) -> dict:
    """The directory settings, with whether a bind password is saved, but never the password."""
    return _public(ldap.config_with_defaults(await settings_store.get(db, 'ldap')))


@router.put('/ldap')
async def put_ldap(body: LdapBody, request: Request,
                   principal: Principal = Depends(require(rbac.SETTINGS_ADMIN)),
                   db: AsyncSession = Depends(get_session)) -> dict:
    """Saves the directory settings.

    A saved bind password is kept only while the servers and the bind DN stay
    the same; otherwise it has to be entered again.
    """
    _check(body)
    cfg = _merge(body, await settings_store.get(db, 'ldap'))
    await settings_store.put(db, 'ldap', cfg, principal.user.id)
    audit.record(db, 'settings.ldap', principal=principal, request=request,
                 details={'enabled': body.enabled, 'urls': body.urls,
                          'password_changed': body.bind_password is not None})
    await db.commit()
    return _public(ldap.config_with_defaults(cfg))


@router.post('/ldap/test')
async def test_ldap(body: LdapTestBody, request: Request,
                    principal: Principal = Depends(require(rbac.SETTINGS_ADMIN)),
                    db: AsyncSession = Depends(get_session)) -> dict:
    """Tries the settings in the form, saved or not, step by step."""
    if not body.urls:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, 'Name at least one directory server.')
    for url in body.urls:
        if not url.lower().startswith(('ldap://', 'ldaps://')):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f'{url!r} is not an ldap:// or ldaps:// URL')
    # A test sends the bind password, and the test person's, like a sign-in does
    _check_tls(body, True)
    cfg = ldap.config_with_defaults(_merge(body, await settings_store.get(db, 'ldap')))
    secret = crypto.decrypt(cfg['bind_password_enc']) if cfg.get('bind_password_enc') else ''
    steps = await ldap.call(ldap.test, cfg, secret, body.username, body.password, guarded=False)
    audit.record(db, 'settings.ldap_test', principal=principal, request=request,
                 outcome='success' if all(s['ok'] for s in steps) else 'failure',
                 details={'username': body.username})
    await db.commit()
    return {'ok': all(s['ok'] for s in steps), 'steps': steps}


@router.get('/general')
async def get_general(_: Principal = Depends(require(rbac.SETTINGS_ADMIN)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    """The general settings: the organisation's name, the sign-in banner and console-wide defaults."""
    return await settings_store.general(db)


@router.put('/general')
async def put_general(body: GeneralBody, request: Request,
                      principal: Principal = Depends(require(rbac.SETTINGS_ADMIN)),
                      db: AsyncSession = Depends(get_session)) -> dict:
    """Saves the general settings, and returns them."""
    await settings_store.put(db, 'general', body.model_dump(), principal.user.id)
    audit.record(db, 'settings.general', principal=principal, request=request,
                 details=body.model_dump())
    await db.commit()
    return await settings_store.general(db)
