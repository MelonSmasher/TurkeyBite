"""Signing in against an LDAP directory, Active Directory included.

The console binds as a service account, finds the person's entry with the
configured filter, binds again as that entry with the password they typed,
and reads their groups. Their role is the highest one any of their groups is
mapped to; a person in no mapped group is refused unless a default role is
set. The role is read again at every sign-in, so removing someone from a
group takes effect the next time they sign in.

An empty password is refused before anything is sent: most directories treat
a simple bind with a DN and no password as an anonymous bind, and report it
as a success.

ldap3 is synchronous, so callers run these functions in a thread.
"""

import logging
import ssl
from dataclasses import dataclass, field

from ldap3 import ALL_ATTRIBUTES, BASE, FIRST, SUBTREE, SYNC, Connection, Server, ServerPool, Tls
from ldap3.core import exceptions as lx
from ldap3.utils.conv import escape_filter_chars

from . import rbac

log = logging.getLogger(__name__)

DEFAULTS = {
    'enabled': False,
    'urls': [],
    'start_tls': False,
    'verify_certs': True,
    'ca_cert_pem': '',
    'bind_dn': '',
    'user_base_dn': '',
    'user_filter': '(&(objectClass=person)(|(uid={username})(sAMAccountName={username})))',
    'attr_username': 'uid',
    'attr_display_name': 'displayName',
    'attr_email': 'mail',
    'attr_groups': 'memberOf',
    'group_base_dn': '',
    'group_filter': '',
    'role_mappings': [],
    'default_role': None,
    'timeout_sec': 5,
}


# The ldap3 client strategy. Tests swap in MOCK_SYNC with an in-memory
# directory; nothing else should change it.
_STRATEGY = SYNC
_MOCK_SERVER = None


class LdapError(Exception):
    """Base for what can go wrong signing in against the directory."""


class LdapUnavailable(LdapError):
    """The directory could not be reached, or the service account was refused."""


class LdapInvalidCredentials(LdapError):
    """No such person, or the wrong password. Deliberately not said which."""


class LdapNotPermitted(LdapError):
    """The person signed in but no group of theirs grants a role."""


@dataclass
class LdapIdentity:
    dn: str
    username: str
    display_name: str | None
    email: str | None
    groups: list[str] = field(default_factory=list)
    role: str | None = None


def config_with_defaults(value: dict | None) -> dict:
    merged = dict(DEFAULTS)
    merged.update({k: v for k, v in (value or {}).items() if k in DEFAULTS or k == 'bind_password_enc'})
    return merged


def _timeout(cfg: dict) -> int:
    # Whole seconds: ldap3 packs the receive timeout into a C struct of
    # integers on Linux and macOS, and a float there raises struct.error
    try:
        return max(1, min(60, int(round(float(cfg.get('timeout_sec') or 5)))))
    except (TypeError, ValueError):
        return 5


def _servers(cfg: dict):
    if _MOCK_SERVER is not None:
        return _MOCK_SERVER
    tls = None
    if cfg.get('verify_certs', True):
        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=cfg.get('ca_cert_pem') or None)
    else:
        tls = Tls(validate=ssl.CERT_NONE)
    timeout = _timeout(cfg)
    servers = []
    for url in cfg.get('urls') or []:
        url = url.strip()
        if not url:
            continue
        servers.append(Server(url, use_ssl=url.lower().startswith('ldaps://'), tls=tls,
                              connect_timeout=timeout, get_info=None))
    if not servers:
        raise LdapUnavailable('no directory server is configured')
    return ServerPool(servers, FIRST, active=1, exhaust=False)


# Bind results that say the directory is struggling rather than that the
# credentials are wrong: busy, unavailable, unwilling to perform, other
_TRANSIENT_BIND_RESULTS = {51, 52, 53, 80}


class _BindRefused(Exception):
    def __init__(self, result: dict):
        super().__init__(result.get('description') or 'bind refused')
        self.result = result

    @property
    def transient(self) -> bool:
        return self.result.get('result') in _TRANSIENT_BIND_RESULTS


def _connect(cfg: dict, user: str, password: str) -> Connection:
    """An open, bound connection. Raises _BindRefused, or an ldap3 exception
    when no server can be reached."""
    timeout = _timeout(cfg)
    conn = Connection(_servers(cfg), user=user, password=password,
                      receive_timeout=timeout, raise_exceptions=False, read_only=True,
                      client_strategy=_STRATEGY)
    conn.open()
    if cfg.get('start_tls') and not getattr(conn.server, 'ssl', False):
        if not conn.start_tls():
            raise lx.LDAPStartTLSError(f'StartTLS failed: {conn.result}')
    if not conn.bind():
        result = dict(conn.result or {})
        try:
            conn.unbind()
        except Exception:
            pass
        raise _BindRefused(result)
    return conn


_UNREACHABLE = (lx.LDAPSocketOpenError, lx.LDAPSocketReceiveError, lx.LDAPSocketSendError,
                lx.LDAPSessionTerminatedByServerError, lx.LDAPStartTLSError,
                lx.LDAPServerPoolExhaustedError, lx.LDAPServerPoolError, lx.LDAPCommunicationError,
                ssl.SSLError, TimeoutError, OSError)


def _service_connection(cfg: dict, bind_password: str) -> Connection:
    try:
        return _connect(cfg, cfg.get('bind_dn') or '', bind_password)
    except _BindRefused as e:
        raise LdapUnavailable(f'the service account could not bind: {e}') from e
    except _UNREACHABLE as e:
        raise LdapUnavailable(f'the directory could not be reached: {e}') from e
    except lx.LDAPException as e:
        raise LdapUnavailable(f'the directory refused the connection: {e}') from e


def _first(entry: dict, name: str) -> str | None:
    if not name:
        return None
    for key, value in entry.items():
        if key.lower() == name.lower():
            if isinstance(value, list):
                return str(value[0]) if value else None
            return str(value) if value not in (None, '') else None
    return None


def _all(entry: dict, name: str) -> list[str]:
    if not name:
        return []
    for key, value in entry.items():
        if key.lower() == name.lower():
            if isinstance(value, list):
                return [str(v) for v in value]
            return [str(value)] if value else []
    return []


def map_role(cfg: dict, groups: list[str]) -> str | None:
    """The highest role any of `groups` is mapped to, else the default."""
    have = {g.strip().lower() for g in groups}
    role = None
    for mapping in cfg.get('role_mappings') or []:
        group = str(mapping.get('group') or '').strip().lower()
        wanted = mapping.get('role')
        if group and group in have and wanted in rbac.ROLES:
            role = rbac.higher_role(role, wanted)
    if role is None and cfg.get('default_role') in rbac.ROLES:
        role = cfg['default_role']
    return role


def _clean_username(username: str) -> str:
    username = (username or '').strip()
    if not username or len(username) > 256 or '\x00' in username:
        raise LdapInvalidCredentials('invalid username or password')
    return username


# Search results that mean the search worked: success, and the size limit
# that finding two people for one name hits
_ANSWERED = (0, 4)
_NO_SUCH_OBJECT = 32


def _answered(conn: Connection, what: str, allow: tuple[int, ...] = _ANSWERED) -> int:
    """The result code of the last operation, if it is one that means the
    directory answered. Busy, unavailable, a time limit, refused access: none
    of those says anything about the person, so they raise rather than read
    as 'not found', which would revoke everyone at once."""
    result = conn.result or {}
    code = int(result.get('result', 0) or 0)
    if code not in allow:
        raise LdapUnavailable(f'the directory did not complete the {what}: '
                              f'{result.get("description") or code} {result.get("message") or ""}'.strip())
    return code


def _attributes(cfg: dict) -> list[str]:
    return [a for a in (cfg.get('attr_username'), cfg.get('attr_display_name'),
                        cfg.get('attr_email'), cfg.get('attr_groups')) if a]


def _find_user(conn: Connection, cfg: dict, username: str) -> tuple[str, dict]:
    search_filter = (cfg.get('user_filter') or DEFAULTS['user_filter']).replace(
        '{username}', escape_filter_chars(username))
    attributes = _attributes(cfg)
    conn.search(cfg.get('user_base_dn') or '', search_filter, search_scope=SUBTREE,
                attributes=attributes or ALL_ATTRIBUTES, size_limit=2)
    _answered(conn, 'search for the account')
    entries = [e for e in conn.response or [] if e.get('type') == 'searchResEntry']
    if len(entries) != 1:
        # None, or an ambiguous filter: refusing is the only safe answer,
        # and saying which would tell a stranger who has an account
        raise LdapInvalidCredentials('invalid username or password')
    return entries[0]['dn'], dict(entries[0].get('attributes') or {})


def _groups(conn: Connection, cfg: dict, dn: str, attributes: dict) -> list[str]:
    groups = _all(attributes, cfg.get('attr_groups') or '')
    if cfg.get('group_filter') and cfg.get('group_base_dn'):
        search_filter = cfg['group_filter'].replace('{dn}', escape_filter_chars(dn))
        conn.search(cfg['group_base_dn'], search_filter, search_scope=SUBTREE, attributes=[])
        _answered(conn, 'search for groups')
        groups += [e['dn'] for e in conn.response or [] if e.get('type') == 'searchResEntry']
    seen, unique = set(), []
    for group in groups:
        if group.lower() not in seen:
            seen.add(group.lower())
            unique.append(group)
    return unique


def authenticate(cfg: dict, bind_password: str, username: str, password: str) -> LdapIdentity:
    """Signs a person in against the directory. Raises an LdapError subclass, and
    only that: anything unexpected from the library means the directory could
    not be used, not that the console should fail the request."""
    try:
        return _authenticate(cfg, bind_password, username, password)
    except LdapError:
        raise
    except Exception as e:
        log.exception('LDAP sign-in failed unexpectedly')
        raise LdapUnavailable(f'the directory could not be used: {type(e).__name__}') from e


def _authenticate(cfg: dict, bind_password: str, username: str, password: str) -> LdapIdentity:
    username = _clean_username(username)
    if not password:
        raise LdapInvalidCredentials('invalid username or password')
    service = _service_connection(cfg, bind_password)
    try:
        dn, attributes = _find_user(service, cfg, username)
        try:
            user_conn = _connect(cfg, dn, password)
            user_conn.unbind()
        except _BindRefused as e:
            if e.transient:
                raise LdapUnavailable(f'the directory could not check the password: {e}') from e
            raise LdapInvalidCredentials('invalid username or password') from e
        except _UNREACHABLE as e:
            raise LdapUnavailable(f'the directory could not be reached: {e}') from e
        groups = _groups(service, cfg, dn, attributes)
    except lx.LDAPException as e:
        if isinstance(e, _UNREACHABLE):
            raise LdapUnavailable(f'the directory could not be reached: {e}') from e
        raise LdapUnavailable(f'the directory refused a search: {e}') from e
    finally:
        try:
            service.unbind()
        except Exception:
            pass
    identity = LdapIdentity(
        dn=dn,
        username=(_first(attributes, cfg.get('attr_username') or '') or username).lower(),
        display_name=_first(attributes, cfg.get('attr_display_name') or ''),
        email=_first(attributes, cfg.get('attr_email') or ''),
        groups=groups,
    )
    identity.role = map_role(cfg, groups)
    if identity.role is None:
        raise LdapNotPermitted('no group of yours grants access to the console')
    return identity


def recheck(cfg: dict, bind_password: str, dn: str | None, username: str) -> LdapIdentity | None:
    """What the directory says about an account now, without its password.

    None when it is gone, or no longer matches the sign-in filter (a disabled
    Active Directory account, if the filter says so); an identity whose role
    is None when no group grants one. Looked up by its DN, the one thing that
    does not depend on which attribute people type at sign-in. Raises
    LdapUnavailable whenever the directory does not give a clear answer."""
    try:
        service = _service_connection(cfg, bind_password)
        try:
            if dn:
                # The sign-in filter, with any name allowed, applied to this
                # one entry: it still has to be an account that may sign in
                search_filter = (cfg.get('user_filter') or DEFAULTS['user_filter']).replace('{username}', '*')
                service.search(dn, search_filter, search_scope=BASE,
                               attributes=_attributes(cfg) or ALL_ATTRIBUTES)
                if _answered(service, 'look-up of the account', _ANSWERED + (_NO_SUCH_OBJECT,)) \
                        == _NO_SUCH_OBJECT:
                    return None
                entries = [e for e in service.response or [] if e.get('type') == 'searchResEntry']
                if len(entries) != 1:
                    return None
                attributes = dict(entries[0].get('attributes') or {})
            else:
                try:
                    dn, attributes = _find_user(service, cfg, _clean_username(username))
                except LdapInvalidCredentials:
                    return None
            groups = _groups(service, cfg, dn, attributes)
        finally:
            try:
                service.unbind()
            except Exception:
                pass
    except LdapError:
        raise
    except Exception as e:
        raise LdapUnavailable(f'the directory could not be used: {type(e).__name__}') from e
    identity = LdapIdentity(
        dn=dn, username=(_first(attributes, cfg.get('attr_username') or '') or username).lower(),
        display_name=_first(attributes, cfg.get('attr_display_name') or ''),
        email=_first(attributes, cfg.get('attr_email') or ''), groups=groups)
    identity.role = map_role(cfg, groups)
    return identity


def test(cfg: dict, bind_password: str, username: str | None = None,
         password: str | None = None) -> list[dict]:
    """Checks the configuration step by step, for the settings page.

    Each step is {step, ok, detail}. Stops at the first failure.
    """
    try:
        return _test(cfg, bind_password, username, password)
    except Exception as e:
        log.exception('LDAP test failed unexpectedly')
        return [{'step': 'Use the directory', 'ok': False,
                 'detail': f'the directory could not be used: {type(e).__name__}: {e}'}]


def _test(cfg: dict, bind_password: str, username: str | None, password: str | None) -> list[dict]:
    steps = []
    try:
        service = _service_connection(cfg, bind_password)
    except LdapUnavailable as e:
        return [{'step': 'Connect and bind as the service account', 'ok': False,
                 'detail': str(e)}]
    steps.append({'step': 'Connect and bind as the service account', 'ok': True,
                  'detail': f'bound as {cfg.get("bind_dn") or "anonymous"}'})
    try:
        if not username:
            return steps
        try:
            dn, attributes = _find_user(service, cfg, _clean_username(username))
        except LdapInvalidCredentials:
            steps.append({'step': f'Find {username}', 'ok': False,
                          'detail': 'the user filter matched no entry, or more than one'})
            return steps
        steps.append({'step': f'Find {username}', 'ok': True, 'detail': dn})
        groups = _groups(service, cfg, dn, attributes)
        steps.append({'step': 'Read groups', 'ok': True,
                      'detail': ', '.join(groups) if groups else 'no groups'})
        role = map_role(cfg, groups)
        steps.append({'step': 'Map a role', 'ok': role is not None,
                      'detail': role or 'no group is mapped to a role, and there is no default'})
        if password:
            try:
                _connect(cfg, dn, password).unbind()
                steps.append({'step': 'Bind with the password given', 'ok': True,
                              'detail': 'the password is right'})
            except _BindRefused as e:
                steps.append({'step': 'Bind with the password given', 'ok': False,
                              'detail': f'the directory refused the password: {e}'})
    except lx.LDAPException as e:
        steps.append({'step': 'Search the directory', 'ok': False, 'detail': str(e)})
    finally:
        try:
            service.unbind()
        except Exception:
            pass
    return steps
