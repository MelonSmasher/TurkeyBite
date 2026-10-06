"""Roles, permissions, and the scopes an API key can carry.

Three roles. A viewer can look at events, findings, rules and dashboards. An
analyst can also triage findings, write rules, build dashboards and hold API
keys of their own. An admin can do everything, including the things that
decide who sees what: users, the directory, webhooks and settings.

An API key carries scopes, which are permissions, and acts with those its
owner's role also has, so demoting a user narrows every key they hold.
"""

EVENTS_READ = 'events:read'
EVENTS_EXPORT = 'events:export'
FINDINGS_READ = 'findings:read'
FINDINGS_WRITE = 'findings:write'
RULES_READ = 'rules:read'
RULES_WRITE = 'rules:write'
DASHBOARDS_READ = 'dashboards:read'
DASHBOARDS_WRITE = 'dashboards:write'
WEBHOOKS_READ = 'webhooks:read'
WEBHOOKS_WRITE = 'webhooks:write'
APIKEYS_SELF = 'apikeys:self'
USERS_ADMIN = 'users:admin'
SETTINGS_ADMIN = 'settings:admin'
AUDIT_READ = 'audit:read'

ALL = (EVENTS_READ, EVENTS_EXPORT, FINDINGS_READ, FINDINGS_WRITE, RULES_READ, RULES_WRITE,
       DASHBOARDS_READ, DASHBOARDS_WRITE, WEBHOOKS_READ, WEBHOOKS_WRITE, APIKEYS_SELF,
       USERS_ADMIN, SETTINGS_ADMIN, AUDIT_READ)

DESCRIPTIONS = {
    EVENTS_READ: 'Search events and read analytics, entities and dashboards',
    EVENTS_EXPORT: 'Export search results as CSV or NDJSON',
    FINDINGS_READ: 'Read findings and their activity',
    FINDINGS_WRITE: 'Triage findings: status, assignment and comments',
    RULES_READ: 'Read rules and their runs',
    RULES_WRITE: 'Create, change, enable and test rules',
    DASHBOARDS_READ: 'Read dashboards and saved searches',
    DASHBOARDS_WRITE: 'Create and change dashboards and saved searches',
    WEBHOOKS_READ: 'Read webhooks and their deliveries',
    WEBHOOKS_WRITE: 'Create, change and test webhooks',
    APIKEYS_SELF: 'Create and revoke API keys of their own',
    USERS_ADMIN: 'Manage users, service accounts and every API key',
    SETTINGS_ADMIN: 'Change settings, including the LDAP directory',
    AUDIT_READ: 'Read the audit log',
}

ROLES = ('viewer', 'analyst', 'admin')
RANK = {role: i for i, role in enumerate(ROLES)}

_VIEWER = frozenset((EVENTS_READ, FINDINGS_READ, RULES_READ, DASHBOARDS_READ))
_ANALYST = _VIEWER | {EVENTS_EXPORT, FINDINGS_WRITE, RULES_WRITE, DASHBOARDS_WRITE, WEBHOOKS_READ,
                      APIKEYS_SELF}
ROLE_PERMISSIONS = {
    'viewer': _VIEWER,
    'analyst': frozenset(_ANALYST),
    'admin': frozenset(ALL),
}


def permissions_for(role: str, scopes=None) -> frozenset[str]:
    """What a role may do, narrowed to `scopes` when the caller is an API key."""
    granted = ROLE_PERMISSIONS.get(role, frozenset())
    if scopes is None:
        return granted
    return granted & frozenset(scopes)


def higher_role(a: str | None, b: str | None) -> str | None:
    """The role of the two that may do more; either may be None."""
    if a is None:
        return b
    if b is None:
        return a
    return a if RANK.get(a, -1) >= RANK.get(b, -1) else b
