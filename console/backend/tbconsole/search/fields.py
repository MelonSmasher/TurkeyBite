"""The fields of a TurkeyBite event, as the console offers them.

Every field a query, a group-by or a rule can name is listed here. The list is
an allowlist as well as a catalogue: a query that names anything else is
refused rather than sent, so nobody can reach a field, a script or an index
the console does not mean to expose by naming it.

The types follow docker/librarian/setup-opensearch-template.sh, which is what
the indices are created with.
"""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Field:
    name: str
    label: str
    type: str                     # keyword, ip, date, boolean, long, text
    group: str
    description: str = ''
    aliases: tuple[str, ...] = ()
    aggregatable: bool = True
    # Values are dotted taxonomy paths, so threat matches threat.malware
    hierarchical: bool = False
    # Identifies a person or a machine, so it is masked in privacy mode and
    # viewing a profile of one is audited
    identity: bool = False
    columns_default: bool = False

    def public(self) -> dict:
        data = asdict(self)
        data['aliases'] = list(self.aliases)
        return data


FIELDS: tuple[Field, ...] = (
    Field('@timestamp', 'Time', 'date', 'Event', 'When the lookup or visit happened.',
          aliases=('time', 'timestamp'), columns_default=True),
    Field('bite.type', 'Event type', 'keyword', 'Event',
          'dns for a lookup Packetbeat saw, browser.history for a page a browser opened.',
          aliases=('type',), columns_default=True),
    Field('bite.request', 'Direction', 'keyword', 'Event', 'query, reply, or the URL scheme.',
          aliases=('request', 'direction')),
    Field('bite.requested', 'Domain', 'keyword', 'Request',
          'The name looked up or the host visited.', aliases=('domain', 'host.name', 'name'),
          columns_default=True),
    Field('bite.registrable_domain', 'Registrable domain', 'keyword', 'Request',
          'The domain one owner registered, from the Public Suffix List.',
          aliases=('site', 'registrable', 'etld1')),
    Field('bite.searches', 'Search keys', 'keyword', 'Request',
          'Every name the lists were searched for: the host, its domain and wildcards.',
          aliases=('searches',)),
    Field('bite.url', 'URL', 'keyword', 'Request',
          'The page visited, trimmed as processor.privacy says.', aliases=('url',)),
    Field('bite.response_code', 'Response code', 'keyword', 'DNS',
          'The DNS response code: NOERROR, NXDOMAIN, SERVFAIL...', aliases=('rcode', 'response')),
    Field('bite.resolved_ips', 'Resolved addresses', 'ip', 'DNS',
          'Addresses in the answer section.', aliases=('resolved', 'answer')),
    Field('bite.cname_chain', 'CNAME chain', 'keyword', 'DNS',
          'CNAME targets in the answer, in order.', aliases=('cname',)),
    Field('bite.contexts', 'Categories', 'keyword', 'Classification',
          'Categories the evidence supports.', aliases=('category', 'cat', 'contexts'),
          columns_default=True),
    Field('bite.purpose', 'Purpose', 'keyword', 'Classification',
          'What kind of thing it is: social.networks, adult.gambling...',
          aliases=('purpose',), hierarchical=True),
    Field('bite.service', 'Service', 'keyword', 'Classification',
          'Which service it is: google.youtube, valve.steam...', aliases=('service',),
          hierarchical=True),
    Field('bite.risk', 'Risk', 'keyword', 'Classification',
          'What the risk is: threat.malware, policy.anonymiser...', aliases=('risk',),
          hierarchical=True, columns_default=True),
    Field('bite.risk_severity', 'Risk severity', 'keyword', 'Classification',
          'high, medium or low, from the risk taxonomy.', aliases=('severity', 'risk_severity')),
    Field('bite.contexts_candidate', 'Candidate categories', 'keyword', 'Evidence',
          'Categories a list claimed without enough support to be believed.',
          aliases=('candidate',)),
    Field('bite.contexts_suppressed', 'Suppressed categories', 'keyword', 'Evidence',
          'Categories the ignorelist cancelled.', aliases=('suppressed',)),
    Field('bite.claims', 'Claims', 'keyword', 'Evidence', 'Which list said what, as category:list.',
          aliases=('claim', 'claims')),
    Field('bite.sources', 'Sources', 'keyword', 'Evidence', 'The lists that matched.',
          aliases=('source', 'list')),
    Field('bite.matched_on', 'Matched on', 'keyword', 'Evidence', 'The key the lists matched.'),
    Field('bite.match_source', 'Match source', 'keyword', 'Evidence',
          'question, cname, or both.'),
    Field('bite.incidental', 'Incidental', 'boolean', 'Evidence',
          'A lookup made on someone else\'s behalf, such as an embedded widget.',
          aliases=('incidental',)),
    Field('bite.unmapped_contexts', 'Unmapped categories', 'keyword', 'Evidence',
          'Categories with no taxonomy row.', aliases=('unmapped',)),
    Field('bite.resolvers.quad9', 'Quad9 verdict', 'keyword', 'Evidence',
          'What Quad9 said, when resolver corroboration is on.', aliases=('quad9',)),
    Field('bite.resolvers.cloudflare-security', 'Cloudflare security verdict', 'keyword',
          'Evidence', aliases=('cloudflare',)),
    Field('bite.resolvers.cloudflare-family', 'Cloudflare family verdict', 'keyword', 'Evidence'),
    Field('bite.client', 'Client IP', 'ip', 'Client', 'The address that asked.',
          aliases=('client', 'ip', 'src'), identity=True, columns_default=True),
    Field('bite.client_ips', 'Client addresses', 'ip', 'Client',
          'Every routable address a browser reported.', identity=True),
    Field('bite.client_user', 'User', 'keyword', 'Client', 'The signed-in user a browser reported.',
          aliases=('user', 'username'), identity=True, columns_default=True),
    Field('bite.client_hostname', 'Hostname', 'keyword', 'Client',
          'The machine name a browser reported.', aliases=('hostname',), identity=True),
    Field('bite.client_hostname_short', 'Host', 'keyword', 'Client',
          'The hostname without its domain.', aliases=('host',), identity=True),
    Field('bite.client_hosts', 'PTR names', 'keyword', 'Client',
          'Reverse DNS names for the client address.', aliases=('ptrs',), identity=True),
    Field('bite.client_hosts_short', 'PTR hosts', 'keyword', 'Client',
          'Reverse DNS names without their domain.', identity=True),
    Field('bite.ptr', 'PTR', 'keyword', 'Client', 'The reverse name that was asked for.',
          aliases=('ptr',), identity=True),
    Field('bite.ptr_status', 'PTR status', 'keyword', 'Client',
          'ok, failed, skipped... from the reverse lookup.'),
    Field('bite.client_platform', 'Platform', 'keyword', 'Client', 'windows, darwin, linux...',
          aliases=('platform', 'os')),
    Field('bite.client_browser', 'Browser', 'keyword', 'Client', 'chrome, firefox, safari...',
          aliases=('browser',)),
    Field('bite.processed', 'Processed', 'date', 'Event', 'When a worker enriched the event.'),
)

BY_NAME: dict[str, Field] = {f.name: f for f in FIELDS}
_ALIASES: dict[str, str] = {}
for _f in FIELDS:
    _ALIASES[_f.name.lower()] = _f.name
    for _alias in _f.aliases:
        _ALIASES[_alias.lower()] = _f.name

# Who an event is about, as a list of fields tried in order. A browser event
# names a user and a machine; a DNS event usually only an address, and a PTR
# name when reverse lookups are on. Grouping by the first one an event has
# means one rule covers both feeds.
ENTITY = 'entity'
ENTITY_FIELDS = ('bite.client_user', 'bite.client_hostname_short', 'bite.client_hosts_short',
                 'bite.client')
ENTITY_LABEL = 'Person or machine'


def resolve(name: str) -> Field | None:
    """The field a name or alias means, or None."""
    canonical = _ALIASES.get((name or '').strip().lower())
    return BY_NAME.get(canonical) if canonical else None


def group_fields(group_by: list[str] | tuple[str, ...]) -> list[str]:
    """Expands `entity` and aliases into the real fields to group on, in order."""
    out: list[str] = []
    for name in group_by or []:
        if name == ENTITY:
            out.extend(f for f in ENTITY_FIELDS if f not in out)
            continue
        f = resolve(name)
        if f is None or not f.aggregatable:
            raise ValueError(f'cannot group by {name!r}')
        if f.name not in out:
            out.append(f.name)
    return out


def catalog() -> list[dict]:
    return [f.public() for f in FIELDS]
