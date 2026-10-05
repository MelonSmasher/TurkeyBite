"""The rules the console ships with.

Each has a key and a version. At every start the console adds any it does not
have yet, and moves an unmodified one to a newer version when this file
changes. A rule someone has changed keeps their change and is marked as
having an update available, which they can review and take by resetting it.

The threat and policy rules read the taxonomy facets TurkeyBite writes,
bite.risk and bite.purpose, rather than raw category names, so a new list
spelling the same judgement differently is covered without editing a rule.
Incidental lookups, made on someone's behalf by an embedded widget, are left
out wherever a rule is about what a person chose to do.
"""

ENTITY = ['entity']

# Hostnames of public DNS-over-HTTPS and DNS-over-TLS resolvers. A device
# that uses one sends its lookups around the network's own resolver, which is
# where TurkeyBite sees them, so its traffic disappears from every other rule.
ENCRYPTED_DNS = (
    'dns.google', 'dns64.dns.google', 'cloudflare-dns.com', 'mozilla.cloudflare-dns.com',
    'chrome.cloudflare-dns.com', 'one.one.one.one', 'security.cloudflare-dns.com',
    'family.cloudflare-dns.com', 'dns.quad9.net', 'dns9.quad9.net', 'dns10.quad9.net',
    'dns11.quad9.net', 'doh.opendns.com', 'doh.familyshield.opendns.com', 'dns.nextdns.io',
    'doh.cleanbrowsing.org', 'dns.adguard-dns.com', 'dns-unfiltered.adguard.com',
    'dns.adguard.com', 'doh.mullvad.net', 'dns.mullvad.net', 'adblock.dns.mullvad.net',
    'doh.dns.sb', 'dns.controld.com', 'freedns.controld.com', 'doh.libredns.gr',
    'dns.alidns.com', 'doh.pub', 'dns.twnic.tw', 'ordns.he.net',
)


def _any(field: str, values) -> str:
    return f'{field}:(' + ' OR '.join(values) + ')'


DEFAULT_RULES: list[dict] = [
    # -- threats ------------------------------------------------------------
    {
        'key': 'threat-domain', 'version': 1, 'category': 'threat',
        'name': 'Known threat domain contacted',
        'description': 'A lookup or visit to a domain the threat lists agree is malware, '
                       'ransomware, phishing or command and control. One event is enough.',
        'type': 'threshold', 'query': 'risk:(threat.malware OR threat.ransomware OR '
                                      'threat.phishing OR threat.malicious OR threat.c2)',
        'params': {'threshold': 1}, 'group_by': ENTITY, 'severity': 'critical', 'enabled': True,
        'interval_seconds': 300, 'window_seconds': 900, 'dedup_seconds': 4 * 3600,
        'tags': ['threat'], 'title_template': 'Threat domain contacted by {entity}',
    },
    {
        'key': 'fraud-scam', 'version': 1, 'category': 'threat',
        'name': 'Fraud or scam site',
        'description': 'A visit or lookup the lists classify as fraud or a scam.',
        'type': 'threshold', 'query': 'risk:(threat.fraud OR threat.scam) AND NOT incidental:true',
        'params': {'threshold': 1}, 'group_by': ENTITY, 'severity': 'medium', 'enabled': True,
        'interval_seconds': 300, 'window_seconds': 900, 'dedup_seconds': 12 * 3600,
        'tags': ['threat'], 'title_template': 'Fraud or scam site reached by {entity}',
    },
    {
        'key': 'cryptomining', 'version': 1, 'category': 'threat',
        'name': 'Cryptomining',
        'description': 'Repeated contact with mining pools or in-browser miners, a common '
                       'sign of a compromised machine or a hijacked page.',
        'type': 'threshold', 'query': 'risk:threat.cryptomining',
        'params': {'threshold': 3}, 'group_by': ENTITY, 'severity': 'high', 'enabled': True,
        'interval_seconds': 300, 'window_seconds': 1800, 'dedup_seconds': 12 * 3600,
        'tags': ['threat'], 'title_template': 'Cryptomining activity on {entity}',
    },
    {
        'key': 'dns-tunneling', 'version': 1, 'category': 'threat',
        'name': 'Possible DNS tunneling',
        'description': 'Hundreds of distinct names under one domain in a few minutes. Data '
                       'smuggled out through DNS looks like this; so does a CDN, which is '
                       'why advertising and tracking domains are left out and the bar is high.',
        'type': 'unique_count',
        'query': 'type:dns AND NOT risk:(privacy.advertising OR privacy.tracking)',
        'params': {'field': 'bite.requested', 'threshold': 300},
        'group_by': ['bite.registrable_domain'], 'severity': 'high', 'enabled': True,
        'interval_seconds': 300, 'window_seconds': 900, 'dedup_seconds': 6 * 3600,
        'tags': ['threat', 'dns'], 'title_template': 'Possible DNS tunneling through {entity}',
    },
    {
        'key': 'nxdomain-storm', 'version': 1, 'category': 'threat',
        'name': 'Failed-lookup storm',
        'description': 'Most of a client\'s lookups fail with NXDOMAIN. Malware that generates '
                       'domain names to find its controller looks like this, as does a badly '
                       'misconfigured machine.',
        'type': 'ratio', 'query': 'type:dns',
        'params': {'numerator': 'rcode:NXDOMAIN', 'ratio': 0.6, 'min_count': 100},
        'group_by': ENTITY, 'severity': 'high', 'enabled': True,
        'interval_seconds': 300, 'window_seconds': 900, 'dedup_seconds': 6 * 3600,
        'tags': ['threat', 'dns'], 'title_template': 'Failed-lookup storm from {entity}',
    },
    {
        'key': 'new-threat-domain', 'version': 1, 'category': 'threat',
        'name': 'Risky domain seen for the first time',
        'description': 'A domain with any risk classification that nobody on the network had '
                       'contacted in the two weeks before. Waits for two weeks of history.',
        'type': 'new_value', 'query': 'has:risk AND NOT risk:(privacy.advertising OR '
                                      'privacy.tracking) AND NOT incidental:true',
        'params': {'field': 'bite.registrable_domain', 'lookback_days': 14},
        'group_by': [], 'severity': 'medium', 'enabled': True,
        'interval_seconds': 900, 'window_seconds': 900, 'dedup_seconds': 24 * 3600,
        'tags': ['threat', 'first-seen'], 'title_template': 'First contact with a risky domain',
    },

    # -- policy ---------------------------------------------------------------
    {
        'key': 'encrypted-dns-bypass', 'version': 1, 'category': 'policy',
        'name': 'Encrypted DNS bypass',
        'description': 'A device looked up a public DNS-over-HTTPS or DNS-over-TLS resolver. '
                       'Once it uses one, its lookups go around the network resolver that '
                       'TurkeyBite watches, and every other rule goes blind to it.',
        'type': 'threshold', 'query': _any('domain', ENCRYPTED_DNS),
        'params': {'threshold': 1}, 'group_by': ENTITY, 'severity': 'high', 'enabled': True,
        'interval_seconds': 300, 'window_seconds': 900, 'dedup_seconds': 24 * 3600,
        'tags': ['policy', 'evasion'], 'title_template': 'Encrypted DNS resolver used by {entity}',
    },
    {
        'key': 'anonymiser', 'version': 1, 'category': 'policy',
        'name': 'VPN or proxy use',
        'description': 'Contact with a VPN provider or anonymising proxy, which hides what '
                       'happens next from the network.',
        'type': 'threshold', 'query': 'risk:policy.anonymiser AND NOT incidental:true',
        'params': {'threshold': 2}, 'group_by': ENTITY, 'severity': 'medium', 'enabled': True,
        'interval_seconds': 300, 'window_seconds': 1800, 'dedup_seconds': 24 * 3600,
        'tags': ['policy', 'evasion'], 'title_template': 'VPN or proxy used by {entity}',
    },
    {
        'key': 'adult-content', 'version': 1, 'category': 'content',
        'name': 'Adult content',
        'description': 'Pornography the lists agree on, visited or looked up on purpose: '
                       'incidental lookups by embedded widgets are left out.',
        'type': 'threshold', 'query': 'purpose:adult.pornography AND NOT incidental:true',
        'params': {'threshold': 2}, 'group_by': ENTITY, 'severity': 'high', 'enabled': True,
        'interval_seconds': 300, 'window_seconds': 900, 'dedup_seconds': 12 * 3600,
        'tags': ['content'], 'title_template': 'Adult content reached by {entity}',
    },
    {
        'key': 'gambling', 'version': 1, 'category': 'content',
        'name': 'Gambling',
        'description': 'Repeated visits to gambling sites.',
        'type': 'threshold', 'query': 'purpose:adult.gambling AND NOT incidental:true',
        'params': {'threshold': 3}, 'group_by': ENTITY, 'severity': 'medium', 'enabled': True,
        'interval_seconds': 600, 'window_seconds': 3600, 'dedup_seconds': 24 * 3600,
        'tags': ['content'], 'title_template': 'Gambling sites visited by {entity}',
    },
    {
        'key': 'drugs', 'version': 1, 'category': 'content',
        'name': 'Drug sites',
        'description': 'Repeated visits to sites the lists classify as drug-related.',
        'type': 'threshold', 'query': 'purpose:adult.drugs AND NOT incidental:true',
        'params': {'threshold': 3}, 'group_by': ENTITY, 'severity': 'medium', 'enabled': False,
        'interval_seconds': 600, 'window_seconds': 3600, 'dedup_seconds': 24 * 3600,
        'tags': ['content'], 'title_template': 'Drug-related sites visited by {entity}',
    },
    {
        'key': 'piracy', 'version': 1, 'category': 'policy',
        'name': 'Piracy and torrents',
        'description': 'Torrent trackers and piracy sites.',
        'type': 'threshold', 'query': 'risk:policy.piracy AND NOT incidental:true',
        'params': {'threshold': 5}, 'group_by': ENTITY, 'severity': 'low', 'enabled': False,
        'interval_seconds': 900, 'window_seconds': 3600, 'dedup_seconds': 24 * 3600,
        'tags': ['policy'], 'title_template': 'Piracy or torrent use by {entity}',
    },
    {
        'key': 'dating', 'version': 1, 'category': 'content',
        'name': 'Dating apps',
        'description': 'Dating services, for networks where they are out of policy.',
        'type': 'threshold', 'query': 'purpose:social.dating AND NOT incidental:true',
        'params': {'threshold': 3}, 'group_by': ENTITY, 'severity': 'low', 'enabled': False,
        'interval_seconds': 900, 'window_seconds': 3600, 'dedup_seconds': 24 * 3600,
        'tags': ['content'], 'title_template': 'Dating service used by {entity}',
    },
    {
        'key': 'ai-tools', 'version': 1, 'category': 'content',
        'name': 'Generative AI tools',
        'description': 'Use of AI assistants, for networks that need to know, such as during '
                       'exams.',
        'type': 'threshold', 'query': 'purpose:technology.ai AND NOT incidental:true',
        'params': {'threshold': 5}, 'group_by': ENTITY, 'severity': 'info', 'enabled': False,
        'interval_seconds': 900, 'window_seconds': 3600, 'dedup_seconds': 24 * 3600,
        'tags': ['content'], 'title_template': 'AI tools used by {entity}',
    },
    {
        'key': 'after-hours', 'version': 1, 'category': 'policy',
        'name': 'After-hours browsing',
        'description': 'Pages opened between 22:00 and 06:00. Set the hours and the time zone '
                       'to the network\'s own before enabling.',
        'type': 'threshold', 'query': 'type:browser.history AND NOT incidental:true',
        'params': {'threshold': 20}, 'group_by': ENTITY, 'severity': 'low', 'enabled': False,
        'interval_seconds': 900, 'window_seconds': 3600, 'dedup_seconds': 24 * 3600,
        'schedule': {'days': [0, 1, 2, 3, 4, 5, 6], 'start': '22:00', 'end': '06:00',
                     'timezone': 'UTC'},
        'tags': ['policy'], 'title_template': 'After-hours activity by {entity}',
    },

    # -- anomalies ------------------------------------------------------------
    {
        'key': 'entity-spike', 'version': 1, 'category': 'anomaly',
        'name': 'Unusual burst of activity',
        'description': 'A person or machine making far more requests than usual for the time '
                       'of day: an infected machine, an automated tool, or a binge.',
        'type': 'spike', 'query': 'NOT incidental:true',
        'params': {'baseline_windows': 24, 'z_score': 5.0, 'ratio': 4.0, 'min_count': 400},
        'group_by': ENTITY, 'severity': 'medium', 'enabled': True,
        'interval_seconds': 900, 'window_seconds': 3600, 'dedup_seconds': 6 * 3600,
        'tags': ['anomaly'], 'title_template': 'Unusual burst of activity from {entity}',
    },
    {
        'key': 'risk-spike', 'version': 1, 'category': 'anomaly',
        'name': 'Spike in risky traffic',
        'description': 'Network-wide, many more risky events than usual: an outbreak, a '
                       'campaign, or a list that just started flagging something common.',
        'type': 'spike', 'query': 'has:risk AND NOT risk:(privacy.advertising OR '
                                  'privacy.tracking)',
        'params': {'baseline_windows': 24, 'z_score': 4.0, 'ratio': 3.0, 'min_count': 50},
        'group_by': [], 'severity': 'high', 'enabled': True,
        'interval_seconds': 900, 'window_seconds': 3600, 'dedup_seconds': 6 * 3600,
        'tags': ['anomaly'], 'title_template': 'Spike in risky traffic network-wide',
    },
    {
        'key': 'new-purpose-for-entity', 'version': 1, 'category': 'anomaly',
        'name': 'New kind of site for someone',
        'description': 'A person reaching a kind of site, by purpose, that they had not in the '
                       'two weeks before. Useful, and noisy: enable it with care.',
        'type': 'new_value', 'query': 'has:purpose AND NOT incidental:true',
        'params': {'field': 'bite.purpose', 'lookback_days': 14},
        'group_by': ENTITY, 'severity': 'info', 'enabled': False,
        'interval_seconds': 1800, 'window_seconds': 1800, 'dedup_seconds': 24 * 3600,
        'tags': ['anomaly', 'first-seen'], 'title_template': 'New kind of site for {entity}',
    },

    # -- health -----------------------------------------------------------------
    {
        'key': 'pipeline-silent', 'version': 1, 'category': 'health',
        'name': 'TurkeyBite stopped sending events',
        'description': 'No events at all for 15 minutes after a normal day. The beats, the '
                       'workers or OpenSearch have stopped, and nothing is being watched.',
        'type': 'absence', 'query': '',
        'params': {'threshold': 1, 'lookback_seconds': 86400, 'min_baseline': 100},
        'group_by': [], 'severity': 'critical', 'enabled': True,
        'interval_seconds': 300, 'window_seconds': 900, 'dedup_seconds': 2 * 3600,
        'tags': ['health'], 'title_template': 'TurkeyBite stopped sending events',
    },
    {
        'key': 'agent-silent', 'version': 1, 'category': 'health',
        'name': 'A browser agent went quiet',
        'description': 'A machine that reported browsing all day has sent nothing for two '
                       'hours. Machines sleep, so this is off by default; on managed desktops '
                       'it catches an agent that was stopped.',
        'type': 'absence', 'query': 'type:browser.history',
        'params': {'threshold': 1, 'lookback_seconds': 86400, 'min_baseline': 50},
        'group_by': ['bite.client_hostname_short'], 'severity': 'low', 'enabled': False,
        'interval_seconds': 1800, 'window_seconds': 7200, 'dedup_seconds': 24 * 3600,
        'tags': ['health'], 'title_template': 'Browser agent quiet on {entity}',
    },
]

BY_KEY = {rule['key']: rule for rule in DEFAULT_RULES}

DEFINITION_FIELDS = ('name', 'description', 'category', 'type', 'query', 'params', 'group_by',
                     'severity', 'interval_seconds', 'window_seconds', 'dedup_seconds',
                     'schedule', 'tags', 'title_template')
