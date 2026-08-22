"""Three facets, from the one flat array of categories.

`bite.contexts` jams three different kinds of statement into one list. Sorting
the categories by what they actually assert:

    what kind of thing it is   social, streaming, games, mail, search ...
    which service it is        facebook, youtube, steam, zoom ...
    what the risk is           malware, phishing, tracking, torrent ...

Those are orthogonal. facebook.com is simultaneously the Facebook service, social
media by purpose, and a tracking risk, and cramming all three into one array is
why every percentage computed from it is ambiguous: `social` double counts
everything that is also `facebook`, and `professional` counts Outlook once as
`professional` and again as `mail`.

So each category maps to one or more (facet, path) pairs, and the event carries
`bite.purpose`, `bite.service` and `bite.risk` alongside the unchanged
`bite.contexts`. Nothing is removed, so existing queries keep working.

Two properties worth knowing about the mapping.

A vendor category contributes its purpose as well as its service, so
`steam` yields both `valve.steam` and `gaming.storefronts`. The lists happen to
assign the parent category too, which would make that redundant, but relying on
that would make the facets depend on list behaviour rather than on the taxonomy.

Duplicate categories collapse. `fake-news` and `fakenews` are the same judgement
spelled two ways by two different sources, as are `signal` and `whispersystems`,
and mapping them onto one path is the point of having a taxonomy at all.
"""

PURPOSE = 'purpose'
SERVICE = 'service'
RISK = 'risk'
FACETS = (PURPOSE, SERVICE, RISK)

# Editorial branches are deliberately separate from threat and privacy. A report
# that names a person against an editorially defined category is scrutinised
# differently from one that names malware, and the distinction has to be visible
# in the data for a UI to be able to exclude it.
TAXONOMY = {
    # -- purpose only ----------------------------------------------------
    'social': ((PURPOSE, 'social.networks'),),
    'streaming': ((PURPOSE, 'media.streaming'),),
    'streaming-audio': ((PURPOSE, 'media.audio'),),
    'streaming-video': ((PURPOSE, 'media.video'),),
    'games': ((PURPOSE, 'gaming.platforms'),),
    'shopping': ((PURPOSE, 'commerce.retail'),),
    'news': ((PURPOSE, 'information.news'),),
    'education': ((PURPOSE, 'information.education'),),
    'government': ((PURPOSE, 'information.government'),),
    'search': ((PURPOSE, 'information.search'),),
    'professional': ((PURPOSE, 'productivity.office'),),
    'mail': ((PURPOSE, 'communication.email'),),
    'it': ((PURPOSE, 'technology.it-services'),),
    'development': ((PURPOSE, 'technology.development'),),
    'ai': ((PURPOSE, 'technology.ai'),),
    # Pornography, gambling and drugs are content types. Whether they are a
    # policy violation is a separate question and belongs to policy
    # configuration, not baked into the content label.
    'porn': ((PURPOSE, 'adult.pornography'),),
    'gambling': ((PURPOSE, 'adult.gambling'),),
    'drugs': ((PURPOSE, 'adult.drugs'),),

    # -- risk only -------------------------------------------------------
    # `malicious` is the generic threat label the lists use most, so it gets a
    # leaf of its own rather than being forced under a specific threat type
    'malicious': ((RISK, 'threat.malicious'),),
    'malware': ((RISK, 'threat.malware'),),
    'ransomware': ((RISK, 'threat.ransomware'),),
    'phishing': ((RISK, 'threat.phishing'),),
    'fraud': ((RISK, 'threat.fraud'),),
    'scam': ((RISK, 'threat.scam'),),
    # Named "crypto" by its sources, which in a blocklist means cryptojacking
    # rather than currency sites
    'crypto': ((RISK, 'threat.cryptomining'),),
    'tracking': ((RISK, 'privacy.tracking'),),
    'windows-tracking': ((RISK, 'privacy.tracking'),),
    'advertising': ((RISK, 'privacy.advertising'),),
    'torrent': ((RISK, 'policy.piracy'),),
    'piracy': ((RISK, 'policy.piracy'),),
    'url-shorteners': ((RISK, 'policy.url-shortener'),),
    'proxy': ((RISK, 'policy.anonymiser'),),
    'vpn': ((RISK, 'policy.anonymiser'),),
    'fake-news': ((RISK, 'editorial.fakenews'),),
    'fakenews': ((RISK, 'editorial.fakenews'),),
    'fascist': ((RISK, 'editorial.fascist'),),
    'zionist': ((RISK, 'editorial.zionist'),),

    # -- services: social and communication ------------------------------
    'facebook': ((SERVICE, 'meta.facebook'), (PURPOSE, 'social.networks')),
    'instagram': ((SERVICE, 'meta.instagram'), (PURPOSE, 'social.networks')),
    'whatsapp': ((SERVICE, 'meta.whatsapp'), (PURPOSE, 'communication.messaging')),
    'twitter': ((SERVICE, 'x.twitter'), (PURPOSE, 'social.networks')),
    'tiktok': ((SERVICE, 'bytedance.tiktok'), (PURPOSE, 'social.networks')),
    'snapchat': ((SERVICE, 'snap.snapchat'), (PURPOSE, 'social.networks')),
    'reddit': ((SERVICE, 'reddit'), (PURPOSE, 'social.forums')),
    'myspace': ((SERVICE, 'myspace'), (PURPOSE, 'social.networks')),
    'tinder': ((SERVICE, 'match.tinder'), (PURPOSE, 'social.dating')),
    'discord': ((SERVICE, 'discord'), (PURPOSE, 'communication.messaging')),
    'telegram': ((SERVICE, 'telegram'), (PURPOSE, 'communication.messaging')),
    'signal': ((SERVICE, 'signal'), (PURPOSE, 'communication.messaging')),
    'whispersystems': ((SERVICE, 'signal'), (PURPOSE, 'communication.messaging')),
    # The Zoom problem from the taxonomy notes: a work tool that was inflating
    # social media numbers because the flat array had nowhere else to put it
    'zoom': ((SERVICE, 'zoom'), (PURPOSE, 'communication.voice-video')),

    # -- services: media -------------------------------------------------
    'youtube': ((SERVICE, 'google.youtube'), (PURPOSE, 'media.video')),
    'netflix': ((SERVICE, 'netflix'), (PURPOSE, 'media.video')),
    'hulu': ((SERVICE, 'hulu'), (PURPOSE, 'media.video')),
    'disneyplus': ((SERVICE, 'disney.plus'), (PURPOSE, 'media.video')),
    'vimeo': ((SERVICE, 'vimeo'), (PURPOSE, 'media.video')),
    'spotify': ((SERVICE, 'spotify'), (PURPOSE, 'media.audio')),
    'twitch': ((SERVICE, 'amazon.twitch'), (PURPOSE, 'gaming.streaming')),

    # -- services: gaming ------------------------------------------------
    'steam': ((SERVICE, 'valve.steam'), (PURPOSE, 'gaming.storefronts')),
    'epicgames': ((SERVICE, 'epic.games'), (PURPOSE, 'gaming.storefronts')),
    'nintendo': ((SERVICE, 'nintendo.eshop'), (PURPOSE, 'gaming.platforms')),
    'ea': ((SERVICE, 'ea'), (PURPOSE, 'gaming.platforms')),
    'activision': ((SERVICE, 'activision'), (PURPOSE, 'gaming.platforms')),
    'blizzard': ((SERVICE, 'blizzard'), (PURPOSE, 'gaming.platforms')),
    'riotgames': ((SERVICE, 'riot.games'), (PURPOSE, 'gaming.platforms')),
    'rockstargames': ((SERVICE, 'rockstar.games'), (PURPOSE, 'gaming.platforms')),
    'take-twointeractive': ((SERVICE, 'taketwo'), (PURPOSE, 'gaming.platforms')),
    'ubisoft': ((SERVICE, 'ubisoft'), (PURPOSE, 'gaming.platforms')),
    'square-enix': ((SERVICE, 'squareenix'), (PURPOSE, 'gaming.platforms')),
    'minecraft': ((SERVICE, 'microsoft.minecraft'), (PURPOSE, 'gaming.platforms')),
    'roblox': ((SERVICE, 'roblox'), (PURPOSE, 'gaming.platforms')),
    'warthunder': ((SERVICE, 'gaijin.warthunder'), (PURPOSE, 'gaming.platforms')),
    'zynga': ((SERVICE, 'zynga'), (PURPOSE, 'gaming.platforms')),

    # -- services: VPN vendors -------------------------------------------
    # Each names a product and each carries the same policy concern, which is
    # exactly the separation the flat array could not express
    'atlasvpn': ((SERVICE, 'atlasvpn'), (RISK, 'policy.anonymiser')),
    'cyberghostvpn': ((SERVICE, 'cyberghost'), (RISK, 'policy.anonymiser')),
    'expressvpn': ((SERVICE, 'expressvpn'), (RISK, 'policy.anonymiser')),
    'freevpnplanet': ((SERVICE, 'freevpnplanet'), (RISK, 'policy.anonymiser')),
    'hide.me': ((SERVICE, 'hideme'), (RISK, 'policy.anonymiser')),
    'hotspotshield': ((SERVICE, 'pango.hotspotshield'), (RISK, 'policy.anonymiser')),
    'ipvanish': ((SERVICE, 'ipvanish'), (RISK, 'policy.anonymiser')),
    'ivpn': ((SERVICE, 'ivpn'), (RISK, 'policy.anonymiser')),
    'mullvad': ((SERVICE, 'mullvad'), (RISK, 'policy.anonymiser')),
    'privadovpn': ((SERVICE, 'privadovpn'), (RISK, 'policy.anonymiser')),
    'privateinternetaccess': ((SERVICE, 'pia'), (RISK, 'policy.anonymiser')),
    'protonvpn': ((SERVICE, 'proton.vpn'), (RISK, 'policy.anonymiser')),
    'purevpn': ((SERVICE, 'purevpn'), (RISK, 'policy.anonymiser')),
    'strongvpn': ((SERVICE, 'strongvpn'), (RISK, 'policy.anonymiser')),
    'surfshark': ((SERVICE, 'surfshark'), (RISK, 'policy.anonymiser')),
    'tunnelbear': ((SERVICE, 'tunnelbear'), (RISK, 'policy.anonymiser')),
    'urbanvpn': ((SERVICE, 'urbanvpn'), (RISK, 'policy.anonymiser')),
}

# Severity is a property of the risk leaf rather than a separate list, so a
# finding rule can threshold on it. Absent means the leaf carries no severity,
# which is true of the editorial branch by design: those are judgements to be
# reported on request, not ranked against malware.
SEVERITY = {
    'threat.malicious': 'high',
    'threat.malware': 'high',
    'threat.ransomware': 'high',
    'threat.phishing': 'high',
    'threat.c2': 'high',
    'threat.fraud': 'medium',
    'threat.scam': 'medium',
    'threat.cryptomining': 'medium',
    'policy.anonymiser': 'medium',
    'policy.piracy': 'low',
    'policy.url-shortener': 'low',
    'privacy.tracking': 'low',
    'privacy.advertising': 'low',
}


def classify(contexts):
    """Facets for a list of flat categories.

    Returns a dict with only the non-empty keys, so a query can tell absent from
    empty. `unmapped` names categories with no taxonomy row, which is how a newly
    added list source becomes visible instead of silently contributing nothing.
    """
    buckets = {facet: set() for facet in FACETS}
    unmapped = []
    for context in contexts or []:
        if not isinstance(context, str):
            continue
        key = context.strip().lower()
        if not key:
            continue
        rows = TAXONOMY.get(key)
        if not rows:
            if key not in unmapped:
                unmapped.append(key)
            continue
        for facet, path in rows:
            buckets[facet].add(path)

    result = {}
    for facet in FACETS:
        if buckets[facet]:
            result[facet] = sorted(buckets[facet])
    if unmapped:
        result['unmapped'] = sorted(unmapped)

    severities = {SEVERITY[path] for path in buckets[RISK] if path in SEVERITY}
    for level in ('high', 'medium', 'low'):
        if level in severities:
            result['risk_severity'] = level
            break
    return result
