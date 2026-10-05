"""Made-up data for trying the console: python -m tbconsole demo seed.

Everything here is invented: the school, its people and machines, and every
domain that is not a household name. The events are written to OpenSearch in
the shape TurkeyBite's workers write them, the index template is TurkeyBite's
own, and the findings are raised by running the console's real rule engine
over the events, at the times it would have run, so what the demo shows is
what the console does.

This empties the console's database first. Never point it at a real console.
"""

import hashlib
import json
import random
import string
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sqlalchemy import select, text, update

from . import db, rollups, settings_store
from .analysis import engine
from .api.dashboards import sync_builtin_dashboards
from .models import (ApiKey, AuditEvent, DailyStat, Dashboard, Finding, FindingActivity, Rule,
                     SavedSearch, User, Webhook, WebhookDelivery)
from .search.client import SearchClient
from .security import apikeys, crypto, passwords, totp
from .webhooks import dispatcher, signing

ORG = 'Harbor Point Academy'
DOMAIN = 'harborpoint.local'
DEMO_PASSWORD = 'TurkeyBite-demo-2026!'
INDEX_PREFIX = 'tb-index'

# -- the taxonomy, as much of TurkeyBite's as the demo uses ---------------------------
TAXONOMY = {
    'social': [('purpose', 'social.networks')], 'streaming': [('purpose', 'media.streaming')],
    'games': [('purpose', 'gaming.platforms')], 'shopping': [('purpose', 'commerce.retail')],
    'news': [('purpose', 'information.news')], 'education': [('purpose', 'information.education')],
    'search': [('purpose', 'information.search')], 'professional': [('purpose', 'productivity.office')],
    'mail': [('purpose', 'communication.email')], 'it': [('purpose', 'technology.it-services')],
    'development': [('purpose', 'technology.development')], 'ai': [('purpose', 'technology.ai')],
    'porn': [('purpose', 'adult.pornography')], 'gambling': [('purpose', 'adult.gambling')],
    'malicious': [('risk', 'threat.malicious')], 'malware': [('risk', 'threat.malware')],
    'phishing': [('risk', 'threat.phishing')], 'scam': [('risk', 'threat.scam')],
    'crypto': [('risk', 'threat.cryptomining')], 'tracking': [('risk', 'privacy.tracking')],
    'advertising': [('risk', 'privacy.advertising')], 'torrent': [('risk', 'policy.piracy')],
    'url-shorteners': [('risk', 'policy.url-shortener')], 'proxy': [('risk', 'policy.anonymiser')],
    'vpn': [('risk', 'policy.anonymiser')],
    'tiktok': [('service', 'bytedance.tiktok'), ('purpose', 'social.networks')],
    'instagram': [('service', 'meta.instagram'), ('purpose', 'social.networks')],
    'snapchat': [('service', 'snap.snapchat'), ('purpose', 'social.networks')],
    'reddit': [('service', 'reddit'), ('purpose', 'social.forums')],
    'discord': [('service', 'discord'), ('purpose', 'communication.messaging')],
    'twitter': [('service', 'x.twitter'), ('purpose', 'social.networks')],
    'facebook': [('service', 'meta.facebook'), ('purpose', 'social.networks')],
    'youtube': [('service', 'google.youtube'), ('purpose', 'media.video')],
    'netflix': [('service', 'netflix'), ('purpose', 'media.video')],
    'spotify': [('service', 'spotify'), ('purpose', 'media.audio')],
    'twitch': [('service', 'amazon.twitch'), ('purpose', 'gaming.streaming')],
    'roblox': [('service', 'roblox'), ('purpose', 'gaming.platforms')],
    'minecraft': [('service', 'microsoft.minecraft'), ('purpose', 'gaming.platforms')],
    'steam': [('service', 'valve.steam'), ('purpose', 'gaming.storefronts')],
    'epicgames': [('service', 'epic.games'), ('purpose', 'gaming.storefronts')],
    'zoom': [('service', 'zoom'), ('purpose', 'communication.voice-video')],
    'protonvpn': [('service', 'proton.vpn'), ('risk', 'policy.anonymiser')],
    'expressvpn': [('service', 'expressvpn'), ('risk', 'policy.anonymiser')],
}
SEVERITY = {'threat.malicious': 'high', 'threat.malware': 'high', 'threat.phishing': 'high',
            'threat.scam': 'medium', 'threat.cryptomining': 'medium',
            'policy.anonymiser': 'medium', 'policy.piracy': 'low', 'policy.url-shortener': 'low',
            'privacy.tracking': 'low', 'privacy.advertising': 'low'}
LISTS = ('StevenBlack', 'oisd', 'hagezi', 'blocklistproject', 'urlhaus', 'local', 'shallalist',
         'phishing-army', 'firebog')


def facets(contexts: list[str]) -> dict:
    out = {'purpose': set(), 'service': set(), 'risk': set()}
    for c in contexts:
        for facet, path in TAXONOMY.get(c, ()):
            out[facet].add(path)
    fields = {k: sorted(v) for k, v in out.items() if v}
    levels = {SEVERITY[p] for p in out['risk'] if p in SEVERITY}
    for level in ('high', 'medium', 'low'):
        if level in levels:
            fields['risk_severity'] = level
            break
    return fields


# -- domains: (registrable, hosts, contexts, weight by persona) ----------------------
# persona weights: s = student, t = staff, l = lab machine, d = device (printer, camera)
D = [
    ('google.com', ['www.google.com', 'accounts.google.com', 'clients4.google.com'], ['search'], dict(s=30, t=30, l=30, d=2)),
    ('googleapis.com', ['fonts.googleapis.com', 'www.googleapis.com', 'storage.googleapis.com'], [], dict(s=20, t=20, l=20, d=4)),
    ('gstatic.com', ['www.gstatic.com', 'ssl.gstatic.com', 'fonts.gstatic.com'], [], dict(s=18, t=18, l=18)),
    ('instructure.com', ['harborpoint.instructure.com', 'du11hjcvx0uqb.cloudfront.net'], ['education'], dict(s=22, t=14, l=20)),
    ('khanacademy.org', ['www.khanacademy.org', 'cdn.kastatic.org'], ['education'], dict(s=9, t=2, l=12)),
    ('quizlet.com', ['quizlet.com', 'assets.quizlet.com'], ['education'], dict(s=8, t=1, l=6)),
    ('desmos.com', ['www.desmos.com'], ['education'], dict(s=5, l=7)),
    ('wikipedia.org', ['en.wikipedia.org', 'upload.wikimedia.org'], ['education'], dict(s=9, t=6, l=9)),
    ('microsoft.com', ['login.microsoftonline.com', 'www.microsoft.com', 'settings-win.data.microsoft.com'], ['professional', 'it'], dict(s=6, t=22, l=14, d=3)),
    ('office.com', ['www.office.com', 'outlook.office.com'], ['professional', 'mail'], dict(s=4, t=24, l=4)),
    ('zoom.us', ['zoom.us', 'us06web.zoom.us'], ['zoom'], dict(s=1, t=7)),
    ('apple.com', ['www.apple.com', 'gsp-ssl.ls.apple.com', 'mesu.apple.com'], ['it'], dict(s=6, t=6, d=2)),
    ('youtube.com', ['www.youtube.com', 'i.ytimg.com', 'rr3---sn-ab5l6nr6.googlevideo.com'], ['youtube', 'streaming'], dict(s=24, t=5, l=4)),
    ('tiktok.com', ['www.tiktok.com', 'v16-webapp.tiktok.com', 'mon.tiktokv.com'], ['tiktok', 'social'], dict(s=18, t=1)),
    ('instagram.com', ['www.instagram.com', 'scontent.cdninstagram.com'], ['instagram', 'social'], dict(s=12, t=2)),
    ('snapchat.com', ['web.snapchat.com', 'app.snapchat.com'], ['snapchat', 'social'], dict(s=8)),
    ('reddit.com', ['www.reddit.com', 'i.redd.it'], ['reddit', 'social'], dict(s=7, t=3)),
    ('discord.com', ['discord.com', 'gateway.discord.gg', 'cdn.discordapp.com'], ['discord'], dict(s=9, t=1)),
    ('x.com', ['x.com', 'pbs.twimg.com'], ['twitter', 'social'], dict(s=3, t=3)),
    ('spotify.com', ['open.spotify.com', 'audio-ak-spotify-com.akamaized.net'], ['spotify', 'streaming'], dict(s=9, t=4)),
    ('netflix.com', ['www.netflix.com', 'occ-0-1-2.1.nflxso.net'], ['netflix', 'streaming'], dict(s=3, t=1)),
    ('twitch.tv', ['www.twitch.tv', 'static.twitchcdn.net'], ['twitch'], dict(s=4)),
    ('roblox.com', ['www.roblox.com', 'apis.roblox.com', 'tr.rbxcdn.com'], ['roblox', 'games'], dict(s=9)),
    ('minecraft.net', ['www.minecraft.net', 'session.minecraft.net'], ['minecraft', 'games'], dict(s=4)),
    ('coolmathgames.com', ['www.coolmathgames.com'], ['games'], dict(s=6, l=3)),
    ('steampowered.com', ['store.steampowered.com', 'steamcdn-a.akamaihd.net'], ['steam'], dict(s=2)),
    ('epicgames.com', ['www.epicgames.com', 'launcher-public-service-prod06.ol.epicgames.com'], ['epicgames'], dict(s=2)),
    ('bbc.co.uk', ['www.bbc.co.uk', 'ichef.bbci.co.uk'], ['news'], dict(s=2, t=6)),
    ('nytimes.com', ['www.nytimes.com', 'static01.nyt.com'], ['news'], dict(s=1, t=5)),
    ('amazon.com', ['www.amazon.com', 'm.media-amazon.com'], ['shopping'], dict(s=4, t=6)),
    ('chatgpt.com', ['chatgpt.com', 'cdn.oaistatic.com'], ['ai'], dict(s=6, t=4)),
    ('claude.ai', ['claude.ai'], ['ai'], dict(s=2, t=3)),
    ('github.com', ['github.com', 'avatars.githubusercontent.com'], ['development'], dict(s=2, t=3, l=2)),
    ('doubleclick.net', ['securepubads.g.doubleclick.net', 'stats.g.doubleclick.net'], ['advertising'], dict(s=14, t=10, l=6)),
    ('google-analytics.com', ['www.google-analytics.com', 'region1.google-analytics.com'], ['tracking'], dict(s=12, t=10, l=8)),
    ('scorecardresearch.com', ['sb.scorecardresearch.com'], ['tracking'], dict(s=5, t=4)),
    ('facebook.net', ['connect.facebook.net'], ['facebook', 'tracking'], dict(s=5, t=3)),
    ('bit.ly', ['bit.ly'], ['url-shorteners'], dict(s=1, t=1)),
    ('pool.ntp.org', ['0.pool.ntp.org', '1.pool.ntp.org'], ['it'], dict(l=2, d=10)),
    ('hp.com', ['h10141.www1.hp.com', 'hpeprint.com'], ['it'], dict(d=10)),
    ('axis.com', ['firmware.axis.com'], ['it'], dict(d=6)),
]

# Rare and risky, used by background noise and by the incidents
RISKY = {
    'secure-docs-share.top': (['docs.secure-docs-share.top', 'secure-docs-share.top'], ['phishing'], 'phishing-army'),
    'paypa1-account-verify.com': (['www.paypa1-account-verify.com'], ['phishing', 'scam'], 'phishing-army'),
    'update-flashplayer-secure.com': (['dl.update-flashplayer-secure.com'], ['malware', 'malicious'], 'urlhaus'),
    'cdn-jsdelivr-libs.info': (['cdn-jsdelivr-libs.info'], ['malicious'], 'urlhaus'),
    'minexmr-pool.net': (['pool.minexmr-pool.net', 'xmr.minexmr-pool.net'], ['crypto'], 'hagezi'),
    'webminer-js.com': (['webminer-js.com'], ['crypto'], 'hagezi'),
    'protonvpn.com': (['protonvpn.com', 'account.protonvpn.com', 'api.protonvpn.ch'], ['protonvpn', 'vpn'], 'local'),
    'expressvpn.com': (['www.expressvpn.com'], ['expressvpn', 'vpn'], 'local'),
    'croxyproxy.com': (['www.croxyproxy.com'], ['proxy'], 'shallalist'),
    'proxysite.cloud': (['www.proxysite.cloud'], ['proxy'], 'shallalist'),
    'spinpalace-casino.net': (['www.spinpalace-casino.net', 'lobby.spinpalace-casino.net'], ['gambling'], 'blocklistproject'),
    'betstars-online.com': (['betstars-online.com'], ['gambling'], 'blocklistproject'),
    'nsfw-tube-example.com': (['www.nsfw-tube-example.com', 'cdn.nsfw-tube-example.com'], ['porn'], 'StevenBlack'),
    'adult-clips-example.net': (['adult-clips-example.net'], ['porn'], 'StevenBlack'),
    'fasttorrent-tracker.net': (['tracker.fasttorrent-tracker.net'], ['torrent'], 'StevenBlack'),
    'giftcard-winner-now.com': (['giftcard-winner-now.com'], ['scam'], 'oisd'),
}

DOH = ['mozilla.cloudflare-dns.com', 'dns.google', 'chrome.cloudflare-dns.com', 'dns.nextdns.io']

FIRST = ['ava', 'liam', 'noah', 'emma', 'olivia', 'ethan', 'mia', 'lucas', 'sophia', 'mason', 'isla',
         'logan', 'amelia', 'jacob', 'harper', 'elijah', 'aria', 'james', 'chloe', 'leo', 'zoe',
         'owen', 'nora', 'caleb']
LAST = ['chen', 'patel', 'kim', 'garcia', 'nguyen', 'brooks', 'rivera', 'okafor', 'schmidt',
        'haddad', 'murphy', 'santos', 'ito', 'kowalski', 'reyes', 'lindqvist', 'mensah', 'dubois',
        'cohen', 'abara', 'walsh', 'novak', 'singh', 'morales']
STAFF = [('m.rodriguez', 'Maria Rodriguez'), ('j.morrison', 'James Morrison'),
         ('a.okonkwo', 'Ada Okonkwo'), ('d.fischer', 'Daniel Fischer'), ('s.yamamoto', 'Sara Yamamoto'),
         ('p.oneill', 'Patrick O\'Neill'), ('r.bauer', 'Rachel Bauer'), ('t.adeyemi', 'Tunde Adeyemi'),
         ('k.larsen', 'Karin Larsen'), ('h.costa', 'Helena Costa')]


class Entity:
    def __init__(self, persona, ip, host=None, user=None, platform=None, browser=None, weight=1.0,
                 ptr=True):
        self.persona = persona
        self.ip = ip
        self.host = host
        self.user = user
        self.platform = platform
        self.browser = browser
        self.weight = weight
        self.ptr = ptr


def build_entities(rng: random.Random) -> list[Entity]:
    entities = []
    platforms = [('chromeos', 'chrome'), ('darwin', 'safari'), ('windows', 'chrome'),
                 ('windows', 'firefox'), ('darwin', 'chrome')]
    for i, (first, last) in enumerate(zip(FIRST, LAST)):
        platform, browser = platforms[i % len(platforms)]
        host = f'chromebook-{1100 + i * 7}' if platform == 'chromeos' else (
            f'mbp-{first}' if platform == 'darwin' else f'hp-st-{200 + i}')
        entities.append(Entity('s', f'10.40.{i // 8 + 1}.{20 + i * 3}', host, f'{first}.{last}',
                               platform, browser, weight=rng.uniform(0.6, 1.6)))
    for i, (user, _) in enumerate(STAFF):
        entities.append(Entity('t', f'10.30.{i // 4 + 1}.{40 + i * 5}', f'staff-lt-{300 + i}', user,
                               'windows' if i % 3 else 'darwin', 'chrome' if i % 2 else 'firefox',
                               weight=rng.uniform(0.8, 1.4)))
    for i in range(1, 19):
        entities.append(Entity('l', f'10.20.{i}.{30 + i}', f'lab-{i:02d}', weight=rng.uniform(0.5, 1.2)))
    for i, name in enumerate(['printer-lib-01', 'printer-office-02', 'cam-gym-01', 'cam-lobby-02',
                              'nas-backup-01', 'acct-ws-04']):
        entities.append(Entity('d', f'10.50.0.{10 + i * 4}', name, weight=0.4 if name != 'acct-ws-04' else 0.8))
    return entities


def _ip_for(domain: str) -> str:
    h = hashlib.sha256(domain.encode()).digest()
    return f'{h[0] % 200 + 20}.{h[1]}.{h[2]}.{h[3] % 250 + 2}'


def _doc(ts: datetime, entity: Entity, host: str, registrable: str, contexts: list[str],
         sources: list[str], kind: str, rcode: str = 'NOERROR', incidental: bool = False,
         candidates: list[str] | None = None, suppressed: list[str] | None = None,
         quad9: str | None = None) -> dict:
    stamp = ts.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    bite: dict = {
        'processed': (ts + timedelta(milliseconds=180)).isoformat(),
        'requested': [host], 'registrable_domain': registrable,
        'searches': [host, registrable, f'*.{registrable}', f'*.{registrable.split(".")[-1]}'],
        'contexts': contexts, 'type': kind,
    }
    bite.update(facets(contexts))
    if contexts:
        bite['claims'] = sorted({f'{c}:{s}' for c in contexts for s in sources})
        bite['sources'] = sorted(set(sources))
        bite['matched_on'] = [registrable if host != registrable else host]
        bite['match_source'] = ['question']
    if candidates:
        bite['contexts_candidate'] = candidates
    if suppressed:
        bite['contexts_suppressed'] = suppressed
    if incidental:
        bite['incidental'] = True
    if quad9:
        bite['resolvers'] = {'quad9': quad9}
    if kind == 'dns':
        bite['client'] = entity.ip
        bite['request'] = 'query'
        bite['response_code'] = rcode
        if rcode == 'NOERROR':
            bite['resolved_ips'] = [_ip_for(host)]
        if entity.ptr and entity.host:
            fqdn = f'{entity.host}.{DOMAIN}'
            bite.update({'client_hosts': [fqdn], 'client_hosts_short': [entity.host], 'ptr': fqdn,
                         'ptr_status': 'ok'})
        else:
            bite['ptr_status'] = 'nxdomain'
        packet = {'type': 'dns', 'status': 'OK' if rcode == 'NOERROR' else 'Error',
                  'network': {'direction': 'ingress', 'transport': 'udp', 'protocol': 'dns'},
                  'client': {'ip': entity.ip, 'port': 40000 + hash(host) % 20000},
                  'server': {'ip': '10.0.0.53', 'port': 53},
                  'dns': {'question': {'name': host, 'type': 'A', 'class': 'IN',
                                       'registered_domain': registrable},
                          'response_code': rcode},
                  '@timestamp': stamp}
    else:
        path = '/' + ''.join(random.choice(string.ascii_lowercase) for _ in range(6))
        bite.update({'client_user': entity.user, 'client_hostname': entity.host,
                     'client_hostname_short': entity.host, 'client_platform': entity.platform,
                     'client_browser': entity.browser, 'client_ips': [entity.ip],
                     'url': f'https://{host}{path}', 'request': 'https',
                     'event_time_utc': stamp, 'event_time_local': stamp})
        packet = {'data': {'@timestamp': stamp, 'event': {'data': {
            'entry': {'url': f'https://{host}{path}', 'title': host.split('.')[-2].title(),
                      'visit_count': random.randint(1, 9)},
            'client': {'Hostname': entity.host, 'user': entity.user, 'platform': entity.platform,
                       'browser': entity.browser, 'ip_addresses': [entity.ip]}}}}}
    return {'@timestamp': stamp, '@metadata': {'beat': 'turkeybite', 'type': '_doc',
                                               'version': '0.1.0'},
            'bite': bite, 'packet': packet}


def _hour_weight(hour: int, weekday: int) -> float:
    school = weekday < 5
    if 8 <= hour < 15:
        return 10.0 if school else 3.0
    if 15 <= hour < 18:
        return 5.0 if school else 4.0
    if 18 <= hour < 22:
        return 3.5
    if 7 <= hour < 8:
        return 3.0 if school else 1.0
    return 0.35


def background(rng: random.Random, entities: list[Entity], day: datetime, per_day: int,
               gap: tuple[datetime, datetime] | None) -> list[dict]:
    docs = []
    weights = [_hour_weight(h, day.weekday()) for h in range(24)]
    persona_domains = {persona: [(d, w_get(d, persona)) for d in D if w_get(d, persona)]
                       for persona in 'stld'}
    day_scale = 1.0 if day.weekday() < 5 else 0.55
    total = int(per_day * day_scale * rng.uniform(0.9, 1.1))
    ent_weights = [e.weight * {'s': 1.0, 't': 1.0, 'l': 0.8, 'd': 0.25}[e.persona] for e in entities]
    if day.weekday() >= 5:
        # At weekends the labs are shut and most staff are away; students
        # keep their own machines, and the devices stay on
        ent_weights = [w if e.persona in ('s', 'd') or rng.random() < (0.25 if e.persona == 't' else 0.1) else 0.0
                       for e, w in zip(entities, ent_weights)]
    for _ in range(total):
        hour = rng.choices(range(24), weights)[0]
        ts = day.replace(hour=hour, minute=rng.randrange(60), second=rng.randrange(60),
                         microsecond=rng.randrange(1000) * 1000)
        if gap and gap[0] <= ts < gap[1]:
            continue
        if ts > datetime.now(timezone.utc):
            continue
        entity = rng.choices(entities, ent_weights)[0]
        if entity.persona == 'd' and not (6 <= hour <= 20) and rng.random() < 0.5:
            continue
        pool = persona_domains[entity.persona]
        domain = rng.choices([p[0] for p in pool], [p[1] for p in pool])[0]
        registrable, hosts, contexts, _ = domain
        host = rng.choice(hosts)
        browser_capable = entity.persona in ('s', 't')
        kind = 'browser.history' if browser_capable and rng.random() < 0.32 and contexts and \
            'tracking' not in contexts and 'advertising' not in contexts else 'dns'
        incidental = kind == 'dns' and ('tracking' in contexts or 'advertising' in contexts) and rng.random() < 0.7
        sources = rng.sample(LISTS[:6], k=2) if contexts else []
        rcode = 'NOERROR' if rng.random() > 0.012 else 'NXDOMAIN'
        candidates = ['gambling'] if registrable == 'coolmathgames.com' and rng.random() < 0.3 else None
        suppressed = ['games'] if registrable == 'khanacademy.org' and rng.random() < 0.2 else None
        docs.append(_doc(ts, entity, host, registrable, list(contexts), sources, kind, rcode,
                         incidental, candidates, suppressed))
        # Occasional noise from the risky list, rarely and spread out
        if rng.random() < 0.0016:
            name = rng.choice(['giftcard-winner-now.com', 'fasttorrent-tracker.net',
                               'cdn-jsdelivr-libs.info', 'webminer-js.com', 'betstars-online.com'])
            hosts_r, ctx, src = RISKY[name]
            docs.append(_doc(ts + timedelta(seconds=2), entity, rng.choice(hosts_r), name, ctx,
                             [src, 'oisd'], 'dns', incidental=rng.random() < 0.5,
                             quad9='blocked' if 'malicious' in ctx else None))
    return docs


def w_get(domain, persona) -> float:
    return domain[3].get(persona, 0)


def _burst(rng, entity, start, minutes, count, registrable, kind='dns', rcode='NOERROR',
           incidental=False):
    hosts, contexts, source = RISKY[registrable]
    docs = []
    for _ in range(count):
        ts = start + timedelta(seconds=rng.uniform(0, minutes * 60))
        if ts > datetime.now(timezone.utc):
            continue
        docs.append(_doc(ts, entity, rng.choice(hosts), registrable, contexts, [source, 'oisd', 'hagezi'],
                         kind, rcode, incidental,
                         quad9='blocked' if set(contexts) & {'malware', 'malicious', 'phishing'} else None))
    return docs


def incidents(rng: random.Random, entities: list[Entity], now: datetime) -> list[dict]:
    by_host = {e.host: e for e in entities}
    by_user = {e.user: e for e in entities if e.user}
    docs = []
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    def at(days_ago: int, hour: int, minute: int = 0) -> datetime:
        return today - timedelta(days=days_ago) + timedelta(hours=hour, minutes=minute)

    # Phishing, then malware, on the library machine of one student
    noah = by_user['noah.kim']
    docs += _burst(rng, noah, at(3, 10, 12), 6, 4, 'secure-docs-share.top', 'browser.history')
    docs += _burst(rng, noah, at(1, 13, 40), 3, 3, 'update-flashplayer-secure.com', 'dns')
    docs += _burst(rng, noah, now - timedelta(minutes=95), 4, 5, 'paypa1-account-verify.com', 'browser.history')
    # A lab machine mining Monero for days
    lab12 = by_host['lab-12']
    for d in (3, 2, 1, 0):
        for h in range(8, 23, 2):
            docs += _burst(rng, lab12, at(d, h, 5), 30, 6, 'minexmr-pool.net')
    # Firefox with DNS over HTTPS
    ava = by_user['ava.chen']
    for d, h in ((2, 9), (0, 8)):
        for name in DOH[:2]:
            for _ in range(3):
                ts = at(d, h, rng.randrange(50))
                if ts < now:
                    docs.append(_doc(ts, ava, name, '.'.join(name.split('.')[-2:]), [], [], 'dns'))
    chloe = by_user['chloe.cohen']
    ts = now - timedelta(hours=3, minutes=10)
    for _ in range(4):
        docs.append(_doc(ts + timedelta(seconds=rng.randrange(300)), chloe, 'dns.nextdns.io',
                         'nextdns.io', [], [], 'dns'))
    # VPN and web proxies
    liam = by_user['liam.patel']
    docs += _burst(rng, liam, at(1, 12, 15), 20, 6, 'protonvpn.com')
    docs += _burst(rng, liam, now - timedelta(hours=2, minutes=30), 25, 8, 'croxyproxy.com', 'browser.history')
    mason = by_user['mason.haddad']
    docs += _burst(rng, mason, at(2, 14, 20), 15, 5, 'expressvpn.com')
    # Adult content, late at night and again today
    ethan = by_user['ethan.brooks']
    docs += _burst(rng, ethan, at(1, 22, 40), 25, 9, 'nsfw-tube-example.com', 'browser.history')
    docs += _burst(rng, ethan, now - timedelta(minutes=50), 12, 5, 'adult-clips-example.net', 'browser.history')
    # Gambling at lunch, by staff
    morrison = by_user['j.morrison']
    for d in (4, 2, 0):
        docs += _burst(rng, morrison, at(d, 12, 10), 35, 7, 'spinpalace-casino.net', 'browser.history')
    # Data leaving through DNS from an accounts workstation
    acct = by_host['acct-ws-04']
    start = now - timedelta(hours=2, minutes=20)
    alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
    for i in range(720):
        label = ''.join(rng.choice(alphabet) for _ in range(rng.randint(28, 52)))
        ts = start + timedelta(seconds=i * 0.8 + rng.random())
        docs.append(_doc(ts, acct, f'{label}.{rng.randrange(9999)}.t.exfil-telemetry.net',
                         'exfil-telemetry.net', [], [], 'dns'))
    # A lab machine generating domain names, and failing to resolve them
    lab5 = by_host['lab-05']
    for when in (now - timedelta(days=1, hours=5), now - timedelta(hours=4, minutes=30)):
        for i in range(420):
            label = ''.join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(rng.randint(10, 16)))
            tld = rng.choice(['com', 'net', 'info', 'biz', 'xyz'])
            ts = when + timedelta(seconds=rng.uniform(0, 600))
            failed = rng.random() < 0.86
            docs.append(_doc(ts, lab5, f'{label}.{tld}', f'{label}.{tld}', [], [], 'dns',
                             'NXDOMAIN' if failed else 'NOERROR'))
    # A burst of activity from one Chromebook
    burst_entity = by_user['zoe.walsh']
    burst_start = now - timedelta(hours=6)
    for i in range(1900):
        d = rng.choice([d for d in D if w_get(d, 's') > 5])
        ts = burst_start + timedelta(seconds=rng.uniform(0, 3300))
        if ts < now:
            docs.append(_doc(ts, burst_entity, rng.choice(d[1]), d[0], list(d[2]), ['StevenBlack', 'oisd'],
                             'dns'))
    return docs


# -- OpenSearch -----------------------------------------------------------------

TEMPLATE = {
    'index_patterns': [f'{INDEX_PREFIX}-*'],
    'template': {
        'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
        'mappings': {'properties': {
            '@timestamp': {'type': 'date'},
            'bite': {'properties': {
                **{name: {'type': 'keyword'} for name in (
                    'event_time_local', 'url', 'client_hosts', 'client_hosts_short', 'client_hostname',
                    'client_hostname_short', 'client_user', 'client_platform', 'client_browser', 'ptr',
                    'ptr_status', 'sources', 'matched_on', 'cname_chain', 'cname_matched_on',
                    'cname_contexts', 'match_source', 'response_code', 'contexts_index',
                    'index_error', 'requested', 'registrable_domain', 'searches', 'contexts',
                    'contexts_candidate', 'contexts_suppressed', 'claims', 'purpose', 'service',
                    'risk', 'risk_severity', 'unmapped_contexts', 'request', 'type')},
                'processed': {'type': 'date'}, 'event_time_utc': {'type': 'date'},
                'client': {'type': 'ip'}, 'client_ips': {'type': 'ip'},
                'resolved_ips': {'type': 'ip'}, 'context_match': {'type': 'boolean'},
                'psl_fallback': {'type': 'boolean'}, 'incidental': {'type': 'boolean'},
                'index_built_at': {'type': 'date', 'format': 'epoch_second'},
                'resolvers': {'properties': {'quad9': {'type': 'keyword'},
                                             'cloudflare-security': {'type': 'keyword'},
                                             'cloudflare-family': {'type': 'keyword'}}},
            }},
            'packet': {'type': 'object', 'enabled': False},
        }},
    },
}


async def write_events(search: SearchClient, docs: list[dict]) -> int:
    await search.request('PUT', '/_index_template/turkeybite', TEMPLATE)
    written = 0
    for i in range(0, len(docs), 4000):
        chunk = docs[i:i + 4000]
        lines = []
        for doc in chunk:
            day = doc['@timestamp'][:10]
            lines.append(json.dumps({'index': {'_index': f'{INDEX_PREFIX}-{day}'}}))
            lines.append(json.dumps(doc))
        result = await search.request('POST', '/_bulk', content=('\n'.join(lines) + '\n').encode())
        if result.get('errors'):
            first = next(item for item in result['items'] if item['index'].get('error'))
            raise RuntimeError(f'bulk indexing failed: {first["index"]["error"]}')
        written += len(chunk)
    await search.request('POST', f'/{INDEX_PREFIX}-*/_refresh')
    return written


# -- the webhook receiver the demo webhooks point at --------------------------------------

class _Sink(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get('content-length') or 0)
        self.rfile.read(length)
        code = {'/slack': 200, '/siem': 202, '/teams': 200, '/pager': 503}.get(self.path, 404)
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'ok' if code < 300 else b'no such hook')

    def log_message(self, *args):
        pass


def start_sink(url: str) -> ThreadingHTTPServer | None:
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    try:
        server = ThreadingHTTPServer((parts.hostname, parts.port), _Sink)
    except OSError:
        return None  # already running, perhaps as python -m tbconsole.demo_sink
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# -- the console's own records -----------------------------------------------------------

async def reset_database() -> None:
    async with db.sessionmaker()() as session:
        await session.execute(text(
            'TRUNCATE audit_events, daily_stats, leases, webhook_deliveries, finding_activity, '
            'findings, rule_runs, rules, webhooks, api_keys, user_sessions, saved_searches, '
            'dashboards, settings, users RESTART IDENTITY CASCADE'))
        await session.commit()


async def seed_people(session) -> dict:
    people = {}

    def add(username, display, role, source, password=None, email=None, mfa=False, **extra):
        user = User(username=username, display_name=display, role=role, source=source,
                    email=email or (f'{username}@harborpoint.edu' if source != 'service' else None),
                    preferences={}, **extra)
        if password:
            user.password_hash = passwords.hash_password(password)
        if mfa:
            user.totp_secret_enc = crypto.encrypt(totp.new_secret())
            user.totp_enabled = True
        if source == 'ldap':
            user.ldap_dn = f'uid={username},ou=people,dc=harborpoint,dc=edu'
        session.add(user)
        people[username] = user
        return user
    now = datetime.now(timezone.utc)
    add('admin', 'Jordan Harris', 'admin', 'local', DEMO_PASSWORD, last_login_at=now - timedelta(minutes=8))
    add('breakglass', 'Break-glass admin', 'admin', 'local', DEMO_PASSWORD + '-bg', mfa=True,
        last_login_at=now - timedelta(days=41))
    add('sofia.alvarez', 'Sofia Alvarez', 'analyst', 'ldap', last_login_at=now - timedelta(hours=2))
    add('marcus.lee', 'Marcus Lee', 'analyst', 'ldap', last_login_at=now - timedelta(hours=5))
    add('priya.raman', 'Priya Raman', 'analyst', 'ldap', last_login_at=now - timedelta(days=1, hours=3))
    add('dean.gray', 'Dean Gray', 'viewer', 'ldap', last_login_at=now - timedelta(days=2))
    add('helpdesk', 'Help desk', 'viewer', 'local', DEMO_PASSWORD + '-hd', disabled=True,
        last_login_at=now - timedelta(days=90))
    add('svc-siem', 'SIEM integration', 'analyst', 'service')
    add('svc-ticketing', 'Ticketing integration', 'analyst', 'service')
    await session.flush()
    return people


async def seed(days: int = 21, per_day: int = 12000, sink: str = 'http://127.0.0.1:8799') -> int:
    rng = random.Random(20261005)
    random.seed(20261005)
    now = datetime.now(timezone.utc)
    search = SearchClient()
    print(f'Writing {days} days of made-up events to OpenSearch...')
    try:
        await search.request('DELETE', f'/{INDEX_PREFIX}-*', params={'ignore_unavailable': 'true'})
    except Exception:
        pass
    entities = build_entities(rng)
    docs = []
    # An hour with no events at all, as if the workers had stopped
    gap_day = now - timedelta(days=2)
    gap = (gap_day.replace(hour=3, minute=10, second=0, microsecond=0),
           gap_day.replace(hour=4, minute=5, second=0, microsecond=0))
    for d in range(days, -1, -1):
        day = (now - timedelta(days=d)).replace(hour=0, minute=0, second=0, microsecond=0)
        docs += background(rng, entities, day, per_day, gap)
    docs += incidents(rng, entities, now)
    written = await write_events(search, docs)
    print(f'  {written:,} events written.')

    print('Resetting the console database...')
    await reset_database()
    async with db.sessionmaker()() as session:
        people = await seed_people(session)
        await settings_store.put(session, 'general', {**settings_store.GENERAL_DEFAULTS,
                                                      'org_name': ORG,
                                                      'login_banner': 'Authorised use only. '
                                                      'Activity in this console is audited.'}, None)
        await settings_store.put(session, 'ldap', {
            'enabled': True, 'urls': ['ldaps://dc1.harborpoint.edu', 'ldaps://dc2.harborpoint.edu'],
            'start_tls': False, 'verify_certs': True, 'ca_cert_pem': '',
            'bind_dn': 'cn=svc-turkeybite,ou=service,dc=harborpoint,dc=edu',
            'bind_password_enc': crypto.encrypt('not-a-real-password'),
            'user_base_dn': 'ou=people,dc=harborpoint,dc=edu',
            'user_filter': '(&(objectClass=inetOrgPerson)(uid={username}))',
            'attr_username': 'uid', 'attr_display_name': 'displayName', 'attr_email': 'mail',
            'attr_groups': 'memberOf', 'group_base_dn': '', 'group_filter': '',
            'role_mappings': [
                {'group': 'cn=it-security,ou=groups,dc=harborpoint,dc=edu', 'role': 'admin'},
                {'group': 'cn=safeguarding,ou=groups,dc=harborpoint,dc=edu', 'role': 'analyst'},
                {'group': 'cn=leadership,ou=groups,dc=harborpoint,dc=edu', 'role': 'viewer'}],
            'default_role': None, 'timeout_sec': 5}, None)
        await session.commit()
        await engine.sync_builtin_rules(session)
        await sync_builtin_dashboards(session)

        # Webhooks: three that answer, one that does not
        hooks = {}
        for name, path, fmt, events, all_findings, minimum, redact in (
                ('Safeguarding team (Slack)', '/slack', 'slack', ['finding.created', 'finding.reminder'], True, 'high', True),
                ('SIEM (signed JSON)', '/siem', 'json', ['finding.created', 'finding.reminder', 'finding.status_changed', 'rule.failing'], True, 'low', False),
                ('IT on-call (Teams)', '/teams', 'teams', ['finding.created', 'rule.failing'], True, 'critical', False),
                ('Legacy pager bridge', '/pager', 'json', ['finding.created'], False, 'critical', False)):
            hook = Webhook(name=name, url=sink.rstrip('/') + path, format=fmt,
                           secret_enc=crypto.encrypt(signing.new_secret()), events=events,
                           all_findings=all_findings, min_severity=minimum, redact_entities=redact,
                           enabled=True, created_by_id=people['admin'].id)
            session.add(hook)
            hooks[name] = hook
        await session.flush()

        # Rules: switch some on, change one, and add the school's own
        rules = {r.builtin_key: r for r in (await session.execute(select(Rule))).scalars()}
        rules['after-hours'].enabled = True
        rules['after-hours'].schedule = {'days': [0, 1, 2, 3, 4, 6], 'start': '22:00', 'end': '06:00',
                                         'timezone': 'UTC'}
        rules['after-hours'].params = {'threshold': 8}
        rules['after-hours'].modified = True
        rules['ai-tools'].enabled = True
        rules['adult-content'].params = {'threshold': 1}
        rules['adult-content'].modified = True
        rules['adult-content'].webhook_ids = [str(hooks['Legacy pager bridge'].id)]
        rules['threat-domain'].webhook_ids = [str(hooks['Legacy pager bridge'].id)]
        rules['anonymiser'].exceptions = [{'id': 'demo-1', 'query': 'host:staff-lt-302',
                                           'note': 'IT staff test VPN clients', 'created_by': 'admin',
                                           'created_at': (now - timedelta(days=9)).isoformat()}]
        custom = [
            Rule(name='Social media on lab machines in class time', category='custom',
                 description='Lab machines are for lessons. Social media on one during the school '
                             'day usually means a student found a way around the browser policy.',
                 type='threshold', query='host:lab-* AND purpose:social.*',
                 params={'threshold': 15}, group_by=['entity'], severity='low', enabled=True,
                 interval_seconds=900, window_seconds=1800, dedup_seconds=6 * 3600,
                 schedule={'days': [0, 1, 2, 3, 4], 'start': '08:00', 'end': '15:00',
                           'timezone': 'UTC'},
                 tags=['custom', 'labs'], title_template='Social media on {entity} during class',
                 created_by_id=people['sofia.alvarez'].id, next_run_at=now),
            Rule(name='Many distinct sites from one device', category='custom',
                 description='A device touching an unusual number of different domains in an hour '
                             'is often crawling, scanning, or running something it should not.',
                 type='unique_count', query='type:dns AND NOT incidental:true',
                 params={'field': 'bite.registrable_domain', 'threshold': 250},
                 group_by=['entity'], severity='medium', enabled=True, interval_seconds=900,
                 window_seconds=3600, dedup_seconds=6 * 3600, tags=['custom'],
                 title_template='{entity} reached {count} events across many domains',
                 created_by_id=people['marcus.lee'].id, next_run_at=now),
        ]
        session.add_all(custom)
        await session.commit()

        # API keys
        key_rows = [
            ('SIEM pull', people['svc-siem'], ['events:read', 'findings:read'], now - timedelta(days=60), now + timedelta(days=120), now - timedelta(minutes=3), None),
            ('Ticket sync', people['svc-ticketing'], ['findings:read', 'findings:write'], now - timedelta(days=30), now + timedelta(days=60), now - timedelta(minutes=41), None),
            ('Jupyter notebook', people['admin'], ['events:read', 'events:export'], now - timedelta(days=12), now + timedelta(days=78), now - timedelta(days=1, hours=2), None),
            ('Old SIEM key', people['svc-siem'], ['events:read'], now - timedelta(days=200), now + timedelta(days=10), now - timedelta(days=61), now - timedelta(days=60)),
            ('Dashboard kiosk', people['dean.gray'], ['events:read', 'findings:read', 'dashboards:read'], now - timedelta(days=100), now - timedelta(days=10), now - timedelta(days=11), None),
        ]
        for name, owner, scopes, created, expires, used, revoked in key_rows:
            _, prefix, digest = apikeys.generate()
            session.add(ApiKey(user_id=owner.id, name=name, prefix=prefix, key_hash=digest,
                               scopes=scopes, created_at=created, expires_at=expires,
                               last_used_at=used, last_used_ip='10.60.0.12', revoked_at=revoked,
                               created_by_id=people['admin'].id))
        # Saved searches and a dashboard of the analysts' own
        for owner, name, query, rng_from, shared, pinned in (
                ('sofia.alvarez', 'Threat lookups', 'risk:threat', 'now-7d', True, True),
                ('sofia.alvarez', 'Encrypted DNS resolvers', 'domain:(dns.google OR *.cloudflare-dns.com OR dns.nextdns.io)', 'now-7d', True, False),
                ('marcus.lee', 'Failed lookups from labs', 'rcode:NXDOMAIN AND host:lab-*', 'now-24h', False, True),
                ('admin', 'Anonymisers, not incidental', 'risk:policy.anonymiser AND NOT incidental:true', 'now-30d', True, False)):
            session.add(SavedSearch(owner_id=people[owner].id, name=name, query=query,
                                    time_range={'from': rng_from, 'to': 'now'}, shared=shared,
                                    pinned=pinned))
        session.add(Dashboard(owner_id=people['sofia.alvarez'].id, name='Labs at a glance', shared=True,
                              icon='monitor', description='The 18 lab machines, what they reach and when.',
                              time_range={'from': 'now-24h', 'to': 'now'}, widgets=[
                                  {'id': 'labs-time', 'title': 'Lab traffic by purpose', 'type': 'pivot', 'span': 8, 'height': 'md', 'viz': 'stacked',
                                   'pivot': {'query': 'host:lab-* AND has:purpose', 'metric': 'count', 'over_time': True, 'split': 'bite.purpose', 'split_size': 5}},
                                  {'id': 'labs-top', 'title': 'Busiest labs', 'type': 'pivot', 'span': 4, 'height': 'md', 'viz': 'hbar',
                                   'pivot': {'query': 'host:lab-*', 'metric': 'count', 'rows': 'entity', 'rows_size': 8}},
                                  {'id': 'labs-risk', 'title': 'Risky domains from labs', 'type': 'pivot', 'span': 12, 'height': 'md', 'viz': 'table',
                                   'pivot': {'query': 'host:lab-* AND has:risk AND NOT risk:(privacy.tracking OR privacy.advertising)', 'metric': 'count', 'rows': 'bite.registrable_domain', 'rows_size': 10, 'split': 'bite.risk', 'split_size': 3}}]))
        await session.commit()

    print('Running the rule engine over the last three days...')
    start = now - timedelta(days=3)
    step = timedelta(minutes=15)
    async with db.sessionmaker()() as session:
        rules = [r for r in (await session.execute(select(Rule).where(Rule.enabled.is_(True)))).scalars()]
        moment = start
        last_run: dict = {}
        while moment <= now:
            for rule in rules:
                previous = last_run.get(rule.id)
                if previous is not None and (moment - previous).total_seconds() < max(rule.interval_seconds, 900):
                    continue
                await engine.run_rule(session, search, rule, now=moment)
                last_run[rule.id] = moment
            await session.commit()
            moment += step
        for rule in rules:
            rule.next_run_at = now + timedelta(seconds=rule.interval_seconds)
            await engine.prune_runs(session, rule.id)
        await session.commit()

    print('Sending the webhooks the findings queued...')
    server = start_sink(sink)
    import httpx
    async with httpx.AsyncClient(timeout=5) as http:
        for _ in range(200):
            if not await dispatcher.run_once(http):
                break
    async with db.sessionmaker()() as session:
        # Failed deliveries would be retried for hours; let a few be dead already
        await session.execute(update(WebhookDelivery).where(WebhookDelivery.status == 'failed')
                              .values(next_attempt_at=now + timedelta(minutes=20)))
        await session.commit()
    if server is not None:
        server.shutdown()

    print('Backdating, and triaging some findings as analysts would have...')
    async with db.sessionmaker()() as session:
        await session.execute(text('UPDATE findings SET created_at = first_seen, updated_at = last_seen'))
        await session.execute(text(
            "UPDATE finding_activity a SET created_at = f.first_seen FROM findings f "
            "WHERE a.finding_id = f.id AND a.kind = 'created'"))
        await session.execute(text(
            "UPDATE finding_activity a SET created_at = f.last_seen FROM findings f "
            "WHERE a.finding_id = f.id AND a.kind = 'occurrence'"))
        await session.execute(text(
            "UPDATE webhook_deliveries d SET created_at = f.first_seen + interval '20 seconds', "
            "delivered_at = CASE WHEN d.delivered_at IS NULL THEN NULL ELSE f.first_seen + interval '21 seconds' END "
            "FROM findings f WHERE d.finding_id = f.id"))
        findings = list((await session.execute(select(Finding).order_by(Finding.first_seen))).scalars())
        analysts = [people['sofia.alvarez'], people['marcus.lee'], people['priya.raman']]
        for i, f in enumerate(findings):
            age = (now - f.first_seen).total_seconds() / 3600
            who = analysts[i % len(analysts)]
            name = who.display_name

            def act(kind, body='', data=None, hours_after=1.0):
                session.add(FindingActivity(finding_id=f.id, actor_id=who.id, actor_name=name,
                                            kind=kind, body=body, data=data or {},
                                            created_at=min(now, f.first_seen + timedelta(hours=hours_after))))
            if f.rule_name.startswith('Unusual burst') and age > 20:
                f.status, f.resolved_at, f.resolved_by_id = 'false_positive', f.first_seen + timedelta(hours=3), who.id
                act('status', 'Exam revision site preloading assets. Expected.', {'from': 'new', 'to': 'false_positive'}, 3)
            elif age > 36 and i % 3 != 0:
                f.status, f.resolved_at, f.resolved_by_id = 'resolved', f.first_seen + timedelta(hours=age / 3), who.id
                f.assignee_id = who.id
                act('assign', data={'to': name}, hours_after=0.5)
                act('comment', rng.choice([
                    'Spoke with the student and their form tutor. Logged with safeguarding.',
                    'Machine reimaged by IT. Credentials reset.',
                    'Confirmed with the user; blocked at the resolver too.',
                    'Covered by the acceptable-use conversation this morning.']), hours_after=age / 4)
                act('status', '', {'from': 'acknowledged', 'to': 'resolved'}, age / 3)
            elif age > 6 and i % 2 == 0:
                f.status = 'in_progress' if i % 4 == 0 else 'acknowledged'
                f.assignee_id = who.id
                act('assign', data={'to': name}, hours_after=0.4)
                act('status', '', {'from': 'new', 'to': f.status}, 0.5)
                if f.status == 'in_progress':
                    act('comment', 'Asked IT to pull the machine for a scan before end of day.', hours_after=0.8)
        await session.commit()

        # A history of who did what
        audit_rows = []
        for hours, actor, action, target_type, target, outcome, details in (
                (0.15, 'admin', 'auth.login', 'user', 'admin', 'success', {'method': 'local'}),
                (0.5, 'sofia.alvarez', 'entity.view', 'bite.client_user', 'noah.kim', 'success', {}),
                (1.1, 'sofia.alvarez', 'finding.update', 'finding', 'F-1007', 'success', {'changes': ['status new -> acknowledged']}),
                (1.9, 'marcus.lee', 'events.export', None, None, 'success', {'query': 'risk:threat', 'format': 'csv', 'limit': 1000}),
                (2.0, 'sofia.alvarez', 'auth.login', 'user', 'sofia.alvarez', 'success', {'method': 'ldap'}),
                (2.4, 'unknown', 'auth.login', None, None, 'failure', {'reason': 'no such local account and LDAP refused'}),
                (2.41, 'unknown', 'auth.login', None, None, 'failure', {'reason': 'directory refused the credentials'}),
                (3.0, 'admin', 'rule.update', 'rule', 'Adult content', 'success', {}),
                (5.0, 'marcus.lee', 'auth.login', 'user', 'marcus.lee', 'success', {'method': 'ldap'}),
                (5.2, 'marcus.lee', 'domain.view', 'domain', 'exfil-telemetry.net', 'success', {}),
                (8.0, 'admin', 'webhook.test', 'webhook', 'SIEM (signed JSON)', 'success', {}),
                (26.0, 'priya.raman', 'entity.view', 'bite.client_hostname_short', 'lab-12', 'success', {}),
                (27.0, 'admin', 'apikey.create', 'apikey', 'Jupyter notebook', 'success', {'scopes': ['events:read', 'events:export']}),
                (49.0, 'admin', 'settings.ldap', None, None, 'success', {'enabled': True}),
                (52.0, 'admin', 'user.update', 'user', 'helpdesk', 'success', {'disabled': True}),
                (71.0, 'breakglass', 'auth.login', 'user', 'breakglass', 'success', {'method': 'local+totp'})):
            audit_rows.append(AuditEvent(at=now - timedelta(hours=hours), actor_type='session' if actor != 'unknown' else 'anonymous',
                                         actor_id=people[actor].id if actor in people else None,
                                         actor_name=actor if actor != 'unknown' else 'jsmith',
                                         action=action, outcome=outcome, target_type=target_type,
                                         target_label=target, target_id=target, ip='10.60.0.' + str(10 + int(hours) % 40),
                                         details=details))
        session.add_all(audit_rows)
        await session.commit()

    print('Counting daily statistics, and making up a longer history for the trends...')
    await rollups.run(search, backfill=True)
    async with db.sessionmaker()() as session:
        first_real = (await session.execute(select(DailyStat.day).order_by(DailyStat.day).limit(1))).scalar()
        rows = []
        for back in range(1, 200):
            day = first_real - timedelta(days=back)
            weekday = day.weekday() < 5
            season = 0.75 + 0.25 * abs(((day.timetuple().tm_yday / 365.0) * 2) % 2 - 1)
            holiday = 0.35 if day.month in (7, 8) else 1.0
            base = per_day * (1.0 if weekday else 0.55) * season * holiday * rng.uniform(0.92, 1.08)
            total_events = int(base)
            # About what the seeded weeks hold, so the line does not jump
            high = int(total_events * rng.uniform(0.0002, 0.0004) * (1.8 if day.month == 6 else 1))
            medium = int(total_events * rng.uniform(0.0005, 0.0010))
            low = int(total_events * rng.uniform(0.11, 0.14))
            rows += [
                {'day': day, 'dimension': 'total', 'key': '', 'count': total_events},
                {'day': day, 'dimension': 'risky', 'key': '', 'count': high + medium + low},
                {'day': day, 'dimension': 'severity', 'key': 'high', 'count': high},
                {'day': day, 'dimension': 'severity', 'key': 'medium', 'count': medium},
                {'day': day, 'dimension': 'severity', 'key': 'low', 'count': low},
                {'day': day, 'dimension': 'type', 'key': 'dns', 'count': int(total_events * 0.74)},
                {'day': day, 'dimension': 'type', 'key': 'browser.history', 'count': int(total_events * 0.26)},
                {'day': day, 'dimension': 'unique', 'key': 'clients', 'count': int(rng.uniform(55, 58) * (0.6 if day.month in (7, 8) else 1)) if weekday else int(rng.uniform(31, 36))},
                {'day': day, 'dimension': 'unique', 'key': 'users', 'count': int(rng.uniform(32, 34) * (0.6 if day.month in (7, 8) else 1)) if weekday else int(rng.uniform(25, 29))},
                {'day': day, 'dimension': 'response_code', 'key': 'NXDOMAIN', 'count': int(total_events * 0.012)},
                {'day': day, 'dimension': 'risk', 'key': 'threat.malicious', 'count': int(high * 0.5)},
                {'day': day, 'dimension': 'risk', 'key': 'threat.phishing', 'count': int(high * 0.3)},
                {'day': day, 'dimension': 'risk', 'key': 'policy.anonymiser', 'count': int(medium * 0.4)},
                {'day': day, 'dimension': 'risk', 'key': 'threat.cryptomining', 'count': int(medium * 0.2)},
                {'day': day, 'dimension': 'risk', 'key': 'threat.scam', 'count': int(medium * 0.25)},
                {'day': day, 'dimension': 'risk', 'key': 'policy.piracy', 'count': int(low * 0.004)},
                {'day': day, 'dimension': 'risk', 'key': 'policy.url-shortener', 'count': int(total_events * rng.uniform(0.002, 0.003))},
            ]
            for purpose, share in (('social.networks', 0.16), ('media.video', 0.12), ('information.education', 0.15),
                                   ('information.search', 0.14), ('productivity.office', 0.09),
                                   ('gaming.platforms', 0.05), ('technology.ai', 0.012 + 0.02 * (back < 120)),
                                   ('communication.messaging', 0.04)):
                rows.append({'day': day, 'dimension': 'purpose', 'key': purpose,
                             'count': int(total_events * share * rng.uniform(0.9, 1.1))})
        from sqlalchemy.dialects.postgresql import insert
        for i in range(0, len(rows), 2000):
            await session.execute(insert(DailyStat).values(rows[i:i + 2000]))
        await session.commit()
    await search.close()
    await db.dispose()
    print()
    print(f'Done. Sign in as admin with the password {DEMO_PASSWORD}')
    return 0



async def feed(per_day: int = 12000, every: float = 5.0) -> int:
    """Keeps writing made-up events as they would arrive, until interrupted.

    For a demo that should look alive: the pipeline indicator, the live tail
    and the rules all have something new to see.
    """
    import asyncio
    rng = random.Random()
    entities = build_entities(random.Random(20261005))
    search = SearchClient()
    print(f'Writing about {per_day:,} made-up events a day to OpenSearch. Ctrl-C to stop.')
    try:
        while True:
            now = datetime.now(timezone.utc)
            weights = [_hour_weight(h, now.weekday()) for h in range(24)]
            share = weights[now.hour] / sum(weights)
            expected = per_day * share * every / 3600 * (1.0 if now.weekday() < 5 else 0.55)
            count = int(expected) + (1 if rng.random() < expected - int(expected) else 0)
            docs = []
            day = now.replace(hour=0, minute=0, second=0, microsecond=0)
            for doc in background(rng, entities, day, max(count * 40, 1), None):
                if len(docs) >= count:
                    break
                stamp = now - timedelta(seconds=rng.uniform(0, every))
                text_stamp = stamp.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
                doc['@timestamp'] = text_stamp
                doc['bite']['processed'] = (stamp + timedelta(milliseconds=150)).isoformat()
                for key in ('event_time_utc', 'event_time_local'):
                    if key in doc['bite']:
                        doc['bite'][key] = text_stamp
                docs.append(doc)
            if docs:
                lines = []
                for doc in docs:
                    lines.append(json.dumps({'index': {'_index': f'{INDEX_PREFIX}-{doc["@timestamp"][:10]}'}}))
                    lines.append(json.dumps(doc))
                await search.request('POST', '/_bulk', content=('\n'.join(lines) + '\n').encode(),
                                     params={'refresh': 'false'})
            await asyncio.sleep(every)
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 0
    finally:
        await search.close()
