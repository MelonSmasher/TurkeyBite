import yaml
import urllib.request
import re
import os
from redis import Redis
import json
import time

host_files = [

    # Porn

    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/alternates/porn-only/hosts',
        'categories': ['porn', 'list-StevenBlack-porn-only'],
        'file': 'lists/porn/StevenBlack-porn-only',
        'name': 'StevenBlack-porn-only'
    },
    {
        'url': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt',
        'categories': ['porn', 'list-hagezi-nsfw'],
        'file': 'lists/porn/hagezi-nsfw',
        'name': 'hagezi-nsfw'
    },
    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/porn-nl.txt',
        'categories': ['porn', 'list-blocklistproject-porn-nl'],
        'file': 'lists/porn/blocklistproject-porn-nl',
        'name': 'blocklistproject-porn-nl'
    },
    {
        'url': 'https://raw.githubusercontent.com/tiuxo/hosts/master/porn',
        'categories': ['porn', 'list-tiuxo-porn'],
        'file': 'lists/porn/tiuxo-porn',
        'name': 'tiuxo-porn'
    },
    {
        'url': 'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/adult-themed/optimized.black.domain.list',
        'categories': ['porn', 'list-cbuijs-adult-themed'],
        'file': 'lists/porn/cbuijs-adult-themed',
        'name': 'cbuijs-adult-themed'
    },
    {
        'url': 'https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Adult',
        'categories': ['porn', 'list-shadowwhisperer-adult'],
        'file': 'lists/porn/shadowwhisperer-adult',
        'name': 'shadowwhisperer-adult'
    },
    {
        'url': 'https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild_nsfw.txt',
        'categories': ['porn', 'list-sjhgvr-domainswild-nsfw'],
        'file': 'lists/porn/sjhgvr-domainswild-nsfw',
        'name': 'sjhgvr-domainswild-nsfw'
    },

    # Piracy
    {
        'url': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/anti.piracy.txt',
        'categories': ['piracy', 'list-hagezi-anti-piracy'],
        'file': 'lists/piracy/hagezi-anti-piracy',
        'name': 'hagezi-anti-piracy'
    },
    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/piracy-nl.txt',
        'categories': ['piracy', 'list-blocklistproject-piracy-nl'],
        'file': 'lists/piracy/blocklistproject-piracy-nl',
        'name': 'blocklistproject-piracy-nl'
    },
    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt',
        'categories': ['piracy', 'torrent', 'list-blocklistproject-torrent-nl'],
        'file': 'lists/piracy/blocklistproject-torrent-nl',
        'name': 'blocklistproject-torrent-nl'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/piracy-blocklists/master/torrent-websites',
        'categories': ['piracy', 'torrent', 'list-nextdns-torrent-websites'],
        'file': 'lists/piracy/nextdns-torrent-websites',
        'name': 'nextdns-torrent-websites'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/piracy-blocklists/master/torrent-trackers',
        'categories': ['piracy', 'torrent', 'list-nextdns-torrent-trackers'],
        'file': 'lists/piracy/nextdns-torrent-trackers',
        'name': 'nextdns-torrent-trackers'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/piracy-blocklists/master/torrent-clients',
        'categories': ['piracy', 'torrent', 'list-nextdns-torrent-clients'],
        'file': 'lists/piracy/nextdns-torrent-clients',
        'name': 'nextdns-torrent-clients'
    },

    # Social

    {
        'url': 'https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/social_networks/domains',
        'categories': ['social', 'list-olbat-social-networks'],
        'file': 'lists/social/olbat-social-networks',
        'name': 'olbat-social-networks'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/alternates/social-only/hosts',
        'categories': ['social', 'list-StevenBlack-social-only'],
        'file': 'lists/social/StevenBlack-social-only',
        'name': 'StevenBlack-social-only'
    },
    {
        'url': 'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/refs/heads/master/adguard-facebook.txt',
        'categories': ['social', 'facebook', 'list-gieljnssns-facebook'],
        'file': 'lists/social/gieljnssns-facebook',
        'name': 'gieljnssns-facebook'
    },
    {
        'url': 'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/refs/heads/master/adguard-instagram.txt',
        'categories': ['social', 'instagram', 'list-gieljnssns-instagram'],
        'file': 'lists/social/gieljnssns-instagram',
        'name': 'gieljnssns-instagram'
    },
    {
        'url': 'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/refs/heads/master/adguard-reddit.txt',
        'categories': ['social', 'reddit', 'list-gieljnssns-reddit'],
        'file': 'lists/social/gieljnssns-reddit',
        'name': 'gieljnssns-reddit'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-reddit.txt',
        'categories': ['social', 'reddit', 'list-nickoppen-reddit'],
        'file': 'lists/social/nickoppen-reddit',
        'name': 'nickoppen-reddit'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/services/main/services/twitter',
        'categories': ['social', 'twitter', 'list-nextdns-twitter'],
        'file': 'lists/social/nextdns-twitter',
        'name': 'nextdns-twitter'
    },
    {
        'url': 'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/refs/heads/master/adguard-snapchat.txt',
        'categories': ['social', 'snapchat', 'list-gieljnssns-snapchat'],
        'file': 'lists/social/gieljnssns-snapchat',
        'name': 'gieljnssns-snapchat'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-myspace.txt',
        'categories': ['social', 'myspace', 'list-nickoppen-myspace'],
        'file': 'lists/social/nickoppen-myspace',
        'name': 'nickoppen-myspace'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-signal.txt',
        'categories': ['social', 'signal', 'list-nickoppen-signal'],
        'file': 'lists/social/nickoppen-signal',
        'name': 'nickoppen-signal'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-telegram.txt',
        'categories': ['social', 'telegram', 'list-nickoppen-telegram'],
        'file': 'lists/social/nickoppen-telegram',
        'name': 'nickoppen-telegram'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-tiktok.txt',
        'categories': ['social', 'tiktok', 'list-nickoppen-tiktok'],
        'file': 'lists/social/nickoppen-tiktok',
        'name': 'nickoppen-tiktok'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-tinder.txt',
        'categories': ['social', 'tinder', 'list-nickoppen-tinder'],
        'file': 'lists/social/nickoppen-tinder',
        'name': 'nickoppen-tinder'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/services/main/services/whatsapp',
        'categories': ['social', 'whatsapp', 'list-nextdns-whatsapp'],
        'file': 'lists/social/nextdns-whatsapp',
        'name': 'nextdns-whatsapp'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/services/main/services/zoom',
        'categories': ['social', 'zoom', 'list-nextdns-zoom'],
        'file': 'lists/social/nextdns-zoom',
        'name': 'nextdns-zoom'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-whispersystems.txt',
        'categories': ['social', 'whispersystems', 'list-nickoppen-whispersystems'],
        'file': 'lists/social/nickoppen-whispersystems',
        'name': 'nickoppen-whispersystems'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-discord.txt',
        'categories': ['social', 'discord', 'list-nickoppen-discord'],
        'file': 'lists/social/nickoppen-discord',
        'name': 'nickoppen-discord'
    },



    # Drugs

    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt',
        'categories': ['drugs', 'list-blocklistproject-drugs-nl'],
        'file': 'lists/drugs/blocklistproject-drugs-nl',
        'name': 'blocklistproject-drugs-nl'
    },

    # Gambling

    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/alternates/gambling-only/hosts',
        'categories': ['gambling', 'list-StevenBlack-gambling-only'],
        'file': 'lists/gambling/StevenBlack-gambling-only',
        'name': 'StevenBlack-gambling-only'
    },
    {
        'url': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.txt',
        'categories': ['gambling', 'list-hagezi-gambling'],
        'file': 'lists/gambling/hagezi-gambling',
        'name': 'hagezi-gambling'
    },
    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt',
        'categories': ['gambling', 'list-blocklistproject-gambling-nl'],
        'file': 'lists/gambling/blocklistproject-gambling-nl',
        'name': 'blocklistproject-gambling-nl'
    },

    # Games

    {
        'url': 'https://raw.githubusercontent.com/IREK-szef/games-blocklist/main/lists/Adblock-dns/games.txt',
        'categories': ['games', 'list-IREK-szef-games'],
        'file': 'lists/games/IREK-szef-games',
        'name': 'IREK-szef-games'
    },
    {
        'url': 'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/refs/heads/master/adguard-roblox.txt',
        'categories': ['games', 'roblox', 'list-gieljnssns-roblox'],
        'file': 'lists/games/gieljnssns-roblox',
        'name': 'gieljnssns-roblox'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-minecraft.txt',
        'categories': ['games', 'minecraft', 'list-nickoppen-minecraft'],
        'file': 'lists/games/nickoppen-minecraft',
        'name': 'nickoppen-minecraft'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-steam.txt',
        'categories': ['games', 'steam', 'list-nickoppen-steam'],
        'file': 'lists/games/nickoppen-steam',
        'name': 'nickoppen-steam'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-square-enix.txt',
        'categories': ['games', 'square-enix', 'list-nickoppen-square-enix'],
        'file': 'lists/games/nickoppen-square-enix',
        'name': 'nickoppen-square-enix'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-rockstargames.txt',
        'categories': ['games', 'rockstargames', 'list-nickoppen-rockstargames'],
        'file': 'lists/games/nickoppen-rockstargames',
        'name': 'nickoppen-rockstargames'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-riotgames.txt',
        'categories': ['games', 'riotgames', 'list-nickoppen-riotgames'],
        'file': 'lists/games/nickoppen-riotgames',
        'name': 'nickoppen-riotgames'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-ubisoft.txt',
        'categories': ['games', 'ubisoft', 'list-nickoppen-ubisoft'],
        'file': 'lists/games/nickoppen-ubisoft',
        'name': 'nickoppen-ubisoft'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-warthunder.txt',
        'categories': ['games', 'warthunder', 'list-nickoppen-warthunder'],
        'file': 'lists/games/nickoppen-warthunder',
        'name': 'nickoppen-warthunder'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-zynga.txt',
        'categories': ['games', 'zynga', 'list-nickoppen-zynga'],
        'file': 'lists/games/nickoppen-zynga',
        'name': 'nickoppen-zynga'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-blizzard.txt',
        'categories': ['games', 'blizzard', 'list-nickoppen-blizzard'],
        'file': 'lists/games/nickoppen-blizzard',
        'name': 'nickoppen-blizzard'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-activision.txt',
        'categories': ['games', 'activision', 'list-nickoppen-activision'],
        'file': 'lists/games/nickoppen-activision',
        'name': 'nickoppen-activision'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-ea.txt',
        'categories': ['games', 'ea', 'list-nickoppen-ea'],
        'file': 'lists/games/nickoppen-ea',
        'name': 'nickoppen-ea'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-epicgames.txt',
        'categories': ['games', 'epicgames', 'list-nickoppen-epicgames'],
        'file': 'lists/games/nickoppen-epicgames',
        'name': 'nickoppen-epicgames'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-nintendo.txt',
        'categories': ['games', 'nintendo', 'list-nickoppen-nintendo'],
        'file': 'lists/games/nickoppen-nintendo',
        'name': 'nickoppen-nintendo'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-take-twoInteractive.txt',
        'categories': ['games', 'take-twointeractive', 'list-nickoppen-take-twointeractive'],
        'file': 'lists/games/nickoppen-take-twointeractive',
        'name': 'nickoppen-take-twointeractive'
    },

    # URL Shorteners

    {
        'url': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/urlshortener.txt',
        'categories': ['url-shorteners', 'list-hagezi-urlshortener'],
        'file': 'lists/url-shorteners/hagezi-urlshortener',
        'name': 'hagezi-urlshortener'
    },

    # FakeNews

    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/alternates/fakenews-only/hosts',
        'categories': ['fake-news', 'list-StevenBlack-fakenews-only'],
        'file': 'lists/fakenews/StevenBlack-fakenews-only',
        'name': 'StevenBlack-fakenews-only'
    },

    # Streaming
    
    {
        'url': 'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/refs/heads/master/adguard-netflix.txt',
        'categories': ['streaming', 'netflix', 'list-gieljnssns-netflix'],
        'file': 'lists/streaming/gieljnssns-netflix',
        'name': 'gieljnssns-netflix'
    },
    {
        'url': 'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/refs/heads/master/adguard-twitch.txt',
        'categories': ['streaming', 'twitch', 'list-gieljnssns-twitch'],
        'file': 'lists/streaming/gieljnssns-twitch',
        'name': 'gieljnssns-twitch'
    },
    {
        'url': 'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/refs/heads/master/adguard-tiktok.txt',
        'categories': ['streaming', 'tiktok', 'list-gieljnssns-tiktok'],
        'file': 'lists/streaming/gieljnssns-tiktok',
        'name': 'gieljnssns-tiktok'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/services/main/services/disneyplus',
        'categories': ['streaming', 'disneyplus', 'list-nextdns-disneyplus'],
        'file': 'lists/streaming/nextdns-disneyplus',
        'name': 'nextdns-disneyplus'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/services/main/services/hulu',
        'categories': ['streaming', 'hulu', 'list-nextdns-hulu'],
        'file': 'lists/streaming/nextdns-hulu',
        'name': 'nextdns-hulu'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/services/main/services/spotify',
        'categories': ['streaming', 'spotify', 'list-nextdns-spotify'],
        'file': 'lists/streaming/nextdns-spotify',
        'name': 'nextdns-spotify'
    },
    {
        'url': 'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/refs/heads/master/adguard-youtube.txt',
        'categories': ['streaming', 'youtube', 'list-gieljnssns-youtube'],
        'file': 'lists/streaming/gieljnssns-youtube',
        'name': 'gieljnssns-youtube'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/services/main/services/vimeo',
        'categories': ['streaming', 'vimeo', 'list-nextdns-vimeo'],
        'file': 'lists/streaming/nextdns-vimeo',
        'name': 'nextdns-vimeo'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/piracy-blocklists/master/streaming-video',
        'categories': ['streaming', 'streaming-video','list-nextdns-streaming-video'],
        'file': 'lists/streaming/nextdns-streaming-video',
        'name': 'nextdns-streaming-video'
    },
    {
        'url': 'https://raw.githubusercontent.com/nextdns/piracy-blocklists/master/streaming-audio',
        'categories': ['streaming', 'streaming-audio','list-nextdns-streaming-audio'],
        'file': 'lists/streaming/nextdns-streaming-audio',
        'name': 'nextdns-streaming-audio'
    },

    # Malicious

    {
        'url': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt',
        'categories': ['malicious', 'list-hagezi-fake'],
        'file': 'lists/malicious/hagezi-fake',
        'name': 'hagezi-fake'
    },
    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt',
        'categories': ['malicious', 'fraud','list-blocklistproject-fraud-nl'],
        'file': 'lists/malicious/blocklistproject-fraud-nl',
        'name': 'blocklistproject-fraud-nl'
    },
    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt',
        'categories': ['malicious', 'ransomware', 'list-blocklistproject-ransomware-nl'],
        'file': 'lists/malicious/blocklistproject-ransomware-nl',
        'name': 'blocklistproject-ransomware-nl'
    },
    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt',
        'categories': ['malicious', 'scam', 'list-blocklistproject-scam-nl'],
        'file': 'lists/malicious/blocklistproject-scam-nl',
        'name': 'blocklistproject-scam-nl'
    },
    {
        'url': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/tif.txt',
        'categories': ['malicious', 'list-hagezi-tif'],
        'file': 'lists/malicious/hagezi-tif',
        'name': 'hagezi-tif'
    },
    {
        'url': 'https://phishing.army/download/phishing_army_blocklist_extended.txt',
        'categories': ['malicious', 'phishing', 'list-phishing_army'],
        'file': 'lists/malicious/phishing_army_blocklist_extended',
        'name': 'malicious-phishing_army_blocklist_extended'
    },
    {
        'url': 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt',
        'categories': ['malicious', 'malware', 'list-notrack-malware'],
        'file': 'lists/malicious/notrack-malware',
        'name': 'malicious-notrack-malware'
    },
    {
        'url': 'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt',
        'categories': ['malicious', 'list-DandelionSprout-anti-malware-hosts'],
        'file': 'lists/malicious/DandelionSprout-anti-malware-hosts',
        'name': 'DandelionSprout-malicious-anti-malware-hosts'
    },
    {
        'url': 'https://v.firebog.net/hosts/Prigent-Crypto.txt',
        'categories': ['malicious', 'crypto', 'list-Prigent-Crypto'],
        'file': 'lists/malicious/Prigent-Crypto',
        'name': 'Prigent-malicious-crypto'
    },
    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/crypto-nl.txt',
        'categories': ['malicious', 'crypto', 'list-blocklistproject-crypto-nl'],
        'file': 'lists/malicious/blocklistproject-crypto-nl',
        'name': 'blocklistproject-crypto-nl'
    },
    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt',
        'categories': ['malicious', 'malware', 'list-blocklistproject-malware-nl'],
        'file': 'lists/malicious/blocklistproject-malware-nl',
        'name': 'blocklistproject-malware-nl'
    },
    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt',
        'categories': ['malicious', 'phishing', 'list-blocklistproject-phishing-nl'],
        'file': 'lists/malicious/blocklistproject-phishing-nl',
        'name': 'blocklistproject-phishing-nl'
    },
    {
        'url': 'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts',
        'categories': ['malicious', 'list-FadeMind-Risk'],
        'file': 'lists/malicious/FadeMind-Risk',
        'name': 'FadeMind-malicious-risk'
    },
    {
        'url': 'https://v.firebog.net/hosts/RPiList-Malware.txt',
        'categories': ['malicious', 'list-RPiList-Malware'],
        'file': 'lists/malicious/RPiList-Malware',
        'name': 'RPiList-malicious'
    },
    {
        'url': 'https://lists.cyberhost.uk/malware.txt',
        'categories': ['malicious', 'list-cyberhostuk-malware'],
        'file': 'lists/malicious/cyberhostuk-malware',
        'name': 'cyberhostuk-malicious'
    },

    # Tracking

    {
        'url': 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt',
        'categories': ['tracking', 'list-notrack-blocklist'],
        'file': 'lists/tracking/notrack-blocklist',
        'name': 'tracking-notrack-blocklist'
    },
    {
        'url': 'https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts',
        'categories': ['tracking', 'list-FadeMind-2o7Net'],
        'file': 'lists/tracking/FadeMind-2o7Net',
        'name': 'tracking-FadeMind-2o7Net'
    },
    {
        'url': 'https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt',
        'categories': ['tracking', 'list-firstparty-trackers'],
        'file': 'lists/tracking/firstparty-trackers',
        'name': 'tracking-firstparty-trackers'
    },
    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt',
        'categories': ['tracking', 'list-blocklistproject-tracking-nl'],
        'file': 'lists/tracking/blocklistproject-tracking-nl',
        'name': 'blocklistproject-tracking-nl'
    },
    {
        'url': 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt',
        'categories': ['tracking', 'windows-tracking', 'list-windows-spy-blocker'],
        'file': 'lists/tracking/WindowsSpyBlocker',
        'name': 'tracking-WindowsSpyBlocker'
    },
    {
        'url': 'https://v.firebog.net/hosts/Easyprivacy.txt',
        'categories': ['tracking', 'list-Easyprivacy'],
        'file': 'lists/tracking/Easyprivacy',
        'name': 'tracking-Easyprivacy'
    },
    {
        'url': 'https://v.firebog.net/hosts/Prigent-Ads.txt',
        'categories': ['tracking', 'list-Prigent-Ads'],
        'file': 'lists/tracking/Prigent-Ads',
        'name': 'tracking-Prigent-Ads'
    },

    # Advertising

    {
        'url': 'https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt',
        'categories': ['advertising', 'list-blocklistproject-ads-nl'],
        'file': 'lists/advertising/blocklistproject-ads-nl',
        'name': 'blocklistproject-ads-nl'
    },
    {
        'url': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/popupads.txt',
        'categories': ['advertising', 'list-hagezi-popupads'],
        'file': 'lists/advertising/hagezi-popupads',
        'name': 'hagezi-popupads'
    },
    {
        'url': 'https://adaway.org/hosts.txt',
        'categories': ['advertising', 'list-AdAway'],
        'file': 'lists/advertising/AdAway',
        'name': 'advertising-AdAway'
    },
    {
        'url': 'https://v.firebog.net/hosts/AdguardDNS.txt',
        'categories': ['advertising', 'list-AdguardDNS'],
        'file': 'lists/advertising/AdguardDNS',
        'name': 'advertising-AdguardDNS'
    },
    {
        'url': 'https://v.firebog.net/hosts/Admiral.txt',
        'categories': ['advertising', 'list-Admiral'],
        'file': 'lists/advertising/Admiral',
        'name': 'advertising-Admiral'
    },
    {
        'url': 'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',
        'categories': ['advertising', 'list-anudeepND'],
        'file': 'lists/advertising/anudeepND',
        'name': 'advertising-anudeepND'
    },
    {
        'url': 'https://v.firebog.net/hosts/Easylist.txt',
        'categories': ['advertising', 'list-Easylist'],
        'file': 'lists/advertising/Easylist',
        'name': 'advertising-Easylist'
    },
    {
        'url': 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext',
        'categories': ['advertising', 'list-pgl-yoyo'],
        'file': 'lists/advertising/pgl-yoyo',
        'name': 'advertising-pgl-yoyo'
    },
    {
        'url': 'https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts',
        'categories': ['advertising', 'list-bigdargon-hostsVN'],
        'file': 'lists/advertising/bigdargon-hostsVN',
        'name': 'advertising-bigdargon-hostsVN'
    },

    # VPN
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-atlasvpn.txt',
        'categories': ['vpn', 'atlasvpn', 'list-nickoppen-atlasvpn'],
        'file': 'lists/vpn/nickoppen-atlasvpn',
        'name': 'nickoppen-atlasvpn'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-cyberghostvpn.txt',
        'categories': ['vpn', 'cyberghostvpn', 'list-nickoppen-cyberghostvpn'],
        'file': 'lists/vpn/nickoppen-cyberghostvpn',
        'name': 'nickoppen-cyberghostvpn'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-expressvpn.txt',
        'categories': ['vpn', 'expressvpn', 'list-nickoppen-expressvpn'],
        'file': 'lists/vpn/nickoppen-expressvpn',
        'name': 'nickoppen-expressvpn'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-freevpnplanet.txt',
        'categories': ['vpn', 'freevpnplanet', 'list-nickoppen-freevpnplanet'],
        'file': 'lists/vpn/nickoppen-freevpnplanet',
        'name': 'nickoppen-freevpnplanet'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-hide.txt',
        'categories': ['vpn', 'hide.me', 'list-nickoppen-hide'],
        'file': 'lists/vpn/nickoppen-hide',
        'name': 'nickoppen-hide'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-hideservers.txt',
        'categories': ['vpn', 'hide.me', 'list-nickoppen-hideservers'],
        'file': 'lists/vpn/nickoppen-hideservers',
        'name': 'nickoppen-hideservers'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-hotspotshield.txt',
        'categories': ['vpn', 'hotspotshield', 'list-nickoppen-hotspotshield'],
        'file': 'lists/vpn/nickoppen-hotspotshield',
        'name': 'nickoppen-hotspotshield'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-ipvanish.txt',
        'categories': ['vpn', 'ipvanish', 'list-nickoppen-ipvanish'],
        'file': 'lists/vpn/nickoppen-ipvanish',
        'name': 'nickoppen-ipvanish'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-ivpn.txt',
        'categories': ['vpn', 'ivpn', 'list-nickoppen-ivpn'],
        'file': 'lists/vpn/nickoppen-ivpn',
        'name': 'nickoppen-ivpn'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-mullvad.txt',
        'categories': ['vpn', 'mullvad', 'list-nickoppen-mullvad'],
        'file': 'lists/vpn/nickoppen-mullvad',
        'name': 'nickoppen-mullvad'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-privadovpn.txt',
        'categories': ['vpn', 'privadovpn', 'list-nickoppen-privadovpn'],
        'file': 'lists/vpn/nickoppen-privadovpn',
        'name': 'nickoppen-privadovpn'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-privateinternetaccess.txt',
        'categories': ['vpn', 'privateinternetaccess', 'list-nickoppen-privateinternetaccess'],
        'file': 'lists/vpn/nickoppen-privateinternetaccess',
        'name': 'nickoppen-privateinternetaccess'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-protonvpn.txt',
        'categories': ['vpn', 'protonvpn', 'list-nickoppen-protonvpn'],
        'file': 'lists/vpn/nickoppen-protonvpn',
        'name': 'nickoppen-protonvpn'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-purevpn.txt',
        'categories': ['vpn', 'purevpn', 'list-nickoppen-purevpn'],
        'file': 'lists/vpn/nickoppen-purevpn',
        'name': 'nickoppen-purevpn'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-strongvpn.txt',
        'categories': ['vpn', 'strongvpn', 'list-nickoppen-strongvpn'],
        'file': 'lists/vpn/nickoppen-strongvpn',
        'name': 'nickoppen-strongvpn'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-surfshark.txt',
        'categories': ['vpn', 'surfshark', 'list-nickoppen-surfshark'],
        'file': 'lists/vpn/nickoppen-surfshark',
        'name': 'nickoppen-surfshark'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-tunnelbear.txt',
        'categories': ['vpn', 'tunnelbear', 'list-nickoppen-tunnelbear'],
        'file': 'lists/vpn/nickoppen-tunnelbear',
        'name': 'nickoppen-tunnelbear'
    },
    {
        'url': 'https://raw.githubusercontent.com/nickoppen/pihole-blocklists/refs/heads/master/blocklist-urban-vpn.txt',
        'categories': ['vpn', 'urbanvpn', 'list-nickoppen-urbanvpn'],
        'file': 'lists/vpn/nickoppen-urbanvpn',
        'name': 'nickoppen-urbanvpn'
    },

    # Proxies
    {
        'url': 'https://raw.githubusercontent.com/nextdns/piracy-blocklists/master/proxies',
        'categories': ['proxy', 'list-nextdns-proxy'],
        'file': 'lists/proxy/nextdns-proxy',
        'name': 'nextdns-proxy'
    },

]


def get_host_files():
    return host_files


def read_config(config_file='config.yaml'):
    """Reads our config file

    :return: dict
    """
    with open(config_file, 'r') as stream:
        try:
            conf = yaml.load(stream, Loader=yaml.FullLoader)
            password_file = conf['redis']['password_file']
            if not os.path.exists(password_file):
                raise FileNotFoundError(f"Password file {password_file} not found")
            # Read the password from the secret file
            with open(password_file, 'r') as password_file:
                conf['redis']['password'] = password_file.read().strip()
            return conf
        except yaml.YAMLError as exc:
            print(exc)


def process_ignorelist(r=False, tag=False):
    print('Processing ignorelist')
    if os.path.exists('lists/ignorelist.json'):
        config = read_config()
        if not r:
            r = Redis(
                host=config['redis']['host'],
                port=config['redis']['port'],
                password=config['redis']['password'],
                db=config['redis']['host_list_db']
            )
            if not tag:
                tag = r.get('turkey-bite:current-tag').decode('utf-8')
                pass

        with open('lists/ignorelist.json', 'r') as json_file:
            ignorelist = json.load(json_file)
            for context, hosts in ignorelist.items():
                print('Processing ' + context + ' ignorelist... ')
                for host in hosts:
                    key = 'turkey-bite:' + tag + ':' + host
                    result = r.get(key)
                    if result:
                        result = json.loads(result.decode('utf-8'))
                        print('Processing ' + host + ':')
                        print(result['categories'])
                        while context in result['categories']:
                            result['categories'].remove(context)
                        r.set(key, json.dumps({'name': host, 'categories': result['categories']}))
                        print('Done processing ' + host + ':')
                        print(result['categories'])
    else:
        print('No ignorelist.json file to process.')

def pull_tld_list():
    tlds = []
    file = 'lists/tld/tld.txt'
    try:
        print('Downloading: TLD list')
        opener = urllib.request.build_opener()
        opener.addheaders = [
            (
                'User-agent',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'
            )
        ]
        if os.path.exists(file):
            # remove the file
            os.remove(file)
        urllib.request.install_opener(opener)
        urllib.request.urlretrieve('https://data.iana.org/TLD/tlds-alpha-by-domain.txt', file)
        print('Downloaded: TLD list')
        
    except Exception as e:
        print('Failed to download: TLD list')
        print(e)
        print('Using fallback TLD list')
        file = 'lists/tld/fallback.txt'
    
    with open(file, 'r') as tld_file:
        for line in tld_file:
            if line.startswith('#'):
                continue
            tlds.append(line.strip().lower())
    return tlds
    
def clean_list_file(file_path: str, tlds: list[str]):
    hosts = []
    # Read the file
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    # Process the file
    for line in lines:
        line = line.strip()
        if line:
            # Sanitize the line
            # For IPv4 addresses at start of line
            line = re.sub(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*', '', line)
            # For IPv6 addresses at start of line 
            line = re.sub(r'^([0-9a-fA-F:]{2,39})\s*', '', line)
            # Remove any whitespace
            line = re.sub(r'\s+', '', line)
            # Strip '||' from begining
            line = re.sub(r'^\|\|', '', line)
            # String '^' from end
            line = re.sub(r'\^$', '', line)

            # Validate the line
            # Skip comments and anything that starts with a hyphen
            # domains starting with a hyphen are not valid
            if line[0] in ['-', '#']:
                continue
            # Skip anything that ends with a hyphen
            # domains ending with a hyphen are not valid
            if line[-1] == '-':
                continue
            # Skip anything missing a period
            if '.' not in line:
                continue
            # ensure that line only contains valid characters
            if not re.match(r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$', line):
                continue
            # Check if the line is a valid domain
            if line.split('.')[-1] not in tlds:
                continue
            # Add the line to the list
            hosts.append(line)

    with open(file_path, 'w') as file:
        for host in hosts:
            file.write(host + '\n')

def pull_host_lists():
    # Get the list of TLDs
    tlds = pull_tld_list()
    # get names of only folders in lists/
    folders = [f for f in os.listdir('lists') if os.path.isdir(os.path.join('lists', f))]
    #loop over the folders and look for a default turkeybite list and custom list
    for folder in folders:
        # Skip tld folder
        if folder in ['tld']:
            continue
        # This allows for built in lists to be added to the host_files list
        if os.path.exists('lists/' + folder + '/turkeybite'):
            host_files.append({
                'url': None,
                'categories': ['list-turkeybite', folder],
                'file': 'lists/' + folder + '/turkeybite',
                'name': folder
            })
        # This allows for custom lists and categories to be added to the host_files list
        if os.path.exists('lists/' + folder + '/custom'):
            host_files.append({
                'url': None,
                'categories': ['list-custom', folder],
                'file': 'lists/' + folder + '/custom',
                'name': folder
            })

    for hlist in host_files:
        # Skip local lists for downloads
        if hlist['url'] is None:
            continue
        try:
            print('Downloading: ' + hlist['name'])
            opener = urllib.request.build_opener()
            opener.addheaders = [
                (
                    'User-agent',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'
                )
            ]
            urllib.request.install_opener(opener)
            urllib.request.urlretrieve(hlist['url'], hlist['file'])
            print('Downloaded: ' + hlist['name'])
            print('Cleaning: ' + hlist['name'])
            clean_list_file(hlist['file'], tlds)
            print('Cleaned: ' + hlist['name'])
        except Exception as e:
            print('Failed to download: ' + hlist['name'])
            print(e)
            pass

    config = read_config()
    r = Redis(
        host=config['redis']['host'],
        port=config['redis']['port'],
        password=config['redis']['password'],
        db=config['redis']['host_list_db']
    )
    print('Adding host entries to redis')

    tags = r.hgetall('turkey-bite:tags')
    old_tag = r.get('turkey-bite:current-tag')
    new_tag = str(int(time.time()))

    if tags:
        tags[new_tag] = 'creating'
    else:
        tags = {
            new_tag: 'creating'
        }
    r.hmset('turkey-bite:tags', tags)

    if old_tag:
        old_tag = old_tag.decode('utf-8')
        r.set('turkey-bite:old-tag', old_tag)

    for hostlist in host_files:
        # If the file exists
        if os.path.exists(hostlist['file']):
            # Open the file
            with open(hostlist['file']) as f:
                for line in f:
                    line = line.strip().lower()
                    key = 'turkey-bite:' + new_tag + ':' + line
                    result = r.get(key)
                    if result:
                        try:
                            result = json.loads(result.decode('utf-8'))
                            result['categories'] = result['categories'] + list(
                                set(hostlist['categories']) - set(result['categories']))
                            r.set(key, json.dumps({'name': line, 'categories': result['categories']}))
                            print('Updated ' + line + ' in host list cache.')
                        except:
                            print('Jamming entry into place anyway')
                            r.set(key, json.dumps({'name': line, 'categories': hostlist['categories']}))
                            print('Added ' + line + ' to host list cache.')
                    else:
                        r.set(key, json.dumps({'name': line, 'categories': hostlist['categories']}))
                        print('Added ' + line + ' to host list cache.')

    process_ignorelist(r=r, tag=new_tag)

    # Set the new tag as live
    tags[new_tag] = 'live'
    r.set('turkey-bite:current-tag', new_tag)
    r.hmset('turkey-bite:tags', tags)

    if old_tag:
        print('Purging previous data')
        tags[old_tag] = 'purging'
        r.hmset('turkey-bite:tags', tags)
        for key in r.scan_iter('turkey-bite:' + old_tag + ':*'):
            r.delete(key)
        tags[old_tag] = 'purged'
        r.hmset('turkey-bite:tags', tags)
        print('Done purging previous data')
