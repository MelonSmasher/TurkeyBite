import yaml
import urllib.request
import subprocess
import os
from redis import Redis
import json
import time

host_files = [
    {
        'url': 'https://blocklist.site/app/dl/proxy',
        'categories': ['proxy/vpn'],
        'file': 'lists/proxy/blocklist-site-proxy',
        'name': 'proxy-blocklist-site-proxy'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/porn/clefspeare13/hosts',
        'categories': ['porn'],
        'file': 'lists/porn/clefspeare13',
        'name': 'porn-clefspeare13'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/porn/sinfonietta-snuff/hosts',
        'categories': ['porn', 'snuff'],
        'file': 'lists/porn/sinfonietta-snuff',
        'name': 'porn-sinfonietta-snuff'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/porn/sinfonietta/hosts',
        'categories': ['porn'],
        'file': 'lists/porn/sinfonietta',
        'name': 'porn-sinfonietta'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/porn/tiuxo/hosts',
        'categories': ['porn'],
        'file': 'lists/porn/tiuxo',
        'name': 'porn-tiuxo'
    },
    {
        'url': 'https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list',
        'categories': ['porn'],
        'file': 'lists/porn/pi_blocklist_porn_all',
        'name': 'porn-pi_blocklist_porn_all'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/social/tiuxo/hosts',
        'categories': ['social'],
        'file': 'lists/social/tiuxo',
        'name': 'social-tiuxo'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/social/sinfonietta/hosts',
        'categories': ['social'],
        'file': 'lists/social/sinfonietta',
        'name': 'social-sinfonietta'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/gambling/hosts',
        'categories': ['gambling'],
        'file': 'lists/gambling/StevenBlack',
        'name': 'gambling-StevenBlack'
    },
    {
        'url': 'https://blocklist.site/app/dl/gambling',
        'categories': ['gambling'],
        'file': 'lists/gambling/blocklist-site-gambling',
        'name': 'gambling-blocklist-site-gambling'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/extensions/fakenews/hosts',
        'categories': ['fakenews'],
        'file': 'lists/fakenews/StevenBlack',
        'name': 'fakenews-StevenBlack'
    },
    {
        'url': 'https://blocklist.site/app/dl/fakenews',
        'categories': ['fakenews'],
        'file': 'lists/fakenews/blocklist-site-fakenews',
        'name': 'fakenews-blocklist-site-fakenews'
    },
    {
        'url': 'https://www.malwaredomainlist.com/hostslist/hosts.txt',
        'categories': ['malicious', 'malware'],
        'file': 'lists/malicious/malwaredomainlist',
        'name': 'malicious-malwaredomainlist'
    },
    {
        'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt',
        'categories': ['advertising'],
        'file': 'lists/malicious/disconnect-me',
        'name': 'malicious-disconnect-me'
    },
    {
        'url': 'https://hosts-file.net/exp.txt',
        'categories': ['malicious', 'exploits'],
        'file': 'lists/malicious/hosts-file-net-exp',
        'name': 'malicious-hosts-file-net-exp'
    },
    {
        'url': 'https://hosts-file.net/emd.txt',
        'categories': ['malicious', 'malware'],
        'file': 'lists/malicious/hosts-file-net-emd',
        'name': 'malicious-hosts-file-net-emd'
    },
    {
        'url': 'https://hosts-file.net/psh.txt',
        'categories': ['malicious', 'phishing'],
        'file': 'lists/malicious/hosts-file-net-psh',
        'name': 'malicious-hosts-file-net-psh'
    },
    {
        'url': 'https://hosts-file.net/ad_servers.txt',
        'categories': ['advertising'],
        'file': 'lists/advertising/ad_servers',
        'name': 'advertising-ad_servers'
    },
    {
        'url': 'https://hosts-file.net/fsa.txt',
        'categories': ['malicious', 'fraud'],
        'file': 'lists/malicious/fsa',
        'name': 'malicious-hosts-file-net-fsa'
    },
    {
        'url': 'https://blocklist.site/app/dl/fraud',
        'categories': ['malicious', 'fraud'],
        'file': 'lists/malicious/blocklist-site-fraud',
        'name': 'malicious-blocklist-site-fraud'
    },
    {
        'url': 'https://hosts-file.net/hjk.txt',
        'categories': ['malicious', 'hijack'],
        'file': 'lists/malicious/hjk',
        'name': 'malicious-hosts-file-net-hjk'
    },
    {
        'url': 'https://mirror.cedia.org.ec/malwaredomains/immortal_domains.txt',
        'categories': ['malicious', 'malware'],
        'file': 'lists/malicious/immortal_domains',
        'name': 'malicious-immortal_domains'
    },
    {
        'url': 'https://blocklist.site/app/dl/malware',
        'categories': ['malicious', 'malware'],
        'file': 'lists/malicious/blocklist-site-malware',
        'name': 'malicious-blocklist-site-malware'
    },
    {
        'url': 'https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt',
        'categories': ['malicious'],
        'file': 'lists/malicious/ethanr',
        'name': 'malicious-ethanr'
    },
    {
        'url': 'https://v.firebog.net/hosts/Prigent-Malware.txt',
        'categories': ['malicious', 'malware'],
        'file': 'lists/malicious/firebog-malware',
        'name': 'malicious-firebog-malware'
    },
    {
        'url': 'https://v.firebog.net/hosts/Prigent-Phishing.txt',
        'categories': ['malicious', 'phishing'],
        'file': 'lists/malicious/firebog-phishing',
        'name': 'malicious-firebog-phishing'
    },
    {
        'url': 'https://blocklist.site/app/dl/phishing',
        'categories': ['malicious', 'phishing'],
        'file': 'lists/malicious/blocklist-site-phishing',
        'name': 'malicious-blocklist-site-phishing'
    },
    {
        'url': 'https://blocklist.site/app/dl/piracy',
        'categories': ['piracy'],
        'file': 'lists/piracy/blocklist-site-piracy',
        'name': 'piracy-blocklist-site-piracy'
    },
    {
        'url': 'https://blocklist.site/app/dl/torrent',
        'categories': ['torrent'],
        'file': 'lists/piracy/blocklist-site-torrent',
        'name': 'piracy-blocklist-site-torrent'
    },
    {
        'url': 'https://phishing.army/download/phishing_army_blocklist_extended.txt',
        'categories': ['malicious', 'phishing'],
        'file': 'lists/malicious/phishing_army_blocklist_extended',
        'name': 'malicious-phishing_army_blocklist_extended'
    },
    {
        'url': 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt',
        'categories': ['malicious', 'malware'],
        'file': 'lists/malicious/notrack-malware',
        'name': 'malicious-notrack-malware'
    },
    {
        'url': 'https://blocklist.site/app/dl/ransomware',
        'categories': ['malicious', 'ransomware'],
        'file': 'lists/malicious/blocklist-site-ransomware',
        'name': 'malicious-blocklist-site-ransomware'
    },
    {
        'url': 'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt',
        'categories': ['malicious', 'ransomware'],
        'file': 'lists/malicious/RW_DOMBL',
        'name': 'malicious-RW_DOMBL'
    },
    {
        'url': 'https://ransomwaretracker.abuse.ch/downloads/CW_C2_DOMBL.txt',
        'categories': ['malicious', 'ransomware'],
        'file': 'lists/malicious/CW_C2_DOMBL',
        'name': 'malicious-CW_C2_DOMBL'
    },
    {
        'url': 'https://ransomwaretracker.abuse.ch/downloads/LY_C2_DOMBL.txt',
        'categories': ['malicious', 'ransomware'],
        'file': 'lists/malicious/LY_C2_DOMBL',
        'name': 'malicious-LY_C2_DOMBL'
    },
    {
        'url': 'https://ransomwaretracker.abuse.ch/downloads/TC_C2_DOMBL.txt',
        'categories': ['malicious', 'ransomware'],
        'file': 'lists/malicious/TC_C2_DOMBL',
        'name': 'malicious-TC_C2_DOMBL'
    },
    {
        'url': 'https://ransomwaretracker.abuse.ch/downloads/TL_C2_DOMBL.txt',
        'categories': ['malicious', 'ransomware'],
        'file': 'lists/malicious/TL_C2_DOMBL',
        'name': 'malicious-TL_C2_DOMBL'
    },
    {
        'url': 'https://v.firebog.net/hosts/Shalla-mal.txt',
        'categories': ['malicious'],
        'file': 'lists/malicious/shalla',
        'name': 'malicious-shalla'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.Risk/hosts',
        'categories': ['malicious'],
        'file': 'lists/malicious/StevenBlack-risk',
        'name': 'malicious-StevenBlack-risk'
    },
    {
        'url': 'https://www.squidblacklist.org/downloads/dg-malicious.acl',
        'categories': ['malicious'],
        'file': 'lists/malicious/squidblacklist',
        'name': 'malicious-squidblacklist'
    },
    {
        'url': 'https://raw.githubusercontent.com/HorusTeknoloji/TR-PhishingList/master/url-lists.txt',
        'categories': ['malicious', 'phishing'],
        'file': 'lists/malicious/HorusTeknoloji-Phishing',
        'name': 'malicious-HorusTeknoloji-Phishing'
    },
    {
        'url': 'https://v.firebog.net/hosts/Airelle-hrsk.txt',
        'categories': ['malicious'],
        'file': 'lists/malicious/Airelle-hrsk',
        'name': 'malicious-Airelle-hrsk'
    },
    {
        'url': 'https://zerodot1.gitlab.io/CoinBlockerLists/hosts',
        'categories': ['malicious', 'mining'],
        'file': 'lists/mining/CoinBlockerLists',
        'name': 'malicious-CoinBlockerLists'
    },
    {
        'url': 'https://blocklist.site/app/dl/drugs',
        'categories': ['drugs'],
        'file': 'lists/drugs/blocklist-site',
        'name': 'drugs-blocklist-site'
    },
    {
        'url': 'https://v.firebog.net/hosts/Easyprivacy.txt',
        'categories': ['tracking'],
        'file': 'lists/tracking/Easyprivacy',
        'name': 'tracking-Easyprivacy'
    },
    {
        'url': 'https://blocklist.site/app/dl/tracking',
        'categories': ['tracking'],
        'file': 'lists/tracking/blocklist-site-tracking',
        'name': 'tracking-locklist-site-tracking'
    },
    {
        'url': 'https://v.firebog.net/hosts/Prigent-Ads.txt',
        'categories': ['tracking'],
        'file': 'lists/tracking/Prigent-Ads',
        'name': 'tracking-Prigent-Ads'
    },
    {
        'url': 'https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt',
        'categories': ['tracking'],
        'file': 'lists/tracking/notrack-blocklist',
        'name': 'tracking-notrack-blocklist'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/add.2o7Net/hosts',
        'categories': ['tracking'],
        'file': 'lists/tracking/StevenBlack',
        'name': 'tracking-StevenBlack'
    },
    {
        'url': 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt',
        'categories': ['tracking'],
        'file': 'lists/tracking/WindowsSpyBlocker',
        'name': 'tracking-WindowsSpyBlocker'
    },
    {
        'url': 'https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt',
        'categories': ['tracking'],
        'file': 'lists/tracking/android',
        'name': 'tracking-android'
    },
    {
        'url': 'https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt',
        'categories': ['tracking'],
        'file': 'lists/tracking/SmartTV',
        'name': 'tracking-SmartTV'
    },
    {
        'url': 'https://v.firebog.net/hosts/Airelle-trc.txt',
        'categories': ['tracking'],
        'file': 'lists/tracking/Airelle-trc',
        'name': 'tracking-Airelle-trc'
    },
    {
        'url': 'https://adaway.org/hosts.txt',
        'categories': ['advertising'],
        'file': 'lists/advertising/adaway',
        'name': 'advertising-adaway'
    },
    {
        'url': 'https://v.firebog.net/hosts/AdguardDNS.txt',
        'categories': ['advertising'],
        'file': 'lists/advertising/AdguardDNS',
        'name': 'advertising-AdguardDNS'
    },
    {
        'url': 'https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt',
        'categories': ['advertising'],
        'file': 'lists/advertising/anudeepND',
        'name': 'advertising-anudeepND'
    },
    {
        'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt',
        'categories': ['advertising'],
        'file': 'lists/advertising/disconnect-me',
        'name': 'advertising-disconnect-me'
    },
    {
        'url': 'https://v.firebog.net/hosts/Easylist.txt',
        'categories': ['advertising'],
        'file': 'lists/advertising/Easylist',
        'name': 'advertising-Easylist'
    },
    {
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/UncheckyAds/hosts',
        'categories': ['advertising'],
        'file': 'lists/advertising/UncheckyAds',
        'name': 'advertising-UncheckyAds'
    },
    {
        'url': 'https://www.squidblacklist.org/downloads/dg-ads.acl',
        'categories': ['advertising'],
        'file': 'lists/advertising/squidblacklist',
        'name': 'advertising-squidblacklist'
    },
    {
        'url': 'https://blocklist.site/app/dl/ads',
        'categories': ['advertising'],
        'file': 'lists/advertising/blocklist-site',
        'name': 'advertising-blocklist-site'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/adv/domains',
        'categories': ['advertising'],
        'file': 'lists/advertising/shallalist-adv',
        'name': 'advertising-shallalist-adv'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/aggressive/domains',
        'categories': ['aggressive'],
        'file': 'lists/misc/shallalist-aggressive',
        'name': 'misc-shallalist-aggressive'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/alcohol/domains',
        'categories': ['alcohol'],
        'file': 'lists/drugs/shallalist-alcohol',
        'name': 'drugs-shallalist-alcohol'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/anonvpn/domains',
        'categories': ['proxy/vpn'],
        'file': 'lists/proxy/shallalist-anonvpn',
        'name': 'proxy-shallalist-anonvpn'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/anonvpn/domains',
        'categories': ['proxy/vpn'],
        'file': 'lists/proxy/shallalist-anonvpn',
        'name': 'proxy-shallalist-anonvpn'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/automobile/bikes/domains',
        'categories': ['automobile', 'bikes'],
        'file': 'lists/misc/shallalist-automobile-bikes',
        'name': 'misc-shallalist-automobile-bikes'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/automobile/boats/domains',
        'categories': ['automobile', 'boats'],
        'file': 'lists/misc/shallalist-automobile-boats',
        'name': 'misc-shallalist-automobile-boats'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/automobile/cars/domains',
        'categories': ['automobile', 'cars'],
        'file': 'lists/misc/shallalist-automobile-cars',
        'name': 'misc-shallalist-automobile-cars'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/automobile/planes/domains',
        'categories': ['automobile', 'planes'],
        'file': 'lists/misc/shallalist-automobile-planes',
        'name': 'misc-shallalist-automobile-planes'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/chat/domains',
        'categories': ['social', 'chat'],
        'file': 'social/misc/shallalist-chat',
        'name': 'social-shallalist-chat'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/costtraps/domains',
        'categories': ['cost-trap'],
        'file': 'lists/misc/shallalist-costtraps',
        'name': 'misc-shallalist-costtraps'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/dating/domains',
        'categories': ['dating'],
        'file': 'lists/misc/shallalist-dating',
        'name': 'misc-shallalist-dating'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/drugs/domains',
        'categories': ['drugs'],
        'file': 'lists/drugs/shallalist-drugs',
        'name': 'drugs-shallalist-drugs'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/education/schools/domains',
        'categories': ['education'],
        'file': 'lists/misc/shallalist-education-schools',
        'name': 'misc-shallalist-education-schools'
    },

    {
        'url': 'https://res.sage.edu/files/shallalist/BL/finance/banking/domains',
        'categories': ['finance', 'banking'],
        'file': 'lists/misc/shallalist-finance-banking',
        'name': 'misc-shallalist-finance-banking'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/finance/insurance/domains',
        'categories': ['finance', 'insurance'],
        'file': 'lists/misc/shallalist-finance-insurance',
        'name': 'misc-shallalist-finance-insurance'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/finance/moneylending/domains',
        'categories': ['finance', 'moneylending'],
        'file': 'lists/misc/shallalist-finance-moneylending',
        'name': 'misc-shallalist-finance-moneylending'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/finance/other/domains',
        'categories': ['finance'],
        'file': 'lists/misc/shallalist-finance-other',
        'name': 'misc-shallalist-finance-other'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/finance/realestate/domains',
        'categories': ['finance', 'realestate'],
        'file': 'lists/misc/shallalist-finance-realestate',
        'name': 'misc-shallalist-finance-realestate'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/finance/trading/domains',
        'categories': ['finance', 'trading'],
        'file': 'lists/misc/shallalist-finance-trading',
        'name': 'misc-shallalist-finance-trading'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/fortunetelling/domains',
        'categories': ['fortunetelling'],
        'file': 'lists/misc/shallalist-fortunetelling',
        'name': 'misc-shallalist-fortunetelling'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/forum/domains',
        'categories': ['forum'],
        'file': 'lists/misc/shallalist-forum',
        'name': 'misc-shallalist-forum'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/gamble/domains',
        'categories': ['gambling'],
        'file': 'lists/gambling/shallalist-gamble',
        'name': 'gambling-shallalist-gamble'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/government/domains',
        'categories': ['government'],
        'file': 'lists/misc/shallalist-government',
        'name': 'misc-shallalist-government'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/hacking/domains',
        'categories': ['hacking'],
        'file': 'lists/misc/shallalist-hacking',
        'name': 'misc-shallalist-hacking'
    },

    {
        'url': 'https://res.sage.edu/files/shallalist/BL/hobby/cooking/domains',
        'categories': ['hobby', 'cooking'],
        'file': 'lists/misc/shallalist-hobby-cooking',
        'name': 'misc-shallalist-hobby-cooking'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/hobby/games-misc/domains',
        'categories': ['hobby', 'games-misc', 'gaming'],
        'file': 'lists/misc/shallalist-hobby-games-misc',
        'name': 'misc-shallalist-hobby-games-misc'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/hobby/games-online/domains',
        'categories': ['hobby', 'games-online', 'gaming'],
        'file': 'lists/misc/shallalist-hobby-games-online',
        'name': 'misc-shallalist-hobby-games-online'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/hobby/gardening/domains',
        'categories': ['hobby', 'gardening'],
        'file': 'lists/misc/shallalist-hobby-gardening',
        'name': 'misc-shallalist-hobby-gardening'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/hobby/pets/domains',
        'categories': ['hobby', 'pets'],
        'file': 'lists/misc/shallalist-hobby-pets',
        'name': 'misc-shallalist-hobby-pets'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/homestyle/domains',
        'categories': ['lifestyle'],
        'file': 'lists/misc/shallalist-homestyle',
        'name': 'misc-shallalist-homestyle'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/hospitals/domains',
        'categories': ['hospital'],
        'file': 'lists/misc/shallalist-hospitals',
        'name': 'misc-shallalist-hospitals'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/imagehosting/domains',
        'categories': ['image-hosting'],
        'file': 'lists/misc/shallalist-imagehosting',
        'name': 'misc-shallalist-imagehosting'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/isp/domains',
        'categories': ['isp'],
        'file': 'lists/misc/shallalist-isp',
        'name': 'misc-shallalist-isp'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/jobsearch/domains',
        'categories': ['job-search'],
        'file': 'lists/misc/shallalist-jobsearch',
        'name': 'misc-shallalist-jobsearch'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/library/domains',
        'categories': ['library'],
        'file': 'lists/misc/shallalist-library',
        'name': 'misc-shallalist-library'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/military/domains',
        'categories': ['military'],
        'file': 'lists/misc/shallalist-military',
        'name': 'misc-shallalist-military'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/models/domains',
        'categories': ['models'],
        'file': 'lists/misc/shallalist-models',
        'name': 'misc-shallalist-models'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/movies/domains',
        'categories': ['movies'],
        'file': 'lists/misc/shallalist-movies',
        'name': 'misc-shallalist-movies'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/music/domains',
        'categories': ['music'],
        'file': 'lists/misc/shallalist-music',
        'name': 'misc-shallalist-music'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/news/domains',
        'categories': ['news'],
        'file': 'lists/misc/shallalist-news',
        'name': 'misc-shallalist-news'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/podcast/domains',
        'categories': ['podcast'],
        'file': 'lists/misc/shallalist-podcast',
        'name': 'misc-shallalist-podcast'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/politics/domains',
        'categories': ['politics'],
        'file': 'lists/misc/shallalist-politics',
        'name': 'misc-shallalist-politics'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/porn/domains',
        'categories': ['porn'],
        'file': 'lists/porn/shallalist-porn',
        'name': 'porn-shallalist-porn'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/radiotv/domains',
        'categories': ['radio-tv'],
        'file': 'lists/misc/shallalist-radiotv',
        'name': 'misc-shallalist-radiotv'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/recreation/humor/domains',
        'categories': ['recreation', 'humor'],
        'file': 'lists/misc/shallalist-recreation-humor',
        'name': 'misc-shallalist-recreation-humor'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/recreation/martialarts/domains',
        'categories': ['recreation', 'martial-arts', 'lifestyle'],
        'file': 'lists/misc/shallalist-recreation-martialarts',
        'name': 'misc-shallalist-recreation-martialarts'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/recreation/restaurants/domains',
        'categories': ['recreation', 'restaurants'],
        'file': 'lists/misc/shallalist-recreation-restaurants',
        'name': 'misc-shallalist-recreation-restaurants'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/recreation/sports/domains',
        'categories': ['recreation', 'sports', 'lifestyle'],
        'file': 'lists/misc/shallalist-recreation-sports',
        'name': 'misc-shallalist-recreation-sports'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/recreation/travel/domains',
        'categories': ['recreation', 'travel', 'lifestyle'],
        'file': 'lists/misc/shallalist-recreation-travel',
        'name': 'misc-shallalist-recreation-travel'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/recreation/wellness/domains',
        'categories': ['recreation', 'wellness', 'lifestyle'],
        'file': 'lists/misc/shallalist-recreation-wellness',
        'name': 'misc-shallalist-recreation-wellness'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/religion/domains',
        'categories': ['religion'],
        'file': 'lists/misc/shallalist-religion',
        'name': 'misc-shallalist-religion'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/remotecontrol/domains',
        'categories': ['remote-control'],
        'file': 'lists/misc/shallalist-remotecontrol',
        'name': 'misc-shallalist-remotecontrol'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/ringtones/domains',
        'categories': ['ringtones'],
        'file': 'lists/misc/shallalist-ringtones',
        'name': 'misc-shallalist-ringtones'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/science/astronomy/domains',
        'categories': ['science', 'astronomy'],
        'file': 'lists/misc/shallalist-science-astronomy',
        'name': 'misc-shallalist-science-astronomy'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/science/chemistry/domains',
        'categories': ['science', 'chemistry'],
        'file': 'lists/misc/shallalist-science-chemistry',
        'name': 'misc-shallalist-science-chemistry'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/searchengines/domains',
        'categories': ['search-engine'],
        'file': 'lists/misc/shallalist-searchengines',
        'name': 'misc-shallalist-searchengines'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/sex/education/domains',
        'categories': ['sex', 'sex-education'],
        'file': 'lists/misc/shallalist-sex-education',
        'name': 'misc-shallalist-sex-education'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/sex/lingerie/domains',
        'categories': ['sex', 'lingerie'],
        'file': 'lists/misc/shallalist-sex-lingerie',
        'name': 'misc-shallalist-sex-lingerie'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/shopping/domains',
        'categories': ['shopping'],
        'file': 'lists/misc/shallalist-shopping',
        'name': 'misc-shallalist-shopping'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/socialnet/domains',
        'categories': ['social', 'social-network'],
        'file': 'lists/misc/shallalist-socialnet',
        'name': 'misc-shallalist-socialnet'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/spyware/domains',
        'categories': ['spyware', 'malicious'],
        'file': 'lists/malicious/shallalist-spyware',
        'name': 'malicious-shallalist-spyware'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/tracker/domains',
        'categories': ['tracking'],
        'file': 'lists/tracking/shallalist-tracker',
        'name': 'tracking-shallalist-tracker'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/updatesites/domains',
        'categories': ['software-update'],
        'file': 'lists/misc/shallalist-updatesites',
        'name': 'misc-shallalist-updatesites'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/urlshortener/domains',
        'categories': ['url-shortener'],
        'file': 'lists/misc/shallalist-urlshortener',
        'name': 'misc-shallalist-urlshortener'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/violence/domains',
        'categories': ['violence'],
        'file': 'lists/misc/shallalist-violence',
        'name': 'misc-shallalist-violence'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/warez/domains',
        'categories': ['warez', 'piracy'],
        'file': 'lists/piracy/shallalist-warez',
        'name': 'piracy-shallalist-warez'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/weapons/domains',
        'categories': ['weapons'],
        'file': 'lists/misc/shallalist-weapons',
        'name': 'misc-shallalist-weapons'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/webmail/domains',
        'categories': ['web-mail'],
        'file': 'lists/misc/shallalist-webmail',
        'name': 'misc-shallalist-webmail'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/webphone/domains',
        'categories': ['web-phone'],
        'file': 'lists/misc/shallalist-webphone',
        'name': 'misc-shallalist-webphone'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/webradio/domains',
        'categories': ['web-radio'],
        'file': 'lists/misc/shallalist-webradio',
        'name': 'misc-shallalist-webradio'
    },
    {
        'url': 'https://res.sage.edu/files/shallalist/BL/webtv/domains',
        'categories': ['web-tv'],
        'file': 'lists/misc/shallalist-webtv',
        'name': 'misc-shallalist-webtv'
    }
]


def get_host_files():
    return host_files


def read_config():
    """
    Reads our config file
    :return: dict
    """
    with open('config.yaml', 'r') as stream:
        try:
            return yaml.load(stream, Loader=yaml.FullLoader)
        except yaml.YAMLError as exc:
            print(exc)


def pull_host_lists():
    for hlist in host_files:
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
            subprocess.call(['./cleanList.sh ' + hlist['file']], shell=True)
            print('Cleaned: ' + hlist['name'])
        except:
            print('Failed to download: ' + hlist['name'])
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
