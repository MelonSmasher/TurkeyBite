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
        'categories': ['proxy'],
        'file': 'lists/proxy/blocklist-site-proxy',
        'name': 'proxy-blocklist-site-proxy'
    },
    {
        'url': 'https://blocklist.site/app/dl/porn',
        'categories': ['porn'],
        'file': 'lists/porn/blocklist-site-porn',
        'name': 'porn-blocklist-site-porn'
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
        'url': 'https://raw.githubusercontent.com/chadmayfield/pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list',
        'categories': ['porn'],
        'file': 'lists/porn/pi_blocklist_porn_top1m',
        'name': 'porn-pi_blocklist_porn_top1m'
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
        'categories': ['malvertising'],
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
        'url': 'https://blocklist.site/app/dl/crypto',
        'categories': ['malicious', 'mining'],
        'file': 'lists/mining/blocklist-site',
        'name': 'malicious-blocklist-site'
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
                            result = json.loads(result)
                            result['categories'] = result['categories'] + list(
                                set(hostlist['categories']) - set(result['categories']))
                            r.set(key, json.dumps({'name': line, 'categories': result['categories']}))
                            print('Updated ' + line + ' in host list cache.')
                        except TypeError as e:
                            try:
                                print(e)
                                result = json.loads(result.decode('utf-8'))
                                result['categories'] = result['categories'] + list(
                                    set(hostlist['categories']) - set(result['categories']))
                                r.set(key, json.dumps({'name': line, 'categories': result['categories']}))
                                print('Updated ' + line + ' in host list cache.')
                            except:
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
        tags[old_tag] = 'purging'
        r.hmset('turkey-bite:tags', tags)
        for key in r.scan_iter('turkey-bite:' + old_tag + ':*'):
            r.delete(key)
        tags[old_tag] = 'purged'
        r.hmset('turkey-bite:tags', tags)
