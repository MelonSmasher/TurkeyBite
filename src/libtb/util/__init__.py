import sys
import yaml
import urllib.request
import re
import os
from redis import Redis
import json
import time


def dig(data, *keys):
    """Walks nested dict keys.

    Returns None as soon as a level is missing or is not a dict, so a
    malformed packet yields None instead of raising.
    """
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def get_host_files():
    host_files = []
    if os.path.exists('lists/host_files.json'):
        with open('lists/host_files.json', 'r') as json_file:
            host_files = json.load(json_file)
    else:
        with open('lists/host_files.example.json', 'r') as json_file:
            host_files = json.load(json_file)
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
                
            # Initialize sieve section if needed
            if 'sieve' not in conf:
                conf['sieve'] = {}
                
            # Initialize browserbeat configuration if needed
            if 'browserbeat' not in conf['sieve']:
                conf['sieve']['browserbeat'] = {}
                
            if 'ignore' not in conf['sieve']['browserbeat']:
                conf['sieve']['browserbeat']['ignore'] = {}
                
            # Ensure all browserbeat ignore lists are initialized
            browserbeat_ignore_lists = ['clients', 'users', 'domains', 'hosts']
            for list_name in browserbeat_ignore_lists:
                if list_name not in conf['sieve']['browserbeat']['ignore'] or conf['sieve']['browserbeat']['ignore'][list_name] is None:
                    conf['sieve']['browserbeat']['ignore'][list_name] = []
            
            # Initialize general sieve ignore section
            if 'ignore' not in conf['sieve']:
                conf['sieve']['ignore'] = {}
                
            # Ensure all general sieve ignore lists are initialized
            sieve_ignore_lists = ['domains', 'clients', 'hosts']
            for list_name in sieve_ignore_lists:
                if list_name not in conf['sieve']['ignore'] or conf['sieve']['ignore'][list_name] is None:
                    conf['sieve']['ignore'][list_name] = []
                    
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
                try:
                    tag = r.get('turkey-bite:current-tag').decode('utf-8')
                except AttributeError:
                    print('No current tag found')
                    exit()
                    
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

def read_tld_file(path):
    """Reads a TLD list file into a list of lowercased suffixes."""
    tlds = []
    with open(path, 'r') as tld_file:
        for line in tld_file:
            if line.startswith('#'):
                continue
            tld = line.strip().lower()
            if tld:
                tlds.append(tld)
    return tlds


def usable_tld_list(tlds):
    """Sanity check on a downloaded TLD list.

    A truncated file or an HTML error page will parse without raising and then
    silently reject every domain in every list, so check that the result looks
    like the IANA file before trusting it.
    """
    return len(tlds) > 1000 and 'com' in tlds and 'org' in tlds


def build_domain_index(path=None):
    """Builds the memory-mapped domain index from the cleaned list files.

    Kept separate from the Valkey load so both can coexist while the index is
    on trial. Never raises: a failed index build must not fail a list pull that
    otherwise succeeded, because the Valkey path is still there.
    """
    from libtb.index.builder import build, collect_entries, DEFAULT_PATH
    target = path or DEFAULT_PATH
    try:
        print('Building domain index')
        entries, files = collect_entries('lists')
        stats = build(entries, path=target)
        print('Built domain index: ' + str(stats['domains']) + ' domains from '
              + str(files) + ' files, ' + str(round(stats['bytes'] / 1e6, 1)) + ' MB, '
              + str(stats['attr_combinations']) + ' attribute combinations')
        return stats
    except Exception as e:
        print('Failed to build domain index: ' + str(e), file=sys.stderr)
        return None


def pull_tld_list():
    file = 'lists/tld/tld.txt'
    fallback = 'lists/tld/fallback.txt'
    # Download beside the cached copy and only move it into place once it has
    # been read and sanity checked. The previous version deleted the cache
    # before downloading, so one failed fetch lost it permanently and every
    # later run silently fell back to the ageing bundled list.
    pending = file + '.new'
    try:
        print('Downloading: TLD list')
        opener = urllib.request.build_opener()
        opener.addheaders = [
            (
                'User-agent',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'
            )
        ]
        urllib.request.install_opener(opener)
        urllib.request.urlretrieve('https://data.iana.org/TLD/tlds-alpha-by-domain.txt', pending)
        tlds = read_tld_file(pending)
        if not usable_tld_list(tlds):
            raise ValueError(f'downloaded TLD list looks wrong: {len(tlds)} entries')
        os.replace(pending, file)
        print('Downloaded: TLD list (' + str(len(tlds)) + ' entries)')
        return tlds
    except Exception as e:
        print('Failed to download: TLD list')
        print(e)
        if os.path.exists(pending):
            os.remove(pending)

    if os.path.exists(file):
        tlds = read_tld_file(file)
        if usable_tld_list(tlds):
            print('Using the previously cached TLD list (' + str(len(tlds)) + ' entries)')
            return tlds
        print('Cached TLD list looks wrong, ignoring it')

    print('Using fallback TLD list')
    return read_tld_file(fallback)
    
# Hosts-file lines put an address, then whitespace, then the domain.
# The trailing \s+ is required: without it these patterns match the leading
# hex-looking characters of a bare domain and eat its first label, turning
# facebook.com into ook.com.
IPV4_PREFIX = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\s+')
IPV6_PREFIX = re.compile(r'^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){1,7}(?:%\w+)?\s+')
# Adblock address markers, '||domain^' and '|domain^'.
ADBLOCK_PREFIX = re.compile(r'^\|\|?')
# A trailing comment introduced by '#' or '!' after whitespace.
TRAILING_COMMENT = re.compile(r'\s+[#!]')
# A DNS label: alphanumeric ends, hyphens allowed only in the middle.
LABEL = r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?'
# Either a '*.' wildcard of the kind the lookup keys use, so '*.gov' counts,
# or a plain domain of two labels or more.
VALID_HOST = re.compile(
    r'^(?:\*\.' + LABEL + r'(?:\.' + LABEL + r')*'
    r'|' + LABEL + r'(?:\.' + LABEL + r')+)$'
)


def clean_list_file(file_path: str, tlds: list[str]):
    # Keys of a dict, so duplicate entries collapse and order is kept
    hosts = {}
    # Read the file
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Process the file
    for line in lines:
        line = line.strip().lower()
        if not line:
            continue
        # Skip comments and adblock metadata such as '[Adblock Plus 2.0]'
        if line[0] in ('#', '!', '['):
            continue
        # An adblock '@@' rule means do not match this domain, so drop the
        # line rather than strip the marker and add the domain
        if line.startswith('@@'):
            continue
        # Cut a trailing comment off the end of the entry
        line = TRAILING_COMMENT.split(line, maxsplit=1)[0]
        # Drop a leading address, hosts-file style
        line = IPV4_PREFIX.sub('', line)
        line = IPV6_PREFIX.sub('', line)
        # Drop adblock markers and anything the '^' separator introduces,
        # e.g. '||example.com^$third-party'
        line = ADBLOCK_PREFIX.sub('', line)
        line = line.split('^')[0]
        # Some lists put several domains on one line, take the first
        fields = line.split()
        if not fields:
            continue
        # Drop the leading dot of '.example.com' and the root dot of an FQDN
        host = fields[0].strip('.')
        if not host:
            continue

        # Validate the entry
        # Skip anything missing a period before paying for the regex
        if '.' not in host:
            continue
        # Ensure the entry is a well formed domain
        if not VALID_HOST.match(host):
            continue
        # Check the entry against the TLD list
        if host.split('.')[-1] not in tlds:
            continue
        hosts[host] = None

    with open(file_path, 'w') as file:
        for host in hosts:
            file.write(host + '\n')

def pull_host_lists():
    host_files = get_host_files()
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
                'categories': [folder],
                'file': 'lists/' + folder + '/turkeybite',
                'name': folder
            })
        # This allows for custom lists and categories to be added to the host_files list
        if os.path.exists('lists/' + folder + '/custom'):
            host_files.append({
                'url': None,
                'categories': [folder],
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

    build_domain_index()

    if old_tag:
        print('Purging previous data')
        tags[old_tag] = 'purging'
        r.hmset('turkey-bite:tags', tags)
        for key in r.scan_iter('turkey-bite:' + old_tag + ':*'):
            r.delete(key)
        tags[old_tag] = 'purged'
        r.hmset('turkey-bite:tags', tags)
        print('Done purging previous data')
