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
    """Strips deliberately-wrong categories from the Valkey host list keyspace.

    Only meaningful for the modes that read that keyspace. In index mode the same
    corrections are applied by apply_ignorelist while the index is built, so there
    is nothing here to edit.
    """
    print('Processing ignorelist')
    if os.path.exists('lists/ignorelist.json'):
        config = read_config()
        if index_config(config)['mode'] not in VALKEY_BACKED_MODES:
            # Said plainly, because the alternative is a missing-tag complaint
            # every time the ignorelist loop runs, which reads like a fault
            print('Domain index mode is active, the index build applies the '
                  'ignorelist instead')
            return
        if not r:
            r = Redis(
                host=config['redis']['host'],
                port=config['redis']['port'],
                password=config['redis']['password'],
                db=config['redis']['host_list_db']
            )
            if not tag:
                tag = r.get('turkey-bite:current-tag')
                if tag is None:
                    # A return rather than exit(): this is library code and the
                    # caller decides what a missing tag means for it
                    print('No current tag found')
                    return
                tag = tag.decode('utf-8')
                    
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


def index_config(config=None):
    """Domain index settings, defaulted so an old config still works."""
    from libtb.index.builder import DEFAULT_PATH
    if config is None:
        config = read_config()
    settings = (config.get('processor') or {}).get('domain_index') or {}
    return {
        'mode': settings.get('mode', 'valkey'),
        'path': settings.get('path', DEFAULT_PATH),
        # Where a worker reads the index from
        'source': settings.get('source', 'file'),
        # Whether the librarian publishes it for remote workers. Separate from
        # `source` on purpose: on the node that runs the librarian, the local
        # worker reads the file directly while a worker on another host still
        # needs it published. Tying the two together would mean the natural
        # setting on that node silently starved every remote worker.
        'publish': bool(settings.get('publish', False)),
        'sync_interval_sec': int(settings.get('sync_interval_sec', 300)),
    }


def build_domain_index(path=None, publish_to_valkey=None):
    """Builds the domain index, and publishes it when the workers are remote.

    Kept separate from the Valkey list load so both can coexist while the index
    is on trial. Never raises: a failed index build must not fail a list pull
    that otherwise succeeded, because the Valkey path is still there.
    """
    from libtb.index.builder import apply_ignorelist, build, collect_entries
    from libtb.index import transport
    config = read_config()
    settings = index_config(config)
    target = path or settings['path']
    if publish_to_valkey is None:
        publish_to_valkey = settings['publish']
    # One generation number for the file, the manifest and the marker, so all
    # three agree and a mismatch anywhere is a real fault rather than clock skew
    built_at = int(time.time())
    try:
        print('Building domain index')
        entries, files, skipped = collect_entries('lists', exclude_path=target)
        # The curated corrections live outside the collector's glob, so they have
        # to be applied here or the index keeps categories marked as wrong
        ignored, dropped = apply_ignorelist(entries, 'lists')
        stats = build(entries, path=target, built_at=built_at)
        # A worker sharing this filesystem with the librarian already has the
        # file, so record the generation and save it a pointless 175 MB download
        with open(target + '.generation', 'w') as marker:
            marker.write(str(built_at))
        print('Built domain index generation ' + str(built_at) + ': '
              + str(stats['domains']) + ' domains from '
              + str(files) + ' files, ' + str(round(stats['bytes'] / 1e6, 1)) + ' MB, '
              + str(stats['attr_combinations']) + ' attribute combinations, '
              + str(skipped) + ' lines skipped, '
              + str(ignored) + ' categories removed by the ignorelist, '
              + str(dropped) + ' entries dropped')
    except Exception as e:
        print('Failed to build domain index: ' + str(e), file=sys.stderr)
        return None

    if publish_to_valkey:
        try:
            r = Redis(
                host=config['redis']['host'],
                port=config['redis']['port'],
                password=config['redis']['password'],
                db=config['redis']['host_list_db']
            )
            manifest = transport.publish(r, target, built_at)
            print('Published domain index generation ' + str(manifest['built_at'])
                  + ' as ' + str(manifest['chunks']) + ' chunks')
            stats['published'] = manifest
        except Exception as e:
            print('Failed to publish domain index: ' + str(e), file=sys.stderr)
    return stats


def sync_domain_index():
    """Downloads the published index if the local copy is not current.

    Runs in its own loop rather than in the event path. A worker that fetched
    lazily per job would have every concurrent job downloading the same 175 MB
    the moment a new generation appeared.
    """
    from libtb.index import transport
    config = read_config()
    settings = index_config(config)
    if settings['source'] != 'valkey':
        print('Domain index source is ' + settings['source'] + ', nothing to sync')
        return None
    r = Redis(
        host=config['redis']['host'],
        port=config['redis']['port'],
        password=config['redis']['password'],
        db=config['redis']['host_list_db']
    )
    try:
        manifest = transport.fetch_if_stale(r, settings['path'])
    except Exception as e:
        print('Failed to sync domain index: ' + str(e), file=sys.stderr)
        return None
    if manifest:
        print('Synced domain index generation ' + str(manifest['built_at'])
              + ', ' + str(round(manifest['bytes'] / 1e6, 1)) + ' MB')
    return manifest


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

# A key in the per-domain host list keyspace: turkey-bite:<unix tag>:<domain>.
# Anchored on a numeric tag so the index manifest and chunks, which live under
# turkey-bite:index:, can never be swept by mistake.
TAGGED_KEY = re.compile(r'^turkey-bite:\d+:')

# Lookup modes that read the tagged keyspace, so the librarian has to populate
# it. `compare` belongs here because Valkey stays authoritative in that mode;
# dropping it would make the comparison meaningless rather than merely slower.
VALKEY_BACKED_MODES = frozenset(('valkey', 'compare'))


def unlink_matching(r, match, batch=1000):
    """UNLINKs every key matching a glob, in batches. Returns the count.

    DEL blocks the server for the whole call, which matters when the pattern
    covers millions of keys, and one round trip per key makes the sweep the
    slowest part of a list pull.
    """
    removed = 0
    pending = 0
    pipe = r.pipeline(transaction=False)
    for raw in r.scan_iter(match=match, count=1000):
        pipe.unlink(raw)
        pending += 1
        if pending >= batch:
            pipe.execute()
            removed += pending
            pending = 0
            pipe = r.pipeline(transaction=False)
    if pending:
        pipe.execute()
        removed += pending
    return removed


def purge_tagged_keyspace(r, batch=1000):
    """Removes the per-domain host list keyspace and its tag bookkeeping.

    Returns the number of keys removed. UNLINK rather than DEL because this can
    be millions of keys and DEL would block the server for the whole sweep.

    SCAN while deleting is safe here: it may repeat or miss a key, a repeated
    UNLINK is a no-op, and anything missed is swept on the next run.
    """
    removed = 0
    pending = 0
    pipe = r.pipeline(transaction=False)
    for raw in r.scan_iter(match='turkey-bite:*', count=1000):
        name = raw.decode('utf-8') if isinstance(raw, bytes) else raw
        if not TAGGED_KEY.match(name):
            continue
        pipe.unlink(name)
        pending += 1
        if pending >= batch:
            pipe.execute()
            removed += pending
            pending = 0
            pipe = r.pipeline(transaction=False)
    if pending:
        pipe.execute()
        removed += pending
    # Without a current tag, valkey_contexts returns no contexts rather than
    # reading a keyspace that is no longer maintained
    for key in ('turkey-bite:tags', 'turkey-bite:current-tag', 'turkey-bite:old-tag'):
        r.unlink(key)
    return removed


def pull_psl():
    """Fetches the Public Suffix List, replacing the cached copy atomically.

    Fetched at runtime rather than bundled so a newly delegated suffix is picked
    up without a deploy. Every container fetches its own copy from the one URL
    the list asks to be pulled from, so nodes converge on the same content and
    no distribution is needed.

    Same shape as the TLD list fetch: download beside the cache, parse and sanity
    check, and only then move it into place. A truncated download or an error page
    parses into a handful of rules, and a short rule set produces quietly wrong
    registrable domains rather than obvious failures.

    Returns True when the cached copy was replaced.
    """
    from libtb.psl import DEFAULT_PATH, SOURCE_URL, parse, usable

    directory = os.path.dirname(DEFAULT_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    pending = DEFAULT_PATH + '.new'
    try:
        print('Downloading: public suffix list')
        opener = urllib.request.build_opener()
        opener.addheaders = [
            (
                'User-agent',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'
            )
        ]
        urllib.request.install_opener(opener)
        urllib.request.urlretrieve(SOURCE_URL, pending)
        with open(pending, encoding='utf-8', errors='replace') as handle:
            rules, wildcards, exceptions = parse(handle)
        if not usable(rules):
            raise ValueError(f'downloaded list looks wrong: {len(rules)} rules')
        os.replace(pending, DEFAULT_PATH)
        print('Downloaded: public suffix list (' + str(len(rules)) + ' rules, '
              + str(len(wildcards)) + ' wildcards, ' + str(len(exceptions))
              + ' exceptions)')
        return True
    except Exception as e:
        print('Failed to download: public suffix list')
        print(e)
        return False
    finally:
        if os.path.exists(pending):
            os.remove(pending)


def download_list(hlist, tlds):
    """Fetches and cleans one list, replacing the live copy only on success.

    Downloaded beside the live file and renamed into place. urlretrieve opens its
    destination for writing straight away, so writing directly to the live path
    meant a download that died part way through truncated a list that was working,
    and cleaning that remnant turned it into a short but valid-looking list. It
    also meant a concurrent index build could read a half-written file.

    A result that cleans to nothing is discarded rather than installed. An error
    page served with a 200 cleans to zero entries, and so does a truncated
    download; in both cases the copy already on disk is the better one.

    Returns True when the live file was replaced.
    """
    pending = hlist['file'] + '.new'
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
        urllib.request.urlretrieve(hlist['url'], pending)
        print('Downloaded: ' + hlist['name'])
        print('Cleaning: ' + hlist['name'])
        clean_list_file(pending, tlds)
        if os.path.getsize(pending) == 0:
            print('Discarded: ' + hlist['name'] + ' cleaned to no entries, '
                  'keeping the copy already on disk')
            return False
        os.replace(pending, hlist['file'])
        print('Cleaned: ' + hlist['name'])
        return True
    except Exception as e:
        print('Failed to download: ' + hlist['name'])
        print(e)
        return False
    finally:
        # os.replace consumed it on the success path, so this only fires when
        # something went wrong and would otherwise leave a stray .new behind
        if os.path.exists(pending):
            os.remove(pending)


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
        download_list(hlist, tlds)

    config = read_config()
    r = Redis(
        host=config['redis']['host'],
        port=config['redis']['port'],
        password=config['redis']['password'],
        db=config['redis']['host_list_db']
    )

    # valkey_contexts is the only reader of the tagged keyspace, and it answers
    # the `valkey` and `compare` modes. `compare` needs it because Valkey stays
    # authoritative there. `index` does not read it at all, so populating it
    # spends a GET and a SET per domain on data no query will ever touch.
    populate_valkey = index_config(config)['mode'] in VALKEY_BACKED_MODES

    if not populate_valkey:
        print('Domain index mode is active, skipping the Valkey host list')
        removed = purge_tagged_keyspace(r)
        if removed:
            print('Reclaimed ' + str(removed) + ' keys from the unused host list keyspace')
        build_domain_index()
        return

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
        unlink_matching(r, 'turkey-bite:' + old_tag + ':*')
        tags[old_tag] = 'purged'
        r.hmset('turkey-bite:tags', tags)
        print('Done purging previous data')
