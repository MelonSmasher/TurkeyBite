import yaml
import urllib.request
import re
import os
from redis import Redis
import json
import time


def get_host_files():
    # get the current directory of this library file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    with open(current_dir + '/host_files.json', 'r') as json_file:
        return json.load(json_file)


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

    if old_tag:
        print('Purging previous data')
        tags[old_tag] = 'purging'
        r.hmset('turkey-bite:tags', tags)
        for key in r.scan_iter('turkey-bite:' + old_tag + ':*'):
            r.delete(key)
        tags[old_tag] = 'purged'
        r.hmset('turkey-bite:tags', tags)
        print('Done purging previous data')
