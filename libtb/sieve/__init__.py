class Filters(object):
    # Packet types we care about
    packets = ['dns', 'browser.history']
    valids = ['OK']

    def __init__(self, config):
        self.config = config

    # Packetbeat DNS filters
    def dns(self, data):
        # If we are filtering invalid packets
        if self.config['drop_error_packets']:
            # Is this status OK?
            if data['status'] not in self.valids:
                return False

        # For inbound requests
        if 'client' in data.keys():
            if 'ip' in data['client'].keys():
                if data['client']['ip'] in self.config['ignore']['clients']:
                    return False

        # For outbound requests
        if 'destination' in data.keys():
            if 'ip' in data['destination']:
                if data['destination']['ip'] in self.config['ignore']['clients']:
                    return False
        if 'network' in data.keys():
            if 'direction' in data['network'].keys():
                if data['network']['direction'] == 'outbound':
                    if self.config['drop_replies']:
                        return False

        # Do we have a registered domain key?
        if 'registered_domain' in data['dns']['question'].keys():
            if data['dns']['question']['registered_domain'].strip().lower() in self.config['ignore']['domains']:
                return False

        # Do we have a etld_plus_one key?
        if 'etld_plus_one' in data['dns']['question'].keys():
            if data['dns']['question']['etld_plus_one'].strip().lower() in self.config['ignore']['domains']:
                return False

        # Do we have a name key?
        if 'resource' in data.keys():
            if data['resource'].strip().lower() in self.config['ignore']['hosts']:
                return False
            for d in self.config['ignore']['domains']:
                if data['resource'].strip().lower().endswith(d):
                    return False

        # Do we have a name key?
        if 'name' in data['dns']['question'].keys():
            if data['dns']['question']['name'].strip().lower() in self.config['ignore']['hosts']:
                return False
            for d in self.config['ignore']['domains']:
                if data['dns']['question']['name'].strip().lower().endswith(d):
                    return False

        # If we made it here, we're good
        return True

    # Browserbeat filters
    def browserbeat(self, data):
        ignore_clients = self.config['browserbeat']['ignore']['clients']
        ignore_users = self.config['browserbeat']['ignore']['users']
        ignore_doamins = self.config['browserbeat']['ignore']['domains']
        ignore_hosts = self.config['browserbeat']['ignore']['hosts']

        # Dive down into the data structure
        if 'data' in data.keys():
            print(data)


            if 'event' in data['data'].keys():
                if 'data' in data['data']['event'].keys():

                    # Client level rules
                    if 'client' in data['data']['event']['data'].keys():

                        # Filter ignored client hostnames
                        if 'Hostname' in data['data']['event']['data']['client'].keys():
                            # Filter fqdn hostname
                            if 'hostname' in data['data']['event']['data']['client']['Hostname'].keys():
                                if data['data']['event']['data']['client']['Hostname']['hostname'] in ignore_clients:
                                    return False
                            # Filter short hostname
                            if 'short' in data['data']['event']['data']['client']['Hostname'].keys():
                                if data['data']['event']['data']['client']['Hostname']['short'] in ignore_clients:
                                    return False

                        # Filter ignored IPs
                        if 'ip_addresses' in data['data']['event']['data']['client'].keys():
                            for ip in data['data']['event']['data']['client']['ip_addresses']:
                                if ip in ignore_clients:
                                    return False

                        # Filter ignored users
                        if 'user' in data['data']['event']['data']['client'].keys():
                            if data['data']['event']['data']['client']['user'] in ignore_users:
                                return False

                    # History entry level rules
                    if 'entry' in data['data']['event']['data'].keys():
                        if 'url_data' in data['data']['event']['data']['entry'].keys():
                            if 'Host' in data['data']['event']['data']['entry']['url_data'].keys():
                                host = data['data']['event']['data']['entry']['url_data']['Host']
                                if host:
                                    if ':' in host:
                                        # Deal with hosts that have a port in the string
                                        host = host.split(':')[0]
                                    # Should we ignore this host
                                    if host in ignore_hosts:
                                        return False
                                    # Deal with ignored domains
                                    domain = host
                                    if '.' in host:
                                        parts = host.split('.')
                                        domain = '.'.join([parts[len(parts - 2)], parts[len(parts - 1)]])
                                    if domain in ignore_doamins:
                                        return False

        else:
            # If we get here we aren't user how to process this
            return False

        # If we made it here, we're good
        return True

    def should_process(self, data):
        # Ensure that the data is now a dict
        if isinstance(data, dict):
            # If `type` is a key in the dict
            if 'type' in data.keys():
                # Is this packet one of the types we can process?
                if data['type'] in self.packets:
                    # different filters for different packet types
                    if data['type'] == 'dns':
                        return self.dns(data)
                    elif data['type'] == 'browser.history':
                        return self.browserbeat(data)
                    else:
                        return False
        # If we made it here, we don't want this packet
        return False
