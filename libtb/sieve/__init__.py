class Filters(object):
    # Packet types we care about
    packets = ['dns']
    valids = ['OK']

    def __init__(self, config):
        self.config = config

    def dns(self, data):
        # If we are filtering invalid packets
        if self.config['drop_error_packets']:
            # Is this status OK?
            if data['status'] not in self.valids:
                return False

        # For inbound requests
        if data['network']['direction'] == 'inbound':
            if data['client']['ip'] in self.config['ignore']['clients']:
                return False

        # For outbound requests
        if data['network']['direction'] == 'outbound':
            if self.config['drop_replies']:
                return False
            if data['destination']['ip'] in self.config['ignore']['clients']:
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
                    else:
                        return False
        return False
