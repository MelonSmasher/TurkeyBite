from libtb.util import dig


def normalize_host(value):
    """Lowercases a hostname field and drops surrounding dots.

    A query can arrive in FQDN form as 'www.example.com.', which should match
    the same ignore entries as 'www.example.com'. Returns None when the field
    is absent, empty or not a string.
    """
    if not isinstance(value, str):
        return None
    return value.strip().lower().strip('.') or None


# Browserbeat legitimately backfills years of history, so old timestamps are
# expected. But Chrome and Edge store visit times as microseconds since
# 1601-01-01, and a zero value decodes to exactly that instant. Those are not
# browse events, and they break date histograms: a histogram spanning 1601 to
# now tries to allocate millions of buckets and fails outright.
MIN_PLAUSIBLE_YEAR = 1990


def plausible_timestamp(value):
    """False only when the year is implausibly old.

    Returns True when the value cannot be judged, so an unexpected format is
    passed along rather than silently dropped.
    """
    if not isinstance(value, str) or len(value) < 4:
        return True
    try:
        return int(value[:4]) >= MIN_PLAUSIBLE_YEAR
    except ValueError:
        return True


def matches_domain(host, domain):
    """True when host is the domain itself or a subdomain of it.

    A bare endswith() also matches evil-example.com against example.com, and
    4.3.2.110.in-addr.arpa against 10.in-addr.arpa, because it does not
    require a label boundary.
    """
    return host == domain or host.endswith('.' + domain)


class Filters(object):
    # Packet types we care about
    packets = ['dns', 'browser.history']
    valids = ['OK']

    def __init__(self, config):
        """Sieve class responsible for filtering out messages that should be ignored.

        This lessens the load on the queue workers and makes ES lighter.
        """
        self.config = config
        # Hostnames from packets are normalized before comparison, so normalize
        # the configured entries the same way once at startup. Otherwise a
        # config entry of 'Example.com' or '.example.com' never matches.
        ignore = config.get('ignore') or {}
        self.ignore_domains = [d for d in
                               (normalize_host(v) for v in (ignore.get('domains') or []))
                               if d]
        self.ignore_hosts = [h for h in
                             (normalize_host(v) for v in (ignore.get('hosts') or []))
                             if h]
        # Same for the browserbeat lists. Client hostnames and usernames are
        # left as written, since usernames are not case-insensitive.
        browserbeat_ignore = dig(config, 'browserbeat', 'ignore') or {}
        self.browserbeat_ignore_domains = [d for d in
                                          (normalize_host(v) for v in
                                           (browserbeat_ignore.get('domains') or []))
                                          if d]
        self.browserbeat_ignore_hosts = [h for h in
                                         (normalize_host(v) for v in
                                          (browserbeat_ignore.get('hosts') or []))
                                         if h]

    # Packetbeat DNS filters
    def dns(self, data):
        # If we are filtering invalid packets
        if self.config['drop_error_packets']:
            # Is this status OK? A packet carrying no status at all cannot be
            # confirmed good, so it goes with the rest
            if data.get('status') not in self.valids:
                return False

        # For inbound requests
        if dig(data, 'client', 'ip') in self.config['ignore']['clients']:
            return False

        # For outbound requests
        if dig(data, 'destination', 'ip') in self.config['ignore']['clients']:
            return False
        if dig(data, 'network', 'direction') in ['outbound', 'egress']:
            if self.config['drop_replies']:
                return False

        # Do we have a registered domain key?
        registered_domain = normalize_host(dig(data, 'dns', 'question', 'registered_domain'))
        if registered_domain in self.ignore_domains:
            return False

        # Do we have a etld_plus_one key?
        etld_plus_one = normalize_host(dig(data, 'dns', 'question', 'etld_plus_one'))
        if etld_plus_one in self.ignore_domains:
            return False

        # Do we have a resource key?
        resource = normalize_host(data.get('resource'))
        if resource:
            if resource in self.ignore_hosts:
                return False
            for d in self.ignore_domains:
                if matches_domain(resource, d):
                    return False

        # Do we have a name key?
        name = normalize_host(dig(data, 'dns', 'question', 'name'))
        if name:
            if name in self.ignore_hosts:
                return False
            for d in self.ignore_domains:
                if matches_domain(name, d):
                    return False

        # If we made it here, we're good
        return True

    # Browserbeat filters
    def browserbeat(self, data):
        ignore_clients = self.config['browserbeat']['ignore']['clients']
        ignore_users = self.config['browserbeat']['ignore']['users']
        ignore_domains = self.browserbeat_ignore_domains
        ignore_hosts = self.browserbeat_ignore_hosts

        # Reject the 1601 sentinel, but keep genuine historical backfill
        if not plausible_timestamp(dig(data, 'data', '@timestamp')):
            return False

        # Dive down into the data structure. A history event without this
        # much structure carries no URL to look at, and would only fail later
        # in the worker, so drop it here.
        event_data = dig(data, 'data', 'event', 'data')
        if not isinstance(event_data, dict):
            return False

        # Client level rules
        client = dig(event_data, 'client')
        if isinstance(client, dict):
            # Filter ignored client hostnames
            hostnames = dig(client, 'Hostname')
            if isinstance(hostnames, dict):
                # Filter fqdn hostname
                hostname = hostnames.get('hostname')
                if hostname is not None and hostname in ignore_clients:
                    return False
                # Filter short hostname
                short_hostname = hostnames.get('short')
                if short_hostname is not None and short_hostname in ignore_clients:
                    return False

            # Filter ignored IPs
            ip_addresses = client.get('ip_addresses')
            if isinstance(ip_addresses, (list, tuple)):
                for ip in ip_addresses:
                    if ip in ignore_clients:
                        return False

            # Filter ignored users
            if 'user' in client.keys():
                if client['user'] in ignore_users:
                    return False

        # History entry level rules. Without a usable entry there is no URL to
        # look at, so drop the event rather than let the worker fail on it.
        entry = dig(event_data, 'entry')
        if not isinstance(entry, dict):
            return False

        url_data = dig(entry, 'url_data')
        if isinstance(url_data, dict):
            scheme = url_data.get('Scheme')
            if isinstance(scheme, str) and scheme.strip().lower() == 'file':
                return False
        # Skip file:// urls
        u = entry.get('url')
        if isinstance(u, str) and u.strip().lower().startswith('file://'):
            return False
        # Without a host there is nothing to look up. The worker would
        # only fail on the event or index an empty one, so drop it here.
        host = normalize_host(dig(entry, 'url_data', 'Host'))
        if host and ':' in host:
            # Deal with hosts that have a port in the string
            host = normalize_host(host.split(':')[0])
        if not host:
            return False
        # Should we ignore this host
        if host in ignore_hosts:
            return False
        # Deal with ignored domains. Matched on label boundaries, the same way
        # the DNS path does it, rather than by deriving a domain from the last
        # two labels and comparing that. The old form under-matched: an entry for
        # bbc.co.uk never fired, because the derived domain was co.uk.
        for d in ignore_domains:
            if matches_domain(host, d):
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
