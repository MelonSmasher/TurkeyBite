"""What an event keeps of the URLs it carries, and whether it keeps the raw packet.

A browser history event stored the page's full URL twice, in bite.url and in
the raw Browserbeat packet, which also breaks it into parts under url_data. A
full URL says far more than where someone went: the search terms in a query
string, session tokens, password reset links, email addresses, and now and
then a user name and password before the host. None of it is needed to
categorise a visit, which is decided by the host alone.

processor.privacy.urls governs every URL an event stores, in bite and in the
packet alike:

    full     as the browser recorded it, which is what events held before
    trimmed  scheme, host, port and path: the query string, the fragment and
             any user:password@ are dropped. The default.
    host     scheme, host and port only

processor.privacy.packet is `keep`, the default, or `none`, which leaves the
raw packet off the event entirely. The packet holds everything the beat sent,
including the page title, which is not a URL and is kept by `trimmed`, and
which for a search results page is usually the search.

A string counts as a URL when it starts, after any leading whitespace, with an
http or https scheme in any case, or with any other scheme followed by //.
Wrapper schemes such as view-source: and blob: may come first. Trimming fails
closed: whatever follows the scheme is cut at the first ? or #, whatever
precedes the last @ of the authority is dropped, and whitespace anywhere in the
string changes none of that, so a URL with a space, a tab or a no-break space in
it cannot slip through whole. A string that does not start that way is left
exactly as it is, including a sentence that mentions a URL part way through.
Browserbeat's url_data is Go's net/url.URL, which it serialises field by field,
so there the same parts are blanked in the form Go gives a URL without them:
RawQuery, Fragment and RawFragment empty, ForceQuery false and User null.

Where to look depends on the event. A browser history event is URLs throughout,
so all of it is searched. A DNS event has none in its own fields: the only
strings in it that can be a URL are the data of its resource records, where a
TXT record may carry one, so only those are looked at rather than every string
in every lookup. An event of any other type is searched in full.

Unknown keys or values stop the worker at start, like the evidence settings,
so a typo cannot quietly leave full URLs on every event.
"""

import re
from collections import namedtuple

FULL, TRIMMED, HOST = 'full', 'trimmed', 'host'
URL_MODES = (FULL, TRIMMED, HOST)
KEEP, NONE = 'keep', 'none'
PACKET_MODES = (KEEP, NONE)

Settings = namedtuple('Settings', 'urls packet')
DEFAULT = Settings(TRIMMED, KEEP)

# The start of a URL. Leading whitespace is any Unicode whitespace, plus the
# invisible format characters copying and pasting brings along. Then any
# wrapper schemes, such as view-source: or blob:, kept as they are, and either
# http or https in any case, with or without slashes, or another scheme that is
# followed by // or by the backslashes browsers read as slashes.
_URL_START = re.compile(
    r'[\s\u200b\u200c\u200d\u2060\ufeff]*'
    r'(?P<scheme>(?:[A-Za-z][A-Za-z0-9+.\-]*:)*?'
    r'(?:https?:|[A-Za-z][A-Za-z0-9+.\-]*:(?=[/\\]{2})))'
    r'(?P<slashes>[/\\]*)',
    re.IGNORECASE)

# url_data fields, blanked to what Go's url.URL holds when the URL has no such part
_TRIMMED_FIELDS = (('User', None), ('RawQuery', ''), ('ForceQuery', False),
                   ('Fragment', ''), ('RawFragment', ''))
_HOST_FIELDS = _TRIMMED_FIELDS + (('Path', ''), ('RawPath', ''), ('Opaque', ''))


def _choice(value, name, allowed):
    if isinstance(value, bool):
        # YAML reads an unquoted no, off or false as False
        raise ValueError(f'processor.privacy.{name} must be one of {", ".join(allowed)}, '
                         f'not {value!r}; YAML reads an unquoted no or off as false')
    if value not in allowed:
        raise ValueError(f'processor.privacy.{name} must be one of {", ".join(allowed)}, '
                         f'not {value!r}')
    return value


def settings(value=None):
    """processor.privacy as Settings, checked. Absent means DEFAULT.

    Raises ValueError for an unknown key or value, so the worker stops at
    start rather than storing more than the operator meant it to.
    """
    value = {} if value is None else value
    if not isinstance(value, dict):
        raise ValueError(f'processor.privacy must be a mapping, not {value!r}')
    unknown = sorted(set(map(str, value)) - {'urls', 'packet'})
    if unknown:
        raise ValueError(f'processor.privacy has unknown keys {", ".join(unknown)}; '
                         f'it takes urls and packet')
    return Settings(_choice(value.get('urls', DEFAULT.urls), 'urls', URL_MODES),
                    _choice(value.get('packet', DEFAULT.packet), 'packet', PACKET_MODES))


def trim_url(value, mode):
    """A URL with the parts `mode` drops taken out. Anything else unchanged.

    Fails closed: a string that starts as a URL is always cut, whatever else
    is in it, so whitespace, a malformed host or an unclosed IPv6 bracket
    cannot leave it whole. That is why this is done by hand: urllib raises on
    some malformed URLs, and a regular expression for a whole URL fails to
    match on others. The authority ends at the first /, ?, # or backslash, as
    browsers read it, the user:password@ ends at its last @, and the path ends
    at the first ? or #. Leading and trailing whitespace is dropped.
    """
    if mode == FULL or not isinstance(value, str):
        return value
    match = _URL_START.match(value)
    if not match:
        return value
    rest = value[match.end():]
    end = len(rest)
    for mark in '/\\?#':
        at = rest.find(mark)
        if at != -1:
            end = min(end, at)
    start = match.group('scheme') + match.group('slashes')
    host = rest[:end].rpartition('@')[2]
    if mode == HOST:
        return (start + host).rstrip()
    path = re.split(r'[?#]', rest[end:], maxsplit=1)[0]
    return (start + host + path).rstrip()


def _url_struct(value):
    """True for a dict shaped like Browserbeat's url_data, Go's url.URL."""
    return 'Scheme' in value and 'Host' in value


def scrub(value, mode):
    """`value` with every URL in it trimmed to `mode`, as a new structure.

    Walks dicts and lists, so the URL is found wherever the beat put it.
    The input is not modified.
    """
    if mode == FULL:
        return value
    if isinstance(value, str):
        return trim_url(value, mode)
    if isinstance(value, list):
        return [scrub(item, mode) for item in value]
    if isinstance(value, dict):
        out = {key: scrub(item, mode) for key, item in value.items()}
        if _url_struct(value):
            for field, blank in (_HOST_FIELDS if mode == HOST else _TRIMMED_FIELDS):
                if field in out:
                    out[field] = blank
        return out
    return value


# Where a DNS event can hold a URL: the data of its resource records, since a
# TXT record may carry one. Packetbeat writes nothing else that can.
DNS_RECORD_SECTIONS = ('answers', 'authorities', 'additionals')


def _dns_packet(packet, mode):
    """A Packetbeat DNS event with the URLs in its resource records trimmed.

    Copies only the dicts and lists on the way to a record, so the rest of the
    event is shared with the input rather than rebuilt.
    """
    dns = packet.get('dns')
    if not isinstance(dns, dict):
        return packet
    changed = {}
    for section in DNS_RECORD_SECTIONS:
        records = dns.get(section)
        if not isinstance(records, list):
            continue
        trimmed = []
        for record in records:
            if isinstance(record, dict) and isinstance(record.get('data'), str):
                data = trim_url(record['data'], mode)
                if data != record['data']:
                    record = dict(record, data=data)
            trimmed.append(record)
        if any(a is not b for a, b in zip(trimmed, records)):
            changed[section] = trimmed
    if not changed:
        return packet
    return dict(packet, dns=dict(dns, **changed))


def redact_packet(packet, mode):
    """A beat event with every URL it can hold trimmed to `mode`.

    The one decision about where to look, see the module docstring, shared by
    the worker and by the inlet, which trims an event before it is queued.
    """
    if mode == FULL or not isinstance(packet, dict):
        return packet
    if packet.get('type') == 'dns':
        return _dns_packet(packet, mode)
    return scrub(packet, mode)


def redact(document, privacy):
    """The document an event ships, with the privacy settings applied.

    With urls full and the packet kept this is the document itself, exactly
    as before these settings existed. A DNS event's own fields hold names and
    addresses and never a URL, so only its packet is looked at; any other
    event is searched in full.
    """
    if privacy.packet == NONE and 'packet' in document:
        document = {key: value for key, value in document.items() if key != 'packet'}
    if privacy.urls == FULL:
        return document
    bite = document.get('bite')
    if isinstance(bite, dict) and bite.get('type') == 'dns':
        if 'packet' in document:
            document = dict(document, packet=redact_packet(document['packet'], privacy.urls))
        return document
    return scrub(document, privacy.urls)
