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

A string counts as a URL only when the whole of it is one: a scheme, ://, and
no whitespace, as browsers record them. A sentence that happens to contain a
URL is left as it is, as is any other string, so trimming can only ever remove
the parts of a URL named above. Browserbeat's url_data is Go's net/url.URL,
which it serialises field by field, so there the same parts are blanked in the
form Go gives a URL without them: RawQuery, Fragment and RawFragment empty,
ForceQuery false and User null.

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

# One or more schemes, as RFC 3986 spells them, then //. More than one allows
# for wrappers such as view-source:https:// and blob:https://, which are kept as
# they are while the URL they wrap is trimmed.
_URL = re.compile(r'((?:[A-Za-z][A-Za-z0-9+.\-]*:)+//)(\S*)')

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

    Done by hand rather than with urllib, which raises on some malformed URLs,
    such as an unclosed IPv6 bracket, and would leave them whole. Here the
    authority ends at the first /, ? or #, as RFC 3986 has it, so a malformed
    host still loses its query.
    """
    if mode == FULL or not isinstance(value, str):
        return value
    match = _URL.fullmatch(value.strip())
    if not match:
        return value
    schemes, rest = match.groups()
    end = len(rest)
    for mark in '/?#':
        at = rest.find(mark)
        if at != -1:
            end = min(end, at)
    # user:password@ ends at the last @ before the host
    host = rest[:end].rpartition('@')[2]
    if mode == HOST:
        return schemes + host
    path = re.split(r'[?#]', rest[end:], maxsplit=1)[0]
    return schemes + host + path


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


def redact(document, privacy):
    """The document an event ships, with the privacy settings applied.

    With urls full and the packet kept this is the document itself, exactly
    as before these settings existed.
    """
    if privacy.packet == NONE and 'packet' in document:
        document = {key: value for key, value in document.items() if key != 'packet'}
    return scrub(document, privacy.urls)
