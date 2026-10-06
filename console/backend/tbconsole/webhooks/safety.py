"""Where a webhook may point, and connecting only to where it was checked.

A webhook makes the console send a request to a URL an admin chose, so
without a check an admin account, or a stolen admin session, could use it to
reach what only the console's network can: a cloud metadata endpoint, an
internal admin page. Unless TBCONSOLE_WEBHOOK_ALLOW_PRIVATE is on, a URL whose
host resolves to a loopback, private, shared, link-local, multicast or
reserved address is refused. Link-local addresses, which is where cloud
metadata services live, are refused whatever the setting.

Checking a name and then letting the HTTP client resolve it again would let
a name that answers differently a moment later (DNS rebinding) through, so
`resolve` returns the address it checked and delivery connects to exactly
that address, sending the original name as the Host header and as the TLS
server name, so certificates are still verified against the name.

IPv4 addresses written inside IPv6 ones (::ffff:a.b.c.d, 6to4, NAT64) are
unwrapped before they are judged.
"""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from ..config import get_settings


class UnsafeUrl(ValueError):
    pass


_ALWAYS_BLOCKED = tuple(ipaddress.ip_network(n) for n in (
    '169.254.0.0/16',      # link-local: AWS, GCP and Azure metadata, ECS task metadata
    'fe80::/10',           # IPv6 link-local
    'fd00:ec2::254/128',   # AWS metadata over IPv6
    '100.100.100.200/32',  # Alibaba Cloud metadata
    '0.0.0.0/8',
))
_NAT64 = ipaddress.ip_network('64:ff9b::/96')
_SHARED = ipaddress.ip_network('100.64.0.0/10')


def _unwrap(address: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped:
            return address.ipv4_mapped
        if address.sixtofour:
            return address.sixtofour
        if address in _NAT64:
            return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return address


def _blocked(address: ipaddress._BaseAddress, allow_private: bool) -> bool:
    address = _unwrap(address)
    if any(address in net for net in _ALWAYS_BLOCKED if net.version == address.version):
        return True
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        return True
    if allow_private:
        return False
    return (address.is_private or address.is_loopback or address.is_link_local
            or getattr(address, 'is_site_local', False)
            or (address.version == 4 and address in _SHARED))


def check_shape(url: str) -> tuple[str, str, int]:
    """The scheme, host and port of an acceptable URL. Raises UnsafeUrl."""
    if len(url) > 2000:
        raise UnsafeUrl('The URL is too long.')
    if not url.isascii() or any(ord(ch) < 33 or ord(ch) == 127 for ch in url):
        raise UnsafeUrl('The URL may only hold printable ASCII; write an international name in punycode.')
    parts = urlsplit(url.strip())
    if parts.scheme not in ('https', 'http'):
        raise UnsafeUrl('Use an http or https URL.')
    if parts.username or parts.password:
        raise UnsafeUrl('Put credentials in a header, not in the URL.')
    if not parts.hostname:
        raise UnsafeUrl('The URL has no host.')
    try:
        port = parts.port
    except ValueError as e:
        raise UnsafeUrl('The port is not a number.') from e
    if port == 0:
        raise UnsafeUrl('Port 0 is not a port anything listens on.')
    port = port or (443 if parts.scheme == 'https' else 80)
    return parts.scheme, parts.hostname, port


@dataclass
class Target:
    """A checked URL, and how to connect to each address that was checked."""
    url: str
    host: str
    host_header: str
    pinned_url: str
    address: str
    tls: bool
    addresses: list[str] = field(default_factory=list)
    scheme: str = 'https'
    port: int = 443
    path: str = '/'
    query: str = ''

    def url_for(self, address: str) -> str:
        """The URL that connects to `address`, one of those checked."""
        literal = f'[{address}]' if ':' in address else address
        default = 443 if self.scheme == 'https' else 80
        netloc = literal if self.port == default else f'{literal}:{self.port}'
        return urlunsplit((self.scheme, netloc, self.path, self.query, ''))


async def resolve(url: str) -> Target:
    """Checks a URL and picks the address delivery will connect to. Raises UnsafeUrl."""
    scheme, host, port = check_shape(url)
    settings = get_settings()
    allow_private = settings.webhook_allow_private
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            if not settings.webhook_proxy:
                raise UnsafeUrl(f'{host} does not resolve.') from e
            # Through a proxy, a name only the proxy can resolve is the
            # proxy's to reach, by its own rules; one that does resolve here
            # is still checked below
            infos = []
        addresses = [ipaddress.ip_address(info[4][0].split('%')[0]) for info in infos]
    if not addresses and not settings.webhook_proxy:
        raise UnsafeUrl(f'{host} does not resolve.')
    # Every address the name has must be acceptable, not just the first,
    # or a name with one public and one private address would get through
    for address in addresses:
        if _blocked(address, allow_private):
            hint = '' if allow_private else (' Set TBCONSOLE_WEBHOOK_ALLOW_PRIVATE=true to allow '
                                             'receivers on the local network.')
            raise UnsafeUrl(f'{host} resolves to {address}, which webhooks may not reach.{hint}')
    parts = urlsplit(url.strip())
    default = 443 if scheme == 'https' else 80
    # An IPv6 literal goes in the Host header in brackets, as in the URL
    named = f'[{host}]' if ':' in host else host
    host_header = named if port == default else f'{named}:{port}'
    unique = list(dict.fromkeys(str(a) for a in addresses))
    target = Target(url=url, host=host, host_header=host_header, pinned_url='',
                    address=unique[0] if unique else '', tls=scheme == 'https', addresses=unique,
                    scheme=scheme, port=port, path=parts.path or '/', query=parts.query)
    target.pinned_url = target.url_for(unique[0]) if unique else url
    return target


async def check(url: str) -> None:
    """Refuses a URL that is malformed or reaches somewhere it should not."""
    await resolve(url)
