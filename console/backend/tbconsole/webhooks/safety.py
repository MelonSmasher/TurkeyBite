"""Where a webhook may point.

A webhook makes the console send a request to a URL an admin chose, so
without a check an admin account, or a stolen admin session, could use it to
reach things only the console's own network can: a cloud metadata endpoint,
an internal admin page. Unless TBCONSOLE_WEBHOOK_ALLOW_PRIVATE is on, a URL
whose host resolves to a loopback, private, link-local, multicast or reserved
address is refused, both when it is saved and again before every delivery,
since what a name resolves to can change after it was checked.
"""

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from ..config import get_settings


class UnsafeUrl(ValueError):
    pass


# Never reachable, whatever the setting: the metadata services of the
# common clouds, which hand out credentials to anything that asks
_ALWAYS_BLOCKED = (ipaddress.ip_network('169.254.169.254/32'),
                   ipaddress.ip_network('fd00:ec2::254/128'),
                   ipaddress.ip_network('100.100.100.200/32'))


def _blocked(address: ipaddress._BaseAddress, allow_private: bool) -> bool:
    if any(address in net for net in _ALWAYS_BLOCKED):
        return True
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        return True
    if allow_private:
        return False
    return (address.is_private or address.is_loopback or address.is_link_local
            or getattr(address, 'is_site_local', False))


def check_shape(url: str) -> tuple[str, str, int]:
    """The scheme, host and port of an acceptable URL. Raises UnsafeUrl."""
    if len(url) > 2000:
        raise UnsafeUrl('The URL is too long.')
    parts = urlsplit(url.strip())
    if parts.scheme not in ('https', 'http'):
        raise UnsafeUrl('Use an http or https URL.')
    if parts.username or parts.password:
        raise UnsafeUrl('Put credentials in a header, not in the URL.')
    if not parts.hostname:
        raise UnsafeUrl('The URL has no host.')
    try:
        port = parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError as e:
        raise UnsafeUrl('The port is not a number.') from e
    return parts.scheme, parts.hostname, port


async def check(url: str) -> None:
    """Refuses a URL that is malformed or reaches somewhere it should not."""
    _, host, port = check_shape(url)
    allow_private = get_settings().webhook_allow_private
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise UnsafeUrl(f'{host} does not resolve.') from e
        addresses = [ipaddress.ip_address(info[4][0].split('%')[0]) for info in infos]
    for address in addresses:
        if _blocked(address, allow_private):
            hint = '' if allow_private else (' Set TBCONSOLE_WEBHOOK_ALLOW_PRIVATE=true to allow '
                                             'receivers on the local network.')
            raise UnsafeUrl(f'{host} resolves to {address}, which webhooks may not reach.{hint}')
