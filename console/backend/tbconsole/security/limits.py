"""The brake on guessing passwords, in memory, in front of the per-account
lockout, which lives in the database and holds across replicas.

Failures are counted per address and username, so one person guessing cannot
lock out everyone who shares their address: a school behind one NAT, or
every user at once when a proxy's address is all the console sees. An address
trying many usernames is held back, past a looser limit, only on the usernames
it has already got wrong, so it cannot lock out the others either, and past a
much higher one on everything, as a brake on a flood. IPv6 addresses count
by their /64, since anyone with one has the whole network to rotate through.
"""

import ipaddress
import time
from collections import defaultdict, deque

WINDOW = 300
PAIR_LIMIT = 10
ADDRESS_LIMIT = 100
FLOOD_LIMIT = 1000
_MAX_TRACKED = 20000
_SWEEP_EVERY = 30.0

_failures: dict[tuple[str, str], deque] = defaultdict(deque)
_last_sweep = 0.0


def reset() -> None:
    _failures.clear()


def source(ip: str | None) -> str:
    """Who is counted: the address, an IPv6 one by its /64, or one bucket for
    every request whose address could not be read."""
    if not ip:
        return 'unknown'
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return 'unknown'
    if address.version == 6:
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f'{address}/64', strict=False))
    return str(address)


def _recent(key: tuple[str, str]) -> int:
    window = _failures.get(key)
    if not window:
        return 0
    cutoff = time.monotonic() - WINDOW
    while window and window[0] < cutoff:
        window.popleft()
    if not window:
        del _failures[key]
    return len(window)


def limited(ip: str | None, username: str) -> bool:
    who = source(ip)
    pair = _recent((who, username.lower()))
    if pair >= PAIR_LIMIT:
        return True
    from_address = _recent((who, ''))
    return (from_address >= ADDRESS_LIMIT and pair > 0) or from_address >= FLOOD_LIMIT


def failed(ip: str | None, username: str) -> None:
    global _last_sweep
    now = time.monotonic()
    if len(_failures) > _MAX_TRACKED and now - _last_sweep > _SWEEP_EVERY:
        _last_sweep = now
        for key in list(_failures):
            _recent(key)
    who = source(ip)
    _failures[(who, username.lower())].append(now)
    _failures[(who, '')].append(now)
