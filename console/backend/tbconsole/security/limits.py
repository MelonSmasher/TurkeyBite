"""The brake on guessing passwords, in memory, in front of the per-account
lockout, which lives in the database and holds across replicas.

Failures are counted per address and username, so one person guessing cannot
lock out everyone who shares their address: a school behind one NAT, or
every user at once when a proxy's address is all the console sees. An address
trying many usernames is held back, past a looser limit, only on the usernames
it has already got wrong, so it cannot lock out the others either. A flood
is bounded by the work it can cause instead: each address has a few sign-ins
worked on at once, password checks and directory calls, and a queue behind
them, and past that is turned away at once (admitted); an IPv6 address by
its /56 here. So a flood from one address waits on itself, and every other
address is served as before; and once it stops, nothing it did lingers. One
account's password is checked once at a time, wherever the guesses come from. IPv6 addresses count by their /64,
since anyone with one has the whole network to rotate through. Names count
in the form directories compare them in, so width and case variants of one
name are one name here.
"""

import asyncio
import ipaddress
import time
import unicodedata
from collections import defaultdict, deque
from contextlib import asynccontextmanager

WINDOW = 300
PAIR_LIMIT = 10
ADDRESS_LIMIT = 100
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


def name(username: str) -> str:
    """A name as it is counted: NFKC, case folded, and never empty, so a blank
    one is not mistaken for the address's own count."""
    return unicodedata.normalize('NFKC', username or '').casefold().strip() or '\x00blank'


def limited(ip: str | None, username: str) -> bool:
    who = source(ip)
    pair = _recent((who, name(username)))
    if pair >= PAIR_LIMIT:
        return True
    # Never refuses a name this address has not got wrong
    return pair > 0 and _recent((who, '')) >= ADDRESS_LIMIT


def failed(ip: str | None, username: str) -> None:
    global _last_sweep
    now = time.monotonic()
    if len(_failures) > _MAX_TRACKED and now - _last_sweep > _SWEEP_EVERY:
        _last_sweep = now
        for key in list(_failures):
            _recent(key)
    who = source(ip)
    _failures[(who, name(username))].append(now)
    _failures[(who, '')].append(now)


# Sign-ins worked on at once per address, and how many more may wait. Those
# waiting hold nothing but their place: no database connection, no thread
IN_FLIGHT = 2
QUEUE = 64
# And per account, one password at a time, so guesses sent together are
# checked in turn, each seeing the lockout the one before may have set
NAME_QUEUE = 16


class Busy(Exception):
    """An address, or an account, with as many sign-ins under way and
    waiting as it may have."""


class _Gate:
    def __init__(self, turns: int):
        self.turns = asyncio.Semaphore(turns)
        self.holding = 0


_gates: dict[tuple[str, str], _Gate] = {}


@asynccontextmanager
async def _turn(key: tuple[str, str], turns: int, queue: int):
    gate = _gates.get(key)
    if gate is None:
        gate = _gates[key] = _Gate(turns)
    if gate.holding >= turns + queue:
        raise Busy(key[1])
    gate.holding += 1
    try:
        async with gate.turns:
            yield
    finally:
        gate.holding -= 1
        if not gate.holding and _gates.get(key) is gate:
            del _gates[key]


def gate_source(ip: str | None) -> str:
    """Whose turn a sign-in takes: the address, an IPv6 one by its /56, the
    least a site is given, so a host cannot rotate through its own /64s to
    take more turns."""
    who = source(ip)
    if ':' in who:
        return str(ipaddress.ip_network(who, strict=False).supernet(new_prefix=56))
    return who


@asynccontextmanager
async def admitted(ip: str | None, username: str | None = None):
    """A turn for one sign-in from this address, and for this account when
    it is named, or Busy at once."""
    async with _turn(('address', gate_source(ip)), IN_FLIGHT, QUEUE):
        if username is None:
            yield
        else:
            async with _turn(('name', name(username)), 1, NAME_QUEUE):
                yield
