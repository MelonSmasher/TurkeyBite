"""Local account passwords: Argon2id hashes and the rules a new one must meet."""

import asyncio
import weakref

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()

MIN_LENGTH = 12
MAX_LENGTH = 512

# A hash to verify against when the account does not exist, so a missing
# account takes as long to refuse as a wrong password and the timing does
# not say which usernames are real
_DUMMY = _hasher.hash('not a password anyone has, used only for timing')


def hash_password(password: str) -> str:
    """An Argon2id hash of `password`, to store."""
    return _hasher.hash(password)


def verify_password(stored: str | None, password: str) -> bool:
    """Whether `password` matches the stored hash; with none stored it is checked anyway, for the timing, and fails."""
    try:
        return _hasher.verify(stored or _DUMMY, password) and stored is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# Argon2 is meant to be slow; a few at a time, off the event loop, so a burst
# of sign-ins waits its turn rather than stalls every other request
_TURNS: 'weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore]' = weakref.WeakKeyDictionary()


def _turn() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    turn = _TURNS.get(loop)
    if turn is None:
        turn = _TURNS[loop] = asyncio.Semaphore(4)
    return turn


async def verify_async(stored: str | None, password: str) -> bool:
    """verify_password, off the event loop and a few at a time."""
    async with _turn():
        return await asyncio.to_thread(verify_password, stored, password)


async def hash_async(password: str) -> str:
    """hash_password, off the event loop and a few at a time."""
    async with _turn():
        return await asyncio.to_thread(hash_password, password)


def needs_rehash(stored: str) -> bool:
    """Whether a stored hash was made with older settings, or is not one this hasher reads."""
    try:
        return _hasher.check_needs_rehash(stored)
    except InvalidHashError:
        return True


def password_problems(password: str, username: str = '') -> list[str]:
    """What is wrong with a proposed password, in words for the person choosing it."""
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f'Use at least {MIN_LENGTH} characters.')
    if len(password) > MAX_LENGTH:
        problems.append(f'Use at most {MAX_LENGTH} characters.')
    if password.strip() != password:
        problems.append('Leave out spaces at the start and end.')
    if username and username.lower() in password.lower():
        problems.append('Do not include the username.')
    if len(set(password)) < 5:
        problems.append('Use more different characters.')
    return problems
