"""API keys: tbc_<prefix>_<secret>.

The prefix finds the row and is safe to show; the secret is 32 random bytes
and is shown once, when the key is made. Only its SHA-256 is stored. A slow
hash such as Argon2 buys nothing for 256 bits of randomness, and every API
call has to check one.
"""

import base64
import hmac
import secrets

from .crypto import sha256

KEY_PREFIX = 'tbc_'


def generate() -> tuple[str, str, bytes]:
    """A new key as (full key, prefix, hash of the full key)."""
    prefix = base64.b32encode(secrets.token_bytes(5)).decode('ascii').lower().rstrip('=')
    secret = secrets.token_urlsafe(32)
    key = f'{KEY_PREFIX}{prefix}_{secret}'
    return key, prefix, sha256(key)


def parse(key: str) -> str | None:
    """The prefix of something shaped like a key, or None."""
    if not key.startswith(KEY_PREFIX):
        return None
    rest = key[len(KEY_PREFIX):]
    prefix, sep, secret = rest.partition('_')
    if not sep or len(prefix) != 8 or len(secret) < 32:
        return None
    return prefix


def matches(key: str, stored_hash: bytes) -> bool:
    """Whether `key` is the key whose hash was stored, compared in constant time."""
    return hmac.compare_digest(sha256(key), stored_hash)
