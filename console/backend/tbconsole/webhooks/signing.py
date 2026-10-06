"""Webhook signatures, so a receiver can tell a delivery came from this console.

    X-TurkeyBite-Signature: t=1760000000,v1=<hex HMAC-SHA256>

The HMAC is over the timestamp, a full stop, and the exact body bytes, keyed
with the webhook's secret. A receiver recomputes it, compares in constant
time, and refuses a timestamp more than five minutes old, which stops a
captured delivery being replayed later.
"""

import hashlib
import hmac
import secrets
import time

HEADER = 'X-TurkeyBite-Signature'
TOLERANCE_SECONDS = 300


def new_secret() -> str:
    """A new signing secret for a webhook."""
    return 'whsec_' + secrets.token_urlsafe(32)


def sign(secret: str, body: bytes, timestamp: int | None = None) -> str:
    """The signature header's value for `body`, at `timestamp` or now."""
    timestamp = int(time.time()) if timestamp is None else timestamp
    digest = hmac.new(secret.encode('utf-8'), f'{timestamp}.'.encode('ascii') + body,
                      hashlib.sha256).hexdigest()
    return f't={timestamp},v1={digest}'


def verify(secret: str, body: bytes, header: str, now: int | None = None) -> bool:
    """What a receiver does; here for the tests and for the docs to quote.

    Anything malformed is simply not a valid signature.
    """
    try:
        parts = dict(item.split('=', 1) for item in header.split(','))
        timestamp = int(parts['t'])
        now = int(time.time()) if now is None else now
        if abs(now - timestamp) > TOLERANCE_SECONDS:
            return False
        expected = sign(secret, body, timestamp).split('v1=', 1)[1]
        return hmac.compare_digest(expected.encode('ascii'), str(parts.get('v1', '')).encode('utf-8'))
    except (ValueError, KeyError, TypeError, AttributeError):
        return False
