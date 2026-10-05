"""Time-based one-time passwords for local accounts.

Local accounts are the way in when the directory is down, which makes them
the accounts most worth protecting: a break-glass admin with a password
alone is one phished password from everything. A second factor is optional
per account and can be required for admins in settings.
"""

import time

import pyotp

ISSUER = 'TurkeyBite Console'
STEP = 30


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def verify(secret: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """The time step `code` is valid for, or None.

    One step either side of now is accepted, for clocks a little apart. A
    step at or before `last_step` is refused, so an observed code cannot be
    replayed within its window.
    """
    code = ''.join(ch for ch in code if ch.isdigit())
    if len(code) != 6:
        return None
    now = time.time() if now is None else now
    totp = pyotp.TOTP(secret)
    current = int(now // STEP)
    for step in (current, current - 1, current + 1):
        if last_step is not None and step <= last_step:
            continue
        if pyotp.utils.strings_equal(totp.at(step * STEP), code):
            return step
    return None
