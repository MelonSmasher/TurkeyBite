"""Encryption for secrets the console must be able to read back.

Passwords and API keys are hashed, never encrypted, since nothing needs them
back. A webhook's signing secret, its custom headers and the LDAP bind
password are different: the console has to send them. They are encrypted
with a key derived from TBCONSOLE_SECRET_KEY, so a copy of the database alone
does not give them away. Keys in TBCONSOLE_SECRET_KEY_PREVIOUS still decrypt,
so the key can be rotated by re-saving what was encrypted under the old one.
"""

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..config import get_settings


class SecretUnreadable(Exception):
    """A stored secret was encrypted under a key the console no longer has."""


def _derive(secret: str, purpose: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b'tbconsole/v1',
                info=purpose).derive(secret.encode('utf-8'))


def _fernet() -> MultiFernet:
    settings = get_settings()
    keys = [settings.secret_key, *settings.secret_key_previous]
    return MultiFernet([Fernet(base64.urlsafe_b64encode(_derive(key, b'fernet')))
                        for key in keys])


def encrypt(plaintext: str) -> str:
    """`plaintext` encrypted under the current secret key, as text to store."""
    return _fernet().encrypt(plaintext.encode('utf-8')).decode('ascii')


def decrypt(token: str) -> str:
    """What `encrypt` stored, under the current or a previous key; raises SecretUnreadable otherwise."""
    try:
        return _fernet().decrypt(token.encode('ascii')).decode('utf-8')
    except InvalidToken as e:
        raise SecretUnreadable('a stored secret cannot be decrypted with the configured '
                               'TBCONSOLE_SECRET_KEY; save it again') from e


def mac(purpose: str, message: bytes) -> bytes:
    """An HMAC under a key derived for one purpose, so no two uses share a key."""
    key = _derive(get_settings().secret_key, b'hmac:' + purpose.encode('utf-8'))
    return hmac.new(key, message, hashlib.sha256).digest()


def sha256(value: str | bytes) -> bytes:
    """The SHA-256 digest of `value`, text taken as UTF-8."""
    if isinstance(value, str):
        value = value.encode('utf-8')
    return hashlib.sha256(value).digest()
