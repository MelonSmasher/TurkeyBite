"""Single-tenant Microsoft Entra ID OpenID Connect helpers."""

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class EntraError(Exception):
    """A sign-in response or identity from Entra could not be trusted."""


class EntraUnavailable(EntraError):
    """The Entra identity service could not be reached."""


DEFAULTS = {
    'enabled': False,
    'tenant_id': '',
    'client_id': '',
    'client_secret_enc': '',
}


@dataclass(frozen=True)
class Config:
    """The provider credentials loaded from encrypted console settings."""

    tenant_id: str
    client_id: str
    client_secret: str
    redirect_uri: str


def _b64decode(value: str) -> bytes:
    """Decodes an unpadded base64url JWT segment strictly."""
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)


def _json_segment(value: str) -> dict:
    decoded = json.loads(_b64decode(value))
    if not isinstance(decoded, dict):
        raise ValueError('JWT segment is not an object')
    return decoded


def new_secret() -> str:
    """Creates an unguessable OIDC state, nonce, or PKCE verifier."""
    return secrets.token_urlsafe(48)


def pkce_challenge(verifier: str) -> str:
    """The S256 challenge for a PKCE verifier."""
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')


def authorization_url(config: Config, state: str, nonce: str, verifier: str) -> str:
    """Builds the fixed-tenant authorization URL with state, nonce, and PKCE."""
    endpoint = (f'https://login.microsoftonline.com/{config.tenant_id}'
                '/oauth2/v2.0/authorize')
    params = {
        'client_id': config.client_id,
        'response_type': 'code',
        'redirect_uri': config.redirect_uri,
        'response_mode': 'query',
        'scope': 'openid profile email',
        'state': state,
        'nonce': nonce,
        'code_challenge': pkce_challenge(verifier),
        'code_challenge_method': 'S256',
    }
    return f'{endpoint}?{urlencode(params)}'


async def exchange_code(config: Config, code: str, verifier: str) -> str:
    """Exchanges an authorization code for its ID token over verified TLS."""
    endpoint = (f'https://login.microsoftonline.com/{config.tenant_id}'
                '/oauth2/v2.0/token')
    data = {
        'client_id': config.client_id,
        'client_secret': config.client_secret,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': config.redirect_uri,
        'code_verifier': verifier,
        'scope': 'openid profile email',
    }
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.post(endpoint, data=data)
    except httpx.HTTPError as e:
        raise EntraUnavailable('The Microsoft sign-in service could not be reached.') from e
    if response.status_code >= 500:
        raise EntraUnavailable('The Microsoft sign-in service is unavailable.')
    if response.status_code != 200:
        raise EntraError('Microsoft did not accept the sign-in response.')
    try:
        result = response.json()
    except ValueError as e:
        raise EntraUnavailable('Microsoft returned an invalid sign-in response.') from e
    token = result.get('id_token') if isinstance(result, dict) else None
    if not isinstance(token, str) or not token or len(token) > 32_768:
        raise EntraError('Microsoft did not return an ID token.')
    return token


async def validate_id_token(config: Config, token: str, nonce: str) -> dict:
    """Verifies the Microsoft ID token signature, tenant, audience, expiry, and nonce."""
    try:
        header_text, claims_text, signature_text = token.split('.')
        header = _json_segment(header_text)
        claims = _json_segment(claims_text)
        signature = _b64decode(signature_text)
    except (ValueError, TypeError, json.JSONDecodeError) as e:
        raise EntraError('Microsoft returned a malformed ID token.') from e

    if header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str):
        raise EntraError('Microsoft returned an unsupported ID token.')

    issuer = f'https://login.microsoftonline.com/{config.tenant_id}/v2.0'
    metadata_url = (f'https://login.microsoftonline.com/{config.tenant_id}'
                    '/v2.0/.well-known/openid-configuration')
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            metadata_response = await client.get(metadata_url)
            if metadata_response.status_code >= 500:
                raise EntraUnavailable('The Microsoft sign-in service is unavailable.')
            metadata_response.raise_for_status()
            metadata = metadata_response.json()
            jwks_uri = metadata.get('jwks_uri') if isinstance(metadata, dict) else None
            if not isinstance(jwks_uri, str):
                raise EntraError('Microsoft returned invalid signing-key metadata.')
            parts = urlsplit(jwks_uri)
            if (metadata.get('issuer') != issuer or parts.scheme != 'https'
                    or parts.hostname != 'login.microsoftonline.com' or parts.username
                    or parts.password):
                raise EntraError('Microsoft returned invalid signing-key metadata.')
            keys_response = await client.get(jwks_uri)
            if keys_response.status_code >= 500:
                raise EntraUnavailable('The Microsoft sign-in service is unavailable.')
            keys_response.raise_for_status()
            jwks = keys_response.json()
    except EntraError:
        raise
    except (httpx.HTTPError, ValueError) as e:
        raise EntraUnavailable('Microsoft signing keys could not be retrieved.') from e

    keys = jwks.get('keys') if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise EntraError('Microsoft returned invalid signing keys.')
    key = next((item for item in keys
                if isinstance(item, dict) and item.get('kid') == header['kid']
                and item.get('kty') == 'RSA' and item.get('use', 'sig') == 'sig'), None)
    if key is None:
        raise EntraError('Microsoft signed the ID token with an unknown key.')
    try:
        public_key = rsa.RSAPublicNumbers(
            int.from_bytes(_b64decode(key['e']), 'big'),
            int.from_bytes(_b64decode(key['n']), 'big'),
        ).public_key()
        public_key.verify(signature, f'{header_text}.{claims_text}'.encode('ascii'),
                          padding.PKCS1v15(), hashes.SHA256())
    except (KeyError, TypeError, ValueError, InvalidSignature) as e:
        raise EntraError('Microsoft ID token signature is invalid.') from e

    moment = time.time()
    audience = claims.get('aud')
    audiences = audience if isinstance(audience, list) else [audience]
    if (claims.get('iss') != issuer or config.client_id not in audiences
            or claims.get('tid') != config.tenant_id
            or not isinstance(claims.get('oid'), str)
            or not hmac.compare_digest(str(claims.get('nonce', '')), nonce)
            or not isinstance(claims.get('exp'), (int, float)) or claims['exp'] <= moment
            or (claims.get('nbf') is not None
                and (not isinstance(claims['nbf'], (int, float)) or claims['nbf'] > moment + 60))
            or (claims.get('iat') is not None
                and (not isinstance(claims['iat'], (int, float)) or claims['iat'] > moment + 60))):
        raise EntraError('Microsoft ID token claims did not match this sign-in.')
    try:
        if str(uuid.UUID(claims['oid'])) != claims['oid'].lower():
            raise ValueError('non-canonical object id')
    except ValueError as e:
        raise EntraError('Microsoft ID token object ID is invalid.') from e
    return claims
