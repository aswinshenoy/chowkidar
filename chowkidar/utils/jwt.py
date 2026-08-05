from __future__ import annotations

from typing import Any
from datetime import timedelta

import jwt
from django.utils import timezone


def encode_payload(payload: object) -> str:
    """Encode a payload dict into a signed JWT string.

    Parameters
    ----------
    payload : object
        Dictionary of claims to encode into the token.

    Returns
    -------
    str
        The encoded JWT token string.

    Notes
    -----
    - Uses ``JWT_PRIVATE_KEY`` if set, otherwise falls back to ``JWT_SECRET_KEY``.

    """
    from chowkidar.settings import JWT_ALGORITHM
    from chowkidar.settings import JWT_SECRET_KEY
    from chowkidar.settings import JWT_PRIVATE_KEY

    return jwt.encode(
        payload=payload,
        key=JWT_PRIVATE_KEY or JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT token string, returning the payload.

    Parameters
    ----------
    token : str
        The JWT token string to decode.

    Returns
    -------
    dict[str, Any]
        The decoded JWT payload as a dictionary.

    Raises
    ------
    jwt.ExpiredSignatureError
        If the token has expired beyond the configured leeway.
    jwt.InvalidTokenError
        If the token is malformed or fails signature verification.

    Notes
    -----
    - Uses ``JWT_PUBLIC_KEY`` if set, otherwise falls back to ``JWT_SECRET_KEY``.
    - Requires and verifies ``iat`` and ``exp`` claims.

    """
    from chowkidar.settings import JWT_ISSUER
    from chowkidar.settings import JWT_LEEWAY
    from chowkidar.settings import JWT_ALGORITHM
    from chowkidar.settings import JWT_PUBLIC_KEY
    from chowkidar.settings import JWT_SECRET_KEY

    return jwt.decode(
        jwt=token,
        key=JWT_PUBLIC_KEY or JWT_SECRET_KEY,
        algorithms=[JWT_ALGORITHM],
        leeway=JWT_LEEWAY,
        options={
            "require_iat": True,
            "require_exp": True,
            "verify_iat": True,
            "verify_exp": True,
            "verify_signature": True,
        },
        issuer=JWT_ISSUER,
    )


def generate_token_from_claims(
    claims: dict,
    expiration_delta: timedelta,
) -> object:
    """Generate a signed JWT token from the given claims and expiration delta.

    Parameters
    ----------
    claims : dict
        Dictionary of custom claims to embed in the token payload.
    expiration_delta : timedelta
        Duration after issue time when the token should expire.

    Returns
    -------
    dict
        Dictionary with ``token`` (the encoded JWT string) and ``payload``
        (the full claims dict including ``iat``, ``exp``, and optionally ``iss``).

    """
    from chowkidar.settings import JWT_ISSUER

    now = timezone.now()
    payload = dict()
    payload.update(claims)
    registered_claims = {
        "iat": now,
        "exp": now + expiration_delta,
    }

    if JWT_ISSUER is not None:
        registered_claims["iss"] = JWT_ISSUER

    payload.update(registered_claims)
    return {
        "token": encode_payload(payload),
        "payload": payload,
    }


def decode_payload_from_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT token, translating library exceptions into AuthError.

    Parameters
    ----------
    token : str
        The JWT token string to decode.

    Returns
    -------
    dict[str, Any]
        The decoded payload as a dictionary.

    Raises
    ------
    AuthError
        If the token is expired (code ``EXPIRED_TOKEN``) or invalid (code ``INVALID_TOKEN``).

    """
    from chowkidar.utils.exceptions import AuthError

    try:
        return decode_token(token)
    except jwt.ExpiredSignatureError:
        raise AuthError(
            message="JWT Token expired",
            code="EXPIRED_TOKEN",
        )
    except jwt.InvalidTokenError:
        raise AuthError(
            message="Invalid authentication token",
            code="INVALID_TOKEN",
        )


__all__ = [
    "generate_token_from_claims",
    "decode_payload_from_token",
]
