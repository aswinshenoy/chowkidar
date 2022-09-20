import jwt
from django.utils.timezone import datetime, timedelta
from typing import Dict, Any

from ..settings import (
    JWT_ISSUER,
    JWT_ALGORITHM,
    JWT_PRIVATE_KEY,
    JWT_SECRET_KEY,
    JWT_PUBLIC_KEY,
    JWT_LEEWAY,
)

from .exceptions import AuthError


def encode_payload(payload: object) -> str:
    return jwt.encode(
        payload=payload,
        # private key or secret key
        key=JWT_PRIVATE_KEY or JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decodes a JWT token string, with verification and returns the payload.

    :param token: JWT token passed as string
    :return: JWT payload as dictionary
    """
    return jwt.decode(
        jwt=token,
        # public key or secret key
        key=JWT_PUBLIC_KEY or JWT_SECRET_KEY,
        verify=True,
        algorithms=[JWT_ALGORITHM],
        # time margin in seconds for the expiration check
        leeyway=JWT_LEEWAY,
        options={
            "require_iat": True,
            "require_exp": True,
            "verify_iat": True,
            "verify_exp": True,
        },
        issuer=JWT_ISSUER,
    )


def generate_token_from_claims(claims: dict, expiration_delta: timedelta) -> object:
    """
    Generate a JWT token with claims and expiration delta passed

    :param claims: dictionary containing claims/data to be embedded inside the token
    :param expiration_delta: timedelta object representing duration after issue time when the token should expire
    :return: an object containing 'token' as str, and payload as dict
    """
    now = datetime.utcnow()
    payload = dict()
    payload.update(claims)
    registered_claims = {
        # issued at
        "iat": now,
        # expiration time of the token
        "exp": now + expiration_delta,
    }
    if JWT_ISSUER is not None:
        registered_claims["iss"] = JWT_ISSUER
    payload.update(registered_claims)
    return {
        "token": encode_payload(payload),
        "payload": payload
    }


def decode_payload_from_token(token: str) -> Dict[str, Any]:
    """
    Decode the passed JWT token, verify it and get the payload data inside it

    :param token: JWT token string
    :return: payload inside the JWT token as a dictionary
    """
    try:
        return decode_token(token)
    except jwt.ExpiredSignatureError:
        raise AuthError('JWT Token expired', code="EXPIRED_TOKEN")
    except jwt.InvalidTokenError:
        raise AuthError('Invalid authentication token', code="INVALID_TOKEN")


__all__ = [
    "generate_token_from_claims",
    "decode_payload_from_token"
]
