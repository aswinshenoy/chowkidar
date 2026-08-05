from __future__ import annotations

from typing import TYPE_CHECKING

from django.apps import apps
from django.conf import settings
from django.http import HttpRequest

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractUser

User = apps.get_model(settings.AUTH_USER_MODEL, require_ready=False)


def authenticate_with_username(
    password: str,
    username: str,
    request: HttpRequest | None = None,
) -> AbstractUser:
    """Authenticate a user by username and password via Django's auth backend.

    Parameters
    ----------
    password : str
        The plaintext password to verify.
    username : str
        The username to authenticate.
    request : HttpRequest | None, optional
        The current HTTP request, passed through to Django's ``authenticate()``,
        by default None.

    Returns
    -------
    User
        The authenticated Django user instance.

    Raises
    ------
    AuthError
        If credentials are invalid (code ``INVALID_CREDENTIALS``).

    """
    from django.contrib.auth import authenticate

    from chowkidar.utils.exceptions import AuthError

    user = authenticate(
        request=request,
        username=username,
        password=password,
    )

    if user is None:
        msg = "The username or password you entered is wrong"

        if username is None:
            msg = "The email or password you entered is wrong"

        raise AuthError(
            message=msg,
            code="INVALID_CREDENTIALS",
        )

    return user


def authenticate_with_email(
    password: str,
    email: str,
    request: HttpRequest | None = None,
) -> AbstractUser:
    """Authenticate a user by email and password.

    Parameters
    ----------
    password : str
        The plaintext password to verify.
    email : str
        The email address to look up.
    request : HttpRequest | None, optional
        The current HTTP request, by default None.

    Returns
    -------
    User
        The authenticated Django user instance.

    Raises
    ------
    AuthError
        If no account exists for the email (code ``EMAIL_NOT_FOUND``), or if
        multiple accounts share the email (code ``EMAIL_NOT_UNIQUE``).

    Notes
    -----
    - Performs a case-insensitive email lookup and delegates to
      ``authenticate_with_username`` for credential verification.

    """
    from chowkidar.utils import validate_email
    from chowkidar.utils.exceptions import AuthError

    try:
        username = User.objects.get(email__iexact=validate_email(email)).username

        return authenticate_with_username(
            password=password,
            username=username,
            request=request,
        )
    except User.DoesNotExist:
        raise AuthError(
            message="An account with this email address does not exist",
            code="EMAIL_NOT_FOUND",
        )
    except User.MultipleObjectsReturned:
        raise AuthError(
            message="We cannot authenticate you with your email address, please enter your username",
            code="EMAIL_NOT_UNIQUE",
        )


def authenticate(
    password: str,
    username: str | None = None,
    email: str | None = None,
    request: HttpRequest | None = None,
) -> AbstractUser:
    """Authenticate a user by email or username with the given password.

    Parameters
    ----------
    password : str
        The plaintext password to verify.
    username : str | None, optional
        The username to authenticate with, by default None.
    email : str | None, optional
        The email address to authenticate with, by default None.
    request : HttpRequest | None, optional
        The current HTTP request, by default None.

    Returns
    -------
    User
        The authenticated Django user instance.

    Raises
    ------
    AuthError
        If neither ``email`` nor ``username`` is provided (code ``EMAIL_USERNAME_MISSING``).

    Notes
    -----
    - When both ``email`` and ``username`` are provided, ``email`` takes precedence.

    """
    from chowkidar.utils.exceptions import AuthError

    if username is None and email is None:
        raise AuthError(
            message="Email or username is required for authentication",
            code="EMAIL_USERNAME_MISSING",
        )

    if email is not None:
        user = authenticate_with_email(
            email=email,
            password=password,
            request=request,
        )
    else:
        user = authenticate_with_username(
            username=username,
            password=password,
            request=request,
        )

    return user


__all__ = [
    "authenticate_with_username",
    "authenticate_with_email",
    "authenticate",
]
