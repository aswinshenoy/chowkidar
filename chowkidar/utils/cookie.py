from __future__ import annotations

from datetime import datetime

from django.http import HttpResponse
from django.http import JsonResponse


def set_cookie(
    name: str,
    value: str,
    response: HttpResponse | JsonResponse,
    expires: datetime,
) -> HttpResponse | JsonResponse:
    """Set an HTTP cookie on the response with the configured security attributes.

    Parameters
    ----------
    name : str
        Name of the cookie.
    value : str
        Value to store in the cookie.
    response : HttpResponse | JsonResponse
        The HTTP response object to attach the cookie to.
    expires : datetime
        Expiry timestamp for the cookie.

    Returns
    -------
    HttpResponse | JsonResponse
        The response object with the cookie set.

    Notes
    -----
    - Cookie attributes (``secure``, ``httponly``, ``samesite``, ``domain``) are read
      from ``chowkidar.settings`` at call time.

    """
    from chowkidar.settings import JWT_COOKIE_DOMAIN
    from chowkidar.settings import JWT_COOKIE_SECURE
    from chowkidar.settings import JWT_COOKIE_HTTP_ONLY
    from chowkidar.settings import JWT_COOKIE_SAME_SITE

    response.set_cookie(
        key=name,
        value=value,
        secure=JWT_COOKIE_SECURE,
        httponly=JWT_COOKIE_HTTP_ONLY,
        expires=expires,
        samesite=JWT_COOKIE_SAME_SITE,
        domain=JWT_COOKIE_DOMAIN,
    )
    return response


def delete_cookie(
    name: str,
    response: HttpResponse | JsonResponse,
) -> HttpResponse | JsonResponse:
    """Delete a cookie from the response.

    Parameters
    ----------
    name : str
        Name of the cookie to delete.
    response : HttpResponse | JsonResponse
        The HTTP response object from which the cookie is removed.

    Returns
    -------
    HttpResponse | JsonResponse
        The response object with the cookie deleted.

    """
    response.delete_cookie(key=name)
    return response


__all__ = [
    "set_cookie",
    "delete_cookie",
]
