from datetime import datetime
from django.http import HttpResponse, JsonResponse


def set_cookie(
    name: str,
    value: str,
    response: (HttpResponse or JsonResponse),
    expires: datetime,
) -> (HttpResponse or JsonResponse):
    """
        Sets a cookie through HTTP Response

        :param name: name of the cookie
        :param value: value to be stored in the cookie
        :param response: HTTP response object
        :param expires: expiry time of the cookie
    """
    from ..settings import (
        JWT_COOKIE_SAME_SITE,
        JWT_COOKIE_SECURE,
        JWT_COOKIE_HTTP_ONLY,
        JWT_COOKIE_DOMAIN,
    )

    response.set_cookie(
        key=name,
        value=value,
        # if enabled, cookie is sent only when request is made via https
        secure=JWT_COOKIE_SECURE,
        # prevents client-side JS from accessing cookie
        httponly=JWT_COOKIE_HTTP_ONLY,
        # expire time of cookie
        expires=expires,
        # same site disable
        samesite=JWT_COOKIE_SAME_SITE,
        # cookie domain
        domain=JWT_COOKIE_DOMAIN,
    )
    return response


def delete_cookie(
    name: str,
    response: (HttpResponse or JsonResponse),
) -> (HttpResponse or JsonResponse):
    """
        Deletes a cookie through HTTP Response

        :param name: name of the cookie
        :param response: HTTP response object
    """
    response.delete_cookie(key=name)
    return response


__all__ = [
    "set_cookie",
    "delete_cookie"
]
