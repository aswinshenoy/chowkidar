from __future__ import annotations

from functools import wraps
from collections.abc import Callable

from django.http import HttpRequest
from django.http import HttpResponse
from django.http import JsonResponse


def auth_enabled_view(view_func: Callable) -> Callable:
    """Wrap a Django view to manage JWT auth cookies on the HTTP response.

    Reads custom request attributes set by ``JWTAuthExtension`` and the login/logout
    wrapper decorators, and sets or removes access/refresh token cookies accordingly.

    Parameters
    ----------
    view_func : callable
        The Django view function (typically ``GraphQLView.as_view(...)``).

    Returns
    -------
    callable
        Wrapped view that processes auth cookies after the response is prepared.

    Usage
    -----
    .. code-block:: python

        auth_enabled_view(
            GraphQLView.as_view(schema=schema),
        )

    """

    def set_refresh_token_cookie(
        request: HttpRequest,
        response: HttpResponse | JsonResponse,
    ) -> HttpResponse | JsonResponse:
        """Set the refresh token cookie on the response if a new token was issued.

        Parameters
        ----------
        request : HttpRequest
            The incoming HTTP request object, which may have a ``NEW_REFRESH_TOKEN``
            attribute set by the login wrapper decorator.
        response : HttpResponse | JsonResponse
            The outgoing HTTP response object to which the cookie will be attached.

        Returns
        -------
        HttpResponse | JsonResponse
            The response object with the refresh token cookie set if applicable.

        Notes
        -----
        - This function is called after the view has processed the request and prepared
          the response, allowing it to modify the response headers to include the
          refresh token cookie if a new token was generated during login.
        - The refresh token cookie is only set if the request has a ``NEW_REFRESH_TOKEN``
          attribute, which is typically set by the login wrapper decorator after a
          successful login mutation resolver.

        """
        from chowkidar.settings import JWT_REFRESH_TOKEN_COOKIE_NAME
        from chowkidar.utils.jwt import generate_token_from_claims
        from chowkidar.utils.cookie import set_cookie

        if hasattr(request, "NEW_REFRESH_TOKEN"):
            rt = request.NEW_REFRESH_TOKEN
            data = generate_token_from_claims(
                claims={"refreshToken": rt.get_token()},
                expiration_delta=rt.get_refresh_token_expiry_delta(),
            )
            response = set_cookie(
                name=JWT_REFRESH_TOKEN_COOKIE_NAME,
                value=data["token"],
                expires=data["payload"]["exp"],
                response=response,
            )

        return response

    def set_access_token_cookie(
        request: HttpRequest,
        response: HttpResponse | JsonResponse,
    ) -> HttpResponse | JsonResponse:
        """Set the access token cookie on the response if the token was refreshed.

        Parameters
        ----------
        request : HttpRequest
            The incoming HTTP request object, which may have a ``REFRESHED_ACCESS_TOKEN``
            attribute set by the JWT auth extension.
        response : HttpResponse | JsonResponse
            The outgoing HTTP response object to which the cookie will be attached.

        Returns
        -------
        HttpResponse | JsonResponse
            The response object with the access token cookie set if applicable.

        Notes
        -----
        - This function is called after the view has processed the request and prepared
          the response, allowing it to modify the response headers to include the
          access token cookie if the token was refreshed during request processing.
        - The access token cookie is only set if the request has a
            ``REFRESHED_ACCESS_TOKEN`` attribute, which is typically set by the JWT auth
            extension when a new access token is generated from a valid refresh token.

        """
        from chowkidar.settings import JWT_ACCESS_TOKEN_COOKIE_NAME
        from chowkidar.utils.cookie import set_cookie

        if hasattr(request, "REFRESHED_ACCESS_TOKEN"):
            data = request.REFRESHED_ACCESS_TOKEN
            response = set_cookie(
                name=JWT_ACCESS_TOKEN_COOKIE_NAME,
                value=data["token"],
                expires=data["payload"]["exp"],
                response=response,
            )

        return response

    def finish_response(
        request: HttpRequest,
        response: HttpResponse | JsonResponse,
    ) -> HttpResponse | JsonResponse:
        """Apply auth cookie mutations to the response after view processing.

        Parameters
        ----------
        request : HttpRequest
            The incoming HTTP request object, which may have custom attributes set by
            the JWT auth extension or login/logout wrapper decorators.
        response : HttpResponse | JsonResponse
            The outgoing HTTP response object to which cookies may be attached or removed.

        Returns
        -------
        HttpResponse | JsonResponse
            The response object with auth cookies set or removed based on request attributes.

        Notes
        -----
        - This function checks for the presence of ``PERFORM_LOGIN``, ``PERFORM_LOGOUT``, and ``REFRESHED_ACCESS_TOKEN``
            attributes on the request to determine whether to set or remove the corresponding auth cookies.
        - If ``PERFORM_LOGIN`` is present, it sets the refresh token cookie using the ``NEW_REFRESH_TOKEN`` attribute.
        - If ``PERFORM_LOGOUT`` is present, it removes both the refresh and access token cookies.
        - If ``REFRESHED_ACCESS_TOKEN`` is present, it sets the access token cookie with the new token data.

        """
        from chowkidar.settings import JWT_ACCESS_TOKEN_COOKIE_NAME
        from chowkidar.settings import JWT_REFRESH_TOKEN_COOKIE_NAME
        from chowkidar.utils.cookie import delete_cookie

        if hasattr(request, "PERFORM_LOGIN") or hasattr(request, "PERFORM_LOGOUT"):
            if hasattr(request, "PERFORM_LOGIN"):
                response = set_refresh_token_cookie(
                    request=request,
                    response=response,
                )
            else:
                response = delete_cookie(
                    response=response,
                    name=JWT_REFRESH_TOKEN_COOKIE_NAME,
                )
                response = delete_cookie(
                    response=response,
                    name=JWT_ACCESS_TOKEN_COOKIE_NAME,
                )
        elif hasattr(request, "REFRESHED_ACCESS_TOKEN"):
            response = set_access_token_cookie(
                request=request,
                response=response,
            )

        return response

    @wraps(view_func)
    def wrapped_view(
        request: HttpRequest,
        *args: tuple,
        **kwargs: dict,
    ) -> HttpResponse | JsonResponse:
        return finish_response(
            request,
            view_func(
                request,
                *args,
                **kwargs,
            ),
        )

    return wrapped_view


__all__ = ["auth_enabled_view"]
