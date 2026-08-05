from __future__ import annotations

from typing import Any
from functools import wraps
from collections.abc import Callable

import strawberry
from django.apps import apps
from django.http import HttpRequest
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser


def issue_tokens_on_login(f: Callable) -> Callable:
    """Issue JWT auth tokens after a successful login resolver.

    Wrap this decorator around a login mutation resolver. The resolver must set
    ``info.context.LOGIN_USER`` to the authenticated ``User`` instance to trigger
    token issuance.

    Parameters
    ----------
    f : callable
        The Strawberry resolver function to wrap.

    Returns
    -------
    callable
        Wrapped resolver that creates a refresh token and sets login flags on
        the request context when ``info.context.LOGIN_USER`` is set.

    """

    def generate_refresh_token(
        userID: int,
        request: HttpRequest,
    ) -> AbstractBaseUser:
        """Create and persist a new refresh token for the given user.

        Parameters
        ----------
        userID : int
            The ID of the authenticated user for whom to create a refresh token.
        request : HttpRequest
            The incoming HTTP request object, which may be used to set additional
            attributes on the token before saving.

        Returns
        -------
        AbstractBaseUser
            The newly created refresh token instance.

        Notes
        -----
        - The token is saved to the database and can be used to issue new access tokens.
        - The token is associated with the user ID provided and may include additional
          request-specific information if needed.

        """
        from chowkidar.settings import REFRESH_TOKEN_MODEL

        RefreshToken = apps.get_model(REFRESH_TOKEN_MODEL, require_ready=False)

        token = RefreshToken(user_id=userID)
        token.process_request_before_save(request)
        token.save()
        return token

    @wraps(f)
    def wrapper(
        cls: type,
        info: strawberry.Info,
        *args: tuple,
        **kwargs: dict,
    ) -> Any:
        """Wrap the resolver to issue JWT tokens after successful login.

        Parameters
        ----------
        cls : type
            The class containing the resolver method.
        info : strawberry.Info
            The Strawberry resolver info object, which contains the request context.
        *args : tuple
            Additional positional arguments forwarded to the resolver.
        **kwargs : dict
            Additional keyword arguments forwarded to the resolver.

        Returns
        -------
        Any
            The result of the resolver if login is successful, otherwise the original resolver result.

        Notes
        -----
        - If ``info.context.LOGIN_USER`` is set to an authenticated user instance, the decorator
            generates a new refresh token for that user and sets ``ctx.PERFORM_LOGIN`` to ``True``.
        - The new refresh token is stored in ``ctx.NEW_REFRESH_TOKEN`` for later use in setting cookies in the response.

        """
        from chowkidar.utils import get_context

        result = f(
            cls,
            info,
            *args,
            **kwargs,
        )

        ctx = get_context(info)
        if hasattr(info.context, "LOGIN_USER") and info.context.LOGIN_USER:
            token = generate_refresh_token(info.context.LOGIN_USER.id, ctx)
            ctx.PERFORM_LOGIN = True
            ctx.NEW_REFRESH_TOKEN = token

        return result

    return wrapper


def revoke_tokens_on_logout(f: Callable) -> Callable:
    """Revoke JWT auth tokens after a successful logout resolver.

    Wrap this decorator around a logout mutation resolver. The resolver must set
    ``info.context.LOGOUT_USER`` to ``True`` to trigger token revocation.

    Parameters
    ----------
    f : Callable
        The Strawberry resolver function to wrap.

    Returns
    -------
    callable
        Wrapped resolver that revokes the active refresh token and sets logout
        flags on the request context when ``info.context.LOGOUT_USER`` is ``True``.

    """

    @wraps(f)
    def wrapper(
        cls: type,
        info: strawberry.Info,
        *args: tuple,
        **kwargs: dict,
    ) -> Any:
        """Wrap the resolver to revoke JWT tokens after successful logout.

        Parameters
        ----------
        cls : type
            The class containing the resolver method.
        info : strawberry.Info
            The Strawberry resolver info object, which contains the request context.
        *args : tuple
            Additional positional arguments forwarded to the resolver.
        **kwargs : dict
            Additional keyword arguments forwarded to the resolver.

        Returns
        -------
        Any
            The result of the resolver if logout is successful, otherwise the original resolver result.

        Notes
        -----
        - If ``info.context.LOGOUT_USER`` is set to ``True``, the decorator revokes the refresh token
            associated with the user ID and refresh token present in the context.
        - The decorator sets ``ctx.PERFORM_LOGOUT`` to ``True`` to indicate that logout actions
            should be performed in the response processing phase.

        """
        from chowkidar.utils import get_context
        from chowkidar.settings import REFRESH_TOKEN_MODEL

        result = f(
            cls,
            info,
            *args,
            **kwargs,
        )
        ctx = get_context(info)

        if hasattr(info.context, "LOGOUT_USER") and info.context.LOGOUT_USER:
            if info.context.userID and info.context.refreshToken:
                RefreshToken = apps.get_model(REFRESH_TOKEN_MODEL, require_ready=False)

                RefreshToken.objects.filter(
                    token=info.context.refreshToken,
                    user_id=info.context.userID,
                ).update(revoked=timezone.now())

            ctx.PERFORM_LOGOUT = True

        return result

    return wrapper


__all__ = [
    "issue_tokens_on_login",
    "revoke_tokens_on_logout",
]
