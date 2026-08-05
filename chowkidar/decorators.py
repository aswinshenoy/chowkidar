from __future__ import annotations

from typing import Any
from functools import wraps

import strawberry
from django.apps import apps
from django.conf import settings


def login_required(resolver):
    """Restrict a Strawberry resolver to authenticated users only.

    Parameters
    ----------
    resolver : callable
        The Strawberry resolver function to wrap.

    Returns
    -------
    callable
        Wrapped resolver that returns ``None`` when ``info.context.userID`` is absent.

    Notes
    -----
    - Does not hit the database; checks ``info.context.userID`` which is set by
      ``JWTAuthExtension``.
    - Prefer this over ``@resolve_user`` when the ``User`` model instance is not needed.

    """

    @wraps(resolver)
    def wrapper(
        parent: Any,
        info: strawberry.Info,
        *args: tuple,
        **kwargs: dict,
    ) -> Any:
        """Wrap the resolver to check for ``info.context.userID`` before proceeding.

        Parameters
        ----------
        parent : Any
            The parent resolved value.
        info : strawberry.Info
            The Strawberry resolver info object.
        *args : tuple
            Additional positional arguments.
        **kwargs : dict
            Additional keyword arguments forwarded to the resolver.


        Returns
        -------
        Any
            The result of the resolver if the user is authenticated, otherwise ``None``.

        Notes
        -----
        - If ``info.context.userID`` is not set, the resolver is not called and ``None`` is returned.
        - This decorator does not raise an exception for unauthenticated users; it simply prevents the resolver from executing.

        """
        userID = getattr(
            info.context,
            "userID",
            None,
        )
        if userID:
            return resolver(
                parent,
                info,
                *args,
                **kwargs,
            )

        return None

    return wrapper


def resolve_user(resolver):
    """Resolve the requesting user's ``User`` instance and attach it to ``info.context.user``.

    Parameters
    ----------
    resolver : callable
        The Strawberry resolver function to wrap.

    Returns
    -------
    callable
        Wrapped resolver that sets ``info.context.user`` to the ``User`` instance,
        or returns ``None`` if the user is not logged in or does not exist.

    Notes
    -----
    - Hits the database to fetch the ``User`` instance; use ``@login_required`` instead
      when only ``info.context.userID`` is needed.
    - Internally applies ``@login_required``, so unauthenticated requests are rejected
      before the database query.

    """

    @wraps(resolver)
    @login_required
    def wrapper(
        parent: Any,
        info: strawberry.Info,
        *args: tuple,
        **kwargs: dict,
    ) -> Any:
        """Wrap the resolver to fetch and attach the ``User`` instance.

        Parameters
        ----------
        parent : Any
            The parent resolved value.
        info : strawberry.Info
            The Strawberry resolver info object.
        *args : tuple
            Additional positional arguments.
        **kwargs : dict
            Additional keyword arguments forwarded to the resolver.

        Returns
        -------
        Any
            The result of the resolver if the user is authenticated, otherwise ``None``.

        Notes
        -----
        - If the user does not exist in the database, returns ``None`` instead of raising an exception.
        - The ``User`` model is dynamically retrieved using the ``AUTH_USER_MODEL`` setting.

        """
        User = apps.get_model(settings.AUTH_USER_MODEL, require_ready=False)

        try:
            info.context.user = User.objects.get(id=info.context.userID)
        except User.DoesNotExist:
            return None

        return resolver(
            parent,
            info,
            *args,
            **kwargs,
        )

    return wrapper


__all__ = [
    "resolve_user",
    "login_required",
]
