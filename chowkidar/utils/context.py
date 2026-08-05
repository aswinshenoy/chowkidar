from __future__ import annotations

from typing import Any

from graphql import GraphQLResolveInfo
from django.http import HttpRequest
from strawberry.types import Info
from strawberry.django.context import StrawberryDjangoContext


def get_context(info: HttpRequest | Info[Any, Any] | GraphQLResolveInfo) -> Any:
    """Get the request context from the provided info object.

    Parameters
    ----------
    info : HttpRequest | Info[Any, Any] | GraphQLResolveInfo
        The info object from which to extract the request context.

    Returns
    -------
    Any
        The request context, which can be an HttpRequest or a StrawberryDjangoContext.

    Raises
    ------
    TypeError
        If the provided info object is not of a recognized type.

    Notes
    -----
    - If the info object is an instance of HttpRequest, it is returned directly.
    - If the info object is an instance of Info, its context attribute is checked.
      - If the context is an instance of StrawberryDjangoContext, its request attribute is returned.
      - Otherwise, the context itself is returned.
    - If the info object is an instance of GraphQLResolveInfo, its context attribute is returned.
    - If the info object is of an unrecognized type, a TypeError is raised.

    """
    if hasattr(info, "context"):
        ctx = getattr(info, "context")
        if isinstance(ctx, StrawberryDjangoContext):
            return ctx.request

        return ctx
    return info


__all__ = ["get_context"]
