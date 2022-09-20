from typing import Any, Union

from django.http import HttpRequest
from graphql import GraphQLResolveInfo
from strawberry.django.context import StrawberryDjangoContext
from strawberry.types import Info


def get_context(info: Union[HttpRequest, Info[Any, Any], GraphQLResolveInfo]) -> Any:
    if hasattr(info, "context"):
        ctx = getattr(info, "context")
        if isinstance(ctx, StrawberryDjangoContext):
            return ctx.request
        return ctx
    return info


__all__ = [
    'get_context',
]
