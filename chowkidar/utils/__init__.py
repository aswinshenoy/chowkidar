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


def validate_email(email: str) -> str:
    from re import match
    from chowkidar.utils.exceptions import AuthError
    if not match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email):
        raise AuthError(message='You have entered an invalid email address', code='INVALID_EMAIL')
    return email


__all__ = [
    'get_context',
    'validate_email'
]
