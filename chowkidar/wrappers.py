from functools import wraps
from ipware import get_client_ip
from django.http import HttpRequest

from .utils import get_context
from .models import RefreshToken


def issue_tokens_on_login(f):
    """
    Wrap this decorator around a graphql resolver function (eg- Login Mutation) to issue auth tokens and login the user.
    The wrapped resolver function must set info.context.LOGIN_USER to the User model instance.
    """

    def generate_refresh_token(userID, request: HttpRequest):
        ip, is_routable = get_client_ip(request)

        agent = None
        if "User-Agent" in request.headers:
            agent = request.headers["user-agent"]

        return RefreshToken.objects.create(user_id=userID, ip=ip, userAgent=agent)

    @wraps(f)
    def wrapper(cls, info, *args, **kwargs):
        result = f(cls, info, *args, **kwargs)
        ctx = get_context(info)
        if hasattr(info.context, "LOGIN_USER") and info.context.LOGIN_USER:
            token = generate_refresh_token(info.context.LOGIN_USER.id, ctx)
            ctx.NEW_REFRESH_TOKEN = token
        return result

    return wrapper


def revoke_tokens_on_logout(f):
    """
    Wrap this decorator around a graphql resolver function (eg- Logout Mutation) to revoke auth tokens and logout the
    user. To revoke, the wrapped resolver function must set info.context.LOGOUT_USER to True.
    """

    @wraps(f)
    def wrapper(cls, info, *args, **kwargs):
        result = f(cls, info, *args, **kwargs)
        ctx = get_context(info)
        if hasattr(info.context, "LOGOUT_USER") and info.context.LOGOUT_USER:
            ctx.REMOVE_REFRESH_TOKEN = True
            ctx.REMOVE_JWT_TOKEN = True
        return result

    return wrapper


__all__ = [
    "issue_tokens_on_login",
    "revoke_tokens_on_logout"
]
